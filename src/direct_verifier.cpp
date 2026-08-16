// SPDX-License-Identifier: Apache-2.0

#include "direct_verifier.hpp"

#include "base64url.hpp"
#include "crypto.hpp"
#include "strict_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

namespace credbind::direct {
namespace {

using Json = nlohmann::json;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using EcSignaturePtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using ParamBuilderPtr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using ParamsPtr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;

constexpr std::size_t kMaximumTokenBytes = 32768U;
constexpr std::size_t kMaximumEvidenceBytes = 16384U;
constexpr std::size_t kMaximumHeaderBytes = 8192U;
constexpr std::size_t kMaximumHeaderDepth = 8U;
constexpr std::size_t kMaximumHeaderMembers = 32U;
constexpr std::size_t kMaximumHeaderValues = 64U;
constexpr std::size_t kMaximumHeaderKeyBytes = 256U;
constexpr std::size_t kMaximumPrincipalClaimBytes = 32768U;

constexpr std::string_view kVersionName = "https://credbind.dev/core/v1#version";
constexpr std::string_view kRoleName = "https://credbind.dev/core/v1#role";
constexpr std::string_view kBindingName = "https://credbind.dev/core/v1#binding";
constexpr std::string_view kEvidenceName = "https://credbind.dev/core/v1#evidence";
constexpr std::string_view kNonceName = "https://credbind.dev/core/v1#nonce";
constexpr std::string_view kEcdsaCertificate =
    "ecdsa-sha2-nistp256-cert-v01@openssh.com";
constexpr std::string_view kEd25519Certificate = "ssh-ed25519-cert-v01@openssh.com";
constexpr std::string_view kEcdsaKey = "ecdsa-sha2-nistp256";
constexpr std::string_view kEd25519Key = "ssh-ed25519";

ParseError error(ParseErrorKind kind, std::string message) {
    return ParseError{kind, std::move(message)};
}

enum class JsonContextKind { object, array };

struct JsonContext {
    JsonContextKind kind;
    bool root;
    std::unordered_set<std::string> members;
    std::string pending_name;
    bool has_pending_name;
    Json value;
};

class HeaderSax final : public nlohmann::json_sax<Json> {
  public:
    bool null() override { return scalar(nullptr); }
    bool boolean(bool value) override { return scalar(value); }
    bool number_integer(number_integer_t value) override { return scalar(value); }
    bool number_unsigned(number_unsigned_t value) override { return scalar(value); }
    bool number_float(number_float_t value, const string_t&) override { return scalar(value); }
    bool string(string_t& value) override { return scalar(std::move(value)); }
    bool binary(binary_t&) override { return fail("binary CIC JSON value"); }

    bool start_object(std::size_t) override {
        if (!count_value()) return false;
        if (stack_.empty()) {
            stack_.push_back(JsonContext{JsonContextKind::object, true, {}, {}, false,
                                         Json::object()});
            return true;
        }
        if (!parent_ready() || stack_.size() + 1U > kMaximumHeaderDepth) {
            return stack_.size() + 1U <= kMaximumHeaderDepth
                       ? false
                       : fail_limit("CIC JSON depth");
        }
        stack_.push_back(JsonContext{JsonContextKind::object, false, {}, {}, false,
                                     Json::object()});
        return true;
    }

    bool key(string_t& value) override {
        if (stack_.empty() || stack_.back().kind != JsonContextKind::object) {
            return fail("CIC member outside object");
        }
        ++members_;
        if (members_ > kMaximumHeaderMembers || value.size() > kMaximumHeaderKeyBytes) {
            return fail_limit("CIC JSON member");
        }
        auto& context = stack_.back();
        if (!context.members.insert(value).second) return fail("duplicate CIC member");
        context.pending_name = std::move(value);
        context.has_pending_name = true;
        return true;
    }

    bool end_object() override {
        if (stack_.empty() || stack_.back().kind != JsonContextKind::object ||
            stack_.back().has_pending_name) {
            return fail("unexpected CIC object end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        if (context.root) {
            root_ = std::move(context.value);
            complete_ = true;
            return true;
        }
        return attach(std::move(context.value));
    }

    bool start_array(std::size_t) override {
        if (stack_.empty() || !count_value() || !parent_ready()) return false;
        if (stack_.size() + 1U > kMaximumHeaderDepth) return fail_limit("CIC JSON depth");
        stack_.push_back(JsonContext{JsonContextKind::array, false, {}, {}, false,
                                     Json::array()});
        return true;
    }

    bool end_array() override {
        if (stack_.empty() || stack_.back().kind != JsonContextKind::array) {
            return fail("unexpected CIC array end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        return attach(std::move(context.value));
    }

    bool parse_error(std::size_t, const std::string&,
                     const nlohmann::detail::exception&) override {
        return fail("invalid strict CIC JSON");
    }

    [[nodiscard]] bool complete() const { return complete_ && stack_.empty(); }
    [[nodiscard]] bool failed() const { return failed_; }
    [[nodiscard]] const ParseError& failure() const { return failure_; }
    [[nodiscard]] Json take() { return std::move(root_); }

  private:
    template <typename Value>
    bool scalar(Value value) {
        if (!count_value() || stack_.empty()) return false;
        return attach(Json(std::move(value)));
    }

    bool attach(Json value) {
        auto& context = stack_.back();
        if (context.kind == JsonContextKind::array) {
            context.value.push_back(std::move(value));
            return true;
        }
        if (!context.has_pending_name) return fail("CIC value has no member");
        context.value[std::move(context.pending_name)] = std::move(value);
        context.pending_name.clear();
        context.has_pending_name = false;
        return true;
    }

    bool parent_ready() {
        if (stack_.back().kind == JsonContextKind::object &&
            !stack_.back().has_pending_name) {
            return fail("CIC container has no member");
        }
        return true;
    }

    bool count_value() {
        ++values_;
        return values_ <= kMaximumHeaderValues ? true : fail_limit("CIC JSON value");
    }

    bool fail(std::string message) {
        if (!failed_) {
            failure_ = error(ParseErrorKind::malformed_input, std::move(message));
            failed_ = true;
        }
        return false;
    }

    bool fail_limit(std::string message) {
        if (!failed_) {
            failure_ = error(ParseErrorKind::resource_limit, std::move(message));
            failed_ = true;
        }
        return false;
    }

    std::vector<JsonContext> stack_;
    Json root_;
    ParseError failure_{ParseErrorKind::malformed_input, "CIC parse failed"};
    std::size_t members_ = 0U;
    std::size_t values_ = 0U;
    bool complete_ = false;
    bool failed_ = false;
};

tl::expected<Json, ParseError> parse_header_json(std::string_view input) {
    if (input.size() > kMaximumHeaderBytes) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "CIC exceeds byte bound"));
    }
    HeaderSax handler;
    const bool parsed = Json::sax_parse(input.begin(), input.end(), &handler,
                                        Json::input_format_t::json, true, false);
    if (!parsed || handler.failed() || !handler.complete()) {
        return tl::make_unexpected(handler.failure());
    }
    return handler.take();
}

const std::string* json_string(const Json& object, std::string_view name) {
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || !iterator->is_string()) return nullptr;
    return &iterator->get_ref<const std::string&>();
}

std::vector<std::uint8_t> bytes(std::string_view value) {
    std::vector<std::uint8_t> result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    return result;
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_value(std::vector<std::uint8_t>& output, std::string_view value) {
    append_u64(output, static_cast<std::uint64_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

bool valid_requested_user(std::string_view value) {
    if (value.empty() || value.size() > 256U) return false;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::uint32_t codepoint = 0U;
        std::size_t continuation_count = 0U;
        if (first <= 0x7fU) {
            codepoint = first;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            codepoint = first & 0x1fU;
            continuation_count = 1U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            codepoint = first & 0x0fU;
            continuation_count = 2U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            codepoint = first & 0x07U;
            continuation_count = 3U;
        } else {
            return false;
        }
        if (continuation_count > value.size() - offset - 1U) return false;
        for (std::size_t index = 0U; index < continuation_count; ++index) {
            const auto continuation =
                static_cast<unsigned char>(value[offset + index + 1U]);
            if ((continuation & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (continuation & 0x3fU);
        }
        if ((continuation_count == 2U && codepoint < 0x800U) ||
            (continuation_count == 3U && codepoint < 0x10000U) ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU ||
            codepoint <= 0x1fU || (codepoint >= 0x7fU && codepoint <= 0x9fU)) {
            return false;
        }
        offset += continuation_count + 1U;
    }
    return true;
}

std::string encode_base64url(const std::uint8_t* input, std::size_t size) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve(((size + 2U) / 3U) * 4U);
    std::size_t offset = 0U;
    while (size - offset >= 3U) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1U]) << 8U) |
                           static_cast<std::uint32_t>(input[offset + 2U]);
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.push_back(alphabet[(value >> 6U) & 63U]);
        output.push_back(alphabet[value & 63U]);
        offset += 3U;
    }
    const auto remaining = size - offset;
    if (remaining == 1U) {
        const auto value = static_cast<std::uint32_t>(input[offset]) << 16U;
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
    } else if (remaining == 2U) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1U]) << 8U);
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.push_back(alphabet[(value >> 6U) & 63U]);
    }
    return output;
}

std::string encode_base64(const std::vector<std::uint8_t>& input) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((input.size() + 2U) / 3U) * 4U);
    std::size_t offset = 0U;
    while (input.size() - offset >= 3U) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1U]) << 8U) |
                           static_cast<std::uint32_t>(input[offset + 2U]);
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.push_back(alphabet[(value >> 6U) & 63U]);
        output.push_back(alphabet[value & 63U]);
        offset += 3U;
    }
    const auto remaining = input.size() - offset;
    if (remaining == 1U) {
        const auto value = static_cast<std::uint32_t>(input[offset]) << 16U;
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.append("==");
    } else if (remaining == 2U) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1U]) << 8U);
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.push_back(alphabet[(value >> 6U) & 63U]);
        output.push_back('=');
    }
    return output;
}

tl::expected<PkeyPtr, ParseError> p256_key(const std::vector<std::uint8_t>& point,
                                           ParseErrorKind kind) {
    if (point.size() != 65U || point.front() != 0x04U) {
        return tl::make_unexpected(error(kind, "invalid P-256 point encoding"));
    }
    ParamBuilderPtr builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!builder ||
        OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                        const_cast<char*>("prime256v1"), 0U) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                         const_cast<std::uint8_t*>(point.data()),
                                         point.size()) != 1) {
        return tl::make_unexpected(error(kind, "could not construct P-256 parameters"));
    }
    ParamsPtr parameters(OSSL_PARAM_BLD_to_param(builder.get()), OSSL_PARAM_free);
    PkeyContextPtr context(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                           EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!parameters || !context || EVP_PKEY_fromdata_init(context.get()) <= 0 ||
        EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY,
                          parameters.get()) <= 0 ||
        raw == nullptr) {
        EVP_PKEY_free(raw);
        return tl::make_unexpected(error(kind, "invalid P-256 public key"));
    }
    PkeyPtr key(raw, EVP_PKEY_free);
    PkeyContextPtr check(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        return tl::make_unexpected(error(kind, "invalid P-256 public point"));
    }
    return key;
}

tl::expected<PkeyPtr, ParseError> ed25519_key(const std::vector<std::uint8_t>& encoded,
                                              ParseErrorKind kind) {
    if (encoded.size() != 32U) {
        return tl::make_unexpected(error(kind, "invalid Ed25519 public key length"));
    }
    EVP_PKEY* raw = EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr,
                                                   encoded.data(), encoded.size());
    if (raw == nullptr) {
        return tl::make_unexpected(error(kind, "invalid Ed25519 public key"));
    }
    PkeyPtr key(raw, EVP_PKEY_free);
    PkeyContextPtr check(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        return tl::make_unexpected(error(kind, "invalid Ed25519 public key"));
    }
    return key;
}

tl::expected<std::vector<std::uint8_t>, ParseError> ecdsa_der(
    const std::vector<std::uint8_t>& r, const std::vector<std::uint8_t>& s,
    ParseErrorKind kind) {
    if (r.empty() || s.empty() || r.size() > 33U || s.size() > 33U) {
        return tl::make_unexpected(error(kind, "invalid ECDSA signature scalars"));
    }
    BnPtr r_bn(BN_bin2bn(r.data(), static_cast<int>(r.size()), nullptr), BN_free);
    BnPtr s_bn(BN_bin2bn(s.data(), static_cast<int>(s.size()), nullptr), BN_free);
    EcSignaturePtr signature(ECDSA_SIG_new(), ECDSA_SIG_free);
    if (!r_bn || !s_bn || !signature || BN_is_zero(r_bn.get()) == 1 ||
        BN_is_zero(s_bn.get()) == 1 ||
        ECDSA_SIG_set0(signature.get(), r_bn.release(), s_bn.release()) != 1) {
        return tl::make_unexpected(error(kind, "invalid ECDSA signature"));
    }
    const int length = i2d_ECDSA_SIG(signature.get(), nullptr);
    if (length <= 0) return tl::make_unexpected(error(kind, "invalid ECDSA signature"));
    std::vector<std::uint8_t> result(static_cast<std::size_t>(length));
    auto* output = result.data();
    if (i2d_ECDSA_SIG(signature.get(), &output) != length) {
        return tl::make_unexpected(error(kind, "invalid ECDSA signature"));
    }
    return result;
}

tl::expected<void, ParseError> verify_signature(EVP_PKEY* key,
                                                CallerAlgorithm algorithm,
                                                std::string_view input,
                                                const std::vector<std::uint8_t>& signature,
                                                ParseErrorKind kind) {
    MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) return tl::make_unexpected(error(kind, "signature setup failed"));
    if (algorithm == CallerAlgorithm::ed25519) {
        if (signature.size() != 64U ||
            EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key) != 1 ||
            EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                             reinterpret_cast<const std::uint8_t*>(input.data()),
                             input.size()) != 1) {
            return tl::make_unexpected(error(kind, "Ed25519 signature verification failed"));
        }
        return {};
    }
    if (EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key) != 1 ||
        EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                         reinterpret_cast<const std::uint8_t*>(input.data()),
                         input.size()) != 1) {
        return tl::make_unexpected(error(kind, "P-256 signature verification failed"));
    }
    return {};
}

struct Cic {
    CallerKey key;
    PkeyPtr verification_key{nullptr, EVP_PKEY_free};
    std::string binding_profile;
    std::string evidence_profile;
};

tl::expected<Cic, ParseError> parse_cic(std::string_view json,
                                        const CorePolicy& policy) {
    const auto object = parse_header_json(json);
    if (!object) return tl::make_unexpected(object.error());
    constexpr std::array<std::string_view, 9> exact_names{
        "alg", "jwk", "typ", "crit", kVersionName, kRoleName, kBindingName,
        kEvidenceName, kNonceName};
    if (!object->is_object() || object->size() != exact_names.size() ||
        std::any_of(exact_names.begin(), exact_names.end(),
                    [&object](std::string_view name) {
                        return object->find(std::string(name)) == object->end();
                    })) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "CIC does not contain its exact members"));
    }
    const auto version = json_string(*object, kVersionName);
    if (version == nullptr) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "CIC version has wrong type"));
    }
    if (*version != "1") {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_version,
                                         "unsupported CIC version"));
    }
    const auto role = json_string(*object, kRoleName);
    const auto type = json_string(*object, "typ");
    const auto binding = json_string(*object, kBindingName);
    const auto evidence = json_string(*object, kEvidenceName);
    const auto nonce = json_string(*object, kNonceName);
    const auto algorithm = json_string(*object, "alg");
    if (role == nullptr || type == nullptr || binding == nullptr || evidence == nullptr ||
        nonce == nullptr || algorithm == nullptr) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "CIC string member has wrong type"));
    }
    if (*role != "caller") {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_version,
                                         "unsupported CIC role"));
    }
    if (*type != "credbind+json") {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "wrong CIC media type"));
    }
    const auto nonce_bytes = base64url::decode(*nonce, 16U);
    if (!nonce_bytes || nonce_bytes->size() != 16U) {
        return tl::make_unexpected(!nonce_bytes
                                       ? nonce_bytes.error()
                                       : error(ParseErrorKind::malformed_input,
                                               "CIC nonce has wrong length"));
    }
    const auto crit = object->find("crit");
    if (crit == object->end() || !crit->is_array() || crit->size() != 5U) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "CIC crit has wrong type or count"));
    }
    const std::unordered_set<std::string> required_critical{
        std::string(kVersionName), std::string(kRoleName), std::string(kBindingName),
        std::string(kEvidenceName), std::string(kNonceName)};
    std::unordered_set<std::string> actual_critical;
    for (const auto& value : *crit) {
        if (!value.is_string() ||
            !actual_critical.insert(value.get_ref<const std::string&>()).second) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "CIC crit is not an exact unique string set"));
        }
    }
    if (actual_critical != required_critical) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "wrong CIC critical parameters"));
    }
    if ((*binding != issuer::kOidcNonceBinding &&
         *binding != issuer::kAudienceBinding &&
         *binding != issuer::kCredBindClaimBinding) ||
        (*evidence != issuer::kStandardEvidence && *evidence != issuer::kGqEvidence)) {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                         "CIC profile is unsupported"));
    }
    if (policy.issuer_policy.binding_profiles.find(*binding) ==
            policy.issuer_policy.binding_profiles.end() ||
        policy.issuer_policy.evidence_profiles.find(*evidence) ==
            policy.issuer_policy.evidence_profiles.end() ||
        (policy.issuer_policy.require_non_reconstructible_evidence &&
         *evidence == issuer::kStandardEvidence)) {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                         "CIC profile is not permitted"));
    }
    if (policy.caller_algorithms.find(*algorithm) == policy.caller_algorithms.end()) {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_algorithm,
                                         "caller algorithm is not permitted"));
    }
    const auto jwk = object->find("jwk");
    if (jwk == object->end() || !jwk->is_object()) {
        return tl::make_unexpected(error(ParseErrorKind::caller_key_invalid,
                                         "caller JWK is not an object"));
    }
    if (*algorithm == "ES256") {
        if (jwk->size() != 4U || json_string(*jwk, "kty") == nullptr ||
            json_string(*jwk, "crv") == nullptr || json_string(*jwk, "x") == nullptr ||
            json_string(*jwk, "y") == nullptr || *json_string(*jwk, "kty") != "EC" ||
            *json_string(*jwk, "crv") != "P-256") {
            return tl::make_unexpected(error(ParseErrorKind::caller_key_invalid,
                                             "invalid public ES256 JWK schema"));
        }
        const auto x = base64url::decode(*json_string(*jwk, "x"), 32U);
        const auto y = base64url::decode(*json_string(*jwk, "y"), 32U);
        if (!x || !y || x->size() != 32U || y->size() != 32U) {
            return tl::make_unexpected(error(ParseErrorKind::caller_key_invalid,
                                             "invalid ES256 JWK coordinate"));
        }
        std::vector<std::uint8_t> point;
        point.reserve(65U);
        point.push_back(0x04U);
        point.insert(point.end(), x->begin(), x->end());
        point.insert(point.end(), y->begin(), y->end());
        auto key = p256_key(point, ParseErrorKind::caller_key_invalid);
        if (!key) return tl::make_unexpected(key.error());
        return Cic{CallerKey{CallerAlgorithm::es256, std::move(point)}, std::move(*key),
                   *binding, *evidence};
    }
    if (*algorithm == "Ed25519") {
        if (jwk->size() != 3U || json_string(*jwk, "kty") == nullptr ||
            json_string(*jwk, "crv") == nullptr || json_string(*jwk, "x") == nullptr ||
            *json_string(*jwk, "kty") != "OKP" ||
            *json_string(*jwk, "crv") != "Ed25519") {
            return tl::make_unexpected(error(ParseErrorKind::caller_key_invalid,
                                             "invalid public Ed25519 JWK schema"));
        }
        const auto encoded = base64url::decode(*json_string(*jwk, "x"), 32U);
        if (!encoded || encoded->size() != 32U) {
            return tl::make_unexpected(error(ParseErrorKind::caller_key_invalid,
                                             "invalid Ed25519 JWK key"));
        }
        auto key = ed25519_key(*encoded, ParseErrorKind::caller_key_invalid);
        if (!key) return tl::make_unexpected(key.error());
        return Cic{CallerKey{CallerAlgorithm::ed25519, *encoded}, std::move(*key),
                   *binding, *evidence};
    }
    return tl::make_unexpected(error(ParseErrorKind::unsupported_algorithm,
                                     "unsupported caller algorithm"));
}

tl::expected<std::string, ParseError> commitment(std::string_view cic) {
    std::vector<std::uint8_t> input;
    constexpr std::string_view label = "CredBind-CIC-v1";
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0U);
    append_value(input, cic);
    const auto digest = crypto::digest_sha256(input.data(), input.size());
    if (!digest) return tl::make_unexpected(digest.error());
    return encode_base64url(digest->data(), digest->size());
}

bool digest_equal(const crypto::Sha256Digest& left,
                  const crypto::Sha256Digest& right) {
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

tl::expected<crypto::Sha256Digest, ParseError> expected_evidence_digest(
    std::string_view profile, std::string_view payload,
    const std::vector<std::uint8_t>& evidence) {
    std::vector<std::uint8_t> input;
    constexpr std::string_view label = "CredBind-Issuer-Evidence-Digest-v1";
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0U);
    append_value(input, profile);
    append_value(input, payload);
    append_u64(input, static_cast<std::uint64_t>(evidence.size()));
    input.insert(input.end(), evidence.begin(), evidence.end());
    return crypto::digest_sha256(input.data(), input.size());
}

tl::expected<std::uint32_t, ParseError> read_u32(std::string_view input,
                                                 std::size_t& offset,
                                                 ParseErrorKind kind) {
    if (input.size() - offset < 4U) {
        return tl::make_unexpected(error(kind, "truncated SSH field"));
    }
    std::uint32_t value = 0U;
    for (std::size_t index = 0U; index < 4U; ++index) {
        value = static_cast<std::uint32_t>(
            (value << 8U) | static_cast<unsigned char>(input[offset + index]));
    }
    offset += 4U;
    return value;
}

tl::expected<std::string_view, ParseError> read_ssh_string(
    std::string_view input, std::size_t& offset, std::size_t maximum,
    ParseErrorKind kind) {
    const auto length = read_u32(input, offset, kind);
    if (!length || static_cast<std::uint64_t>(*length) >
                       static_cast<std::uint64_t>(input.size() - offset) ||
        static_cast<std::uint64_t>(*length) > static_cast<std::uint64_t>(maximum)) {
        return tl::make_unexpected(!length ? length.error()
                                           : error(kind, "invalid SSH field length"));
    }
    const auto value = input.substr(offset, static_cast<std::size_t>(*length));
    offset += static_cast<std::size_t>(*length);
    return value;
}

tl::expected<void, ParseError> verify_certificate_signature(
    const openssh::Certificate& certificate, CallerAlgorithm algorithm) {
    const std::string key_blob(certificate.signature_key.begin(),
                               certificate.signature_key.end());
    std::size_t offset = 0U;
    const auto key_type = read_ssh_string(key_blob, offset, 256U,
                                          ParseErrorKind::ssh_certificate_invalid);
    if (!key_type) return tl::make_unexpected(key_type.error());
    PkeyPtr key(nullptr, EVP_PKEY_free);
    if (algorithm == CallerAlgorithm::es256) {
        const auto curve = read_ssh_string(key_blob, offset, 256U,
                                           ParseErrorKind::ssh_certificate_invalid);
        const auto point = read_ssh_string(key_blob, offset, 65U,
                                           ParseErrorKind::ssh_certificate_invalid);
        if (!curve || !point || *key_type != kEcdsaKey || *curve != "nistp256" ||
            offset != key_blob.size()) {
            return tl::make_unexpected(error(ParseErrorKind::ssh_certificate_invalid,
                                             "invalid P-256 carrier CA"));
        }
        auto constructed = p256_key(bytes(*point),
                                    ParseErrorKind::ssh_certificate_invalid);
        if (!constructed) return tl::make_unexpected(constructed.error());
        key = std::move(*constructed);
        const std::string encoded(certificate.signature.begin(),
                                  certificate.signature.end());
        std::size_t signature_offset = 0U;
        const auto r = read_ssh_string(encoded, signature_offset, 33U,
                                       ParseErrorKind::ssh_certificate_invalid);
        const auto s = read_ssh_string(encoded, signature_offset, 33U,
                                       ParseErrorKind::ssh_certificate_invalid);
        if (!r || !s || signature_offset != encoded.size()) {
            return tl::make_unexpected(error(ParseErrorKind::ssh_certificate_invalid,
                                             "invalid carrier ECDSA signature"));
        }
        const auto der = ecdsa_der(bytes(*r), bytes(*s),
                                   ParseErrorKind::ssh_certificate_invalid);
        if (!der) return tl::make_unexpected(der.error());
        return verify_signature(key.get(), algorithm,
                                std::string_view(
                                    reinterpret_cast<const char*>(certificate.signed_bytes.data()),
                                    certificate.signed_bytes.size()),
                                *der, ParseErrorKind::ssh_certificate_invalid);
    }
    const auto encoded_key = read_ssh_string(key_blob, offset, 32U,
                                             ParseErrorKind::ssh_certificate_invalid);
    if (!encoded_key || *key_type != kEd25519Key || encoded_key->size() != 32U ||
        offset != key_blob.size()) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_certificate_invalid,
                                         "invalid Ed25519 carrier CA"));
    }
    auto constructed = ed25519_key(bytes(*encoded_key),
                                   ParseErrorKind::ssh_certificate_invalid);
    if (!constructed) return tl::make_unexpected(constructed.error());
    key = std::move(*constructed);
    return verify_signature(key.get(), algorithm,
                            std::string_view(
                                reinterpret_cast<const char*>(certificate.signed_bytes.data()),
                                certificate.signed_bytes.size()),
                            certificate.signature,
                            ParseErrorKind::ssh_certificate_invalid);
}

tl::expected<std::string, ParseError> principal(const CoreResult& core,
                                                std::string_view claim_name) {
    if (claim_name.empty()) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_principal_invalid,
                                         "principal claim policy is empty"));
    }
    const auto iterator = core.claims.find(std::string(claim_name));
    if (iterator == core.claims.end() || !iterator->second.is_string()) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_principal_invalid,
                                         "principal claim is absent or not a string"));
    }
    const auto& value = iterator->second.get_ref<const std::string&>();
    if (value.empty() || value.size() > kMaximumPrincipalClaimBytes) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_principal_invalid,
                                         "principal claim is empty or oversized"));
    }
    std::vector<std::uint8_t> input;
    constexpr std::string_view label = "CredBind-SSH-Principal-v1";
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0U);
    append_value(input, core.issuer);
    append_value(input, claim_name);
    append_value(input, value);
    const auto digest = crypto::digest_sha256(input.data(), input.size());
    if (!digest) return tl::make_unexpected(digest.error());
    return std::string("credbind-v1-") +
           encode_base64url(digest->data(), digest->size());
}

tl::expected<std::int64_t, ParseError> checked_add(std::int64_t left,
                                                  std::int64_t right,
                                                  ParseErrorKind kind) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return tl::make_unexpected(error(kind, "time arithmetic overflow"));
    }
    return left + right;
}

bool account_predicate_matches(const issuer::Claims& claims,
                               const issuer::Predicate& predicate) {
    if (predicate.claim.empty()) return false;
    const auto iterator = claims.find(predicate.claim);
    if (iterator == claims.end()) return false;
    if (predicate.operation == issuer::PredicateOperation::string_array_contains) {
        if (!predicate.values.empty() || !iterator->second.is_array()) return false;
        std::unordered_set<std::string> unique;
        bool matched = false;
        for (const auto& value : iterator->second) {
            if (!value.is_string()) return false;
            const auto& text = value.get_ref<const std::string&>();
            if (!unique.insert(text).second) return false;
            matched = matched || text == predicate.value;
        }
        return matched;
    }
    if (!iterator->second.is_string()) return false;
    const auto& value = iterator->second.get_ref<const std::string&>();
    if (predicate.operation == issuer::PredicateOperation::string_equals) {
        return predicate.values.empty() && value == predicate.value;
    }
    if (predicate.operation != issuer::PredicateOperation::string_one_of ||
        !predicate.value.empty() || predicate.values.empty()) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const auto& permitted : predicate.values) {
        if (permitted.empty() || !unique.insert(permitted).second) return false;
    }
    return std::find(predicate.values.begin(), predicate.values.end(), value) !=
           predicate.values.end();
}

bool account_rule_matches(const AccountRule& rule, const CoreResult& core,
                          const std::vector<std::string>& certificate_extensions) {
    if (rule.issuer.empty() || rule.issuer != core.issuer) return false;
    if (!std::all_of(rule.all.begin(), rule.all.end(),
                     [&core](const issuer::Predicate& predicate) {
                         return account_predicate_matches(core.claims, predicate);
                     })) {
        return false;
    }
    return std::all_of(certificate_extensions.begin(), certificate_extensions.end(),
                       [&rule](const std::string& extension) {
                           return rule.allowed_certificate_extensions.find(extension) !=
                                  rule.allowed_certificate_extensions.end();
                       });
}

}  // namespace

tl::expected<void, ParseError> validate_evidence_result_digest(
    const crypto::Sha256Digest& expected, const crypto::Sha256Digest& verified) {
    if (!digest_equal(expected, verified)) {
        return tl::make_unexpected(error(ParseErrorKind::evidence_result_mismatch,
                                         "issuer evidence digest does not match"));
    }
    return {};
}

CoreVerificationResult verify_token(std::string_view token, const CorePolicy& policy,
                                    const jwks::StaticJwks& keys,
                                    std::int64_t verification_time_unix) {
    if (policy.limits.max_token_bytes == 0U ||
        policy.limits.max_token_bytes > kMaximumTokenBytes ||
        policy.limits.max_evidence_bytes == 0U ||
        policy.limits.max_evidence_bytes > kMaximumEvidenceBytes) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "invalid configured core limits"));
    }
    if (token.size() > policy.limits.max_token_bytes) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "token exceeds protocol bound"));
    }
    if (policy.caller_algorithms.empty()) {
        return tl::make_unexpected(error(ParseErrorKind::issuer_untrusted,
                                         "caller algorithm policy is empty"));
    }
    const auto envelope = strict_json::parse_core_envelope(token);
    if (!envelope) return tl::make_unexpected(envelope.error());
    const auto payload = base64url::decode(envelope->payload, kMaximumTokenBytes);
    const auto protected_header = base64url::decode(
        envelope->caller_signature.protected_header, kMaximumHeaderBytes);
    const auto caller_signature = base64url::decode(
        envelope->caller_signature.signature, 128U);
    const auto evidence = base64url::decode(envelope->evidence,
                                            policy.limits.max_evidence_bytes);
    if (!payload || !protected_header || !caller_signature || !evidence) {
        if (!payload) return tl::make_unexpected(payload.error());
        if (!protected_header) return tl::make_unexpected(protected_header.error());
        if (!caller_signature) return tl::make_unexpected(caller_signature.error());
        return tl::make_unexpected(evidence.error());
    }
    const std::string cic_json(protected_header->begin(), protected_header->end());
    auto cic = parse_cic(cic_json, policy);
    if (!cic) return tl::make_unexpected(cic.error());
    const auto bound_commitment = commitment(cic_json);
    if (!bound_commitment) return tl::make_unexpected(bound_commitment.error());
    const auto expected_digest = expected_evidence_digest(
        cic->evidence_profile, envelope->payload, *evidence);
    if (!expected_digest) return tl::make_unexpected(expected_digest.error());
    const auto evidence_result = issuer::verify(
        issuer::VerificationInput{cic->evidence_profile, cic->binding_profile,
                                  *bound_commitment, envelope->payload, *evidence,
                                  verification_time_unix},
        policy.issuer_policy, keys);
    if (!evidence_result) return tl::make_unexpected(evidence_result.error());
    const auto digest_result = validate_evidence_result_digest(
        *expected_digest, evidence_result->verified_evidence_digest);
    if (evidence_result->issuer.empty() || evidence_result->issuer_key_id.empty() ||
        evidence_result->issuer != policy.issuer_policy.issuer ||
        evidence_result->binding_profile != cic->binding_profile ||
        !digest_result) {
        return tl::make_unexpected(error(ParseErrorKind::evidence_result_mismatch,
                                         "issuer evidence result is inconsistent"));
    }
    if (std::any_of(evidence_result->claims.begin(), evidence_result->claims.end(),
                    [&policy](const auto& claim) {
                        return policy.issuer_policy.admitted_claims.find(claim.first) ==
                               policy.issuer_policy.admitted_claims.end();
                    })) {
        return tl::make_unexpected(error(ParseErrorKind::evidence_result_mismatch,
                                         "issuer result contains an unadmitted claim"));
    }
    const std::string signing_input = envelope->caller_signature.protected_header + "." +
                                      envelope->payload;
    if (caller_signature->size() != 64U) {
        return tl::make_unexpected(error(ParseErrorKind::caller_signature_invalid,
                                         "caller signature has wrong encoding length"));
    }
    if (cic->key.algorithm == CallerAlgorithm::es256) {
        const std::vector<std::uint8_t> r(caller_signature->begin(),
                                          caller_signature->begin() + 32);
        const std::vector<std::uint8_t> s(caller_signature->begin() + 32,
                                          caller_signature->end());
        const auto der = ecdsa_der(r, s, ParseErrorKind::caller_signature_invalid);
        if (!der) return tl::make_unexpected(der.error());
        const auto verified = verify_signature(cic->verification_key.get(),
                                               cic->key.algorithm, signing_input, *der,
                                               ParseErrorKind::caller_signature_invalid);
        if (!verified) return tl::make_unexpected(verified.error());
    } else {
        const auto verified = verify_signature(cic->verification_key.get(),
                                               cic->key.algorithm, signing_input,
                                               *caller_signature,
                                               ParseErrorKind::caller_signature_invalid);
        if (!verified) return tl::make_unexpected(verified.error());
    }
    return CoreResult{evidence_result->issuer, evidence_result->claims,
                      std::move(cic->key), cic->binding_profile, cic->evidence_profile,
                      *bound_commitment, evidence_result->credential_valid_until_unix};
}

CarrierVerificationResult verify_carrier(const CarrierInput& input,
                                         const CorePolicy& core_policy,
                                         const CarrierPolicy& carrier_policy,
                                         const AccountPolicies& accounts,
                                         const jwks::StaticJwks& keys,
                                         openssh::Limits limits,
                                         CarrierAuditContext* audit_context) {
    if (carrier_policy.clock_skew_seconds < 0 ||
        carrier_policy.maximum_identity_lifetime_seconds < 0) {
        return tl::make_unexpected(error(ParseErrorKind::issuer_untrusted,
                                         "invalid carrier time policy"));
    }
    if (!valid_requested_user(input.requested_user) || input.key_type_argument.empty()) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid direct-verifier command input"));
    }
    const auto certificate = openssh::parse_certificate(input.certificate_blob, limits);
    if (!certificate) return tl::make_unexpected(certificate.error());
    const std::string_view expected_type =
        certificate->caller_algorithm == openssh::CallerAlgorithm::es256
            ? kEcdsaCertificate
            : kEd25519Certificate;
    if (input.key_type_argument != expected_type) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "key type argument does not match certificate"));
    }
    const std::string token(certificate->token.begin(), certificate->token.end());
    auto core = verify_token(token, core_policy, keys, input.verification_time_unix);
    if (!core) return tl::make_unexpected(core.error());
    if (audit_context != nullptr) {
        audit_context->core = *core;
        audit_context->core_verified = true;
    }
    const auto carrier_algorithm =
        certificate->caller_algorithm == openssh::CallerAlgorithm::es256
            ? CallerAlgorithm::es256
            : CallerAlgorithm::ed25519;
    const auto signature = verify_certificate_signature(*certificate,
                                                        carrier_algorithm);
    if (!signature) return tl::make_unexpected(signature.error());
    const bool algorithm_matches =
        (certificate->caller_algorithm == openssh::CallerAlgorithm::es256 &&
         core->caller_key.algorithm == CallerAlgorithm::es256) ||
        (certificate->caller_algorithm == openssh::CallerAlgorithm::ed25519 &&
         core->caller_key.algorithm == CallerAlgorithm::ed25519);
    if (!algorithm_matches || certificate->certified_key != core->caller_key.canonical_public_key) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_key_mismatch,
                                         "certified key does not match CIC key"));
    }
    const auto now_with_skew = checked_add(input.verification_time_unix,
                                           carrier_policy.clock_skew_seconds,
                                           ParseErrorKind::ssh_identity_not_yet_valid);
    const auto now_without_skew = checked_add(input.verification_time_unix,
                                              -carrier_policy.clock_skew_seconds,
                                              ParseErrorKind::ssh_identity_expired);
    if (!now_with_skew) return tl::make_unexpected(now_with_skew.error());
    if (!now_without_skew) return tl::make_unexpected(now_without_skew.error());
    if (*now_with_skew < 0 ||
        static_cast<std::uint64_t>(*now_with_skew) < certificate->valid_after) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_identity_not_yet_valid,
                                         "SSH identity is not yet valid"));
    }
    if (*now_without_skew >= 0 &&
        static_cast<std::uint64_t>(*now_without_skew) >= certificate->valid_before) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_identity_expired,
                                         "SSH identity has expired"));
    }
    if (core->credential_valid_until_unix < 0) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_identity_expired,
                                         "credential boundary is not an SSH timestamp"));
    }
    std::uint64_t boundary = static_cast<std::uint64_t>(core->credential_valid_until_unix);
    if (carrier_policy.maximum_identity_lifetime_seconds > 0) {
        const auto lifetime = static_cast<std::uint64_t>(
            carrier_policy.maximum_identity_lifetime_seconds);
        if (certificate->valid_after > std::numeric_limits<std::uint64_t>::max() - lifetime) {
            return tl::make_unexpected(error(ParseErrorKind::ssh_certificate_invalid,
                                             "SSH identity policy overflows"));
        }
        boundary = std::min(boundary, certificate->valid_after + lifetime);
    }
    if (certificate->valid_before > boundary) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_identity_expired,
                                         "SSH identity exceeds authenticated boundary"));
    }
    const auto required_principal = principal(*core,
                                              carrier_policy.certificate_principal_claim);
    if (!required_principal) return tl::make_unexpected(required_principal.error());
    if (certificate->principals.size() != 1U ||
        certificate->principals.front() != *required_principal) {
        return tl::make_unexpected(error(ParseErrorKind::ssh_principal_invalid,
                                         "SSH carrier principal mismatch"));
    }
    const auto account = accounts.find(std::string(input.requested_user));
    if (input.requested_user.empty() || account == accounts.end() ||
        !std::any_of(account->second.begin(), account->second.end(),
                     [&core, &certificate](const AccountRule& rule) {
                         return account_rule_matches(rule, *core,
                                                     certificate->permission_extensions);
                     })) {
        return tl::make_unexpected(error(ParseErrorKind::account_unauthorized,
                                         "no account rule authorizes the verified identity"));
    }
    const std::string ca_type = core->caller_key.algorithm == CallerAlgorithm::es256
                                    ? std::string(kEcdsaKey)
                                    : std::string(kEd25519Key);
    return CarrierResult{std::move(*core), *required_principal, ca_type,
                         encode_base64(certificate->signature_key)};
}

}  // namespace credbind::direct
