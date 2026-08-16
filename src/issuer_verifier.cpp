// SPDX-License-Identifier: Apache-2.0

#include "issuer_verifier.hpp"

#include "base64url.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace credbind::issuer {
namespace {

using Json = nlohmann::json;

constexpr std::size_t kMaximumJsonBytes = 32768U;
constexpr std::size_t kMaximumEvidenceBytes = 16384U;
constexpr std::size_t kMaximumJsonDepth = 32U;
constexpr std::size_t kMaximumJsonMembers = 4096U;
constexpr std::size_t kMaximumJsonValues = 4096U;
constexpr std::size_t kMaximumJsonKeyBytes = 256U;
constexpr double kMaximumExactJsonInteger = 9007199254740991.0;

ParseError error(ParseErrorKind kind, std::string message) {
    return ParseError{kind, std::move(message)};
}

enum class ContextKind { object, array };

struct Context {
    ContextKind kind;
    bool root = false;
    std::unordered_set<std::string> members;
    std::string pending_name;
    bool has_pending_name = false;
    Json value;
};

class ObjectSax final : public nlohmann::json_sax<Json> {
  public:
    bool null() override { return scalar(nullptr); }
    bool boolean(bool value) override { return scalar(value); }
    bool number_integer(number_integer_t value) override { return scalar(value); }
    bool number_unsigned(number_unsigned_t value) override { return scalar(value); }
    bool number_float(number_float_t value, const string_t&) override {
        if (!std::isfinite(value)) {
            return fail(ParseErrorKind::malformed_input, "non-finite issuer JSON number");
        }
        return scalar(value);
    }
    bool string(string_t& value) override { return scalar(std::move(value)); }
    bool binary(binary_t&) override {
        return fail(ParseErrorKind::malformed_input, "binary JSON value is unsupported");
    }

    bool start_object(std::size_t) override {
        if (!count_value()) {
            return false;
        }
        if (stack_.empty()) {
            stack_.push_back(
                Context{ContextKind::object, true, {}, {}, false, Json::object()});
            return true;
        }
        if (stack_.size() + 1U > kMaximumJsonDepth || !container_parent_ready()) {
            return false;
        }
        stack_.push_back(
            Context{ContextKind::object, false, {}, {}, false, Json::object()});
        return true;
    }

    bool key(string_t& value) override {
        if (stack_.empty() || stack_.back().kind != ContextKind::object) {
            return fail(ParseErrorKind::malformed_input, "JSON member outside object");
        }
        ++members_;
        if (members_ > kMaximumJsonMembers || value.size() > kMaximumJsonKeyBytes) {
            return fail(ParseErrorKind::resource_limit, "issuer JSON member bound");
        }
        auto& context = stack_.back();
        if (!context.members.insert(value).second) {
            return fail(ParseErrorKind::malformed_input, "duplicate issuer JSON member");
        }
        context.pending_name = std::move(value);
        context.has_pending_name = true;
        return true;
    }

    bool end_object() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::object ||
            stack_.back().has_pending_name) {
            return fail(ParseErrorKind::malformed_input, "unexpected issuer JSON object end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        if (context.root) {
            root_complete_ = true;
            for (auto& item : context.value.items()) {
                object_.emplace(item.key(), std::move(item.value()));
            }
            return true;
        }
        return attach_value(std::move(context.value));
    }

    bool start_array(std::size_t) override {
        if (stack_.empty()) {
            return fail(ParseErrorKind::malformed_input,
                        "issuer JSON root is not an object");
        }
        if (!count_value() || stack_.size() + 1U > kMaximumJsonDepth ||
            !container_parent_ready()) {
            return false;
        }
        stack_.push_back(
            Context{ContextKind::array, false, {}, {}, false, Json::array()});
        return true;
    }

    bool end_array() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::array) {
            return fail(ParseErrorKind::malformed_input, "unexpected issuer JSON array end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        return attach_value(std::move(context.value));
    }

    bool parse_error(std::size_t, const std::string&,
                     const nlohmann::detail::exception&) override {
        return fail(ParseErrorKind::malformed_input, "invalid strict issuer JSON");
    }

    [[nodiscard]] bool has_error() const noexcept { return failed_; }
    [[nodiscard]] bool complete() const noexcept { return root_complete_ && stack_.empty(); }
    [[nodiscard]] const ParseError& parse_failure() const noexcept { return error_; }
    [[nodiscard]] Claims take_object() { return std::move(object_); }

  private:
    template <typename Value>
    bool scalar(Value value) {
        if (!count_value() || stack_.empty()) {
            return false;
        }
        return attach_value(Json(std::move(value)));
    }

    bool attach_value(Json value) {
        auto& context = stack_.back();
        if (context.kind == ContextKind::object) {
            if (!context.has_pending_name) {
                return fail(ParseErrorKind::malformed_input, "issuer JSON scalar has no member");
            }
            context.value[std::move(context.pending_name)] = std::move(value);
            context.pending_name.clear();
            context.has_pending_name = false;
        } else {
            context.value.push_back(std::move(value));
        }
        return true;
    }

    bool container_parent_ready() {
        auto& parent = stack_.back();
        if (parent.kind == ContextKind::object && !parent.has_pending_name) {
            return fail(ParseErrorKind::malformed_input,
                        "issuer JSON container has no member");
        }
        return true;
    }

    bool count_value() {
        ++values_;
        if (values_ > kMaximumJsonValues) {
            return fail(ParseErrorKind::resource_limit, "issuer JSON value bound");
        }
        return true;
    }

    bool fail(ParseErrorKind kind, std::string message) {
        if (!failed_) {
            error_ = error(kind, std::move(message));
            failed_ = true;
        }
        return false;
    }

    std::vector<Context> stack_;
    Claims object_;
    ParseError error_{ParseErrorKind::malformed_input, "issuer JSON parse failed"};
    std::size_t members_ = 0U;
    std::size_t values_ = 0U;
    bool root_complete_ = false;
    bool failed_ = false;
};

tl::expected<Claims, ParseError> parse_object(std::string_view input) {
    if (input.size() > kMaximumJsonBytes) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "issuer JSON exceeds byte bound"));
    }
    ObjectSax handler;
    const bool parsed = Json::sax_parse(input.begin(), input.end(), &handler,
                                        Json::input_format_t::json, true, false);
    if (!parsed || handler.has_error() || !handler.complete()) {
        return tl::make_unexpected(handler.parse_failure());
    }
    return handler.take_object();
}

const std::string* string_claim(const Claims& claims, std::string_view name) {
    const auto iterator = claims.find(std::string(name));
    if (iterator == claims.end() || !iterator->second.is_string()) {
        return nullptr;
    }
    return &iterator->second.get_ref<const std::string&>();
}

std::optional<std::int64_t> integer_claim(const Claims& claims, std::string_view name) {
    const auto iterator = claims.find(std::string(name));
    if (iterator == claims.end()) {
        return std::nullopt;
    }
    const auto& value = iterator->second;
    if (value.is_number_unsigned()) {
        const auto number = value.get<std::uint64_t>();
        if (number <= 9007199254740991ULL) {
            return static_cast<std::int64_t>(number);
        }
    } else if (value.is_number_integer()) {
        const auto number = value.get<std::int64_t>();
        if (number >= -9007199254740991LL && number <= 9007199254740991LL) {
            return number;
        }
    } else if (value.is_number_float()) {
        const auto number = value.get<double>();
        if (std::isfinite(number) && std::trunc(number) == number &&
            number >= -kMaximumExactJsonInteger && number <= kMaximumExactJsonInteger) {
            return static_cast<std::int64_t>(number);
        }
    }
    return std::nullopt;
}

struct Header {
    std::string algorithm;
    std::string kid;
};

tl::expected<Header, ParseError> parse_header(std::string_view encoded) {
    const auto decoded = base64url::decode(encoded, kMaximumJsonBytes);
    if (!decoded) {
        return tl::make_unexpected(decoded.error());
    }
    const std::string json(decoded->begin(), decoded->end());
    const auto object = parse_object(json);
    if (!object) {
        return tl::make_unexpected(object.error());
    }
    for (const std::string_view prohibited : {"jku", "x5u", "jwk", "x5c"}) {
        if (object->find(std::string(prohibited)) != object->end()) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_untrusted, "token-supplied issuer key reference"));
        }
    }
    if (object->find("crit") != object->end()) {
        return tl::make_unexpected(
            error(ParseErrorKind::unsupported_profile, "issuer critical parameters unsupported"));
    }
    const auto algorithm = string_claim(*object, "alg");
    const auto kid = string_claim(*object, "kid");
    if (algorithm == nullptr || kid == nullptr || algorithm->empty() || kid->empty()) {
        return tl::make_unexpected(
            error(ParseErrorKind::malformed_input, "issuer alg or kid is absent"));
    }
    return Header{*algorithm, *kid};
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

void append_value(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& value) {
    append_u64(output, static_cast<std::uint64_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

struct StandardEvidence {
    std::string header;
    std::vector<std::uint8_t> signature;
};

tl::expected<std::string, ParseError> read_text(const std::vector<std::uint8_t>& input,
                                                std::size_t& offset) {
    if (input.size() - offset < 8U) {
        return tl::make_unexpected(
            error(ParseErrorKind::malformed_input, "truncated standard evidence length"));
    }
    std::uint64_t length = 0U;
    for (std::size_t index = 0U; index < 8U; ++index) {
        length = (length << 8U) | input[offset + index];
    }
    offset += 8U;
    if (length == 0U || length > static_cast<std::uint64_t>(input.size() - offset) ||
        length > static_cast<std::uint64_t>(kMaximumJsonBytes)) {
        return tl::make_unexpected(
            error(ParseErrorKind::malformed_input, "invalid standard evidence length"));
    }
    const auto size = static_cast<std::size_t>(length);
    const std::string value(input.begin() + static_cast<std::ptrdiff_t>(offset),
                            input.begin() + static_cast<std::ptrdiff_t>(offset + size));
    offset += size;
    return value;
}

tl::expected<StandardEvidence, ParseError> parse_standard(
    const std::vector<std::uint8_t>& representation) {
    std::size_t offset = 0U;
    const auto header = read_text(representation, offset);
    if (!header) {
        return tl::make_unexpected(header.error());
    }
    const auto encoded_signature = read_text(representation, offset);
    if (!encoded_signature) {
        return tl::make_unexpected(encoded_signature.error());
    }
    if (offset != representation.size()) {
        return tl::make_unexpected(
            error(ParseErrorKind::malformed_input, "trailing standard evidence"));
    }
    const auto signature = base64url::decode(*encoded_signature, 1024U);
    if (!signature) {
        return tl::make_unexpected(signature.error());
    }
    return StandardEvidence{*header, *signature};
}

tl::expected<std::string, ParseError> gq_header(
    const std::vector<std::uint8_t>& representation) {
    std::size_t offset = 0U;
    const auto header = read_text(representation, offset);
    if (!header) {
        return tl::make_unexpected(
            error(ParseErrorKind::evidence_invalid, "invalid GQ header framing"));
    }
    return header;
}

bool set_contains(const std::unordered_set<std::string>& values, std::string_view value) {
    return values.find(std::string(value)) != values.end();
}

tl::expected<void, ParseError> validate_policy(const VerificationInput& input,
                                               const Policy& policy) {
    if (policy.issuer.size() < 9U || policy.issuer.compare(0U, 8U, "https://") != 0 ||
        policy.audiences.empty() || policy.issuer_algorithms.empty() ||
        policy.evidence_profiles.empty() || policy.binding_profiles.empty() ||
        policy.clock_skew_seconds < 0 || policy.maximum_credential_age_seconds < 0) {
        return tl::make_unexpected(
            error(ParseErrorKind::issuer_untrusted, "invalid trusted issuer policy"));
    }
    if ((input.evidence_profile != kStandardEvidence && input.evidence_profile != kGqEvidence) ||
        !set_contains(policy.evidence_profiles, input.evidence_profile) ||
        (policy.require_non_reconstructible_evidence &&
         input.evidence_profile == kStandardEvidence)) {
        return tl::make_unexpected(
            error(ParseErrorKind::unsupported_profile, "evidence profile is not permitted"));
    }
    if ((input.binding_profile != kOidcNonceBinding &&
         input.binding_profile != kAudienceBinding &&
         input.binding_profile != kCredBindClaimBinding) ||
        !set_contains(policy.binding_profiles, input.binding_profile)) {
        return tl::make_unexpected(
            error(ParseErrorKind::unsupported_profile, "binding profile is not permitted"));
    }
    for (const auto& predicate : policy.required_claims) {
        if (predicate.claim.empty() ||
            (predicate.operation == PredicateOperation::string_equals &&
             !predicate.values.empty()) ||
            (predicate.operation == PredicateOperation::string_one_of &&
             (predicate.values.empty() || !predicate.value.empty())) ||
            (predicate.operation == PredicateOperation::string_array_contains &&
             !predicate.values.empty())) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_untrusted, "invalid required-claim policy"));
        }
        if (predicate.operation == PredicateOperation::string_one_of) {
            std::unordered_set<std::string> unique;
            for (const auto& value : predicate.values) {
                if (value.empty() || !unique.insert(value).second) {
                    return tl::make_unexpected(
                        error(ParseErrorKind::issuer_untrusted,
                              "invalid required-claim one-of policy"));
                }
            }
        }
    }
    return {};
}

bool audience_allowed(const ClaimValue& value,
                      const std::unordered_set<std::string>& allowed) {
    if (value.is_string()) {
        return set_contains(allowed, value.get_ref<const std::string&>());
    }
    if (!value.is_array() || value.empty()) {
        return false;
    }
    std::unordered_set<std::string> seen;
    bool matched = false;
    for (const auto& item : value) {
        if (!item.is_string()) {
            return false;
        }
        const auto& text = item.get_ref<const std::string&>();
        if (!seen.insert(text).second) {
            return false;
        }
        matched = matched || set_contains(allowed, text);
    }
    return matched;
}

bool exact_audience(const ClaimValue& value, std::string_view commitment) {
    if (value.is_string()) {
        return value.get_ref<const std::string&>() == commitment;
    }
    return value.is_array() && value.size() == 1U && value.front().is_string() &&
           value.front().get_ref<const std::string&>() == commitment;
}

bool predicate_matches(const Claims& claims, const Predicate& predicate) {
    const auto iterator = claims.find(predicate.claim);
    if (iterator == claims.end() || predicate.claim.empty()) {
        return false;
    }
    if (predicate.operation == PredicateOperation::string_array_contains) {
        if (!iterator->second.is_array()) {
            return false;
        }
        return std::any_of(iterator->second.begin(), iterator->second.end(),
                           [&predicate](const Json& value) {
                               return value.is_string() &&
                                      value.get_ref<const std::string&>() == predicate.value;
                           });
    }
    if (!iterator->second.is_string()) {
        return false;
    }
    const auto& text = iterator->second.get_ref<const std::string&>();
    if (predicate.operation == PredicateOperation::string_equals) {
        return text == predicate.value;
    }
    return std::find(predicate.values.begin(), predicate.values.end(), text) !=
           predicate.values.end();
}

tl::expected<std::int64_t, ParseError> checked_add(std::int64_t left,
                                                  std::int64_t right) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return tl::make_unexpected(
            error(ParseErrorKind::issuer_claims_invalid, "NumericDate arithmetic overflow"));
    }
    return left + right;
}

tl::expected<std::int64_t, ParseError> validate_claims(const VerificationInput& input,
                                                       const Policy& policy,
                                                       const Claims& claims) {
    const auto issuer = string_claim(claims, "iss");
    if (issuer == nullptr || *issuer != policy.issuer) {
        return tl::make_unexpected(
            error(ParseErrorKind::issuer_claims_invalid, "issuer claim mismatch"));
    }
    const auto audience = claims.find("aud");
    if (input.binding_profile == kOidcNonceBinding) {
        const auto nonce = string_claim(claims, "nonce");
        if (nonce == nullptr || *nonce != input.commitment) {
            return tl::make_unexpected(
                error(ParseErrorKind::binding_invalid, "OIDC nonce binding mismatch"));
        }
        if (audience == claims.end() || !audience_allowed(audience->second, policy.audiences)) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_claims_invalid, "issuer audience mismatch"));
        }
    } else if (input.binding_profile == kAudienceBinding) {
        if (audience == claims.end() || !exact_audience(audience->second, input.commitment)) {
            return tl::make_unexpected(
                error(ParseErrorKind::binding_invalid, "workload audience binding mismatch"));
        }
    } else {
        const auto bound = string_claim(claims, "https://credbind.dev/commitment");
        if (bound == nullptr || *bound != input.commitment) {
            return tl::make_unexpected(
                error(ParseErrorKind::binding_invalid, "workload claim binding mismatch"));
        }
        if (audience == claims.end() || !audience_allowed(audience->second, policy.audiences)) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_claims_invalid, "issuer audience mismatch"));
        }
    }
    if (!policy.authorized_parties.empty()) {
        const auto party = string_claim(claims, "azp");
        if (party == nullptr || !set_contains(policy.authorized_parties, *party)) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_claims_invalid, "authorized party mismatch"));
        }
    }
    for (const auto& predicate : policy.required_claims) {
        if (!predicate_matches(claims, predicate)) {
            return tl::make_unexpected(
                error(ParseErrorKind::issuer_claims_invalid, "required claim predicate failed"));
        }
    }
    const auto issued_at = integer_claim(claims, "iat");
    const auto expires_at = integer_claim(claims, "exp");
    if (!issued_at || !expires_at) {
        return tl::make_unexpected(
            error(ParseErrorKind::issuer_claims_invalid, "required NumericDate is absent"));
    }
    const auto now_with_skew = checked_add(input.verification_time_unix,
                                           policy.clock_skew_seconds);
    if (!now_with_skew) {
        return tl::make_unexpected(now_with_skew.error());
    }
    if (*now_with_skew < *issued_at) {
        return tl::make_unexpected(
            error(ParseErrorKind::credential_not_yet_valid, "credential is not yet valid"));
    }
    const auto not_before = integer_claim(claims, "nbf");
    if (claims.find("nbf") != claims.end() && !not_before) {
        return tl::make_unexpected(
            error(ParseErrorKind::issuer_claims_invalid, "invalid not-before NumericDate"));
    }
    if (not_before && *now_with_skew < *not_before) {
        return tl::make_unexpected(
            error(ParseErrorKind::credential_not_yet_valid, "credential is not yet valid"));
    }
    const auto now_without_skew = checked_add(input.verification_time_unix,
                                              -policy.clock_skew_seconds);
    if (!now_without_skew) {
        return tl::make_unexpected(now_without_skew.error());
    }
    if (*now_without_skew >= *expires_at) {
        return tl::make_unexpected(
            error(ParseErrorKind::credential_expired, "credential has expired"));
    }
    std::int64_t valid_until = *expires_at;
    if (policy.maximum_credential_age_seconds > 0) {
        const auto maximum_age_until = checked_add(*issued_at,
                                                   policy.maximum_credential_age_seconds);
        if (!maximum_age_until) {
            return tl::make_unexpected(maximum_age_until.error());
        }
        valid_until = std::min(valid_until, *maximum_age_until);
        if (*now_without_skew >= valid_until) {
            return tl::make_unexpected(
                error(ParseErrorKind::credential_expired, "maximum credential age exceeded"));
        }
    }
    return valid_until;
}

tl::expected<crypto::Sha256Digest, ParseError> evidence_digest(
    const VerificationInput& input) {
    std::vector<std::uint8_t> digest_input;
    constexpr std::string_view label = "CredBind-Issuer-Evidence-Digest-v1";
    digest_input.insert(digest_input.end(), label.begin(), label.end());
    digest_input.push_back(0U);
    append_value(digest_input, input.evidence_profile);
    append_value(digest_input, input.issuer_encoded_payload);
    append_value(digest_input, input.evidence_representation);
    return crypto::digest_sha256(digest_input.data(), digest_input.size());
}

}  // namespace

ClaimValidationResult validate_authenticated_claims(
    const VerificationInput& input, const Policy& policy, const Claims& claims) {
    const auto policy_result = validate_policy(input, policy);
    if (!policy_result) {
        return tl::make_unexpected(policy_result.error());
    }
    return validate_claims(input, policy, claims);
}

Result verify(const VerificationInput& input, const Policy& policy,
              const jwks::StaticJwks& keys) {
    if (input.evidence_representation.size() > kMaximumEvidenceBytes) {
        return tl::make_unexpected(
            error(ParseErrorKind::resource_limit, "evidence exceeds protocol bound"));
    }
    const auto policy_result = validate_policy(input, policy);
    if (!policy_result) {
        return tl::make_unexpected(policy_result.error());
    }
    const auto payload_bytes = base64url::decode(input.issuer_encoded_payload,
                                                 kMaximumJsonBytes);
    if (!payload_bytes) {
        return tl::make_unexpected(payload_bytes.error());
    }
    const std::string payload_json(payload_bytes->begin(), payload_bytes->end());
    const auto claims = parse_object(payload_json);
    if (!claims) {
        return tl::make_unexpected(claims.error());
    }

    std::string encoded_header;
    std::vector<std::uint8_t> standard_signature;
    if (input.evidence_profile == kStandardEvidence) {
        const auto standard = parse_standard(input.evidence_representation);
        if (!standard) {
            return tl::make_unexpected(standard.error());
        }
        encoded_header = standard->header;
        standard_signature = standard->signature;
    } else {
        const auto header = gq_header(input.evidence_representation);
        if (!header) {
            return tl::make_unexpected(header.error());
        }
        encoded_header = *header;
    }
    const auto header = parse_header(encoded_header);
    if (!header) {
        if (input.evidence_profile == kGqEvidence &&
            header.error().kind == ParseErrorKind::malformed_input) {
            return tl::make_unexpected(
                error(ParseErrorKind::evidence_invalid, "invalid GQ protected header"));
        }
        return tl::make_unexpected(header.error());
    }
    if (header->algorithm != "RS256" ||
        !set_contains(policy.issuer_algorithms, header->algorithm)) {
        return tl::make_unexpected(
            error(ParseErrorKind::unsupported_algorithm, "issuer algorithm is not permitted"));
    }
    const auto key = keys.resolve_rs256(header->kid);
    if (!key) {
        return tl::make_unexpected(key.error());
    }
    if (input.evidence_profile == kStandardEvidence) {
        const auto cryptographic = crypto::verify_rs256(
            encoded_header + "." + input.issuer_encoded_payload, standard_signature, *key);
        if (!cryptographic) {
            return tl::make_unexpected(cryptographic.error());
        }
    } else {
        const auto cryptographic = crypto::verify_gq_rs256(
            input.issuer_encoded_payload, input.commitment, policy.issuer,
            input.evidence_representation, *key);
        if (!cryptographic) {
            return tl::make_unexpected(cryptographic.error());
        }
    }
    const auto valid_until = validate_claims(input, policy, *claims);
    if (!valid_until) {
        return tl::make_unexpected(valid_until.error());
    }
    Claims admitted;
    for (const auto& name : policy.admitted_claims) {
        const auto iterator = claims->find(name);
        if (iterator != claims->end()) {
            admitted.emplace(iterator->first, iterator->second);
        }
    }
    const auto digest = evidence_digest(input);
    if (!digest) {
        return tl::make_unexpected(digest.error());
    }
    return VerificationResult{policy.issuer, header->kid, input.binding_profile,
                              std::move(admitted), *valid_until, *digest};
}

}  // namespace credbind::issuer
