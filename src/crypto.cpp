// SPDX-License-Identifier: Apache-2.0

#include "crypto.hpp"

#include "base64url.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

namespace credbind::crypto {
namespace {

constexpr std::uint32_t kRsaExponent = 65537U;
constexpr std::size_t kGqRounds = 8U;
constexpr std::size_t kMaximumEvidenceBytes = 16384U;
constexpr std::string_view kGqProfile = "gq-rs256-v1";
constexpr std::string_view kHashSuite = "credbind-sha256-v1";
constexpr std::array<std::uint8_t, 19> kSha256DigestInfoPrefix{
    0x30U, 0x31U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U,
    0x65U, 0x03U, 0x04U, 0x02U, 0x01U, 0x05U, 0x00U, 0x04U, 0x20U};

using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using BnContextPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using ParamBuilderPtr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using ParamsPtr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;

ParseError evidence_error(std::string message) {
    return ParseError{ParseErrorKind::evidence_invalid, std::move(message)};
}

ParseError signature_error(std::string message) {
    return ParseError{ParseErrorKind::issuer_signature_invalid, std::move(message)};
}

BnPtr make_bn(const std::vector<std::uint8_t>& encoded) {
    if (encoded.empty() || encoded.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return BnPtr(nullptr, BN_free);
    }
    return BnPtr(BN_bin2bn(encoded.data(), static_cast<int>(encoded.size()), nullptr), BN_free);
}

BnPtr make_word(std::uint32_t value) {
    BnPtr result(BN_new(), BN_free);
    if (!result || BN_set_word(result.get(), static_cast<BN_ULONG>(value)) != 1) {
        return BnPtr(nullptr, BN_free);
    }
    return result;
}

tl::expected<PkeyPtr, ParseError> make_rsa_key(const RsaPublicKey& key,
                                               ParseErrorKind error_kind) {
    if (key.modulus.empty() || key.modulus.front() == 0U || key.exponent != kRsaExponent) {
        return tl::make_unexpected(ParseError{error_kind, "ineligible RSA public key"});
    }
    auto modulus = make_bn(key.modulus);
    auto exponent = make_word(key.exponent);
    if (!modulus || !exponent || BN_num_bits(modulus.get()) < 2048) {
        return tl::make_unexpected(ParseError{error_kind, "ineligible RSA public key"});
    }
    ParamBuilderPtr builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!builder || OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_N, modulus.get()) != 1 ||
        OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_E, exponent.get()) != 1) {
        return tl::make_unexpected(ParseError{error_kind, "could not construct RSA parameters"});
    }
    ParamsPtr parameters(OSSL_PARAM_BLD_to_param(builder.get()), OSSL_PARAM_free);
    PkeyContextPtr context(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw_key = nullptr;
    if (!parameters || !context || EVP_PKEY_fromdata_init(context.get()) <= 0 ||
        EVP_PKEY_fromdata(context.get(), &raw_key, EVP_PKEY_PUBLIC_KEY, parameters.get()) <= 0 ||
        raw_key == nullptr) {
        EVP_PKEY_free(raw_key);
        return tl::make_unexpected(ParseError{error_kind, "could not construct RSA public key"});
    }
    return PkeyPtr(raw_key, EVP_PKEY_free);
}

tl::expected<std::array<std::uint8_t, 32>, ParseError> sha256(
    const std::uint8_t* data, std::size_t size) {
    std::array<std::uint8_t, 32> digest{};
    std::size_t written = 0U;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, data, size, digest.data(), &written) != 1 ||
        written != digest.size()) {
        return tl::make_unexpected(evidence_error("SHA-256 operation failed"));
    }
    return digest;
}

tl::expected<std::array<std::uint8_t, 32>, ParseError> sha256(std::string_view value) {
    return sha256(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
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

class Reader final {
  public:
    explicit Reader(const std::vector<std::uint8_t>& input) : input_(input) {}

    tl::expected<std::uint32_t, ParseError> u32() {
        if (input_.size() - offset_ < 4U) {
            return tl::make_unexpected(evidence_error("truncated GQ uint32"));
        }
        std::uint32_t value = 0U;
        for (std::size_t index = 0U; index < 4U; ++index) {
            value = (value << 8U) | input_[offset_ + index];
        }
        offset_ += 4U;
        return value;
    }

    tl::expected<std::uint64_t, ParseError> u64() {
        if (input_.size() - offset_ < 8U) {
            return tl::make_unexpected(evidence_error("truncated GQ uint64"));
        }
        std::uint64_t value = 0U;
        for (std::size_t index = 0U; index < 8U; ++index) {
            value = (value << 8U) | input_[offset_ + index];
        }
        offset_ += 8U;
        return value;
    }

    tl::expected<std::vector<std::uint8_t>, ParseError> value(std::size_t maximum,
                                                              std::string_view field) {
        const auto length = u64();
        if (!length || *length == 0U || *length > static_cast<std::uint64_t>(maximum) ||
            *length > static_cast<std::uint64_t>(input_.size() - offset_)) {
            return tl::make_unexpected(
                !length ? length.error() : evidence_error(std::string("invalid ") + std::string(field)));
        }
        const auto size = static_cast<std::size_t>(*length);
        std::vector<std::uint8_t> result(input_.begin() + static_cast<std::ptrdiff_t>(offset_),
                                         input_.begin() + static_cast<std::ptrdiff_t>(offset_ + size));
        offset_ += size;
        return result;
    }

    [[nodiscard]] bool empty() const { return offset_ == input_.size(); }

  private:
    const std::vector<std::uint8_t>& input_;
    std::size_t offset_ = 0U;
};

struct Round {
    BnPtr commitment{nullptr, BN_free};
    BnPtr response{nullptr, BN_free};
    std::vector<std::uint8_t> encoded_commitment;
};

tl::expected<BnPtr, ParseError> canonical_integer(const std::vector<std::uint8_t>& encoded,
                                                  const BIGNUM* modulus) {
    if (encoded.empty() || encoded.front() == 0U) {
        return tl::make_unexpected(evidence_error("non-canonical GQ integer"));
    }
    auto value = make_bn(encoded);
    if (!value || BN_is_zero(value.get()) == 1 || BN_is_negative(value.get()) == 1 ||
        BN_cmp(value.get(), modulus) >= 0) {
        return tl::make_unexpected(evidence_error("GQ integer outside modulus"));
    }
    return value;
}

tl::expected<std::vector<std::uint8_t>, ParseError> encoded_message(
    std::size_t modulus_size, std::string_view signing_input) {
    const auto digest = sha256(signing_input);
    if (!digest) {
        return tl::make_unexpected(digest.error());
    }
    const auto digest_info_size = kSha256DigestInfoPrefix.size() + digest->size();
    if (modulus_size < digest_info_size + 11U) {
        return tl::make_unexpected(evidence_error("RSA modulus is too small"));
    }
    const auto padding_size = modulus_size - digest_info_size - 3U;
    std::vector<std::uint8_t> result;
    result.reserve(modulus_size);
    result.push_back(0U);
    result.push_back(1U);
    result.insert(result.end(), padding_size, 0xffU);
    result.push_back(0U);
    result.insert(result.end(), kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end());
    result.insert(result.end(), digest->begin(), digest->end());
    return result;
}

tl::expected<std::uint32_t, ParseError> challenge(
    const std::array<std::uint8_t, 32>& transcript_hash, std::uint32_t round) {
    for (std::uint32_t retry = 0U;; ++retry) {
        std::vector<std::uint8_t> input;
        constexpr std::string_view label = "CredBind-GQ-Challenge-v1";
        input.insert(input.end(), label.begin(), label.end());
        input.push_back(0U);
        append_u64(input, transcript_hash.size());
        input.insert(input.end(), transcript_hash.begin(), transcript_hash.end());
        append_u32(input, round);
        append_u32(input, retry);
        const auto digest = sha256(input.data(), input.size());
        if (!digest) {
            return tl::make_unexpected(digest.error());
        }
        const auto candidate =
            ((static_cast<std::uint32_t>((*digest)[0]) << 16U) |
             (static_cast<std::uint32_t>((*digest)[1]) << 8U) |
             static_cast<std::uint32_t>((*digest)[2])) >>
            7U;
        if (candidate <= 65536U) {
            return candidate;
        }
        if (retry == std::numeric_limits<std::uint32_t>::max()) {
            return tl::make_unexpected(evidence_error("GQ challenge retry exhausted"));
        }
    }
}

}  // namespace

VerificationResult verify_rs256(std::string_view signing_input,
                                 const std::vector<std::uint8_t>& signature,
                                 const RsaPublicKey& key) {
    const auto public_key = make_rsa_key(key, ParseErrorKind::issuer_signature_invalid);
    if (!public_key || signature.size() != key.modulus.size()) {
        return tl::make_unexpected(!public_key ? public_key.error()
                                               : signature_error("wrong RS256 signature length"));
    }
    MdContextPtr digest_context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* key_context = nullptr;
    if (!digest_context ||
        EVP_DigestVerifyInit(digest_context.get(), &key_context, EVP_sha256(), nullptr,
                             public_key->get()) != 1 ||
        key_context == nullptr || EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PADDING) <= 0) {
        return tl::make_unexpected(signature_error("RS256 verification setup failed"));
    }
    const auto result = EVP_DigestVerify(
        digest_context.get(), signature.data(), signature.size(),
        reinterpret_cast<const std::uint8_t*>(signing_input.data()), signing_input.size());
    if (result != 1) {
        return tl::make_unexpected(signature_error("RS256 signature verification failed"));
    }
    return {};
}

VerificationResult verify_gq_rs256(
    std::string_view encoded_payload, std::string_view encoded_commitment,
    std::string_view authenticated_issuer, const std::vector<std::uint8_t>& evidence,
    const RsaPublicKey& key) {
    if (evidence.size() > kMaximumEvidenceBytes) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::resource_limit, "GQ evidence exceeds protocol bound"});
    }
    const auto public_key = make_rsa_key(key, ParseErrorKind::evidence_invalid);
    if (!public_key) {
        return tl::make_unexpected(public_key.error());
    }
    auto modulus = make_bn(key.modulus);
    auto exponent = make_word(key.exponent);
    if (!modulus || !exponent) {
        return tl::make_unexpected(evidence_error("could not initialize GQ key"));
    }

    Reader reader(evidence);
    const auto header_bytes = reader.value(32768U, "GQ issuer header");
    if (!header_bytes) {
        return tl::make_unexpected(header_bytes.error());
    }
    const std::string header(header_bytes->begin(), header_bytes->end());
    if (!base64url::decode(header, 32768U)) {
        return tl::make_unexpected(evidence_error("invalid GQ issuer header"));
    }
    const auto round_count = reader.u32();
    if (!round_count || *round_count != static_cast<std::uint32_t>(kGqRounds)) {
        return tl::make_unexpected(!round_count ? round_count.error()
                                                 : evidence_error("wrong GQ round count"));
    }
    std::vector<Round> rounds;
    rounds.reserve(kGqRounds);
    for (std::size_t index = 0U; index < kGqRounds; ++index) {
        auto encoded_commitment_value = reader.value(key.modulus.size(), "GQ commitment");
        auto encoded_response = reader.value(key.modulus.size(), "GQ response");
        if (!encoded_commitment_value || !encoded_response) {
            return tl::make_unexpected(!encoded_commitment_value ? encoded_commitment_value.error()
                                                                   : encoded_response.error());
        }
        auto commitment_value = canonical_integer(*encoded_commitment_value, modulus.get());
        auto response = canonical_integer(*encoded_response, modulus.get());
        if (!commitment_value || !response) {
            return tl::make_unexpected(!commitment_value ? commitment_value.error()
                                                         : response.error());
        }
        rounds.push_back(Round{std::move(*commitment_value), std::move(*response),
                               std::move(*encoded_commitment_value)});
    }
    if (!reader.empty()) {
        return tl::make_unexpected(evidence_error("trailing GQ evidence"));
    }

    const std::string signing_input = header + "." + std::string(encoded_payload);
    const auto em = encoded_message(key.modulus.size(), signing_input);
    if (!em) {
        return tl::make_unexpected(em.error());
    }
    auto message = make_bn(*em);
    if (!message || BN_cmp(message.get(), modulus.get()) >= 0) {
        return tl::make_unexpected(evidence_error("invalid GQ encoded message"));
    }

    std::vector<std::uint8_t> transcript;
    constexpr std::string_view transcript_label = "CredBind-GQ-Transcript-v1";
    transcript.insert(transcript.end(), transcript_label.begin(), transcript_label.end());
    transcript.push_back(0U);
    append_value(transcript, kGqProfile);
    append_value(transcript, kHashSuite);
    append_value(transcript, header);
    append_value(transcript, encoded_payload);
    append_value(transcript, encoded_commitment);
    append_value(transcript, authenticated_issuer);
    append_value(transcript, key.modulus);
    std::vector<std::uint8_t> encoded_exponent;
    bool started = false;
    for (unsigned int shift : {24U, 16U, 8U, 0U}) {
        const auto octet = static_cast<std::uint8_t>(key.exponent >> shift);
        if (octet != 0U || started) {
            encoded_exponent.push_back(octet);
            started = true;
        }
    }
    append_value(transcript, encoded_exponent);
    append_value(transcript, *em);
    append_u32(transcript, static_cast<std::uint32_t>(kGqRounds));
    for (const auto& round : rounds) {
        append_value(transcript, round.encoded_commitment);
    }
    const auto transcript_hash = sha256(transcript.data(), transcript.size());
    if (!transcript_hash) {
        return tl::make_unexpected(transcript_hash.error());
    }

    BnContextPtr bn_context(BN_CTX_new(), BN_CTX_free);
    if (!bn_context) {
        return tl::make_unexpected(evidence_error("could not initialize GQ arithmetic"));
    }
    for (std::size_t index = 0U; index < rounds.size(); ++index) {
        const auto derived = challenge(*transcript_hash, static_cast<std::uint32_t>(index));
        auto challenge_bn = derived ? make_word(*derived) : BnPtr(nullptr, BN_free);
        BnPtr left(BN_new(), BN_free);
        BnPtr message_power(BN_new(), BN_free);
        BnPtr right(BN_new(), BN_free);
        if (!derived || !challenge_bn || !left || !message_power || !right ||
            BN_mod_exp(left.get(), rounds[index].response.get(), exponent.get(), modulus.get(),
                       bn_context.get()) != 1 ||
            BN_mod_exp(message_power.get(), message.get(), challenge_bn.get(), modulus.get(),
                       bn_context.get()) != 1 ||
            BN_mod_mul(right.get(), rounds[index].commitment.get(), message_power.get(),
                       modulus.get(), bn_context.get()) != 1 ||
            BN_cmp(left.get(), right.get()) != 0) {
            return tl::make_unexpected(evidence_error("GQ proof equation failed"));
        }
    }
    return {};
}

}  // namespace credbind::crypto
