// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_DIRECT_VERIFIER_HPP
#define CREDBIND_DIRECT_VERIFIER_HPP

#include "issuer_verifier.hpp"
#include "jwks.hpp"
#include "openssh_certificate.hpp"
#include "parse_error.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::direct {

constexpr const char* kSerializationProfile = "general-jws-json-v1";
constexpr const char* kCarrierProfile = "ssh-certificate-v1";
constexpr const char* kServerProfile = "openssh-authorized-keys-command-v1";

enum class CallerAlgorithm { es256, ed25519 };

struct CallerKey {
    CallerAlgorithm algorithm;
    std::vector<std::uint8_t> canonical_public_key;
};

struct CoreLimits {
    std::size_t max_token_bytes = 32768U;
    std::size_t max_evidence_bytes = 16384U;
};

struct CorePolicy {
    std::unordered_set<std::string> caller_algorithms;
    issuer::Policy issuer_policy;
    CoreLimits limits{};
};

struct CoreResult {
    std::string issuer;
    issuer::Claims claims;
    CallerKey caller_key;
    std::string binding_profile;
    std::string evidence_profile;
    std::string commitment;
    std::int64_t credential_valid_until_unix;
};

using CoreVerificationResult = tl::expected<CoreResult, ParseError>;

[[nodiscard]] CoreVerificationResult verify_token(std::string_view token,
                                                   const CorePolicy& policy,
                                                   const jwks::StaticJwks& keys,
                                                   std::int64_t verification_time_unix);

struct CarrierPolicy {
    std::string certificate_principal_claim;
    std::int64_t maximum_identity_lifetime_seconds = 0;
    std::int64_t clock_skew_seconds = 0;
};

struct AccountRule {
    std::string issuer;
    std::vector<issuer::Predicate> all;
    std::unordered_set<std::string> allowed_certificate_extensions;
};

using AccountPolicies = std::unordered_map<std::string, std::vector<AccountRule>>;

struct CarrierInput {
    std::string_view certificate_blob;
    std::string_view key_type_argument;
    std::string_view requested_user;
    std::int64_t verification_time_unix;
};

struct CarrierResult {
    CoreResult core;
    std::string principal;
    std::string ca_key_type;
    std::string ca_public_key_base64;
};

struct CarrierAuditContext {
    bool core_verified = false;
    CoreResult core;
};

using CarrierVerificationResult = tl::expected<CarrierResult, ParseError>;

[[nodiscard]] CarrierVerificationResult verify_carrier(
    const CarrierInput& input, const CorePolicy& core_policy,
    const CarrierPolicy& carrier_policy, const AccountPolicies& accounts,
    const jwks::StaticJwks& keys,
    openssh::Limits limits = {}, CarrierAuditContext* audit_context = nullptr);

}  // namespace credbind::direct

#endif
