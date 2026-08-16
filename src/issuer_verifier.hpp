// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_ISSUER_VERIFIER_HPP
#define CREDBIND_ISSUER_VERIFIER_HPP

#include "crypto.hpp"
#include "jwks.hpp"
#include "parse_error.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::issuer {

constexpr const char* kStandardEvidence = "standard-jws-v1";
constexpr const char* kGqEvidence = "gq-rs256-v1";
constexpr const char* kOidcNonceBinding = "oidc-nonce-v1";
constexpr const char* kAudienceBinding = "audience-v1";
constexpr const char* kCredBindClaimBinding = "credbind-claim-v1";

using ClaimValue = nlohmann::json;
using Claims = std::unordered_map<std::string, ClaimValue>;

enum class PredicateOperation { string_equals, string_one_of, string_array_contains };

struct Predicate {
    std::string claim;
    PredicateOperation operation;
    std::string value;
    std::vector<std::string> values;
};

struct Policy {
    std::string issuer;
    std::unordered_set<std::string> audiences;
    std::unordered_set<std::string> authorized_parties;
    std::unordered_set<std::string> issuer_algorithms;
    std::unordered_set<std::string> evidence_profiles;
    std::unordered_set<std::string> binding_profiles;
    bool require_non_reconstructible_evidence = false;
    std::int64_t maximum_credential_age_seconds = 0;
    std::int64_t clock_skew_seconds = 0;
    std::vector<Predicate> required_claims;
    std::unordered_set<std::string> admitted_claims;
};

struct VerificationInput {
    std::string evidence_profile;
    std::string binding_profile;
    std::string commitment;
    std::string issuer_encoded_payload;
    std::vector<std::uint8_t> evidence_representation;
    std::int64_t verification_time_unix;
};

struct VerificationResult {
    std::string issuer;
    std::string issuer_key_id;
    std::string binding_profile;
    Claims claims;
    std::int64_t credential_valid_until_unix;
    crypto::Sha256Digest verified_evidence_digest;
};

using Result = tl::expected<VerificationResult, ParseError>;

using ClaimValidationResult = tl::expected<std::int64_t, ParseError>;

// Validate claims only after an issuer-signature boundary has authenticated them.
// This is also the language-neutral seam used by conformance mutations that
// require re-signed synthetic credentials, whose private keys are deliberately
// absent from the published corpus.
[[nodiscard]] ClaimValidationResult validate_authenticated_claims(
    const VerificationInput& input, const Policy& policy, const Claims& claims);

[[nodiscard]] Result verify(const VerificationInput& input, const Policy& policy,
                            const jwks::StaticJwks& keys);

}  // namespace credbind::issuer

#endif
