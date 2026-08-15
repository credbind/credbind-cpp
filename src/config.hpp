// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_CONFIG_HPP
#define CREDBIND_CONFIG_HPP

#include "direct_verifier.hpp"
#include "jwks.hpp"
#include "parse_error.hpp"
#include "syslog_logger.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::config {

struct ResourceLimits {
    std::size_t max_token_bytes;
    std::size_t max_evidence_bytes;
    std::size_t max_ssh_certificate_bytes;
    std::size_t max_offered_key_chars;
    std::size_t max_authorized_keys_output_chars;
};

struct IssuerConfiguration {
    std::string policy_id;
    direct::CorePolicy core_policy;
    direct::CarrierPolicy carrier_policy;
    std::vector<std::string> acquisition_profiles;
    std::string audit_identity_claim;
    jwks::StaticJwks keys;
};

struct Configuration {
    std::int64_t clock_skew_seconds;
    std::uint64_t total_verification_deadline_nanoseconds;
    ResourceLimits resource_limits;
    std::vector<IssuerConfiguration> trusted_issuers;
    direct::AccountPolicies accounts;
    audit::Facility facility;
};

using Result = tl::expected<Configuration, ParseError>;

[[nodiscard]] Result parse_and_validate(std::string_view input,
                                        std::uint32_t required_owner);
[[nodiscard]] Result load_and_validate(std::string_view path,
                                       std::uint32_t required_owner);
[[nodiscard]] tl::expected<void, ParseError> validate_render_path(
    std::string_view path, bool require_regular_file);
[[nodiscard]] bool valid_command_user(std::string_view user) noexcept;

}  // namespace credbind::config

#endif
