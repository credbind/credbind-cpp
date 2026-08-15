// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_SYSLOG_LOGGER_HPP
#define CREDBIND_SYSLOG_LOGGER_HPP

#include "parse_error.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <tl/expected.hpp>

namespace credbind::audit {

enum class Facility {
    authpriv,
    auth,
    daemon,
    user,
    local0,
    local1,
    local2,
    local3,
    local4,
    local5,
    local6,
    local7
};

enum class Severity { info, notice, error };

class Logger {
  public:
    virtual ~Logger() = default;
    virtual void emit(Facility facility, Severity severity,
                      std::string_view payload) noexcept = 0;
};

class SyslogLogger final : public Logger {
  public:
    void emit(Facility facility, Severity severity,
              std::string_view payload) noexcept override;
};

enum class VerificationOutcome { allow, deny, error };
enum class ConfigurationOutcome { valid, invalid, error };

struct VerificationEvent {
    VerificationOutcome outcome = VerificationOutcome::error;
    std::optional<ParseErrorKind> reason = ParseErrorKind::internal_error;
    std::uint32_t duration_ms = 0U;
    std::string requested_user;
    std::string issuer_policy;
    std::string identity_ref_sha256;
    std::string acquisition_profile;
    std::string binding_profile;
    std::string evidence_profile;
    std::string caller_algorithm;
};

struct ConfigurationEvent {
    ConfigurationOutcome outcome = ConfigurationOutcome::error;
    std::optional<ParseErrorKind> reason = ParseErrorKind::internal_error;
    std::uint32_t duration_ms = 0U;
};

struct SerializedEvent {
    std::string payload;
    Severity severity;
};

[[nodiscard]] const char* error_name(ParseErrorKind kind) noexcept;
[[nodiscard]] const char* facility_name(Facility facility) noexcept;
[[nodiscard]] tl::expected<Facility, ParseError> parse_facility(std::string_view value);
[[nodiscard]] tl::expected<SerializedEvent, ParseError> serialize(
    const VerificationEvent& event);
[[nodiscard]] tl::expected<SerializedEvent, ParseError> serialize(
    const ConfigurationEvent& event);
[[nodiscard]] tl::expected<std::string, ParseError> identity_reference(
    std::string_view issuer, std::string_view claim_name, std::string_view claim_value);

}  // namespace credbind::audit

#endif
