// SPDX-License-Identifier: Apache-2.0

#include "syslog_logger.hpp"

#include "crypto.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <syslog.h>

namespace credbind::audit {
namespace {

constexpr std::size_t kMaximumEventBytes = 1024U;
constexpr std::size_t kMaximumUsernameBytes = 256U;

ParseError error(ParseErrorKind kind, std::string message) {
    return ParseError{kind, std::move(message)};
}

std::string quoted(std::string_view value) {
    return nlohmann::json(std::string(value)).dump();
}

void member(std::string& output, std::string_view name, std::string_view value,
            bool& first) {
    if (!first) output.push_back(',');
    first = false;
    output += quoted(name);
    output.push_back(':');
    output += quoted(value);
}

void integer_member(std::string& output, std::string_view name, std::uint64_t value,
                    bool& first) {
    if (!first) output.push_back(',');
    first = false;
    output += quoted(name);
    output.push_back(':');
    output += std::to_string(value);
}

std::string lowercase_hex(const crypto::Sha256Digest& digest) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2U);
    for (const auto octet : digest) {
        output.push_back(alphabet[octet >> 4U]);
        output.push_back(alphabet[octet & 0x0fU]);
    }
    return output;
}

tl::expected<std::string, ParseError> sha256_hex(std::string_view input) {
    const auto digest = crypto::digest_sha256(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    if (!digest) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "audit SHA-256 failed"));
    }
    return lowercase_hex(*digest);
}

bool safe_username(std::string_view value) {
    if (value.empty() || value.size() > kMaximumUsernameBytes) return false;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::uint32_t codepoint = 0U;
        std::size_t length = 0U;
        if (first <= 0x7fU) {
            codepoint = first;
            length = 1U;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            codepoint = first & 0x1fU;
            length = 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            codepoint = first & 0x0fU;
            length = 3U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            codepoint = first & 0x07U;
            length = 4U;
        } else {
            return false;
        }
        if (length > value.size() - offset) return false;
        for (std::size_t index = 1U; index < length; ++index) {
            const auto continuation = static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (continuation & 0x3fU);
        }
        if ((length == 3U && codepoint < 0x800U) ||
            (length == 4U && codepoint < 0x10000U) || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            return false;
        }
        if ((codepoint <= 0x1fU) || (codepoint >= 0x7fU && codepoint <= 0x9fU)) {
            return false;
        }
        offset += length;
    }
    return true;
}

bool ascii_enum(std::string_view value,
                std::initializer_list<std::string_view> allowed) {
    return value.empty() || std::find(allowed.begin(), allowed.end(), value) != allowed.end();
}

bool valid_policy_id(std::string_view value) {
    if (value.empty()) return true;
    if (value.size() > 64U) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        const char character = value[index];
        const bool alphanumeric = (character >= 'A' && character <= 'Z') ||
                                  (character >= 'a' && character <= 'z') ||
                                  (character >= '0' && character <= '9');
        if (!alphanumeric &&
            (index == 0U || (character != '.' && character != '_' && character != '-'))) {
            return false;
        }
    }
    return true;
}

bool lower_hex_digest(std::string_view value) {
    if (value.empty()) return true;
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

tl::expected<SerializedEvent, ParseError> verification_payload(
    const VerificationEvent& event, bool hash_username) {
    const bool allowed = event.outcome == VerificationOutcome::allow;
    const bool internal = event.reason && *event.reason == ParseErrorKind::internal_error;
    const bool valid_outcome =
        (allowed && !event.reason) ||
        (event.outcome == VerificationOutcome::deny && event.reason && !internal) ||
        (event.outcome == VerificationOutcome::error && event.reason && internal);
    if (!valid_outcome || !valid_policy_id(event.issuer_policy) ||
        !lower_hex_digest(event.identity_ref_sha256) ||
        !ascii_enum(event.acquisition_profile,
                    {"oidc-native-auth-code-v1", "oidc-confidential-web-auth-code-v1",
                     "challenge-bound-workload-v1"}) ||
        !ascii_enum(event.binding_profile,
                    {"oidc-nonce-v1", "audience-v1", "credbind-claim-v1"}) ||
        !ascii_enum(event.evidence_profile,
                    {"standard-jws-v1", "gq-rs256-v1"}) ||
        !ascii_enum(event.caller_algorithm, {"ES256", "Ed25519"})) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "invalid verification audit outcome"));
    }
    const std::string_view result = allowed ? "allow"
                                    : event.outcome == VerificationOutcome::deny ? "deny"
                                                                                : "error";
    const std::string_view reason = allowed ? "none" : error_name(*event.reason);
    std::string output{"{"};
    bool first = true;
    integer_member(output, "event_version", 1U, first);
    member(output, "event", "verification_completed", first);
    member(output, "result", result, first);
    member(output, "reason", reason, first);
    integer_member(output, "duration_ms", event.duration_ms, first);
    if (!hash_username) {
        member(output, "requested_user", event.requested_user, first);
    } else {
        const auto digest = sha256_hex(event.requested_user);
        if (!digest) return tl::make_unexpected(digest.error());
        member(output, "requested_user_sha256", *digest, first);
    }
    if (!event.issuer_policy.empty()) member(output, "issuer_policy", event.issuer_policy, first);
    if (!event.identity_ref_sha256.empty()) {
        if (event.issuer_policy.empty()) {
            return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                             "identity reference has no issuer policy"));
        }
        member(output, "identity_ref_sha256", event.identity_ref_sha256, first);
    }
    if (!event.acquisition_profile.empty()) {
        member(output, "acquisition_profile", event.acquisition_profile, first);
    }
    if (!event.binding_profile.empty()) member(output, "binding_profile", event.binding_profile, first);
    if (!event.evidence_profile.empty()) member(output, "evidence_profile", event.evidence_profile, first);
    if (!event.caller_algorithm.empty()) member(output, "caller_algorithm", event.caller_algorithm, first);
    output.push_back('}');
    if (output.size() > kMaximumEventBytes || output.find('\n') != std::string::npos ||
        output.find('\0') != std::string::npos) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "audit event exceeds safe bound"));
    }
    return SerializedEvent{std::move(output),
                           allowed ? Severity::info
                                         : internal ? Severity::error : Severity::notice};
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

int facility_value(Facility facility) noexcept {
    switch (facility) {
        case Facility::authpriv: return LOG_AUTHPRIV;
        case Facility::auth: return LOG_AUTH;
        case Facility::daemon: return LOG_DAEMON;
        case Facility::user: return LOG_USER;
        case Facility::local0: return LOG_LOCAL0;
        case Facility::local1: return LOG_LOCAL1;
        case Facility::local2: return LOG_LOCAL2;
        case Facility::local3: return LOG_LOCAL3;
        case Facility::local4: return LOG_LOCAL4;
        case Facility::local5: return LOG_LOCAL5;
        case Facility::local6: return LOG_LOCAL6;
        case Facility::local7: return LOG_LOCAL7;
    }
    return LOG_AUTHPRIV;
}

int severity_value(Severity severity) noexcept {
    switch (severity) {
        case Severity::info: return LOG_INFO;
        case Severity::notice: return LOG_NOTICE;
        case Severity::error: return LOG_ERR;
    }
    return LOG_ERR;
}

}  // namespace

void SyslogLogger::emit(Facility facility, Severity severity,
                        std::string_view payload) noexcept {
    try {
        const std::string copy(payload);
        ::openlog("credbind-ssh-authorized-keys", LOG_NDELAY, facility_value(facility));
        ::syslog(severity_value(severity), "%s", copy.c_str());
        ::closelog();
    } catch (...) {
        // Logging is explicitly authorization-independent.
    }
}

const char* error_name(ParseErrorKind kind) noexcept {
    switch (kind) {
        case ParseErrorKind::malformed_input: return "malformed_input";
        case ParseErrorKind::resource_limit: return "resource_limit";
        case ParseErrorKind::unsupported_version: return "unsupported_version";
        case ParseErrorKind::unsupported_profile: return "unsupported_profile";
        case ParseErrorKind::unsupported_algorithm: return "unsupported_algorithm";
        case ParseErrorKind::caller_key_invalid: return "caller_key_invalid";
        case ParseErrorKind::issuer_untrusted: return "issuer_untrusted";
        case ParseErrorKind::issuer_signature_invalid: return "issuer_signature_invalid";
        case ParseErrorKind::evidence_invalid: return "evidence_invalid";
        case ParseErrorKind::evidence_result_mismatch: return "evidence_result_mismatch";
        case ParseErrorKind::binding_invalid: return "binding_invalid";
        case ParseErrorKind::issuer_claims_invalid: return "issuer_claims_invalid";
        case ParseErrorKind::credential_not_yet_valid: return "credential_not_yet_valid";
        case ParseErrorKind::credential_expired: return "credential_expired";
        case ParseErrorKind::caller_signature_invalid: return "caller_signature_invalid";
        case ParseErrorKind::ssh_certificate_invalid: return "ssh_certificate_invalid";
        case ParseErrorKind::ssh_key_mismatch: return "ssh_key_mismatch";
        case ParseErrorKind::ssh_identity_not_yet_valid: return "ssh_identity_not_yet_valid";
        case ParseErrorKind::ssh_identity_expired: return "ssh_identity_expired";
        case ParseErrorKind::ssh_principal_invalid: return "ssh_principal_invalid";
        case ParseErrorKind::account_unauthorized: return "account_unauthorized";
        case ParseErrorKind::deadline_exceeded: return "deadline_exceeded";
        case ParseErrorKind::operation_cancelled: return "operation_cancelled";
        case ParseErrorKind::state_invalid: return "state_invalid";
        case ParseErrorKind::internal_error: return "internal_error";
    }
    return "internal_error";
}

const char* facility_name(Facility facility) noexcept {
    switch (facility) {
        case Facility::authpriv: return "authpriv";
        case Facility::auth: return "auth";
        case Facility::daemon: return "daemon";
        case Facility::user: return "user";
        case Facility::local0: return "local0";
        case Facility::local1: return "local1";
        case Facility::local2: return "local2";
        case Facility::local3: return "local3";
        case Facility::local4: return "local4";
        case Facility::local5: return "local5";
        case Facility::local6: return "local6";
        case Facility::local7: return "local7";
    }
    return "authpriv";
}

tl::expected<Facility, ParseError> parse_facility(std::string_view value) {
    constexpr std::array<std::pair<std::string_view, Facility>, 12> values{{
        {"authpriv", Facility::authpriv}, {"auth", Facility::auth},
        {"daemon", Facility::daemon}, {"user", Facility::user},
        {"local0", Facility::local0}, {"local1", Facility::local1},
        {"local2", Facility::local2}, {"local3", Facility::local3},
        {"local4", Facility::local4}, {"local5", Facility::local5},
        {"local6", Facility::local6}, {"local7", Facility::local7},
    }};
    const auto iterator = std::find_if(values.begin(), values.end(),
                                       [value](const auto& item) { return item.first == value; });
    if (iterator == values.end()) {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                         "unsupported local syslog facility"));
    }
    return iterator->second;
}

tl::expected<SerializedEvent, ParseError> serialize(const VerificationEvent& event) {
    const bool safe = safe_username(event.requested_user);
    auto result = verification_payload(event, !safe);
    if (!result && safe) result = verification_payload(event, true);
    return result;
}

tl::expected<SerializedEvent, ParseError> serialize(const ConfigurationEvent& event) {
    const bool valid = event.outcome == ConfigurationOutcome::valid;
    const bool internal = event.reason && *event.reason == ParseErrorKind::internal_error;
    const bool cancelled = event.reason && *event.reason == ParseErrorKind::operation_cancelled;
    const bool valid_outcome = (valid && !event.reason) ||
        (event.outcome == ConfigurationOutcome::invalid && event.reason && !internal && !cancelled) ||
        (event.outcome == ConfigurationOutcome::error && event.reason && (internal || cancelled));
    if (!valid_outcome) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "invalid configuration audit outcome"));
    }
    const std::string_view result = valid ? "valid"
                                    : event.outcome == ConfigurationOutcome::invalid ? "invalid"
                                                                                     : "error";
    const std::string_view reason = valid ? "none" : error_name(*event.reason);
    std::string output{"{"};
    bool first = true;
    integer_member(output, "event_version", 1U, first);
    member(output, "event", "configuration_checked", first);
    member(output, "result", result, first);
    member(output, "reason", reason, first);
    integer_member(output, "duration_ms", event.duration_ms, first);
    output.push_back('}');
    if (output.size() > kMaximumEventBytes) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "configuration event exceeds safe bound"));
    }
    return SerializedEvent{std::move(output),
                           valid ? Severity::info
                                 : cancelled ? Severity::notice : Severity::error};
}

tl::expected<std::string, ParseError> identity_reference(
    std::string_view issuer, std::string_view claim_name, std::string_view claim_value) {
    std::vector<std::uint8_t> input;
    constexpr std::string_view label = "CredBind-Audit-Identity-v1";
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0U);
    append_value(input, issuer);
    append_value(input, claim_name);
    append_value(input, claim_value);
    const auto digest = crypto::digest_sha256(input.data(), input.size());
    if (!digest) {
        return tl::make_unexpected(error(ParseErrorKind::internal_error,
                                         "audit identity digest failed"));
    }
    return lowercase_hex(*digest);
}

}  // namespace credbind::audit
