// SPDX-License-Identifier: Apache-2.0

#include "command.hpp"

#include "config.hpp"
#include "direct_verifier.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace credbind::command {
namespace {

constexpr std::uint64_t kNanosecondsPerMillisecond = 1000000U;
constexpr std::uint64_t kMaximumVerificationNanoseconds = 10U * 1000U *
                                                           kNanosecondsPerMillisecond;

ParseError error(ParseErrorKind kind, std::string message) {
    return ParseError{kind, std::move(message)};
}

std::uint32_t duration(Clock& clock, std::uint64_t started) {
    const auto ended = clock.monotonic_nanoseconds();
    const auto elapsed = ended >= started
                             ? (ended - started) / kNanosecondsPerMillisecond
                             : 0U;
    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(elapsed, std::numeric_limits<std::uint32_t>::max()));
}

struct Interruption final {
    bool triggered;
    ParseErrorKind reason;
};

Interruption interrupted(Clock& clock, std::uint64_t started,
                         std::uint64_t budget) {
    const auto now = clock.monotonic_nanoseconds();
    if (now < started) return {true, ParseErrorKind::internal_error};
    if (now - started >= budget) return {true, ParseErrorKind::deadline_exceeded};
    if (clock.cancellation_requested()) {
        return {true, ParseErrorKind::operation_cancelled};
    }
    return {false, ParseErrorKind::internal_error};
}

void emit(audit::Logger& logger, audit::Facility facility,
          const audit::VerificationEvent& event) noexcept {
    try {
        const auto serialized = audit::serialize(event);
        if (serialized) logger.emit(facility, serialized->severity, serialized->payload);
    } catch (...) {
    }
}

void emit(audit::Logger& logger, audit::Facility facility,
          const audit::ConfigurationEvent& event) noexcept {
    try {
        const auto serialized = audit::serialize(event);
        if (serialized) logger.emit(facility, serialized->severity, serialized->payload);
    } catch (...) {
    }
}

tl::expected<std::vector<std::uint8_t>, ParseError> decode_base64(
    std::string_view input, std::size_t maximum) {
    if (input.empty() || input.size() % 4U != 0U ||
        input.size() / 4U > (maximum + 2U) / 3U) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid OpenSSH base64 length"));
    }
    auto value = [](char character) -> int {
        if (character >= 'A' && character <= 'Z') return character - 'A';
        if (character >= 'a' && character <= 'z') return character - 'a' + 26;
        if (character >= '0' && character <= '9') return character - '0' + 52;
        if (character == '+') return 62;
        if (character == '/') return 63;
        return -1;
    };
    std::vector<std::uint8_t> output;
    output.reserve(std::min(maximum, input.size() / 4U * 3U));
    for (std::size_t offset = 0U; offset < input.size(); offset += 4U) {
        const bool last = offset + 4U == input.size();
        const bool pad2 = input[offset + 2U] == '=';
        const bool pad3 = input[offset + 3U] == '=';
        const int a = value(input[offset]);
        const int b = value(input[offset + 1U]);
        const int c = pad2 ? 0 : value(input[offset + 2U]);
        const int d = pad3 ? 0 : value(input[offset + 3U]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (!last && (pad2 || pad3)) ||
            (pad2 && !pad3) || (pad2 && (b & 15) != 0) ||
            (!pad2 && pad3 && (c & 3) != 0)) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "non-canonical OpenSSH base64"));
        }
        output.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
        if (!pad2) output.push_back(static_cast<std::uint8_t>((b << 4) | (c >> 2)));
        if (!pad3) output.push_back(static_cast<std::uint8_t>((c << 6) | d));
        if (output.size() > maximum) {
            return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                             "OpenSSH certificate exceeds configured bound"));
        }
    }
    return output;
}

std::string caller_algorithm(direct::CallerAlgorithm value) {
    return value == direct::CallerAlgorithm::es256 ? "ES256" : "Ed25519";
}

std::string acquisition_profile(const config::IssuerConfiguration& policy,
                                std::string_view binding) {
    if (binding == issuer::kAudienceBinding || binding == issuer::kCredBindClaimBinding) {
        return std::find(policy.acquisition_profiles.begin(), policy.acquisition_profiles.end(),
                         "challenge-bound-workload-v1") != policy.acquisition_profiles.end()
                   ? "challenge-bound-workload-v1" : "";
    }
    if (binding != issuer::kOidcNonceBinding) return "";
    std::string result;
    for (const std::string_view candidate : {"oidc-native-auth-code-v1",
                                             "oidc-confidential-web-auth-code-v1"}) {
        if (std::find(policy.acquisition_profiles.begin(), policy.acquisition_profiles.end(),
                      candidate) != policy.acquisition_profiles.end()) {
            if (!result.empty()) return "";
            result = candidate;
        }
    }
    return result;
}

void add_authenticated_audit(audit::VerificationEvent& event,
                             const config::IssuerConfiguration& policy,
                             const direct::CoreResult& core) {
    event.issuer_policy = policy.policy_id;
    event.acquisition_profile = acquisition_profile(policy, core.binding_profile);
    event.binding_profile = core.binding_profile;
    event.evidence_profile = core.evidence_profile;
    event.caller_algorithm = caller_algorithm(core.caller_key.algorithm);
    if (!policy.audit_identity_claim.empty()) {
        const auto claim = core.claims.find(policy.audit_identity_claim);
        if (claim != core.claims.end() && claim->second.is_string()) {
            const auto& value = claim->second.get_ref<const std::string&>();
            if (!value.empty()) {
                const auto reference = audit::identity_reference(
                    core.issuer, policy.audit_identity_claim, value);
                if (reference) event.identity_ref_sha256 = *reference;
            }
        }
    }
}

int deny_verify(std::string_view requested_user, ParseErrorKind reason,
                audit::Facility facility, std::uint64_t started,
                audit::Logger& logger, Clock& clock,
                const config::IssuerConfiguration* policy = nullptr,
                const direct::CoreResult* core = nullptr) {
    audit::VerificationEvent event;
    event.outcome = reason == ParseErrorKind::internal_error
                        ? audit::VerificationOutcome::error
                        : audit::VerificationOutcome::deny;
    event.reason = reason;
    event.duration_ms = duration(clock, started);
    event.requested_user = std::string(requested_user);
    if (policy != nullptr && core != nullptr) add_authenticated_audit(event, *policy, *core);
    emit(logger, facility, event);
    return 0;
}

int run_verify(const std::vector<std::string_view>& args, std::ostream& output,
               audit::Logger& logger, Clock& clock) {
    const auto started = clock.monotonic_nanoseconds();
    std::uint64_t budget = kMaximumVerificationNanoseconds;
    std::string_view config_path;
    std::string_view requested_user;
    std::string_view encoded_key;
    std::string_view key_type;
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, audit::Facility::authpriv,
                           started, logger, clock);
    }
    if (args.size() == 9U && args[1] == "--config" && args[3] == "--user" &&
        args[5] == "--key" && args[7] == "--key-type") {
        config_path = args[2];
        requested_user = args[4];
        encoded_key = args[6];
        key_type = args[8];
    } else {
        return deny_verify(requested_user, ParseErrorKind::malformed_input,
                           audit::Facility::authpriv, started, logger, clock);
    }
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, audit::Facility::authpriv,
                           started, logger, clock);
    }
    const auto configuration = config::load_and_validate(
        config_path, static_cast<std::uint32_t>(::geteuid()));
    if (!configuration) {
        return deny_verify(requested_user, configuration.error().kind,
                           audit::Facility::authpriv, started, logger, clock);
    }
    budget = configuration->total_verification_deadline_nanoseconds;
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, configuration->facility,
                           started, logger, clock);
    }
    if (encoded_key.size() > configuration->resource_limits.max_offered_key_chars) {
        return deny_verify(requested_user, ParseErrorKind::resource_limit,
                           configuration->facility, started, logger, clock);
    }
    const auto blob = decode_base64(encoded_key,
                                    configuration->resource_limits.max_ssh_certificate_bytes);
    if (!blob) {
        return deny_verify(requested_user, blob.error().kind,
                           configuration->facility, started, logger, clock);
    }
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, configuration->facility,
                           started, logger, clock);
    }
    const std::string certificate(reinterpret_cast<const char*>(blob->data()), blob->size());
    std::vector<std::pair<std::size_t, direct::CarrierResult>> successes;
    ParseErrorKind first_error = ParseErrorKind::issuer_untrusted;
    bool have_error = false;
    std::vector<std::pair<std::size_t, direct::CoreResult>> authenticated;
    for (std::size_t index = 0U; index < configuration->trusted_issuers.size(); ++index) {
        if (const auto state = interrupted(clock, started, budget); state.triggered) {
            return deny_verify(requested_user, state.reason, configuration->facility,
                               started, logger, clock);
        }
        const auto& policy = configuration->trusted_issuers[index];
        direct::CarrierAuditContext context;
        auto result = direct::verify_carrier(
            direct::CarrierInput{certificate, key_type, requested_user,
                                 clock.wall_time_unix()},
            policy.core_policy, policy.carrier_policy, configuration->accounts,
            policy.keys,
            openssh::Limits{configuration->resource_limits.max_ssh_certificate_bytes,
                            configuration->resource_limits.max_token_bytes, 16U, 16U, 256U},
            &context);
        if (const auto state = interrupted(clock, started, budget); state.triggered) {
            const direct::CoreResult* core = nullptr;
            if (result) core = &result->core;
            else if (context.core_verified) core = &context.core;
            return deny_verify(requested_user, state.reason, configuration->facility,
                               started, logger, clock, core == nullptr ? nullptr : &policy,
                               core);
        }
        if (result) {
            successes.emplace_back(index, std::move(*result));
        } else {
            if (!have_error) { first_error = result.error().kind; have_error = true; }
            if (context.core_verified) authenticated.emplace_back(index, std::move(context.core));
        }
    }
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, configuration->facility,
                           started, logger, clock);
    }
    if (successes.size() != 1U) {
        const auto reason = successes.size() > 1U ? ParseErrorKind::issuer_untrusted
                                                  : first_error;
        if (successes.empty() && authenticated.size() == 1U) {
            const auto& selected = authenticated.front();
            return deny_verify(requested_user, reason, configuration->facility, started,
                               logger, clock, &configuration->trusted_issuers[selected.first],
                               &selected.second);
        }
        return deny_verify(requested_user, reason, configuration->facility,
                           started, logger, clock);
    }
    auto& selected = successes.front();
    const auto& policy = configuration->trusted_issuers[selected.first];
    const std::string line = "cert-authority,principals=\"" + selected.second.principal +
        "\" " + selected.second.ca_key_type + " " + selected.second.ca_public_key_base64 + "\n";
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, configuration->facility,
                           started, logger, clock, &policy, &selected.second.core);
    }
    if (line.size() > configuration->resource_limits.max_authorized_keys_output_chars) {
        return deny_verify(requested_user, ParseErrorKind::resource_limit,
                           configuration->facility, started, logger, clock,
                           &policy, &selected.second.core);
    }
    if (const auto state = interrupted(clock, started, budget); state.triggered) {
        return deny_verify(requested_user, state.reason, configuration->facility,
                           started, logger, clock, &policy, &selected.second.core);
    }
    const auto written = output.rdbuf()->sputn(
        line.data(), static_cast<std::streamsize>(line.size()));
    if (written != static_cast<std::streamsize>(line.size())) {
        return deny_verify(requested_user, ParseErrorKind::internal_error,
                           configuration->facility, started, logger, clock,
                           &policy, &selected.second.core);
    }
    audit::VerificationEvent event;
    event.outcome = audit::VerificationOutcome::allow;
    event.reason.reset();
    event.duration_ms = duration(clock, started);
    event.requested_user = std::string(requested_user);
    add_authenticated_audit(event, policy, selected.second.core);
    emit(logger, configuration->facility, event);
    return 0;
}

int fail(std::ostream& diagnostics, ParseErrorKind kind) {
    diagnostics << audit::error_name(kind) << '\n';
    return 2;
}

}  // namespace

SystemClock::SystemClock(const volatile std::sig_atomic_t* cancellation) noexcept
    : cancellation_(cancellation) {}

std::int64_t SystemClock::wall_time_unix() noexcept {
    return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::uint64_t SystemClock::monotonic_nanoseconds() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool SystemClock::cancellation_requested() noexcept {
    return cancellation_ != nullptr && *cancellation_ != 0;
}

int run_dispatch(const std::vector<std::string_view>& arguments, std::ostream& output,
                 std::ostream& diagnostics, audit::Logger& logger, Clock& clock) {
    if (arguments.empty()) return fail(diagnostics, ParseErrorKind::malformed_input);
    if (arguments[0] == "verify") {
        return run_verify(arguments, output, logger, clock);
    }
    if (arguments[0] == "config" && arguments.size() >= 2U && arguments[1] == "init") {
        bool deny_all = false;
        bool force = false;
        bool have_output = false;
        std::string_view output_path;
        for (std::size_t index = 2U; index < arguments.size(); ++index) {
            if (arguments[index] == "--deny-all" && !deny_all) {
                deny_all = true;
            } else if (arguments[index] == "--force" && !force) {
                force = true;
            } else if (arguments[index] == "--output" && !have_output &&
                       index + 1U < arguments.size()) {
                have_output = true;
                output_path = arguments[++index];
            } else {
                return fail(diagnostics, ParseErrorKind::malformed_input);
            }
        }
        if (!deny_all || (force && !have_output)) {
            return fail(diagnostics, ParseErrorKind::malformed_input);
        }
        // The shared contract does not yet define the selected values for the
        // mandatory skew, deadline, and resource fields. Emitting guessed trust
        // configuration would not be deterministic across implementations.
        static_cast<void>(output_path);
        return fail(diagnostics, ParseErrorKind::state_invalid);
    }
    if (arguments[0] == "config" && arguments.size() == 4U &&
        arguments[1] == "check" && arguments[2] == "--config") {
        const auto started = clock.monotonic_nanoseconds();
        if (clock.cancellation_requested()) {
            audit::ConfigurationEvent event;
            event.outcome = audit::ConfigurationOutcome::error;
            event.reason = ParseErrorKind::operation_cancelled;
            event.duration_ms = duration(clock, started);
            emit(logger, audit::Facility::authpriv, event);
            return fail(diagnostics, ParseErrorKind::operation_cancelled);
        }
        const auto checked = config::load_and_validate(
            arguments[3], static_cast<std::uint32_t>(::geteuid()));
        audit::ConfigurationEvent event;
        event.duration_ms = duration(clock, started);
        audit::Facility facility = audit::Facility::authpriv;
        if (clock.cancellation_requested()) {
            event.outcome = audit::ConfigurationOutcome::error;
            event.reason = ParseErrorKind::operation_cancelled;
            if (checked) facility = checked->facility;
            emit(logger, facility, event);
            return fail(diagnostics, ParseErrorKind::operation_cancelled);
        }
        if (checked) {
            event.outcome = audit::ConfigurationOutcome::valid;
            event.reason.reset();
            facility = checked->facility;
            const std::string_view success = "configuration valid\n";
            const auto written = output.rdbuf()->sputn(
                success.data(), static_cast<std::streamsize>(success.size()));
            if (written != static_cast<std::streamsize>(success.size())) {
                event.outcome = audit::ConfigurationOutcome::error;
                event.reason = ParseErrorKind::internal_error;
            }
        } else {
            event.outcome = checked.error().kind == ParseErrorKind::internal_error
                                ? audit::ConfigurationOutcome::error
                                : audit::ConfigurationOutcome::invalid;
            event.reason = checked.error().kind;
        }
        emit(logger, facility, event);
        if (event.outcome == audit::ConfigurationOutcome::error) {
            return fail(diagnostics, *event.reason);
        }
        return checked ? 0 : fail(diagnostics, checked.error().kind);
    }
    if (arguments[0] == "sshd-config" && arguments.size() == 8U &&
        arguments[1] == "render" && arguments[2] == "--config" &&
        arguments[4] == "--verifier" && arguments[6] == "--command-user") {
        if (clock.cancellation_requested()) {
            return fail(diagnostics, ParseErrorKind::operation_cancelled);
        }
        const auto checked = config::load_and_validate(
            arguments[3], static_cast<std::uint32_t>(::geteuid()));
        if (!checked) return fail(diagnostics, checked.error().kind);
        if (clock.cancellation_requested()) {
            return fail(diagnostics, ParseErrorKind::operation_cancelled);
        }
        const auto config_path = config::validate_render_path(arguments[3], true);
        const auto verifier_path = config::validate_render_path(arguments[5], true);
        if (!config_path) return fail(diagnostics, config_path.error().kind);
        if (!verifier_path) return fail(diagnostics, verifier_path.error().kind);
        if (!config::valid_command_user(arguments[7])) {
            return fail(diagnostics, ParseErrorKind::malformed_input);
        }
        const std::string fragment = "AuthorizedKeysCommand " +
            std::string(arguments[5]) + " verify --config " +
            std::string(arguments[3]) + " --user %u --key %k --key-type %t\n" +
            "AuthorizedKeysCommandUser " + std::string(arguments[7]) + "\n";
        const auto written = output.rdbuf()->sputn(
            fragment.data(), static_cast<std::streamsize>(fragment.size()));
        if (written != static_cast<std::streamsize>(fragment.size())) {
            return fail(diagnostics, ParseErrorKind::internal_error);
        }
        return 0;
    }
    return fail(diagnostics, ParseErrorKind::malformed_input);
}

int run_catching_exceptions(const std::vector<std::string_view>& arguments,
                            std::ostream& output, std::ostream& diagnostics,
                            audit::Logger& logger, Clock& clock) {
    try {
        return run_dispatch(arguments, output, diagnostics, logger, clock);
    } catch (...) {
        if (!arguments.empty() && arguments.front() == "verify") {
            std::string_view requested_user;
            for (std::size_t index = 1U; index + 1U < arguments.size(); ++index) {
                if (arguments[index] == "--user") {
                    requested_user = arguments[index + 1U];
                    break;
                }
            }
            audit::VerificationEvent event;
            event.outcome = audit::VerificationOutcome::error;
            event.reason = ParseErrorKind::internal_error;
            event.requested_user = std::string(requested_user);
            emit(logger, audit::Facility::authpriv, event);
            return 0;
        }
        return fail(diagnostics, ParseErrorKind::internal_error);
    }
}

int run(const std::vector<std::string_view>& arguments, std::ostream& output,
        std::ostream& diagnostics, audit::Logger& logger, Clock& clock) {
    return run_catching_exceptions(arguments, output, diagnostics, logger, clock);
}

}  // namespace credbind::command
