// SPDX-License-Identifier: Apache-2.0

#include "command.hpp"
#include "config.hpp"
#include "syslog_logger.hpp"

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>

namespace {

void require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "adapter test failure: " << message << '\n';
        std::exit(1);
    }
}

class FakeLogger final : public credbind::audit::Logger {
  public:
    void emit(credbind::audit::Facility facility_value,
              credbind::audit::Severity severity_value,
              std::string_view payload_value) noexcept override {
        ++calls;
        facility = facility_value;
        severity = severity_value;
        payload = std::string(payload_value);
    }

    int calls = 0;
    credbind::audit::Facility facility = credbind::audit::Facility::authpriv;
    credbind::audit::Severity severity = credbind::audit::Severity::error;
    std::string payload;
};

class DropLogger final : public credbind::audit::Logger {
  public:
    void emit(credbind::audit::Facility, credbind::audit::Severity,
              std::string_view) noexcept override { ++calls; }
    int calls = 0;
};

class FakeClock final : public credbind::command::Clock {
  public:
    std::int64_t wall_time_unix() noexcept override { return wall; }
    std::uint64_t monotonic_nanoseconds() noexcept override {
        const auto result = monotonic;
        monotonic += 7000000U;
        return result;
    }
    bool cancellation_requested() noexcept override { return cancelled; }
    std::int64_t wall = 1786061100;
    std::uint64_t monotonic = 100000000U;
    bool cancelled = false;
};

class ThrowClock final : public credbind::command::Clock {
  public:
    std::int64_t wall_time_unix() override { throw 1; }
    std::uint64_t monotonic_nanoseconds() override { throw 1; }
    bool cancellation_requested() override { throw 1; }
};

class AdvancingClock final : public credbind::command::Clock {
  public:
    std::int64_t wall_time_unix() noexcept override { return wall; }
    std::uint64_t monotonic_nanoseconds() noexcept override {
        const auto result = monotonic;
        monotonic += step;
        return result;
    }
    bool cancellation_requested() noexcept override { return cancelled; }
    std::int64_t wall = 1788739500;
    std::uint64_t monotonic = 0U;
    std::uint64_t step = 0U;
    bool cancelled = false;
};

class CancelAfterCheckClock final : public credbind::command::Clock {
  public:
    std::int64_t wall_time_unix() noexcept override { return 1788739500; }
    std::uint64_t monotonic_nanoseconds() noexcept override { return 0U; }
    bool cancellation_requested() noexcept override { return calls++ != 0U; }
    std::uint32_t calls = 0U;
};

class RejectBuffer final : public std::streambuf {
  protected:
    std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
    int_type overflow(int_type) override { return traits_type::eof(); }
};

std::string base_config(std::string_view issuers = "[]",
                        std::string_view accounts = "{}") {
    return std::string("{\"version\":1,\"clock_skew\":\"0s\","
        "\"total_verification_deadline\":\"5s\",\"resource_limits\":{"
        "\"max_token_bytes\":32768,\"max_evidence_bytes\":16384,"
        "\"max_ssh_certificate_bytes\":49152,\"max_offered_key_chars\":65536,"
        "\"max_authorized_keys_output_chars\":4096},\"trusted_issuers\":") +
        std::string(issuers) + ",\"accounts\":" + std::string(accounts) +
        ",\"logging\":{\"facility\":\"local3\"}}";
}

std::string issuer_policy(std::string_view jwks_path, std::string_view policy_id,
                          std::string_view caller = "[\"ES256\"]",
                          std::string_view acquisitions = "[\"oidc-native-auth-code-v1\"]",
                          std::string_view bindings = "[\"oidc-nonce-v1\"]") {
    return std::string("{\"policy_id\":\"") + std::string(policy_id) +
        "\",\"issuer\":\"https://issuer.example.test\",\"key_source\":{"
        "\"type\":\"static-jwks-file\",\"path\":\"" + std::string(jwks_path) +
        "\"},\"audiences\":[\"credbind-fixture-client\"],"
        "\"issuer_algorithms\":[\"RS256\"],\"caller_algorithms\":" +
        std::string(caller) + ",\"evidence_profiles\":[\"standard-jws-v1\"],"
        "\"binding_profiles\":" + std::string(bindings) +
        ",\"acquisition_profiles\":" + std::string(acquisitions) +
        ",\"require_non_reconstructible_evidence\":false,"
        "\"certificate_principal_claim\":\"sub\"}";
}

void test_audit() {
    using namespace credbind;
    audit::VerificationEvent allowed;
    allowed.outcome = audit::VerificationOutcome::allow;
    allowed.reason.reset();
    allowed.duration_ms = 9U;
    allowed.requested_user = "alice";
    allowed.issuer_policy = "issuer-1";
    allowed.binding_profile = "oidc-nonce-v1";
    allowed.evidence_profile = "standard-jws-v1";
    allowed.caller_algorithm = "ES256";
    auto serialized = audit::serialize(allowed);
    require(serialized && serialized->severity == audit::Severity::info,
            "allow severity");
    require(serialized->payload ==
        "{\"event_version\":1,\"event\":\"verification_completed\","
        "\"result\":\"allow\",\"reason\":\"none\",\"duration_ms\":9,"
        "\"requested_user\":\"alice\",\"issuer_policy\":\"issuer-1\","
        "\"binding_profile\":\"oidc-nonce-v1\","
        "\"evidence_profile\":\"standard-jws-v1\",\"caller_algorithm\":\"ES256\"}",
        "allow exact payload");

    audit::VerificationEvent cancelled;
    cancelled.outcome = audit::VerificationOutcome::deny;
    cancelled.reason = ParseErrorKind::operation_cancelled;
    cancelled.requested_user = "bad\nuser";
    serialized = audit::serialize(cancelled);
    require(serialized && serialized->severity == audit::Severity::notice,
            "cancelled verification notice");
    require(serialized->payload.find(
        "\"requested_user_sha256\":\"1576c8a6a1fd3c5eb636e4233b3ab700d2bc798fab13a3ee160b7419329ebe7a\"")
            != std::string::npos,
            "raw username digest");

    audit::ConfigurationEvent valid;
    valid.outcome = audit::ConfigurationOutcome::valid;
    valid.reason.reset();
    serialized = audit::serialize(valid);
    require(serialized && serialized->severity == audit::Severity::info &&
            serialized->payload ==
                "{\"event_version\":1,\"event\":\"configuration_checked\","
                "\"result\":\"valid\",\"reason\":\"none\",\"duration_ms\":0}",
            "valid configuration event");

    audit::ConfigurationEvent config_cancelled;
    config_cancelled.outcome = audit::ConfigurationOutcome::error;
    config_cancelled.reason = ParseErrorKind::operation_cancelled;
    serialized = audit::serialize(config_cancelled);
    require(serialized && serialized->severity == audit::Severity::notice &&
            serialized->payload.find("\"result\":\"error\"") != std::string::npos,
            "configuration cancellation notice");

    audit::ConfigurationEvent invalid;
    invalid.outcome = audit::ConfigurationOutcome::invalid;
    invalid.reason = ParseErrorKind::malformed_input;
    serialized = audit::serialize(invalid);
    require(serialized && serialized->severity == audit::Severity::error,
            "invalid configuration error severity");

    audit::VerificationEvent impossible;
    impossible.outcome = audit::VerificationOutcome::allow;
    impossible.reason = ParseErrorKind::malformed_input;
    require(!audit::serialize(impossible), "reject reason on allow");
    allowed.identity_ref_sha256 = "ABC";
    require(!audit::serialize(allowed), "reject malformed identity reference");

    audit::VerificationEvent crowded;
    crowded.outcome = audit::VerificationOutcome::deny;
    crowded.reason = ParseErrorKind::ssh_principal_invalid;
    crowded.requested_user = std::string(257U, '\\');
    crowded.issuer_policy = std::string(64U, 'p');
    crowded.identity_ref_sha256 = std::string(64U, 'a');
    crowded.acquisition_profile = "oidc-confidential-web-auth-code-v1";
    crowded.binding_profile = "credbind-claim-v1";
    crowded.evidence_profile = "standard-jws-v1";
    crowded.caller_algorithm = "Ed25519";
    serialized = audit::serialize(crowded);
    require(serialized && serialized->payload.size() <= 1024U &&
            serialized->payload.find("requested_user_sha256") != std::string::npos &&
            serialized->payload.find("requested_user\"") == std::string::npos,
            "over-bound clear username falls back to hash");
    const std::vector<std::string_view> ordered{
        "event_version", "event", "result", "reason", "duration_ms",
        "requested_user_sha256", "issuer_policy", "identity_ref_sha256",
        "acquisition_profile", "binding_profile", "evidence_profile", "caller_algorithm"};
    std::size_t prior = 0U;
    for (const auto field : ordered) {
        const auto position = serialized->payload.find(field);
        require(position != std::string::npos && position >= prior, "audit field order");
        prior = position;
    }
    audit::VerificationEvent invalid_utf8;
    invalid_utf8.outcome = audit::VerificationOutcome::deny;
    invalid_utf8.reason = ParseErrorKind::malformed_input;
    invalid_utf8.requested_user.assign(1U, static_cast<char>(0xff));
    serialized = audit::serialize(invalid_utf8);
    require(serialized && serialized->payload.find("requested_user_sha256") != std::string::npos,
            "invalid UTF-8 username is hashed");

    const auto identity = audit::identity_reference(
        "https://issuer.example.test", "sub", "opaque-123");
    require(identity && *identity ==
        "e256ccaec6aa83043960b1828241f0b1a6ae1604b4381f5f314ad43be154f518",
        "identity reference domain separation");
}

void test_config(std::string_view jwks_path) {
    using namespace credbind;
    const auto owner = static_cast<std::uint32_t>(::geteuid());
    auto parsed = config::parse_and_validate(base_config(), owner);
    require(parsed && parsed->facility == audit::Facility::local3,
            "deny-all typed config");
    require(!config::parse_and_validate(base_config() + "{}", owner),
            "trailing JSON value rejected");
    require(!config::parse_and_validate(
        "{\"version\":1,\"version\":1}", owner), "duplicate config member rejected");

    std::string maximum_deadline = base_config();
    maximum_deadline.replace(maximum_deadline.find("5s"), 2U, "10s");
    require(static_cast<bool>(config::parse_and_validate(maximum_deadline, owner)),
            "exact ten-second deadline admitted");
    maximum_deadline.replace(maximum_deadline.find("10s"), 3U, "10s1ns");
    const auto over_deadline = config::parse_and_validate(maximum_deadline, owner);
    require(!over_deadline && over_deadline.error().kind == ParseErrorKind::resource_limit,
            "deadline above ten seconds rejected");

    const auto first = issuer_policy(jwks_path, "first");
    const auto second = issuer_policy(jwks_path, "second");
    parsed = config::parse_and_validate(base_config("[" + first + "," + second + "]"), owner);
    require(parsed && parsed->trusted_issuers.size() == 2U,
            "same issuer may have distinct policies");
    require(!config::parse_and_validate(
        base_config("[" + issuer_policy(jwks_path, "bad", "[\"Ed25519\"]") + "]"), owner),
        "ES256 mandatory");
    require(!config::parse_and_validate(
        base_config("[" + issuer_policy(jwks_path, "bad-pair", "[\"ES256\"]",
                                        "[\"challenge-bound-workload-v1\"]",
                                        "[\"oidc-nonce-v1\"]") + "]"), owner),
        "acquisition binding pairing");

    for (const std::string_view bad_uri : {"https://:443", "https://[",
                                           "https://issuer.example/%zz",
                                           "https://issuer.example:99999"}) {
        std::string invalid_uri = issuer_policy(jwks_path, "bad-uri");
        const std::string valid_uri = "https://issuer.example.test";
        invalid_uri.replace(invalid_uri.find(valid_uri), valid_uri.size(), bad_uri);
        require(!config::parse_and_validate(base_config("[" + invalid_uri + "]"), owner),
                "malformed HTTPS issuer URI rejected");
    }

    std::string discovery = issuer_policy(jwks_path, "discovery");
    const std::string static_source = std::string("{\"type\":\"static-jwks-file\",\"path\":\"") +
                                      std::string(jwks_path) + "\"}";
    discovery.replace(discovery.find(static_source), static_source.size(),
                      "{\"type\":\"oidc-discovery\"}");
    const auto unsupported = config::parse_and_validate(base_config("[" + discovery + "]"), owner);
    require(!unsupported && unsupported.error().kind == ParseErrorKind::unsupported_profile,
            "C++ discovery rejected offline");
}

void test_command() {
    FakeLogger logger;
    FakeClock clock;
    std::ostringstream output;
    std::ostringstream diagnostics;
    const std::vector<std::string_view> verify{
        "verify", "--config", "/definitely/absent", "--user", "alice",
        "--key", "AAAA", "--key-type", "ssh-ed25519-cert-v01@openssh.com"};
    require(credbind::command::run(verify, output, diagnostics, logger, clock) == 0,
            "verify denial exits zero");
    require(output.str().empty() && diagnostics.str().empty(),
            "verify denial is silent");
    require(logger.calls == 1 && logger.facility == credbind::audit::Facility::authpriv &&
            logger.severity == credbind::audit::Severity::notice &&
            logger.payload.find("\"reason\":\"state_invalid\"") != std::string::npos,
            "verify attempts one fallback-facility event");

    FakeLogger exception_logger;
    ThrowClock throwing_clock;
    std::ostringstream exception_output;
    std::ostringstream exception_diagnostics;
    require(credbind::command::run(verify, exception_output, exception_diagnostics,
                                   exception_logger, throwing_clock) == 0,
            "unexpected verify exception exits as denial");
    require(exception_output.str().empty() && exception_diagnostics.str().empty() &&
            exception_logger.calls == 1 &&
            exception_logger.payload.find("\"result\":\"error\"") != std::string::npos &&
            exception_logger.payload.find("\"reason\":\"internal_error\"") != std::string::npos,
            "unexpected verify exception attempts one internal-error event");
}

void test_authenticated_command(std::string_view vector_path,
                                std::string_view jwks_path) {
    std::ifstream input{std::string(vector_path)};
    require(static_cast<bool>(input), "open carrier vector");
    const auto carrier = nlohmann::json::parse(input);
    nlohmann::json configured = {
        {"version", 1}, {"clock_skew", "0s"},
        {"total_verification_deadline", "5s"},
        {"resource_limits", {
            {"max_token_bytes", 32768}, {"max_evidence_bytes", 16384},
            {"max_ssh_certificate_bytes", 49152}, {"max_offered_key_chars", 65536},
            {"max_authorized_keys_output_chars", 4096}}},
        {"trusted_issuers", {nlohmann::json{
            {"policy_id", "fixture-policy"},
            {"issuer", "https://issuer.v1-rc1.example.test"},
            {"key_source", {{"type", "static-jwks-file"}, {"path", jwks_path}}},
            {"audiences", {"credbind-v1-rc1-client"}},
            {"authorized_parties", {"credbind-v1-rc1-client"}},
            {"issuer_algorithms", {"RS256"}}, {"caller_algorithms", {"ES256"}},
            {"evidence_profiles", {"standard-jws-v1"}},
            {"binding_profiles", {"oidc-nonce-v1"}},
            {"acquisition_profiles", {"oidc-native-auth-code-v1"}},
            {"require_non_reconstructible_evidence", false},
            {"certificate_principal_claim", "sub"}}}},
        {"accounts", {{"fixture-user", {{"allow", {nlohmann::json{
            {"issuer", "https://issuer.v1-rc1.example.test"},
            {"all", {nlohmann::json{{"claim", "sub"}, {"type", "string"},
                                     {"op", "equals"},
                                     {"value", "fixture-subject-v1-rc1"}}}},
            {"allowed_certificate_extensions",
             {"permit-port-forwarding", "permit-pty"}}}}}}}}},
        {"logging", {{"facility", "local3"}}},
    };
    char path[] = "/tmp/credbind-adapter-config.XXXXXX";
    const int descriptor = ::mkstemp(path);
    require(descriptor >= 0 && ::fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
            "create private config fixture");
    const std::string bytes = configured.dump();
    require(::write(descriptor, bytes.data(), bytes.size()) ==
                static_cast<ssize_t>(bytes.size()) && ::close(descriptor) == 0,
            "write config fixture");

    const auto& encoded = carrier.at("certificate_blob_base64").get_ref<const std::string&>();
    const auto& key_type = carrier.at("key_type_argument").get_ref<const std::string&>();
    const std::vector<std::string_view> arguments{
        "verify", "--config", path, "--user", "fixture-user", "--key", encoded,
        "--key-type", key_type};
    FakeLogger logger;
    FakeClock clock;
    clock.wall = 1788739500;
    std::ostringstream output;
    std::ostringstream diagnostics;
    require(credbind::command::run(
                arguments, output, diagnostics, logger, clock) == 0,
            "authenticated command exit");
    require(output.str() == carrier.at("authorized_keys_output").get<std::string>() &&
            diagnostics.str().empty(), "authenticated command exact line");
    require(logger.calls == 1 && logger.facility == credbind::audit::Facility::local3 &&
            logger.severity == credbind::audit::Severity::info &&
            logger.payload.find("\"result\":\"allow\"") != std::string::npos &&
            logger.payload.find("\"issuer_policy\":\"fixture-policy\"") != std::string::npos &&
            logger.payload.find("\"acquisition_profile\":\"oidc-native-auth-code-v1\"") !=
                std::string::npos &&
            logger.payload.find("\"evidence_profile\":\"standard-jws-v1\"") !=
                std::string::npos && logger.payload.find(encoded) == std::string::npos,
            "authenticated allow emits exact trusted audit context");

    DropLogger dropped;
    FakeClock dropped_clock;
    dropped_clock.wall = 1788739500;
    std::ostringstream dropped_output;
    std::ostringstream dropped_diagnostics;
    require(credbind::command::run(
                arguments, dropped_output, dropped_diagnostics, dropped, dropped_clock) == 0 &&
            dropped.calls == 1 &&
            dropped_output.str() == carrier.at("authorized_keys_output").get<std::string>() &&
            dropped_diagnostics.str().empty(),
            "discarded logger event does not alter authorization");

    RejectBuffer rejected;
    std::ostream failed_output(&rejected);
    FakeLogger failed_logger;
    FakeClock failed_clock;
    failed_clock.wall = 1788739500;
    std::ostringstream failed_diagnostics;
    require(credbind::command::run(
                arguments, failed_output, failed_diagnostics, failed_logger, failed_clock) == 0 &&
            failed_logger.calls == 1 &&
            failed_logger.payload.find("\"result\":\"error\"") != std::string::npos &&
            failed_logger.payload.find("\"reason\":\"internal_error\"") != std::string::npos &&
            failed_logger.payload.find(encoded) == std::string::npos,
            "failed authorization output is internal-error denial");

    AdvancingClock deadline_clock;
    deadline_clock.step = 1000000000U;
    FakeLogger deadline_logger;
    std::ostringstream deadline_output;
    std::ostringstream deadline_diagnostics;
    require(credbind::command::run(arguments, deadline_output, deadline_diagnostics,
                                   deadline_logger, deadline_clock) == 0 &&
            deadline_output.str().empty() && deadline_diagnostics.str().empty() &&
            deadline_logger.calls == 1 &&
            deadline_logger.payload.find("\"reason\":\"deadline_exceeded\"") !=
                std::string::npos,
            "cumulative configured deadline denies before output");

    AdvancingClock cancelled_clock;
    cancelled_clock.cancelled = true;
    FakeLogger cancelled_logger;
    std::ostringstream cancelled_output;
    std::ostringstream cancelled_diagnostics;
    require(credbind::command::run(arguments, cancelled_output, cancelled_diagnostics,
                                   cancelled_logger, cancelled_clock) == 0 &&
            cancelled_output.str().empty() && cancelled_diagnostics.str().empty() &&
            cancelled_logger.calls == 1 &&
            cancelled_logger.payload.find("\"reason\":\"operation_cancelled\"") !=
                std::string::npos,
            "cancellation denies before output");

    AdvancingClock simultaneous_clock;
    simultaneous_clock.step = 10000000000U;
    simultaneous_clock.cancelled = true;
    FakeLogger simultaneous_logger;
    std::ostringstream simultaneous_output;
    std::ostringstream simultaneous_diagnostics;
    require(credbind::command::run(arguments, simultaneous_output,
                                   simultaneous_diagnostics, simultaneous_logger,
                                   simultaneous_clock) == 0 &&
            simultaneous_output.str().empty() && simultaneous_diagnostics.str().empty() &&
            simultaneous_logger.calls == 1 &&
            simultaneous_logger.payload.find("\"reason\":\"deadline_exceeded\"") !=
                std::string::npos,
            "deadline precedes simultaneous cancellation");

    const std::vector<std::string_view> check{"config", "check", "--config", path};
    FakeLogger check_logger;
    FakeClock check_clock;
    std::ostringstream check_diagnostics;
    require(credbind::command::run(check, failed_output, check_diagnostics,
                                   check_logger, check_clock) != 0 &&
            check_logger.calls == 1 &&
            check_logger.payload.find("\"result\":\"error\"") != std::string::npos &&
            check_diagnostics.str() == "internal_error\n",
            "config-check output failure is audited internal error");

    CancelAfterCheckClock check_cancel_clock;
    FakeLogger check_cancel_logger;
    std::ostringstream check_cancel_output;
    std::ostringstream check_cancel_diagnostics;
    require(credbind::command::run(check, check_cancel_output,
                                   check_cancel_diagnostics, check_cancel_logger,
                                   check_cancel_clock) != 0 &&
            check_cancel_output.str().empty() &&
            check_cancel_diagnostics.str() == "operation_cancelled\n" &&
            check_cancel_logger.calls == 1 &&
            check_cancel_logger.facility == credbind::audit::Facility::local3 &&
            check_cancel_logger.severity == credbind::audit::Severity::notice &&
            check_cancel_logger.payload.find("\"result\":\"error\"") !=
                std::string::npos &&
            check_cancel_logger.payload.find("\"reason\":\"operation_cancelled\"") !=
                std::string::npos,
            "config-check cancellation is silent on stdout and audited");

    const std::vector<std::string_view> render{
        "sshd-config", "render", "--config", path, "--verifier", "/bin/sh",
        "--command-user", "credbind"};
    std::ostringstream render_diagnostics;
    require(credbind::command::run(render, failed_output, render_diagnostics,
                                   check_logger, check_clock) != 0 &&
            render_diagnostics.str() == "internal_error\n",
            "render output failure returns internal error");
    static_cast<void>(::unlink(path));
}

}  // namespace

int main(int argc, char* argv[]) {
    require(argc == 2 || argc == 4, "fixture path arguments");
    test_audit();
    test_config(argv[1]);
    test_command();
    if (argc == 4) test_authenticated_command(argv[2], argv[3]);
    return 0;
}
