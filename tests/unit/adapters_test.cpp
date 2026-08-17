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
#include <unordered_set>
#include <utility>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>

namespace {

std::unordered_set<std::string> conformance_assertions;

void conformance_asserted(std::string id) {
    conformance_assertions.insert(std::move(id));
}

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
    if (const char* observable = std::getenv("CREDBIND_AUDIT_OBSERVABLE");
        observable != nullptr) {
        std::ofstream output(observable, std::ios::binary | std::ios::trunc);
        require(output.is_open(), "open audit observable");
        output << serialized->payload << '\n' << "info\n";
        require(output.good(), "write audit observable");
    }
    conformance_asserted("audit-event-go-cpp-equivalence");

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
    conformance_asserted("cpp-rejects-oidc-discovery-config");
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

void test_help() {
    const std::vector<std::pair<std::vector<std::string_view>, std::string_view>> topics{
        {{}, R"(Usage:
  credbind-ssh-authorized-keys version
  credbind-ssh-authorized-keys config init --policy-input PATH [OPTIONS]
  credbind-ssh-authorized-keys config init --deny-all [OPTIONS]
  credbind-ssh-authorized-keys config check --config PATH
  credbind-ssh-authorized-keys sshd-config render --config PATH --verifier PATH --command-user USER
  credbind-ssh-authorized-keys verify --config PATH --user USER --key KEY --key-type TYPE

Options:
  -h, --help  Show help.
)"},
        {{"version"}, R"(Usage:
  credbind-ssh-authorized-keys version

Print version metadata as JSON.
)"},
        {{"config"}, R"(Usage:
  credbind-ssh-authorized-keys config init --help
  credbind-ssh-authorized-keys config check --help
)"},
        {{"config", "init"}, R"(Usage:
  credbind-ssh-authorized-keys config init --policy-input PATH [OPTIONS]
  credbind-ssh-authorized-keys config init --deny-all [OPTIONS]

Options:
  --policy-input PATH                         Initialize from explicit trust and account policy.
  --deny-all                                  Initialize an explicit deny-all policy.
  --clock-skew DURATION                       Set verifier clock skew.
  --total-verification-deadline DURATION      Set the total verification deadline.
  --max-token-bytes INTEGER                   Set the token byte limit.
  --max-evidence-bytes INTEGER                Set the evidence byte limit.
  --max-ssh-certificate-bytes INTEGER         Set the SSH certificate byte limit.
  --max-offered-key-chars INTEGER             Set the offered-key character limit.
  --max-authorized-keys-output-chars INTEGER  Set the authorized-keys output limit.
  --issuer-key-cache-directory PATH           Set the issuer-key cache directory.
  --issuer-key-cache-maximum-freshness DURATION
                                               Set the issuer-key cache freshness limit.
  --logging-facility FACILITY                 Set the local syslog facility.
  --output PATH                               Atomically write instead of using stdout.
  --force                                     Replace an existing regular output file.
  -h, --help                                  Show help.
)"},
        {{"config", "check"}, R"(Usage:
  credbind-ssh-authorized-keys config check --config PATH

Validate configuration offline without changing it.
)"},
        {{"sshd-config"}, R"(Usage:
  credbind-ssh-authorized-keys sshd-config render --help
)"},
        {{"sshd-config", "render"}, R"(Usage:
  credbind-ssh-authorized-keys sshd-config render --config PATH --verifier PATH --command-user USER

Render the minimal OpenSSH AuthorizedKeysCommand fragment without installing it.
)"},
        {{"verify"}, R"(Usage:
  credbind-ssh-authorized-keys verify --config PATH --user USER --key KEY --key-type TYPE

Verify one OpenSSH certificate request. Denial produces empty stdout and exit status 0.
)"},
    };
    for (const auto& topic : topics) {
        for (const std::string_view flag : {"-h", "--help"}) {
            auto arguments = topic.first;
            arguments.push_back(flag);
            FakeLogger logger;
            ThrowClock clock;
            std::ostringstream output;
            std::ostringstream diagnostics;
            require(credbind::command::run(arguments, output, diagnostics,
                                            logger, clock) == 0,
                    "help exits zero");
            require(output.str() == topic.second && diagnostics.str().empty(),
                    "help exact stdout and empty stderr");
            require(logger.calls == 0, "help does not emit audit events");
        }
    }
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
            {"issuer", "https://issuer.v1-rc4.example.test"},
            {"key_source", {{"type", "static-jwks-file"}, {"path", jwks_path}}},
            {"audiences", {"credbind-v1-rc4-client"}},
            {"authorized_parties", {"credbind-v1-rc4-client"}},
            {"issuer_algorithms", {"RS256"}}, {"caller_algorithms", {"ES256"}},
            {"evidence_profiles", {"standard-jws-v1"}},
            {"binding_profiles", {"oidc-nonce-v1"}},
            {"acquisition_profiles", {"oidc-native-auth-code-v1"}},
            {"require_non_reconstructible_evidence", false},
            {"certificate_principal_claim", "sub"}}}},
        {"accounts", {{"fixture-user", {{"allow", {nlohmann::json{
            {"issuer", "https://issuer.v1-rc4.example.test"},
            {"all", {nlohmann::json{{"claim", "sub"}, {"type", "string"},
                                     {"op", "equals"},
                                     {"value", "fixture-subject-v1-rc4"}}}},
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

    const std::vector<std::string_view> denied_arguments{
        "verify", "--config", path, "--user", "unauthorized-user", "--key", encoded,
        "--key-type", key_type};
    FakeLogger denied_logger;
    FakeClock denied_clock;
    denied_clock.wall = 1788739500;
    std::ostringstream denied_output;
    std::ostringstream denied_diagnostics;
    require(credbind::command::run(
                denied_arguments, denied_output, denied_diagnostics,
                denied_logger, denied_clock) == 0 &&
            denied_output.str().empty() && denied_diagnostics.str().empty() &&
            denied_logger.calls == 1 &&
            denied_logger.payload.find("\"reason\":\"account_unauthorized\"") !=
                std::string::npos,
            "account denial exits zero with empty authorization output");
    conformance_asserted("ssh-deny-empty-stdout-zero-exit");

    const std::string oversized_key(65537U, 'A');
    const std::vector<std::string_view> resource_arguments{
        "verify", "--config", path, "--user", "fixture-user", "--key", oversized_key,
        "--key-type", key_type};
    FakeLogger resource_logger;
    FakeClock resource_clock;
    std::ostringstream resource_output;
    std::ostringstream resource_diagnostics;
    require(credbind::command::run(
                resource_arguments, resource_output, resource_diagnostics,
                resource_logger, resource_clock) == 0 &&
            resource_output.str().empty() && resource_diagnostics.str().empty() &&
            resource_logger.calls == 1 &&
            resource_logger.payload.find("\"reason\":\"resource_limit\"") !=
                std::string::npos,
            "resource denial translates to zero exit and empty authorization output");
    for (const std::string_view id : {
             "resource-limit-just-over-authorized_keys_output_chars",
             "resource-limit-just-over-evidence_bytes",
             "resource-limit-just-over-offered_key_chars",
             "resource-limit-just-over-ssh_certificate_bytes",
             "resource-limit-just-over-token_bytes"}) {
        conformance_asserted(std::string(id));
    }

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
    conformance_asserted("deadline-cumulative-two-phase-no-reset");

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
    conformance_asserted("operation-cancelled-before-deadline");

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
    conformance_asserted("deadline-vs-operation-cancelled-precedence");
    conformance_asserted("deadline-exact-boundary-empty-stdout");

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
        "sshd-config", "render", "--config", path, "--verifier", path,
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
    if (argc == 4 && std::string_view(argv[1]) == "--size-bound") {
        std::size_t maximum = 0U;
        std::size_t input_size = 0U;
        try {
            maximum = static_cast<std::size_t>(std::stoull(argv[2]));
            input_size = static_cast<std::size_t>(std::stoull(argv[3]));
        } catch (...) {
            require(false, "invalid size-bound fixture");
        }
        const auto result = credbind::command::validate_size_bound(input_size, maximum);
        require(!result && result.error().kind == credbind::ParseErrorKind::resource_limit,
                "size-bound fixture did not return resource_limit");
        return 0;
    }
    require(argc == 2 || argc == 4, "fixture path arguments");
    test_audit();
    test_config(argv[1]);
    test_help();
    test_command();
    if (argc == 4) test_authenticated_command(argv[2], argv[3]);
    if (const char* selected = std::getenv("CREDBIND_CONFORMANCE_CASE"); selected != nullptr) {
        require(conformance_assertions.find(selected) != conformance_assertions.end(),
                "selected conformance case did not execute its exact assertion");
    }
    return 0;
}
