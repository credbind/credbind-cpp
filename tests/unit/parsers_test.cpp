// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"
#include "jws.hpp"
#include "openssh_certificate.hpp"
#include "parse_error.hpp"
#include "strict_json.hpp"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

template <typename Result>
void expect_error(const Result& result, credbind::ParseErrorKind expected, std::string_view name) {
    require(!result, std::string(name) + ": input was accepted");
    require(result.error().kind == expected, std::string(name) + ": wrong error kind");
}

void test_base64url() {
    const auto decoded = credbind::base64url::decode("_w", 1U);
    require(decoded && *decoded == std::vector<std::uint8_t>{0xffU},
            "canonical Base64url decode failed");
    for (const std::string_view input : {"", "_w=", "_w\n", "A", "_x", "+w"}) {
        expect_error(credbind::base64url::decode(input, 64U),
                     credbind::ParseErrorKind::malformed_input, "Base64url rejection");
    }
    expect_error(credbind::base64url::decode("AAAA", 2U),
                 credbind::ParseErrorKind::resource_limit, "Base64url output bound");
}

void test_compact_jws() {
    const std::string valid = "e30.eyJzdWIiOiJhbGljZSJ9.AA";
    const auto parsed = credbind::jws::parse_compact(valid);
    require(parsed && parsed->protected_header == "e30" &&
                parsed->payload == "eyJzdWIiOiJhbGljZSJ9" && parsed->signature == "AA",
            "compact JWS parse did not preserve exact segments");
    for (const std::string_view input : {
             "e30.eyJzdWIiOiJhbGljZSJ9", ".e30.AA", "e30..AA", "e30.e30.",
             "e30.e30.AA.extra", "e30=.e30.AA", "e30.e30.A",
         }) {
        expect_error(credbind::jws::parse_compact(input),
                     credbind::ParseErrorKind::malformed_input, "compact JWS rejection");
    }
    expect_error(credbind::jws::parse_compact(valid, credbind::jws::Limits{8U, 32U}),
                 credbind::ParseErrorKind::resource_limit, "compact JWS byte bound");
}

void append_u32(std::string& output, std::uint32_t value) {
    for (int shift : {24, 16, 8, 0}) {
        output.push_back(static_cast<char>((value >> static_cast<unsigned int>(shift)) & 0xffU));
    }
}

void append_u64(std::string& output, std::uint64_t value) {
    for (int shift : {56, 48, 40, 32, 24, 16, 8, 0}) {
        output.push_back(static_cast<char>((value >> static_cast<unsigned int>(shift)) & 0xffU));
    }
}

std::string ssh_string(std::string_view value) {
    std::string output;
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.append(value);
    return output;
}

struct CertificateOptions {
    bool ecdsa = false;
    std::string certificate_type;
    std::size_t principal_count = 1U;
    std::string critical_options;
    std::vector<std::pair<std::string, std::string>> extensions;
    std::string reserved;
    std::string ca_algorithm;
    std::string signature_algorithm;
    std::uint64_t valid_after = 100U;
    std::uint64_t valid_before = 200U;
};

std::string make_certificate(CertificateOptions options = {}) {
    const std::string ecdsa_key = "ecdsa-sha2-nistp256";
    const std::string ed25519_key = "ssh-ed25519";
    if (options.certificate_type.empty()) {
        options.certificate_type = options.ecdsa
                                       ? "ecdsa-sha2-nistp256-cert-v01@openssh.com"
                                       : "ssh-ed25519-cert-v01@openssh.com";
    }
    if (options.ca_algorithm.empty()) {
        options.ca_algorithm = options.ecdsa ? ecdsa_key : ed25519_key;
    }
    if (options.signature_algorithm.empty()) {
        options.signature_algorithm = options.ecdsa ? ecdsa_key : ed25519_key;
    }
    if (options.extensions.empty()) {
        options.extensions = {
            {"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")},
            {"permit-pty", ""},
        };
    }

    std::string certificate = ssh_string(options.certificate_type);
    certificate += ssh_string(std::string(32U, '\x01'));
    if (options.ecdsa) {
        std::string point(65U, '\x02');
        point[0] = '\x04';
        certificate += ssh_string("nistp256") + ssh_string(point);
    } else {
        certificate += ssh_string(std::string(32U, '\x03'));
    }
    append_u64(certificate, 7U);
    append_u32(certificate, 1U);
    certificate += ssh_string("ignored-key-id");
    std::string principals;
    for (std::size_t index = 0U; index < options.principal_count; ++index) {
        principals += ssh_string(index == 0U ? "credbind-v1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                             : "credbind-v1-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    }
    certificate += ssh_string(principals);
    append_u64(certificate, options.valid_after);
    append_u64(certificate, options.valid_before);
    certificate += ssh_string(options.critical_options);
    std::string extensions;
    for (const auto& extension : options.extensions) {
        extensions += ssh_string(extension.first) + ssh_string(extension.second);
    }
    certificate += ssh_string(extensions);
    certificate += ssh_string(options.reserved);

    std::string ca_blob = ssh_string(options.ca_algorithm);
    if (options.ca_algorithm == ecdsa_key) {
        std::string point(65U, '\x04');
        ca_blob += ssh_string("nistp256") + ssh_string(point);
    } else {
        ca_blob += ssh_string(std::string(32U, '\x05'));
    }
    certificate += ssh_string(ca_blob);

    std::string signature;
    if (options.ecdsa) {
        signature = ssh_string(std::string(1U, '\x01')) + ssh_string(std::string(1U, '\x02'));
    } else {
        signature = std::string(64U, '\x06');
    }
    certificate += ssh_string(ssh_string(options.signature_algorithm) + ssh_string(signature));
    return certificate;
}

void test_openssh_certificate() {
    for (const bool ecdsa : {false, true}) {
        CertificateOptions valid_options;
        valid_options.ecdsa = ecdsa;
        const auto parsed =
            credbind::openssh::parse_certificate(make_certificate(std::move(valid_options)));
        require(parsed && parsed->principals.size() == 1U &&
                    parsed->token == std::vector<std::uint8_t>({'e', '3', '0', '.', 'e', '3', '0', '.', 'A', 'A'}) &&
                    parsed->permission_extensions == std::vector<std::string>{"permit-pty"} &&
                    !parsed->signed_bytes.empty(),
                "OpenSSH certificate parse failed");
    }

    std::vector<std::string> malformed_inputs;
    auto trailing = make_certificate();
    trailing.push_back('\0');
    malformed_inputs.push_back(std::move(trailing));
    auto truncated = make_certificate();
    truncated.pop_back();
    malformed_inputs.push_back(std::move(truncated));
    CertificateOptions unsupported;
    unsupported.certificate_type = "ssh-rsa-cert-v01@openssh.com";
    expect_error(credbind::openssh::parse_certificate(make_certificate(std::move(unsupported))),
                 credbind::ParseErrorKind::unsupported_algorithm,
                 "unsupported certificate algorithm");

    CertificateOptions critical;
    critical.critical_options = "prohibited";
    malformed_inputs.push_back(make_certificate(std::move(critical)));
    CertificateOptions multiple_principals;
    multiple_principals.principal_count = 2U;
    malformed_inputs.push_back(make_certificate(std::move(multiple_principals)));
    CertificateOptions unsorted;
    unsorted.extensions = {{"permit-pty", ""},
                           {"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")}};
    malformed_inputs.push_back(make_certificate(std::move(unsorted)));
    CertificateOptions duplicate;
    duplicate.extensions = {{"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")},
                            {"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")}};
    malformed_inputs.push_back(make_certificate(std::move(duplicate)));
    CertificateOptions direct_carrier;
    direct_carrier.extensions = {{"credbind-ssh-v1@credbind.dev", "e30.e30.AA"}};
    malformed_inputs.push_back(make_certificate(std::move(direct_carrier)));
    CertificateOptions trailing_carrier;
    trailing_carrier.extensions = {
        {"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA") + "x"}};
    malformed_inputs.push_back(make_certificate(std::move(trailing_carrier)));
    CertificateOptions missing_carrier;
    missing_carrier.extensions = {{"permit-pty", ""}};
    malformed_inputs.push_back(make_certificate(std::move(missing_carrier)));
    CertificateOptions unknown;
    unknown.extensions = {{"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")},
                          {"unknown", ""}};
    malformed_inputs.push_back(make_certificate(std::move(unknown)));
    CertificateOptions nonempty_permission;
    nonempty_permission.extensions = {
        {"credbind-ssh-v1@credbind.dev", ssh_string("e30.e30.AA")}, {"permit-pty", "x"}};
    malformed_inputs.push_back(make_certificate(std::move(nonempty_permission)));
    CertificateOptions infinite;
    infinite.valid_before = std::numeric_limits<std::uint64_t>::max();
    malformed_inputs.push_back(make_certificate(std::move(infinite)));

    for (const auto& input : malformed_inputs) {
        expect_error(credbind::openssh::parse_certificate(input),
                     credbind::ParseErrorKind::malformed_input, "OpenSSH certificate rejection");
    }
    CertificateOptions wrong_ca;
    wrong_ca.ca_algorithm = "ecdsa-sha2-nistp256";
    expect_error(credbind::openssh::parse_certificate(make_certificate(std::move(wrong_ca))),
                 credbind::ParseErrorKind::unsupported_algorithm,
                 "carrier CA algorithm substitution");
    CertificateOptions wrong_signature;
    wrong_signature.signature_algorithm = "ecdsa-sha2-nistp256";
    expect_error(
        credbind::openssh::parse_certificate(make_certificate(std::move(wrong_signature))),
        credbind::ParseErrorKind::unsupported_algorithm,
        "certificate signature algorithm substitution");
    expect_error(
        credbind::openssh::parse_certificate(
            make_certificate(), credbind::openssh::Limits{8U, 8U, 1U, 1U, 32U}),
        credbind::ParseErrorKind::resource_limit, "OpenSSH certificate byte bound");
}

void test_core_envelope() {
    const std::string valid =
        R"({"payload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})";
    const auto parsed = credbind::strict_json::parse_core_envelope(valid);
    require(parsed && parsed->payload == "AA" && parsed->caller_signature.protected_header == "AA" &&
                parsed->caller_signature.signature == "AA" && parsed->evidence == "AA",
            "strict core envelope parse failed");

    for (const std::string& input : {
             R"({"payload":"AA","payload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})",
             R"({"payload":"AA","\u0070ayload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})",
             R"({"payload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"} [])",
             R"({"Payload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})",
             R"({"payload":"AA","signatures":[{"protected":"AA","signature":"AA","extra":true}],"credbind_evidence":"AA"})",
             R"({"payload":"AA","signatures":[],"credbind_evidence":"AA"})",
             R"({"payload":1,"signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})",
             R"({"payload":01,"signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})",
         }) {
        expect_error(credbind::strict_json::parse_core_envelope(input),
                     credbind::ParseErrorKind::malformed_input, "strict JSON rejection");
    }

    std::string invalid_utf8 = valid;
    invalid_utf8.insert(invalid_utf8.find("AA"), 1U, static_cast<char>(0xff));
    expect_error(credbind::strict_json::parse_core_envelope(invalid_utf8),
                 credbind::ParseErrorKind::malformed_input, "invalid UTF-8");

    using credbind::strict_json::Limits;
    expect_error(credbind::strict_json::parse_core_envelope(valid, Limits{8, 4, 8, 8, 64}),
                 credbind::ParseErrorKind::resource_limit, "JSON byte bound");
    expect_error(credbind::strict_json::parse_core_envelope(valid, Limits{256, 2, 8, 8, 64}),
                 credbind::ParseErrorKind::resource_limit, "JSON depth bound");
    expect_error(credbind::strict_json::parse_core_envelope(valid, Limits{256, 4, 4, 8, 64}),
                 credbind::ParseErrorKind::resource_limit, "JSON member bound");
    expect_error(credbind::strict_json::parse_core_envelope(valid, Limits{256, 4, 8, 3, 64}),
                 credbind::ParseErrorKind::resource_limit, "JSON value bound");
    expect_error(credbind::strict_json::parse_core_envelope(valid, Limits{256, 4, 8, 8, 4}),
                 credbind::ParseErrorKind::resource_limit, "JSON key bound");
}

}  // namespace

int main(int argc, char** argv) {
    test_base64url();
    test_compact_jws();
    test_core_envelope();
    test_openssh_certificate();
    if (argc == 2) {
        const auto parsed = credbind::strict_json::parse_core_envelope(argv[1]);
        require(static_cast<bool>(parsed), "pinned core token did not pass strict envelope parsing");
    } else if (argc == 3 && std::string_view(argv[1]) == "--compact-jws") {
        require(static_cast<bool>(credbind::jws::parse_compact(argv[2])),
                "pinned compact JWS did not parse");
    } else if (argc == 3 && std::string_view(argv[1]) == "--certificate-file") {
        std::ifstream input(argv[2], std::ios::binary);
        const std::string blob{std::istreambuf_iterator<char>(input),
                               std::istreambuf_iterator<char>()};
        require(input.good() || input.eof(), "could not read pinned certificate file");
        require(static_cast<bool>(credbind::openssh::parse_certificate(blob)),
                "pinned OpenSSH certificate did not parse");
    } else {
        require(argc == 1, "usage: parsers_test [core-token | parser mode]");
    }
    return 0;
}
