// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"
#include "crypto.hpp"
#include "issuer_verifier.hpp"
#include "jwks.hpp"
#include "jws.hpp"
#include "openssh_certificate.hpp"
#include "parse_error.hpp"
#include "strict_json.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <unistd.h>
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

class CryptoFrameReader final {
  public:
    explicit CryptoFrameReader(std::string_view input) : input_(input) {}

    bool byte(char& value) {
        if (offset_ == input_.size()) return false;
        value = input_[offset_++];
        return true;
    }

    bool field(std::string_view& value) {
        if (input_.size() - offset_ < 4U) return false;
        std::uint32_t size = 0U;
        for (std::size_t index = 0U; index < 4U; ++index) {
            size = static_cast<std::uint32_t>(
                (size << 8U) | static_cast<unsigned char>(input_[offset_ + index]));
        }
        offset_ += 4U;
        if (static_cast<std::size_t>(size) > input_.size() - offset_) return false;
        value = input_.substr(offset_, static_cast<std::size_t>(size));
        offset_ += static_cast<std::size_t>(size);
        return true;
    }

    [[nodiscard]] bool empty() const { return offset_ == input_.size(); }

  private:
    std::string_view input_;
    std::size_t offset_ = 0U;
};

std::vector<std::uint8_t> octets(std::string_view value) {
    std::vector<std::uint8_t> result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    return result;
}

void verify_crypto_frame(const std::string& frame) {
    CryptoFrameReader reader(frame);
    char mode = '\0';
    require(reader.byte(mode), "invalid cryptographic test frame");
    const bool expect_success = mode == 'S' || mode == 'G';
    require(expect_success || mode == 's' || mode == 'g', "unknown cryptographic test mode");
    const auto expected_error = mode == 's' ? credbind::ParseErrorKind::issuer_signature_invalid
                                             : credbind::ParseErrorKind::evidence_invalid;

    std::vector<std::string_view> fields;
    const std::size_t field_count = mode == 'S' || mode == 's' ? 4U : 6U;
    for (std::size_t index = 0U; index < field_count; ++index) {
        std::string_view field;
        require(reader.field(field), "truncated cryptographic test frame");
        fields.push_back(field);
    }
    require(reader.empty() && fields.back().size() == 4U,
            "invalid cryptographic test frame fields");
    std::uint32_t exponent = 0U;
    for (const char character : fields.back()) {
        exponent = static_cast<std::uint32_t>(
            (exponent << 8U) | static_cast<unsigned char>(character));
    }

    credbind::crypto::VerificationResult result;
    if (mode == 'S' || mode == 's') {
        result = credbind::crypto::verify_rs256(
            fields[0], octets(fields[1]),
            credbind::crypto::RsaPublicKey{octets(fields[2]), exponent});
    } else {
        result = credbind::crypto::verify_gq_rs256(
            fields[0], fields[1], fields[2], octets(fields[3]),
            credbind::crypto::RsaPublicKey{octets(fields[4]), exponent});
    }
    require(static_cast<bool>(result) == expect_success,
            "cryptographic fixture had unexpected result");
    if (!expect_success) {
        require(result.error().kind == expected_error,
                "cryptographic fixture had unexpected error category");
    }
}

void test_jwks_policy() {
    const auto result = credbind::jwks::load(
        credbind::jwks::KeySource{credbind::jwks::KeySourceProfile::oidc_discovery, ""},
        credbind::jwks::FilePolicy{static_cast<std::uint32_t>(::geteuid())});
    expect_error(result, credbind::ParseErrorKind::unsupported_profile,
                 "offline discovery rejection");
    expect_error(
        credbind::jwks::parse("{\"keys\":[]}", credbind::jwks::Limits{8U, 1U, 8U, 8U}),
        credbind::ParseErrorKind::resource_limit, "static JWKS byte bound");
}

void verify_jwks_file(std::string_view path, std::string_view kid,
                      credbind::ParseErrorKind expected, bool expect_success) {
    const auto loaded = credbind::jwks::load(
        credbind::jwks::KeySource{credbind::jwks::KeySourceProfile::static_jwks_file,
                                 std::string(path)},
        credbind::jwks::FilePolicy{static_cast<std::uint32_t>(::geteuid())});
    if (expect_success) {
        require(static_cast<bool>(loaded), "pinned static JWKS was rejected");
        require(loaded->size() == 1U, "pinned static JWKS has wrong key count");
        const auto key = loaded->resolve_rs256(kid);
        require(key && key->exponent == 65537U && key->modulus.size() == 256U,
                "pinned static JWKS key resolution failed");
        return;
    }
    if (!loaded) {
        require(loaded.error().kind == expected, "static JWKS had wrong error category");
        return;
    }
    const auto key = loaded->resolve_rs256(kid);
    expect_error(key, expected, "static JWKS key resolution rejection");
}

credbind::ParseErrorKind issuer_expected_error(char mode) {
    switch (mode) {
        case 'M': return credbind::ParseErrorKind::malformed_input;
        case 'R': return credbind::ParseErrorKind::unsupported_profile;
        case 'A': return credbind::ParseErrorKind::unsupported_algorithm;
        case 'U': return credbind::ParseErrorKind::issuer_untrusted;
        case 'S': return credbind::ParseErrorKind::issuer_signature_invalid;
        case 'E': return credbind::ParseErrorKind::evidence_invalid;
        case 'B': return credbind::ParseErrorKind::binding_invalid;
        case 'C': return credbind::ParseErrorKind::issuer_claims_invalid;
        case 'N': return credbind::ParseErrorKind::credential_not_yet_valid;
        case 'X': return credbind::ParseErrorKind::credential_expired;
        default: return credbind::ParseErrorKind::malformed_input;
    }
}

void verify_issuer_frame(const std::string& frame) {
    CryptoFrameReader reader(frame);
    char mode = '\0';
    require(reader.byte(mode), "invalid issuer-verifier test frame");
    require(mode == 'P' || mode == 'M' || mode == 'R' || mode == 'A' || mode == 'U' ||
                mode == 'S' || mode == 'E' || mode == 'B' || mode == 'C' || mode == 'N' ||
                mode == 'X',
            "unknown issuer-verifier test mode");
    std::vector<std::string_view> fields;
    for (std::size_t index = 0U; index < 13U; ++index) {
        std::string_view field;
        require(reader.field(field), "truncated issuer-verifier test frame");
        fields.push_back(field);
    }
    require(reader.empty(), "trailing issuer-verifier test frame");
    std::int64_t verification_time = 0;
    const auto parsed_time = std::from_chars(fields[9].data(), fields[9].data() + fields[9].size(),
                                             verification_time);
    require(parsed_time.ec == std::errc{} && parsed_time.ptr == fields[9].data() + fields[9].size(),
            "invalid issuer-verifier test time");

    const auto loaded = credbind::jwks::load_static_file(
        fields[6], credbind::jwks::FilePolicy{static_cast<std::uint32_t>(::geteuid())});
    require(static_cast<bool>(loaded), "issuer-verifier fixture JWKS was rejected");
    credbind::issuer::Policy policy{
        std::string(fields[5]), {std::string(fields[7])},
        fields[8].empty() ? std::unordered_set<std::string>{}
                          : std::unordered_set<std::string>{std::string(fields[8])},
        {"RS256"}, {std::string(fields[0])}, {std::string(fields[1])}, false, 0, 30,
        {}, {"sub", "email", "iat"}};
    const std::string scenario(fields[10]);
    if (scenario == "wrong-audience") {
        policy.audiences = {"wrong-audience"};
    } else if (scenario == "wrong-authorized-party") {
        policy.authorized_parties = {"wrong-authorized-party"};
    } else if (scenario == "wrong-issuer") {
        policy.issuer = "https://other-issuer.example.test";
    } else if (scenario == "required-claim-wrong") {
        policy.required_claims.push_back(credbind::issuer::Predicate{
            "email", credbind::issuer::PredicateOperation::string_equals,
            "wrong@example.test", {}});
    } else if (scenario == "required-one-of-pass") {
        policy.required_claims.push_back(credbind::issuer::Predicate{
            "sub", credbind::issuer::PredicateOperation::string_one_of, "",
            {"fixture-subject-v1-rc1", "other"}});
    } else if (scenario == "required-array-contains-wrong") {
        policy.required_claims.push_back(credbind::issuer::Predicate{
            "aud", credbind::issuer::PredicateOperation::string_array_contains,
            "missing", {}});
    } else if (scenario == "non-reconstructible") {
        policy.require_non_reconstructible_evidence = true;
    } else if (scenario == "disallowed-binding") {
        policy.binding_profiles = {credbind::issuer::kAudienceBinding};
    } else if (scenario == "maximum-age") {
        policy.maximum_credential_age_seconds = 100;
    } else {
        require(scenario.empty(), "unknown issuer-verifier policy scenario");
    }

    const auto result = credbind::issuer::verify(
        credbind::issuer::VerificationInput{
            std::string(fields[0]), std::string(fields[1]), std::string(fields[2]),
            std::string(fields[3]), octets(fields[4]), verification_time},
        policy, *loaded);
    if (mode == 'P') {
        require(result && result->issuer == policy.issuer && !result->issuer_key_id.empty() &&
                    result->binding_profile == fields[1] && result->claims.size() == 3U &&
                    result->claims.at("sub") == "fixture-subject-v1-rc1" &&
                    result->claims.at("iat").is_number_integer() &&
                    result->credential_valid_until_unix > verification_time &&
                    fields[11].size() == result->verified_evidence_digest.size() &&
                    std::equal(result->verified_evidence_digest.begin(),
                               result->verified_evidence_digest.end(), fields[11].begin(),
                               [](std::uint8_t left, char right) {
                                   return left == static_cast<std::uint8_t>(
                                                      static_cast<unsigned char>(right));
                               }),
                "issuer-verifier fixture did not produce a complete result");
        std::int64_t expected_valid_until = 0;
        const auto parsed_valid_until = std::from_chars(
            fields[12].data(), fields[12].data() + fields[12].size(), expected_valid_until);
        require(parsed_valid_until.ec == std::errc{} &&
                    parsed_valid_until.ptr == fields[12].data() + fields[12].size() &&
                    result->credential_valid_until_unix == expected_valid_until,
                "issuer-verifier credential validity boundary mismatch");
        return;
    }
    expect_error(result, issuer_expected_error(mode), "issuer-verifier rejection");
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
    test_jwks_policy();
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
    } else if (argc == 3 && std::string_view(argv[1]) == "--crypto-file") {
        std::ifstream input(argv[2], std::ios::binary);
        const std::string frame{std::istreambuf_iterator<char>(input),
                                std::istreambuf_iterator<char>()};
        require(input.good() || input.eof(), "could not read cryptographic fixture file");
        verify_crypto_frame(frame);
    } else if (argc == 5 && std::string_view(argv[1]) == "--jwks-file") {
        const std::string_view expectation(argv[2]);
        const bool expect_success = expectation == "pass";
        require(expect_success || expectation == "untrusted" || expectation == "limit",
                "unknown static JWKS test expectation");
        const auto expected = expectation == "limit" ? credbind::ParseErrorKind::resource_limit
                                                       : credbind::ParseErrorKind::issuer_untrusted;
        verify_jwks_file(argv[3], argv[4], expected, expect_success);
    } else if (argc == 3 && std::string_view(argv[1]) == "--issuer-file") {
        std::ifstream input(argv[2], std::ios::binary);
        const std::string frame{std::istreambuf_iterator<char>(input),
                                std::istreambuf_iterator<char>()};
        require(input.good() || input.eof(), "could not read issuer-verifier fixture file");
        verify_issuer_frame(frame);
    } else {
        require(argc == 1, "usage: parsers_test [core-token | parser mode]");
    }
    return 0;
}
