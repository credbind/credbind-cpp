// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"
#include "crypto.hpp"
#include "direct_verifier.hpp"
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
#include <unordered_map>
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

std::string read_bounded_frame(const char* path, std::size_t maximum,
                               std::string_view message) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    require(static_cast<bool>(input), message);
    const auto end = input.tellg();
    require(end >= 0 && static_cast<std::uint64_t>(end) <= maximum, message);
    std::string frame(static_cast<std::size_t>(end), '\0');
    input.seekg(0, std::ios::beg);
    input.read(frame.data(), static_cast<std::streamsize>(frame.size()));
    require(input.good() || input.eof(), message);
    require(static_cast<std::size_t>(input.gcount()) == frame.size(), message);
    return frame;
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
            {"fixture-subject-v1-rc2", "other"}});
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
                    result->claims.at("sub") == "fixture-subject-v1-rc2" &&
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

void verify_authenticated_claims_frame(const std::string& frame) {
    CryptoFrameReader reader(frame);
    char mode = '\0';
    require(reader.byte(mode), "invalid authenticated-claims frame");
    require(mode == 'P' || mode == 'B' || mode == 'C' || mode == 'N' || mode == 'X',
            "unknown authenticated-claims expectation");
    std::vector<std::string_view> fields;
    for (std::size_t index = 0U; index < 7U; ++index) {
        std::string_view field;
        require(reader.field(field), "truncated authenticated-claims frame");
        fields.push_back(field);
    }
    require(reader.empty(), "trailing authenticated-claims frame");
    std::int64_t verification_time = 0;
    const auto parsed_time = std::from_chars(fields[5].data(),
                                             fields[5].data() + fields[5].size(),
                                             verification_time);
    require(parsed_time.ec == std::errc{} &&
                parsed_time.ptr == fields[5].data() + fields[5].size(),
            "invalid authenticated-claims time");
    const auto object = nlohmann::json::parse(fields[6], nullptr, false);
    require(object.is_object(), "authenticated claims must be an object");
    credbind::issuer::Claims claims;
    for (const auto& item : object.items()) {
        claims.emplace(item.key(), item.value());
    }
    credbind::issuer::Policy policy{
        std::string(fields[2]), {std::string(fields[3])},
        fields[4].empty() ? std::unordered_set<std::string>{}
                          : std::unordered_set<std::string>{std::string(fields[4])},
        {"RS256"}, {credbind::issuer::kStandardEvidence},
        {std::string(fields[0])}, false, 0, 30, {}, {}};
    const auto result = credbind::issuer::validate_authenticated_claims(
        credbind::issuer::VerificationInput{
            credbind::issuer::kStandardEvidence, std::string(fields[0]),
            std::string(fields[1]), "", {}, verification_time},
        policy, claims);
    if (mode == 'P') {
        require(static_cast<bool>(result), "authenticated claims were rejected");
        return;
    }
    const auto expected = mode == 'B' ? credbind::ParseErrorKind::binding_invalid
                          : mode == 'C' ? credbind::ParseErrorKind::issuer_claims_invalid
                          : mode == 'N' ? credbind::ParseErrorKind::credential_not_yet_valid
                                        : credbind::ParseErrorKind::credential_expired;
    expect_error(result, expected, "authenticated-claims rejection");
}

void verify_evidence_digest_mismatch() {
    credbind::crypto::Sha256Digest expected{};
    credbind::crypto::Sha256Digest verified{};
    verified.back() = 1U;
    expect_error(credbind::direct::validate_evidence_result_digest(expected, verified),
                 credbind::ParseErrorKind::evidence_result_mismatch,
                 "evidence-result digest mismatch");
}

void verify_resource_limit(std::string_view name, std::size_t maximum,
                           std::size_t input_size) {
    require(input_size == maximum + 1U, "resource fixture is not just over its bound");
    if (name == "token_bytes") {
        credbind::direct::CorePolicy policy;
        policy.limits.max_token_bytes = maximum;
        policy.limits.max_evidence_bytes = 16384U;
        const auto result = credbind::direct::verify_token(
            std::string(input_size, 'x'), policy, credbind::jwks::StaticJwks{}, 0);
        expect_error(result, credbind::ParseErrorKind::resource_limit,
                     "token byte resource limit");
        return;
    }
    if (name == "evidence_bytes") {
        const std::string evidence((input_size * 4U + 2U) / 3U, 'A');
        const auto result = credbind::base64url::decode(evidence, maximum);
        expect_error(result, credbind::ParseErrorKind::resource_limit,
                     "evidence byte resource limit");
        return;
    }
    if (name == "ssh_certificate_bytes") {
        expect_error(
            credbind::openssh::parse_certificate(
                std::string(input_size, '\0'),
                credbind::openssh::Limits{maximum, 8U, 16U, 16U, 32768U}),
            credbind::ParseErrorKind::resource_limit,
            "SSH certificate byte resource limit");
        return;
    }
    require(false, "unknown internal resource-limit fixture");
}

std::unordered_set<std::string> split_set(std::string_view value) {
    std::unordered_set<std::string> result;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto comma = value.find(',', offset);
        const auto item = value.substr(offset, comma == std::string_view::npos
                                                  ? value.size() - offset
                                                  : comma - offset);
        require(!item.empty() && result.insert(std::string(item)).second,
                "invalid direct-verifier test set");
        if (comma == std::string_view::npos) break;
        offset = comma + 1U;
    }
    return result;
}

std::int64_t parse_i64(std::string_view value, std::string_view name) {
    std::int64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    require(result.ec == std::errc{} && result.ptr == value.data() + value.size(), name);
    return parsed;
}

credbind::ParseErrorKind direct_expected_error(char mode) {
    switch (mode) {
        case 'M': return credbind::ParseErrorKind::malformed_input;
        case 'W': return credbind::ParseErrorKind::unsupported_version;
        case 'R': return credbind::ParseErrorKind::unsupported_profile;
        case 'A': return credbind::ParseErrorKind::unsupported_algorithm;
        case 'K': return credbind::ParseErrorKind::caller_key_invalid;
        case 'E': return credbind::ParseErrorKind::evidence_result_mismatch;
        case 'B': return credbind::ParseErrorKind::binding_invalid;
        case 'Q': return credbind::ParseErrorKind::caller_signature_invalid;
        case 'V': return credbind::ParseErrorKind::ssh_certificate_invalid;
        case 'Y': return credbind::ParseErrorKind::ssh_key_mismatch;
        case 'N': return credbind::ParseErrorKind::ssh_identity_not_yet_valid;
        case 'X': return credbind::ParseErrorKind::ssh_identity_expired;
        case 'J': return credbind::ParseErrorKind::ssh_principal_invalid;
        case 'D': return credbind::ParseErrorKind::account_unauthorized;
        default: return credbind::ParseErrorKind::malformed_input;
    }
}

void verify_direct_carrier_frame(const std::string& frame) {
    CryptoFrameReader reader(frame);
    char mode = '\0';
    require(reader.byte(mode), "invalid direct-verifier test frame");
    require(mode == 'P' || mode == 'M' || mode == 'R' || mode == 'A' || mode == 'K' ||
                mode == 'E' || mode == 'B' || mode == 'Q' || mode == 'V' || mode == 'Y' ||
                mode == 'N' || mode == 'X' || mode == 'J' || mode == 'D',
            "unknown direct-verifier test mode");
    std::vector<std::string_view> fields;
    for (std::size_t index = 0U; index < 23U; ++index) {
        std::string_view field;
        require(reader.field(field), "truncated direct-verifier test frame");
        fields.push_back(field);
    }
    require(reader.empty(), "trailing direct-verifier test frame");
    const auto loaded = credbind::jwks::load_static_file(
        fields[4], credbind::jwks::FilePolicy{static_cast<std::uint32_t>(::geteuid())});
    require(static_cast<bool>(loaded), "direct-verifier fixture JWKS was rejected");
    credbind::issuer::Policy issuer_policy{
        std::string(fields[3]), {std::string(fields[5])},
        fields[6].empty() ? std::unordered_set<std::string>{}
                          : std::unordered_set<std::string>{std::string(fields[6])},
        {"RS256"}, split_set(fields[10]), split_set(fields[11]), fields[19] == "1",
        0, parse_i64(fields[18], "invalid direct-verifier skew"), {},
        split_set(fields[12])};
    credbind::direct::CorePolicy core_policy{split_set(fields[9]),
                                             std::move(issuer_policy)};
    std::vector<credbind::issuer::Predicate> predicates;
    if (fields[15] == "@one-of") {
        predicates.push_back(credbind::issuer::Predicate{
            "sub", credbind::issuer::PredicateOperation::string_one_of, "",
            {"other-subject", "fixture-subject-v1-rc2"}});
    } else if (fields[15] == "@array-wrong-type") {
        predicates.push_back(credbind::issuer::Predicate{
            "sub", credbind::issuer::PredicateOperation::string_array_contains,
            "fixture-subject-v1-rc2", {}});
    } else if (!fields[15].empty() && fields[15] != "@split-rules") {
        predicates.push_back(credbind::issuer::Predicate{
            std::string(fields[15]), credbind::issuer::PredicateOperation::string_equals,
            std::string(fields[16]), {}});
    }
    credbind::direct::AccountPolicies accounts;
    accounts[std::string(fields[2])].push_back(credbind::direct::AccountRule{
        std::string(fields[14]), std::move(predicates), split_set(fields[13])});
    if (fields[15] == "@split-rules") {
        accounts[std::string(fields[2])].clear();
        accounts[std::string(fields[2])].push_back(credbind::direct::AccountRule{
            std::string(fields[14]),
            {credbind::issuer::Predicate{
                "sub", credbind::issuer::PredicateOperation::string_equals,
                "fixture-subject-v1-rc2", {}}},
            {"permit-pty"}});
        accounts[std::string(fields[2])].push_back(credbind::direct::AccountRule{
            std::string(fields[14]),
            {credbind::issuer::Predicate{
                "sub", credbind::issuer::PredicateOperation::string_equals,
                "other-subject", {}}},
            {"permit-port-forwarding", "permit-pty"}});
    }
    const auto result = credbind::direct::verify_carrier(
        credbind::direct::CarrierInput{fields[0], fields[1], fields[2],
                                       parse_i64(fields[7], "invalid direct-verifier time")},
        core_policy,
        credbind::direct::CarrierPolicy{
            std::string(fields[8]),
            parse_i64(fields[17], "invalid maximum identity lifetime"),
            parse_i64(fields[18], "invalid carrier skew")},
        accounts, *loaded);
    if (mode == 'P') {
        require(result && result->principal == fields[20] &&
                    result->ca_key_type == fields[21] &&
                    result->ca_public_key_base64 == fields[22] &&
                    !result->core.commitment.empty() && !result->core.issuer.empty(),
                "direct carrier fixture did not produce the exact complete result");
        return;
    }
    expect_error(result, direct_expected_error(mode), "direct carrier rejection");
}

void verify_direct_token_frame(const std::string& frame) {
    CryptoFrameReader reader(frame);
    char mode = '\0';
    require(reader.byte(mode) && (mode == 'P' || mode == 'Q' || mode == 'M' ||
                                  mode == 'W' || mode == 'R' || mode == 'A' ||
                                  mode == 'K'),
            "invalid direct-token test mode");
    std::vector<std::string_view> fields;
    for (std::size_t index = 0U; index < 12U; ++index) {
        std::string_view field;
        require(reader.field(field), "truncated direct-token test frame");
        fields.push_back(field);
    }
    require(reader.empty(), "trailing direct-token test frame");
    const auto loaded = credbind::jwks::load_static_file(
        fields[2], credbind::jwks::FilePolicy{static_cast<std::uint32_t>(::geteuid())});
    require(static_cast<bool>(loaded), "direct-token fixture JWKS was rejected");
    credbind::issuer::Policy issuer_policy{
        std::string(fields[1]), {std::string(fields[3])},
        fields[4].empty() ? std::unordered_set<std::string>{}
                          : std::unordered_set<std::string>{std::string(fields[4])},
        {"RS256"}, split_set(fields[7]), split_set(fields[8]), false, 0, 30, {},
        split_set(fields[9])};
    const auto result = credbind::direct::verify_token(
        fields[0], credbind::direct::CorePolicy{split_set(fields[6]),
                                                std::move(issuer_policy)},
        *loaded, parse_i64(fields[5], "invalid direct-token time"));
    if (mode == 'P') {
        const auto expected_algorithm =
            fields[11] == "ES256" ? credbind::direct::CallerAlgorithm::es256
                                  : credbind::direct::CallerAlgorithm::ed25519;
        require(result && result->commitment == fields[10] &&
                    result->caller_key.algorithm == expected_algorithm &&
                    result->evidence_profile == fields[7] &&
                    result->binding_profile == fields[8],
                "direct-token fixture did not produce the exact complete result");
        return;
    }
    expect_error(result, direct_expected_error(mode), "direct-token rejection");
}

void test_core_envelope() {
    const std::string valid =
        R"({"payload":"AA","signatures":[{"protected":"AA","signature":"AA"}],"credbind_evidence":"AA"})";
    const auto parsed = credbind::strict_json::parse_core_envelope(valid);
    require(parsed && parsed->payload == "AA" && parsed->caller_signature.protected_header == "AA" &&
                parsed->caller_signature.signature == "AA" && parsed->evidence == "AA",
            "strict core envelope parse failed");

    for (const char* const input : {
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
    if (argc == 2 && std::string_view(argv[1]) == "--digest-mismatch") {
        verify_evidence_digest_mismatch();
    } else if (argc == 2) {
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
    } else if (argc == 3 && std::string_view(argv[1]) == "--direct-carrier-file") {
        const auto frame = read_bounded_frame(
            argv[2], 262144U, "invalid or oversized direct-verifier fixture file");
        verify_direct_carrier_frame(frame);
    } else if (argc == 3 && std::string_view(argv[1]) == "--direct-token-file") {
        const auto frame = read_bounded_frame(
            argv[2], 131072U, "invalid or oversized direct-token fixture file");
        verify_direct_token_frame(frame);
    } else if (argc == 3 && std::string_view(argv[1]) == "--claims-file") {
        const auto frame = read_bounded_frame(
            argv[2], 131072U, "invalid or oversized authenticated-claims fixture file");
        verify_authenticated_claims_frame(frame);
    } else if (argc == 5 && std::string_view(argv[1]) == "--resource-limit") {
        std::size_t maximum = 0U;
        std::size_t input_size = 0U;
        const auto maximum_result = std::from_chars(argv[3], argv[3] + std::strlen(argv[3]), maximum);
        const auto input_result = std::from_chars(argv[4], argv[4] + std::strlen(argv[4]), input_size);
        require(maximum_result.ec == std::errc{} && *maximum_result.ptr == '\0' &&
                    input_result.ec == std::errc{} && *input_result.ptr == '\0',
                "invalid resource-limit number");
        verify_resource_limit(argv[2], maximum, input_size);
    } else {
        require(argc == 1, "usage: parsers_test [core-token | parser mode]");
    }
    return 0;
}
