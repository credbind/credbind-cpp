// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"
#include "parse_error.hpp"
#include "strict_json.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
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
    test_core_envelope();
    if (argc == 2) {
        const auto parsed = credbind::strict_json::parse_core_envelope(argv[1]);
        require(static_cast<bool>(parsed), "pinned core token did not pass strict envelope parsing");
    } else {
        require(argc == 1, "usage: parsers_test [core-token]");
    }
    return 0;
}
