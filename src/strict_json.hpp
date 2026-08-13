// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_STRICT_JSON_HPP
#define CREDBIND_STRICT_JSON_HPP

#include "parse_error.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include <tl/expected.hpp>

namespace credbind::strict_json {

struct Limits {
    std::size_t max_bytes = 32768;
    std::size_t max_depth = 32;
    std::size_t max_members = 4096;
    std::size_t max_values = 4096;
    std::size_t max_key_bytes = 256;
};

struct CoreSignature {
    std::string protected_header;
    std::string signature;
};

struct CoreEnvelope {
    std::string payload;
    CoreSignature caller_signature;
    std::string evidence;
};

using CoreEnvelopeResult = tl::expected<CoreEnvelope, ParseError>;

[[nodiscard]] CoreEnvelopeResult parse_core_envelope(std::string_view input,
                                                      Limits limits = {});

}  // namespace credbind::strict_json

#endif
