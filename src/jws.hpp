// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_JWS_HPP
#define CREDBIND_JWS_HPP

#include "parse_error.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include <tl/expected.hpp>

namespace credbind::jws {

struct Limits {
    std::size_t max_compact_bytes = 32768;
    std::size_t max_decoded_segment_bytes = 32768;
};

struct CompactJws {
    std::string protected_header;
    std::string payload;
    std::string signature;
};

using CompactJwsResult = tl::expected<CompactJws, ParseError>;

[[nodiscard]] CompactJwsResult parse_compact(std::string_view input, Limits limits = {});

}  // namespace credbind::jws

#endif
