// SPDX-License-Identifier: Apache-2.0

#include "jws.hpp"

#include "base64url.hpp"

#include <array>

namespace credbind::jws {

CompactJwsResult parse_compact(std::string_view input, Limits limits) {
    if (limits.max_compact_bytes == 0U || limits.max_decoded_segment_bytes == 0U) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::resource_limit, "invalid compact JWS limits"});
    }
    if (input.size() > limits.max_compact_bytes) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::resource_limit, "compact JWS exceeds local bound"});
    }

    const auto first = input.find('.');
    if (first == std::string_view::npos) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::malformed_input, "compact JWS is missing separators"});
    }
    const auto second = input.find('.', first + 1U);
    if (second == std::string_view::npos || input.find('.', second + 1U) != std::string_view::npos) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::malformed_input, "compact JWS has wrong segment count"});
    }

    const std::array<std::string_view, 3> segments{
        input.substr(0U, first), input.substr(first + 1U, second - first - 1U),
        input.substr(second + 1U)};
    for (const auto segment : segments) {
        const auto decoded = base64url::decode(segment, limits.max_decoded_segment_bytes);
        if (!decoded) {
            return tl::make_unexpected(decoded.error());
        }
    }
    return CompactJws{std::string(segments[0]), std::string(segments[1]),
                      std::string(segments[2])};
}

}  // namespace credbind::jws
