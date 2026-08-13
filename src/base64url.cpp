// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"

#include <array>
#include <cstddef>
#include <limits>

namespace credbind::base64url {
namespace {

constexpr std::uint8_t kInvalid = std::numeric_limits<std::uint8_t>::max();

constexpr std::array<std::uint8_t, 256> decode_table() {
    std::array<std::uint8_t, 256> table{};
    for (std::size_t index = 0; index < table.size(); ++index) {
        table[index] = kInvalid;
    }
    for (std::uint8_t index = 0; index < 26; ++index) {
        table[static_cast<std::size_t>('A') + index] = index;
        table[static_cast<std::size_t>('a') + index] = static_cast<std::uint8_t>(26U + index);
    }
    for (std::uint8_t index = 0; index < 10; ++index) {
        table[static_cast<std::size_t>('0') + index] = static_cast<std::uint8_t>(52U + index);
    }
    table[static_cast<std::size_t>('-')] = 62;
    table[static_cast<std::size_t>('_')] = 63;
    return table;
}

constexpr auto kDecode = decode_table();

tl::expected<std::uint8_t, ParseError> sextet(char character) {
    const auto value = kDecode[static_cast<unsigned char>(character)];
    if (value == kInvalid) {
        return tl::make_unexpected(ParseError{ParseErrorKind::malformed_input,
                                               "invalid Base64url character"});
    }
    return value;
}

}  // namespace

DecodeResult decode(std::string_view encoded, std::size_t max_output_bytes) {
    if (max_output_bytes == 0U) {
        return tl::make_unexpected(ParseError{ParseErrorKind::resource_limit,
                                               "invalid Base64url output limit"});
    }
    if (encoded.empty() || encoded.size() % 4U == 1U) {
        return tl::make_unexpected(ParseError{ParseErrorKind::malformed_input,
                                               "invalid Base64url length"});
    }
    const auto complete_groups = encoded.size() / 4U;
    const auto remainder = encoded.size() % 4U;
    if (complete_groups > max_output_bytes / 3U ||
        complete_groups * 3U + (remainder == 0U ? 0U : remainder - 1U) > max_output_bytes) {
        return tl::make_unexpected(ParseError{ParseErrorKind::resource_limit,
                                               "Base64url output exceeds local bound"});
    }

    std::vector<std::uint8_t> output;
    output.reserve(complete_groups * 3U + (remainder == 0U ? 0U : remainder - 1U));
    std::size_t offset = 0;
    while (encoded.size() - offset >= 4U) {
        const auto a = sextet(encoded[offset]);
        const auto b = sextet(encoded[offset + 1U]);
        const auto c = sextet(encoded[offset + 2U]);
        const auto d = sextet(encoded[offset + 3U]);
        if (!a || !b || !c || !d) {
            return tl::make_unexpected(!a ? a.error() : !b ? b.error() : !c ? c.error() : d.error());
        }
        output.push_back(static_cast<std::uint8_t>((*a << 2U) | (*b >> 4U)));
        output.push_back(static_cast<std::uint8_t>((*b << 4U) | (*c >> 2U)));
        output.push_back(static_cast<std::uint8_t>((*c << 6U) | *d));
        offset += 4U;
    }
    const auto remaining = encoded.size() - offset;
    if (remaining == 2U) {
        const auto a = sextet(encoded[offset]);
        const auto b = sextet(encoded[offset + 1U]);
        if (!a || !b) {
            return tl::make_unexpected(!a ? a.error() : b.error());
        }
        if ((*b & 0x0fU) != 0U) {
            return tl::make_unexpected(ParseError{ParseErrorKind::malformed_input,
                                                   "non-zero Base64url pad bits"});
        }
        output.push_back(static_cast<std::uint8_t>((*a << 2U) | (*b >> 4U)));
    } else if (remaining == 3U) {
        const auto a = sextet(encoded[offset]);
        const auto b = sextet(encoded[offset + 1U]);
        const auto c = sextet(encoded[offset + 2U]);
        if (!a || !b || !c) {
            return tl::make_unexpected(!a ? a.error() : !b ? b.error() : c.error());
        }
        if ((*c & 0x03U) != 0U) {
            return tl::make_unexpected(ParseError{ParseErrorKind::malformed_input,
                                                   "non-zero Base64url pad bits"});
        }
        output.push_back(static_cast<std::uint8_t>((*a << 2U) | (*b >> 4U)));
        output.push_back(static_cast<std::uint8_t>((*b << 4U) | (*c >> 2U)));
    }
    return output;
}

}  // namespace credbind::base64url
