// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_BASE64URL_HPP
#define CREDBIND_BASE64URL_HPP

#include "parse_error.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::base64url {

using DecodeResult = tl::expected<std::vector<std::uint8_t>, ParseError>;

[[nodiscard]] DecodeResult decode(std::string_view encoded, std::size_t max_output_bytes);

}  // namespace credbind::base64url

#endif
