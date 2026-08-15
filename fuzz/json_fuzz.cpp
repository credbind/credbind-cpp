// SPDX-License-Identifier: Apache-2.0

#include "strict_json.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = std::string_view(reinterpret_cast<const char*>(data), size);
    static_cast<void>(credbind::strict_json::parse_core_envelope(input));
    return 0;
}
