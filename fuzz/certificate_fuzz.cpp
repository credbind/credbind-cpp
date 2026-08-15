// SPDX-License-Identifier: Apache-2.0

#include "openssh_certificate.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = std::string_view(reinterpret_cast<const char*>(data), size);
    static_cast<void>(credbind::openssh::parse_certificate(input));
    return 0;
}
