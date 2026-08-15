// SPDX-License-Identifier: Apache-2.0

#include "base64url.hpp"
#include "jws.hpp"
#include "strict_json.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = std::string_view(reinterpret_cast<const char*>(data), size);
    const auto envelope = credbind::strict_json::parse_core_envelope(input);
    if (envelope) {
        static_cast<void>(credbind::base64url::decode(envelope->payload, 32768U));
        static_cast<void>(credbind::base64url::decode(envelope->caller_signature.protected_header,
                                                     32768U));
        static_cast<void>(credbind::base64url::decode(envelope->caller_signature.signature,
                                                     32768U));
        static_cast<void>(credbind::base64url::decode(envelope->evidence, 16384U));
    }
    static_cast<void>(credbind::jws::parse_compact(input));
    return 0;
}
