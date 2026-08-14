// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_CRYPTO_HPP
#define CREDBIND_CRYPTO_HPP

#include "parse_error.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::crypto {

struct RsaPublicKey {
    std::vector<std::uint8_t> modulus;
    std::uint32_t exponent;
};

using VerificationResult = tl::expected<void, ParseError>;

[[nodiscard]] VerificationResult verify_rs256(std::string_view signing_input,
                                               const std::vector<std::uint8_t>& signature,
                                               const RsaPublicKey& key);

[[nodiscard]] VerificationResult verify_gq_rs256(
    std::string_view encoded_payload, std::string_view encoded_commitment,
    std::string_view authenticated_issuer, const std::vector<std::uint8_t>& evidence,
    const RsaPublicKey& key);

}  // namespace credbind::crypto

#endif
