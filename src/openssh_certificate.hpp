// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_OPENSSH_CERTIFICATE_HPP
#define CREDBIND_OPENSSH_CERTIFICATE_HPP

#include "parse_error.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::openssh {

enum class CallerAlgorithm { es256, ed25519 };

struct Limits {
    std::size_t max_certificate_bytes = 49152;
    std::size_t max_token_bytes = 32768;
    std::size_t max_principals = 16;
    std::size_t max_extensions = 16;
    std::size_t max_name_bytes = 256;
};

struct Certificate {
    CallerAlgorithm caller_algorithm;
    std::vector<std::uint8_t> certified_key;
    std::uint64_t serial;
    std::string key_id;
    std::vector<std::string> principals;
    std::uint64_t valid_after;
    std::uint64_t valid_before;
    std::vector<std::string> permission_extensions;
    std::vector<std::uint8_t> token;
    std::vector<std::uint8_t> signature_key;
    std::string signature_algorithm;
    std::vector<std::uint8_t> signature;
    std::vector<std::uint8_t> signed_bytes;
};

using CertificateResult = tl::expected<Certificate, ParseError>;

[[nodiscard]] CertificateResult parse_certificate(std::string_view blob, Limits limits = {});

}  // namespace credbind::openssh

#endif
