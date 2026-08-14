// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_JWKS_HPP
#define CREDBIND_JWKS_HPP

#include "crypto.hpp"
#include "parse_error.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <tl/expected.hpp>

namespace credbind::jwks {

struct Limits {
    std::size_t max_bytes = 1048576U;
    std::size_t max_keys = 64U;
    std::size_t max_members = 512U;
    std::size_t max_kid_bytes = 256U;
};

struct FilePolicy {
    std::uint32_t required_owner;
    bool allow_root_owner = true;
    Limits limits{};
};

class StaticJwks final {
  public:
    [[nodiscard]] tl::expected<crypto::RsaPublicKey, ParseError> resolve_rs256(
        std::string_view kid) const;
    [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }

  private:
    friend tl::expected<StaticJwks, ParseError> parse(std::string_view, Limits);
    std::unordered_map<std::string, crypto::RsaPublicKey> keys_;
};

enum class KeySourceProfile { static_jwks_file, oidc_discovery };

struct KeySource {
    KeySourceProfile profile;
    std::string path;
};

using JwksResult = tl::expected<StaticJwks, ParseError>;

[[nodiscard]] JwksResult parse(std::string_view input, Limits limits = {});
[[nodiscard]] JwksResult load_static_file(std::string_view path,
                                          const FilePolicy& policy);
[[nodiscard]] JwksResult load(const KeySource& source, const FilePolicy& policy);

}  // namespace credbind::jwks

#endif
