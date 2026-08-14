// SPDX-License-Identifier: Apache-2.0

#include "jwks.hpp"

#include "base64url.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <vector>

namespace credbind::jwks {
namespace {

using Json = nlohmann::json;

ParseError untrusted(std::string message) {
    return ParseError{ParseErrorKind::issuer_untrusted, std::move(message)};
}

class FileDescriptor final {
  public:
    explicit FileDescriptor(int value) : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) {
            static_cast<void>(::close(value_));
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    [[nodiscard]] int get() const noexcept { return value_; }

  private:
    int value_;
};

struct ParsedKey {
    std::string kty;
    std::string kid;
    std::string use;
    std::string alg;
    std::string n;
    std::string e;
};

enum class ContextKind { root_object, keys_array, key_object };

struct Context {
    ContextKind kind;
    std::unordered_set<std::string> members;
    std::string pending_name;
};

class JwksSax final : public nlohmann::json_sax<Json> {
  public:
    explicit JwksSax(Limits limits) : limits_(limits) {}

    bool null() override { return wrong_type(); }
    bool boolean(bool) override { return wrong_type(); }
    bool number_integer(number_integer_t) override { return wrong_type(); }
    bool number_unsigned(number_unsigned_t) override { return wrong_type(); }
    bool number_float(number_float_t, const string_t&) override { return wrong_type(); }

    bool string(string_t& value) override {
        if (stack_.empty() || stack_.back().kind != ContextKind::key_object) {
            return fail(ParseErrorKind::issuer_untrusted, "wrong JWKS member type");
        }
        auto& context = stack_.back();
        if (context.pending_name.empty()) {
            return fail(ParseErrorKind::issuer_untrusted, "JWKS string has no member name");
        }
        if (context.pending_name == "kid" &&
            (value.empty() || value.size() > limits_.max_kid_bytes)) {
            return fail(ParseErrorKind::issuer_untrusted, "invalid issuer key ID");
        }
        auto assign = [&value](std::string& destination) { destination = std::move(value); };
        if (context.pending_name == "kty") {
            assign(current_.kty);
        } else if (context.pending_name == "kid") {
            assign(current_.kid);
        } else if (context.pending_name == "use") {
            assign(current_.use);
        } else if (context.pending_name == "alg") {
            assign(current_.alg);
        } else if (context.pending_name == "n") {
            assign(current_.n);
        } else if (context.pending_name == "e") {
            assign(current_.e);
        } else {
            return fail(ParseErrorKind::issuer_untrusted, "unsupported JWK member");
        }
        context.pending_name.clear();
        return true;
    }

    bool binary(binary_t&) override {
        return fail(ParseErrorKind::issuer_untrusted, "binary JWKS value is unsupported");
    }

    bool start_object(std::size_t) override {
        if (stack_.empty()) {
            stack_.push_back(Context{ContextKind::root_object, {}, {}});
            return true;
        }
        if (stack_.back().kind != ContextKind::keys_array) {
            return fail(ParseErrorKind::issuer_untrusted, "wrong JWKS object structure");
        }
        ++key_count_;
        if (key_count_ > limits_.max_keys) {
            return fail(ParseErrorKind::resource_limit, "JWKS key-count bound");
        }
        current_ = ParsedKey{};
        stack_.push_back(Context{ContextKind::key_object, {}, {}});
        return true;
    }

    bool key(string_t& value) override {
        if (stack_.empty() || stack_.back().kind == ContextKind::keys_array) {
            return fail(ParseErrorKind::issuer_untrusted, "JWKS member outside object");
        }
        ++member_count_;
        if (member_count_ > limits_.max_members) {
            return fail(ParseErrorKind::resource_limit, "JWKS member-count bound");
        }
        auto& context = stack_.back();
        if (!context.members.insert(value).second) {
            return fail(ParseErrorKind::issuer_untrusted, "duplicate JWKS member");
        }
        if (context.kind == ContextKind::root_object) {
            if (value != "keys") {
                return fail(ParseErrorKind::issuer_untrusted, "unknown JWKS top-level member");
            }
        } else if (value != "kty" && value != "kid" && value != "use" && value != "alg" &&
                   value != "n" && value != "e") {
            return fail(ParseErrorKind::issuer_untrusted, "unsupported or private JWK member");
        }
        context.pending_name = std::move(value);
        return true;
    }

    bool end_object() override {
        if (stack_.empty()) {
            return fail(ParseErrorKind::issuer_untrusted, "unexpected JWKS object end");
        }
        if (stack_.back().kind == ContextKind::key_object) {
            if (!complete_key()) {
                return false;
            }
            parsed_keys_.push_back(std::move(current_));
        } else if (stack_.back().kind == ContextKind::root_object) {
            if (!have_keys_ || stack_.back().members.size() != 1U) {
                return fail(ParseErrorKind::issuer_untrusted, "missing JWKS keys member");
            }
        } else {
            return fail(ParseErrorKind::issuer_untrusted, "JWKS object ended inside array");
        }
        stack_.pop_back();
        return true;
    }

    bool start_array(std::size_t) override {
        if (stack_.empty() || stack_.back().kind != ContextKind::root_object ||
            stack_.back().pending_name != "keys") {
            return fail(ParseErrorKind::issuer_untrusted, "wrong JWKS array structure");
        }
        have_keys_ = true;
        stack_.back().pending_name.clear();
        stack_.push_back(Context{ContextKind::keys_array, {}, {}});
        return true;
    }

    bool end_array() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::keys_array) {
            return fail(ParseErrorKind::issuer_untrusted, "unexpected JWKS array end");
        }
        if (key_count_ == 0U) {
            return fail(ParseErrorKind::issuer_untrusted, "empty JWKS key set");
        }
        stack_.pop_back();
        return true;
    }

    bool parse_error(std::size_t, const std::string&,
                     const nlohmann::detail::exception&) override {
        return fail(ParseErrorKind::issuer_untrusted, "invalid strict JWKS JSON");
    }

    [[nodiscard]] bool has_error() const noexcept { return failed_; }
    [[nodiscard]] const ParseError& error() const noexcept { return error_; }
    [[nodiscard]] std::vector<ParsedKey> take_keys() { return std::move(parsed_keys_); }

  private:
    bool wrong_type() {
        return fail(ParseErrorKind::issuer_untrusted, "wrong JWKS member type");
    }

    bool complete_key() {
        const auto& members = stack_.back().members;
        if (members.size() != 6U || current_.kty.empty() || current_.kid.empty() ||
            current_.use.empty() || current_.alg.empty() || current_.n.empty() ||
            current_.e.empty()) {
            return fail(ParseErrorKind::issuer_untrusted, "incomplete public JWK");
        }
        if (current_.kty != "RSA" || current_.use != "sig" || current_.alg != "RS256") {
            return fail(ParseErrorKind::issuer_untrusted, "unsupported issuer JWK role");
        }
        return true;
    }

    bool fail(ParseErrorKind kind, std::string message) {
        if (!failed_) {
            error_ = ParseError{kind, std::move(message)};
            failed_ = true;
        }
        return false;
    }

    Limits limits_;
    std::vector<Context> stack_;
    std::vector<ParsedKey> parsed_keys_;
    ParsedKey current_;
    ParseError error_{ParseErrorKind::issuer_untrusted, "strict JWKS parse failed"};
    std::size_t key_count_ = 0U;
    std::size_t member_count_ = 0U;
    bool have_keys_ = false;
    bool failed_ = false;
};

tl::expected<crypto::RsaPublicKey, ParseError> decode_key(const ParsedKey& key) {
    const auto modulus = base64url::decode(key.n, 1024U);
    const auto exponent = base64url::decode(key.e, 8U);
    if (!modulus || !exponent || modulus->empty() || modulus->front() == 0U ||
        (modulus->size() < 256U || (modulus->size() == 256U && (modulus->front() & 0x80U) == 0U)) ||
        *exponent != std::vector<std::uint8_t>({0x01U, 0x00U, 0x01U})) {
        return tl::make_unexpected(untrusted("invalid RS256 public JWK"));
    }
    return crypto::RsaPublicKey{*modulus, 65537U};
}

}  // namespace

tl::expected<crypto::RsaPublicKey, ParseError> StaticJwks::resolve_rs256(
    std::string_view kid) const {
    const auto iterator = keys_.find(std::string(kid));
    if (kid.empty() || iterator == keys_.end()) {
        return tl::make_unexpected(untrusted("issuer key ID is unavailable"));
    }
    return iterator->second;
}

JwksResult parse(std::string_view input, Limits limits) {
    if (limits.max_bytes == 0U || limits.max_keys == 0U || limits.max_members == 0U ||
        limits.max_kid_bytes == 0U || input.size() > limits.max_bytes) {
        return tl::make_unexpected(ParseError{ParseErrorKind::resource_limit,
                                               "invalid or exceeded JWKS limit"});
    }
    JwksSax handler(limits);
    const bool parsed = Json::sax_parse(input.begin(), input.end(), &handler,
                                        Json::input_format_t::json, true, false);
    if (!parsed || handler.has_error()) {
        return tl::make_unexpected(handler.error());
    }
    StaticJwks result;
    for (const auto& parsed_key : handler.take_keys()) {
        const auto key = decode_key(parsed_key);
        if (!key || !result.keys_.emplace(parsed_key.kid, *key).second) {
            return tl::make_unexpected(!key ? key.error() : untrusted("duplicate issuer key ID"));
        }
    }
    return result;
}

JwksResult load_static_file(std::string_view path, const FilePolicy& policy) {
    if (path.size() < 2U || path.front() != '/' || path.find('\0') != std::string_view::npos) {
        return tl::make_unexpected(untrusted("static JWKS path is not absolute"));
    }
    const std::string owned_path(path);
    FileDescriptor descriptor(
        ::open(owned_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (descriptor.get() < 0) {
        return tl::make_unexpected(untrusted("static JWKS file cannot be opened safely"));
    }
    struct stat metadata {};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (metadata.st_uid != static_cast<uid_t>(policy.required_owner) &&
         !(policy.allow_root_owner && metadata.st_uid == static_cast<uid_t>(0))) ||
        metadata.st_size < 0) {
        return tl::make_unexpected(untrusted("unsafe static JWKS file metadata"));
    }
    const auto size = static_cast<std::uintmax_t>(metadata.st_size);
    if (size > static_cast<std::uintmax_t>(policy.limits.max_bytes) ||
        size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::resource_limit, "static JWKS file exceeds bound"});
    }
    std::string snapshot(static_cast<std::size_t>(size), '\0');
    std::size_t offset = 0U;
    while (offset < snapshot.size()) {
        const auto count = ::read(descriptor.get(), snapshot.data() + offset, snapshot.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return tl::make_unexpected(untrusted("static JWKS snapshot read failed"));
        }
        offset += static_cast<std::size_t>(count);
    }
    struct stat after {};
    if (::fstat(descriptor.get(), &after) != 0 || after.st_dev != metadata.st_dev ||
        after.st_ino != metadata.st_ino || after.st_size != metadata.st_size) {
        return tl::make_unexpected(untrusted("static JWKS changed during snapshot"));
    }
    return parse(snapshot, policy.limits);
}

JwksResult load(const KeySource& source, const FilePolicy& policy) {
    if (source.profile != KeySourceProfile::static_jwks_file) {
        return tl::make_unexpected(
            ParseError{ParseErrorKind::unsupported_profile,
                       "OIDC discovery is unsupported by the offline C++ verifier"});
    }
    return load_static_file(source.path, policy);
}

}  // namespace credbind::jwks
