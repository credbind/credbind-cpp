// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

namespace credbind::config {
namespace {

using Json = nlohmann::json;

constexpr std::size_t kMaximumConfigurationBytes = 1048576U;
constexpr std::size_t kMaximumDepth = 32U;
constexpr std::size_t kMaximumMembers = 4096U;
constexpr std::size_t kMaximumValues = 8192U;
constexpr std::size_t kMaximumKeyBytes = 256U;
constexpr std::size_t kMaximumPolicies = 64U;
constexpr std::size_t kMaximumAccountRules = 256U;
constexpr std::uint64_t kNanosecondsPerSecond = 1000000000ULL;

ParseError error(ParseErrorKind kind, std::string message) {
    return ParseError{kind, std::move(message)};
}

enum class ContextKind { object, array };

struct Context {
    ContextKind kind;
    bool root;
    std::unordered_set<std::string> members;
    std::string pending;
    bool has_pending;
    Json value;
};

class ConfigSax final : public nlohmann::json_sax<Json> {
  public:
    bool null() override { return scalar(nullptr); }
    bool boolean(bool value) override { return scalar(value); }
    bool number_integer(number_integer_t value) override { return scalar(value); }
    bool number_unsigned(number_unsigned_t value) override { return scalar(value); }
    bool number_float(number_float_t value, const string_t&) override { return scalar(value); }
    bool string(string_t& value) override { return scalar(std::move(value)); }
    bool binary(binary_t&) override { return fail(ParseErrorKind::malformed_input, "binary configuration JSON"); }

    bool start_object(std::size_t) override {
        if (!count_value()) return false;
        if (stack_.empty()) {
            stack_.push_back(Context{ContextKind::object, true, {}, {}, false, Json::object()});
            return true;
        }
        if (!parent_ready()) return false;
        if (stack_.size() + 1U > kMaximumDepth) {
            return fail(ParseErrorKind::resource_limit, "configuration JSON depth bound");
        }
        stack_.push_back(Context{ContextKind::object, false, {}, {}, false, Json::object()});
        return true;
    }

    bool key(string_t& value) override {
        if (stack_.empty() || stack_.back().kind != ContextKind::object) {
            return fail(ParseErrorKind::malformed_input, "configuration member outside object");
        }
        ++members_;
        if (members_ > kMaximumMembers || value.size() > kMaximumKeyBytes) {
            return fail(ParseErrorKind::resource_limit, "configuration member bound");
        }
        auto& context = stack_.back();
        if (!context.members.insert(value).second) {
            return fail(ParseErrorKind::malformed_input, "duplicate configuration member");
        }
        context.pending = std::move(value);
        context.has_pending = true;
        return true;
    }

    bool end_object() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::object ||
            stack_.back().has_pending) {
            return fail(ParseErrorKind::malformed_input, "unexpected configuration object end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        if (context.root) {
            root_ = std::move(context.value);
            complete_ = true;
            return true;
        }
        return attach(std::move(context.value));
    }

    bool start_array(std::size_t) override {
        if (stack_.empty() || !count_value() || !parent_ready()) return false;
        if (stack_.size() + 1U > kMaximumDepth) {
            return fail(ParseErrorKind::resource_limit, "configuration JSON depth bound");
        }
        stack_.push_back(Context{ContextKind::array, false, {}, {}, false, Json::array()});
        return true;
    }

    bool end_array() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::array) {
            return fail(ParseErrorKind::malformed_input, "unexpected configuration array end");
        }
        auto context = std::move(stack_.back());
        stack_.pop_back();
        return attach(std::move(context.value));
    }

    bool parse_error(std::size_t, const std::string&,
                     const nlohmann::detail::exception&) override {
        return fail(ParseErrorKind::malformed_input, "invalid strict configuration JSON");
    }

    [[nodiscard]] bool failed() const { return failed_; }
    [[nodiscard]] bool complete() const { return complete_ && stack_.empty(); }
    [[nodiscard]] const ParseError& failure() const { return failure_; }
    [[nodiscard]] Json take() { return std::move(root_); }

  private:
    template <typename Value>
    bool scalar(Value value) {
        if (!count_value() || stack_.empty()) return false;
        return attach(Json(std::move(value)));
    }

    bool attach(Json value) {
        auto& context = stack_.back();
        if (context.kind == ContextKind::array) {
            context.value.push_back(std::move(value));
            return true;
        }
        if (!context.has_pending) {
            return fail(ParseErrorKind::malformed_input, "configuration value has no member");
        }
        context.value[std::move(context.pending)] = std::move(value);
        context.pending.clear();
        context.has_pending = false;
        return true;
    }

    bool parent_ready() {
        if (stack_.back().kind == ContextKind::object && !stack_.back().has_pending) {
            return fail(ParseErrorKind::malformed_input, "configuration container has no member");
        }
        return true;
    }

    bool count_value() {
        ++values_;
        return values_ <= kMaximumValues
                   ? true
                   : fail(ParseErrorKind::resource_limit, "configuration value bound");
    }

    bool fail(ParseErrorKind kind, std::string message) {
        if (!failed_) {
            failure_ = error(kind, std::move(message));
            failed_ = true;
        }
        return false;
    }

    std::vector<Context> stack_;
    Json root_;
    ParseError failure_{ParseErrorKind::malformed_input, "configuration parse failed"};
    std::size_t members_ = 0U;
    std::size_t values_ = 0U;
    bool complete_ = false;
    bool failed_ = false;
};

tl::expected<Json, ParseError> parse_json(std::string_view input) {
    if (input.size() > kMaximumConfigurationBytes) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "configuration exceeds byte bound"));
    }
    ConfigSax handler;
    const bool parsed = Json::sax_parse(input.begin(), input.end(), &handler,
                                        Json::input_format_t::json, true, false);
    if (!parsed || handler.failed() || !handler.complete()) {
        return tl::make_unexpected(handler.failure());
    }
    return handler.take();
}

bool exact_members(const Json& object, std::initializer_list<std::string_view> required,
                   std::initializer_list<std::string_view> optional = {}) {
    if (!object.is_object()) return false;
    std::unordered_set<std::string> allowed;
    for (const auto name : required) allowed.emplace(name);
    for (const auto name : optional) allowed.emplace(name);
    if (std::any_of(required.begin(), required.end(), [&object](std::string_view name) {
            return object.find(std::string(name)) == object.end();
        })) {
        return false;
    }
    for (const auto& item : object.items()) {
        if (allowed.find(item.key()) == allowed.end()) return false;
    }
    return true;
}

const std::string* string_value(const Json& object, std::string_view name) {
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || !iterator->is_string()) return nullptr;
    return &iterator->get_ref<const std::string&>();
}

bool utf8_without_controls(std::string_view value, std::size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::uint32_t codepoint = 0U;
        std::size_t length = 0U;
        if (first <= 0x7fU) { codepoint = first; length = 1U; }
        else if (first >= 0xc2U && first <= 0xdfU) { codepoint = first & 0x1fU; length = 2U; }
        else if (first >= 0xe0U && first <= 0xefU) { codepoint = first & 0x0fU; length = 3U; }
        else if (first >= 0xf0U && first <= 0xf4U) { codepoint = first & 0x07U; length = 4U; }
        else return false;
        if (length > value.size() - offset) return false;
        for (std::size_t index = 1U; index < length; ++index) {
            const auto next = static_cast<unsigned char>(value[offset + index]);
            if ((next & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((length == 3U && codepoint < 0x800U) ||
            (length == 4U && codepoint < 0x10000U) || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint <= 0x1fU ||
            (codepoint >= 0x7fU && codepoint <= 0x9fU)) return false;
        offset += length;
    }
    return true;
}

tl::expected<std::uint64_t, ParseError> duration_nanoseconds(std::string_view value) {
    if (value.size() < 2U) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid duration"));
    }
    std::uint64_t total = 0U;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        if (value[offset] < '0' || value[offset] > '9') {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "invalid duration number"));
        }
        std::uint64_t number = 0U;
        while (offset < value.size() && value[offset] >= '0' && value[offset] <= '9') {
            const auto digit = static_cast<std::uint64_t>(value[offset] - '0');
            if (number > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
                return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                                 "duration overflow"));
            }
            number = number * 10U + digit;
            ++offset;
        }
        std::uint64_t unit = 0U;
        if (value.substr(offset, 2U) == "ns") { unit = 1U; offset += 2U; }
        else if (value.substr(offset, 2U) == "us") { unit = 1000U; offset += 2U; }
        else if (value.substr(offset, 2U) == "ms") { unit = 1000000U; offset += 2U; }
        else if (offset < value.size() && value[offset] == 's') { unit = kNanosecondsPerSecond; ++offset; }
        else if (offset < value.size() && value[offset] == 'm') { unit = 60U * kNanosecondsPerSecond; ++offset; }
        else if (offset < value.size() && value[offset] == 'h') { unit = 3600U * kNanosecondsPerSecond; ++offset; }
        else return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                              "invalid duration unit"));
        if (number > std::numeric_limits<std::uint64_t>::max() / unit ||
            total > std::numeric_limits<std::uint64_t>::max() - number * unit) {
            return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                             "duration overflow"));
        }
        total += number * unit;
    }
    return total;
}

tl::expected<std::int64_t, ParseError> whole_seconds(const Json& object,
                                                     std::string_view name,
                                                     bool positive) {
    const auto value = string_value(object, name);
    if (value == nullptr || value->size() < 2U) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "duration has wrong type"));
    }
    std::uint64_t seconds = 0U;
    std::uint64_t nanoseconds = 0U;
    std::size_t offset = 0U;
    while (offset < value->size()) {
        if ((*value)[offset] < '0' || (*value)[offset] > '9') {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "invalid whole-second duration"));
        }
        std::uint64_t number = 0U;
        while (offset < value->size() && (*value)[offset] >= '0' && (*value)[offset] <= '9') {
            const auto digit = static_cast<std::uint64_t>((*value)[offset] - '0');
            if (number > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
                return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                                 "duration overflow"));
            }
            number = number * 10U + digit;
            ++offset;
        }
        std::uint64_t unit_nanoseconds = 0U;
        std::uint64_t unit_seconds = 0U;
        if (value->substr(offset, 2U) == "ns") { unit_nanoseconds = 1U; offset += 2U; }
        else if (value->substr(offset, 2U) == "us") { unit_nanoseconds = 1000U; offset += 2U; }
        else if (value->substr(offset, 2U) == "ms") { unit_nanoseconds = 1000000U; offset += 2U; }
        else if (offset < value->size() && (*value)[offset] == 's') { unit_seconds = 1U; ++offset; }
        else if (offset < value->size() && (*value)[offset] == 'm') { unit_seconds = 60U; ++offset; }
        else if (offset < value->size() && (*value)[offset] == 'h') { unit_seconds = 3600U; ++offset; }
        else return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                              "invalid duration unit"));
        std::uint64_t added_seconds = 0U;
        std::uint64_t added_nanoseconds = 0U;
        if (unit_seconds != 0U) {
            if (number > std::numeric_limits<std::uint64_t>::max() / unit_seconds) {
                return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                                 "duration overflow"));
            }
            added_seconds = number * unit_seconds;
        } else {
            const auto units_per_second = kNanosecondsPerSecond / unit_nanoseconds;
            added_seconds = number / units_per_second;
            added_nanoseconds = (number % units_per_second) * unit_nanoseconds;
        }
        if (seconds > std::numeric_limits<std::uint64_t>::max() - added_seconds) {
            return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                             "duration overflow"));
        }
        seconds += added_seconds;
        nanoseconds += added_nanoseconds;
        if (nanoseconds >= kNanosecondsPerSecond) {
            if (seconds == std::numeric_limits<std::uint64_t>::max()) {
                return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                                 "duration overflow"));
            }
            ++seconds;
            nanoseconds -= kNanosecondsPerSecond;
        }
    }
    if (nanoseconds != 0U || (positive && seconds == 0U) ||
        seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "duration is not an admitted whole-second value"));
    }
    return static_cast<std::int64_t>(seconds);
}

tl::expected<std::unordered_set<std::string>, ParseError> string_set(
    const Json& object, std::string_view name, bool nonempty) {
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || !iterator->is_array() ||
        (nonempty && iterator->empty())) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "configuration string set has wrong type"));
    }
    std::unordered_set<std::string> result;
    for (const auto& value : *iterator) {
        if (!value.is_string() || value.get_ref<const std::string&>().empty() ||
            !result.insert(value.get_ref<const std::string&>()).second) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "configuration string set is invalid"));
        }
    }
    return result;
}

bool subset(const std::unordered_set<std::string>& values,
            std::initializer_list<std::string_view> allowed) {
    return std::all_of(values.begin(), values.end(), [allowed](const std::string& value) {
        return std::find(allowed.begin(), allowed.end(), value) != allowed.end();
    });
}

tl::expected<issuer::Predicate, ParseError> predicate(const Json& value) {
    const auto claim = string_value(value, "claim");
    const auto type = string_value(value, "type");
    const auto operation = string_value(value, "op");
    if (claim == nullptr || claim->empty() || type == nullptr || operation == nullptr) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid claim predicate"));
    }
    if (*type == "string" && *operation == "equals" &&
        exact_members(value, {"claim", "type", "op", "value"})) {
        const auto expected = string_value(value, "value");
        if (expected != nullptr) {
            return issuer::Predicate{*claim, issuer::PredicateOperation::string_equals,
                                     *expected, {}};
        }
    }
    if (*type == "string" && *operation == "one-of" &&
        exact_members(value, {"claim", "type", "op", "values"})) {
        const auto values = string_set(value, "values", true);
        if (values) {
            return issuer::Predicate{*claim, issuer::PredicateOperation::string_one_of,
                                     "", std::vector<std::string>(values->begin(), values->end())};
        }
    }
    if (*type == "string-array" && *operation == "contains" &&
        exact_members(value, {"claim", "type", "op", "value"})) {
        const auto expected = string_value(value, "value");
        if (expected != nullptr) {
            return issuer::Predicate{*claim, issuer::PredicateOperation::string_array_contains,
                                     *expected, {}};
        }
    }
    return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                     "unsupported claim predicate"));
}

tl::expected<std::vector<issuer::Predicate>, ParseError> predicates(
    const Json& object, std::string_view name, bool required) {
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end()) {
        if (!required) return std::vector<issuer::Predicate>{};
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "missing predicate array"));
    }
    if (!iterator->is_array()) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "predicate list has wrong type"));
    }
    std::vector<issuer::Predicate> result;
    result.reserve(iterator->size());
    for (const auto& item : *iterator) {
        const auto parsed = predicate(item);
        if (!parsed) return tl::make_unexpected(parsed.error());
        result.push_back(*parsed);
    }
    return result;
}

tl::expected<std::size_t, ParseError> size_member(const Json& object,
                                                  std::string_view name,
                                                  std::size_t maximum) {
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || !iterator->is_number_unsigned()) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "resource limit has wrong type"));
    }
    const auto value = iterator->get<std::uint64_t>();
    if (value == 0U || value > static_cast<std::uint64_t>(maximum)) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "resource limit exceeds protocol bound"));
    }
    return static_cast<std::size_t>(value);
}

tl::expected<ResourceLimits, ParseError> resource_limits(const Json& value) {
    if (!exact_members(value, {"max_token_bytes", "max_evidence_bytes",
                               "max_ssh_certificate_bytes", "max_offered_key_chars",
                               "max_authorized_keys_output_chars"})) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid resource-limits object"));
    }
    const auto token = size_member(value, "max_token_bytes", 32768U);
    const auto evidence = size_member(value, "max_evidence_bytes", 16384U);
    const auto certificate = size_member(value, "max_ssh_certificate_bytes", 49152U);
    const auto offered = size_member(value, "max_offered_key_chars", 65536U);
    const auto output = size_member(value, "max_authorized_keys_output_chars", 4096U);
    if (!token || !evidence || !certificate || !offered || !output) {
        if (!token) return tl::make_unexpected(token.error());
        if (!evidence) return tl::make_unexpected(evidence.error());
        if (!certificate) return tl::make_unexpected(certificate.error());
        if (!offered) return tl::make_unexpected(offered.error());
        return tl::make_unexpected(output.error());
    }
    return ResourceLimits{*token, *evidence, *certificate, *offered, *output};
}

bool valid_policy_id(std::string_view value) {
    if (value.empty() || value.size() > 64U) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        const char character = value[index];
        const bool alphanumeric = (character >= 'A' && character <= 'Z') ||
                                  (character >= 'a' && character <= 'z') ||
                                  (character >= '0' && character <= '9');
        if (!alphanumeric && (index == 0U || (character != '.' && character != '_' && character != '-'))) {
            return false;
        }
    }
    return true;
}

bool valid_https_uri(std::string_view value) {
    constexpr std::string_view prefix = "https://";
    if (value.size() <= prefix.size() || value.substr(0U, prefix.size()) != prefix) {
        return false;
    }
    const auto authority_end = value.find_first_of("/?#", prefix.size());
    const auto authority = value.substr(
        prefix.size(), authority_end == std::string_view::npos
                           ? value.size() - prefix.size()
                           : authority_end - prefix.size());
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        value.find('#') != std::string_view::npos) {
        return false;
    }
    for (const char raw_character : value) {
        const auto character = static_cast<unsigned char>(raw_character);
        if (character <= 0x20U || character >= 0x7fU || character == '\\') return false;
    }
    auto hexadecimal = [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'A' && character <= 'F') ||
               (character >= 'a' && character <= 'f');
    };
    auto escaped_component = [hexadecimal](std::string_view component,
                                           bool query) {
        constexpr std::string_view unreserved =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        constexpr std::string_view subdelimiters = "!$&'()*+,;=";
        for (std::size_t index = 0U; index < component.size(); ++index) {
            const char character = component[index];
            if (character == '%') {
                if (index + 2U >= component.size() || !hexadecimal(component[index + 1U]) ||
                    !hexadecimal(component[index + 2U])) return false;
                index += 2U;
            } else if (unreserved.find(character) == std::string_view::npos &&
                       subdelimiters.find(character) == std::string_view::npos &&
                       character != ':' && character != '@' && character != '/' &&
                       !(query && character == '?')) {
                return false;
            }
        }
        return true;
    };
    std::string_view host;
    std::string_view port;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos || close == 1U) return false;
        const std::string address(authority.substr(1U, close - 1U));
        std::array<unsigned char, 16> bytes{};
        if (::inet_pton(AF_INET6, address.c_str(), bytes.data()) != 1) return false;
        host = authority.substr(0U, close + 1U);
        if (close + 1U < authority.size()) {
            if (authority[close + 1U] != ':') return false;
            port = authority.substr(close + 2U);
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':') != colon) return false;
            host = authority.substr(0U, colon);
            port = authority.substr(colon + 1U);
        } else {
            host = authority;
        }
        if (host.empty() || !escaped_component(host, false) ||
            host.find('/') != std::string_view::npos || host.find(':') != std::string_view::npos ||
            host.find('@') != std::string_view::npos) return false;
    }
    if (host.empty()) return false;
    if (authority.back() == ':' || !port.empty()) {
        if (port.empty() || port.size() > 5U) return false;
        std::uint32_t numeric = 0U;
        for (const char character : port) {
            if (character < '0' || character > '9') return false;
            numeric = numeric * 10U + static_cast<std::uint32_t>(character - '0');
        }
        if (numeric == 0U || numeric > 65535U) return false;
    }
    if (authority_end != std::string_view::npos) {
        const auto suffix = value.substr(authority_end);
        const auto question = suffix.find('?');
        const auto path = suffix.substr(0U, question);
        const auto query = question == std::string_view::npos
                               ? std::string_view{}
                               : suffix.substr(question + 1U);
        if (!escaped_component(path, false) || !escaped_component(query, true)) return false;
    }
    return true;
}

bool compatible_acquisition_binding(
    const std::unordered_set<std::string>& acquisitions,
    const std::unordered_set<std::string>& bindings) {
    const bool interactive = acquisitions.find("oidc-native-auth-code-v1") != acquisitions.end() ||
        acquisitions.find("oidc-confidential-web-auth-code-v1") != acquisitions.end();
    const bool workload = acquisitions.find("challenge-bound-workload-v1") != acquisitions.end();
    const bool nonce = bindings.find("oidc-nonce-v1") != bindings.end();
    const bool workload_binding = bindings.find("audience-v1") != bindings.end() ||
        bindings.find("credbind-claim-v1") != bindings.end();
    return interactive == nonce && workload == workload_binding;
}

tl::expected<std::string, ParseError> read_file(std::string_view path,
                                                std::uint32_t required_owner) {
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string_view::npos) {
        return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                         "configuration path is not absolute"));
    }
    const std::string copy(path);
    const int descriptor = ::open(copy.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                         "configuration file cannot be opened"));
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_uid != required_owner && status.st_uid != 0U) ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0 || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) > kMaximumConfigurationBytes) {
        ::close(descriptor);
        return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                         "configuration file is unsafe"));
    }
    std::string contents(static_cast<std::size_t>(status.st_size), '\0');
    std::size_t offset = 0U;
    while (offset < contents.size()) {
        const auto read_count = ::read(descriptor, contents.data() + offset,
                                       contents.size() - offset);
        if (read_count < 0 && errno == EINTR) continue;
        if (read_count <= 0) {
            ::close(descriptor);
            return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                             "configuration file read failed"));
        }
        offset += static_cast<std::size_t>(read_count);
    }
    if (::close(descriptor) != 0) {
        return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                         "configuration file close failed"));
    }
    return contents;
}

}  // namespace

Result parse_and_validate(std::string_view input, std::uint32_t required_owner) {
    const auto root = parse_json(input);
    if (!root) return tl::make_unexpected(root.error());
    if (!exact_members(*root, {"version", "clock_skew", "total_verification_deadline",
                               "resource_limits", "trusted_issuers", "accounts", "logging"},
                              {"issuer_key_cache"})) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid top-level configuration schema"));
    }
    const auto version = root->find("version");
    if (version == root->end() || !version->is_number_unsigned() ||
        version->get<std::uint64_t>() != 1U) {
        return tl::make_unexpected(error(ParseErrorKind::unsupported_version,
                                         "unsupported configuration version"));
    }
    const auto skew = whole_seconds(*root, "clock_skew", false);
    const auto deadline_text = string_value(*root, "total_verification_deadline");
    const auto deadline = deadline_text == nullptr
                              ? tl::expected<std::uint64_t, ParseError>(
                                    tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                                              "deadline has wrong type")))
                              : duration_nanoseconds(*deadline_text);
    const auto resources = resource_limits(root->at("resource_limits"));
    if (!skew || !deadline || !resources) {
        if (!skew) return tl::make_unexpected(skew.error());
        if (!deadline) return tl::make_unexpected(deadline.error());
        return tl::make_unexpected(resources.error());
    }
    if (*deadline == 0U || *deadline > 10U * kNanosecondsPerSecond) {
        return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                         "total verification deadline exceeds protocol bound"));
    }
    if (root->find("issuer_key_cache") != root->end()) {
        const auto& cache = root->at("issuer_key_cache");
        if (!exact_members(cache, {"directory", "maximum_freshness"})) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "invalid issuer key cache"));
        }
        const auto directory = string_value(cache, "directory");
        const auto freshness_text = string_value(cache, "maximum_freshness");
        const auto freshness = freshness_text == nullptr
                                   ? tl::expected<std::uint64_t, ParseError>(
                                         tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                                                   "cache freshness has wrong type")))
                                   : duration_nanoseconds(*freshness_text);
        if (directory == nullptr || directory->size() < 2U || directory->front() != '/' ||
            !freshness) {
            return tl::make_unexpected(!freshness ? freshness.error()
                                                   : error(ParseErrorKind::malformed_input,
                                                           "invalid cache directory"));
        }
        if (*freshness != 0U && (*freshness < 60U * kNanosecondsPerSecond ||
                                 *freshness > 720U * 3600U * kNanosecondsPerSecond)) {
            return tl::make_unexpected(error(ParseErrorKind::resource_limit,
                                             "cache freshness is outside bounds"));
        }
    }
    const auto trusted = root->find("trusted_issuers");
    const auto accounts_value = root->find("accounts");
    const auto logging = root->find("logging");
    if (trusted == root->end() || !trusted->is_array() || trusted->size() > kMaximumPolicies ||
        accounts_value == root->end() || !accounts_value->is_object() ||
        logging == root->end() ||
        !exact_members(*logging, {}, {"facility"})) {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "invalid trust, account, or logging structure"));
    }
    audit::Facility facility = audit::Facility::authpriv;
    if (logging->find("facility") != logging->end()) {
        const auto selected = string_value(*logging, "facility");
        if (selected == nullptr) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "logging facility has wrong type"));
        }
        const auto parsed = audit::parse_facility(*selected);
        if (!parsed) return tl::make_unexpected(parsed.error());
        facility = *parsed;
    }

    Configuration result{*skew, *deadline, *resources, {}, {}, facility};
    std::unordered_set<std::string> policy_ids;
    std::unordered_set<std::string> issuer_ids;
    for (const auto& value : *trusted) {
        if (!exact_members(value,
                           {"policy_id", "issuer", "key_source", "audiences",
                            "issuer_algorithms", "caller_algorithms", "evidence_profiles",
                            "binding_profiles", "acquisition_profiles",
                            "require_non_reconstructible_evidence",
                            "certificate_principal_claim"},
                           {"authorized_parties", "maximum_credential_age",
                            "maximum_identity_lifetime", "audit_identity_claim",
                            "required_claims", "environment_discriminator"})) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "invalid issuer policy schema"));
        }
        const auto policy_id = string_value(value, "policy_id");
        const auto issuer_name = string_value(value, "issuer");
        const auto principal_claim = string_value(value, "certificate_principal_claim");
        if (policy_id == nullptr || !valid_policy_id(*policy_id) ||
            !policy_ids.insert(*policy_id).second || issuer_name == nullptr ||
            !valid_https_uri(*issuer_name) || principal_claim == nullptr ||
            principal_claim->empty()) {
            return tl::make_unexpected(error(ParseErrorKind::issuer_untrusted,
                                             "invalid or duplicate issuer policy identity"));
        }
        const auto audiences = string_set(value, "audiences", true);
        const auto issuer_algorithms = string_set(value, "issuer_algorithms", true);
        const auto caller_algorithms = string_set(value, "caller_algorithms", true);
        const auto evidence_profiles = string_set(value, "evidence_profiles", true);
        const auto binding_profiles = string_set(value, "binding_profiles", true);
        const auto acquisition_profiles = string_set(value, "acquisition_profiles", true);
        if (!audiences || !issuer_algorithms || !caller_algorithms || !evidence_profiles ||
            !binding_profiles || !acquisition_profiles) {
            if (!audiences) return tl::make_unexpected(audiences.error());
            if (!issuer_algorithms) return tl::make_unexpected(issuer_algorithms.error());
            if (!caller_algorithms) return tl::make_unexpected(caller_algorithms.error());
            if (!evidence_profiles) return tl::make_unexpected(evidence_profiles.error());
            if (!binding_profiles) return tl::make_unexpected(binding_profiles.error());
            return tl::make_unexpected(acquisition_profiles.error());
        }
        if (*issuer_algorithms != std::unordered_set<std::string>{"RS256"} ||
            caller_algorithms->find("ES256") == caller_algorithms->end() ||
            !subset(*caller_algorithms, {"ES256", "Ed25519"}) ||
            !subset(*evidence_profiles, {issuer::kStandardEvidence, issuer::kGqEvidence}) ||
            !subset(*binding_profiles, {issuer::kOidcNonceBinding, issuer::kAudienceBinding,
                                        issuer::kCredBindClaimBinding}) ||
            !subset(*acquisition_profiles,
                    {"oidc-native-auth-code-v1", "oidc-confidential-web-auth-code-v1",
                     "challenge-bound-workload-v1"}) ||
            !compatible_acquisition_binding(*acquisition_profiles, *binding_profiles)) {
            return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                             "issuer policy contains unsupported capability"));
        }
        issuer_ids.insert(*issuer_name);
        std::unordered_set<std::string> authorized_parties;
        if (value.find("authorized_parties") != value.end()) {
            const auto parsed = string_set(value, "authorized_parties", true);
            if (!parsed) return tl::make_unexpected(parsed.error());
            authorized_parties = *parsed;
        }
        auto required_claims = predicates(value, "required_claims", false);
        if (!required_claims) return tl::make_unexpected(required_claims.error());
        if (value.find("environment_discriminator") != value.end()) {
            const auto discriminator = predicate(value.at("environment_discriminator"));
            if (!discriminator) return tl::make_unexpected(discriminator.error());
            required_claims->push_back(*discriminator);
        }
        std::int64_t maximum_age = 0;
        if (value.find("maximum_credential_age") != value.end()) {
            const auto parsed = whole_seconds(value, "maximum_credential_age", true);
            if (!parsed) return tl::make_unexpected(parsed.error());
            maximum_age = *parsed;
        }
        std::int64_t maximum_identity = 0;
        if (value.find("maximum_identity_lifetime") != value.end()) {
            const auto parsed = whole_seconds(value, "maximum_identity_lifetime", true);
            if (!parsed) return tl::make_unexpected(parsed.error());
            maximum_identity = *parsed;
        }
        const auto reconstructible = value.find("require_non_reconstructible_evidence");
        if (reconstructible == value.end() || !reconstructible->is_boolean()) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "reconstructibility policy has wrong type"));
        }
        std::string audit_claim;
        if (value.find("audit_identity_claim") != value.end()) {
            const auto selected = string_value(value, "audit_identity_claim");
            if (selected == nullptr || !utf8_without_controls(*selected, 256U)) {
                return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                                 "invalid audit identity claim"));
            }
            audit_claim = *selected;
        }
        const auto source = value.find("key_source");
        if (source == value.end() || !source->is_object()) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "key source has wrong type"));
        }
        const auto source_type = string_value(*source, "type");
        if (source_type == nullptr) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "key source type is absent"));
        }
        if (*source_type == "oidc-discovery") {
            if (!exact_members(*source, {"type"})) {
                return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                                 "invalid discovery key source"));
            }
            return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                             "C++ verifier does not support discovery"));
        }
        if (*source_type != "static-jwks-file" ||
            !exact_members(*source, {"type", "path"})) {
            return tl::make_unexpected(error(ParseErrorKind::unsupported_profile,
                                             "unsupported issuer key source"));
        }
        const auto source_path = string_value(*source, "path");
        if (source_path == nullptr || source_path->size() < 2U || source_path->front() != '/') {
            return tl::make_unexpected(error(ParseErrorKind::issuer_untrusted,
                                             "static JWKS path is not absolute"));
        }
        const auto keys = jwks::load_static_file(
            *source_path, jwks::FilePolicy{required_owner});
        if (!keys) return tl::make_unexpected(keys.error());
        std::unordered_set<std::string> admitted{*principal_claim};
        if (!audit_claim.empty()) admitted.insert(audit_claim);
        for (const auto& required : *required_claims) admitted.insert(required.claim);
        issuer::Policy issuer_policy{*issuer_name, *audiences, authorized_parties,
                                     *issuer_algorithms, *evidence_profiles,
                                     *binding_profiles, reconstructible->get<bool>(),
                                     maximum_age, *skew, *required_claims, admitted};
        std::vector<std::string> acquisitions(acquisition_profiles->begin(),
                                              acquisition_profiles->end());
        std::sort(acquisitions.begin(), acquisitions.end());
        result.trusted_issuers.push_back(IssuerConfiguration{
            *policy_id,
            direct::CorePolicy{*caller_algorithms, std::move(issuer_policy),
                               direct::CoreLimits{resources->max_token_bytes,
                                                  resources->max_evidence_bytes}},
            direct::CarrierPolicy{*principal_claim, maximum_identity, *skew},
            std::move(acquisitions), audit_claim, *keys});
    }

    std::size_t rule_count = 0U;
    for (const auto& account_item : accounts_value->items()) {
        if (!utf8_without_controls(account_item.key(), 256U) ||
            !exact_members(account_item.value(), {"allow"}) ||
            !account_item.value().at("allow").is_array() ||
            account_item.value().at("allow").empty()) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "invalid account policy"));
        }
        for (const auto& rule : account_item.value().at("allow")) {
            ++rule_count;
            if (rule_count > kMaximumAccountRules ||
                !exact_members(rule, {"issuer", "all", "allowed_certificate_extensions"})) {
                return tl::make_unexpected(error(rule_count > kMaximumAccountRules
                                                     ? ParseErrorKind::resource_limit
                                                     : ParseErrorKind::malformed_input,
                                                 "invalid account authorization rule"));
            }
            const auto issuer_name = string_value(rule, "issuer");
            const auto all = predicates(rule, "all", true);
            const auto extensions = string_set(rule, "allowed_certificate_extensions", false);
            if (issuer_name == nullptr || !all || !extensions ||
                issuer_ids.find(*issuer_name) == issuer_ids.end() ||
                !subset(*extensions, {"permit-agent-forwarding", "permit-port-forwarding",
                                      "permit-pty", "permit-user-rc",
                                      "permit-X11-forwarding"})) {
                return tl::make_unexpected(error(ParseErrorKind::issuer_untrusted,
                                                 "account rule references invalid policy data"));
            }
            result.accounts[account_item.key()].push_back(
                direct::AccountRule{*issuer_name, *all, *extensions});
            for (auto& configured_issuer : result.trusted_issuers) {
                if (configured_issuer.core_policy.issuer_policy.issuer == *issuer_name) {
                    for (const auto& item : *all) {
                        configured_issuer.core_policy.issuer_policy.admitted_claims.insert(item.claim);
                    }
                }
            }
        }
    }
    return result;
}

Result load_and_validate(std::string_view path, std::uint32_t required_owner) {
    const auto contents = read_file(path, required_owner);
    if (!contents) return tl::make_unexpected(contents.error());
    return parse_and_validate(*contents, required_owner);
}

tl::expected<void, ParseError> validate_render_path(std::string_view path,
                                                    bool require_regular_file) {
    if (path.empty() || path.front() != '/') {
        return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                         "render path is not absolute"));
    }
    for (const char character : path) {
        const bool admitted = (character >= 'A' && character <= 'Z') ||
                              (character >= 'a' && character <= 'z') ||
                              (character >= '0' && character <= '9') ||
                              character == '/' || character == '.' || character == '_' ||
                              character == '-';
        if (!admitted) {
            return tl::make_unexpected(error(ParseErrorKind::malformed_input,
                                             "render path contains a token separator"));
        }
    }
    if (require_regular_file) {
        const std::string copy(path);
        struct stat status {};
        if (::lstat(copy.c_str(), &status) != 0 || S_ISLNK(status.st_mode) ||
            !S_ISREG(status.st_mode)) {
            return tl::make_unexpected(error(ParseErrorKind::state_invalid,
                                             "render path is not a regular file"));
        }
    }
    return {};
}

bool valid_command_user(std::string_view user) noexcept {
    if (user.empty() || user.size() > 256U) return false;
    for (std::size_t index = 0U; index < user.size(); ++index) {
        const char character = user[index];
        const bool alpha = (character >= 'A' && character <= 'Z') ||
                           (character >= 'a' && character <= 'z') || character == '_';
        const bool rest = alpha || (character >= '0' && character <= '9') ||
                          character == '.' || character == '-';
        if ((index == 0U && !alpha) || (index > 0U && !rest)) return false;
    }
    return true;
}

}  // namespace credbind::config
