// SPDX-License-Identifier: Apache-2.0

#include "strict_json.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace credbind::strict_json {
namespace {

using Json = nlohmann::json;

enum class ContextKind { root_object, signatures_array, signature_object };

struct Context {
    ContextKind kind;
    std::unordered_set<std::string> names;
    std::string pending_name;
    std::size_t array_items = 0;
};

class CoreEnvelopeSax final : public nlohmann::json_sax<Json> {
  public:
    explicit CoreEnvelopeSax(Limits limits) : limits_(limits) {}

    bool null() override { return wrong_scalar_type(); }
    bool boolean(bool) override { return wrong_scalar_type(); }
    bool number_integer(number_integer_t) override { return wrong_scalar_type(); }
    bool number_unsigned(number_unsigned_t) override { return wrong_scalar_type(); }
    bool number_float(number_float_t, const string_t&) override { return wrong_scalar_type(); }

    bool string(string_t& value) override {
        if (!count_value()) {
            return false;
        }
        if (stack_.empty()) {
            return fail(ParseErrorKind::malformed_input, "top-level JSON value is not an object");
        }
        auto& context = stack_.back();
        if (context.kind == ContextKind::root_object) {
            if (context.pending_name == "payload") {
                envelope_.payload = std::move(value);
                have_payload_ = true;
            } else if (context.pending_name == "credbind_evidence") {
                envelope_.evidence = std::move(value);
                have_evidence_ = true;
            } else {
                return fail(ParseErrorKind::malformed_input, "wrong core envelope member type");
            }
        } else if (context.kind == ContextKind::signature_object) {
            if (context.pending_name == "protected") {
                envelope_.caller_signature.protected_header = std::move(value);
                have_protected_ = true;
            } else if (context.pending_name == "signature") {
                envelope_.caller_signature.signature = std::move(value);
                have_signature_ = true;
            } else {
                return fail(ParseErrorKind::malformed_input, "wrong caller signature member type");
            }
        } else {
            return fail(ParseErrorKind::malformed_input, "signature entry is not an object");
        }
        context.pending_name.clear();
        return true;
    }

    bool binary(binary_t&) override {
        return fail(ParseErrorKind::malformed_input, "binary JSON value is unsupported");
    }

    bool start_object(std::size_t) override {
        if (!count_container()) {
            return false;
        }
        if (stack_.empty()) {
            stack_.push_back(Context{ContextKind::root_object, {}, {}, 0U});
            return true;
        }
        auto& parent = stack_.back();
        if (parent.kind != ContextKind::signatures_array) {
            return fail(ParseErrorKind::malformed_input, "wrong core envelope object type");
        }
        ++parent.array_items;
        if (parent.array_items > 1U) {
            return fail(ParseErrorKind::malformed_input, "wrong caller signature count");
        }
        stack_.push_back(Context{ContextKind::signature_object, {}, {}, 0U});
        return true;
    }

    bool key(string_t& value) override {
        if (stack_.empty() || stack_.back().kind == ContextKind::signatures_array) {
            return fail(ParseErrorKind::malformed_input, "JSON member outside object");
        }
        ++members_;
        if (members_ > limits_.max_members || value.size() > limits_.max_key_bytes) {
            return fail(ParseErrorKind::resource_limit, "JSON member bound");
        }
        auto& context = stack_.back();
        if (!context.names.insert(value).second) {
            return fail(ParseErrorKind::malformed_input, "duplicate JSON member");
        }
        if (context.kind == ContextKind::root_object) {
            if (value != "payload" && value != "signatures" && value != "credbind_evidence") {
                return fail(ParseErrorKind::malformed_input, "unknown core envelope member");
            }
        } else if (value != "protected" && value != "signature") {
            return fail(ParseErrorKind::malformed_input, "unknown caller signature member");
        }
        context.pending_name = std::move(value);
        return true;
    }

    bool end_object() override {
        if (stack_.empty()) {
            return fail(ParseErrorKind::malformed_input, "unexpected object end");
        }
        const auto context = stack_.back().kind;
        if (context == ContextKind::root_object) {
            if (!have_payload_ || !have_signatures_ || !have_evidence_) {
                return fail(ParseErrorKind::malformed_input, "missing core envelope member");
            }
        } else if (context == ContextKind::signature_object) {
            if (!have_protected_ || !have_signature_) {
                return fail(ParseErrorKind::malformed_input, "missing caller signature member");
            }
        } else {
            return fail(ParseErrorKind::malformed_input, "object ended inside array");
        }
        stack_.pop_back();
        return true;
    }

    bool start_array(std::size_t) override {
        if (!count_container() || stack_.empty()) {
            return false;
        }
        auto& parent = stack_.back();
        if (parent.kind != ContextKind::root_object || parent.pending_name != "signatures") {
            return fail(ParseErrorKind::malformed_input, "wrong core envelope array type");
        }
        have_signatures_ = true;
        parent.pending_name.clear();
        stack_.push_back(Context{ContextKind::signatures_array, {}, {}, 0U});
        return true;
    }

    bool end_array() override {
        if (stack_.empty() || stack_.back().kind != ContextKind::signatures_array) {
            return fail(ParseErrorKind::malformed_input, "unexpected array end");
        }
        if (stack_.back().array_items != 1U) {
            return fail(ParseErrorKind::malformed_input, "wrong caller signature count");
        }
        stack_.pop_back();
        return true;
    }

    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception& error) override {
        return fail(ParseErrorKind::malformed_input, std::string("invalid strict JSON: ") + error.what());
    }

    [[nodiscard]] const CoreEnvelope& envelope() const noexcept { return envelope_; }
    [[nodiscard]] const ParseError& error() const noexcept { return error_; }
    [[nodiscard]] bool has_error() const noexcept { return failed_; }

  private:
    bool count_value() {
        ++values_;
        if (values_ > limits_.max_values) {
            return fail(ParseErrorKind::resource_limit, "JSON value bound");
        }
        return true;
    }

    bool count_container() {
        if (!count_value()) {
            return false;
        }
        if (stack_.size() + 1U > limits_.max_depth) {
            return fail(ParseErrorKind::resource_limit, "JSON depth bound");
        }
        return true;
    }

    bool wrong_scalar_type() {
        if (!count_value()) {
            return false;
        }
        return fail(ParseErrorKind::malformed_input, "wrong core envelope member type");
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
    CoreEnvelope envelope_;
    ParseError error_{ParseErrorKind::malformed_input, "strict JSON parse failed"};
    std::size_t members_ = 0;
    std::size_t values_ = 0;
    bool failed_ = false;
    bool have_payload_ = false;
    bool have_signatures_ = false;
    bool have_evidence_ = false;
    bool have_protected_ = false;
    bool have_signature_ = false;
};

}  // namespace

CoreEnvelopeResult parse_core_envelope(std::string_view input, Limits limits) {
    if (limits.max_bytes == 0U || limits.max_depth == 0U || limits.max_members == 0U ||
        limits.max_values == 0U || limits.max_key_bytes == 0U) {
        return tl::make_unexpected(ParseError{ParseErrorKind::resource_limit,
                                               "invalid strict JSON limits"});
    }
    if (input.size() > limits.max_bytes) {
        return tl::make_unexpected(ParseError{ParseErrorKind::resource_limit,
                                               "JSON input exceeds local bound"});
    }

    CoreEnvelopeSax handler(limits);
    const bool parsed = Json::sax_parse(input.begin(), input.end(), &handler,
                                        Json::input_format_t::json, true, false);
    if (!parsed || handler.has_error()) {
        return tl::make_unexpected(handler.error());
    }
    return handler.envelope();
}

}  // namespace credbind::strict_json
