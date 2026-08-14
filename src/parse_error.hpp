// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_PARSE_ERROR_HPP
#define CREDBIND_PARSE_ERROR_HPP

#include <string>
#include <utility>

namespace credbind {

enum class ParseErrorKind {
    malformed_input,
    resource_limit,
    unsupported_profile,
    unsupported_algorithm,
    issuer_untrusted,
    issuer_signature_invalid,
    evidence_invalid
};

struct ParseError final {
    ParseErrorKind kind;
    std::string message;

    ParseError(ParseErrorKind error_kind, std::string error_message)
        : kind(error_kind), message(std::move(error_message)) {}
};

}  // namespace credbind

#endif
