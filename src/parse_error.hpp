// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_PARSE_ERROR_HPP
#define CREDBIND_PARSE_ERROR_HPP

#include <string>
#include <utility>

namespace credbind {

enum class ParseErrorKind {
    malformed_input,
    resource_limit,
    unsupported_version,
    unsupported_profile,
    unsupported_algorithm,
    caller_key_invalid,
    issuer_untrusted,
    issuer_signature_invalid,
    evidence_invalid,
    evidence_result_mismatch,
    binding_invalid,
    issuer_claims_invalid,
    credential_not_yet_valid,
    credential_expired,
    caller_signature_invalid,
    ssh_certificate_invalid,
    ssh_key_mismatch,
    ssh_identity_not_yet_valid,
    ssh_identity_expired,
    ssh_principal_invalid,
    account_unauthorized,
    deadline_exceeded,
    operation_cancelled,
    state_invalid,
    internal_error
};

struct ParseError final {
    ParseErrorKind kind;
    std::string message;

    ParseError(ParseErrorKind error_kind, std::string error_message)
        : kind(error_kind), message(std::move(error_message)) {}
};

}  // namespace credbind

#endif
