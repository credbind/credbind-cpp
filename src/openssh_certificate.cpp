// SPDX-License-Identifier: Apache-2.0

#include "openssh_certificate.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace credbind::openssh {
namespace {

constexpr std::string_view kEcdsaCertificate =
    "ecdsa-sha2-nistp256-cert-v01@openssh.com";
constexpr std::string_view kEd25519Certificate = "ssh-ed25519-cert-v01@openssh.com";
constexpr std::string_view kEcdsaKey = "ecdsa-sha2-nistp256";
constexpr std::string_view kEd25519Key = "ssh-ed25519";
constexpr std::string_view kCurve = "nistp256";
constexpr std::string_view kCarrier = "credbind-ssh-v1@credbind.dev";

ParseError malformed(std::string message) {
    return ParseError{ParseErrorKind::malformed_input, std::move(message)};
}

ParseError resource(std::string message) {
    return ParseError{ParseErrorKind::resource_limit, std::move(message)};
}

ParseError unsupported(std::string message) {
    return ParseError{ParseErrorKind::unsupported_algorithm, std::move(message)};
}

class Reader final {
  public:
    explicit Reader(std::string_view input) : input_(input) {}

    [[nodiscard]] std::size_t offset() const { return offset_; }
    [[nodiscard]] bool empty() const { return offset_ == input_.size(); }

    tl::expected<std::uint32_t, ParseError> u32() {
        if (input_.size() - offset_ < 4U) {
            return tl::make_unexpected(malformed("truncated SSH uint32"));
        }
        std::uint32_t value = 0U;
        for (std::size_t index = 0U; index < 4U; ++index) {
            value = static_cast<std::uint32_t>(
                (value << 8U) | static_cast<unsigned char>(input_[offset_ + index]));
        }
        offset_ += 4U;
        return value;
    }

    tl::expected<std::uint64_t, ParseError> u64() {
        if (input_.size() - offset_ < 8U) {
            return tl::make_unexpected(malformed("truncated SSH uint64"));
        }
        std::uint64_t value = 0U;
        for (std::size_t index = 0U; index < 8U; ++index) {
            value = (value << 8U) | static_cast<unsigned char>(input_[offset_ + index]);
        }
        offset_ += 8U;
        return value;
    }

    tl::expected<std::string_view, ParseError> string(std::size_t maximum,
                                                       std::string_view field) {
        const auto length = u32();
        if (!length) {
            return tl::make_unexpected(length.error());
        }
        const auto size = static_cast<std::size_t>(*length);
        if (size > input_.size() - offset_) {
            return tl::make_unexpected(malformed(std::string("truncated ") + std::string(field)));
        }
        if (static_cast<std::uint64_t>(*length) > static_cast<std::uint64_t>(maximum)) {
            return tl::make_unexpected(resource(std::string(field) + " exceeds local bound"));
        }
        const auto result = input_.substr(offset_, size);
        offset_ += size;
        return result;
    }

  private:
    std::string_view input_;
    std::size_t offset_ = 0U;
};

std::vector<std::uint8_t> bytes(std::string_view input) {
    std::vector<std::uint8_t> result;
    result.reserve(input.size());
    for (const char character : input) {
        result.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    return result;
}

bool valid_ecdsa_point(std::string_view point) {
    return point.size() == 65U && static_cast<unsigned char>(point.front()) == 0x04U;
}

bool ascii_nonempty(std::string_view value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](char character) {
               const auto octet = static_cast<unsigned char>(character);
               return octet >= 0x21U && octet <= 0x7eU;
           });
}

bool allowed_permission(std::string_view name) {
    constexpr std::array<std::string_view, 5> names{
        "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding",
        "permit-pty", "permit-user-rc"};
    return std::find(names.begin(), names.end(), name) != names.end();
}

tl::expected<std::vector<std::uint8_t>, ParseError> parse_public_key_blob(
    std::string_view blob, CallerAlgorithm expected, const Limits& limits) {
    Reader reader(blob);
    const auto algorithm = reader.string(limits.max_name_bytes, "SSH key algorithm");
    if (!algorithm) {
        return tl::make_unexpected(algorithm.error());
    }
    if (expected == CallerAlgorithm::es256) {
        if (*algorithm != kEcdsaKey) {
            return tl::make_unexpected(unsupported("carrier CA algorithm does not match certificate"));
        }
        const auto curve = reader.string(limits.max_name_bytes, "ECDSA curve");
        const auto point = reader.string(65U, "ECDSA public point");
        if (!curve || !point) {
            return tl::make_unexpected(!curve ? curve.error() : point.error());
        }
        if (*curve != kCurve) {
            return tl::make_unexpected(unsupported("unsupported carrier CA ECDSA curve"));
        }
        if (!valid_ecdsa_point(*point) || !reader.empty()) {
            return tl::make_unexpected(malformed("invalid P-256 carrier CA key"));
        }
    } else {
        if (*algorithm != kEd25519Key) {
            return tl::make_unexpected(unsupported("carrier CA algorithm does not match certificate"));
        }
        const auto key = reader.string(32U, "Ed25519 public key");
        if (!key) {
            return tl::make_unexpected(key.error());
        }
        if (key->size() != 32U || !reader.empty()) {
            return tl::make_unexpected(malformed("invalid Ed25519 carrier CA key"));
        }
    }
    return bytes(blob);
}

bool valid_positive_mpint(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    const auto first = static_cast<unsigned char>(value.front());
    if ((first & 0x80U) != 0U) {
        return false;
    }
    if (first == 0U) {
        return value.size() > 1U &&
               (static_cast<unsigned char>(value[1U]) & 0x80U) != 0U;
    }
    return true;
}

tl::expected<std::pair<std::string, std::vector<std::uint8_t>>, ParseError> parse_signature_blob(
    std::string_view blob, CallerAlgorithm expected, const Limits& limits) {
    Reader reader(blob);
    const auto algorithm = reader.string(limits.max_name_bytes, "SSH signature algorithm");
    const auto signature = reader.string(256U, "SSH certificate signature");
    if (!algorithm || !signature) {
        return tl::make_unexpected(!algorithm ? algorithm.error() : signature.error());
    }
    if (!reader.empty()) {
        return tl::make_unexpected(malformed("trailing SSH signature data"));
    }
    if (expected == CallerAlgorithm::es256) {
        if (*algorithm != kEcdsaKey) {
            return tl::make_unexpected(unsupported("certificate signature algorithm mismatch"));
        }
        Reader scalars(*signature);
        const auto r = scalars.string(33U, "ECDSA signature r");
        const auto s = scalars.string(33U, "ECDSA signature s");
        if (!r || !s) {
            return tl::make_unexpected(!r ? r.error() : s.error());
        }
        if (!valid_positive_mpint(*r) || !valid_positive_mpint(*s) || !scalars.empty()) {
            return tl::make_unexpected(malformed("invalid ECDSA signature encoding"));
        }
    } else {
        if (*algorithm != kEd25519Key || signature->size() != 64U) {
            return tl::make_unexpected(*algorithm != kEd25519Key
                                           ? unsupported("certificate signature algorithm mismatch")
                                           : malformed("invalid Ed25519 certificate signature"));
        }
    }
    return std::make_pair(std::string(*algorithm), bytes(*signature));
}

}  // namespace

CertificateResult parse_certificate(std::string_view blob, Limits limits) {
    if (limits.max_certificate_bytes == 0U || limits.max_certificate_bytes > 49152U ||
        limits.max_token_bytes == 0U || limits.max_token_bytes > 32768U ||
        limits.max_principals == 0U || limits.max_extensions == 0U ||
        limits.max_name_bytes == 0U) {
        return tl::make_unexpected(resource("invalid OpenSSH certificate limits"));
    }
    if (blob.size() > limits.max_certificate_bytes) {
        return tl::make_unexpected(resource("OpenSSH certificate exceeds local bound"));
    }

    Reader reader(blob);
    const auto type = reader.string(limits.max_name_bytes, "certificate type");
    if (!type) {
        return tl::make_unexpected(type.error());
    }
    CallerAlgorithm caller_algorithm;
    if (*type == kEcdsaCertificate) {
        caller_algorithm = CallerAlgorithm::es256;
    } else if (*type == kEd25519Certificate) {
        caller_algorithm = CallerAlgorithm::ed25519;
    } else {
        return tl::make_unexpected(unsupported("unsupported OpenSSH certificate algorithm"));
    }

    const auto nonce = reader.string(1024U, "certificate nonce");
    if (!nonce || nonce->empty()) {
        return tl::make_unexpected(!nonce ? nonce.error() : malformed("empty certificate nonce"));
    }

    std::vector<std::uint8_t> certified_key;
    if (caller_algorithm == CallerAlgorithm::es256) {
        const auto curve = reader.string(limits.max_name_bytes, "certified ECDSA curve");
        const auto point = reader.string(65U, "certified ECDSA point");
        if (!curve || !point) {
            return tl::make_unexpected(!curve ? curve.error() : point.error());
        }
        if (*curve != kCurve || !valid_ecdsa_point(*point)) {
            return tl::make_unexpected(*curve != kCurve
                                           ? unsupported("unsupported certified ECDSA curve")
                                           : malformed("invalid certified P-256 key"));
        }
        certified_key = bytes(*point);
    } else {
        const auto key = reader.string(32U, "certified Ed25519 key");
        if (!key) {
            return tl::make_unexpected(key.error());
        }
        if (key->size() != 32U) {
            return tl::make_unexpected(malformed("invalid certified Ed25519 key"));
        }
        certified_key = bytes(*key);
    }

    const auto serial = reader.u64();
    const auto certificate_class = reader.u32();
    const auto key_id = reader.string(1024U, "certificate key ID");
    const auto principal_blob = reader.string(limits.max_certificate_bytes, "certificate principals");
    if (!serial || !certificate_class || !key_id || !principal_blob) {
        if (!serial) return tl::make_unexpected(serial.error());
        if (!certificate_class) return tl::make_unexpected(certificate_class.error());
        if (!key_id) return tl::make_unexpected(key_id.error());
        return tl::make_unexpected(principal_blob.error());
    }
    if (*certificate_class != 1U) {
        return tl::make_unexpected(malformed("OpenSSH certificate is not a user certificate"));
    }

    std::vector<std::string> principals;
    Reader principal_reader(*principal_blob);
    while (!principal_reader.empty()) {
        if (principals.size() == limits.max_principals) {
            return tl::make_unexpected(resource("too many certificate principals"));
        }
        const auto principal = principal_reader.string(256U, "certificate principal");
        if (!principal) {
            return tl::make_unexpected(principal.error());
        }
        if (!ascii_nonempty(*principal)) {
            return tl::make_unexpected(malformed("invalid certificate principal"));
        }
        principals.emplace_back(*principal);
    }
    if (principals.size() != 1U) {
        return tl::make_unexpected(malformed("certificate must contain exactly one principal"));
    }

    const auto valid_after = reader.u64();
    const auto valid_before = reader.u64();
    const auto critical_options = reader.string(limits.max_certificate_bytes, "critical options");
    const auto extension_blob = reader.string(limits.max_certificate_bytes, "certificate extensions");
    const auto reserved = reader.string(limits.max_certificate_bytes, "certificate reserved field");
    const auto signature_key_blob = reader.string(limits.max_certificate_bytes, "certificate signature key");
    if (!valid_after || !valid_before || !critical_options || !extension_blob || !reserved ||
        !signature_key_blob) {
        if (!valid_after) return tl::make_unexpected(valid_after.error());
        if (!valid_before) return tl::make_unexpected(valid_before.error());
        if (!critical_options) return tl::make_unexpected(critical_options.error());
        if (!extension_blob) return tl::make_unexpected(extension_blob.error());
        if (!reserved) return tl::make_unexpected(reserved.error());
        return tl::make_unexpected(signature_key_blob.error());
    }
    if (*valid_before == std::numeric_limits<std::uint64_t>::max() ||
        *valid_after >= *valid_before) {
        return tl::make_unexpected(malformed("certificate validity is not finite and ordered"));
    }
    if (!critical_options->empty()) {
        return tl::make_unexpected(malformed("certificate critical options are prohibited"));
    }
    if (!reserved->empty()) {
        return tl::make_unexpected(malformed("certificate reserved field is not empty"));
    }

    std::vector<std::string> permissions;
    std::vector<std::uint8_t> token;
    std::string previous;
    Reader extension_reader(*extension_blob);
    std::size_t extension_count = 0U;
    while (!extension_reader.empty()) {
        if (extension_count == limits.max_extensions) {
            return tl::make_unexpected(resource("too many certificate extensions"));
        }
        const auto name = extension_reader.string(limits.max_name_bytes, "extension name");
        const auto data = extension_reader.string(limits.max_certificate_bytes, "extension data");
        if (!name || !data) {
            return tl::make_unexpected(!name ? name.error() : data.error());
        }
        if (!ascii_nonempty(*name) || (!previous.empty() && previous >= *name)) {
            return tl::make_unexpected(malformed("extensions are duplicate or not lexically sorted"));
        }
        previous.assign(name->begin(), name->end());
        ++extension_count;
        if (*name == kCarrier) {
            if (!token.empty()) {
                return tl::make_unexpected(malformed("duplicate CredBind carrier extension"));
            }
            Reader carrier_reader(*data);
            const auto nested_token = carrier_reader.string(limits.max_token_bytes, "CredBind token");
            if (!nested_token) {
                return tl::make_unexpected(nested_token.error());
            }
            if (nested_token->empty() || !carrier_reader.empty()) {
                return tl::make_unexpected(malformed("malformed CredBind carrier tuple"));
            }
            token = bytes(*nested_token);
        } else {
            if (!allowed_permission(*name) || !data->empty()) {
                return tl::make_unexpected(malformed("unknown or non-empty permission extension"));
            }
            permissions.emplace_back(*name);
        }
    }
    if (token.empty()) {
        return tl::make_unexpected(malformed("missing CredBind carrier extension"));
    }

    const auto signature_key = parse_public_key_blob(*signature_key_blob, caller_algorithm, limits);
    if (!signature_key) {
        return tl::make_unexpected(signature_key.error());
    }
    const auto signed_length = reader.offset();
    const auto signature_blob = reader.string(512U, "certificate signature blob");
    if (!signature_blob) {
        return tl::make_unexpected(signature_blob.error());
    }
    if (!reader.empty()) {
        return tl::make_unexpected(malformed("trailing OpenSSH certificate data"));
    }
    const auto parsed_signature = parse_signature_blob(*signature_blob, caller_algorithm, limits);
    if (!parsed_signature) {
        return tl::make_unexpected(parsed_signature.error());
    }

    Certificate result{caller_algorithm,
                       std::move(certified_key),
                       *serial,
                       std::string(*key_id),
                       std::move(principals),
                       *valid_after,
                       *valid_before,
                       std::move(permissions),
                       std::move(token),
                       *signature_key,
                       parsed_signature->first,
                       parsed_signature->second,
                       bytes(blob.substr(0U, signed_length))};
    return result;
}

}  // namespace credbind::openssh
