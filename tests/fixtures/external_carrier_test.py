#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Feed one externally generated carrier through the internal C++ verifier.

This is a bounded conformance ingress for the early cross-language carrier
subgate. It is not a production configuration or command interface.
"""

from __future__ import annotations

import argparse
import base64
import json
import struct
import subprocess
import tempfile
from pathlib import Path


MAX_DESCRIPTOR_BYTES = 65536
MAX_CERTIFICATE_BYTES = 49152
MAX_FIELD_BYTES = 65536
CALLER_ALGORITHMS = {"ES256", "Ed25519"}
EVIDENCE_PROFILES = {"standard-jws-v1", "gq-rs256-v1"}
BINDING_PROFILES = {"oidc-nonce-v1", "audience-v1", "credbind-claim-v1"}
ACQUISITION_PROFILES = {
    "oidc-native-auth-code-v1", "oidc-confidential-web-auth-code-v1",
    "challenge-bound-workload-v1",
}
EXTENSIONS = {
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
    "permit-X11-forwarding",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_object(value: object, names: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == names, f"invalid {label}")
    return value


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate JSON member: {name}")
        result[name] = value
    return result


def text(value: object, label: str, *, allow_empty: bool = False) -> str:
    require(isinstance(value, str), f"invalid {label}")
    encoded = value.encode("utf-8")
    require((allow_empty or encoded) and len(encoded) <= MAX_FIELD_BYTES, f"invalid {label}")
    return value


def unique_set(value: object, allowed: set[str] | None, label: str,
               *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list) and (allow_empty or value), f"invalid {label}")
    result = [text(item, label) for item in value]
    require(len(result) == len(set(result)), f"duplicate {label}")
    require(allowed is None or set(result) <= allowed, f"unsupported {label}")
    return result


def field(value: bytes) -> bytes:
    require(len(value) <= MAX_FIELD_BYTES, "external carrier frame field is too large")
    return struct.pack(">I", len(value)) + value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("descriptor", type=Path)
    args = parser.parse_args()
    raw = args.descriptor.read_bytes()
    require(len(raw) <= MAX_DESCRIPTOR_BYTES, "descriptor is too large")
    descriptor = exact_object(
        json.loads(raw, object_pairs_hook=reject_duplicate_object),
        {
            "certificate_blob_base64", "key_type_argument", "requested_user",
            "issuer", "jwks_path", "audience", "authorized_party",
            "verification_time", "principal_claim", "caller_algorithms",
            "evidence_profiles", "binding_profiles", "acquisition_profiles",
            "admitted_claims",
            "account_rule", "maximum_identity_lifetime_seconds",
            "clock_skew_seconds", "require_non_reconstructible_evidence",
            "expected",
        },
        "descriptor",
    )
    certificate = base64.b64decode(
        text(descriptor["certificate_blob_base64"], "certificate"), validate=True
    )
    require(0 < len(certificate) <= MAX_CERTIFICATE_BYTES, "invalid certificate size")
    jwks_path = Path(text(descriptor["jwks_path"], "JWKS path"))
    require(jwks_path.is_absolute(), "JWKS path is not absolute")
    verification_time = descriptor["verification_time"]
    maximum_lifetime = descriptor["maximum_identity_lifetime_seconds"]
    clock_skew = descriptor["clock_skew_seconds"]
    require(all(isinstance(value, int) and not isinstance(value, bool)
                for value in (verification_time, maximum_lifetime, clock_skew)),
            "invalid time policy")
    require(maximum_lifetime >= 0 and clock_skew >= 0, "negative time policy")
    require(isinstance(descriptor["require_non_reconstructible_evidence"], bool),
            "invalid reconstructibility policy")
    account = exact_object(
        descriptor["account_rule"],
        {"issuer", "claim", "value", "allowed_certificate_extensions"},
        "account rule",
    )
    expected = exact_object(
        descriptor["expected"],
        {"principal", "ca_key_type", "ca_public_key_base64"},
        "expected result",
    )
    caller_algorithms = unique_set(
        descriptor["caller_algorithms"], CALLER_ALGORITHMS, "caller algorithms"
    )
    evidence_profiles = unique_set(
        descriptor["evidence_profiles"], EVIDENCE_PROFILES, "evidence profiles"
    )
    binding_profiles = unique_set(
        descriptor["binding_profiles"], BINDING_PROFILES, "binding profiles"
    )
    unique_set(
        descriptor["acquisition_profiles"], ACQUISITION_PROFILES,
        "acquisition profiles",
    )
    admitted_claims = unique_set(
        descriptor["admitted_claims"], None, "admitted claims"
    )
    allowed_extensions = unique_set(
        account["allowed_certificate_extensions"], EXTENSIONS,
        "allowed certificate extensions", allow_empty=True,
    )
    values = (
        certificate,
        text(descriptor["key_type_argument"], "key type").encode("ascii"),
        text(descriptor["requested_user"], "requested user").encode("utf-8"),
        text(descriptor["issuer"], "issuer").encode("utf-8"),
        str(jwks_path).encode("utf-8"),
        text(descriptor["audience"], "audience").encode("utf-8"),
        text(descriptor["authorized_party"], "authorized party", allow_empty=True).encode("utf-8"),
        str(verification_time).encode("ascii"),
        text(descriptor["principal_claim"], "principal claim").encode("utf-8"),
        ",".join(caller_algorithms).encode("ascii"),
        ",".join(evidence_profiles).encode("ascii"),
        ",".join(binding_profiles).encode("ascii"),
        ",".join(admitted_claims).encode("utf-8"),
        ",".join(allowed_extensions).encode("ascii"),
        text(account["issuer"], "account issuer").encode("utf-8"),
        text(account["claim"], "account claim", allow_empty=True).encode("utf-8"),
        text(account["value"], "account value", allow_empty=True).encode("utf-8"),
        str(maximum_lifetime).encode("ascii"),
        str(clock_skew).encode("ascii"),
        (b"1" if descriptor["require_non_reconstructible_evidence"] else b"0"),
        text(expected["principal"], "expected principal").encode("ascii"),
        text(expected["ca_key_type"], "expected CA key type").encode("ascii"),
        text(expected["ca_public_key_base64"], "expected CA key").encode("ascii"),
    )
    frame = b"P" + b"".join(field(value) for value in values)
    with tempfile.NamedTemporaryFile(prefix="credbind-external-carrier-", suffix=".frame") as handle:
        handle.write(frame)
        handle.flush()
        result = subprocess.run(
            [str(args.binary), "--direct-carrier-file", handle.name],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=10.0,
        )
    require(result.returncode == 0 and not result.stdout and not result.stderr,
            "external carrier was rejected")
    print(json.dumps({"status": "verified"}, sort_keys=True))


if __name__ == "__main__":
    main()
