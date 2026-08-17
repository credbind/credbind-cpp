#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise implemented C++ parsers against the immutable RC corpus."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = (
    ROOT / ".cache" / "conformance" / "v1.0.0-rc.4" / "corpus"
    / "credbind-ssh-v1-conformance-v1.0.0-rc.4"
)


def invoke(binary: Path, *arguments: str) -> None:
    result = subprocess.run(
        [str(binary), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # Arguments contain bearer-sensitive fixtures. Never include the
        # command or parser streams in the test failure.
        raise RuntimeError("pinned parser vector was rejected")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def crypto_frame(mode: bytes, *fields: bytes) -> bytes:
    return mode + b"".join(struct.pack(">I", len(field)) + field for field in fields)


def run_crypto(binary: Path, directory: Path, name: str, frame: bytes) -> None:
    path = directory / f"{name}.frame"
    path.write_bytes(frame)
    invoke(binary, "--crypto-file", str(path))


def run_jwks(binary: Path, expectation: str, path: Path, kid: str) -> None:
    invoke(binary, "--jwks-file", expectation, str(path), kid)


def encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def standard_evidence(header: str, signature: str) -> bytes:
    return struct.pack(">Q", len(header)) + header.encode("ascii") + struct.pack(
        ">Q", len(signature)
    ) + signature.encode("ascii")


def split_standard_evidence(evidence: bytes) -> tuple[str, str]:
    header_length = int.from_bytes(evidence[:8], "big")
    header_offset = 8
    signature_length_offset = header_offset + header_length
    signature_length = int.from_bytes(
        evidence[signature_length_offset : signature_length_offset + 8], "big"
    )
    signature_offset = signature_length_offset + 8
    if signature_offset + signature_length != len(evidence):
        raise RuntimeError("invalid pinned standard evidence framing")
    return (
        evidence[header_offset:signature_length_offset].decode("ascii"),
        evidence[signature_offset:].decode("ascii"),
    )


def run_issuer(
    binary: Path,
    directory: Path,
    name: str,
    mode: bytes,
    vector: dict,
    jwks_path: Path,
    *,
    commitment: str | None = None,
    payload: str | None = None,
    evidence: bytes | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    authorized_party: str | None = None,
    verification_time: int | None = None,
    scenario: str = "",
) -> None:
    token = json.loads(vector["token"])
    claims = vector["issuer_claims"]
    claim_audience = claims["aud"]
    if isinstance(claim_audience, list):
        claim_audience = claim_audience[0]
    selected_commitment = commitment or vector["expected_commitment"]
    selected_payload = payload or token["payload"]
    selected_evidence = evidence if evidence is not None else b64url(token["credbind_evidence"])
    digest_input = b"CredBind-Issuer-Evidence-Digest-v1\x00"
    for value in (
        vector["evidence_profile"].encode("ascii"),
        selected_payload.encode("ascii"),
        selected_evidence,
    ):
        digest_input += struct.pack(">Q", len(value)) + value
    expected_digest = hashlib.sha256(digest_input).digest()
    frame = crypto_frame(
        mode,
        vector["evidence_profile"].encode("ascii"),
        vector["binding_profile"].encode("ascii"),
        selected_commitment.encode("ascii"),
        selected_payload.encode("ascii"),
        selected_evidence,
        (issuer or vector["authenticated_issuer"]).encode("utf-8"),
        str(jwks_path).encode("utf-8"),
        (audience or claim_audience).encode("utf-8"),
        (authorized_party if authorized_party is not None else claims.get("azp", "")).encode(
            "utf-8"
        ),
        str(verification_time or vector["verification_time"]).encode("ascii"),
        scenario.encode("ascii"),
        expected_digest,
        str(claims["exp"]).encode("ascii"),
    )
    path = directory / f"issuer-{name}.frame"
    path.write_bytes(frame)
    invoke(binary, "--issuer-file", str(path))


def direct_carrier_frame(
    mode: bytes,
    certificate: bytes,
    carrier: dict,
    token_vector: dict,
    jwks_path: Path,
    *,
    key_type: str | None = None,
    requested_user: str = "fixture-user",
    verification_time: int | None = None,
    principal_claim: str = "sub",
    caller_algorithms: str | None = None,
    evidence_profiles: str | None = None,
    binding_profiles: str | None = None,
    admitted_claims: str = "sub,email,iat",
    allowed_extensions: str = "permit-port-forwarding,permit-pty",
    account_issuer: str | None = None,
    account_claim: str = "sub",
    account_value: str = "fixture-subject-v1-rc4",
    maximum_identity_lifetime: int = 0,
    clock_skew: int = 30,
) -> bytes:
    claims = token_vector["issuer_claims"]
    audience = claims["aud"]
    if isinstance(audience, list):
        audience = audience[0]
    return crypto_frame(
        mode,
        certificate,
        (key_type or carrier["key_type_argument"]).encode("ascii"),
        requested_user.encode("utf-8"),
        token_vector["authenticated_issuer"].encode("utf-8"),
        str(jwks_path).encode("utf-8"),
        audience.encode("utf-8"),
        claims.get("azp", "").encode("utf-8"),
        str(verification_time or token_vector["verification_time"]).encode("ascii"),
        principal_claim.encode("utf-8"),
        (caller_algorithms or token_vector["caller_algorithm"]).encode("ascii"),
        (evidence_profiles or token_vector["evidence_profile"]).encode("ascii"),
        (binding_profiles or token_vector["binding_profile"]).encode("ascii"),
        admitted_claims.encode("utf-8"),
        allowed_extensions.encode("ascii"),
        (account_issuer or token_vector["authenticated_issuer"]).encode("utf-8"),
        account_claim.encode("utf-8"),
        account_value.encode("utf-8"),
        str(maximum_identity_lifetime).encode("ascii"),
        str(clock_skew).encode("ascii"),
        b"0",
        carrier["principal"].encode("ascii"),
        carrier["ca_public_key"].split(" ", 1)[0].encode("ascii"),
        carrier["ca_public_key"].split(" ", 1)[1].encode("ascii"),
    )


def run_direct_carrier(
    binary: Path,
    directory: Path,
    name: str,
    frame: bytes,
) -> None:
    path = directory / f"direct-{name}.frame"
    path.write_bytes(frame)
    invoke(binary, "--direct-carrier-file", str(path))


def run_direct_token(
    binary: Path,
    directory: Path,
    name: str,
    mode: bytes,
    vector: dict,
    jwks_path: Path,
    *,
    token: str | None = None,
) -> None:
    claims = vector["issuer_claims"]
    audience = claims["aud"]
    if isinstance(audience, list):
        audience = audience[0]
    frame = crypto_frame(
        mode,
        (token or vector["token"]).encode("utf-8"),
        vector["authenticated_issuer"].encode("utf-8"),
        str(jwks_path).encode("utf-8"),
        audience.encode("utf-8"),
        claims.get("azp", "").encode("utf-8"),
        str(vector["verification_time"]).encode("ascii"),
        vector["caller_algorithm"].encode("ascii"),
        vector["evidence_profile"].encode("ascii"),
        vector["binding_profile"].encode("ascii"),
        b"sub,email,iat",
        vector["expected_commitment"].encode("ascii"),
        vector["caller_algorithm"].encode("ascii"),
    )
    path = directory / f"direct-token-{name}.frame"
    path.write_bytes(frame)
    try:
        invoke(binary, "--direct-token-file", str(path))
    except RuntimeError as failure:
        raise RuntimeError(f"direct-token case {name} was rejected") from failure


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    corpus = Path(os.environ.get("CREDBIND_FIXTURE_CORPUS", DEFAULT_CORPUS))
    if not (corpus / "MANIFEST.json").is_file():
        raise RuntimeError("pinned corpus is unavailable; run make fixtures")

    for name in (
        "standard-p256",
        "standard-ed25519",
        "workload-audience-p256",
        "workload-claim-p256",
        "gq-p256",
    ):
        vector = load(corpus / "vectors" / f"{name}.json")
        invoke(args.binary, vector["token"])
        invoke(args.binary, "--compact-jws", vector["acquired_credential"])

    with tempfile.TemporaryDirectory(prefix="credbind-certificate-") as directory:
        temporary = Path(directory)
        for name in ("p256", "ed25519"):
            vector = load(corpus / "vectors" / f"ssh-carrier-{name}.json")
            certificate = temporary / f"{name}.bin"
            certificate.write_bytes(
                base64.b64decode(vector["certificate_blob_base64"], validate=True)
            )
            invoke(args.binary, "--certificate-file", str(certificate))

        jwks = load(corpus / "keys" / "issuer-jwks.json")
        issuer_key = jwks["keys"][0]
        issuer_jwks_path = corpus / "keys" / "issuer-jwks.json"
        run_jwks(args.binary, "pass", issuer_jwks_path, issuer_key["kid"])

        unsafe_link = temporary / "issuer-jwks-link.json"
        unsafe_link.symlink_to(issuer_jwks_path)
        run_jwks(args.binary, "untrusted", unsafe_link, issuer_key["kid"])

        non_regular = temporary / "issuer-jwks-fifo"
        os.mkfifo(non_regular)
        run_jwks(args.binary, "untrusted", non_regular, issuer_key["kid"])

        group_writable = temporary / "issuer-jwks-group-writable.json"
        group_writable.write_text(json.dumps(jwks), encoding="utf-8")
        group_writable.chmod(0o660)
        run_jwks(args.binary, "untrusted", group_writable, issuer_key["kid"])

        duplicate_kid = temporary / "issuer-jwks-duplicate-kid.json"
        duplicate_kid.write_text(
            json.dumps({"keys": [issuer_key, issuer_key]}), encoding="utf-8"
        )
        run_jwks(args.binary, "untrusted", duplicate_kid, issuer_key["kid"])

        private_key = dict(issuer_key)
        private_key["d"] = "AA"
        private_member = temporary / "issuer-jwks-private-member.json"
        private_member.write_text(json.dumps({"keys": [private_key]}), encoding="utf-8")
        run_jwks(args.binary, "untrusted", private_member, issuer_key["kid"])

        trailing = temporary / "issuer-jwks-trailing.json"
        trailing.write_text(json.dumps(jwks) + " []", encoding="utf-8")
        run_jwks(args.binary, "untrusted", trailing, issuer_key["kid"])

        duplicate_member = temporary / "issuer-jwks-duplicate-member.json"
        duplicate_member.write_text(
            '{"keys":[],"keys":' + json.dumps(jwks["keys"]) + "}", encoding="utf-8"
        )
        run_jwks(args.binary, "untrusted", duplicate_member, issuer_key["kid"])

        wrong_role_key = dict(issuer_key)
        wrong_role_key["use"] = "enc"
        wrong_role = temporary / "issuer-jwks-wrong-role.json"
        wrong_role.write_text(json.dumps({"keys": [wrong_role_key]}), encoding="utf-8")
        run_jwks(args.binary, "untrusted", wrong_role, issuer_key["kid"])

        wrong_algorithm_key = dict(issuer_key)
        wrong_algorithm_key["alg"] = "PS256"
        wrong_algorithm = temporary / "issuer-jwks-wrong-algorithm.json"
        wrong_algorithm.write_text(
            json.dumps({"keys": [wrong_algorithm_key]}), encoding="utf-8"
        )
        run_jwks(args.binary, "untrusted", wrong_algorithm, issuer_key["kid"])

        wrong_exponent_key = dict(issuer_key)
        wrong_exponent_key["e"] = "Aw"
        wrong_exponent = temporary / "issuer-jwks-wrong-exponent.json"
        wrong_exponent.write_text(
            json.dumps({"keys": [wrong_exponent_key]}), encoding="utf-8"
        )
        run_jwks(args.binary, "untrusted", wrong_exponent, issuer_key["kid"])

        invalid_utf8 = temporary / "issuer-jwks-invalid-utf8.json"
        invalid_utf8.write_bytes(issuer_jwks_path.read_bytes().replace(b"RS256", b"RS\xff56"))
        run_jwks(args.binary, "untrusted", invalid_utf8, issuer_key["kid"])
        run_jwks(args.binary, "untrusted", issuer_jwks_path, "missing-key-id")

        issuer_vectors = {
            name: load(corpus / "vectors" / f"{name}.json")
            for name in (
                "standard-p256",
                "standard-ed25519",
                "workload-audience-p256",
                "workload-claim-p256",
                "gq-p256",
            )
        }

        carrier_vectors = {
            name: load(corpus / "vectors" / f"ssh-carrier-{name}.json")
            for name in ("p256", "ed25519")
        }
        direct_positive = 0
        direct_negative = 0
        for name, vector in issuer_vectors.items():
            run_direct_token(
                args.binary, temporary, f"{name}-pass", b"P", vector,
                issuer_jwks_path,
            )
            direct_positive += 1
        caller_mutation_vector = issuer_vectors["gq-p256"]
        caller_mutation = json.loads(caller_mutation_vector["token"])
        caller_signature = caller_mutation["signatures"][0]["signature"]
        caller_mutation["signatures"][0]["signature"] = (
            ("A" if caller_signature[0] != "A" else "B") + caller_signature[1:]
        )
        run_direct_token(
            args.binary, temporary, "gq-caller-signature", b"Q",
            caller_mutation_vector, issuer_jwks_path,
            token=json.dumps(caller_mutation, separators=(",", ":")),
        )
        direct_negative += 1
        cic_vector = issuer_vectors["standard-p256"]

        def mutate_cic(mutator, *, raw_prefix: str = "") -> str:
            token_object = json.loads(cic_vector["token"])
            protected = token_object["signatures"][0]["protected"]
            header_text = b64url(protected).decode("utf-8")
            header = json.loads(header_text)
            mutator(header)
            changed_header = json.dumps(header, separators=(",", ":"))
            if raw_prefix:
                changed_header = "{" + raw_prefix + changed_header[1:]
            token_object["signatures"][0]["protected"] = encode_b64url(
                changed_header.encode("utf-8")
            )
            return json.dumps(token_object, separators=(",", ":"))

        cic_mutations = (
            ("duplicate-member", b"M", lambda h: None, '"alg":"ES256",'),
            ("unknown-member", b"M", lambda h: h.__setitem__("unknown", "x"), ""),
            ("unsupported-version", b"W", lambda h: h.__setitem__(
                "https://credbind.dev/core/v1#version", "2"), ""),
            ("unsupported-role", b"W", lambda h: h.__setitem__(
                "https://credbind.dev/core/v1#role", "other"), ""),
            ("wrong-media-type", b"M", lambda h: h.__setitem__("typ", "JWT"), ""),
            ("wrong-critical-set", b"M", lambda h: h["crit"].__setitem__(
                4, "https://credbind.dev/core/v1#unknown"), ""),
            ("algorithm-substitution", b"A", lambda h: h.__setitem__("alg", "EdDSA"), ""),
            ("private-jwk", b"K", lambda h: h["jwk"].__setitem__("d", "AA"), ""),
            ("invalid-point", b"K", lambda h: h["jwk"].__setitem__(
                "x", encode_b64url(bytes(32))), ""),
            ("wrong-nonce-length", b"M", lambda h: h.__setitem__(
                "https://credbind.dev/core/v1#nonce", encode_b64url(bytes(15))), ""),
            ("duplicate-crit", b"M", lambda h: h["crit"].__setitem__(
                4, h["crit"][0]), ""),
        )
        for name, mode, mutator, raw_prefix in cic_mutations:
            run_direct_token(
                args.binary, temporary, f"cic-{name}", mode, cic_vector,
                issuer_jwks_path, token=mutate_cic(mutator, raw_prefix=raw_prefix),
            )
            direct_negative += 1
        for name, token_name in (("p256", "standard-p256"),
                                 ("ed25519", "standard-ed25519")):
            carrier = carrier_vectors[name]
            token_vector = issuer_vectors[token_name]
            certificate = base64.b64decode(
                carrier["certificate_blob_base64"], validate=True
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-pass",
                direct_carrier_frame(
                    b"P", certificate, carrier, token_vector, issuer_jwks_path
                ),
            )
            direct_positive += 1

            run_direct_carrier(
                args.binary, temporary, f"{name}-wrong-key-type",
                direct_carrier_frame(
                    b"M", certificate, carrier, token_vector, issuer_jwks_path,
                    key_type="ssh-rsa-cert-v01@openssh.com",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-invalid-requested-user",
                direct_carrier_frame(
                    b"M", certificate, carrier, token_vector, issuer_jwks_path,
                    requested_user="invalid\x01user",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-principal-policy",
                direct_carrier_frame(
                    b"J", certificate, carrier, token_vector, issuer_jwks_path,
                    principal_claim="email",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-issuer",
                direct_carrier_frame(
                    b"D", certificate, carrier, token_vector, issuer_jwks_path,
                    account_issuer="https://other-issuer.example.test",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-predicate",
                direct_carrier_frame(
                    b"D", certificate, carrier, token_vector, issuer_jwks_path,
                    account_value="other-subject",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-one-of",
                direct_carrier_frame(
                    b"P", certificate, carrier, token_vector, issuer_jwks_path,
                    account_claim="@one-of",
                ),
            )
            direct_positive += 1
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-array-wrong-type",
                direct_carrier_frame(
                    b"D", certificate, carrier, token_vector, issuer_jwks_path,
                    account_claim="@array-wrong-type",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-extension-subset",
                direct_carrier_frame(
                    b"D", certificate, carrier, token_vector, issuer_jwks_path,
                    allowed_extensions="permit-pty",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-account-rules-do-not-combine",
                direct_carrier_frame(
                    b"D", certificate, carrier, token_vector, issuer_jwks_path,
                    account_claim="@split-rules",
                ),
            )
            run_direct_carrier(
                args.binary, temporary, f"{name}-identity-policy-boundary",
                direct_carrier_frame(
                    b"X", certificate, carrier, token_vector, issuer_jwks_path,
                    maximum_identity_lifetime=60,
                ),
            )
            changed_signature = bytearray(certificate)
            changed_signature[-1] ^= 1
            run_direct_carrier(
                args.binary, temporary, f"{name}-certificate-signature",
                direct_carrier_frame(
                    b"V", bytes(changed_signature), carrier, token_vector,
                    issuer_jwks_path,
                ),
            )
            token = token_vector["token"]
            token_object = json.loads(token)
            signature_text = token_object["signatures"][0]["signature"]
            token_object["signatures"][0]["signature"] = (
                ("A" if signature_text[0] != "A" else "B") + signature_text[1:]
            )
            changed_token = json.dumps(token_object, separators=(",", ":"))
            if len(changed_token) != len(token):
                raise RuntimeError("caller-signature mutation changed token length")
            changed_certificate = certificate.replace(
                token.encode("utf-8"), changed_token.encode("utf-8"), 1
            )
            if changed_certificate == certificate:
                raise RuntimeError("carrier token was not found for mutation")
            run_direct_carrier(
                args.binary, temporary, f"{name}-caller-signature",
                direct_carrier_frame(
                    b"Q", changed_certificate, carrier, token_vector,
                    issuer_jwks_path,
                ),
            )
            direct_negative += 11
        external_carrier = carrier_vectors["p256"]
        external_token = issuer_vectors["standard-p256"]
        external_descriptor = temporary / "external-carrier.json"
        external_descriptor.write_text(
            json.dumps({
                "certificate_blob_base64": external_carrier["certificate_blob_base64"],
                "key_type_argument": external_carrier["key_type_argument"],
                "requested_user": "fixture-user",
                "issuer": external_token["authenticated_issuer"],
                "jwks_path": str(issuer_jwks_path),
                "audience": external_token["issuer_claims"]["aud"],
                "authorized_party": external_token["issuer_claims"]["azp"],
                "verification_time": external_token["verification_time"],
                "principal_claim": "sub",
                "caller_algorithms": ["ES256"],
                "evidence_profiles": ["standard-jws-v1"],
                "binding_profiles": ["oidc-nonce-v1"],
                "acquisition_profiles": ["oidc-native-auth-code-v1"],
                "admitted_claims": ["sub", "email", "iat"],
                "account_rule": {
                    "issuer": external_token["authenticated_issuer"],
                    "claim": "sub",
                    "value": "fixture-subject-v1-rc4",
                    "allowed_certificate_extensions": [
                        "permit-port-forwarding", "permit-pty"
                    ],
                },
                "maximum_identity_lifetime_seconds": 0,
                "clock_skew_seconds": 30,
                "require_non_reconstructible_evidence": False,
                "expected": {
                    "principal": external_carrier["principal"],
                    "ca_key_type": external_carrier["ca_public_key"].split(" ", 1)[0],
                    "ca_public_key_base64": external_carrier["ca_public_key"].split(" ", 1)[1],
                },
            }),
            encoding="utf-8",
        )
        invoke(
            Path(sys.executable),
            str(ROOT / "tests" / "fixtures" / "external_carrier_test.py"),
            str(args.binary),
            str(external_descriptor),
        )
        for name, vector in issuer_vectors.items():
            run_issuer(args.binary, temporary, f"{name}-pass", b"P", vector, issuer_jwks_path)
        run_issuer(
            args.binary,
            temporary,
            "required-one-of-pass",
            b"P",
            issuer_vectors["standard-p256"],
            issuer_jwks_path,
            scenario="required-one-of-pass",
        )

        policy_vector = issuer_vectors["standard-p256"]
        policy_claims = policy_vector["issuer_claims"]
        run_issuer(
            args.binary, temporary, "binding-mismatch", b"B", policy_vector, issuer_jwks_path,
            commitment="_" * 42 + "8",
        )
        run_issuer(
            args.binary, temporary, "audience-mismatch", b"C", policy_vector, issuer_jwks_path,
            scenario="wrong-audience",
        )
        run_issuer(
            args.binary, temporary, "authorized-party-mismatch", b"C", policy_vector,
            issuer_jwks_path, scenario="wrong-authorized-party",
        )
        run_issuer(
            args.binary, temporary, "issuer-mismatch", b"C", policy_vector, issuer_jwks_path,
            scenario="wrong-issuer",
        )
        run_issuer(
            args.binary, temporary, "not-yet-valid", b"N", policy_vector, issuer_jwks_path,
            verification_time=policy_claims["iat"] - 31,
        )
        run_issuer(
            args.binary, temporary, "expired", b"X", policy_vector, issuer_jwks_path,
            verification_time=policy_claims["exp"] + 30,
        )
        run_issuer(
            args.binary, temporary, "maximum-age", b"X", policy_vector, issuer_jwks_path,
            scenario="maximum-age",
        )
        run_issuer(
            args.binary, temporary, "required-claim", b"C", policy_vector, issuer_jwks_path,
            scenario="required-claim-wrong",
        )
        run_issuer(
            args.binary, temporary, "required-array", b"C", policy_vector, issuer_jwks_path,
            scenario="required-array-contains-wrong",
        )
        run_issuer(
            args.binary, temporary, "non-reconstructible", b"R", policy_vector,
            issuer_jwks_path, scenario="non-reconstructible",
        )
        run_issuer(
            args.binary, temporary, "disallowed-binding", b"R", policy_vector,
            issuer_jwks_path, scenario="disallowed-binding",
        )

        standard_token = json.loads(policy_vector["token"])
        original_evidence = b64url(standard_token["credbind_evidence"])
        original_header, original_signature = split_standard_evidence(original_evidence)
        bad_signature_text = ("A" if original_signature[0] != "A" else "B") + original_signature[1:]
        run_issuer(
            args.binary, temporary, "signature-substitution", b"S", policy_vector,
            issuer_jwks_path, evidence=standard_evidence(original_header, bad_signature_text),
        )

        header_object = json.loads(b64url(original_header))
        for name, mode, mutation in (
            ("unknown-kid", b"U", {"kid": "missing-key-id"}),
            ("remote-key-reference", b"U", {"jku": "https://attacker.example/jwks"}),
            ("critical-header", b"R", {"crit": ["unknown"]}),
            ("algorithm-substitution", b"A", {"alg": "PS256"}),
        ):
            changed = dict(header_object)
            changed.update(mutation)
            encoded = encode_b64url(json.dumps(changed, separators=(",", ":")).encode("utf-8"))
            run_issuer(
                args.binary, temporary, name, mode, policy_vector, issuer_jwks_path,
                evidence=standard_evidence(encoded, original_signature),
            )
        header_with_structured_empty_member = dict(header_object)
        header_with_structured_empty_member[""] = {"nested": [None, True, 3]}
        encoded_structured_header = encode_b64url(
            json.dumps(
                header_with_structured_empty_member, separators=(",", ":")
            ).encode("utf-8")
        )
        run_issuer(
            args.binary, temporary, "structured-empty-header-member", b"S",
            policy_vector, issuer_jwks_path,
            evidence=standard_evidence(encoded_structured_header, original_signature),
        )
        malformed_header = encode_b64url(b"{")
        run_issuer(
            args.binary, temporary, "malformed-header", b"M", policy_vector, issuer_jwks_path,
            evidence=standard_evidence(malformed_header, original_signature),
        )
        payload_json = b64url(standard_token["payload"]).decode("utf-8")
        duplicate_payload = encode_b64url(
            ('{"iss":"duplicate",' + payload_json[1:]).encode("utf-8")
        )
        run_issuer(
            args.binary, temporary, "duplicate-payload-member", b"M", policy_vector,
            issuer_jwks_path, payload=duplicate_payload,
        )
        run_issuer(
            args.binary, temporary, "gq-commitment-mismatch", b"E",
            issuer_vectors["gq-p256"], issuer_jwks_path, commitment="_" * 42 + "8",
        )
        gq_token = json.loads(issuer_vectors["gq-p256"]["token"])
        gq_evidence = b64url(gq_token["credbind_evidence"])
        gq_header_length = int.from_bytes(gq_evidence[:8], "big")
        malformed_gq_header = encode_b64url(b"{").encode("ascii")
        malformed_gq_evidence = (
            struct.pack(">Q", len(malformed_gq_header))
            + malformed_gq_header
            + gq_evidence[8 + gq_header_length :]
        )
        run_issuer(
            args.binary, temporary, "gq-malformed-header", b"E",
            issuer_vectors["gq-p256"], issuer_jwks_path,
            evidence=malformed_gq_evidence,
        )

        modulus = b64url(issuer_key["n"])
        exponent = int.from_bytes(b64url(issuer_key["e"]), "big").to_bytes(4, "big")

        standard = load(corpus / "vectors" / "standard-p256.json")
        protected, payload, signature = standard["acquired_credential"].split(".")
        signing_input = f"{protected}.{payload}".encode("ascii")
        signature_bytes = b64url(signature)
        run_crypto(
            args.binary,
            temporary,
            "standard-pass",
            crypto_frame(b"S", signing_input, signature_bytes, modulus, exponent),
        )
        bad_signature = bytes([signature_bytes[0] ^ 1]) + signature_bytes[1:]
        run_crypto(
            args.binary,
            temporary,
            "standard-signature-substitution",
            crypto_frame(b"s", signing_input, bad_signature, modulus, exponent),
        )
        bad_signing_input = bytes([signing_input[0] ^ 1]) + signing_input[1:]
        run_crypto(
            args.binary,
            temporary,
            "standard-signing-input-substitution",
            crypto_frame(b"s", bad_signing_input, signature_bytes, modulus, exponent),
        )
        run_crypto(
            args.binary,
            temporary,
            "standard-wrong-exponent",
            crypto_frame(
                b"s", signing_input, signature_bytes, modulus, (3).to_bytes(4, "big")
            ),
        )
        undersized = modulus[:128]
        run_crypto(
            args.binary,
            temporary,
            "standard-undersized-modulus",
            crypto_frame(b"s", signing_input, signature_bytes, undersized, exponent),
        )

        gq = load(corpus / "vectors" / "gq-p256.json")
        gq_token = json.loads(gq["token"])
        evidence = b64url(gq_token["credbind_evidence"])

        def gq_case(
            name: str,
            *,
            mode: bytes = b"g",
            encoded_payload: str = gq_token["payload"],
            commitment: str = gq["expected_commitment"],
            issuer: str = gq["authenticated_issuer"],
            proof: bytes = evidence,
            n: bytes = modulus,
            e: bytes = exponent,
        ) -> None:
            run_crypto(
                args.binary,
                temporary,
                name,
                crypto_frame(
                    mode,
                    encoded_payload.encode("ascii"),
                    commitment.encode("ascii"),
                    issuer.encode("utf-8"),
                    proof,
                    n,
                    e,
                ),
            )

        gq_case("gq-pass", mode=b"G")
        gq_case("gq-truncated", proof=evidence[:-1])
        gq_case("gq-trailing", proof=evidence + b"\x00")
        header_length = int.from_bytes(evidence[:8], "big")
        count_offset = 8 + header_length
        wrong_count = bytearray(evidence)
        wrong_count[count_offset : count_offset + 4] = struct.pack(">I", 7)
        gq_case("gq-wrong-round-count", proof=bytes(wrong_count))

        first_length_offset = count_offset + 4
        first_length = int.from_bytes(evidence[first_length_offset : first_length_offset + 8], "big")
        first_offset = first_length_offset + 8
        response_length_offset = first_offset + first_length
        response_length = int.from_bytes(
            evidence[response_length_offset : response_length_offset + 8], "big"
        )
        response_offset = response_length_offset + 8
        leading_zero = (
            evidence[:first_length_offset]
            + struct.pack(">Q", first_length + 1)
            + b"\x00"
            + evidence[first_offset:]
        )
        gq_case("gq-leading-zero", proof=leading_zero)
        response_substitution = bytearray(evidence)
        response_substitution[response_offset + response_length - 1] ^= 1
        gq_case("gq-response-substitution", proof=bytes(response_substitution))

        second_length_offset = response_offset + response_length
        second_length = int.from_bytes(
            evidence[second_length_offset : second_length_offset + 8], "big"
        )
        second_offset = second_length_offset + 8
        if first_length != second_length:
            raise RuntimeError("pinned GQ commitment lengths differ")
        reordered = bytearray(evidence)
        first_value = reordered[first_offset : first_offset + first_length]
        reordered[first_offset : first_offset + first_length] = reordered[
            second_offset : second_offset + second_length
        ]
        reordered[second_offset : second_offset + second_length] = first_value
        gq_case("gq-reordered-commitments", proof=bytes(reordered))

        header_substitution = bytearray(evidence)
        header_substitution[8] = ord("f")
        gq_case("gq-header-substitution", proof=bytes(header_substitution))
        workload = load(corpus / "vectors" / "workload-audience-p256.json")
        workload_payload = json.loads(workload["token"])["payload"]
        gq_case("gq-payload-substitution", encoded_payload=workload_payload)
        gq_case("gq-commitment-substitution", commitment="_" * 42 + "8")
        gq_case("gq-issuer-substitution", issuer="https://other-issuer.example.test")
        gq_case("gq-wrong-exponent", e=(3).to_bytes(4, "big"))
        gq_case("gq-undersized-modulus", n=undersized)

    print(json.dumps({
        "certificates": 2,
        "compact_jws": 5,
        "core_tokens": 5,
        "direct_carrier_negative": direct_negative,
        "direct_carrier_positive": direct_positive,
        "gq_negative": 12,
        "gq_positive": 1,
        "jwks_negative": 12,
        "jwks_positive": 1,
        "issuer_negative": 21,
        "issuer_positive": 6,
        "standard_negative": 4,
        "standard_positive": 1,
        "status": "verified",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
