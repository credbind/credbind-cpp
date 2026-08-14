#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise implemented C++ parsers against the immutable RC corpus."""

from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = (
    ROOT / ".cache" / "conformance" / "v1.0.0-rc.1" / "corpus"
    / "credbind-ssh-v1-conformance-v1.0.0-rc.1"
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
        undersized = (int.from_bytes(modulus, "big") >> 1024).to_bytes(128, "big")
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
        "gq_negative": 12,
        "gq_positive": 1,
        "standard_negative": 4,
        "standard_positive": 1,
        "status": "verified",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
