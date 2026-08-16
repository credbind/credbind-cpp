#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Interpret every pinned shared case into a C++ result or owned disposition."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORPUS = (
    ROOT / ".cache/conformance/v1.0.0-rc.2/corpus"
    / "credbind-ssh-v1-conformance-v1.0.0-rc.2"
)


def load_helpers():
    path = ROOT / "tests/fixtures/parser_vectors_test.py"
    spec = importlib.util.spec_from_file_location("credbind_parser_vectors", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load C++ fixture operations")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PV = load_helpers()


DISPOSITIONS = {
    # The C++ language plan is an offline verifier-only implementation. It has
    # no acquisition/helper, browser, callback, client-certificate creation or
    # OIDC-discovery/cache capability.
    "negative-interactive-access-token-substitution": "go-acquisition-only",
    "negative-interactive-userinfo-substitution": "go-acquisition-only",
    "provider-helper-cancelled": "go-acquisition-helper-only",
    "provider-helper-duplicate-status": "go-acquisition-helper-only",
    "provider-helper-extra-success-member": "go-acquisition-helper-only",
    "provider-helper-failure": "go-acquisition-helper-only",
    "provider-helper-malformed-jws": "go-acquisition-helper-only",
    "provider-helper-native-request": "go-acquisition-helper-only",
    "provider-helper-success": "go-acquisition-helper-only",
    "provider-helper-unaccepted-pair": "go-acquisition-helper-only",
    "provider-helper-unknown-error": "go-acquisition-helper-only",
    "provider-helper-workload-claim-request": "go-acquisition-helper-only",
    "provider-helper-workload-request": "go-acquisition-helper-only",
    "deadline-go-discovery-cache-charged": "go-oidc-discovery-only",
    "validity-client-policy-tightening": "go-client-identity-creation-only",
    "validity-fixed-30s-backdate": "go-client-identity-creation-only",
    "confidential-web-deterministic-pkce-required": "go-acquisition-only",
    "loopback-lifetime-bounds": "go-acquisition-only",
}

ADAPTER_CASES = {
    "cpp-rejects-oidc-discovery-config",
    "deadline-vs-operation-cancelled-precedence",
    "operation-cancelled-before-deadline",
    "ssh-deny-empty-stdout-zero-exit",
    "deadline-cumulative-two-phase-no-reset",
    "deadline-exact-boundary-empty-stdout",
    "audit-event-go-cpp-equivalence",
}

RESOURCE_CASES = {
    "resource-limit-just-over-authorized_keys_output_chars",
    "resource-limit-just-over-evidence_bytes",
    "resource-limit-just-over-offered_key_chars",
    "resource-limit-just-over-ssh_certificate_bytes",
    "resource-limit-just-over-token_bytes",
}


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def invoke_adapter(binary: Path, case_id: str, *arguments: str,
                   audit_observable: Path | None = None) -> None:
    environment = dict(os.environ)
    environment["CREDBIND_CONFORMANCE_CASE"] = case_id
    if audit_observable is not None:
        environment["CREDBIND_AUDIT_OBSERVABLE"] = str(audit_observable)
    result = subprocess.run(
        [str(binary), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=environment, check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        if len(detail) > 2048:
            detail = detail[:2048] + "..."
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"C++ adapter assertion failed for {case_id}{suffix}"
        )


def flip_text(text: str) -> str:
    return ("A" if text[0] != "A" else "B") + text[1:]


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def claims_frame(mode: bytes, vector: dict, claims: dict) -> bytes:
    audience = vector["issuer_claims"]["aud"]
    if isinstance(audience, list):
        audience = audience[0]
    return PV.crypto_frame(
        mode,
        vector["binding_profile"].encode("ascii"),
        vector["expected_commitment"].encode("ascii"),
        vector["authenticated_issuer"].encode("utf-8"),
        audience.encode("utf-8"),
        vector["issuer_claims"].get("azp", "").encode("utf-8"),
        str(vector["verification_time"]).encode("ascii"),
        json.dumps(claims, separators=(",", ":")).encode("utf-8"),
    )


def run_claims(binary: Path, temporary: Path, case: dict, vector: dict) -> None:
    # Prove the published base credential at the cryptographic issuer boundary
    # before using the post-authentication seam for a mutation that requires a
    # re-signing key intentionally excluded from the artifact.
    PV.run_issuer(
        binary, temporary, case["id"] + "-base-authenticated", b"P", vector,
        CORPUS / "keys/issuer-jwks.json",
    )
    claims = json.loads(json.dumps(vector["issuer_claims"]))
    mutation = case["inputs"].get("mutation")
    if mutation:
        claim = mutation["claim"]
        if mutation["type"] == "delete-authenticated-claim":
            claims.pop(claim, None)
        else:
            claims[claim] = mutation["value"]
    mode = b"P" if case["expected"]["result"] == "pass" else b"B"
    frame = temporary / f"claims-{case['id']}.frame"
    frame.write_bytes(claims_frame(mode, vector, claims))
    PV.invoke(binary, "--claims-file", str(frame))


def run_direct_token(binary: Path, temporary: Path, case_id: str, vector: dict,
                     mode: bytes, token: str | None = None) -> None:
    PV.run_direct_token(
        binary, temporary, case_id, mode, vector,
        CORPUS / "keys/issuer-jwks.json", token=token,
    )


def mutate_cic(vector: dict, algorithm: str) -> str:
    token = json.loads(vector["token"])
    header = json.loads(PV.b64url(token["signatures"][0]["protected"]))
    header["alg"] = algorithm
    token["signatures"][0]["protected"] = encoded(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    return json.dumps(token, separators=(",", ":"))


def carrier_frame(vector: dict, carrier: dict, mode: bytes = b"P", **kwargs) -> bytes:
    return PV.direct_carrier_frame(
        mode,
        base64.b64decode(carrier["certificate_blob_base64"], validate=True),
        carrier,
        vector,
        CORPUS / "keys/issuer-jwks.json",
        **kwargs,
    )


def run_gq(binary: Path, temporary: Path, case: dict, vector: dict) -> None:
    token = json.loads(vector["token"])
    proof = PV.b64url(token["credbind_evidence"])
    key = load(CORPUS / "keys/issuer-jwks.json")["keys"][0]
    modulus = PV.b64url(key["n"])
    exponent = int.from_bytes(PV.b64url(key["e"]), "big").to_bytes(4, "big")
    payload = token["payload"]
    commitment = vector["expected_commitment"]
    issuer = vector["authenticated_issuer"]
    mutation = case["inputs"].get("mutation", {})
    kind = mutation.get("type")
    if kind == "truncate-decoded-evidence":
        proof = proof[:-mutation["octets"]]
    elif kind == "append-decoded-evidence":
        proof += bytes.fromhex(mutation["value_hex"])
    elif kind == "replace-gq-round-count":
        header_length = int.from_bytes(proof[:8], "big")
        offset = 8 + header_length
        changed = bytearray(proof)
        changed[offset:offset + 4] = struct.pack(">I", mutation["value"])
        proof = bytes(changed)
    elif kind in {"prefix-gq-integer-zero", "flip-gq-integer-octet",
                  "swap-gq-round-field"}:
        header_length = int.from_bytes(proof[:8], "big")
        first_length_offset = 8 + header_length + 4
        first_length = int.from_bytes(proof[first_length_offset:first_length_offset + 8], "big")
        first_offset = first_length_offset + 8
        response_length_offset = first_offset + first_length
        response_length = int.from_bytes(
            proof[response_length_offset:response_length_offset + 8], "big")
        response_offset = response_length_offset + 8
        if kind == "prefix-gq-integer-zero":
            proof = (proof[:first_length_offset] + struct.pack(">Q", first_length + 1)
                     + b"\0" + proof[first_offset:])
        elif kind == "flip-gq-integer-octet":
            changed = bytearray(proof)
            changed[response_offset + response_length - 1] ^= 1
            proof = bytes(changed)
        else:
            second_length_offset = response_offset + response_length
            second_length = int.from_bytes(
                proof[second_length_offset:second_length_offset + 8], "big")
            second_offset = second_length_offset + 8
            if first_length != second_length:
                raise RuntimeError("pinned GQ commitment lengths differ")
            changed = bytearray(proof)
            first = changed[first_offset:first_offset + first_length]
            changed[first_offset:first_offset + first_length] = changed[
                second_offset:second_offset + second_length]
            changed[second_offset:second_offset + second_length] = first
            proof = bytes(changed)
    elif kind == "flip-gq-header-octet":
        changed = bytearray(proof)
        changed[8 + mutation["index"]] ^= 1
        proof = bytes(changed)
    elif kind == "replace-token-payload":
        payload = json.loads(load(CORPUS / mutation["source"])["token"])["payload"]
    elif kind == "replace-authenticated-binding":
        commitment = mutation["value"]
    elif kind == "replace-trusted-issuer":
        issuer = mutation["value"]
    elif kind == "replace-trusted-rsa-exponent":
        exponent = int(mutation["value"]).to_bytes(4, "big")
    elif kind == "replace-trusted-rsa-modulus":
        modulus = (int.from_bytes(modulus, "big") >> (len(modulus) * 8 - mutation["bits"])).to_bytes(
            mutation["bits"] // 8, "big")
    elif kind is not None:
        raise RuntimeError(f"unhandled GQ mutation {kind}")
    mode = b"G" if case["expected"]["result"] == "pass" else b"g"
    frame = PV.crypto_frame(
        mode, payload.encode("ascii"), commitment.encode("ascii"), issuer.encode("utf-8"),
        proof, modulus, exponent,
    )
    PV.run_crypto(binary, temporary, case["id"], frame)


def run_static_invalid(binary: Path, temporary: Path) -> None:
    path = CORPUS / "keys/issuer-jwks.json"
    jwks = load(path)
    key = jwks["keys"][0]
    candidates: list[Path] = []
    link = temporary / "jwks-link.json"
    link.symlink_to(path)
    candidates.append(link)
    group = temporary / "jwks-group.json"
    group.write_text(json.dumps(jwks), encoding="utf-8")
    group.chmod(0o660)
    candidates.append(group)
    duplicate = temporary / "jwks-duplicate.json"
    duplicate.write_text(json.dumps({"keys": [key, key]}), encoding="utf-8")
    candidates.append(duplicate)
    private = dict(key)
    private["d"] = "AA"
    private_path = temporary / "jwks-private.json"
    private_path.write_text(json.dumps({"keys": [private]}), encoding="utf-8")
    candidates.append(private_path)
    trailing = temporary / "jwks-trailing.json"
    trailing.write_text(json.dumps(jwks) + " []", encoding="utf-8")
    candidates.append(trailing)
    for candidate in candidates:
        PV.run_jwks(binary, "untrusted", candidate, key["kid"])


def run_case(binary: Path, adapter: Path, temporary: Path, case: dict,
             vectors: dict, carriers: dict) -> None:
    case_id = case["id"]
    if case_id in ADAPTER_CASES:
        return
    if case_id in {"algo-p256-default-pass", "core-standard-oidc-nonce-pass"}:
        run_direct_token(binary, temporary, case_id, vectors["standard-p256"], b"P")
    elif case_id == "algo-ed25519-optional-pass":
        run_direct_token(binary, temporary, case_id, vectors["standard-ed25519"], b"P")
    elif case_id == "algo-rsa-caller-or-ssh-suite-rejected":
        vector = vectors["standard-p256"]
        run_direct_token(binary, temporary, case_id, vector, b"A", mutate_cic(vector, "RS256"))
    elif case_id in {"cross-language-go-carrier-cpp-verify",
                     "ssh-carrier-principal-policy-pass"}:
        PV.run_direct_carrier(
            binary, temporary, case_id,
            carrier_frame(vectors["standard-p256"], carriers["p256"]),
        )
    elif case_id == "fresh-public-test-keys-only":
        declared = [CORPUS / item for item in case["inputs"]["public_keys"]]
        if not all(item.is_file() for item in declared):
            raise RuntimeError("declared public key is absent")
        forbidden = [p for p in CORPUS.rglob("*") if p.is_file() and "private" in p.name.lower()]
        if case["inputs"]["private_keys_in_artifact"] != 0 or forbidden:
            raise RuntimeError("private key present in release artifact")
    elif case_id in {"malformed-duplicate-top-level-payload", "malformed-padded-payload",
                     "negative-caller-signature-substitution"}:
        vector = vectors["standard-p256"]
        token = json.loads(vector["token"])
        mode = b"M"
        if case_id == "malformed-duplicate-top-level-payload":
            raw = vector["token"]
            token_text = "{\"payload\":" + json.dumps(token["payload"]) + "," + raw[1:]
        elif case_id == "malformed-padded-payload":
            token["payload"] += "="
            token_text = json.dumps(token, separators=(",", ":"))
        else:
            token["signatures"][0]["signature"] = flip_text(
                token["signatures"][0]["signature"])
            token_text = json.dumps(token, separators=(",", ":"))
            mode = b"Q"
        run_direct_token(binary, temporary, case_id, vector, mode, token_text)
    elif case_id == "negative-evidence-result-digest-mismatch":
        run_direct_token(binary, temporary, case_id + "-base", vectors["standard-p256"], b"P")
        PV.invoke(binary, "--digest-mismatch")
    elif case_id.startswith("negative-oidc-nonce-") or case_id.startswith("workload-"):
        vector_name = Path(case["inputs"]["base_vector"]).stem
        run_claims(binary, temporary, case, vectors[vector_name])
    elif case_id == "negative-standard-evidence-signature-substitution":
        vector = vectors["standard-p256"]
        token = json.loads(vector["token"])
        evidence = PV.b64url(token["credbind_evidence"])
        header, signature = PV.split_standard_evidence(evidence)
        PV.run_issuer(
            binary, temporary, case_id, b"S", vector, CORPUS / "keys/issuer-jwks.json",
            evidence=PV.standard_evidence(header, flip_text(signature)),
        )
    elif case["kind"] == "resource-limit":
        name = case["inputs"]["limit"]
        maximum = str(case["inputs"]["configured_maximum"])
        size = str(case["inputs"]["input_size"])
        if name in {"offered_key_chars", "authorized_keys_output_chars"}:
            PV.invoke(adapter, "--size-bound", maximum, size)
        else:
            PV.invoke(binary, "--resource-limit", name, maximum, size)
    elif case_id == "static-jwks-file-pass":
        key = load(CORPUS / "keys/issuer-jwks.json")["keys"][0]
        PV.run_jwks(binary, "pass", CORPUS / "keys/issuer-jwks.json", key["kid"])
    elif case_id == "static-jwks-unsafe-or-invalid-deny":
        run_static_invalid(binary, temporary)
    elif case["kind"] == "gq-verification":
        run_gq(binary, temporary, case, vectors["gq-p256"])
    elif case_id == "validity-credential-derived-pass":
        PV.run_direct_carrier(
            binary, temporary, case_id,
            carrier_frame(vectors["standard-p256"], carriers["p256"]),
        )
    elif case_id == "validity-clock-boundary":
        vector = vectors["standard-p256"]
        PV.run_issuer(
            binary, temporary, case_id, b"X", vector, CORPUS / "keys/issuer-jwks.json",
            verification_time=vector["issuer_claims"]["exp"] + 30,
        )
    else:
        raise RuntimeError(f"unhandled applicable case {case_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("adapter_binary", type=Path)
    args = parser.parse_args()
    manifest = load(CORPUS / "MANIFEST.json")
    cases = [load(path) for path in sorted((CORPUS / "cases").glob("*/*.json"))]
    if len(cases) != 72 or len(manifest.get("cases", [])) != 72:
        raise RuntimeError("pinned corpus does not contain exactly 72 cases")
    ids = [case["id"] for case in cases]
    if len(set(ids)) != len(ids):
        raise RuntimeError("duplicate conformance case identifier")

    vectors = {
        path.stem: load(path) for path in (CORPUS / "vectors").glob("*.json")
        if not path.stem.startswith("ssh-carrier-")
    }
    carriers = {
        name: load(CORPUS / f"vectors/ssh-carrier-{name}.json")
        for name in ("p256", "ed25519")
    }

    # Select each adapter case independently. The C++ test process refuses a
    # selector unless the corresponding exact production-boundary assertion
    # actually executed.
    audit_payload = ""
    audit_severity = ""
    with tempfile.TemporaryDirectory(prefix="credbind-cpp-observables-") as directory:
        observable = Path(directory) / "audit.txt"
        for case_id in sorted(ADAPTER_CASES | RESOURCE_CASES):
            invoke_adapter(
                args.adapter_binary, case_id,
                str(ROOT / "tests/fixtures/issuer-jwks.json"),
                str(CORPUS / "vectors/ssh-carrier-p256.json"),
                str(CORPUS / "keys/issuer-jwks.json"),
                audit_observable=(observable if case_id == "audit-event-go-cpp-equivalence" else None),
            )
        lines = observable.read_text(encoding="utf-8").splitlines()
        if len(lines) != 2:
            raise RuntimeError("C++ audit observable is incomplete")
        audit_payload, audit_severity = lines

    results = []
    with tempfile.TemporaryDirectory(prefix="credbind-conformance-") as directory:
        temporary = Path(directory)
        for case in cases:
            case_id = case["id"]
            if case_id in DISPOSITIONS:
                results.append({
                    "id": case_id,
                    "applicability": "not-applicable",
                    "disposition": DISPOSITIONS[case_id],
                })
                continue
            run_case(args.binary, args.adapter_binary, temporary, case, vectors, carriers)
            observed = {
                "id": case_id,
                "applicability": "applicable",
                "comparison": "cpp-operation-matched-pinned-expected",
                "result": case["expected"]["result"],
                "category": case["expected"].get("category"),
            }
            if "exit_status" in case["expected"]:
                observed["exit_status"] = case["expected"]["exit_status"]
            if "stdout_octets" in case["expected"]:
                observed["stdout_octets"] = case["expected"]["stdout_octets"]
            if case_id == "audit-event-go-cpp-equivalence":
                observed["audit_payload"] = audit_payload
                observed["audit_severity"] = audit_severity
                observed["cross_language_comparison"] = "pending-shared-comparator"
            results.append(observed)

    applicable = sum(item["applicability"] == "applicable" for item in results)
    dispositioned = len(results) - applicable
    report = {
        "artifact_sha256": hashlib.sha256(
            (ROOT / ".cache/conformance/v1.0.0-rc.2/credbind-ssh-v1-conformance-v1.0.0-rc.2.tar.gz").read_bytes()
        ).hexdigest(),
        "manifest_sha256": hashlib.sha256(
            (CORPUS / "MANIFEST.json").read_bytes()
        ).hexdigest(),
        "implementation": "cpp",
        "release": "v1.0.0-rc.2",
        "cases": results,
        "summary": {"applicable": applicable, "dispositioned": dispositioned, "total": 72},
        "status": "cpp-applicable-observables-verified",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
