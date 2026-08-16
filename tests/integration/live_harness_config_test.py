#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline contract checks for the external live-workload harness."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "integration" / "openssh_authorized_keys_test.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def load_harness():
    specification = importlib.util.spec_from_file_location("credbind_live_harness", HARNESS)
    require(specification is not None and specification.loader is not None,
            "cannot load live harness")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def descriptor(evidence: str) -> dict[str, object]:
    return {
        "certificate_blob_base64": "AAAA",
        "key_type_argument": "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "requested_user": "fixture-user",
        "issuer": "https://issuer.example.test/",
        "jwks_path": "unused",
        "audience": "live-test-audience",
        "authorized_party": "live-test-client",
        "verification_time": 1_900_000_000,
        "principal_claim": "sub",
        "caller_algorithms": ["ES256"],
        "evidence_profiles": [evidence],
        "binding_profiles": ["credbind-claim-v1"],
        "acquisition_profiles": ["challenge-bound-workload-v1"],
        "admitted_claims": ["sub"],
        "account_rule": {
            "issuer": "https://issuer.example.test/",
            "claim": "sub",
            "value": "fixture-subject",
            "allowed_certificate_extensions": ["permit-pty"],
        },
        "maximum_identity_lifetime_seconds": 60,
        "clock_skew_seconds": 30,
        "require_non_reconstructible_evidence": evidence == "gq-rs256-v1",
        "expected": {
            "principal": "unused",
            "ca_key_type": "ecdsa-sha2-nistp256",
            "ca_public_key_base64": "AAAA",
        },
    }


def live_report() -> dict[str, object]:
    return {
        "version": 1,
        "cell": "G-WORKLOAD-STD",
        "provider": "google",
        "registry_release": "v1.0.0",
        "registry_entry_sha256": "1" * 64,
        "issuer": "https://accounts.google.com",
        "source_profile": "google-iam-service-account-id-token-v1",
        "acquisition_profile": "challenge-bound-workload-v1",
        "binding_profile": "audience-v1",
        "evidence_profile": "standard-jws-v1",
        "caller_algorithm": "ES256",
        "issuer_algorithm": "RS256",
        "issuer_key_bits": 2048,
        "issuer_exponent": 65537,
        "issuer_jwk_canonical_sha256": "2" * 64,
        "commitment_characters": 43,
        "credential_valid_until": 1_900_000_000,
        "certificate_valid_after": 1_899_999_970,
        "certificate_valid_before": 1_900_000_000,
        "token_bytes": 1000,
        "evidence_bytes": 500,
        "certificate_bytes": 1500,
        "offered_key_characters": 2000,
        "go_verification_microseconds": 100,
        "expired_credential_denied": True,
        "unavailable_issuer_key_denied": True,
        "sanitized_request_fields": ["audience"],
    }


def main() -> int:
    require(len(sys.argv) == 3, "usage: live_harness_config_test.py BINARY JWKS")
    binary = pathlib.Path(sys.argv[1]).resolve()
    jwks = pathlib.Path(sys.argv[2]).resolve()
    require(binary.is_file() and jwks.is_file(), "offline harness inputs are unavailable")
    harness = load_harness()
    with tempfile.TemporaryDirectory(prefix="credbind-live-harness-") as temporary:
        root = pathlib.Path(temporary)
        os.chmod(root, 0o700)
        evidence = root / "evidence.json"
        harness.validate_evidence_output(evidence)
        evidence.write_text("occupied", encoding="utf-8")
        try:
            harness.validate_evidence_output(evidence)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("live evidence output accepted overwrite")
        evidence.unlink()

        report = live_report()
        require(harness.validate_live_report(report, "G-WORKLOAD-STD") is report,
                "sanitized live report was rejected")
        report["credential"] = "must-not-publish"
        try:
            harness.validate_live_report(report, "G-WORKLOAD-STD")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("live report accepted an unexpected credential field")

        for profile in ("standard-jws-v1", "gq-rs256-v1"):
            config = harness.verifier_config(descriptor(profile), jwks)
            decoded = json.loads(config)
            policy = decoded["trusted_issuers"][0]
            require(
                policy["acquisition_profiles"] == ["challenge-bound-workload-v1"]
                and policy["authorized_parties"] == ["live-test-client"]
                and policy["maximum_identity_lifetime"] == "60s"
                and policy["require_non_reconstructible_evidence"]
                == (profile == "gq-rs256-v1"),
                "live policy projection is not exact",
            )
            path = root / f"{profile}.json"
            harness.write_private(path, config)
            checked = subprocess.run(
                [str(binary), "config", "check", "--config", str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
            )
            require(
                (checked.returncode, checked.stdout, checked.stderr)
                == (0, b"configuration valid\n", b""),
                f"live {profile} policy projection was rejected",
            )
    print(json.dumps({"live_harness_profiles": 2, "status": "verified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
