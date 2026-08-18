#!/usr/bin/env python3
"""Semantic tests for the specified C++ command adapter surface."""

from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile


def invoke(binary: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([binary, *arguments], check=False, capture_output=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


HELP_TOPICS = (
    ((), (b"credbind-ssh-authorized-keys", b"config", b"verify")),
    (("version",), (b"credbind-ssh-authorized-keys version",)),
    (("config",), (b"config init", b"config check")),
    (("config", "init"), (b"config init", b"--policy-input", b"--deny-all")),
    (("config", "check"), (b"config check", b"--config")),
    (("sshd-config",), (b"sshd-config render",)),
    (("sshd-config", "render"), (b"sshd-config render", b"--command-user")),
    (("verify",), (b"verify", b"--key-type")),
)


def sample_config() -> bytes:
    value = {
        "version": 1,
        "clock_skew": "0s",
        "total_verification_deadline": "5s",
        "resource_limits": {
            "max_token_bytes": 32768,
            "max_evidence_bytes": 16384,
            "max_ssh_certificate_bytes": 49152,
            "max_offered_key_chars": 65536,
            "max_authorized_keys_output_chars": 4096,
        },
        "trusted_issuers": [],
        "accounts": {},
        "logging": {"facility": "local2"},
    }
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def deny_all_config(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "version": 1,
        "clock_skew": "30s",
        "total_verification_deadline": "5s",
        "resource_limits": {
            "max_token_bytes": 32768,
            "max_evidence_bytes": 16384,
            "max_ssh_certificate_bytes": 49152,
            "max_offered_key_chars": 65536,
            "max_authorized_keys_output_chars": 4096,
        },
        "issuer_key_cache": {
            "directory": "/var/cache/credbind/ssh-verifier/v1",
            "maximum_freshness": "336h",
        },
        "trusted_issuers": [],
        "accounts": {},
        "logging": {"facility": "authpriv"},
    }
    value.update(overrides)
    return (json.dumps(value, indent=2) + "\n").encode()


def policy_input(jwks: pathlib.Path) -> bytes:
    value = {
        "trusted_issuers": [{
            "policy_id": "fixture",
            "issuer": "https://issuer.example.test",
            "key_source": {"type": "static-jwks-file", "path": str(jwks)},
            "audiences": ["credbind-fixture-client"],
            "issuer_algorithms": ["RS256"],
            "caller_algorithms": ["ES256"],
            "evidence_profiles": ["standard-jws-v1"],
            "binding_profiles": ["oidc-nonce-v1"],
            "acquisition_profiles": ["oidc-native-auth-code-v1"],
            "require_non_reconstructible_evidence": False,
            "certificate_principal_claim": "sub",
        }],
        "accounts": {
            "alice": {"allow": [{
                "issuer": "https://issuer.example.test",
                "all": [{"claim": "group", "type": "string", "op": "equals",
                         "value": "ops"}],
                "allowed_certificate_extensions": ["permit-pty"],
            }]},
        },
    }
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def main() -> int:
    binary = pathlib.Path(sys.argv[1]).resolve()
    jwks = pathlib.Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="credbind-cli-") as temporary:
        root = pathlib.Path(temporary)
        config = root / "verifier.json"
        config.write_bytes(sample_config())
        config.chmod(0o600)

        for prefix, required_terms in HELP_TOPICS:
            for help_flag in ("-h", "--help"):
                result = invoke(binary, *prefix, help_flag)
                require(result.returncode == 0 and result.stdout.endswith(b"\n") and
                        result.stderr == b"" and
                        all(term in result.stdout for term in required_terms),
                        f"semantic side-effect-free help for {prefix!r} {help_flag}")

        result = invoke(binary, "config", "check", "--config", str(config))
        require((result.returncode, result.stdout, result.stderr) ==
                (0, b"configuration valid\n", b""), "config check exact success")

        bad = root / "bad.json"
        bad.write_bytes(b'{"version":1,"version":1}\n')
        bad.chmod(0o600)
        result = invoke(binary, "config", "check", "--config", str(bad))
        require(result.returncode != 0 and result.stdout == b"" and
                result.stderr == b"malformed_input\n", "config check safe failure")

        result = invoke(binary, "sshd-config", "render", "--config", str(config),
                        "--verifier", str(binary), "--command-user", "credbind")
        expected = (f"AuthorizedKeysCommand {binary} verify --config {config} "
                    "--user %u --key %k --key-type %t\n"
                    "AuthorizedKeysCommandUser credbind\n").encode()
        require((result.returncode, result.stdout, result.stderr) == (0, expected, b""),
                "render exact output")

        result = invoke(binary, "sshd-config", "render", "--config", str(config),
                        "--verifier", str(binary), "--command-user", "bad user")
        require(result.returncode != 0 and result.stdout == b"" and
                result.stderr == b"malformed_input\n", "render injection rejected")

        result = invoke(binary, "verify", "--config", str(config), "--user", "alice",
                        "--key", "AAAA", "--key-type",
                        "ssh-ed25519-cert-v01@openssh.com")
        require((result.returncode, result.stdout, result.stderr) == (0, b"", b""),
                "verify denial exact observable contract")

        result = invoke(binary, "verify", "--key", "bearer-canary")
        require((result.returncode, result.stdout, result.stderr) == (0, b"", b""),
                "malformed verify never discloses arguments")

        for arguments in (("config", "init"),
                          ("config", "init", "--issuer", "https://example.test"),
                          ("config", "init", "--deny-all", "--deny-all"),
                          ("config", "init", "--deny-all", "--force"),
                          ("config", "init", "--deny-all", "--clock-skew", "030s"),
                          ("config", "init", "--deny-all", "--clock-skew", "31s"),
                          ("config", "init", "--deny-all",
                           "--total-verification-deadline", "0s")):
            result = invoke(binary, *arguments)
            require(result.returncode != 0 and result.stdout == b"" and
                    b"bearer" not in result.stderr,
                    "invalid initializer remains fail closed")

        result = invoke(binary, "config", "init", "--deny-all")
        require((result.returncode, result.stdout, result.stderr) ==
                (0, deny_all_config(), b""), "deny-all exact canonical output")

        result = invoke(binary, "config", "init", "--deny-all",
                        "--clock-skew", "0s", "--logging-facility", "local4")
        require((result.returncode, result.stdout, result.stderr) ==
                (0, deny_all_config(clock_skew="0s", logging={"facility": "local4"}), b""),
                "operational overrides are canonical")

        policy = root / "policy.json"
        policy.write_bytes(policy_input(jwks))
        policy.chmod(0o600)
        result = invoke(binary, "config", "init", "--policy-input", str(policy))
        require(result.returncode == 0 and result.stderr == b"" and
                b'"policy_id": "fixture"' in result.stdout and
                b'"alice"' in result.stdout,
                "useful policy initialization")
        useful = root / "useful.json"
        useful.write_bytes(result.stdout)
        useful.chmod(0o600)
        checked = invoke(binary, "config", "check", "--config", str(useful))
        require((checked.returncode, checked.stdout, checked.stderr) ==
                (0, b"configuration valid\n", b""),
                "initializer output accepted by production parser")

        destination = root / "initialized.json"
        result = invoke(binary, "config", "init", "--deny-all", "--output", str(destination))
        require((result.returncode, result.stdout, result.stderr) == (0, b"", b"") and
                destination.read_bytes() == deny_all_config() and
                stat.S_IMODE(destination.stat().st_mode) == 0o600,
                "atomic publication creates exact private file")
        destination.write_bytes(b"preserve-me\n")
        result = invoke(binary, "config", "init", "--deny-all", "--output", str(destination))
        require(result.returncode != 0 and result.stdout == b"" and
                destination.read_bytes() == b"preserve-me\n",
                "existing output preserved without force")
        result = invoke(binary, "config", "init", "--deny-all", "--output", str(destination),
                        "--force")
        require((result.returncode, result.stdout, result.stderr) == (0, b"", b"") and
                destination.read_bytes() == deny_all_config() and
                stat.S_IMODE(destination.stat().st_mode) == 0o600,
                "force atomically replaces regular output")

        symlink = root / "symlink.json"
        symlink.symlink_to(destination)
        result = invoke(binary, "config", "init", "--deny-all", "--output", str(symlink),
                        "--force")
        require(result.returncode != 0 and result.stdout == b"" and
                destination.read_bytes() == deny_all_config(),
                "force rejects symlink output")

        result = invoke(binary, "unknown", "bearer-canary")
        require(result.returncode != 0 and result.stdout == b"" and
                result.stderr == b"malformed_input\n", "unknown command is safe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
