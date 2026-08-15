#!/usr/bin/env python3
"""Byte-level tests for the specified C++ command adapter surface."""

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


def main() -> int:
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="credbind-cli-") as temporary:
        root = pathlib.Path(temporary)
        config = root / "verifier.json"
        config.write_bytes(sample_config())
        config.chmod(0o600)

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
                          ("config", "init", "--deny-all"),
                          ("config", "init", "--issuer", "https://example.test")):
            result = invoke(binary, *arguments)
            require(result.returncode != 0 and result.stdout == b"" and
                    b"bearer" not in result.stderr,
                    "underspecified initializer remains fail closed")

        result = invoke(binary, "unknown", "bearer-canary")
        require(result.returncode != 0 and result.stdout == b"" and
                result.stderr == b"malformed_input\n", "unknown command is safe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
