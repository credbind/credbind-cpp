#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate deterministic C++ release metadata and disclosure boundaries."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys


SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def snapshot(root: pathlib.Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def execute(arguments: list[str]) -> None:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=30)
    require(result.returncode == 0 and result.stderr == b"",
            "release metadata packager failed: " + result.stderr.decode(errors="replace"))


def main() -> int:
    require(len(sys.argv) == 9,
            "usage: release_package_test.py CXX PKG_CONFIG DIST VERSION REVISION EPOCH TARGET PYTHON")
    cxx, pkg_config, raw_dist, version, revision, epoch, target, python = sys.argv[1:]
    root = pathlib.Path(__file__).resolve().parents[1]
    distribution = pathlib.Path(raw_dist).resolve()
    output = distribution / "release-metadata"
    command = [python, str(root / "scripts" / "package_release.py"),
               "--cxx", cxx, "--pkg-config", pkg_config,
               "--dist", str(distribution.relative_to(root)), "--version", version,
               "--revision", revision, "--source-date-epoch", epoch, "--target", target]
    execute(command)
    first = snapshot(output)
    execute(command)
    require(snapshot(output) == first, "C++ release metadata is not deterministic")
    require(set(first) == {"SHA256SUMS", "licenses.json", "provenance.json",
                           "sbom.spdx.json", "LICENSES/LICENSE.credbind-cpp",
                           "LICENSES/LICENSE.nlohmann_json",
                           "LICENSES/LICENSE.tl__expected",
                           "DOCUMENTATION/README.md",
                           "DOCUMENTATION/OPERATIONS.md"},
            "C++ release metadata output is incomplete or contains extras")
    for name in ("README.md", "OPERATIONS.md"):
        require((output / "DOCUMENTATION" / name).read_bytes() == (root / name).read_bytes(),
                f"release documentation differs from {name}")

    checksums: dict[str, str] = {}
    for line in (output / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        parts = line.split("  ")
        require(len(parts) == 2 and SHA256.fullmatch(parts[0]) is not None
                and parts[1] not in checksums, "invalid SHA256SUMS record")
        checksums[parts[1]] = parts[0]
    require("credbind-ssh-authorized-keys" in checksums,
            "C++ release binary checksum is absent")
    require(set(checksums) == (set(first) - {"SHA256SUMS"})
            | {"credbind-ssh-authorized-keys"},
            "C++ release checksums do not cover the complete output")
    for name, expected in checksums.items():
        path = distribution / name if name == "credbind-ssh-authorized-keys" else output / name
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                f"checksum mismatch for {name}")

    licenses = json.loads((output / "licenses.json").read_bytes())
    require(set(licenses) == {"version", "entries"} and licenses["version"] == 1
            and len(licenses["entries"]) == 4,
            "C++ license inventory is incomplete")
    system = [item for item in licenses["entries"] if item["name"] == "OpenSSL libcrypto"]
    require(len(system) == 1 and system[0]["shipped_file"] is None
            and system[0]["license_sha256"] is None
            and system[0]["distribution"] == "dynamic system libcrypto only",
            "system libcrypto was represented as redistributed content")

    sbom = json.loads((output / "sbom.spdx.json").read_bytes())
    require(sbom.get("spdxVersion") == "SPDX-2.3"
            and sbom.get("dataLicense") == "CC0-1.0"
            and len(sbom.get("packages", [])) == 4
            and len(sbom.get("files", [])) == 1,
            "C++ SPDX document is incomplete")
    provenance = json.loads((output / "provenance.json").read_bytes())
    resolved = provenance.get("predicate", {}).get("buildDefinition", {}).get(
        "resolvedDependencies", [])
    require(provenance.get("_type") == "https://in-toto.io/Statement/v1"
            and provenance.get("predicateType") == "https://slsa.dev/provenance/v1"
            and len(provenance.get("subject", [])) == 5
            and any(item.get("uri", "").startswith("git+https://github.com/credbind/spec@")
                    for item in resolved),
            "C++ provenance statement is incomplete")
    serialized = b"".join((output / name).read_bytes() for name in sorted(first))
    require(str(root).encode() not in serialized and b"PRIVATE KEY" not in serialized
            and b"client_secret" not in serialized,
            "C++ release metadata disclosed a workspace path or secret marker")
    development_command = list(command)
    development_command[development_command.index("--version") + 1] = "v0.0.0-dev"
    rejected = subprocess.run(development_command + ["--archive"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False, timeout=30)
    require(rejected.returncode != 0
            and b"release archive requires a stable version and clean source tree" in rejected.stderr,
            "development or dirty source unexpectedly produced a C++ release archive")
    print(json.dumps({"files": len(first), "packages": 4, "status": "verified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
