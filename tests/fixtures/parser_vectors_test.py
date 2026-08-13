#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise implemented C++ parsers against the immutable RC corpus."""

from __future__ import annotations

import argparse
import base64
import json
import os
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

    print(json.dumps({
        "certificates": 2,
        "compact_jws": 5,
        "core_tokens": 5,
        "status": "verified",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
