#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the cryptographic test binary's permitted dynamic linkage."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from pathlib import Path


def run(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit("cryptographic test binary is missing")
    system = platform.system().lower()
    if system == "darwin":
        dependencies = run(["otool", "-L", str(args.binary)])
        required = "libcrypto.3.dylib"
    elif system == "linux":
        dependencies = run(["readelf", "-W", "-d", str(args.binary)])
        required = "libcrypto.so.3"
    else:
        raise SystemExit(f"unsupported linkage-verification platform: {system}")
    if required not in dependencies:
        raise SystemExit(f"dynamic {required} linkage is missing")
    if "libssl" in dependencies:
        raise SystemExit("libssl linkage is prohibited")
    print(json.dumps({"libcrypto": required, "status": "verified"}, sort_keys=True))


if __name__ == "__main__":
    main()
