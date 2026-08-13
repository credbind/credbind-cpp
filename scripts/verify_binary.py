#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the C++ build metadata, hardening surface, and reproducibility."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, capture_output=True, **kwargs)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", required=True)
    args = parser.parse_args()
    binary = (ROOT / args.binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"missing executable: {binary}")
    value = json.loads(run([str(binary), "version"], text=True).stdout)
    expected = {
        "command": "credbind-ssh-authorized-keys",
        "version": args.version,
        "revision": args.revision,
        "source_date_epoch": args.source_date_epoch,
        "target": args.target,
    }
    if value != expected:
        raise SystemExit(f"version metadata mismatch: {value!r}")
    description = run(["file", str(binary)], text=True).stdout
    if "executable" not in description and "Mach-O" not in description:
        raise SystemExit(f"unexpected binary type: {description.strip()}")
    strings = run(["strings", str(binary)], text=True, errors="replace").stdout
    if str(ROOT) in strings or str(Path.home()) in strings:
        raise SystemExit("local checkout path leaked into binary")
    system = args.target.split("-", 1)[0]
    if system == "darwin":
        header = run(["otool", "-hv", str(binary)], text=True).stdout
        if "PIE" not in header:
            raise SystemExit("Mach-O binary is not PIE")
        symbols = run(["nm", "-gU", str(binary)], text=True).stdout.splitlines()
        if any("__mh_execute_header" not in line for line in symbols):
            raise SystemExit("Mach-O binary retains non-required symbols")
    elif system == "linux":
        header = run(["readelf", "-h", str(binary)], text=True).stdout
        if "DYN (Position-Independent Executable file)" not in header:
            raise SystemExit("ELF binary is not PIE")
        program = run(["readelf", "-W", "-l", str(binary)], text=True).stdout
        dynamic = run(["readelf", "-W", "-d", str(binary)], text=True).stdout
        if "GNU_RELRO" not in program or "BIND_NOW" not in dynamic:
            raise SystemExit("ELF relocation hardening is missing")
        symbols = run(["nm", "--defined-only", str(binary)], text=True).stdout
        if symbols.strip():
            raise SystemExit("ELF binary retains defined symbols")
    with tempfile.TemporaryDirectory(prefix="credbind-cpp-repro-") as directory:
        outputs = []
        for name in ("left", "right"):
            root = Path(directory) / name
            run(["make", "--no-print-directory", "build", f"DIST_ROOT={root}"], cwd=ROOT)
            outputs.append(root / args.target / "credbind-ssh-authorized-keys")
        if digest(outputs[0]) != digest(outputs[1]) or digest(outputs[0]) != digest(binary):
            raise SystemExit("controlled builds are not byte-identical")
    print(json.dumps({"binary": binary.name, "revision": args.revision, "status": "verified"}, sort_keys=True))


if __name__ == "__main__":
    main()
