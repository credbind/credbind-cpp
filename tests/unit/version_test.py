#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    completed = subprocess.run([args.binary, "version"], check=True, capture_output=True, text=True)
    value = json.loads(completed.stdout)
    expected = {
        "command": "credbind-ssh-authorized-keys",
        "version": args.version,
        "revision": args.revision,
        "source_date_epoch": args.source_date_epoch,
        "target": args.target,
    }
    if value != expected or completed.stderr:
        raise SystemExit(f"version output mismatch: {value!r}, stderr={completed.stderr!r}")
    denied = subprocess.run([args.binary, "verify"], capture_output=True)
    if denied.returncode == 0 or denied.stdout:
        raise SystemExit("unimplemented verification reported success or wrote stdout")


if __name__ == "__main__":
    main()
