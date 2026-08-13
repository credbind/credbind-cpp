#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the exact committed C++ header dependencies and licenses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party" / "dependencies.json"


def sha256(path: Path) -> str:
	return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
	value = json.loads(LOCK.read_text(encoding="utf-8"))
	for dependency in value["dependencies"]:
		for path_key, digest_key in (("header", "header_sha256"), ("license_file", "license_sha256")):
			path = ROOT / dependency[path_key]
			actual = sha256(path)
			if actual != dependency[digest_key]:
				raise SystemExit(f"{path.relative_to(ROOT)}: SHA-256 {actual}, want {dependency[digest_key]}")
	print(json.dumps({"dependencies": [entry["name"] for entry in value["dependencies"]], "status": "verified"}, sort_keys=True))


if __name__ == "__main__":
	main()
