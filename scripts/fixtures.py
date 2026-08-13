#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch and verify the immutable conformance artifact pinned by the lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "conformance" / "fixtures.lock.json"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as handle:
        for member in handle.getmembers():
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError("archive path escapes cache")
            if member.issym() or member.islnk():
                raise ValueError("archive links are prohibited")
        handle.extractall(destination, filter="data")


def load_lock() -> dict:
    with LOCK_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def cache_paths(lock: dict) -> tuple[Path, Path, Path]:
    cache = Path(os.environ.get("CREDBIND_FIXTURE_CACHE", ROOT / ".cache" / "conformance"))
    release = cache / lock["release"]
    return release, release / lock["artifact"]["name"], release / "corpus"


def verify(lock: dict, archive: Path, corpus: Path) -> None:
    if not archive.is_file():
        raise ValueError(f"fixture artifact missing: {archive}; run make fixtures")
    if digest(archive) != lock["artifact"]["sha256"]:
        raise ValueError("fixture artifact SHA-256 mismatch")
    manifest = corpus / lock["manifest"]["path"]
    if not manifest.is_file() or digest(manifest) != lock["manifest"]["sha256"]:
        raise ValueError("fixture manifest SHA-256 mismatch")
    with manifest.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if value["release"] != lock["release"] or value["specification_revision"] != lock["specification_revision"]:
        raise ValueError("fixture manifest does not match lock revision")
    print(json.dumps({
        "release": lock["release"],
        "artifact_sha256": lock["artifact"]["sha256"],
        "manifest_sha256": lock["manifest"]["sha256"],
        "cases": len(value["cases"]),
        "status": "verified",
    }, sort_keys=True))


def fetch(lock: dict, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    source = os.environ.get("CREDBIND_FIXTURE_SOURCE")
    with tempfile.NamedTemporaryFile(dir=archive.parent, prefix="fixture-", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        if source:
            with Path(source).open("rb") as incoming, temporary.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        else:
            with urllib.request.urlopen(lock["artifact"]["url"], timeout=30) as incoming, temporary.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        if digest(temporary) != lock["artifact"]["sha256"]:
            raise ValueError("downloaded fixture artifact SHA-256 mismatch")
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)


def install(lock: dict, archive: Path, corpus: Path) -> None:
    with tempfile.TemporaryDirectory(dir=archive.parent, prefix="corpus-") as directory:
        staging = Path(directory)
        safe_extract(archive, staging)
        if corpus.exists():
            shutil.rmtree(corpus)
        os.replace(staging, corpus)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("fetch", "verify"))
    args = parser.parse_args()
    lock = load_lock()
    _, archive, corpus = cache_paths(lock)
    if args.action == "fetch":
        if not archive.is_file() or digest(archive) != lock["artifact"]["sha256"]:
            fetch(lock, archive)
        install(lock, archive, corpus)
    verify(lock, archive, corpus)


if __name__ == "__main__":
    main()
