#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that every documented shell command has a maintained Make surface."""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path


EXPECTED = (
    ("make", "build"),
    ("make", "test-unit"),
    ("make", "dependencies-check"),
    ("make", "verify-binary"),
    ("make", "test-sanitize"),
    ("make", "test-fuzz-smoke"),
    ("make", "fuzz", "TARGET=json", "DURATION=60"),
    ("make", "fuzz", "TARGET=certificate", "DURATION=60"),
    ("make", "fuzz", "TARGET=token", "DURATION=60"),
)


def shell_commands(readme: Path) -> tuple[tuple[str, ...], ...]:
    commands: list[tuple[str, ...]] = []
    in_shell_block = False
    for line in readme.read_text(encoding="utf-8").splitlines():
        if line == "```sh":
            if in_shell_block:
                raise RuntimeError("nested shell block")
            in_shell_block = True
            continue
        if line == "```" and in_shell_block:
            in_shell_block = False
            continue
        if in_shell_block and line.strip():
            commands.append(tuple(shlex.split(line)))
    if in_shell_block:
        raise RuntimeError("unterminated shell block")
    return tuple(commands)


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("usage: readme_commands_test.py README")
    readme = Path(sys.argv[1])
    commands = shell_commands(readme)
    if commands != EXPECTED:
        raise RuntimeError("README shell command inventory changed; review the executable contract")
    for command in commands:
        result = subprocess.run(
            [command[0], "--no-print-directory", "-n", *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"documented command has no runnable Make surface: {' '.join(command)}")
    print(f"verified {len(commands)} documented shell commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
