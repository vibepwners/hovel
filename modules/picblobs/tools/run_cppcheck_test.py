#!/usr/bin/env python3
"""Run cppcheck as a Bazel py_test with declared runfiles."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import cppcheck as cppcheck_package


def main() -> int:
    parser = argparse.ArgumentParser(description="Run cppcheck over C sources.")
    parser.add_argument("--include-dir", action="append", default=[])
    parser.add_argument("srcs", nargs="+")
    args = parser.parse_args()

    cppcheck = (
        Path(cppcheck_package.__file__).resolve().parent / "Cppcheck" / "cppcheck"
    )
    command = [
        str(cppcheck),
        "--error-exitcode=1",
        "--enable=warning,performance,portability",
        "--suppress=missingIncludeSystem",
        "--suppress=normalCheckLevelMaxBranches",
        "--inline-suppr",
        "--language=c",
        "--std=c11",
    ]
    command.extend(
        arg
        for include in args.include_dir
        for arg in ("-I", str(resolve_path(include)))
    )
    command.extend(str(resolve_path(src)) for src in args.srcs)
    return subprocess.run(command, check=False).returncode


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    for root in candidate_roots():
        candidate = root / value
        if candidate.exists():
            return candidate
    return path


def candidate_roots() -> list[Path]:
    roots = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    expanded: list[Path] = []
    for root in roots:
        expanded.extend([root, root / "_main", root / "hovel_slices"])
    return expanded


if __name__ == "__main__":
    raise SystemExit(main())
