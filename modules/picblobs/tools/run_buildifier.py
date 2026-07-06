#!/usr/bin/env python3
"""Run the pinned Bazel-managed buildifier binary."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run pinned buildifier.")
    parser.add_argument("--buildifier-linux-amd64", required=True)
    parser.add_argument("--buildifier-linux-arm64", required=True)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    buildifier = (
        args.buildifier_linux_arm64
        if os.uname().machine in {"aarch64", "arm64"}
        else args.buildifier_linux_amd64
    )
    command_args = args.args
    if command_args[:1] == ["--"]:
        command_args = command_args[1:]
    return subprocess.run(
        [str(resolve_runfile(buildifier)), *command_args],
        check=False,
    ).returncode


def resolve_runfile(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path.resolve()
    for root in candidate_roots():
        candidate = root / value
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"unable to locate runfile {value}")


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
