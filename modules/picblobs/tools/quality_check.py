#!/usr/bin/env python3
"""Bazel test wrapper for picblobs quality checks."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

TOOLS = {
    "fmt": ("fmt.py", ["--check"], []),
    "generate": ("generate.py", ["--check"], []),
    "lint": ("lint.py", ["--check"], ["--check"]),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a picblobs quality check.")
    parser.add_argument("--mode", choices=sorted(TOOLS), required=True)
    parser.add_argument("--clang-format", required=True)
    parser.add_argument("--ruff", required=True)
    parser.add_argument("--lizard", required=True)
    parser.add_argument("--buildifier-linux-amd64", required=True)
    parser.add_argument("--buildifier-linux-arm64", required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    root = find_picblobs_root(args.mode)
    buildifier = (
        args.buildifier_linux_arm64
        if os.uname().machine in {"aarch64", "arm64"}
        else args.buildifier_linux_amd64
    )

    env = os.environ.copy()
    env.update(
        {
            "PICBLOBS_BUILDIFIER": str(resolve_runfile(buildifier)),
            "PICBLOBS_CLANG_FORMAT": str(resolve_runfile(args.clang_format)),
            "PICBLOBS_LIZARD": str(resolve_runfile(args.lizard)),
            "PICBLOBS_REQUIRE_LINT_TOOLS": "1",
            "PICBLOBS_RUFF": str(resolve_runfile(args.ruff)),
            "PYTHONPATH": pythonpath(root / "tools", env.get("PYTHONPATH")),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    script, check_args, write_args = TOOLS[args.mode]
    script_args = list(write_args if args.write else check_args)
    script_args.extend(args.paths)
    return subprocess.run(
        [sys.executable, str(root / "tools" / script), *script_args],
        cwd=root,
        env=env,
        check=False,
    ).returncode


def find_picblobs_root(mode: str) -> Path:
    script, _, _ = TOOLS[mode]
    suffix = Path("modules/picblobs/tools") / script
    for root in candidate_roots():
        if (root / suffix).is_file():
            return root / "modules/picblobs"
        if (root / "tools" / script).is_file():
            return root
    raise SystemExit(f"unable to locate picblobs root for tools/{script}")


def candidate_roots() -> list[Path]:
    roots: list[Path] = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR", "BUILD_WORKSPACE_DIRECTORY"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    expanded: list[Path] = []
    for root in roots:
        expanded.extend(
            [
                root,
                root / "_main",
                root / "hovel_slices",
                root / "picblobs",
            ]
        )
    return expanded


def resolve_runfile(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path.resolve()
    for root in candidate_roots():
        candidate = root / value
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"unable to locate runfile {value}")


def pythonpath(first: Path, existing: str | None) -> str:
    entries = [str(first)]
    if existing:
        entries.append(existing)
    return os.pathsep.join(entries)


if __name__ == "__main__":
    raise SystemExit(main())
