#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


SKIP_DIRS = {".git", ".mypy_cache", ".ruff_cache", ".task", ".venv", "__pycache__", "coverage", "dist", "tmp"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Bazel-provided gofmt over workspace Go sources.")
    parser.add_argument("--gofmt", required=True)
    parser.add_argument("--mode", choices=("check", "write"), required=True)
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="Path to scan instead of the whole workspace. May be repeated.",
    )
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    gofmt = resolve_runfile(args.gofmt)
    roots = [resolve_scan_path(workspace, path) for path in args.path] or [workspace]
    files = [file for root in roots for file in go_files(root)]
    if not files:
        return 0
    if args.mode == "write":
        subprocess.run([str(gofmt), "-w", *map(str, files)], check=True)
        return 0

    result = subprocess.run([str(gofmt), "-l", *map(str, files)], text=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return result.returncode
    unformatted = result.stdout.strip()
    if unformatted:
        print(f"gofmt found files that need formatting:\n{unformatted}", file=sys.stderr)
        print("Run task fmt before committing.", file=sys.stderr)
        return 1
    return 0


def go_files(workspace: Path):
    for root, dirs, files in os.walk(workspace):
        root_path = Path(root)
        dirs[:] = [
            item
            for item in dirs
            if item not in SKIP_DIRS
            and not item.startswith("bazel-")
            and not item.endswith(".egg-info")
            and item != "sdk/python/.venv"
        ]
        for filename in files:
            if filename.endswith(".go"):
                yield root_path / filename


def resolve_scan_path(workspace: Path, path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    if raw.is_absolute() and raw.exists():
        return raw.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / path
            if candidate.exists():
                return candidate.resolve()
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate.resolve()
    raise SystemExit(f"missing runfile: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
