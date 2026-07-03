#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import stat
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage example module binaries into modules/examples/bin/.")
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        metavar="NAME=RUNFILE",
        help="Staged binary name and Bazel runfile path.",
    )
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    dest = workspace / "modules" / "examples" / "bin"
    dest.mkdir(parents=True, exist_ok=True)

    staged = 0
    current = 0
    for item in args.module:
        name, sep, runfile = item.partition("=")
        if not sep or not name or not runfile:
            raise SystemExit(f"invalid --module value: {item!r}")
        src = resolve_runfile(runfile)
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and same_file_contents(src, target):
            current += 1
        else:
            if target.exists():
                target.chmod(target.stat().st_mode | stat.S_IWUSR)
            shutil.copy2(src, target)
            staged += 1
        target.chmod(target.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"example module binaries current: {current}; staged: {staged}; destination: {dest}")
    return 0


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(
            Path(root) / prefix / path
            for root in runfile_roots()
            for prefix in ("", "_main", "hovel")
        )
        candidates.append(Path.cwd() / path)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    searched = "\n  ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"missing runfile: {path}\nsearched:\n  {searched}")


def runfile_roots() -> list[Path]:
    roots: list[Path] = []
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    argv0 = Path(os.environ.get("PYTHON_BINARY", "")) if os.environ.get("PYTHON_BINARY") else None
    if argv0:
        roots.append(argv0.parent)
    roots.append(Path.cwd())
    return roots


def same_file_contents(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    return left.read_bytes() == right.read_bytes()


if __name__ == "__main__":
    raise SystemExit(main())
