#!/usr/bin/env python3
"""Stage the Hovel picblobs provider binary into modules/picblobs/bin."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider", required=True, help="Bazel runfile path for picblobs-provider."
    )
    parser.add_argument(
        "--dest",
        default="modules/picblobs/bin/picblobs-provider",
        help="Workspace-relative destination path.",
    )
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    src = resolve_runfile(args.provider)
    dest = workspace / args.dest
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        dest.chmod(dest.stat().st_mode | stat.S_IWUSR)
    shutil.copy2(src, dest)
    dest.chmod(
        dest.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )

    print(f"staged {dest.relative_to(workspace)}")
    return 0


def resolve_runfile(path: str) -> Path:
    raw = Path(path)
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(
            Path(root) / prefix / path
            for root in runfile_roots()
            for prefix in ("", "_main", "hovel_slices")
        )
        candidates.append(Path.cwd() / path)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    searched = "\n  ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"missing provider runfile: {path}\nsearched:\n  {searched}")


def runfile_roots() -> list[Path]:
    roots: list[Path] = []
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    roots.append(Path.cwd())
    return roots


if __name__ == "__main__":
    raise SystemExit(main())
