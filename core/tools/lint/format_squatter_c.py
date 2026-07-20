#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import clang_format


def main() -> int:
    parser = argparse.ArgumentParser(description="Format Squatter C sources with the Bazel-provided clang-format.")
    parser.parse_args()

    workspace = repository_root()
    sources = sorted(
        path
        for path in (workspace / "modules/squatter/windows/src").rglob("*")
        if path.suffix in {".c", ".h"}
    )
    if sources:
        subprocess.run([str(clang_format_binary()), "-i", *map(str, sources)], check=True)
    return 0


def clang_format_binary() -> Path:
    return Path(clang_format.__file__).resolve().parent / "data/bin/clang-format"


def repository_root() -> Path:
    for name in ("HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY"):
        value = os.environ.get(name)
        if value:
            candidate = Path(value).resolve()
            if (candidate / "modules/squatter/windows/src").is_dir():
                return candidate
            if (candidate.parent / "modules/squatter/windows/src").is_dir():
                return candidate.parent
    for candidate in (Path.cwd(), *Path.cwd().parents):
        if (candidate / "modules/squatter/windows/src").is_dir():
            return candidate.resolve()
    raise SystemExit("could not locate Hovel repository root")


if __name__ == "__main__":
    raise SystemExit(main())
