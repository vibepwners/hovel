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

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    sources = sorted(
        path
        for path in (workspace / "payloads/squatter/windows/src").rglob("*")
        if path.suffix in {".c", ".h"}
    )
    if sources:
        subprocess.run([str(clang_format_binary()), "-i", *map(str, sources)], check=True)
    return 0


def clang_format_binary() -> Path:
    return Path(clang_format.__file__).resolve().parent / "data/bin/clang-format"


if __name__ == "__main__":
    raise SystemExit(main())
