#!/usr/bin/env python3
"""Run clang-tidy with declared Bazel inputs and capture its output."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run clang-tidy for one source.")
    parser.add_argument("--clang-tidy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("clang_tidy_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    clang_tidy_args = list(args.clang_tidy_args)
    if clang_tidy_args and clang_tidy_args[0] == "--":
        clang_tidy_args.pop(0)

    result = subprocess.run(
        [str(args.clang_tidy), *clang_tidy_args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result.stdout, encoding="utf-8")
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
