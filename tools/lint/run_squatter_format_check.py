#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import clang_format


def main() -> int:
    parser = argparse.ArgumentParser(description="Run clang-format in check mode over Squatter C sources.")
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    subprocess.run([str(clang_format_binary()), "--dry-run", "--Werror", *map(str, args.sources)], check=True)
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text("ok\n")
    return 0


def clang_format_binary() -> Path:
    return Path(clang_format.__file__).resolve().parent / "data/bin/clang-format"


if __name__ == "__main__":
    raise SystemExit(main())
