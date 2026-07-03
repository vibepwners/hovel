#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import cppcheck as cppcheck_package


def main() -> int:
    parser = argparse.ArgumentParser(description="Run cppcheck over Squatter C sources.")
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("--include-dir", required=True)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    cppcheck = Path(cppcheck_package.__file__).resolve().parent / "Cppcheck/cppcheck"

    subprocess.run(
        [
            str(cppcheck),
            "--quiet",
            "--enable=warning,performance,portability",
            "--error-exitcode=1",
            "--force",
            "--check-level=exhaustive",
            "--inline-suppr",
            "--std=c11",
            "--suppress=missingIncludeSystem",
            "-D_WIN32_WINNT=0x0501",
            "-DUNICODE",
            "-D_UNICODE",
            "-DDECLSPEC_IMPORT=",
            f"-I{args.include_dir}",
            *map(str, args.sources),
        ],
        check=True,
    )
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text("ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
