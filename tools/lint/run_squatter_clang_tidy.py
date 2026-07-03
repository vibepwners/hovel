#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run clang-tidy for one Squatter C source.")
    parser.add_argument("--clang-tidy", type=Path, required=True)
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--mingw-marker", type=Path, required=True)
    parser.add_argument("--project-include", required=True)
    args = parser.parse_args()

    mingw_include = args.mingw_marker.resolve().parent
    subprocess.run(
        [
            str(args.clang_tidy),
            "--quiet",
            "--checks=clang-analyzer-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling",
            "--warnings-as-errors=*",
            str(args.source),
            "--",
            "-x",
            "c",
            "-std=c11",
            "-D_WIN32_WINNT=0x0501",
            "-DUNICODE",
            "-D_UNICODE",
            "-DDECLSPEC_IMPORT=",
            "-target",
            "i686-w64-windows-gnu",
            "-isystem",
            str(mingw_include),
            f"-I{args.project_include}",
        ],
        check=True,
    )
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text("ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
