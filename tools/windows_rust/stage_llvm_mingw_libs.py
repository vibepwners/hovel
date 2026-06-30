"""Stage llvm-mingw libraries into a single directory for Rust link flags."""

import argparse
import os
import shutil
from pathlib import Path


def copy_files(files: list[Path], target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for src in files:
        shutil.copy2(src, target / src.name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target-lib", action="append", type=Path, default=[])
    parser.add_argument("--compiler-rt", action="append", type=Path, default=[])
    args = parser.parse_args()

    if args.out.exists():
        shutil.rmtree(args.out)
    os.makedirs(args.out)

    copy_files(args.target_lib, args.out / "lib")
    copy_files(args.compiler_rt, args.out / "clang")


if __name__ == "__main__":
    main()
