#!/usr/bin/env python3
"""Run the Bazel-managed cppcheck wheel."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import cppcheck as cppcheck_package


def main() -> int:
    cppcheck = (
        Path(cppcheck_package.__file__).resolve().parent / "Cppcheck" / "cppcheck"
    )
    return subprocess.run([str(cppcheck), *sys.argv[1:]], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
