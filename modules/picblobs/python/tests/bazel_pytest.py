"""Bazel entry point for the picblobs pytest suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


def main() -> int:
    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parents[1]
    venv_bin = project_root / "python" / ".venv" / "bin"
    os.environ["PATH"] = f"{venv_bin}:/usr/local/bin:{os.environ.get('PATH', '')}"
    return pytest.main([str(tests_dir), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
