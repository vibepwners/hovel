#!/usr/bin/env python3
"""Compatibility wrapper for Task-backed Picblobs staging.

The canonical staging graph is declared in Bazel and invoked through
`task picblobs:stage`. This script exists only for older source-tree guidance
that still points at `python tools/stage_blobs.py`.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    cmd = ["task", "picblobs:stage", "--", *argv]
    return subprocess.run(cmd, check=False, cwd=workspace_root()).returncode


def workspace_root() -> Path:
    if workspace := os.environ.get("BUILD_WORKSPACE_DIRECTORY"):
        return Path(workspace)
    return Path(__file__).resolve().parents[3]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
