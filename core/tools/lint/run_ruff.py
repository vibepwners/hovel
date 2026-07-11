#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path


def _is_ruff_binary(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return "pip+lint_pypi" in normalized and normalized.endswith("/bin/ruff")


def _find_ruff() -> str:
    runfiles_dir = os.environ.get("RUNFILES_DIR")
    if runfiles_dir:
        for candidate in Path(runfiles_dir).glob("*/bin/ruff"):
            if _is_ruff_binary(str(candidate)):
                return str(candidate)

    manifest = os.environ.get("RUNFILES_MANIFEST_FILE")
    if manifest:
        for line in Path(manifest).read_text().splitlines():
            key, _, value = line.partition(" ")
            if value and _is_ruff_binary(key):
                return value

    raise FileNotFoundError("Bazel-managed ruff binary was not present in runfiles")


def _working_directory() -> Path:
    for name in ("HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY", "BUILD_WORKING_DIRECTORY"):
        value = os.environ.get(name)
        if value:
            candidate = Path(value)
            if candidate.is_dir():
                return candidate
    return Path.cwd()


if __name__ == "__main__":
    os.chdir(_working_directory())
    os.execv(_find_ruff(), ["ruff", *sys.argv[1:]])
