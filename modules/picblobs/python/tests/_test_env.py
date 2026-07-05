"""Shared test-environment helpers for repo-root path discovery and imports."""

from __future__ import annotations

import sys
from pathlib import Path


def find_project_root() -> Path:
    """Find the repository root (directory containing MODULE.bazel)."""
    p = Path(__file__).resolve()
    for parent in [p, *list(p.parents)]:
        if (parent / "MODULE.bazel").exists():
            return parent
    return Path.cwd()


PROJECT_ROOT = find_project_root()
TESTS_DIR = Path(__file__).resolve().parent


def prepend_source_paths() -> None:
    """Force imports to resolve against the in-repo source tree."""
    for path in (
        PROJECT_ROOT / "python",
        PROJECT_ROOT / "python_cli",
        PROJECT_ROOT,
        TESTS_DIR,
    ):
        path_str = str(path)
        if path_str in sys.path:
            sys.path.remove(path_str)
        sys.path.insert(0, path_str)
