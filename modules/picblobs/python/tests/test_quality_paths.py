"""Regression coverage for staged-file filtering in repo quality tools."""

from __future__ import annotations

from pathlib import Path

try:
    from ._test_env import PROJECT_ROOT, prepend_source_paths
except ImportError:  # pragma: no cover - supports direct module import
    from _test_env import PROJECT_ROOT, prepend_source_paths

prepend_source_paths()


def _relpaths(paths: list[Path]) -> set[str]:
    return {str(path.relative_to(PROJECT_ROOT)) for path in paths}


def test_collect_files_filters_by_extension() -> None:
    from tools.quality_paths import collect_files

    files = collect_files(
        ["python/picblobs/__init__.py", "README.md"],
        roots=["python", "tools"],
        extensions={".py"},
        exclude={"bazel-bin", "bazel-out", ".venv", "__pycache__"},
    )

    assert _relpaths(files) == {"python/picblobs/__init__.py"}


def test_collect_files_walks_directories() -> None:
    from tools.quality_paths import collect_files

    files = collect_files(
        ["tools"],
        roots=["tools"],
        extensions={".py"},
        exclude={"bazel-bin", "bazel-out", ".venv", "__pycache__"},
    )

    relpaths = _relpaths(files)
    assert "tools/fmt.py" in relpaths
    assert "tools/lint.py" in relpaths
