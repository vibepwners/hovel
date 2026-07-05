"""Regression tests for the project version update helper."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

try:
    from ._test_env import PROJECT_ROOT, prepend_source_paths
except ImportError:  # pragma: no cover - supports direct module import
    from _test_env import PROJECT_ROOT, prepend_source_paths

prepend_source_paths()

from tools.update_version import VERSION_TARGETS, update_version  # noqa: E402


def _copy_version_targets(tmp_path: Path) -> Path:
    for target in VERSION_TARGETS:
        src = PROJECT_ROOT / target.path
        dest = tmp_path / target.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            shutil.copy2(src, dest)
    return tmp_path


def test_update_version_updates_all_targets_in_temp_tree(tmp_path: Path) -> None:
    root = _copy_version_targets(tmp_path)

    changes = update_version(root, "v2.3.4")

    assert changes
    assert {change.path for change in changes} == {
        target.path for target in VERSION_TARGETS
    }
    assert not update_version(root, "2.3.4", check=True)

    assert 'version = "2.3.4"' in (root / "python" / "pyproject.toml").read_text()
    assert (
        '__version__ = "2.3.4"'
        in (root / "python" / "picblobs" / "__init__.py").read_text()
    )
    cli_pyproject = (root / "python_cli" / "pyproject.toml").read_text()
    assert 'version = "2.3.4"' in cli_pyproject
    assert '"picblobs>=2.3.4",' in cli_pyproject


def test_update_version_check_reports_drift(tmp_path: Path) -> None:
    root = _copy_version_targets(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "tools" / "update_version.py"),
            "9.9.9",
            "--check",
            "--root",
            str(root),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert "version check failed" in result.stderr
    assert "python/pyproject.toml" in result.stderr
