"""Bazel entry point for the picblobs pytest suite."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest


def _runfile_path(logical_path: str) -> Path | None:
    runfiles_dir = os.environ.get("RUNFILES_DIR")
    if runfiles_dir:
        candidate = Path(runfiles_dir) / "_main" / logical_path
        if candidate.exists():
            return candidate

    manifest = os.environ.get("RUNFILES_MANIFEST_FILE")
    if manifest:
        key = f"_main/{logical_path}"
        for line in Path(manifest).read_text().splitlines():
            if not line.startswith(f"{key} "):
                continue
            candidate = Path(line.split(" ", 1)[1])
            if candidate.exists():
                return candidate
    return None


def _prepare_bazel_sidecars(project_root: Path) -> None:
    """Extract the minimal release sidecars needed by Bazel-only pytest runs."""
    package_blobs = project_root / "python" / "picblobs" / "blobs"
    if (package_blobs / "hello.linux.x86_64.bin").exists():
        return

    hello_so = _runfile_path("modules/picblobs/src/payload/hello.so")
    if hello_so is None:
        hello_so = project_root / "src" / "payload" / "hello.so"
    if not hello_so.exists():
        return

    tmp_root = Path(os.environ.get("TEST_TMPDIR", project_root / ".pytest_tmp"))
    staged_dir = tmp_root / "picblobs-staged" / "linux" / "x86_64"
    out_dir = tmp_root / "picblobs-runtime"
    staged_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(hello_so, staged_dir / "hello.so")

    sys.path.insert(0, str(project_root))
    from tools.extract_release import extract_release

    extracted, errors = extract_release(staged_dir.parents[1], out_dir)
    if extracted < 1 or errors:
        raise RuntimeError(
            "failed to extract Bazel pytest blob sidecars "
            f"(extracted={extracted}, errors={errors})"
        )
    os.environ["PICBLOBS_BLOBS_DIR"] = str(out_dir / "blobs")


def main() -> int:
    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parents[1]
    venv_bin = project_root / "python" / ".venv" / "bin"
    os.environ["PATH"] = f"{venv_bin}:/usr/local/bin:{os.environ.get('PATH', '')}"
    _prepare_bazel_sidecars(project_root)
    return pytest.main([str(tests_dir), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
