"""Bazel entry point for the picblobs pytest suite."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

import pytest


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--clang-format")
    parser.add_argument("--buildifier-linux-amd64")
    parser.add_argument("--buildifier-linux-arm64")
    parser.add_argument("--pytest-target", action="append", default=[])
    return parser.parse_known_args()


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


def _resolve_runfile(path: str | None) -> Path | None:
    if not path:
        return None
    direct = Path(path)
    if direct.exists():
        return direct.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root_raw = os.environ.get(root_name)
        if not root_raw:
            continue
        root = Path(root_raw)
        for candidate in (
            root / path,
            root / "_main" / path,
            root / "hovel_slices" / path,
        ):
            if candidate.exists():
                return candidate.resolve()
    return None


def _configure_declared_tools(args: argparse.Namespace) -> None:
    clang_format = _resolve_runfile(args.clang_format)
    buildifier = _resolve_runfile(_buildifier_arg(args))
    if clang_format:
        os.environ["PICBLOBS_CLANG_FORMAT"] = str(clang_format)
    if buildifier:
        os.environ["PICBLOBS_BUILDIFIER"] = str(buildifier)
    if clang_format and buildifier:
        os.environ["PICBLOBS_REQUIRE_LINT_TOOLS"] = "1"


def _buildifier_arg(args: argparse.Namespace) -> str | None:
    if os.uname().machine in {"aarch64", "arm64"}:
        return args.buildifier_linux_arm64
    return args.buildifier_linux_amd64


def _pytest_targets(tests_dir: Path, targets: list[str]) -> list[str]:
    if not targets:
        return [str(tests_dir)]
    resolved = []
    for target in targets:
        path = Path(target)
        if not path.is_absolute():
            path = tests_dir / path
        resolved.append(str(path))
    return resolved


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
    args, pytest_args = _parse_args()
    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parents[1]
    _configure_declared_tools(args)
    _prepare_bazel_sidecars(project_root)
    return pytest.main([*_pytest_targets(tests_dir, args.pytest_target), *pytest_args])


if __name__ == "__main__":
    raise SystemExit(main())
