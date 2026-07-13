"""Hermetic Bazel entry point for the staged picblobs CLI test suite."""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
import tomllib

_BLOB_SPEC_FIELDS = 4
_RUNNER_SPEC_FIELDS = 3
_TEST_BINARY_SPEC_FIELDS = 4
_PYTEST_OPTIONS = ("-p", "no:cacheprovider")


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--blob", action="append", default=[])
    parser.add_argument("--runner", action="append", default=[])
    parser.add_argument("--test-binary", action="append", default=[])
    parser.add_argument("--qemu-aarch64", required=True)
    parser.add_argument("--qemu-x86-64", required=True)
    return parser.parse_known_args()


def _parse_spec(raw: str, field_count: int) -> tuple[list[str], str]:
    try:
        spec, path = raw.split("=", 1)
    except ValueError as error:
        raise ValueError(f"invalid staged artifact {raw!r}") from error
    fields = spec.split(":")
    if len(fields) != field_count:
        raise ValueError(
            f"invalid staged artifact spec {spec!r}: expected {field_count} fields"
        )
    return fields, path


def _resolve_runfile(logical_path: str) -> Path:
    direct = Path(logical_path)
    if direct.exists():
        return direct.resolve()

    for variable in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(variable)
        if not value:
            continue
        root = Path(value)
        for candidate in (root / logical_path, root / "_main" / logical_path):
            if candidate.exists():
                return candidate.resolve()

    manifest = os.environ.get("RUNFILES_MANIFEST_FILE")
    if manifest:
        key = f"_main/{logical_path}"
        for line in Path(manifest).read_text().splitlines():
            if line.startswith(f"{key} "):
                return Path(line.split(" ", 1)[1]).resolve()

    raise FileNotFoundError(f"declared runfile not found: {logical_path}")


def _copy_package_sources(source_root: Path, test_root: Path) -> None:
    package_paths = (
        Path("python/picblobs"),
        Path("python_cli/picblobs_cli"),
        Path("python_cli/tests"),
    )
    for relative_path in package_paths:
        shutil.copytree(source_root / relative_path, test_root / relative_path)
    shutil.copy2(
        source_root / "python_cli" / "pyproject.toml",
        test_root / "python_cli" / "pyproject.toml",
    )


def _copy_artifact(source: Path, destination: Path, *, executable: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if executable:
        destination.chmod(
            destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )


def _require_artifact_arch(source: Path, expected_arch: str, kind: str) -> None:
    from artifact_arch import verify_artifact_arch

    if not verify_artifact_arch(source, expected_arch):
        raise RuntimeError(
            f"staged {kind} architecture mismatch: "
            f"expected={expected_arch}, path={source}"
        )


def _stage_blobs(raw_specs: list[str], test_root: Path) -> int:
    for raw in raw_specs:
        fields, path = _parse_spec(raw, _BLOB_SPEC_FIELDS)
        os_name, arch, _target, staged_name = fields
        source = _resolve_runfile(path)
        _require_artifact_arch(source, arch, "blob")
        destination = (
            test_root
            / "python"
            / "picblobs"
            / "_blobs"
            / os_name
            / arch
            / f"{staged_name}.so"
        )
        _copy_artifact(source, destination, executable=False)
    return len(raw_specs)


def _stage_runners(raw_specs: list[str], test_root: Path) -> None:
    for raw in raw_specs:
        fields, path = _parse_spec(raw, _RUNNER_SPEC_FIELDS)
        runner_type, _os_name, arch = fields
        destination = (
            test_root
            / "python_cli"
            / "picblobs_cli"
            / "_runners"
            / runner_type
            / arch
            / "runner"
        )
        source = _resolve_runfile(path)
        _require_artifact_arch(source, arch, "runner")
        _copy_artifact(source, destination, executable=True)


def _stage_test_binaries(raw_specs: list[str], test_root: Path) -> None:
    for raw in raw_specs:
        fields, path = _parse_spec(raw, _TEST_BINARY_SPEC_FIELDS)
        fixture_type, os_name, arch, name = fields
        destination = (
            test_root
            / "python_cli"
            / "picblobs_cli"
            / "_test_binaries"
            / fixture_type
            / os_name
            / arch
            / name
        )
        source = _resolve_runfile(path)
        _require_artifact_arch(source, arch, "test binary")
        _copy_artifact(source, destination, executable=True)


def _write_distribution_metadata(source_root: Path, test_root: Path) -> None:
    pyproject = tomllib.loads(
        (source_root / "python_cli" / "pyproject.toml").read_text()
    )
    version = pyproject["project"]["version"]
    metadata_dir = test_root / "python_cli" / f"picblobs_cli-{version}.dist-info"
    metadata_dir.mkdir()
    (metadata_dir / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: picblobs-cli\nVersion: {version}\n"
    )


def _extract_blobs(source_root: Path, test_root: Path, expected: int) -> None:
    sys.path.insert(0, str(source_root))
    from tools.extract_release import extract_release

    package_root = test_root / "python" / "picblobs"
    extracted, errors = extract_release(package_root / "_blobs", package_root)
    if errors or extracted != expected:
        raise RuntimeError(
            "failed to prepare hermetic CLI blob fixtures: "
            f"expected={expected}, extracted={extracted}, errors={errors}"
        )


def _configure_imports(test_root: Path) -> None:
    package_roots = (test_root / "python", test_root / "python_cli")
    for package_root in reversed(package_roots):
        sys.path.insert(0, str(package_root))
    previous = os.environ.get("PYTHONPATH")
    values = [str(path) for path in package_roots]
    if previous:
        values.append(previous)
    os.environ["PYTHONPATH"] = os.pathsep.join(values)
    for module_name in tuple(sys.modules):
        if module_name in {"picblobs", "picblobs_cli"} or module_name.startswith(
            ("picblobs.", "picblobs_cli.")
        ):
            del sys.modules[module_name]
    importlib.invalidate_caches()


def _configure_qemu(logical_paths: tuple[str, ...], test_root: Path) -> None:
    qemu_dir = test_root / "bin"
    for logical_path in logical_paths:
        source = _resolve_runfile(logical_path)
        _copy_artifact(source, qemu_dir / source.name, executable=True)
    previous = os.environ.get("PATH")
    os.environ["PATH"] = os.pathsep.join(
        [str(qemu_dir), *([previous] if previous else [])]
    )
    os.environ["PICBLOBS_HERMETIC_RUNTIME"] = "1"


def main() -> int:
    args, pytest_args = _parse_args()
    tests_dir = Path(__file__).absolute().parent
    source_root = tests_dir.parents[1]
    test_root = Path(os.environ["TEST_TMPDIR"]) / "picblobs-cli-package"

    sys.path.insert(0, str(source_root / "tools"))

    _copy_package_sources(source_root, test_root)
    blob_count = _stage_blobs(args.blob, test_root)
    _stage_runners(args.runner, test_root)
    _stage_test_binaries(args.test_binary, test_root)
    _write_distribution_metadata(source_root, test_root)
    _extract_blobs(source_root, test_root, blob_count)
    _configure_imports(test_root)
    _configure_qemu((args.qemu_aarch64, args.qemu_x86_64), test_root)

    test_file = test_root / "python_cli" / "tests" / "test_picblobs_cli.py"
    return pytest.main([str(test_file), *_PYTEST_OPTIONS, *pytest_args])


if __name__ == "__main__":
    raise SystemExit(main())
