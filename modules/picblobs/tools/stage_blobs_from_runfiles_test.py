"""Regression tests for the production Bazel runfile materializer."""

from __future__ import annotations

import stat
from typing import TYPE_CHECKING

import pytest
from picblobs import OS, Arch, wrap_elf
from stage_blobs_from_runfiles import (
    BlobArtifact,
    blob_dest,
    stage_blob,
    stage_executable,
)

if TYPE_CHECKING:
    from pathlib import Path


def _elf(path: Path, arch: Arch) -> bytes:
    content = wrap_elf(b"\x00", OS.LINUX, arch)
    path.write_bytes(content)
    return content


def test_stage_blob_copies_matching_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source.elf"
    content = _elf(source, Arch.X86_64)
    project_root = tmp_path / "picblobs"
    artifact = BlobArtifact("linux", "x86_64", "hello", "hello", source)

    if not stage_blob(artifact, tmp_path, project_root):
        pytest.fail("matching blob was not staged")
    if blob_dest(project_root, artifact).read_bytes() != content:
        pytest.fail("staged blob contents differ from the source artifact")


def test_stage_blob_rejects_mismatch_before_replacing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.elf"
    _elf(source, Arch.AARCH64)
    project_root = tmp_path / "picblobs"
    artifact = BlobArtifact("linux", "x86_64", "hello", "hello", source)
    destination = blob_dest(project_root, artifact)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"existing-artifact")

    if stage_blob(artifact, tmp_path, project_root):
        pytest.fail("architecture-mismatched blob was staged")
    if destination.read_bytes() != b"existing-artifact":
        pytest.fail("architecture mismatch replaced the existing blob")


def test_stage_executable_validates_arch_and_sets_execute_bits(
    tmp_path: Path,
) -> None:
    source = tmp_path / "runner.elf"
    content = _elf(source, Arch.X86_64)
    destination = tmp_path / "staged" / "runner"

    if not stage_executable(source, destination, "runner", "x86_64"):
        pytest.fail("matching executable was not staged")
    if destination.read_bytes() != content:
        pytest.fail("staged executable contents differ from the source artifact")
    if not destination.stat().st_mode & stat.S_IXUSR:
        pytest.fail("staged executable is not executable by its owner")


def test_stage_executable_rejects_mismatch_before_replacing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "runner.elf"
    _elf(source, Arch.AARCH64)
    destination = tmp_path / "staged" / "runner"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"existing-runner")

    if stage_executable(source, destination, "runner", "x86_64"):
        pytest.fail("architecture-mismatched executable was staged")
    if destination.read_bytes() != b"existing-runner":
        pytest.fail("architecture mismatch replaced the existing executable")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
