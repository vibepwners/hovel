"""Tests for staged binary architecture validation."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from artifact_arch import verify_artifact_arch
from picblobs import OS, Arch, wrap_elf

if TYPE_CHECKING:
    from pathlib import Path

_X86_64_PE_MACHINE = 0x8664
_AARCH64_PE_MACHINE = 0xAA64
_PE_HEADER_OFFSET = 0x40
_PE_HEADER_OFFSET_POSITION = 0x3C


@pytest.mark.parametrize(
    ("actual_arch", "expected_arch", "matches"),
    [
        (Arch.X86_64, "x86_64", True),
        (Arch.X86_64, "aarch64", False),
        (Arch.AARCH64, "aarch64", True),
        (Arch.AARCH64, "x86_64", False),
    ],
)
def test_verify_elf_arch(
    tmp_path: Path,
    actual_arch: Arch,
    expected_arch: str,
    matches: bool,
) -> None:
    artifact = tmp_path / "artifact.elf"
    artifact.write_bytes(wrap_elf(b"\x00", OS.LINUX, actual_arch))

    if verify_artifact_arch(artifact, expected_arch) is not matches:
        pytest.fail(
            f"artifact architecture result did not match expectation: {matches}"
        )


@pytest.mark.parametrize(
    ("machine", "expected_arch", "matches"),
    [
        (_X86_64_PE_MACHINE, "x86_64", True),
        (_X86_64_PE_MACHINE, "aarch64", False),
        (_AARCH64_PE_MACHINE, "aarch64", True),
        (_AARCH64_PE_MACHINE, "x86_64", False),
    ],
)
def test_verify_pe_arch(
    tmp_path: Path,
    machine: int,
    expected_arch: str,
    matches: bool,
) -> None:
    artifact = tmp_path / "artifact.exe"
    data = bytearray(_PE_HEADER_OFFSET + 6)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, _PE_HEADER_OFFSET_POSITION, _PE_HEADER_OFFSET)
    data[_PE_HEADER_OFFSET : _PE_HEADER_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, _PE_HEADER_OFFSET + 4, machine)
    artifact.write_bytes(data)

    if verify_artifact_arch(artifact, expected_arch) is not matches:
        pytest.fail(
            f"artifact architecture result did not match expectation: {matches}"
        )


@pytest.mark.parametrize("content", [b"", b"not-an-executable", b"MZ"])
def test_verify_rejects_malformed_artifact(tmp_path: Path, content: bytes) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(content)

    if verify_artifact_arch(artifact, "x86_64"):
        pytest.fail("malformed artifact was accepted as x86_64")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
