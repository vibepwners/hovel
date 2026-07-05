"""Tests for pure-Python ELF wrapping."""

from __future__ import annotations

import errno
import platform
import stat
import struct
import subprocess
from pathlib import Path

import picblobs
import pytest
from picblobs import Blob, ValidationError


def _unpack_ehdr64(data: bytes) -> dict:
    fields = struct.unpack("<16sHHIQQQIHHHHHH", data[:64])
    return {
        "ident": fields[0],
        "type": fields[1],
        "machine": fields[2],
        "entry": fields[4],
        "phoff": fields[5],
        "shoff": fields[6],
        "flags": fields[7],
        "ehsize": fields[8],
        "phentsize": fields[9],
        "phnum": fields[10],
        "shentsize": fields[11],
        "shnum": fields[12],
        "shstrndx": fields[13],
    }


def _unpack_ehdr32(data: bytes) -> dict:
    fields = struct.unpack("<16sHHIIIIIHHHHHH", data[:52])
    return {
        "ident": fields[0],
        "type": fields[1],
        "machine": fields[2],
        "entry": fields[4],
        "phoff": fields[5],
        "shoff": fields[6],
        "flags": fields[7],
    }


def _unpack_phdr64(data: bytes, offset: int) -> dict:
    fields = struct.unpack("<IIQQQQQQ", data[offset : offset + 56])
    return {
        "type": fields[0],
        "flags": fields[1],
        "offset": fields[2],
        "vaddr": fields[3],
        "paddr": fields[4],
        "filesz": fields[5],
        "memsz": fields[6],
        "align": fields[7],
    }


class TestWrapElf:
    def test_wraps_x86_64_payload_as_minimal_executable(self) -> None:
        payload = b"\xcc" * 7

        out = picblobs.wrap_elf(payload, "linux", "x86_64")
        ehdr = _unpack_ehdr64(out)
        phdr = _unpack_phdr64(out, ehdr["phoff"])

        assert ehdr["ident"][:4] == b"\x7fELF"
        assert ehdr["ident"][4] == 2  # ELFCLASS64
        assert ehdr["ident"][5] == 1  # little-endian
        assert ehdr["type"] == 2  # ET_EXEC
        assert ehdr["machine"] == 62  # EM_X86_64
        assert ehdr["entry"] == 0x400000
        assert ehdr["shoff"] == 0
        assert ehdr["shnum"] == 0
        assert ehdr["shstrndx"] == 0

        assert phdr["type"] == 1  # PT_LOAD
        assert phdr["flags"] == 0x7  # PF_R | PF_W | PF_X
        assert phdr["offset"] == 0x1000
        assert phdr["vaddr"] == 0x400000
        assert phdr["filesz"] == len(payload)
        assert phdr["memsz"] == len(payload)
        assert phdr["align"] == 0x1000
        assert out[0x1000:] == payload

    def test_entry_offset_adjusts_virtual_entry(self) -> None:
        out = picblobs.wrap_elf(
            b"\x90" * 16,
            "linux",
            "x86_64",
            entry_offset=4,
            base_vaddr=0x500000,
        )
        assert _unpack_ehdr64(out)["entry"] == 0x500004

    def test_builder_can_emit_elf(self) -> None:
        raw = Blob("linux", "x86_64").hello().build()
        wrapped = Blob("linux", "x86_64").hello().build_elf()
        assert wrapped == picblobs.wrap_elf(raw, "linux", "x86_64")

    def test_arm_entry_mode_matches_staged_payloads(self) -> None:
        armv5 = picblobs.wrap_elf(b"\x00" * 4, "linux", "armv5_thumb")
        armv7 = picblobs.wrap_elf(b"\x00" * 4, "linux", "armv7_thumb")
        assert _unpack_ehdr32(armv5)["entry"] == 0x10000
        assert _unpack_ehdr32(armv7)["entry"] == 0x10001

    def test_rejects_non_linux_targets(self) -> None:
        with pytest.raises(ValidationError, match="linux"):
            picblobs.wrap_elf(b"\x90", "windows", "x86_64")

    def test_rejects_bad_entry_offset(self) -> None:
        with pytest.raises(ValidationError, match="entry_offset"):
            picblobs.wrap_elf(b"\x90", "linux", "x86_64", entry_offset=1)

    def test_rejects_non_bytes_payload(self) -> None:
        with pytest.raises(ValidationError, match="payload must be bytes"):
            picblobs.wrap_elf("not-bytes", "linux", "x86_64")


@pytest.mark.requires_blobs
class TestWrappedElfExecution:
    def test_linux_x86_64_hello_runs_without_runner(self, tmp_path: Path) -> None:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            pytest.skip("direct smoke test requires a Linux x86_64 host")

        exe = tmp_path / "hello-picblob"
        exe.write_bytes(Blob("linux", "x86_64").hello().build_elf())
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)

        try:
            result = subprocess.run(
                [str(exe)],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except OSError as e:
            if e.errno in {errno.EACCES, errno.ENOEXEC}:
                pytest.skip(f"host refused direct ELF execution: {e}")
            raise

        assert result.returncode == 0, result.stderr
        assert result.stdout == b"Hello, world!\n"
