"""Architecture validation for staged Picblobs binaries."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

if TYPE_CHECKING:
    from pathlib import Path

_ELF_MAGIC = b"\x7fELF"
_PE_DOS_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
_PE_HEADER_OFFSET_POSITION = 0x3C
_PE_MACHINE_OFFSET = len(_PE_SIGNATURE)
_PE_HEADER_OFFSET_SIZE = 4
_PE_MACHINE_SIZE = 2

_ELF_MACHINES: dict[str, tuple[str, bool | None]] = {
    "x86_64": ("EM_X86_64", None),
    "i686": ("EM_386", None),
    "aarch64": ("EM_AARCH64", None),
    "armv5_arm": ("EM_ARM", None),
    "armv5_thumb": ("EM_ARM", None),
    "armv7_thumb": ("EM_ARM", None),
    "s390x": ("EM_S390", False),
    "mipsel32": ("EM_MIPS", True),
    "mipsbe32": ("EM_MIPS", False),
    "sparcv8": ("EM_SPARC", False),
    "powerpc": ("EM_PPC", False),
    "ppc64le": ("EM_PPC64", True),
    "riscv64": ("EM_RISCV", True),
}

_PE_MACHINES = {
    "i686": 0x014C,
    "x86_64": 0x8664,
    "armv7_thumb": 0x01C4,
    "aarch64": 0xAA64,
}


def verify_artifact_arch(path: Path, expected_arch: str) -> bool:
    """Return whether an ELF or PE artifact matches ``expected_arch``."""
    try:
        with path.open("rb") as artifact:
            magic = artifact.read(len(_ELF_MAGIC))
            artifact.seek(0)
            if magic == _ELF_MAGIC:
                return _verify_elf_arch(artifact, expected_arch)
            if magic.startswith(_PE_DOS_MAGIC):
                return _verify_pe_arch(artifact, expected_arch)
    except (ELFError, OSError, struct.error):
        return False
    return False


def _verify_elf_arch(artifact, expected_arch: str) -> bool:
    expected = _ELF_MACHINES.get(expected_arch)
    if expected is None:
        return False
    expected_machine, expected_little_endian = expected
    elf = ELFFile(artifact)
    return elf.header.e_machine == expected_machine and (
        expected_little_endian is None or elf.little_endian == expected_little_endian
    )


def _verify_pe_arch(artifact, expected_arch: str) -> bool:
    expected_machine = _PE_MACHINES.get(expected_arch)
    if expected_machine is None:
        return False

    artifact.seek(_PE_HEADER_OFFSET_POSITION)
    offset_bytes = artifact.read(_PE_HEADER_OFFSET_SIZE)
    if len(offset_bytes) != _PE_HEADER_OFFSET_SIZE:
        return False
    pe_offset = struct.unpack("<I", offset_bytes)[0]

    artifact.seek(pe_offset)
    if artifact.read(len(_PE_SIGNATURE)) != _PE_SIGNATURE:
        return False
    artifact.seek(pe_offset + _PE_MACHINE_OFFSET)
    machine_bytes = artifact.read(_PE_MACHINE_SIZE)
    if len(machine_bytes) != _PE_MACHINE_SIZE:
        return False
    return struct.unpack("<H", machine_bytes)[0] == expected_machine
