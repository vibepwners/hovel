"""Pure-Python ELF wrapping for flat picblobs payloads.

This module intentionally writes only the small executable subset needed to
let Linux load a finalized flat blob directly:

    ELF header + one PT_LOAD program header + page padding + payload bytes

Section headers are omitted. They are useful to linkers and debugging tools,
but the Linux program loader uses program headers to build the process image.
"""

from __future__ import annotations

import dataclasses
import struct

from picblobs._enums import OS, Arch, ValidationError

EI_NIDENT = 16
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
EV_CURRENT = 1
ELFOSABI_SYSV = 0

ET_EXEC = 2
PT_LOAD = 1

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

DEFAULT_SEGMENT_FLAGS = PF_R | PF_W | PF_X
DEFAULT_PAGE_SIZE = 0x1000
DEFAULT_SEGMENT_OFFSET = 0x1000


@dataclasses.dataclass(frozen=True)
class _ElfArch:
    elf_class: int
    data: int
    machine: int
    flags: int = 0
    base_vaddr: int = 0x400000
    thumb_entry: bool = False

    @property
    def endian(self) -> str:
        return "<" if self.data == ELFDATA2LSB else ">"


# Machine constants are the generic ELF e_machine values used by Linux.
# e_flags values mirror the staged toolchain output for architectures where
# Linux or tooling expects ABI details beyond e_machine.
_LINUX_ARCHES: dict[Arch, _ElfArch] = {
    Arch.X86_64: _ElfArch(ELFCLASS64, ELFDATA2LSB, 62, base_vaddr=0x400000),
    Arch.I686: _ElfArch(ELFCLASS32, ELFDATA2LSB, 3, base_vaddr=0x08048000),
    Arch.AARCH64: _ElfArch(ELFCLASS64, ELFDATA2LSB, 183, base_vaddr=0x400000),
    Arch.ARMV5_ARM: _ElfArch(
        ELFCLASS32,
        ELFDATA2LSB,
        40,
        flags=0x05000200,
        base_vaddr=0x00010000,
    ),
    Arch.ARMV5_THUMB: _ElfArch(
        ELFCLASS32,
        ELFDATA2LSB,
        40,
        flags=0x05000200,
        base_vaddr=0x00010000,
    ),
    Arch.ARMV7_THUMB: _ElfArch(
        ELFCLASS32,
        ELFDATA2LSB,
        40,
        flags=0x05000400,
        base_vaddr=0x00010000,
        thumb_entry=True,
    ),
    Arch.MIPSEL32: _ElfArch(
        ELFCLASS32,
        ELFDATA2LSB,
        8,
        flags=0x50001007,
        base_vaddr=0x00400000,
    ),
    Arch.MIPSBE32: _ElfArch(
        ELFCLASS32,
        ELFDATA2MSB,
        8,
        flags=0x50001007,
        base_vaddr=0x00400000,
    ),
    Arch.S390X: _ElfArch(ELFCLASS64, ELFDATA2MSB, 22, base_vaddr=0x00400000),
    Arch.SPARCV8: _ElfArch(ELFCLASS32, ELFDATA2MSB, 2, base_vaddr=0x00010000),
    Arch.POWERPC: _ElfArch(
        ELFCLASS32,
        ELFDATA2MSB,
        20,
        flags=0x00008000,
        base_vaddr=0x01000000,
    ),
    Arch.PPC64LE: _ElfArch(
        ELFCLASS64,
        ELFDATA2LSB,
        21,
        flags=0x00000002,
        base_vaddr=0x10000000,
    ),
    Arch.RISCV64: _ElfArch(
        ELFCLASS64,
        ELFDATA2LSB,
        243,
        flags=0x00000004,
        base_vaddr=0x00010000,
    ),
}


def _ident(arch: _ElfArch) -> bytes:
    ident = bytearray(EI_NIDENT)
    ident[0:4] = b"\x7fELF"
    ident[4] = arch.elf_class
    ident[5] = arch.data
    ident[6] = EV_CURRENT
    ident[7] = ELFOSABI_SYSV
    return bytes(ident)


def _pack_ehdr32(
    arch: _ElfArch,
    entry: int,
    phoff: int,
    phentsize: int,
    phnum: int,
) -> bytes:
    return struct.pack(
        f"{arch.endian}16sHHIIIIIHHHHHH",
        _ident(arch),
        ET_EXEC,
        arch.machine,
        EV_CURRENT,
        entry,
        phoff,
        0,  # e_shoff: no section header table
        arch.flags,
        52,
        phentsize,
        phnum,
        0,
        0,
        0,
    )


def _pack_ehdr64(
    arch: _ElfArch,
    entry: int,
    phoff: int,
    phentsize: int,
    phnum: int,
) -> bytes:
    return struct.pack(
        f"{arch.endian}16sHHIQQQIHHHHHH",
        _ident(arch),
        ET_EXEC,
        arch.machine,
        EV_CURRENT,
        entry,
        phoff,
        0,  # e_shoff: no section header table
        arch.flags,
        64,
        phentsize,
        phnum,
        0,
        0,
        0,
    )


def _pack_phdr32(
    arch: _ElfArch,
    segment_offset: int,
    base_vaddr: int,
    payload_size: int,
    flags: int,
    align: int,
) -> bytes:
    return struct.pack(
        f"{arch.endian}IIIIIIII",
        PT_LOAD,
        segment_offset,
        base_vaddr,
        base_vaddr,
        payload_size,
        payload_size,
        flags,
        align,
    )


def _pack_phdr64(
    arch: _ElfArch,
    segment_offset: int,
    base_vaddr: int,
    payload_size: int,
    flags: int,
    align: int,
) -> bytes:
    return struct.pack(
        f"{arch.endian}IIQQQQQQ",
        PT_LOAD,
        flags,
        segment_offset,
        base_vaddr,
        base_vaddr,
        payload_size,
        payload_size,
        align,
    )


def _check_u32(name: str, value: int) -> None:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValidationError(f"{name} {value:#x} does not fit in ELF32")


def _validate_power_of_two(name: str, value: int) -> None:
    if value <= 0 or value & (value - 1):
        raise ValidationError(f"{name} must be a positive power of two")


def _validate_wrap_inputs(
    payload: bytes,
    arch: _ElfArch,
    entry_offset: int,
    base_vaddr: int,
    segment_offset: int,
    page_size: int,
    segment_flags: int,
) -> None:
    _validate_payload(payload)
    _validate_entry_offset(entry_offset, len(payload))
    _validate_layout_values(
        base_vaddr,
        segment_offset,
        page_size,
        segment_flags,
    )
    if arch.elf_class == ELFCLASS32:
        _validate_elf32_limits(payload, entry_offset, base_vaddr, segment_offset)


def _validate_payload(payload: bytes) -> None:
    if not isinstance(payload, (bytes, bytearray)):
        raise ValidationError("payload must be bytes")
    if not payload:
        raise ValidationError("payload must be non-empty")


def _validate_entry_offset(entry_offset: int, payload_size: int) -> None:
    if not isinstance(entry_offset, int) or isinstance(entry_offset, bool):
        raise ValidationError("entry_offset must be int")
    if entry_offset < 0 or entry_offset >= payload_size:
        raise ValidationError(
            f"entry_offset {entry_offset} is outside payload size {payload_size}"
        )


def _validate_layout_values(
    base_vaddr: int,
    segment_offset: int,
    page_size: int,
    segment_flags: int,
) -> None:
    for name, value in (
        ("base_vaddr", base_vaddr),
        ("segment_offset", segment_offset),
        ("page_size", page_size),
        ("segment_flags", segment_flags),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"{name} must be int")
    _validate_power_of_two("page_size", page_size)
    if segment_offset < page_size:
        raise ValidationError("segment_offset must be at least one page")
    if (base_vaddr % page_size) != (segment_offset % page_size):
        raise ValidationError("base_vaddr and segment_offset must be page-congruent")
    if segment_flags & ~(PF_R | PF_W | PF_X):
        raise ValidationError("segment_flags may only contain PF_R, PF_W, and PF_X")


def _validate_elf32_limits(
    payload: bytes,
    entry_offset: int,
    base_vaddr: int,
    segment_offset: int,
) -> None:
    for name, value in (
        ("base_vaddr", base_vaddr),
        ("entry", base_vaddr + entry_offset),
        ("payload size", len(payload)),
        ("segment_offset", segment_offset),
    ):
        _check_u32(name, value)


def linux_elf_entry(
    target_arch: Arch | str,
    entry_offset: int = 0,
    base_vaddr: int | None = None,
) -> tuple[int, int]:
    """Return ``(base_vaddr, entry_pc)`` for a Linux ELF-wrapped blob.

    Mirrors the address arithmetic in :func:`wrap_elf` so callers (notably the
    ``debug`` command) can predict where a wrapped blob loads and where its
    first instruction lives without re-implementing the per-arch layout. The
    returned ``entry_pc`` carries the Thumb low bit for Thumb targets, matching
    the ELF ``e_entry`` value.

    Raises:
        ValidationError: For architectures ELF wrapping does not support.
    """
    arch_e = Arch.parse(target_arch)
    arch = _LINUX_ARCHES.get(arch_e)
    if arch is None:
        raise ValidationError(f"ELF wrapping does not support arch {arch_e.value}")
    base = arch.base_vaddr if base_vaddr is None else base_vaddr
    entry = base + entry_offset
    if arch.thumb_entry:
        entry |= 1
    return base, entry


def wrap_elf(
    payload: bytes,
    target_os: OS | str,
    target_arch: Arch | str,
    *,
    entry_offset: int = 0,
    base_vaddr: int | None = None,
    segment_offset: int = DEFAULT_SEGMENT_OFFSET,
    page_size: int = DEFAULT_PAGE_SIZE,
    segment_flags: int = DEFAULT_SEGMENT_FLAGS,
) -> bytes:
    """Wrap a finalized flat blob in a minimal Linux ELF executable.

    Args:
        payload: Complete flat blob bytes. For configurable blobs, pass the
            fully assembled code+config bytes returned by the builder API.
        target_os: Currently only ``"linux"`` is supported.
        target_arch: Target architecture string or ``Arch`` enum.
        entry_offset: Payload-relative entry offset. picblobs payloads enter at
            offset 0, so the default is correct for normal use.
        base_vaddr: Virtual address where the payload segment should be loaded.
            Defaults to a conservative per-architecture executable base.
        segment_offset: File offset where payload bytes begin. Must be congruent
            to ``base_vaddr`` modulo ``page_size``.
        page_size: ELF segment alignment. Defaults to 4096.
        segment_flags: Program-header permissions. Defaults to RWX to match the
            existing Linux runner and support writable in-blob data/GOT.

    Returns:
        A complete ELF executable as ``bytes``.

    Raises:
        ValidationError: For unsupported targets or invalid layout parameters.
    """
    os_ = OS.parse(target_os)
    arch_e = Arch.parse(target_arch)
    if os_ is not OS.LINUX:
        raise ValidationError("ELF wrapping currently supports linux targets only")
    arch = _LINUX_ARCHES.get(arch_e)
    if arch is None:
        raise ValidationError(f"ELF wrapping does not support arch {arch_e.value}")

    base = arch.base_vaddr if base_vaddr is None else base_vaddr
    _validate_wrap_inputs(
        payload,
        arch,
        entry_offset,
        base,
        segment_offset,
        page_size,
        segment_flags,
    )
    payload = bytes(payload)

    entry = base + entry_offset
    if arch.thumb_entry:
        entry |= 1

    if arch.elf_class == ELFCLASS32:
        ehdr_size = 52
        phdr_size = 32
        ehdr = _pack_ehdr32(arch, entry, ehdr_size, phdr_size, 1)
        phdr = _pack_phdr32(
            arch,
            segment_offset,
            base,
            len(payload),
            segment_flags,
            page_size,
        )
    else:
        ehdr_size = 64
        phdr_size = 56
        ehdr = _pack_ehdr64(arch, entry, ehdr_size, phdr_size, 1)
        phdr = _pack_phdr64(
            arch,
            segment_offset,
            base,
            len(payload),
            segment_flags,
            page_size,
        )

    header = ehdr + phdr
    if len(header) > segment_offset:
        raise ValidationError("segment_offset is too small for ELF headers")
    return header + (b"\x00" * (segment_offset - len(header))) + payload


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_SEGMENT_FLAGS",
    "DEFAULT_SEGMENT_OFFSET",
    "PF_R",
    "PF_W",
    "PF_X",
    "linux_elf_entry",
    "wrap_elf",
]
