"""picblobs enums — OS, Arch, BlobType.

Each enum accepts either its canonical string value or an enum member
so that the public builder API works uniformly with:

    picblobs.Blob("linux", "x86_64")
    picblobs.Blob(picblobs.OS.LINUX, picblobs.Arch.X86_64)

``parse`` coerces either form to the canonical member and raises
``ValidationError`` on unknown inputs so callers get a clear message
listing supported values instead of a bare ``KeyError``.
"""

from __future__ import annotations

import enum


class ValidationError(ValueError):
    """Raised when builder input fails validation (unknown target, bad
    parameter, missing required field, unsupported combination)."""


class OS(str, enum.Enum):
    LINUX = "linux"
    FREEBSD = "freebsd"
    WINDOWS = "windows"

    @classmethod
    def parse(cls, value: OS | str) -> OS:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value.lower())
            except ValueError:
                pass
        supported = ", ".join(m.value for m in cls)
        raise ValidationError(f"Unsupported OS {value!r}; supported: {supported}")


class Arch(str, enum.Enum):
    X86_64 = "x86_64"
    I686 = "i686"
    AARCH64 = "aarch64"
    ARMV5_ARM = "armv5_arm"
    ARMV5_THUMB = "armv5_thumb"
    ARMV7_THUMB = "armv7_thumb"
    MIPSEL32 = "mipsel32"
    MIPSBE32 = "mipsbe32"
    S390X = "s390x"
    SPARCV8 = "sparcv8"
    POWERPC = "powerpc"
    PPC64LE = "ppc64le"
    RISCV64 = "riscv64"

    @classmethod
    def parse(cls, value: Arch | str) -> Arch:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value.lower())
            except ValueError:
                pass
        supported = ", ".join(m.value for m in cls)
        raise ValidationError(f"Unsupported arch {value!r}; supported: {supported}")


class BlobType(str, enum.Enum):
    HELLO = "hello"
    HELLO_WINDOWS = "hello_windows"
    ALLOC_JUMP = "alloc_jump"
    REFLECTIVE_PE = "reflective_pe"
    STAGER_TCP = "stager_tcp"
    STAGER_FD = "stager_fd"
    STAGER_PIPE = "stager_pipe"
    STAGER_MMAP = "stager_mmap"
    UL_EXEC = "ul_exec"
    NACL_HELLO = "nacl_hello"
    NACL_CLIENT = "nacl_client"
    NACL_SERVER = "nacl_server"
    TEST_PASS = "test_pass"
    TEST_TCP_OK = "test_tcp_ok"
    TEST_FD_OK = "test_fd_ok"
    TEST_PIPE_OK = "test_pipe_ok"
    TEST_MMAP_OK = "test_mmap_ok"

    @classmethod
    def parse(cls, value: BlobType | str) -> BlobType:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value.lower())
            except ValueError:
                pass
        supported = ", ".join(m.value for m in cls)
        raise ValidationError(f"Unknown blob type {value!r}; supported: {supported}")
