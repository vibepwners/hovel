"""Canonical platform registry — single source of truth.

Every architecture, OS, platform combination, and syscall number
is defined HERE. All other files that enumerate platforms, architectures,
or syscall numbers must be generated from or validated against this registry.

To add a new architecture:
  1. Add an entry to ARCHITECTURES below (with traits).
  2. Add syscall numbers to SYSCALL_NUMBERS[os][gcc_define].
  3. Add the syscall asm primitive to src/include/picblobs/syscall.h.
  4. Add the _start stub to tests/runners/{os}/runner.c.
  5. Run: task generate      (regenerates derived files)
  6. Run: task test:unit     (catches anything you missed)

To add a new OS:
  1. Add an entry to OPERATING_SYSTEMS below.
  2. Add syscall numbers to SYSCALL_NUMBERS[os].
  3. Create tests/runners/{os}/runner.c with a test runner.
  4. Run: task generate
  5. Run: task test:unit

To add a new syscall:
  1. Add the number to every arch in SYSCALL_NUMBERS[os].
  2. Add a SyscallDef entry to SYSCALL_DEFS.
  3. Run: python tools/generate.py  (generates sys/{name}.h with numbers + wrapper)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Architecture:
    """Defines a target architecture and all its properties."""

    # Canonical name used in Python/CLI (e.g., "x86_64", "mipsel32").
    name: str

    # GCC compiler predefined macro (e.g., "__x86_64__", "__mips__").
    gcc_define: str

    # QEMU user-static binary name (e.g., "qemu-x86_64-static").
    qemu_binary: str

    # Bootlin toolchain archive architecture slug.
    bootlin_arch: str

    # GCC target triple (e.g., "x86_64-buildroot-linux-gnu").
    gcc_triple: str

    # Bootlin libc variant ("glibc", "musl", "uclibc").
    bootlin_libc: str = "glibc"

    # Extra compiler flags for this architecture.
    extra_cflags: list[str] = field(default_factory=list)

    # Bazel @platforms//cpu constraint value (e.g., "@platforms//cpu:x86_64").
    # Custom constraints use "//modules/picblobs/platforms:{name}" format.
    cpu_constraint: str = ""

    # Architecture traits — central place for per-arch boolean decisions.
    uses_mmap2: bool = False  # Uses mmap2 syscall with page-unit offset.
    uses_old_mmap: bool = (
        False  # Uses old_mmap (args via struct pointer, not registers).
    )
    openat_only: bool = False  # No legacy open syscall (use openat).
    needs_got_reloc: bool = False  # Needs GOT self-relocation (PIC_SELF_RELOCATE).
    needs_trampoline: bool = False  # Needs entry trampoline for PIC setup.
    is_32bit: bool = False  # 32-bit architecture (affects lseek, etc.).
    is_big_endian: bool = False  # Big-endian byte order.

    # Bootlin toolchain version.
    bootlin_version: str = "2024.05-1"

    # SHA256 of the Bootlin archive (empty = unpinned).
    bootlin_sha256: str = ""


@dataclass(frozen=True)
class OperatingSystem:
    """Defines a target operating system."""

    # Canonical name (e.g., "linux", "freebsd", "windows").
    name: str

    # Architectures supported on this OS.
    architectures: list[str]

    # Runner type for test execution.
    runner_type: str = ""

    def __post_init__(self) -> None:
        if not self.runner_type:
            object.__setattr__(self, "runner_type", self.name)


# ============================================================
# Architecture definitions
# ============================================================

ARCHITECTURES: dict[str, Architecture] = {}


def _register_arch(arch: Architecture) -> None:
    ARCHITECTURES[arch.name] = arch


_register_arch(
    Architecture(
        name="x86_64",
        gcc_define="__x86_64__",
        qemu_binary="qemu-x86_64-static",
        bootlin_arch="x86-64",
        gcc_triple="x86_64-buildroot-linux-gnu",
        extra_cflags=["-march=x86-64"],
        cpu_constraint="@platforms//cpu:x86_64",
    )
)

_register_arch(
    Architecture(
        name="i686",
        gcc_define="__i386__",
        qemu_binary="qemu-i386-static",
        bootlin_arch="x86-i686",
        gcc_triple="i686-buildroot-linux-gnu",
        extra_cflags=["-march=i686"],
        cpu_constraint="@platforms//cpu:x86_32",
        uses_mmap2=True,
        is_32bit=True,
    )
)

_register_arch(
    Architecture(
        name="aarch64",
        gcc_define="__aarch64__",
        qemu_binary="qemu-aarch64-static",
        bootlin_arch="aarch64",
        gcc_triple="aarch64-buildroot-linux-gnu",
        cpu_constraint="@platforms//cpu:aarch64",
        openat_only=True,
    )
)

_register_arch(
    Architecture(
        name="armv5_arm",
        gcc_define="__arm__",
        qemu_binary="qemu-arm-static",
        bootlin_arch="armv5-eabi",
        gcc_triple="arm-buildroot-linux-gnueabi",
        extra_cflags=["-march=armv5te"],
        cpu_constraint="@platforms//cpu:arm",
        uses_mmap2=True,
        is_32bit=True,
    )
)

_register_arch(
    Architecture(
        name="armv5_thumb",
        gcc_define="__arm__",
        qemu_binary="qemu-arm-static",
        bootlin_arch="armv5-eabi",
        gcc_triple="arm-buildroot-linux-gnueabi",
        extra_cflags=["-march=armv5te"],
        cpu_constraint="@platforms//cpu:arm",
        uses_mmap2=True,
        is_32bit=True,
    )
)

_register_arch(
    Architecture(
        name="armv7_thumb",
        gcc_define="__arm__",
        qemu_binary="qemu-arm-static",
        bootlin_arch="armv7-eabihf",
        gcc_triple="arm-buildroot-linux-gnueabihf",
        extra_cflags=["-march=armv7-a", "-mthumb"],
        cpu_constraint="@platforms//cpu:armv7",
        uses_mmap2=True,
        is_32bit=True,
    )
)

_register_arch(
    Architecture(
        name="mipsel32",
        gcc_define="__mips__",
        qemu_binary="qemu-mipsel-static",
        bootlin_arch="mips32el",
        gcc_triple="mipsel-buildroot-linux-gnu",
        extra_cflags=["-mips32", "-EL"],
        cpu_constraint="//modules/picblobs/platforms:mipsel32",
        uses_mmap2=True,
        needs_got_reloc=True,
        needs_trampoline=True,
        is_32bit=True,
    )
)

_register_arch(
    Architecture(
        name="s390x",
        gcc_define="__s390x__",
        qemu_binary="qemu-s390x-static",
        bootlin_arch="s390x-z13",
        gcc_triple="s390x-buildroot-linux-gnu",
        extra_cflags=["-march=z13"],
        cpu_constraint="@platforms//cpu:s390x",
        uses_old_mmap=True,
        is_big_endian=True,
    )
)

_register_arch(
    Architecture(
        name="mipsbe32",
        gcc_define="__mips__",
        qemu_binary="qemu-mips-static",
        bootlin_arch="mips32",
        gcc_triple="mips-buildroot-linux-gnu",
        extra_cflags=["-mips32", "-EB"],
        cpu_constraint="//modules/picblobs/platforms:mipsbe32",
        uses_mmap2=True,
        needs_got_reloc=True,
        needs_trampoline=True,
        is_32bit=True,
        is_big_endian=True,
    )
)

_register_arch(
    Architecture(
        name="sparcv8",
        gcc_define="__sparc__",
        qemu_binary="qemu-sparc-static",
        bootlin_arch="sparcv8",
        bootlin_libc="uclibc",
        gcc_triple="sparc-buildroot-linux-uclibc",
        extra_cflags=["-mcpu=v8"],
        cpu_constraint="//modules/picblobs/platforms:sparcv8",
        uses_mmap2=True,
        is_32bit=True,
        is_big_endian=True,
        bootlin_sha256="8ec2c84b84a13b854a13802537f0b04848056ebc65f6212202f6d8c8a78d4bc3",
    )
)

_register_arch(
    Architecture(
        name="powerpc",
        gcc_define="__powerpc__",
        qemu_binary="qemu-ppc-static",
        bootlin_arch="powerpc-e300c3",
        gcc_triple="powerpc-buildroot-linux-gnu",
        extra_cflags=["-mcpu=e300c3"],
        cpu_constraint="@platforms//cpu:ppc32",
        uses_mmap2=True,
        needs_got_reloc=True,
        is_32bit=True,
        is_big_endian=True,
        bootlin_sha256="6c975a7293fde77a52f348124049645ee2ceee19e75ab6e0b2364043090a2dff",
    )
)

_register_arch(
    Architecture(
        name="ppc64le",
        gcc_define="__powerpc64__",
        qemu_binary="qemu-ppc64le-static",
        bootlin_arch="powerpc64le-power8",
        gcc_triple="powerpc64le-buildroot-linux-gnu",
        extra_cflags=["-mcpu=power8"],
        cpu_constraint="@platforms//cpu:ppc64le",
        bootlin_sha256="8133b74614f880eb8b76730efee77b8fd281c982bfa2791b72c5f836a529530d",
    )
)

_register_arch(
    Architecture(
        name="riscv64",
        gcc_define="__riscv",
        qemu_binary="qemu-riscv64-static",
        bootlin_arch="riscv64-lp64d",
        gcc_triple="riscv64-buildroot-linux-gnu",
        cpu_constraint="@platforms//cpu:riscv64",
        openat_only=True,
        bootlin_sha256="78e16f3def8b2ff3da09c16155f993ac7e4dc1791d0904ada03fcb2e04910aab",
    )
)


# ============================================================
# OS definitions
# ============================================================

OPERATING_SYSTEMS: dict[str, OperatingSystem] = {}


def _register_os(os: OperatingSystem) -> None:
    OPERATING_SYSTEMS[os.name] = os


_register_os(
    OperatingSystem(
        name="linux",
        architectures=[
            "x86_64",
            "i686",
            "aarch64",
            "armv5_arm",
            "armv5_thumb",
            "armv7_thumb",
            "s390x",
            "mipsel32",
            "mipsbe32",
            "sparcv8",
            "powerpc",
            "ppc64le",
            "riscv64",
        ],
    )
)

_register_os(
    OperatingSystem(
        name="freebsd",
        architectures=[
            "x86_64",
            "i686",
            "aarch64",
            "armv5_arm",
            "armv5_thumb",
            "armv7_thumb",
            "mipsel32",
            "mipsbe32",
        ],
    )
)

_register_os(
    OperatingSystem(
        name="windows",
        architectures=["x86_64", "i686", "aarch64"],
    )
)


# ============================================================
# Syscall numbers — the data that generates sys/{os}/nr.h
# ============================================================
#
# Structure: SYSCALL_NUMBERS[os][gcc_define][syscall_name] = number
# Every gcc_define block within an OS must define the SAME set of
# syscall names. test_sync.py enforces this.

SYSCALL_NUMBERS: dict[str, dict[str, dict[str, int]]] = {
    "linux": {
        "__x86_64__": {
            "read": 0,
            "write": 1,
            "open": 2,
            "close": 3,
            "fstat": 5,
            "lseek": 8,
            "mmap": 9,
            "mprotect": 10,
            "munmap": 11,
            "socket": 41,
            "connect": 42,
            "accept": 43,
            "bind": 49,
            "listen": 50,
            "setsockopt": 54,
            "dup2": 33,
            "pipe": 22,
            "exit": 60,
            "exit_group": 231,
        },
        "__i386__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "lseek": 19,
            "llseek": 140,
            "mmap": 192,
            "mprotect": 125,
            "munmap": 91,
            "socket": 359,
            "connect": 362,
            "accept": 364,
            "bind": 361,
            "listen": 363,
            "setsockopt": 366,
            "dup2": 63,
            "pipe": 42,
            "fstat": 108,
            "exit": 1,
            "exit_group": 252,
        },
        "__aarch64__": {
            "read": 63,
            "write": 64,
            "openat": 56,
            "close": 57,
            "lseek": 62,
            "mmap": 222,
            "mprotect": 226,
            "munmap": 215,
            "socket": 198,
            "connect": 203,
            "accept": 202,
            "bind": 200,
            "listen": 201,
            "setsockopt": 208,
            "exit": 93,
            "exit_group": 94,
        },
        "__arm__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "lseek": 19,
            "llseek": 140,
            "mmap": 192,
            "mprotect": 125,
            "munmap": 91,
            "socket": 281,
            "connect": 283,
            "accept": 285,
            "bind": 282,
            "listen": 284,
            "setsockopt": 294,
            "dup2": 63,
            "pipe": 42,
            "fstat": 108,
            "exit": 1,
            "exit_group": 248,
        },
        "__s390x__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "fstat": 108,
            "lseek": 19,
            "mmap": 90,
            "mprotect": 125,
            "munmap": 91,
            "socket": 359,
            "connect": 362,
            "accept": 364,
            "bind": 361,
            "listen": 363,
            "setsockopt": 366,
            "dup2": 63,
            "pipe": 42,
            "exit": 1,
            "exit_group": 248,
        },
        "__sparc__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "fstat": 62,
            "lseek": 19,
            "llseek": 236,
            "mmap": 56,
            "mprotect": 74,
            "munmap": 73,
            "socket": 97,
            "connect": 98,
            "accept": 99,
            "bind": 353,
            "listen": 354,
            "setsockopt": 355,
            "dup2": 90,
            "pipe": 42,
            "exit": 1,
            "exit_group": 188,
        },
        "__powerpc__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "fstat": 108,
            "lseek": 19,
            "llseek": 140,
            "mmap": 192,
            "mprotect": 125,
            "munmap": 91,
            "socket": 326,
            "connect": 328,
            "accept": 330,
            "bind": 327,
            "listen": 329,
            "setsockopt": 339,
            "dup2": 63,
            "pipe": 42,
            "exit": 1,
            "exit_group": 234,
        },
        "__powerpc64__": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "fstat": 108,
            "lseek": 19,
            "mmap": 90,
            "mprotect": 125,
            "munmap": 91,
            "socket": 326,
            "connect": 328,
            "accept": 330,
            "bind": 327,
            "listen": 329,
            "setsockopt": 339,
            "dup2": 63,
            "pipe": 42,
            "exit": 1,
            "exit_group": 234,
        },
        "__riscv": {
            "read": 63,
            "write": 64,
            "openat": 56,
            "close": 57,
            "fstat": 80,
            "lseek": 62,
            "mmap": 222,
            "mprotect": 226,
            "munmap": 215,
            "socket": 198,
            "connect": 203,
            "accept": 202,
            "bind": 200,
            "listen": 201,
            "setsockopt": 208,
            "exit": 93,
            "exit_group": 94,
        },
        "__mips__": {
            "read": 4003,
            "write": 4004,
            "open": 4005,
            "close": 4006,
            "lseek": 4019,
            "llseek": 4140,
            "mmap": 4210,
            "mprotect": 4125,
            "munmap": 4091,
            "socket": 4183,
            "connect": 4170,
            "accept": 4168,
            "bind": 4169,
            "listen": 4174,
            "setsockopt": 4181,
            "exit": 4001,
            "exit_group": 4246,
        },
    },
    "freebsd": {
        # FreeBSD syscall numbers are architecture-independent.
        "_all_": {
            "read": 3,
            "write": 4,
            "open": 5,
            "close": 6,
            "lseek": 478,
            "mmap": 477,
            "mprotect": 74,
            "munmap": 73,
            "socket": 97,
            "connect": 98,
            "accept": 30,
            "bind": 104,
            "listen": 106,
            "setsockopt": 105,
            "exit": 1,
            "exit_group": 431,
        },
    },
}

# mmap flag values — architecture/OS-specific.
# Structure: MMAP_FLAGS[flag_group] = {gcc_define_or_os: value, ...}
MMAP_FLAGS: dict[str, dict[str, int]] = {
    "MAP_SHARED": {"_default_": 0x01, "__mips__": 0x001},
    "MAP_PRIVATE": {"_default_": 0x02, "__mips__": 0x002},
    "MAP_FIXED": {"_default_": 0x10, "__mips__": 0x010},
    "MAP_ANONYMOUS": {
        "_default_": 0x20,
        "__mips__": 0x800,
        "freebsd": 0x1000,
    },
}

# ============================================================
# Syscall wrapper definitions — drives sys/{name}.h generation
# ============================================================
#
# Each entry describes one syscall's C wrapper function.
# The generator combines these with SYSCALL_NUMBERS to produce
# a fully self-contained sys/{name}.h header.


@dataclass(frozen=True)
class SyscallDef:
    """Defines how to generate a syscall wrapper function."""

    name: str  # syscall name (matches SYSCALL_NUMBERS keys)
    wrapper: str  # C function name
    return_type: str  # "long", "void *", "void"
    params: str  # C parameter list
    call_args: str  # args passed to pic_syscallN (after __NR_)
    arg_count: int  # number of args to pic_syscallN
    noreturn: bool = False  # __attribute__((noreturn))
    # If set, this is emitted instead of the default wrapper body.
    # Use {NR} as placeholder for the __NR_ macro name.
    custom_body: str = ""
    # Related constants to embed in this syscall's header.
    constants: str = ""
    # Hosted-mode vtable call expression (e.g., "__pic_plat->write(fd, buf, count)").
    # When set, a PIC_PLATFORM_HOSTED block is generated that delegates to the
    # pic_platform vtable instead of issuing a raw syscall.
    hosted_call: str = ""


SYSCALL_DEFS: dict[str, SyscallDef] = {}


def _def_syscall(s: SyscallDef) -> None:
    SYSCALL_DEFS[s.name] = s


# --- simple syscalls ---

_def_syscall(
    SyscallDef(
        name="read",
        wrapper="pic_read",
        return_type="long",
        params="int fd, void *buf, pic_size_t count",
        call_args="fd, (long)buf, count",
        arg_count=3,
        hosted_call="__pic_plat->read(fd, buf, count)",
    )
)

_def_syscall(
    SyscallDef(
        name="write",
        wrapper="pic_write",
        return_type="long",
        params="int fd, const void *buf, pic_size_t count",
        call_args="fd, (long)buf, count",
        arg_count=3,
        hosted_call="__pic_plat->write(fd, buf, count)",
    )
)

_def_syscall(
    SyscallDef(
        name="close",
        wrapper="pic_close",
        return_type="long",
        params="int fd",
        call_args="fd",
        arg_count=1,
        hosted_call="__pic_plat->close(fd)",
    )
)

_def_syscall(
    SyscallDef(
        name="lseek",
        wrapper="pic_lseek",
        return_type="long",
        params="int fd, long offset, int whence",
        call_args="fd, offset, whence",
        arg_count=3,
        constants="\n".join(
            [
                "#define PIC_SEEK_SET 0",
                "#define PIC_SEEK_CUR 1",
                "#define PIC_SEEK_END 2",
            ]
        ),
    )
)

_def_syscall(
    SyscallDef(
        name="mprotect",
        wrapper="pic_mprotect",
        return_type="long",
        params="void *addr, pic_size_t len, int prot",
        call_args="(long)addr, len, prot",
        arg_count=3,
        constants="\n".join(
            [
                "#define PIC_PROT_NONE    0x0",
                "#define PIC_PROT_READ    0x1",
                "#define PIC_PROT_WRITE   0x2",
                "#define PIC_PROT_EXEC    0x4",
            ]
        ),
    )
)

_def_syscall(
    SyscallDef(
        name="munmap",
        wrapper="pic_munmap",
        return_type="long",
        params="void *addr, pic_size_t len",
        call_args="(long)addr, len",
        arg_count=2,
    )
)

_def_syscall(
    SyscallDef(
        name="exit",
        wrapper="pic_exit",
        return_type="void",
        params="int code",
        call_args="code",
        arg_count=1,
        noreturn=True,
    )
)

_def_syscall(
    SyscallDef(
        name="exit_group",
        wrapper="pic_exit_group",
        return_type="void",
        params="int code",
        call_args="code",
        arg_count=1,
        noreturn=True,
        hosted_call="__pic_plat->exit_group(code)",
    )
)

# --- complex syscalls (custom bodies) ---

_def_syscall(
    SyscallDef(
        name="open",
        wrapper="pic_open",
        return_type="long",
        params="const char *path, int flags, int mode",
        call_args="",
        arg_count=0,  # unused — custom body
        custom_body="""\
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

static inline long pic_open(const char *path, int flags, int mode) {
#ifdef __NR_openat
    return pic_syscall4(__NR_openat, AT_FDCWD, (long)path, flags, mode);
#elif defined(__NR_open)
    return pic_syscall3(__NR_open, (long)path, flags, mode);
#else
#error "pic_open() requires __NR_open or __NR_openat"
#endif
}""",
        constants="\n".join(
            [
                "#define PIC_O_RDONLY 0",
                "#define PIC_O_WRONLY 1",
                "#define PIC_O_RDWR   2",
            ]
        ),
    )
)

_def_syscall(
    SyscallDef(
        name="mmap",
        wrapper="pic_mmap",
        return_type="void *",
        params="void *addr, pic_size_t len, int prot, int flags, int fd, long offset",
        call_args="",
        arg_count=0,  # unused — custom body
        custom_body="""\
#define _PIC_MMAP2_SHIFT 12

static inline void *pic_mmap(void *addr, pic_size_t len, int prot,
                             int flags, int fd, long offset) {
#if PIC_ARCH_USES_OLD_MMAP
    /* s390x old_mmap: args passed via struct pointer in r2. */
    unsigned long args[6] = {
        (unsigned long)addr, (unsigned long)len, (unsigned long)prot,
        (unsigned long)flags, (unsigned long)fd, (unsigned long)offset
    };
    return (void *)pic_syscall1(__NR_mmap, (long)args);
#elif PIC_ARCH_USES_MMAP2
    return (void *)pic_syscall6(__NR_mmap, (long)addr, len, prot, flags, fd, offset >> _PIC_MMAP2_SHIFT);
#else
    return (void *)pic_syscall6(__NR_mmap, (long)addr, len, prot, flags, fd, offset);
#endif
}""",
    )
)

# --- networking + misc syscalls (numbers defined, wrappers for future use) ---

_def_syscall(
    SyscallDef(
        name="socket",
        wrapper="pic_socket",
        return_type="long",
        params="int domain, int type, int protocol",
        call_args="domain, type, protocol",
        arg_count=3,
        hosted_call="__pic_plat->socket(domain, type, protocol)",
    )
)

_def_syscall(
    SyscallDef(
        name="connect",
        wrapper="pic_connect",
        return_type="long",
        params="int sockfd, const void *addr, pic_size_t addrlen",
        call_args="sockfd, (long)addr, addrlen",
        arg_count=3,
        hosted_call="__pic_plat->connect(sockfd, addr, addrlen)",
    )
)

_def_syscall(
    SyscallDef(
        name="accept",
        wrapper="pic_accept",
        return_type="long",
        params="int sockfd, void *addr, void *addrlen",
        call_args="sockfd, (long)addr, (long)addrlen",
        arg_count=3,
        hosted_call="__pic_plat->accept(sockfd, addr, addrlen)",
    )
)

_def_syscall(
    SyscallDef(
        name="bind",
        wrapper="pic_bind",
        return_type="long",
        params="int sockfd, const void *addr, pic_size_t addrlen",
        call_args="sockfd, (long)addr, addrlen",
        arg_count=3,
        hosted_call="__pic_plat->bind(sockfd, addr, addrlen)",
    )
)

_def_syscall(
    SyscallDef(
        name="listen",
        wrapper="pic_listen",
        return_type="long",
        params="int sockfd, int backlog",
        call_args="sockfd, backlog",
        arg_count=2,
        hosted_call="__pic_plat->listen(sockfd, backlog)",
    )
)

_def_syscall(
    SyscallDef(
        name="setsockopt",
        wrapper="pic_setsockopt",
        return_type="long",
        params="int sockfd, int level, int optname, const void *optval, pic_size_t optlen",
        call_args="sockfd, level, optname, (long)optval, optlen",
        arg_count=5,
        hosted_call="__pic_plat->setsockopt(sockfd, level, optname, optval, optlen)",
    )
)

_def_syscall(
    SyscallDef(
        name="dup2",
        wrapper="pic_dup2",
        return_type="long",
        params="int oldfd, int newfd",
        call_args="oldfd, newfd",
        arg_count=2,
    )
)

_def_syscall(
    SyscallDef(
        name="pipe",
        wrapper="pic_pipe",
        return_type="long",
        params="int *pipefd",
        call_args="(long)pipefd",
        arg_count=1,
    )
)

_def_syscall(
    SyscallDef(
        name="fstat",
        wrapper="pic_fstat",
        return_type="long",
        params="int fd, void *statbuf",
        call_args="fd, (long)statbuf",
        arg_count=2,
    )
)

_def_syscall(
    SyscallDef(
        name="llseek",
        wrapper="pic_llseek",
        return_type="long",
        params="int fd, unsigned long offset_high, unsigned long offset_low, void *result, unsigned int whence",
        call_args="fd, offset_high, offset_low, (long)result, whence",
        arg_count=5,
    )
)

# The mmap constants (MAP_* flags) are handled specially by the generator
# because they're arch+OS-specific. See MMAP_FLAGS above.


# ============================================================
# Blob type catalog — drives manifest.json generation
# ============================================================
#
# Each entry describes a blob type: what it does, which platforms it
# supports, and the layout of its config struct (if any).


@dataclass(frozen=True)
class ConfigField:
    """One field in a config struct's fixed-size header."""

    name: str
    type: str  # "u8", "u16", "u32", "u64", "uintptr", "bytes:N"
    offset: int


@dataclass(frozen=True)
class TrailingData:
    """A variable-length data buffer that follows the fixed config header."""

    name: str
    length_field: str  # name of the ConfigField whose value is this buffer's size


@dataclass(frozen=True)
class ConfigSchema:
    """Binary layout of a blob's config struct."""

    fixed_size: int
    fields: list[ConfigField]
    trailing_data: list[TrailingData] = field(default_factory=list)


@dataclass(frozen=True)
class BlobType:
    """Defines a blob type and its metadata for the release manifest."""

    name: str
    description: str
    has_config: bool
    platforms: dict[str, list[str]]  # os -> [arch, ...]
    config_schema: ConfigSchema | None = None
    staged_name: str = ""  # override filename when staging (e.g. "alloc_jump")
    pytest_enabled: bool = False
    pytest_stdout: bytes | None = None
    pytest_stdout_contains: bytes | None = None
    pytest_exit_code: int = 0
    pytest_timeout: float = 30.0


BLOB_TYPES: dict[str, BlobType] = {}


def _register_blob(bt: BlobType) -> None:
    BLOB_TYPES[bt.name] = bt


# Helper: all arches for an OS.
def _os_arches(os_name: str) -> list[str]:
    return OPERATING_SYSTEMS[os_name].architectures


def blob_public_name(blob: BlobType) -> str:
    """Return the public staged name for a blob type."""
    return blob.staged_name or blob.name


_register_blob(
    BlobType(
        name="hello",
        description="Minimal hello-world syscall test",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"Hello, world!\n",
        pytest_timeout=10.0,
    )
)

_register_blob(
    BlobType(
        name="hello_windows",
        description="Minimal hello-world for Windows (TEB-based)",
        has_config=False,
        platforms={
            "windows": _os_arches("windows"),
        },
        pytest_enabled=True,
        pytest_stdout=b"Hello, world!\n",
        pytest_timeout=10.0,
    )
)

_register_blob(
    BlobType(
        name="test_tcp_ok",
        description="Inner test payload for stager_tcp (writes TCP_OK)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
    )
)

_register_blob(
    BlobType(
        name="stager_tcp",
        description="TCP connect-back stager (read payload, alloc RWX, jump)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"TCP_OK",
        config_schema=ConfigSchema(
            fixed_size=7,
            fields=[
                ConfigField(name="af", type="u8", offset=0),
                ConfigField(name="port", type="u16", offset=1),
                ConfigField(name="addr", type="u8[4]", offset=3),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_fd",
        description="File-descriptor stager (read payload from fd, alloc RWX, jump)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"FD_OK",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=4,
            fields=[
                ConfigField(name="fd", type="u32", offset=0),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_pipe",
        description="Named-pipe stager (open FIFO, read payload, alloc RWX, jump)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout_contains=b"PIPE_OK",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=2,
            fields=[
                ConfigField(name="path_len", type="u16", offset=0),
            ],
            trailing_data=[
                TrailingData(name="path", length_field="path_len"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_mmap",
        description="Mmap-file stager (open file, read segment, alloc RWX, jump)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"MMAP_OK",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=2,
            fields=[
                ConfigField(name="path_len", type="u16", offset=0),
            ],
            trailing_data=[
                TrailingData(name="path", length_field="path_len"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="test_fd_ok",
        description="Inner test payload for stager_fd (writes FD_OK)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
    )
)

_register_blob(
    BlobType(
        name="test_pipe_ok",
        description="Inner test payload for stager_pipe (writes PIPE_OK)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
    )
)

_register_blob(
    BlobType(
        name="test_mmap_ok",
        description="Inner test payload for stager_mmap (writes MMAP_OK)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
    )
)

_register_blob(
    BlobType(
        name="nacl_hello",
        description="NaCl crypto self-test (TweetNaCl)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"NaCl OK\n",
        pytest_timeout=15.0,
    )
)

_register_blob(
    BlobType(
        name="nacl_client",
        description="NaCl encrypted TCP client (raw syscalls)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        config_schema=ConfigSchema(
            fixed_size=34,
            fields=[
                ConfigField(name="port", type="u16", offset=0),
                # 32-byte handshake auth key, injected per deployment (never
                # embedded). Seals the ephemeral X25519 public-key exchange.
                ConfigField(name="auth_key", type="u8[32]", offset=2),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="nacl_server",
        description="NaCl encrypted TCP server (raw syscalls)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        config_schema=ConfigSchema(
            fixed_size=34,
            fields=[
                ConfigField(name="port", type="u16", offset=0),
                # 32-byte handshake auth key, injected per deployment (never
                # embedded). Seals the ephemeral X25519 public-key exchange.
                ConfigField(name="auth_key", type="u8[32]", offset=2),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="nacl_client_hosted",
        description="NaCl encrypted TCP client (hosted platform vtable)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        config_schema=ConfigSchema(
            fixed_size=34,
            fields=[
                ConfigField(name="port", type="u16", offset=0),
                # 32-byte handshake auth key, injected per deployment (never
                # embedded). Seals the ephemeral X25519 public-key exchange.
                ConfigField(name="auth_key", type="u8[32]", offset=2),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="nacl_server_hosted",
        description="NaCl encrypted TCP server (hosted platform vtable)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        config_schema=ConfigSchema(
            fixed_size=34,
            fields=[
                ConfigField(name="port", type="u16", offset=0),
                # 32-byte handshake auth key, injected per deployment (never
                # embedded). Seals the ephemeral X25519 public-key exchange.
                ConfigField(name="auth_key", type="u8[32]", offset=2),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="test_pass",
        description="Minimal inner payload for alloc_jump testing (writes PASS)",
        has_config=False,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
    )
)

_register_blob(
    BlobType(
        name="alloc_jump",
        description="Allocate RWX memory, copy inner payload, jump (unix: mmap)",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": _os_arches("freebsd"),
        },
        pytest_enabled=True,
        pytest_stdout=b"PASS",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=4,
            fields=[
                ConfigField(name="payload_size", type="u32", offset=0),
            ],
            trailing_data=[
                TrailingData(name="payload_data", length_field="payload_size"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_fd_windows",
        description="Windows stager_fd: read length-prefixed payload from stdin HANDLE",
        has_config=True,
        platforms={
            "windows": _os_arches("windows"),
        },
        staged_name="stager_fd",
        pytest_enabled=True,
        pytest_stdout=b"FD_OK",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=4,
            fields=[
                ConfigField(name="stream_id", type="u32", offset=0),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_pipe_windows",
        description="Windows stager_pipe: CreateFileA a pipe path, read payload",
        has_config=True,
        platforms={
            "windows": _os_arches("windows"),
        },
        staged_name="stager_pipe",
        pytest_enabled=True,
        pytest_stdout_contains=b"PIPE_OK",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=2,
            fields=[
                ConfigField(name="path_len", type="u16", offset=0),
            ],
            trailing_data=[
                TrailingData(name="path", length_field="path_len"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="stager_tcp_windows",
        description="Windows stager_tcp: Winsock connect-back stager",
        has_config=True,
        platforms={
            "windows": _os_arches("windows"),
        },
        staged_name="stager_tcp",
        pytest_enabled=True,
        pytest_stdout=b"TCP_OK",
        config_schema=ConfigSchema(
            fixed_size=7,
            fields=[
                ConfigField(name="af", type="u8", offset=0),
                ConfigField(name="port", type="u16", offset=1),
                ConfigField(name="addr", type="u8[4]", offset=3),
            ],
            trailing_data=[],
        ),
    )
)

_register_blob(
    BlobType(
        name="reflective_pe_windows",
        description="Reflective PE loader: validate headers, alloc RWX, signal LOADED",
        has_config=True,
        platforms={
            "windows": _os_arches("windows"),
        },
        staged_name="reflective_pe",
        pytest_enabled=True,
        pytest_stdout_contains=b"LOADED",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=9,
            fields=[
                ConfigField(name="pe_size", type="u32", offset=0),
                ConfigField(name="flags", type="u32", offset=4),
                ConfigField(name="entry_type", type="u8", offset=8),
            ],
            trailing_data=[
                TrailingData(name="pe_data", length_field="pe_size"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="alloc_jump_windows",
        description="Allocate RWX memory, copy inner payload, jump (Windows TEB)",
        has_config=True,
        platforms={
            "windows": _os_arches("windows"),
        },
        staged_name="alloc_jump",
        pytest_enabled=True,
        pytest_stdout=b"PASS",
        pytest_timeout=15.0,
        config_schema=ConfigSchema(
            fixed_size=4,
            fields=[
                ConfigField(name="payload_size", type="u32", offset=0),
            ],
            trailing_data=[
                TrailingData(name="payload_data", length_field="payload_size"),
            ],
        ),
    )
)

_register_blob(
    BlobType(
        name="ul_exec",
        description="Userland ELF reflective loader",
        has_config=True,
        platforms={
            "linux": _os_arches("linux"),
            "freebsd": ["x86_64"],
        },
        config_schema=ConfigSchema(
            fixed_size=20,
            fields=[
                ConfigField(name="elf_size", type="u32", offset=0),
                ConfigField(name="argc", type="u32", offset=4),
                ConfigField(name="argv_size", type="u32", offset=8),
                ConfigField(name="envp_count", type="u32", offset=12),
                ConfigField(name="envp_size", type="u32", offset=16),
            ],
            trailing_data=[
                TrailingData(name="elf_data", length_field="elf_size"),
                TrailingData(name="argv_data", length_field="argv_size"),
                TrailingData(name="envp_data", length_field="envp_size"),
            ],
        ),
    )
)


# Symbols that the linker script must define and the extractor reads.
# Single source of truth for the linker ↔ extractor contract.
LINKER_SYMBOLS = {
    "blob_start": "__blob_start",
    "blob_end": "__blob_end",
    "config_start": "__config_start",
    "got_start": "__got_start",
    "got_end": "__got_end",
}


# ============================================================
# Derived helpers — computed from the registry above
# ============================================================


def qemu_binaries() -> dict[str, str]:
    """Return {arch_name: qemu_binary_name} for all architectures."""
    return {name: arch.qemu_binary for name, arch in ARCHITECTURES.items()}


def platform_configs() -> dict[str, tuple[str, str]]:
    """Return {os:arch: (bazel_config, runner_type)} for all active platforms."""
    result = {}
    for os_name, os_def in OPERATING_SYSTEMS.items():
        for arch_name in os_def.architectures:
            key = f"{os_name}:{arch_name}"
            bazel_config = f"{os_name}_{arch_name}"
            result[key] = (bazel_config, os_def.runner_type)
    return result


def all_platforms() -> list[tuple[str, str]]:
    """Return [(os, arch), ...] for all defined platforms."""
    result = []
    for os_name, os_def in OPERATING_SYSTEMS.items():
        result.extend((os_name, arch_name) for arch_name in os_def.architectures)
    return result


def gcc_defines() -> set[str]:
    """Return the set of unique GCC architecture defines."""
    return {arch.gcc_define for arch in ARCHITECTURES.values()}


def syscall_os_support(syscall_name: str) -> dict[str, dict[str, int]]:
    """Return {os: {gcc_define: number}} for a given syscall.

    For OSes with architecture-independent numbers (_all_), expands
    to all gcc_defines with the same number.

    Also checks related names (e.g., "open" finds "openat" on aarch64).
    """
    # Related syscall names that should be treated as the same module.
    related_map: dict[str, set[str]] = {
        "open": {"open", "openat"},
        "lseek": {"lseek", "llseek"},
    }
    names_to_check = related_map.get(syscall_name, {syscall_name})

    result: dict[str, dict[str, int]] = {}
    for os_name, arch_tables in SYSCALL_NUMBERS.items():
        if "_all_" in arch_tables:
            for name in names_to_check:
                nr = arch_tables["_all_"].get(name)
                if nr is not None:
                    result[os_name] = {"_all_": nr}
                    break
        else:
            per_arch: dict[str, int] = {}
            for gcc_define, nrs in arch_tables.items():
                for name in names_to_check:
                    if name in nrs:
                        per_arch[gcc_define] = nrs[name]
                        break
            if per_arch:
                result[os_name] = per_arch
    return result


def all_syscall_names() -> set[str]:
    """Return the union of all syscall names across all OSes."""
    names: set[str] = set()
    for arch_tables in SYSCALL_NUMBERS.values():
        for nrs in arch_tables.values():
            names.update(nrs.keys())
    return names


def arches_with_trait(trait: str) -> list[str]:
    """Return architecture names where the given trait is True."""
    return [name for name, arch in ARCHITECTURES.items() if getattr(arch, trait, False)]


def manifest_architectures() -> dict[str, dict[str, object]]:
    """Return the architectures section for manifest.json."""
    result = {}
    for name, arch in ARCHITECTURES.items():
        result[name] = {
            "bits": 32 if arch.is_32bit else 64,
            "endian": "big" if arch.is_big_endian else "little",
            "gcc_triple": arch.gcc_triple,
        }
    return result


def arch_endian(arch_name: str) -> str:
    """Return 'little' or 'big' for the given architecture."""
    arch = ARCHITECTURES.get(arch_name)
    if arch is not None and arch.is_big_endian:
        return "big"
    return "little"
