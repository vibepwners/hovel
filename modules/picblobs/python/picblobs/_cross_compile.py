"""Cross-compilation helpers for building test ELFs via Bootlin toolchains.

Used by build/staging tooling and optional developer tests to compile
small architecture-specific test binaries from the same Bootlin
toolchains as the blobs.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from pathlib import Path

# Map picblobs arch names to GCC cross-compiler triples.
ARCH_TO_TRIPLE: dict[str, str] = {
    "x86_64": "x86_64-buildroot-linux-gnu",
    "i686": "i686-buildroot-linux-gnu",
    "aarch64": "aarch64-buildroot-linux-gnu",
    "armv5_arm": "arm-buildroot-linux-gnueabi",
    "armv5_thumb": "arm-buildroot-linux-gnueabi",
    "armv7_thumb": "arm-buildroot-linux-gnueabihf",
    "mipsel32": "mipsel-buildroot-linux-gnu",
    "mipsbe32": "mips-buildroot-linux-gnu",
    "s390x": "s390x-buildroot-linux-gnu",
    "sparcv8": "sparc-buildroot-linux-uclibc",
    "powerpc": "powerpc-buildroot-linux-gnu",
    "ppc64le": "powerpc64le-buildroot-linux-gnu",
    "riscv64": "riscv64-buildroot-linux-gnu",
}

# Map picblobs arch names to Bootlin toolchain directory names.
ARCH_TO_BOOTLIN: dict[str, str] = {
    "x86_64": "x86_64",
    "i686": "i686",
    "aarch64": "aarch64",
    "armv5_arm": "armv5",
    "armv5_thumb": "armv5",
    "armv7_thumb": "armv7",
    "mipsel32": "mipsel32",
    "mipsbe32": "mipsbe32",
    "s390x": "s390x",
    "sparcv8": "sparcv8",
    "powerpc": "powerpc",
    "ppc64le": "ppc64le",
    "riscv64": "riscv64",
}

# Extra compiler flags for specific arches.
ARCH_EXTRA_CFLAGS: dict[str, list[str]] = {
    "armv5_thumb": ["-mthumb"],
    "armv7_thumb": ["-march=armv7-a", "-mthumb"],
    "powerpc": ["-mcpu=e300c3"],
    "ppc64le": ["-mcpu=power8"],
}

# Big-endian architectures.
BIG_ENDIAN_ARCHES: set[str] = {"mipsbe32", "s390x"}
BIG_ENDIAN_ARCHES.add("sparcv8")
BIG_ENDIAN_ARCHES.add("powerpc")

# Per-arch raw-syscall _start that writes "Hello, ul_exec!\n" and exits.
# Each uses PC-relative data access so it works as both ET_EXEC and ET_DYN.
_MSG = "Hello, ul_exec!\\n"

HELLO_ET_EXEC_ASM: dict[str, str] = {
    "x86_64": (
        f".text\n.globl _start\n_start:\n"
        f"  mov $1, %eax\n  mov $1, %edi\n  lea msg(%rip), %rsi\n"
        f"  mov $16, %edx\n  syscall\n"
        f"  mov $231, %eax\n  xor %edi, %edi\n  syscall\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "i686": (
        f".text\n.globl _start\n_start:\n"
        f"  call 1f\n"
        f"1: pop %ecx\n"
        f"  add $(msg - 1b), %ecx\n"
        f"  mov $4, %eax\n  mov $1, %ebx\n"
        f"  mov $16, %edx\n  int $0x80\n"
        f"  mov $252, %eax\n  xor %ebx, %ebx\n  int $0x80\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "aarch64": (
        f".text\n.globl _start\n_start:\n"
        f"  mov x8, #64\n  mov x0, #1\n  adr x1, msg\n"
        f"  mov x2, #16\n  svc #0\n"
        f"  mov x8, #94\n  mov x0, #0\n  svc #0\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "armv5_arm": (
        f".text\n.globl _start\n_start:\n"
        f"  mov r7, #4\n  mov r0, #1\n  adr r1, msg\n"
        f"  mov r2, #16\n  svc #0\n"
        f"  mov r7, #248\n  mov r0, #0\n  svc #0\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "armv5_thumb": (
        f".syntax unified\n.text\n.globl _start\n.thumb_func\n_start:\n"
        f"  movs r7, #4\n  movs r0, #1\n  adr r1, msg\n"
        f"  movs r2, #16\n  svc #0\n"
        f"  movs r7, #248\n  movs r0, #0\n  svc #0\n"
        f'.align 2\nmsg: .ascii "{_MSG}"\n'
    ),
    "armv7_thumb": (
        f".syntax unified\n.text\n.globl _start\n.thumb_func\n_start:\n"
        f"  movs r7, #4\n  movs r0, #1\n  adr r1, msg\n"
        f"  movs r2, #16\n  svc #0\n"
        f"  movs r7, #248\n  movs r0, #0\n  svc #0\n"
        f'.align 2\nmsg: .ascii "{_MSG}"\n'
    ),
    "mipsel32": (
        f".set noreorder\n.text\n.globl _start\n_start:\n"
        f"  li $v0, 4004\n"
        f"  li $a0, 1\n"
        f"  bal 1f\n"
        f"  li $a2, 16\n"
        f"1: addiu $a1, $ra, (msg - 1b)\n"
        f"  syscall\n"
        f"  li $v0, 4246\n  li $a0, 0\n  syscall\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "mipsbe32": (
        f".set noreorder\n.text\n.globl _start\n_start:\n"
        f"  li $v0, 4004\n"
        f"  li $a0, 1\n"
        f"  bal 1f\n"
        f"  li $a2, 16\n"
        f"1: addiu $a1, $ra, (msg - 1b)\n"
        f"  syscall\n"
        f"  li $v0, 4246\n  li $a0, 0\n  syscall\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "s390x": (
        # s390x: write(1, msg, 16) = svc 0 with r1=4, r2=fd, r3=buf, r4=len
        # exit_group(0) = svc 0 with r1=248, r2=0
        f".text\n.globl _start\n_start:\n"
        f"  lghi %r1, 4\n"  # __NR_write
        f"  lghi %r2, 1\n"  # fd=stdout
        f"  larl %r3, msg\n"  # PC-relative address of msg
        f"  lghi %r4, 16\n"  # len
        f"  svc 0\n"
        f"  lghi %r1, 248\n"  # __NR_exit_group
        f"  lghi %r2, 0\n"  # code=0
        f"  svc 0\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "sparcv8": (
        f".text\n.globl _start\n_start:\n"
        f"  mov 4, %g1\n"
        f"  mov 1, %o0\n"
        f"  sethi %hi(msg), %o1\n"
        f"  or %o1, %lo(msg), %o1\n"
        f"  mov 16, %o2\n"
        f"  ta 0x10\n"
        f"  nop\n"
        f"  mov 188, %g1\n"
        f"  clr %o0\n"
        f"  ta 0x10\n"
        f"  nop\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "powerpc": (
        f".text\n.globl _start\n_start:\n"
        f"  li 0, 4\n"
        f"  li 3, 1\n"
        f"  lis 4, msg@ha\n"
        f"  addi 4, 4, msg@l\n"
        f"  li 5, 16\n"
        f"  sc\n"
        f"  li 0, 234\n"
        f"  li 3, 0\n"
        f"  sc\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "ppc64le": (
        f".text\n.globl _start\n_start:\n"
        f"  li 0, 4\n"
        f"  li 3, 1\n"
        f"  bl 1f\n"
        f"1: mflr 4\n"
        f"  addi 4, 4, msg-1b\n"
        f"  li 5, 16\n"
        f"  sc\n"
        f"  li 0, 234\n"
        f"  li 3, 0\n"
        f"  sc\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
    "riscv64": (
        f".text\n.globl _start\n_start:\n"
        f"  li a7, 64\n  li a0, 1\n  la a1, msg\n"
        f"  li a2, 16\n  ecall\n"
        f"  li a7, 94\n  li a0, 0\n  ecall\n"
        f'msg: .ascii "{_MSG}"\n'
    ),
}


def _find_bazel_output_base() -> Path | None:
    """Find Bazel's output_base from an explicit environment contract."""
    output_base = os.environ.get("PICBLOBS_BAZEL_OUTPUT_BASE")
    if not output_base:
        return None
    path = Path(output_base)
    return path if path.exists() else None


def find_gcc(arch: str) -> str | None:
    """Find the Bootlin cross-compiler GCC for an architecture."""
    triple = ARCH_TO_TRIPLE.get(arch)
    bootlin_name = ARCH_TO_BOOTLIN.get(arch)
    if not triple or not bootlin_name:
        return None

    output_base = _find_bazel_output_base()
    if output_base:
        candidates = [
            output_base
            / "external"
            / f"+bootlin+bootlin_{bootlin_name}"
            / "bin"
            / f"{triple}-gcc",
            output_base / f"+bootlin+bootlin_{bootlin_name}" / "bin" / f"{triple}-gcc",
        ]
        for gcc_path in candidates:
            if gcc_path.exists():
                return str(gcc_path)

    return None


def find_sysroot(arch: str) -> str | None:
    """Find the Bootlin sysroot for an architecture."""
    triple = ARCH_TO_TRIPLE.get(arch)
    bootlin_name = ARCH_TO_BOOTLIN.get(arch)
    if not triple or not bootlin_name:
        return None

    output_base = _find_bazel_output_base()
    if output_base:
        candidates = [
            output_base
            / "external"
            / f"+bootlin+bootlin_{bootlin_name}"
            / f"{triple}"
            / "sysroot",
            output_base / f"+bootlin+bootlin_{bootlin_name}" / f"{triple}" / "sysroot",
        ]
        for sysroot in candidates:
            if sysroot.exists():
                return str(sysroot)

    return None


def compile_c_elf(
    arch: str,
    source: str,
    *,
    static: bool = True,
    extra_cflags: list[str] | None = None,
) -> bytes | None:
    """Compile a C source to an ELF binary using the Bootlin cross-compiler."""
    gcc = find_gcc(arch)
    if gcc is None:
        return None

    sysroot = find_sysroot(arch)

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "test.c"
        out_path = Path(tmpdir) / "test.elf"
        src_path.write_text(source)

        cmd = [gcc]
        if sysroot:
            cmd.append(f"--sysroot={sysroot}")
        cmd.extend([str(src_path), "-o", str(out_path), "-O2"])
        if static:
            cmd.append("-static")
        if extra_cflags:
            cmd.extend(extra_cflags)
        cmd.extend(ARCH_EXTRA_CFLAGS.get(arch, []))

        result = subprocess.run(cmd, capture_output=True, check=False, timeout=30)
        if result.returncode != 0:
            return None

        return out_path.read_bytes()


def compile_raw_elf(arch: str, asm_source: str, *, pie: bool = False) -> bytes | None:
    """Compile an asm source to an ELF binary without libc.

    If ``pie`` is True, emits an ET_DYN binary via ``-shared``.
    Otherwise emits a static non-PIE ET_EXEC binary.
    """
    gcc = find_gcc(arch)
    if gcc is None:
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "test.S"
        out_path = Path(tmpdir) / "test.elf"
        src_path.write_text(asm_source)

        cmd = [
            gcc,
            str(src_path),
            "-o",
            str(out_path),
            "-nostdlib",
            "-nostartfiles",
        ]
        if pie:
            cmd.extend(["-shared", "-Wl,-e,_start"])
        else:
            cmd.append("-static")
        cmd.extend(ARCH_EXTRA_CFLAGS.get(arch, []))

        result = subprocess.run(cmd, capture_output=True, check=False, timeout=30)
        if result.returncode != 0:
            return None

        return out_path.read_bytes()


def compile_hello_et_exec(arch: str) -> bytes | None:
    """Compile a 'Hello, ul_exec!' test binary for the given architecture.

    Returns the static non-PIE ELF binary as bytes, or None.
    """
    asm = HELLO_ET_EXEC_ASM.get(arch)
    if asm is None:
        return None
    return compile_raw_elf(arch, asm)


def build_ul_exec_config(
    elf_data: bytes,
    target_arch: str,
    argv: list[str] | None = None,
    envp: list[str] | None = None,
) -> bytes:
    """Build the ul_exec config struct in target-native byte order."""
    if argv is None:
        argv = ["payload"]
    if envp is None:
        envp = []

    argv_data = b""
    for a in argv:
        argv_data += a.encode() + b"\x00"

    envp_data = b""
    for e in envp:
        envp_data += e.encode() + b"\x00"

    endian = ">" if target_arch in BIG_ENDIAN_ARCHES else "<"
    header = struct.pack(
        f"{endian}IIIII",
        len(elf_data),
        len(argv),
        len(argv_data),
        len(envp),
        len(envp_data),
    )
    return header + elf_data + argv_data + envp_data
