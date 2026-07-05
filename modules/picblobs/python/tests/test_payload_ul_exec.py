"""Payload tests for ul_exec (userland exec) blob.

ul_exec loads an ELF binary from its config buffer and executes it
without using execve(). Tests verify both static and dynamically
linked ELFs.

See: spec/verification/TEST-011-payload-pytest-suite.md
"""

from __future__ import annotations

import pytest
from payload_defs import OPERATING_SYSTEMS
from picblobs import get_blob
from picblobs._cross_compile import build_ul_exec_config, compile_c_elf
from picblobs.runner import is_arch_skip_rosetta, run_blob

try:
    from picblobs_cli import ul_exec_test_binary
except ImportError:  # pragma: no cover - picblobs-cli is a test dependency

    def ul_exec_test_binary(
        os_name: str,
        arch: str,
        name: str = "hello_et_exec",
    ) -> bytes | None:
        return None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


# ---------------------------------------------------------------------------
# Test ELF source code — uses libc for convenience.
# ---------------------------------------------------------------------------

# Static test: uses libc. Compiled with -static.
STATIC_LIBC_SRC = """\
#include <unistd.h>
#include <string.h>
int main(void) {
    const char msg[] = "UL_EXEC_OK\\n";
    write(1, msg, strlen(msg));
    return 0;
}
"""

# Dynamic test (x86_64 only): same source, no -static.
DYNAMIC_TEST_SRC = STATIC_LIBC_SRC

# Raw syscall test: no libc. Works on all arches.
# Each arch needs its own _start because syscall ABI differs.
# Raw syscall test programs. Must work both as non-PIE (ET_EXEC) and
# as PIE (ET_DYN). Use PC-relative addressing where possible; on arches
# without it, embed the string in .text right after the code.
RAW_SYSCALL_SRCS = {
    "x86_64": (
        ".text\n.globl _start\n_start:\n"
        "  mov $1, %eax\n  mov $1, %edi\n  lea msg(%rip), %rsi\n"
        "  mov $11, %edx\n  syscall\n"
        "  mov $231, %eax\n  xor %edi, %edi\n  syscall\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "i686": (
        # i686: no RIP-relative. Use call/pop to get PC, then add offset.
        ".text\n.globl _start\n_start:\n"
        "  call 1f\n"
        "1: pop %ecx\n"
        "  add $(msg - 1b), %ecx\n"
        "  mov $4, %eax\n  mov $1, %ebx\n"
        "  mov $11, %edx\n  int $0x80\n"
        "  mov $252, %eax\n  xor %ebx, %ebx\n  int $0x80\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "aarch64": (
        ".text\n.globl _start\n_start:\n"
        "  mov x8, #64\n  mov x0, #1\n  adr x1, msg\n"
        "  mov x2, #11\n  svc #0\n"
        "  mov x8, #94\n  mov x0, #0\n  svc #0\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "armv5_arm": (
        ".text\n.globl _start\n_start:\n"
        "  mov r7, #4\n  mov r0, #1\n  adr r1, msg\n"
        "  mov r2, #11\n  svc #0\n"
        "  mov r7, #248\n  mov r0, #0\n  svc #0\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "armv5_thumb": (
        ".syntax unified\n.text\n.globl _start\n.thumb_func\n_start:\n"
        "  movs r7, #4\n  movs r0, #1\n  adr r1, msg\n"
        "  movs r2, #11\n  svc #0\n"
        "  movs r7, #248\n  movs r0, #0\n  svc #0\n"
        '.align 2\nmsg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    # armv7_thumb: Thumb-2 uses the same Thumb-1 encodings for these
    # instructions — reuse the armv5_thumb source.
    "armv7_thumb": (
        ".syntax unified\n.text\n.globl _start\n.thumb_func\n_start:\n"
        "  movs r7, #4\n  movs r0, #1\n  adr r1, msg\n"
        "  movs r2, #11\n  svc #0\n"
        "  movs r7, #248\n  movs r0, #0\n  svc #0\n"
        '.align 2\nmsg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "mipsel32": (
        # MIPS: embed string in .text, use bal to get PC.
        ".set noreorder\n.text\n.globl _start\n_start:\n"
        "  li $v0, 4004\n"
        "  li $a0, 1\n"
        "  bal 1f\n"
        "  li $a2, 11\n"  # delay slot
        "1: addiu $a1, $ra, (msg - 1b)\n"
        "  syscall\n"
        "  li $v0, 4246\n  li $a0, 0\n  syscall\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "mipsbe32": (
        ".set noreorder\n.text\n.globl _start\n_start:\n"
        "  li $v0, 4004\n"
        "  li $a0, 1\n"
        "  bal 1f\n"
        "  li $a2, 11\n"
        "1: addiu $a1, $ra, (msg - 1b)\n"
        "  syscall\n"
        "  li $v0, 4246\n  li $a0, 0\n  syscall\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "s390x": (
        ".text\n.globl _start\n_start:\n"
        "  lghi %r1, 4\n  lghi %r2, 1\n  larl %r3, msg\n"
        "  lghi %r4, 11\n  svc 0\n"
        "  lghi %r1, 248\n  lghi %r2, 0\n  svc 0\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "sparcv8": (
        ".text\n.globl _start\n_start:\n"
        "  mov 4, %g1\n"
        "  mov 1, %o0\n"
        "  sethi %hi(msg), %o1\n"
        "  or %o1, %lo(msg), %o1\n"
        "  mov 11, %o2\n"
        "  ta 0x10\n"
        "  nop\n"
        "  mov 188, %g1\n"
        "  clr %o0\n"
        "  ta 0x10\n"
        "  nop\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "powerpc": (
        ".text\n.globl _start\n_start:\n"
        "  li 0, 4\n"
        "  li 3, 1\n"
        "  lis 4, msg@ha\n"
        "  addi 4, 4, msg@l\n"
        "  li 5, 11\n"
        "  sc\n"
        "  li 0, 234\n"
        "  li 3, 0\n"
        "  sc\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "ppc64le": (
        ".text\n.globl _start\n_start:\n"
        "  li 0, 4\n"
        "  li 3, 1\n"
        "  bl 1f\n"
        "1: mflr 4\n"
        "  addi 4, 4, msg-1b\n"
        "  li 5, 11\n"
        "  sc\n"
        "  li 0, 234\n"
        "  li 3, 0\n"
        "  sc\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
    "riscv64": (
        ".text\n.globl _start\n_start:\n"
        "  li a7, 64\n"
        "  li a0, 1\n"
        "  la a1, msg\n"
        "  li a2, 11\n"
        "  ecall\n"
        "  li a7, 94\n"
        "  li a0, 0\n"
        "  ecall\n"
        'msg: .ascii "UL_EXEC_OK\\n"\n'
    ),
}


# ---------------------------------------------------------------------------
# Available architectures for ul_exec (linux only, excluding s390x).
# ---------------------------------------------------------------------------


def _ul_exec_arches() -> list[str]:
    """Arches where ul_exec is built and staged."""
    all_arches = OPERATING_SYSTEMS["linux"].architectures
    return [a for a in all_arches if _blob_exists("ul_exec", "linux", a)]


# ---------------------------------------------------------------------------
# Tests: static ELF execution
# ---------------------------------------------------------------------------


class TestUlExecStatic:
    """Test ul_exec with statically linked ELFs on all architectures.

    Uses staged raw-syscall ET_EXEC fixtures from picblobs-cli so CI can
    exercise ul_exec without keeping cross-compilers in the test jobs.
    """

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize("target_arch", _ul_exec_arches())
    def test_static_elf_executes(self, target_arch: str) -> None:
        """Load and execute a static non-PIE (ET_EXEC) raw-syscall ELF.

        The blob self-remaps to a safe high address, munmaps the
        target's load range, then MAP_FIXED loads the ELF at its
        fixed address. This is the full userland exec path.
        """
        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        elf_data = ul_exec_test_binary("linux", target_arch)
        if elf_data is None:
            pytest.skip(f"No staged ul_exec test ELF for linux:{target_arch}")

        blob = get_blob("ul_exec", "linux", target_arch)
        config = build_ul_exec_config(
            elf_data, argv=["test_static"], target_arch=target_arch
        )

        result = run_blob(blob, config=config, timeout=30.0)

        assert result.exit_code == 0, (
            f"ul_exec linux:{target_arch}: "
            f"exit_code={result.exit_code}, "
            f"stdout={result.stdout!r}, "
            f"stderr={result.stderr!r}"
        )
        assert b"Hello, ul_exec!" in result.stdout, (
            f"ul_exec linux:{target_arch}: "
            f"stdout={result.stdout!r}, expected 'Hello, ul_exec!'"
        )

    @pytest.mark.requires_qemu
    @pytest.mark.requires_cross_compile
    def test_static_libc_elf_x86_64(self) -> None:
        """Static glibc binary on x86_64 (non-PIE, ET_EXEC)."""
        if not _blob_exists("ul_exec", "linux", "x86_64"):
            pytest.skip("ul_exec not staged for linux/x86_64")
        elf_data = compile_c_elf("x86_64", STATIC_LIBC_SRC, static=True)
        if elf_data is None:
            pytest.skip("Cannot compile static libc ELF for x86_64")

        blob = get_blob("ul_exec", "linux", "x86_64")
        config = build_ul_exec_config(
            elf_data, target_arch="x86_64", argv=["test_static_libc"]
        )
        result = run_blob(blob, config=config, timeout=30.0)

        assert result.exit_code == 0, (
            f"exit_code={result.exit_code}, stderr={result.stderr!r}"
        )
        assert b"UL_EXEC_OK" in result.stdout


# ---------------------------------------------------------------------------
# Tests: dynamic ELF execution (x86_64 only)
# ---------------------------------------------------------------------------


class TestUlExecDynamic:
    """Test ul_exec with dynamically linked ELFs (x86_64 only)."""

    @pytest.mark.requires_qemu
    @pytest.mark.requires_cross_compile
    def test_dynamic_elf_executes_x86_64(self) -> None:
        if not _blob_exists("ul_exec", "linux", "x86_64"):
            pytest.skip("ul_exec not staged for linux/x86_64")

        elf_data = compile_c_elf("x86_64", DYNAMIC_TEST_SRC, static=False)
        if elf_data is None:
            pytest.skip("Cannot compile dynamic test ELF for x86_64")

        blob = get_blob("ul_exec", "linux", "x86_64")
        config = build_ul_exec_config(
            elf_data,
            target_arch="x86_64",
            argv=["test_dynamic"],
            envp=["PATH=/usr/bin", "HOME=/tmp"],
        )

        result = run_blob(blob, config=config, timeout=30.0)

        assert result.exit_code == 0, (
            f"ul_exec dynamic linux:x86_64: "
            f"exit_code={result.exit_code}, "
            f"stdout={result.stdout!r}, "
            f"stderr={result.stderr!r}"
        )
        assert b"UL_EXEC_OK" in result.stdout


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestUlExecEdgeCases:
    """Error handling for ul_exec."""

    @pytest.mark.requires_qemu
    def test_invalid_elf_exits_cleanly(self) -> None:
        if not _blob_exists("ul_exec", "linux", "x86_64"):
            pytest.skip("ul_exec not staged for linux/x86_64")

        blob = get_blob("ul_exec", "linux", "x86_64")
        config = build_ul_exec_config(b"\x00" * 64, target_arch="x86_64", argv=["bad"])

        result = run_blob(blob, config=config, timeout=10.0)
        # Should exit with error code 101 (bad ELF magic)
        assert result.exit_code != 0

    @pytest.mark.requires_qemu
    def test_truncated_elf_exits_cleanly(self) -> None:
        if not _blob_exists("ul_exec", "linux", "x86_64"):
            pytest.skip("ul_exec not staged for linux/x86_64")

        blob = get_blob("ul_exec", "linux", "x86_64")
        # Valid ELF magic but truncated
        config = build_ul_exec_config(
            b"\x7fELF" + b"\x00" * 12,
            target_arch="x86_64",
            argv=["trunc"],
        )

        result = run_blob(blob, config=config, timeout=10.0)
        assert result.exit_code != 0
