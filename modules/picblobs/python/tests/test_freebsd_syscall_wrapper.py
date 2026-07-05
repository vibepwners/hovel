"""Verify FreeBSD pic_raw_syscall variants compile and produce correct code.

FreeBSD's syscall ABI signals errors via a carry flag (x86/ARM) and returns
errno as a positive value, unlike Linux which returns -errno directly.
The per-arch pic_raw_syscall wrappers must, when PICBLOBS_OS_FREEBSD is
defined, translate to the Linux convention so callers can uniformly check
``ret < 0`` for errors.

These tests compile a small probe for each arch and verify:

  1. The FreeBSD variant compiles without error.
  2. The generated code captures the error indicator (setc/mrs/etc.) and
     conditionally negates the return value.
  3. The non-FreeBSD variant does NOT contain those instructions (sanity).

Cross-compilers come from Bootlin toolchains provisioned by Bazel. Tests
are skipped if the toolchain isn't present (e.g., clean checkout before
first build).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

try:
    from ._test_env import PROJECT_ROOT
except ImportError:  # pragma: no cover - supports direct module import
    from _test_env import PROJECT_ROOT


PROBE_SOURCE = """
#include "picblobs/syscall.h"

extern long pic_test_call(long n, long a);
long pic_test_call(long n, long a)
{
\treturn pic_raw_syscall(n, a, 0, 0, 0, 0, 0);
}
"""

BAZEL_EXT = Path.home() / ".cache/bazel/_bazel_user"


def _find_cross_gcc(arch: str) -> Path | None:
    """Locate a Bootlin cross-gcc provisioned under the Bazel cache."""
    mapping = {
        "x86_64": ("bootlin_x86_64", "x86_64-buildroot-linux-gnu-gcc"),
        "i686": ("bootlin_i686", "i686-buildroot-linux-gnu-gcc"),
        "aarch64": ("bootlin_aarch64", "aarch64-buildroot-linux-gnu-gcc"),
        "armv5_arm": ("bootlin_armv5", "arm-buildroot-linux-gnueabi-gcc"),
        "mipsel32": ("bootlin_mipsel32", "mipsel-buildroot-linux-gnu-gcc"),
    }
    entry = mapping.get(arch)
    if entry is None:
        return None
    repo, binary = entry
    matches = sorted(BAZEL_EXT.glob(f"*/external/+bootlin+{repo}/bin/{binary}"))
    return matches[0] if matches else None


def _compile_probe(
    arch: str,
    tmp_path: Path,
    *,
    freebsd: bool,
) -> Path:
    """Compile the probe for *arch*, returning the resulting object file."""
    gcc = _find_cross_gcc(arch)
    if gcc is None:
        pytest.skip(f"Cross-gcc for {arch} not found (run task stage first)")

    src = tmp_path / f"probe_{arch}.c"
    src.write_text(PROBE_SOURCE)
    obj = tmp_path / f"probe_{arch}.o"

    cmd = [
        str(gcc),
        "-c",
        f"-I{PROJECT_ROOT}/src/include",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fPIC",
        "-Wall",
        "-Werror",
        "-Os",
        str(src),
        "-o",
        str(obj),
    ]
    if freebsd:
        cmd.insert(-3, "-DPICBLOBS_OS_FREEBSD=1")
    else:
        cmd.insert(-3, "-DPICBLOBS_OS_LINUX=1")

    result = subprocess.run(
        cmd, capture_output=True, check=False, text=True, timeout=30
    )
    assert result.returncode == 0, (
        f"compile failed for {arch} (freebsd={freebsd}):\n{result.stderr}"
    )
    return obj


def _objdump_bin(arch: str) -> Path | None:
    gcc = _find_cross_gcc(arch)
    if gcc is None:
        return None
    objdump = gcc.parent / gcc.name.replace("-gcc", "-objdump")
    return objdump if objdump.exists() else None


def _disassemble(arch: str, obj: Path) -> str:
    od = _objdump_bin(arch)
    assert od is not None, f"objdump for {arch} not found"
    result = subprocess.run(
        [str(od), "-d", str(obj)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    return result.stdout


# Per-arch tokens that should appear in the FreeBSD-variant disassembly.
_FREEBSD_MARKERS = {
    "x86_64": ["setb", "setc"],  # either mnemonic is fine
    "i686": ["setb", "setc"],
    "aarch64": ["nzcv"],
    "armv5_arm": ["apsr", "cpsr"],
    "mipsel32": ["beqz"],  # MIPS wrapper already negates; same asm
}


@pytest.mark.parametrize("arch", sorted(_FREEBSD_MARKERS))
def test_freebsd_variant_compiles(arch: str, tmp_path: Path) -> None:
    """FreeBSD-variant pic_raw_syscall must compile cleanly for each arch."""
    _compile_probe(arch, tmp_path, freebsd=True)


@pytest.mark.parametrize("arch", sorted(_FREEBSD_MARKERS))
def test_linux_variant_compiles(arch: str, tmp_path: Path) -> None:
    """Non-FreeBSD (default) path must still compile cleanly."""
    _compile_probe(arch, tmp_path, freebsd=False)


@pytest.mark.parametrize("arch", sorted(_FREEBSD_MARKERS))
def test_freebsd_variant_emits_error_capture(arch: str, tmp_path: Path) -> None:
    """FreeBSD variant must emit the arch's error-indicator capture insn."""
    if _find_cross_gcc(arch) is None:
        pytest.skip(f"Cross-gcc for {arch} not found")

    obj = _compile_probe(arch, tmp_path, freebsd=True)
    disasm = _disassemble(arch, obj).lower()
    markers = _FREEBSD_MARKERS[arch]
    assert any(m in disasm for m in markers), (
        f"{arch}: FreeBSD wrapper missing error-capture instruction "
        f"(expected one of {markers}). Disasm:\n{disasm}"
    )


def test_x86_64_linux_variant_does_not_negate(tmp_path: Path) -> None:
    """Regression: Linux x86_64 wrapper should not have setb/setc."""
    if _find_cross_gcc("x86_64") is None:
        pytest.skip("x86_64 cross-gcc not found")

    obj = _compile_probe("x86_64", tmp_path, freebsd=False)
    disasm = _disassemble("x86_64", obj).lower()
    assert "setb" not in disasm and "setc" not in disasm, (
        f"Linux x86_64 wrapper unexpectedly contains CF capture:\n{disasm}"
    )


def test_freebsd_variant_runs_on_linux_host(tmp_path: Path) -> None:
    """End-to-end on Linux host: FreeBSD-variant x86_64 wrapper returns the
    right value for a successful syscall, and normalizes errors to -errno.

    Linux kernels never set CF=1, so the FreeBSD wrapper's negation branch
    is dead on Linux — we want to prove the wrapper doesn't corrupt
    successful returns (e.g., by mis-reading flags or clobbering registers)
    and still returns negative errno on failure (which Linux produces
    natively as -errno in rax).
    """
    if os.uname().machine != "x86_64":
        pytest.skip("host must be x86_64 to execute freebsd-variant probe")

    host_gcc = "/usr/bin/gcc"
    if not Path(host_gcc).exists():
        pytest.skip("host gcc not found")

    # Linux __NR_write=1 on x86_64, __NR_close=3.
    src = tmp_path / "run_probe.c"
    src.write_text("""
#include "picblobs/syscall.h"

int main(void)
{
\tlong n = pic_raw_syscall(1, 1, (long)"ok\\n", 3, 0, 0, 0);
\tif (n != 3) return 10;
\tlong e = pic_raw_syscall(3, 999, 0, 0, 0, 0, 0);  /* close(bad fd) */
\tif (e >= 0) return 11;  /* must be negative errno */
\treturn 0;
}
""")
    out = tmp_path / "run_probe"
    cmd = [
        host_gcc,
        "-DPICBLOBS_OS_FREEBSD=1",
        f"-I{PROJECT_ROOT}/src/include",
        "-O2",
        "-Wall",
        "-Werror",
        str(src),
        "-o",
        str(out),
    ]
    r = subprocess.run(cmd, capture_output=True, check=False, text=True, timeout=30)
    assert r.returncode == 0, f"host compile failed:\n{r.stderr}"

    run = subprocess.run([str(out)], capture_output=True, check=False, timeout=10)
    assert run.returncode == 0, (
        f"FreeBSD wrapper failed: exit={run.returncode}, "
        f"stdout={run.stdout!r} stderr={run.stderr!r}"
    )
    assert run.stdout == b"ok\n"
