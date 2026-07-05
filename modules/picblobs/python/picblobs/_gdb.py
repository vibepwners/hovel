"""Cross-toolchain gdb resolution for the ``debug`` command.

Resolves an architecture-appropriate gdb binary. Native targets prefer the
plain system ``gdb``; cross targets prefer an arch-specific ``<triple>-gdb``,
then ``gdb-multiarch`` (which can debug any target the build of gdb supports).
Mirrors the search strategy in :mod:`picblobs._objdump`: the Bazel-provisioned
Bootlin toolchain first, then system binaries on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path

# Architecture → arch-specific cross gdb candidates (without the multiarch /
# plain fallbacks, which are added by _gdb_candidates). The names mirror the
# Bootlin and Debian cross-toolchain conventions used in _objdump.py.
CROSS_GDB_BINARIES: dict[str, list[str]] = {
    "x86_64": ["x86_64-buildroot-linux-gnu-gdb", "x86_64-linux-gnu-gdb"],
    "i686": ["i686-buildroot-linux-gnu-gdb", "i686-linux-gnu-gdb"],
    "aarch64": ["aarch64-buildroot-linux-gnu-gdb", "aarch64-linux-gnu-gdb"],
    "armv5_arm": ["arm-buildroot-linux-gnueabi-gdb", "arm-linux-gnueabi-gdb"],
    "armv5_thumb": ["arm-buildroot-linux-gnueabi-gdb", "arm-linux-gnueabi-gdb"],
    "mipsel32": ["mipsel-buildroot-linux-gnu-gdb", "mipsel-linux-gnu-gdb"],
    "mipsbe32": ["mips-buildroot-linux-gnu-gdb", "mips-linux-gnu-gdb"],
    "s390x": ["s390x-buildroot-linux-gnu-gdb", "s390x-linux-gnu-gdb"],
}


def _gdb_candidates(arch: str, native: bool) -> list[str]:
    """Return gdb binary names to try, in preference order.

    Native targets put the plain ``gdb`` first (it debugs the host arch with
    full native ptrace support). Cross targets put the arch-specific gdb and
    ``gdb-multiarch`` first, since a host ``gdb`` cannot decode foreign code.
    """
    candidates: list[str] = []
    if native:
        candidates.append("gdb")
    candidates.extend(CROSS_GDB_BINARIES.get(arch, []))
    candidates.append("gdb-multiarch")
    if not native:
        candidates.append("gdb")

    seen: set[str] = set()
    ordered: list[str] = []
    for name in candidates:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _find_bazel_toolchain_gdb(arch: str) -> str | None:
    """Search for an arch-specific gdb in the Bazel output tree (Bootlin)."""
    project_root = Path(__file__).resolve().parent.parent.parent

    candidates = list(CROSS_GDB_BINARIES.get(arch, []))
    if not candidates:
        return None

    search_roots = []
    for p in project_root.iterdir():
        if p.name.startswith("bazel-") and p.is_symlink():
            ext = p / "external"
            if ext.exists():
                search_roots.append(ext)

    for search_root in search_roots:
        for candidate in candidates:
            matches = list(search_root.glob(f"*/bin/{candidate}"))
            if matches:
                return str(matches[0])

    return None


def find_gdb(arch: str, *, native: bool = False) -> str:
    """Find a gdb binary able to debug *arch*.

    Search order:
      1. (cross only) Bazel-provisioned Bootlin toolchain in the output tree.
      2. System binaries on PATH (arch-specific gdb, gdb-multiarch, gdb).

    The Bazel toolchain gdb is skipped for *native* targets: those Bootlin
    builds are cross gdbs configured without a native run target, so they
    cannot launch/ptrace a host process (``starti`` fails). They are fine for
    the cross path, which only attaches to a remote qemu gdbstub.

    Args:
        arch: Target architecture (e.g., "x86_64", "aarch64").
        native: True when *arch* runs natively on this host, in which case a
            plain ``gdb`` is preferred over the multiarch / cross builds.

    Raises:
        FileNotFoundError: If no suitable gdb is found.
    """
    if not native:
        bazel_gdb = _find_bazel_toolchain_gdb(arch)
        if bazel_gdb:
            return bazel_gdb

    candidates = _gdb_candidates(arch, native)
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path

    expected = candidates[0] if candidates else "gdb"
    raise FileNotFoundError(
        f"No gdb found for {arch}. Install {expected} (or gdb-multiarch) on "
        f"PATH, or build with Bazel to provision the Bootlin toolchain."
    )
