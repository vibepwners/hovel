"""Cross-toolchain objdump resolution.

Resolves the architecture-appropriate objdump binary for disassembly.
Checks the Bazel-provisioned Bootlin toolchain first, then falls back
to system-installed cross-toolchain binaries.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# Architecture → (toolchain-specific objdump, fallback system objdump).
# For x86_64, the system objdump usually works directly.
OBJDUMP_BINARIES: dict[str, list[str]] = {
    "x86_64": [
        "x86_64-buildroot-linux-gnu-objdump",
        "x86_64-linux-gnu-objdump",
        "objdump",
    ],
    "i686": ["i686-buildroot-linux-gnu-objdump", "i686-linux-gnu-objdump"],
    "aarch64": ["aarch64-buildroot-linux-gnu-objdump", "aarch64-linux-gnu-objdump"],
    "armv5_arm": ["arm-buildroot-linux-gnueabi-objdump", "arm-linux-gnueabi-objdump"],
    "armv5_thumb": ["arm-buildroot-linux-gnueabi-objdump", "arm-linux-gnueabi-objdump"],
    "mipsel32": ["mipsel-buildroot-linux-gnu-objdump", "mipsel-linux-gnu-objdump"],
    "mipsbe32": ["mips-buildroot-linux-gnu-objdump", "mips-linux-gnu-objdump"],
    "s390x": ["s390x-buildroot-linux-gnu-objdump", "s390x-linux-gnu-objdump"],
    "sparcv8": ["sparc-buildroot-linux-uclibc-objdump", "sparc-linux-gnu-objdump"],
    "powerpc": ["powerpc-buildroot-linux-gnu-objdump", "powerpc-linux-gnu-objdump"],
    "ppc64le": [
        "powerpc64le-buildroot-linux-gnu-objdump",
        "powerpc64le-linux-gnu-objdump",
    ],
    "riscv64": ["riscv64-buildroot-linux-gnu-objdump", "riscv64-linux-gnu-objdump"],
}

# Try to import the registry for Bootlin gcc_triple names.
_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "tools"


def _find_bazel_toolchain_objdump(arch: str) -> str | None:
    """Search for objdump in the Bazel output tree (Bootlin toolchains)."""
    project_root = Path(__file__).resolve().parent.parent.parent

    candidates = list(OBJDUMP_BINARIES.get(arch, []))
    if not candidates:
        return None

    # Find the Bazel execroot symlink (bazel-{dirname}/external/).
    # Bazel creates a convenience symlink named bazel-{workspace_dir_name}.
    search_roots = []
    for p in project_root.iterdir():
        if p.name.startswith("bazel-") and p.is_symlink():
            ext = p / "external"
            if ext.exists():
                search_roots.append(ext)

    for search_root in search_roots:
        for candidate in candidates:
            # Bootlin toolchains unpack to external/+bootlin+bootlin_{arch}/bin/
            matches = list(search_root.glob(f"*/bin/{candidate}"))
            if matches:
                return str(matches[0])

    return None


def find_objdump(arch: str) -> str:
    """Find the correct objdump binary for the given architecture.

    Search order:
    1. Bazel-provisioned Bootlin toolchain in the output tree.
    2. System-installed cross-toolchain binaries (via PATH).

    Raises FileNotFoundError if no suitable objdump is found.
    """
    # 1. Check Bazel toolchain.
    bazel_objdump = _find_bazel_toolchain_objdump(arch)
    if bazel_objdump:
        return bazel_objdump

    # 2. Check system PATH.
    candidates = OBJDUMP_BINARIES.get(arch, [])
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path

    # Not found.
    expected = candidates[0] if candidates else f"{arch}-objdump"
    raise FileNotFoundError(
        f"No objdump found for {arch}. "
        f"Install the cross-toolchain (e.g., {expected}) or build with Bazel "
        f"to provision the Bootlin toolchain."
    )


def list_symbols(so_path: str, objdump: str) -> list[tuple[str, str, str]]:
    """List function symbols from a .so file.

    Returns list of (address, type, name) tuples for FUNC symbols.
    Uses objdump -t (symbol table).
    """
    result = subprocess.run(
        [objdump, "-t", so_path],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"objdump failed: {result.stderr.decode(errors='replace').strip()}"
        )

    symbols = []
    for line in result.stdout.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[3] == ".text" and "F" in parts[2]:
            # Format: addr flags section align size name
            addr = parts[0]
            name = parts[-1]
            size = parts[-2]
            symbols.append((addr, size, name))
        elif len(parts) >= 4 and "F" in line and ".text" in line:
            # Alternative objdump output formats — extract what we can.
            addr = parts[0]
            name = parts[-1]
            symbols.append((addr, "", name))

    return symbols


def disassemble_function(
    so_path: str, objdump: str, function: str, source: bool = True
) -> str:
    """Disassemble a single function from a .so file.

    Args:
        so_path: Path to the .so file.
        objdump: Path to the objdump binary.
        function: Function name to disassemble.
        source: If True, interleave source lines (-S). Requires debug symbols.

    Returns the disassembly output as a string.
    """
    cmd = [objdump, "-d", f"--disassemble={function}"]
    if source:
        cmd.append("-S")
    cmd.append(so_path)

    result = subprocess.run(cmd, capture_output=True, check=False)
    output = result.stdout.decode(errors="replace")

    if not output.strip() or result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        if stderr:
            raise RuntimeError(f"objdump error: {stderr}")
        raise RuntimeError(
            f"No disassembly output for function '{function}'. "
            f"Check that the function exists in the .so file."
        )

    return output


def disassemble_full(so_path: str, objdump: str, source: bool = True) -> str:
    """Produce a full disassembly listing of a .so file.

    Args:
        so_path: Path to the .so file.
        objdump: Path to the objdump binary.
        source: If True, interleave source lines (-S). Requires debug symbols.

    Returns the full disassembly output as a string.
    """
    cmd = [objdump, "-d"]
    if source:
        cmd.append("-S")
    cmd.append(so_path)

    result = subprocess.run(cmd, capture_output=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"objdump error: {stderr}")

    return result.stdout.decode(errors="replace")


def has_debug_info(so_path: str, objdump: str) -> bool:
    """Check whether a .so file contains DWARF debug info."""
    result = subprocess.run(
        [objdump, "-h", so_path],
        capture_output=True,
        check=False,
    )
    output = result.stdout.decode(errors="replace")
    return ".debug_info" in output
