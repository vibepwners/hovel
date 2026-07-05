"""QEMU binary name mapping — derived from tools/registry.py.

This module provides the QEMU binary mapping for Python code.
The canonical source of truth is tools/registry.py.
test_sync.py verifies this stays consistent with the Bazel side.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import from the canonical registry.
_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "tools"
if _TOOLS_DIR.exists():
    sys.path.insert(0, str(_TOOLS_DIR.parent))
    from tools.registry import qemu_binaries

    sys.path.pop(0)
    QEMU_BINARIES: dict[str, str] = qemu_binaries()
else:
    # Fallback for installed packages (not editable/source tree).
    # These values must match tools/registry.py — test_sync.py enforces this.
    QEMU_BINARIES: dict[str, str] = {  # type: ignore[no-redef]
        "x86_64": "qemu-x86_64-static",
        "i686": "qemu-i386-static",
        "aarch64": "qemu-aarch64-static",
        "armv5_arm": "qemu-arm-static",
        "armv5_thumb": "qemu-arm-static",
        "armv7_thumb": "qemu-arm-static",
        "s390x": "qemu-s390x-static",
        "mipsel32": "qemu-mipsel-static",
        "mipsbe32": "qemu-mips-static",
        "sparcv8": "qemu-sparc-static",
        "powerpc": "qemu-ppc-static",
        "ppc64le": "qemu-ppc64le-static",
        "riscv64": "qemu-riscv64-static",
    }
