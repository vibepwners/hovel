"""picblobs-cli — click-based CLI + non-Linux bundled runner binaries.

This package is a companion to ``picblobs``: the latter carries the blob
data and Python builder API, the former carries the FreeBSD/Windows
cross-compiled test runners, verifier fixtures, and the ``picblobs-cli``
console script that puts them all together under QEMU.

See ADR-026 and REQ-020 for the design rationale.
"""

from __future__ import annotations

import importlib.metadata
import importlib.resources
from pathlib import Path

try:
    __version__ = importlib.metadata.version("picblobs-cli")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover - source fallback
    try:
        from picblobs import __version__ as __version__
    except ImportError:
        __version__ = "unknown"


def runners_dir() -> Path:
    """Return the on-disk path to the bundled ``_runners`` tree.

    Uses ``importlib.resources`` so the path resolves correctly both in
    source checkouts (where ``_runners`` is a filesystem directory) and
    inside an installed wheel.
    """
    return Path(str(importlib.resources.files(__name__) / "_runners"))


def test_binaries_dir() -> Path:
    """Return the on-disk path to bundled verifier test binaries."""
    return Path(str(importlib.resources.files(__name__) / "_test_binaries"))


def _valid_resource_segment(segment: str) -> bool:
    return (
        bool(segment)
        and segment not in {".", ".."}
        and "/" not in segment
        and "\\" not in segment
    )


def ul_exec_test_binary(
    os_name: str,
    arch: str,
    name: str = "hello_et_exec",
) -> bytes | None:
    """Return a staged ``ul_exec`` test ELF, or ``None`` if it is absent."""
    if not all(_valid_resource_segment(s) for s in (os_name, arch, name)):
        return None
    resource = importlib.resources.files(__name__).joinpath(
        "_test_binaries",
        "ul_exec",
        os_name,
        arch,
        name,
    )
    try:
        return resource.read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return None


__all__ = ["__version__", "runners_dir", "test_binaries_dir", "ul_exec_test_binary"]
