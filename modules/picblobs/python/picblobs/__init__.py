"""picblobs — position-independent code blob library.

Provides pre-compiled PIC blobs for multiple OS/architecture targets.

In release mode, blobs are shipped as pre-extracted .bin files with
JSON sidecar metadata and a manifest.json catalog. Source checkouts use
the same sidecar format; .so extraction is a build-time step performed by
tools/extract_release.py.

Usage:
    from picblobs import get_blob, list_blobs

    blob = get_blob("hello", "linux", "x86_64")
    print(len(blob.code), "bytes")
    print(blob.sections)
"""

from __future__ import annotations

import functools
import json
import os
from pathlib import Path

from picblobs._builder import (
    AllocJumpBuilder,
    Blob,
    HelloBuilder,
    HelloWindowsBuilder,
    ReflectivePeBuilder,
    StagerFdBuilder,
    StagerMmapBuilder,
    StagerPipeBuilder,
    StagerTcpBuilder,
    UlExecBuilder,
)
from picblobs._elf import wrap_elf
from picblobs._enums import OS, Arch, BlobType, ValidationError
from picblobs._extractor import BlobData, load_from_sidecar
from picblobs._introspect import (
    ConfigField,
    ConfigLayout,
    Target,
    blob_size,
    blob_types,
    build_hash,
    config_layout,
    djb2,
    djb2_dll,
    is_supported,
    raw_blob,
    targets,
)

__version__ = "0.1.7"
__all__ = [
    "OS",
    "AllocJumpBuilder",
    "Arch",
    "Blob",
    "BlobData",
    "BlobType",
    "ConfigField",
    "ConfigLayout",
    "HelloBuilder",
    "HelloWindowsBuilder",
    "ReflectivePeBuilder",
    "StagerFdBuilder",
    "StagerMmapBuilder",
    "StagerPipeBuilder",
    "StagerTcpBuilder",
    "Target",
    "UlExecBuilder",
    "ValidationError",
    "blob_size",
    "blob_types",
    "build_hash",
    "clear_cache",
    "config_layout",
    "djb2",
    "djb2_dll",
    "get_blob",
    "is_supported",
    "list_blobs",
    "raw_blob",
    "targets",
    "wrap_elf",
]

_PKG_DIR = Path(__file__).parent
_MANIFEST_PATH = _PKG_DIR / "manifest.json"
_DEFAULT_BLOBS_DIR = _PKG_DIR / "blobs"
_BLOBS_DIR = _DEFAULT_BLOBS_DIR
_EXTRA_BLOBS_DIR = (
    Path(value) if (value := os.environ.get("PICBLOBS_BLOBS_DIR")) else None
)


def _load_manifest() -> dict | None:
    """Load and cache the release manifest, or None if not present."""
    if not hasattr(_load_manifest, "_cache"):
        if _MANIFEST_PATH.exists():
            _load_manifest._cache = json.loads(_MANIFEST_PATH.read_text())
        else:
            _load_manifest._cache = None
    return _load_manifest._cache


def _registry_list_blobs() -> list[tuple[str, str, str]]:
    """Return registry-declared blobs for source-tree introspection.

    This is only used as a last-resort development fallback when neither
    a manifest nor any staged blob files are present. It keeps the support
    matrix and config-layout APIs usable in a clean checkout without
    pretending that raw blob bytes are available.
    """
    from picblobs._introspect import _registry_blob_types

    registry = _registry_blob_types()
    if registry is None:
        return []

    results = {
        ((bt.staged_name or bt.name), os_name, arch_name)
        for bt in registry.values()
        for os_name, arches in bt.platforms.items()
        for arch_name in arches
    }
    return sorted(results)


@functools.lru_cache(maxsize=64)
def get_blob(blob_type: str, target_os: str, target_arch: str) -> BlobData:
    """Load and extract a blob by type, OS, and architecture.

    Results are cached — repeated calls return the same BlobData instance.

    Runtime loading is sidecar-only. Build/staging tooling extracts .so files
    into blobs/{type}.{os}.{arch}.bin plus a JSON sidecar before this function
    can load them.

    Args:
        blob_type: Blob type (e.g., "hello", "ul_exec").
        target_os: Target OS (e.g., "linux", "freebsd", "windows").
        target_arch: Target architecture (e.g., "x86_64", "aarch64").

    Returns:
        BlobData with extracted code bytes and metadata.

    Raises:
        FileNotFoundError: If no blob exists for the given combination.
    """
    basename = f"{blob_type}.{target_os}.{target_arch}"
    checked_paths = []

    blob_dirs = (
        (_BLOBS_DIR,)
        if _BLOBS_DIR != _DEFAULT_BLOBS_DIR
        else tuple(
            blobs_dir
            for blobs_dir in (_EXTRA_BLOBS_DIR, _BLOBS_DIR)
            if blobs_dir is not None
        )
    )

    for blobs_dir in blob_dirs:
        bin_path = blobs_dir / f"{basename}.bin"
        json_path = blobs_dir / f"{basename}.json"
        checked_paths.append(f"{bin_path} and {json_path}")
        if bin_path.exists() and json_path.exists():
            return load_from_sidecar(bin_path, json_path)

    raise FileNotFoundError(
        f"No blob for {blob_type}/{target_os}/{target_arch}: "
        f"checked {'; '.join(checked_paths)}. "
        "Run tools/stage_blobs.py or tools/extract_release.py to generate "
        "runtime sidecar artifacts."
    )


def clear_cache() -> None:
    """Clear the blob loading cache. Call after rebuilding blobs."""
    get_blob.cache_clear()
    if hasattr(_load_manifest, "_cache"):
        del _load_manifest._cache


def list_blobs() -> list[tuple[str, str, str]]:
    """Return all available (blob_type, target_os, target_arch) tuples.

    Primary path: reads manifest.json catalog (authoritative — the manifest
    is the single source of truth for release packages and is not validated
    against the filesystem; get_blob() is the point of failure for missing
    files).

    Fallback: walks the sidecar .bin directory. If no sidecar artifacts are
    present in a source checkout, fall back to the canonical registry so
    introspection APIs still expose the declared support matrix.
    """
    manifest = _load_manifest()
    if manifest is not None:
        # Manifest is authoritative: trust the catalog without checking
        # individual .bin/.json files on disk.
        results = []
        for blob_type, entry in manifest.get("catalog", {}).items():
            for os_name, arches in entry.get("platforms", {}).items():
                results.extend((blob_type, os_name, arch) for arch in arches)
        return sorted(results)

    # Fallback: discover from filesystem.
    seen: set[tuple[str, str, str]] = set()
    results: list[tuple[str, str, str]] = []

    def _scan_bin_dir() -> None:
        if _BLOBS_DIR.exists():
            for bin_file in sorted(_BLOBS_DIR.glob("*.bin")):
                parts = bin_file.stem.rsplit(".", 2)
                if len(parts) == 3:
                    entry = (parts[0], parts[1], parts[2])
                    if entry not in seen:
                        seen.add(entry)
                        results.append(entry)

    _scan_bin_dir()

    if not results:
        return _registry_list_blobs()

    return sorted(results)
