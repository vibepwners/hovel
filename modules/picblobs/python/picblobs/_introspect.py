"""Introspection API — REQ-016.

Exposes ``targets()``, ``blob_types()``, ``is_supported()``, ``raw_blob()``,
``config_layout()``, ``djb2()``, ``djb2_dll()``.

All of these read from the shipped manifest.json (release builds) or fall
back to scanning the staged ``_blobs/`` directory (development). Config
layouts come from the registry ``ConfigSchema`` entries so the shape stays
in sync with the C-side blob sources without a separate spec to maintain.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import json
from pathlib import Path

from picblobs._enums import OS, Arch, BlobType, ValidationError


@dataclasses.dataclass(frozen=True)
class Target:
    """A supported (OS, arch) pair. Hashable, immutable."""

    os: OS
    arch: Arch

    def __str__(self) -> str:
        return f"{self.os.value}:{self.arch.value}"


@dataclasses.dataclass(frozen=True)
class ConfigField:
    """One field in a blob's config struct."""

    name: str
    type: str
    offset: int
    size: int
    variable: bool = False

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ConfigLayout:
    """Structured description of a blob's config struct. Iterable over
    fields; supports name lookup; serializable to a plain dict."""

    blob_type: BlobType
    fields: tuple[ConfigField, ...]
    total_fixed_size: int

    def __iter__(self):
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def __getitem__(self, name: str) -> ConfigField:
        for field in self.fields:
            if field.name == name:
                return field
        raise KeyError(name)

    def to_dict(self) -> dict:
        return {
            "blob_type": self.blob_type.value,
            "total_fixed_size": self.total_fixed_size,
            "fields": [f.to_dict() for f in self.fields],
        }


# ---------------------------------------------------------------------------
# Registry access — the registry lives under ``tools/`` (outside the Python
# package root). It's imported lazily because consumers of the installed
# wheel won't have ``tools/`` on sys.path; in that case the manifest.json
# carries enough metadata on its own.
# ---------------------------------------------------------------------------

_PKG_DIR = Path(__file__).parent
_PROJECT_ROOT = _PKG_DIR.parent.parent
_BLOBS_DIR = _PKG_DIR / "blobs"


@functools.cache
def _registry_blob_types() -> dict | None:
    """Return the ``BLOB_TYPES`` registry if accessible, else None."""
    import sys

    tools = _PROJECT_ROOT / "tools"
    if not tools.exists():
        return None
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    try:
        from tools.registry import BLOB_TYPES
    except ImportError:
        return None
    return BLOB_TYPES


def _type_size(type_str: str) -> int:
    """Return fixed size in bytes for a ConfigField type string."""
    base = {
        "u8": 1,
        "u16": 2,
        "u32": 4,
        "u64": 8,
        "i8": 1,
        "i16": 2,
        "i32": 4,
        "i64": 8,
    }
    if type_str in base:
        return base[type_str]
    # Array form: e.g. "u8[4]".
    if "[" in type_str and type_str.endswith("]"):
        stem, _, rest = type_str.partition("[")
        count = int(rest[:-1])
        return base.get(stem, 1) * count
    return 0


def _load_sidecar_config(os_name: str, arch_name: str, blob_type: str) -> dict | None:
    """Load config metadata from a shipped sidecar JSON, if present."""
    sidecar = _BLOBS_DIR / f"{blob_type}.{os_name}.{arch_name}.json"
    if not sidecar.exists():
        return None
    try:
        data = json.loads(sidecar.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    config = data.get("config")
    return config if isinstance(config, dict) else None


def _registry_blob_entry(registry: dict, blob_name: str):
    """Return the registry BlobType entry, resolving staged-name aliases."""
    bt = registry.get(blob_name)
    if bt is not None:
        return bt
    for entry in registry.values():
        if entry.staged_name == blob_name:
            return entry
    return None


def _config_layout_from_config_dict(blob_e: BlobType, config: dict) -> ConfigLayout:
    """Build a ConfigLayout from shipped sidecar metadata."""
    fields = [
        ConfigField(
            name=field["name"],
            type=field["type"],
            offset=field["offset"],
            size=_type_size(field["type"]),
            variable=False,
        )
        for field in config.get("fields", [])
    ]
    fields.extend(
        ConfigField(
            name=trailing["name"],
            type="u8[]",
            offset=config.get("fixed_size", 0),
            size=0,
            variable=True,
        )
        for trailing in config.get("trailing_data", [])
    )
    if not fields:
        raise ValidationError(f"{blob_e.value} has no config struct")
    return ConfigLayout(
        blob_type=blob_e,
        fields=tuple(fields),
        total_fixed_size=config.get("fixed_size", 0),
    )


def _config_layout_from_sidecar(
    blob_e: BlobType,
    os_name: str,
    arch_name: str,
) -> ConfigLayout:
    """Build a ConfigLayout from shipped sidecar JSON."""
    config = _load_sidecar_config(os_name, arch_name, blob_e.value)
    if config is None:
        raise ValidationError(
            "Config layout metadata is unavailable for "
            f"{blob_e.value}/{os_name}/{arch_name}"
        )
    return _config_layout_from_config_dict(blob_e, config)


def _config_layout_from_registry(blob_e: BlobType, registry: dict) -> ConfigLayout:
    """Build a ConfigLayout from the source registry."""
    bt = _registry_blob_entry(registry, blob_e.value)
    if bt is None or bt.config_schema is None:
        raise ValidationError(f"{blob_e.value} has no config struct")

    fields = [
        ConfigField(
            name=f.name,
            type=f.type,
            offset=f.offset,
            size=_type_size(f.type),
            variable=False,
        )
        for f in bt.config_schema.fields
    ]
    fields.extend(
        ConfigField(
            name=trailing.name,
            type="u8[]",
            offset=bt.config_schema.fixed_size,
            size=0,
            variable=True,
        )
        for trailing in bt.config_schema.trailing_data
    )

    return ConfigLayout(
        blob_type=blob_e,
        fields=tuple(fields),
        total_fixed_size=bt.config_schema.fixed_size,
    )


# ---------------------------------------------------------------------------
# Support matrix (REQ-016 §1) — source of truth is list_blobs().
# ---------------------------------------------------------------------------


def _as_blob_type(value) -> BlobType:
    if isinstance(value, BlobType):
        return value
    return BlobType.parse(value)


def targets() -> list[Target]:
    """Return every (os, arch) pair with at least one blob staged."""
    from picblobs import list_blobs

    seen: set[tuple[str, str]] = set()
    for _, os_name, arch in list_blobs():
        seen.add((os_name, arch))

    return [
        target
        for os_name, arch_name in sorted(seen)
        if (target := _parse_target_pair(os_name, arch_name)) is not None
    ]


def _parse_target_pair(os_name: str, arch_name: str) -> Target | None:
    """Return a Target for valid names, or None for unknown entries."""
    try:
        return Target(OS.parse(os_name), Arch.parse(arch_name))
    except ValidationError:
        return None


def blob_types(os, arch) -> list[BlobType]:
    """Return the blob types staged for a given target."""
    from picblobs import list_blobs

    os_e = OS.parse(os)
    arch_e = Arch.parse(arch)
    result: list[BlobType] = []
    for blob_type, os_name, arch_name in list_blobs():
        if os_name == os_e.value and arch_name == arch_e.value:
            try:
                result.append(BlobType.parse(blob_type))
            except ValidationError:
                continue
    return sorted(set(result), key=lambda b: b.value)


def is_supported(os, arch, blob_type) -> bool:
    """Return True iff the exact (os, arch, blob_type) combination is staged."""
    try:
        os_e = OS.parse(os)
        arch_e = Arch.parse(arch)
        blob_e = _as_blob_type(blob_type)
    except ValidationError:
        return False

    from picblobs import list_blobs

    needle = (blob_e.value, os_e.value, arch_e.value)
    return needle in list_blobs()


# ---------------------------------------------------------------------------
# Raw blob access + metadata (REQ-016 §3 and blob_size/build_hash).
# ---------------------------------------------------------------------------


def raw_blob(os, arch, blob_type) -> bytes:
    """Return the pre-compiled blob binary (no config appended)."""
    from picblobs import get_blob

    os_e = OS.parse(os)
    arch_e = Arch.parse(arch)
    blob_e = _as_blob_type(blob_type)

    if not is_supported(os_e, arch_e, blob_e):
        raise ValidationError(
            f"No blob staged for {blob_e.value}/{os_e.value}/{arch_e.value}"
        )
    return get_blob(blob_e.value, os_e.value, arch_e.value).code


def blob_size(os, arch, blob_type) -> int:
    return len(raw_blob(os, arch, blob_type))


def build_hash(os, arch, blob_type) -> str:
    return hashlib.sha256(raw_blob(os, arch, blob_type)).hexdigest()


# ---------------------------------------------------------------------------
# Config layout (REQ-016 §2).
# ---------------------------------------------------------------------------


def config_layout(os, arch, blob_type) -> ConfigLayout:
    """Return the config struct layout for a blob. Raises if the blob has
    no registered config schema (e.g. ``hello``)."""
    os_e = OS.parse(os)
    arch_e = Arch.parse(arch)
    blob_e = _as_blob_type(blob_type)

    if not is_supported(os_e, arch_e, blob_e):
        raise ValidationError(
            f"No blob staged for {blob_e.value}/{os_e.value}/{arch_e.value}"
        )

    registry = _registry_blob_types()
    if registry is None:
        return _config_layout_from_sidecar(blob_e, os_e.value, arch_e.value)
    return _config_layout_from_registry(blob_e, registry)


# ---------------------------------------------------------------------------
# DJB2 utility (REQ-016 §4) — same algorithm as src/include/picblobs/win/djb2.h.
# ---------------------------------------------------------------------------


def djb2(name: str) -> int:
    """DJB2 hash of a string, mod 2**32. Matches the C implementation
    byte-for-byte (no case folding — caller pre-lowercases DLL names)."""
    h = 5381
    for byte in name.encode("utf-8"):
        h = ((h * 33) + byte) & 0xFFFFFFFF
    return h


def djb2_dll(name: str) -> int:
    """DJB2 hash of a DLL name, lowercased. Matches the convention used
    by the Windows blobs when resolving modules via PEB walk."""
    return djb2(name.lower())
