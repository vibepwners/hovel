"""Build-time tool: extract .so blobs into the canonical release structure.

Reads staged .so files from python/picblobs/_blobs/{os}/{arch}/{type}.so,
extracts flat binaries and generates sidecar JSON + manifest.json.

This is Stage 2 of the release build pipeline (MOD-007).

Usage:
    python tools/extract_release.py                    # extract all
    python tools/extract_release.py --check            # verify freshness
    python tools/extract_release.py --so-dir path/     # custom .so source
    python tools/extract_release.py --out-dir path/    # custom output
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


# Ensure tools/ and python/ are importable.
def _project_root() -> Path:
    if workspace := os.environ.get("BUILD_WORKSPACE_DIRECTORY"):
        return Path(workspace).resolve() / "modules" / "picblobs"
    return Path(__file__).resolve().parent.parent


_PROJECT_ROOT = _project_root()
sys.path.insert(0, str(_PROJECT_ROOT / "python"))
sys.path.insert(0, str(_PROJECT_ROOT))

from elftools.elf.elffile import ELFFile  # noqa: E402, RUF100
from elftools.elf.sections import Section  # noqa: E402, RUF100

from tools.registry import (  # noqa: E402, RUF100
    BLOB_TYPES,
    arch_endian,
    manifest_architectures,
)

# ============================================================
# ELF extraction (build-time only)
# ============================================================

# Section permission mapping from ELF flags.
_SHF_WRITE = 0x1
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4


def _section_perm(sh_flags: int) -> str:
    """Derive permission string from ELF section flags."""
    if sh_flags & _SHF_EXECINSTR:
        return "rx"
    if sh_flags & _SHF_WRITE:
        return "rw"
    return "r"


def _extract_so(so_path: Path) -> dict:
    """Extract a .so into flat bytes + metadata dict.

    Returns a dict with keys: code, size, config_offset, entry_offset,
    sha256, sections (with perm).
    """
    with so_path.open("rb") as f:
        elf = ELFFile(f)
        blob_start, blob_end, config_start = _extract_blob_bounds(elf, so_path)
        buf, sections = _extract_alloc_sections(elf, blob_start, blob_end)

    code = bytes(buf)
    return {
        "code": code,
        "size": len(code),
        "config_offset": config_start - blob_start,
        "entry_offset": 0,
        "sha256": hashlib.sha256(code).hexdigest(),
        "sections": sections,
    }


def _extract_blob_bounds(elf: ELFFile, so_path: Path) -> tuple[int, int, int]:
    """Return (__blob_start, __blob_end, __config_start) symbol values."""
    symtab = _get_section_by_name_relaxed(elf, ".symtab")
    if symtab is None:
        raise ValueError(f"No .symtab in {so_path}")

    needed = {"__blob_start", "__blob_end", "__config_start"}
    syms: dict[str, int] = {}
    for sym in symtab.iter_symbols():
        if sym.name in needed:
            syms[sym.name] = sym.entry.st_value
            if len(syms) == len(needed):
                break
    missing = needed - syms.keys()
    if missing:
        raise ValueError(f"Missing symbols in {so_path}: {', '.join(sorted(missing))}")
    return syms["__blob_start"], syms["__blob_end"], syms["__config_start"]


def _extract_alloc_sections(
    elf: ELFFile,
    blob_start: int,
    blob_end: int,
) -> tuple[bytearray, dict[str, dict]]:
    """Copy allocatable ELF sections into a flat blob buffer."""
    size = blob_end - blob_start
    buf = bytearray(size)
    sections: dict[str, dict] = {}
    for section in _iter_sections_relaxed(elf):
        section_info = _section_overlap(section, blob_start, blob_end)
        if section_info is None:
            continue
        overlap_start, overlap_end = section_info
        if (
            section.name
            and section.header.sh_addr >= blob_start
            and section.header.sh_addr < blob_end
        ):
            sections[section.name] = {
                "offset": section.header.sh_addr - blob_start,
                "size": section.header.sh_size,
                "perm": _section_perm(section.header.sh_flags),
            }
        _copy_section_bytes(buf, section, blob_start, overlap_start, overlap_end)
    return buf, sections


def _iter_sections_relaxed(elf: ELFFile):
    """Yield generic section views without pyelftools' strict type wrappers.

    Some 32-bit FreeBSD/MIPS blobs contain relocation sections whose headers are
    acceptable to binutils but rejected by pyelftools' ``RelocationSection``
    constructor. Extraction only needs the raw alloc sections, so iterate the
    section headers directly and wrap them as generic ``Section`` objects.
    """
    for index in range(elf.num_sections()):
        header = elf._get_section_header(index)
        name = elf._get_section_name(header)
        yield Section(header, name, elf)


def _get_section_by_name_relaxed(elf: ELFFile, target_name: str):
    """Return one named section without forcing pyelftools to scan every type."""
    for index in range(elf.num_sections()):
        header = elf._get_section_header(index)
        name = elf._get_section_name(header)
        if name == target_name:
            return elf._make_section(header)
    return None


def _section_overlap(
    section,
    blob_start: int,
    blob_end: int,
) -> tuple[int, int] | None:
    """Return overlap range between one alloc section and the blob window."""
    sh_flags = section.header.sh_flags
    sh_size = section.header.sh_size
    if not (sh_flags & _SHF_ALLOC) or sh_size == 0:
        return None
    sec_start = section.header.sh_addr
    sec_end = sec_start + sh_size
    overlap_start = max(sec_start, blob_start)
    overlap_end = min(sec_end, blob_end)
    if overlap_start >= overlap_end:
        return None
    return overlap_start, overlap_end


def _copy_section_bytes(
    buf: bytearray,
    section,
    blob_start: int,
    overlap_start: int,
    overlap_end: int,
) -> None:
    """Copy one section's overlapping bytes into the flat buffer."""
    if section.header.sh_type == "SHT_NOBITS":
        return
    data = section.data()
    sec_start = section.header.sh_addr
    data_offset = overlap_start - sec_start
    buf_offset = overlap_start - blob_start
    length = overlap_end - overlap_start
    buf[buf_offset : buf_offset + length] = data[data_offset : data_offset + length]


# ============================================================
# Sidecar + manifest generation
# ============================================================


def _build_sidecar(
    blob_type: str,
    os_name: str,
    arch: str,
    extracted: dict,
) -> dict:
    """Build the sidecar JSON dict for one blob."""
    sidecar: dict = {
        "type": blob_type,
        "os": os_name,
        "arch": arch,
        "size": extracted["size"],
        "entry_offset": extracted["entry_offset"],
        "config_offset": extracted["config_offset"],
        "sha256": extracted["sha256"],
        "sections": extracted["sections"],
        "config": None,
    }

    # Add config schema from registry if available.
    bt = BLOB_TYPES.get(blob_type)
    if bt and bt.config_schema:
        schema = bt.config_schema
        sidecar["config"] = {
            "endian": arch_endian(arch),
            "fixed_size": schema.fixed_size,
            "fields": [
                {"name": f.name, "type": f.type, "offset": f.offset}
                for f in schema.fields
            ],
        }
        if schema.trailing_data:
            sidecar["config"]["trailing_data"] = [
                {"name": td.name, "length_field": td.length_field}
                for td in schema.trailing_data
            ]

    # Add .config section entry if not already present.
    if ".config" not in sidecar["sections"]:
        sidecar["sections"][".config"] = {
            "offset": extracted["config_offset"],
            "size": 0,
            "perm": "rw",
        }

    return sidecar


def _build_manifest(
    version: str,
    extracted_blobs: list[tuple[str, str, str]],
) -> dict:
    """Build the manifest.json dict.

    Args:
        version: picblobs version string.
        extracted_blobs: list of (blob_type, os, arch) that were extracted.
    """
    extracted_set = set(extracted_blobs)
    catalog = _manifest_catalog_from_registry(extracted_set)
    _merge_unregistered_blobs(catalog, extracted_set)

    return {
        "schema_version": 1,
        "picblobs_version": version,
        "architectures": manifest_architectures(),
        "catalog": catalog,
    }


def _manifest_catalog_from_registry(
    extracted_set: set[tuple[str, str, str]],
) -> dict[str, dict]:
    """Build manifest catalog entries for registry-known blobs."""
    catalog: dict[str, dict] = {}
    for bt_name, bt in BLOB_TYPES.items():
        platforms = _manifest_platforms(bt_name, bt.platforms, extracted_set)
        if platforms:
            catalog[bt_name] = {
                "description": bt.description,
                "has_config": bt.has_config,
                "platforms": platforms,
            }
    return catalog


def _manifest_platforms(
    blob_name: str,
    platforms: dict[str, list[str]],
    extracted_set: set[tuple[str, str, str]],
) -> dict[str, list[str]]:
    """Return extracted platforms for one registry blob."""
    present_platforms: dict[str, list[str]] = {}
    for os_name, arches in platforms.items():
        present = [
            arch for arch in arches if (blob_name, os_name, arch) in extracted_set
        ]
        if present:
            present_platforms[os_name] = present
    return present_platforms


def _merge_unregistered_blobs(
    catalog: dict[str, dict],
    extracted_set: set[tuple[str, str, str]],
) -> None:
    """Add extracted blobs missing from the canonical registry."""
    for bt_name, os_name, arch in sorted(extracted_set):
        if bt_name in BLOB_TYPES and not _registry_supports_staged_blob(
            bt_name, os_name, arch
        ):
            continue
        if bt_name not in catalog:
            catalog[bt_name] = {
                "description": "",
                "has_config": False,
                "platforms": {},
            }
        platforms = catalog[bt_name]["platforms"]
        if os_name not in platforms:
            platforms[os_name] = []
        if arch not in platforms[os_name]:
            platforms[os_name].append(arch)


def _get_version() -> str:
    """Read picblobs version from pyproject.toml."""
    pyproject = _PROJECT_ROOT / "python" / "pyproject.toml"
    for line in pyproject.read_text().splitlines():
        if line.strip().startswith("version"):
            # version = "0.1.7"
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


def _is_release_candidate(blob_type: str, os_name: str, arch: str) -> bool:
    """Return True if a staged .so belongs in the release catalog."""
    return _registry_supports_staged_blob(blob_type, os_name, arch)


def _registry_supports_staged_blob(blob_type: str, os_name: str, arch: str) -> bool:
    """Return True if the registry supports one staged/public blob name."""
    for bt_name, bt in BLOB_TYPES.items():
        staged_name = bt.staged_name or bt_name
        if staged_name != blob_type:
            continue
        if arch in bt.platforms.get(os_name, []):
            return True
    return False


def _staged_so_identity(so_path: Path) -> tuple[str, str, str] | None:
    """Return (blob_type, os, arch) derived from a staged .so path."""
    parts = so_path.parts
    try:
        return so_path.stem, parts[-3], parts[-2]
    except IndexError:
        return None


def _release_basename(identity: tuple[str, str, str]) -> str:
    blob_type, os_name, arch = identity
    return f"{blob_type}.{os_name}.{arch}"


def _write_release_artifacts(
    so_path: Path,
    blobs_dir: Path,
    identity: tuple[str, str, str],
    *,
    verbose: bool,
) -> bool:
    """Extract one staged .so and write its .bin/.json artifacts."""
    blob_type, os_name, arch = identity
    basename = _release_basename(identity)
    try:
        extracted = _extract_so(so_path)
    except Exception as e:
        print(f"  ERROR {so_path}: {e}", file=sys.stderr)
        return False

    (blobs_dir / f"{basename}.bin").write_bytes(extracted["code"])
    sidecar = _build_sidecar(blob_type, os_name, arch, extracted)
    (blobs_dir / f"{basename}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=False) + "\n"
    )

    if verbose:
        print(
            "  "
            f"{basename}  {extracted['size']} bytes  "
            f"sha256={extracted['sha256'][:16]}..."
        )
    return True


def _remove_stale_release_artifacts(
    blobs_dir: Path,
    expected_basenames: set[str],
    *,
    verbose: bool,
) -> None:
    """Remove release artifacts whose staged .so is no longer selected."""
    for path in list(blobs_dir.glob("*.bin")) + list(blobs_dir.glob("*.json")):
        if path.stem not in expected_basenames:
            path.unlink()
            if verbose:
                print(f"  removed stale artifact {path.name}")


# ============================================================
# Main
# ============================================================


def extract_release(
    so_dir: Path,
    out_dir: Path,
    *,
    verbose: bool = False,
) -> tuple[int, int]:
    """Extract all .so blobs into the release structure.

    Returns (extracted_count, error_count).
    """
    blobs_dir = out_dir / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    so_files = sorted(so_dir.rglob("*.so"))
    if not so_files:
        print(f"No .so files found in {so_dir}", file=sys.stderr)
        return 0, 0

    extracted_triples: list[tuple[str, str, str]] = []
    expected_basenames: set[str] = set()
    errors = 0

    for so_path in so_files:
        identity = _staged_so_identity(so_path)
        if identity is None:
            print(f"  SKIP {so_path} (unexpected path structure)", file=sys.stderr)
            errors += 1
            continue

        blob_type, os_name, arch = identity
        if not _is_release_candidate(blob_type, os_name, arch):
            if verbose:
                print(
                    f"  SKIP {_release_basename(identity)} "
                    "(not in registry platform matrix)"
                )
            continue

        expected_basenames.add(_release_basename(identity))
        if not _write_release_artifacts(so_path, blobs_dir, identity, verbose=verbose):
            errors += 1
            continue

        extracted_triples.append(identity)

    _remove_stale_release_artifacts(blobs_dir, expected_basenames, verbose=verbose)

    # Write manifest.json.
    version = _get_version()
    manifest = _build_manifest(version, extracted_triples)
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")

    if verbose:
        print(
            f"\nmanifest.json: {len(manifest['catalog'])} blob types, "
            f"{len(extracted_triples)} blobs"
        )

    return len(extracted_triples), errors


def check_release(so_dir: Path, out_dir: Path) -> bool:
    """Verify the release structure is up-to-date with the .so files."""
    manifest_path = out_dir / "manifest.json"
    if not manifest_path.exists():
        print(
            "manifest.json not found — run: python tools/extract_release.py",
            file=sys.stderr,
        )
        return False

    blobs_dir = out_dir / "blobs"

    # Check every .so has a corresponding .bin with matching hash.
    stale = False
    for so_path in sorted(so_dir.rglob("*.so")):
        blob_type = so_path.stem
        parts = so_path.parts
        try:
            arch = parts[-2]
            os_name = parts[-3]
        except IndexError:
            continue

        if not _is_release_candidate(blob_type, os_name, arch):
            continue

        basename = f"{blob_type}.{os_name}.{arch}"
        bin_path = blobs_dir / f"{basename}.bin"
        json_path = blobs_dir / f"{basename}.json"

        if not bin_path.exists() or not json_path.exists():
            print(f"  STALE: {basename} — missing .bin or .json", file=sys.stderr)
            stale = True
            continue

        # Re-extract and compare hash.
        try:
            extracted = _extract_so(so_path)
        except Exception as exc:
            print(f"  SKIP {so_path}: {exc}", file=sys.stderr)
            continue

        sidecar = json.loads(json_path.read_text())
        if sidecar.get("sha256") != extracted["sha256"]:
            print(f"  STALE: {basename} — sha256 mismatch", file=sys.stderr)
            stale = True

    return not stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract .so blobs into the canonical release structure",
    )
    parser.add_argument(
        "--so-dir",
        type=Path,
        default=_PROJECT_ROOT / "python" / "picblobs" / "_blobs",
        help="Directory containing staged .so files (default: python/picblobs/_blobs)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_PROJECT_ROOT / "python" / "picblobs",
        help="Output directory for manifest.json + blobs/ (default: python/picblobs)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify release structure is up-to-date (exit 1 if stale)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)

    if args.check:
        ok = check_release(args.so_dir, args.out_dir)
        return 0 if ok else 1

    extracted, errors = extract_release(args.so_dir, args.out_dir, verbose=args.verbose)
    print(f"Extracted {extracted} blobs ({errors} errors)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
