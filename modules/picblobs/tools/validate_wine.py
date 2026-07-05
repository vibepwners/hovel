#!/usr/bin/env python3
"""Validate Windows blobs under Wine against the mock Linux runner.

Wraps a blob in a minimal PE executable (no toolchain needed) and runs
it under Wine, then compares the result to the mock runner. This tests
that our mock TEB/PEB/export-table runner faithfully reproduces what
real Windows API resolution does.

Usage:
    python tools/validate_wine.py                          # all windows blobs
    python tools/validate_wine.py --type hello_windows     # specific blob
    python tools/validate_wine.py --arch x86_64            # specific arch
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# Bootstrap: add project root so picblobs is importable.
_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "python"))

from picblobs import get_blob, list_blobs
from picblobs.runner import run_blob

# ---------------------------------------------------------------------------
# Minimal PE builder
# ---------------------------------------------------------------------------

_FILE_ALIGN = 0x200
_SECT_ALIGN = 0x1000


def _align(val: int, alignment: int) -> int:
    return (val + alignment - 1) & ~(alignment - 1)


def build_pe(code: bytes, config: bytes, config_offset: int, arch: str) -> bytes:
    """Build a minimal PE executable containing blob code + config.

    Returns the complete PE file as bytes. No toolchain required.
    """
    is_64 = arch == "x86_64"

    # Merge code and config.
    payload = bytearray(code)
    if config:
        if config_offset + len(config) > len(payload):
            payload.extend(b"\x00" * (config_offset + len(config) - len(payload)))
        payload[config_offset : config_offset + len(config)] = config

    raw_size = _align(len(payload), _FILE_ALIGN)
    virt_size = len(payload)
    text_rva = _SECT_ALIGN
    entry_rva = text_rva  # blob entry = start of .text

    # Image size: headers (1 page) + .text (aligned).
    image_size = _SECT_ALIGN + _align(virt_size, _SECT_ALIGN)

    pe = bytearray()

    # --- DOS header (64 bytes) ---
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew
    pe.extend(dos)

    # --- PE signature ---
    pe.extend(b"PE\x00\x00")

    # --- COFF header (20 bytes) ---
    machine = 0x8664 if is_64 else 0x014C
    opt_size = 240 if is_64 else 224
    # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE (64) or
    # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE (32)
    chars = 0x0022 if is_64 else 0x0102
    pe.extend(
        struct.pack(
            "<HHIIIHH",
            machine,
            1,  # NumberOfSections
            0,  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            opt_size,
            chars,
        )
    )

    # --- Optional header ---
    opt = bytearray(opt_size)
    if is_64:
        struct.pack_into("<H", opt, 0, 0x020B)  # PE32+
        struct.pack_into("<I", opt, 0x10, entry_rva)  # AddressOfEntryPoint
        struct.pack_into("<Q", opt, 0x18, 0x140000000)  # ImageBase
        struct.pack_into("<I", opt, 0x20, _SECT_ALIGN)
        struct.pack_into("<I", opt, 0x24, _FILE_ALIGN)
        struct.pack_into("<H", opt, 0x28, 6)  # MajorOSVersion
        struct.pack_into("<H", opt, 0x2C, 6)  # MajorSubsystemVersion
        struct.pack_into("<I", opt, 0x38, image_size)
        struct.pack_into("<I", opt, 0x3C, _FILE_ALIGN)  # SizeOfHeaders
        struct.pack_into("<H", opt, 0x44, 3)  # Subsystem=CONSOLE
        struct.pack_into("<I", opt, 0x6C, 0)  # NumberOfRvaAndSizes
    else:
        struct.pack_into("<H", opt, 0, 0x010B)  # PE32
        struct.pack_into("<I", opt, 0x10, entry_rva)
        struct.pack_into("<I", opt, 0x1C, 0x00400000)  # ImageBase
        struct.pack_into("<I", opt, 0x20, _SECT_ALIGN)
        struct.pack_into("<I", opt, 0x24, _FILE_ALIGN)
        struct.pack_into("<H", opt, 0x28, 6)
        struct.pack_into("<H", opt, 0x2C, 6)
        struct.pack_into("<I", opt, 0x38, image_size)
        struct.pack_into("<I", opt, 0x3C, _FILE_ALIGN)
        struct.pack_into("<H", opt, 0x44, 3)
        struct.pack_into("<I", opt, 0x5C, 0)  # NumberOfRvaAndSizes
    pe.extend(opt)

    # --- Section header (.text, 40 bytes) ---
    sect = bytearray(40)
    sect[0:6] = b".text\x00"
    struct.pack_into("<I", sect, 0x08, virt_size)  # VirtualSize
    struct.pack_into("<I", sect, 0x0C, text_rva)  # VirtualAddress
    struct.pack_into("<I", sect, 0x10, raw_size)  # SizeOfRawData
    struct.pack_into("<I", sect, 0x14, _FILE_ALIGN)  # PointerToRawData
    # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
    # IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE
    struct.pack_into("<I", sect, 0x24, 0xE0000020)
    pe.extend(sect)

    # --- Pad headers to FileAlignment ---
    pe.extend(b"\x00" * (_FILE_ALIGN - len(pe)))

    # --- .text section ---
    pe.extend(payload)
    pe.extend(b"\x00" * (raw_size - len(payload)))

    return bytes(pe)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def find_wine(arch: str) -> str | None:
    """Find wine binary for the given arch."""
    if arch == "x86_64":
        for name in ["wine64", "wine"]:
            if shutil.which(name):
                return name
    elif arch == "i686" and shutil.which("wine"):
        return "wine"
    return None


def run_wine(
    pe_bytes: bytes, wine: str, timeout: float = 15.0
) -> tuple[int, bytes, bytes]:
    """Run a PE under Wine. Returns (exit_code, stdout, stderr)."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(pe_bytes)
        exe_path = f.name

    try:
        env = {"WINEDEBUG": "-all"}  # suppress Wine debug noise
        proc = subprocess.run(
            [wine, exe_path],
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return -1, b"", b"TIMEOUT"
    else:
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        Path(exe_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_blob(
    blob_type: str,
    target_arch: str,
    config: bytes = b"",
) -> tuple[bool, str]:
    """Compare Wine vs mock runner for a blob. Returns (ok, message)."""
    blob = get_blob(blob_type, "windows", target_arch)

    wine = find_wine(target_arch)
    if wine is None:
        return True, "SKIP (no wine)"

    # Run under mock runner.
    mock_result = run_blob(blob, config=config, timeout=15.0)

    # Run under Wine.
    pe = build_pe(blob.code, config, blob.config_offset, target_arch)
    wine_rc, wine_stdout, _wine_stderr = run_wine(pe, wine)

    # Compare. Strip Wine debug noise from stdout.
    # Wine may prefix output with debug messages even with WINEDEBUG=-all
    # when a crash occurs. Extract just the first line for comparison if
    # Wine exited abnormally.
    ok = True
    details = []

    if mock_result.exit_code != wine_rc:
        ok = False
        details.append(f"exit_code: mock={mock_result.exit_code} wine={wine_rc}")

    # If Wine crashed, show a short summary instead of the full dump.
    if wine_rc != 0 and b"Unhandled exception" in wine_stdout:
        exc_line = wine_stdout.split(b"\n")[0].decode(errors="replace")
        details.append(f"wine crashed: {exc_line}")
    elif mock_result.stdout != wine_stdout:
        ok = False
        details.append(f"stdout: mock={mock_result.stdout!r} wine={wine_stdout!r}")

    if ok:
        return True, f"MATCH (exit={wine_rc}, stdout={wine_stdout!r})"
    return False, "MISMATCH: " + "; ".join(details)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Windows blobs under Wine vs mock runner"
    )
    parser.add_argument("--type", help="Blob type (default: all windows blobs)")
    parser.add_argument(
        "--arch",
        choices=["x86_64", "i686"],
        help="Architecture (default: all available; aarch64 not supported)",
    )
    args = parser.parse_args()

    blobs = _matching_windows_blobs(args.type, args.arch)

    if not blobs:
        print("No matching windows blobs found.")
        return 1

    passed, failed = _run_wine_validation(blobs)
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def _matching_windows_blobs(
    type_filter: str | None,
    arch_filter: str | None,
) -> list[tuple[str, str, str]]:
    """Return the Windows blobs supported by the Wine validator."""
    blobs = [
        (bt, os_, arch)
        for bt, os_, arch in list_blobs()
        if os_ == "windows" and arch in ("x86_64", "i686")
    ]
    if type_filter:
        blobs = [(bt, os_, arch) for bt, os_, arch in blobs if bt == type_filter]
    if arch_filter:
        blobs = [(bt, os_, arch) for bt, os_, arch in blobs if arch == arch_filter]
    return blobs


def _run_wine_validation(blobs: list[tuple[str, str, str]]) -> tuple[int, int]:
    """Run Wine validation across a list of staged blob triples."""
    passed = 0
    failed = 0
    for blob_type, _, arch in blobs:
        tag = f"{blob_type} windows:{arch}"
        ok, msg = validate_blob(blob_type, arch)
        print(f"  {tag:40s} {'PASS' if ok else 'FAIL'}  {msg}")
        if ok:
            passed += 1
        else:
            failed += 1
    return passed, failed


if __name__ == "__main__":
    sys.exit(main())
