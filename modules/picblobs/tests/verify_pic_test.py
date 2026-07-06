#!/usr/bin/env python3
"""Verify PIC blob ELF invariants without host shell tools."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MAX_BLOB_BYTES = 100 * 1024


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: verify_pic_test.py <readelf> <blob.so> [<blob.so> ...]",
            file=sys.stderr,
        )
        return 2

    readelf = resolve_path(sys.argv[1])
    blobs = [resolve_path(arg) for arg in sys.argv[2:]]
    failures: list[str] = []

    for blob in blobs:
        failures.extend(check_blob(readelf, blob))
        print()

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("=== SOME CHECKS FAILED ===")
        return 1

    print("=== ALL CHECKS PASSED ===")
    return 0


def check_blob(readelf: Path, blob: Path) -> list[str]:
    name = blob.name
    print(f"--- Checking {name} ---")
    if not blob.is_file():
        return [f"{name}: file not found: {blob}"]

    failures: list[str] = []
    failures.extend(check_relocations(readelf, blob))
    failures.extend(check_symbols(readelf, blob))
    failures.extend(check_machine(readelf, blob))
    return failures


def check_relocations(readelf: Path, blob: Path) -> list[str]:
    name = blob.name
    sections = run_readelf(readelf, "-S", blob)
    reloc_count = sum(
        1 for line in sections.splitlines() if ".rel." in line or ".rela." in line
    )
    if not reloc_count:
        print("  OK: no relocation sections")
        return []
    return [f"{name}: found {reloc_count} relocation section(s); blob is not fully PIC"]


def check_symbols(readelf: Path, blob: Path) -> list[str]:
    name = blob.name
    failures: list[str] = []
    symbols = run_readelf(readelf, "-s", blob)
    start_addr = symbol_address(symbols, "__blob_start")
    end_addr = symbol_address(symbols, "__blob_end")

    if start_addr:
        print("  OK: __blob_start found")
    else:
        failures.append(f"{name}: missing __blob_start symbol")

    if end_addr:
        print("  OK: __blob_end found")
    else:
        failures.append(f"{name}: missing __blob_end symbol")

    if start_addr in {"00000000", "0000000000000000"}:
        print("  OK: __blob_start at address 0")
    else:
        failures.append(f"{name}: __blob_start at {start_addr or '?'} (expected 0)")

    if end_addr:
        blob_size = int(end_addr, 16)
        if blob_size <= MAX_BLOB_BYTES:
            print(f"  OK: blob size {blob_size} bytes ({blob_size // 1024}KB < 100KB)")
        else:
            failures.append(f"{name}: blob size {blob_size} bytes exceeds 100KB limit")
    return failures


def check_machine(readelf: Path, blob: Path) -> list[str]:
    header = run_readelf(readelf, "-h", blob)
    machine = machine_name(header)
    if machine == "ARM":
        print("  OK: ARM ELF")
        return []
    return [f"{blob.name}: expected ARM ELF, got machine={machine}"]


def run_readelf(readelf: Path, mode: str, blob: Path) -> str:
    result = subprocess.run(
        [str(readelf), mode, str(blob)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr or f"{readelf} {mode} {blob} failed")
    return result.stdout


def symbol_address(symbols: str, name: str) -> str:
    for line in symbols.splitlines():
        if name not in line:
            continue
        fields = line.split()
        if len(fields) >= 2:
            return fields[1]
    return ""


def machine_name(header: str) -> str:
    for line in header.splitlines():
        if "Machine:" not in line:
            continue
        return line.split("Machine:", 1)[1].strip().split()[0]
    return ""


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root_raw = os.environ.get(root_name)
        if not root_raw:
            continue
        root = Path(root_raw)
        for candidate in (
            root / value,
            root / "_main" / value,
            root / "hovel_slices" / value,
        ):
            if candidate.exists():
                return candidate
    return path


if __name__ == "__main__":
    raise SystemExit(main())
