#!/usr/bin/env python3
"""Patch vermagic in a .ko file to match the running kernel."""

import sys

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <ko_file> <old_version> <new_version>")
    sys.exit(1)

ko_path = sys.argv[1]
old_ver = sys.argv[2].encode()
new_ver = sys.argv[3].encode()

data = open(ko_path, "rb").read()

marker = b"vermagic="
idx = data.find(marker)
if idx < 0:
    print("No vermagic found")
    sys.exit(1)

# Find the full vermagic string (null-terminated)
end = data.index(b"\x00", idx)
old_magic = data[idx + len(marker) : end]

# Replace just the version part, keep the rest (SMP preempt etc.)
new_magic = old_magic.replace(old_ver, new_ver, 1)

if len(new_magic) != len(old_magic):
    print(f"Length mismatch: {len(old_magic)} vs {len(new_magic)}")
    print(f"Old: {old_magic}")
    print(f"New: {new_magic}")
    sys.exit(1)

data = data[: idx + len(marker)] + new_magic + data[end:]
open(ko_path, "wb").write(data)
print(f"Patched: {old_magic.decode()} → {new_magic.decode()}")
