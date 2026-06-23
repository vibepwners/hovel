#!/usr/bin/env python3
"""Update Hovel release version fields from VERSION."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="new version, with or without leading v")
    parser.add_argument("--sync", action="store_true", help="rewrite derived version fields from VERSION")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()

    current = read_current(args.root)
    print(f"current version: {current}")

    if args.version:
        version = normalize(args.version)
        write_version(args.root, version)
        print(f"updated version: {version}")
    elif args.sync:
        version = current
    else:
        return 0

    sync(args.root, version)
    return 0


def read_current(root: Path) -> str:
    version_file = root / "VERSION"
    if version_file.exists():
        return normalize(version_file.read_text(encoding="utf-8").strip())
    return "0.0.0"


def normalize(version: str) -> str:
    match = VERSION_RE.fullmatch(version.strip())
    if not match:
        raise SystemExit(f"version must look like 1.2.3 or v1.2.3: {version!r}")
    return match.group(1)


def write_version(root: Path, version: str) -> None:
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")


def sync(root: Path, version: str) -> None:
    replace_one(
        root / "MODULE.bazel",
        r'(module\(\n\s+name = "hovel",\n\s+version = ")[^"]+(")',
        rf"\g<1>{version}\2",
    )
    replace_one(root / "sdk/python/pyproject.toml", r'(?m)^(version = ")[^"]+(")$', rf"\g<1>{version}\2")
    replace_one(
        root / "sdk/python/uv.lock",
        r'(\[\[package\]\]\nname = "hovel-sdk"\nversion = ")[^"]+(")',
        rf"\g<1>{version}\2",
    )
    replace_one(root / "internal/version/version.go", r'const Version = "[^"]+"', f'const Version = "{version}"')


def replace_one(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one version field for {pattern!r}, found {count}")
    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
