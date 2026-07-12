#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import check_site_links


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble declared documentation artifacts into one site tree.")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--astro-site", required=True, type=Path)
    parser.add_argument("--sdk-site", required=True, type=Path)
    parser.add_argument("--license", required=True, type=Path)
    parser.add_argument("--demo", action="append", default=[])
    args = parser.parse_args()

    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)

    seen: dict[str, str] = {}
    copy_tree(args.astro_site, args.output, "Astro", seen, ignore_names={".astro-cache"})
    copy_tree(args.sdk_site, args.output, "SDK documentation", seen)
    copy_file(args.license, args.output / "LICENSE", "repository metadata", seen)
    for mapping in args.demo:
        source, separator, destination = mapping.partition("=")
        if not separator:
            raise SystemExit(f"invalid --demo mapping: {mapping}")
        copy_file(Path(source), args.output / destination, "demo artifacts", seen)

    (args.output / ".nojekyll").touch()
    check_site_links.check_site(args.output)
    return 0


def copy_tree(
    source: Path,
    destination: Path,
    owner: str,
    seen: dict[str, str],
    *,
    ignore_names: set[str] | None = None,
) -> None:
    ignored = ignore_names or set()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_file() and not any(part in ignored for part in relative.parts):
            copy_file(path, destination / relative, owner, seen)


def copy_file(source: Path, destination: Path, owner: str, seen: dict[str, str]) -> None:
    relative = destination.as_posix()
    previous = seen.get(relative)
    if previous is not None:
        raise SystemExit(f"site output collision at {relative}: {previous} and {owner}")
    if not source.is_file():
        raise SystemExit(f"missing {owner} input: {source}")
    seen[relative] = owner
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


if __name__ == "__main__":
    raise SystemExit(main())
