#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from pathlib import Path


def _add_lizard_site_packages() -> None:
    runfiles_dir = os.environ.get("RUNFILES_DIR")
    if runfiles_dir:
        for site_packages in Path(runfiles_dir).glob("*/site-packages"):
            if (site_packages / "lizard.py").exists():
                sys.path.insert(0, str(site_packages))
                return

    manifest = os.environ.get("RUNFILES_MANIFEST_FILE")
    if not manifest:
        return

    for line in Path(manifest).read_text().splitlines():
        key, _, value = line.partition(" ")
        if key.endswith("/site-packages/lizard.py") and value:
            sys.path.insert(0, str(Path(value).parent))
            return


def main() -> int:
    _add_lizard_site_packages()
    import lizard

    parser = argparse.ArgumentParser(description="Run lizard complexity checks over Squatter C sources.")
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        lizard.main(["lizard", "-w", "-C", "10", *map(str, args.sources)])
    warnings = output.getvalue()
    if warnings:
        sys.stdout.write(warnings)
        return 1
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text("ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
