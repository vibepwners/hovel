"""Materialize the declared platform wheels without rebuilding them."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-directory", type=Path, action="append", required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    roots = [Path.cwd(), Path(os.environ.get("RUNFILES_DIR", ".")) / "_main", Path(os.environ.get("RUNFILES_DIR", ".")) / "hovel"]
    wheels = []
    for directory in args.wheel_directory:
        resolved = next((root / directory for root in roots if (root / directory).is_dir()), None)
        if resolved is None:
            raise SystemExit("missing wheel output: " + str(directory))
        found = list(resolved.glob("*.whl"))
        if len(found) != 1:
            raise SystemExit("expected one declared wheel: " + str(directory))
        wheels.extend(found)
    if len({p.name for p in wheels}) != len(wheels):
        raise SystemExit("duplicate platform wheel")
    output = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", ".")) / args.out_dir
    output.mkdir(parents=True, exist_ok=True)
    for old in output.glob("hovel-*.whl"):
        old.unlink()
    for wheel in wheels:
        shutil.copyfile(wheel, output / wheel.name)
        print(output / wheel.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
