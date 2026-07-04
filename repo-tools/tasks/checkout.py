#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Slice:
    name: str
    description: str
    paths: tuple[str, ...]
    check_task: str


SLICES: tuple[Slice, ...] = (
    Slice(
        name="core",
        description="framework, CLI, daemon, domain/app layers, schemas, and core build system",
        paths=("core",),
        check_task="core:check",
    ),
    Slice(
        name="sdk",
        description="public Python, Go, and Rust module SDKs",
        paths=("sdk",),
        check_task="sdk:ci",
    ),
    Slice(
        name="module-examples",
        description="Go, Python, and Rust example modules",
        paths=("modules/examples/go", "modules/examples/python", "modules/examples/rust"),
        check_task="modules:examples:ci",
    ),
    Slice(
        name="modules",
        description="full in-repo modules slice including Squatter, module packaging, and labs",
        paths=(
            "modules/examples/go",
            "modules/examples/python",
            "modules/examples/rust",
            "modules/squatter/BUILD.bazel",
            "modules/squatter/client/functest",
            "modules/squatter/client/shell",
            "modules/squatter/client/smbpipe",
            "modules/squatter/client/wire",
            "modules/squatter/client/xfer",
            "modules/squatter/examples",
            "modules/squatter/provider",
            "modules/squatter/tests",
            "modules/squatter/windows",
            "modules/tools",
        ),
        check_task="modules:ci",
    ),
    Slice(
        name="docs",
        description="static book, site assets, and demo recordings",
        paths=("docs",),
        check_task="docs:ci",
    ),
)

FULL_CHECKOUT_PATHS: tuple[str, ...] = (
    "core",
    "docs",
    "modules",
    "repo-tools",
    "sdk",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect and run Hovel checkout-slice tasks.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Print which repository slices are present.")
    subparsers.add_parser("check", help="Run checks for all present slices.")

    require = subparsers.add_parser("require", help="Fail if named paths are not present.")
    require.add_argument("paths", nargs="*", help="Paths that must exist. Defaults to the full checkout.")

    args = parser.parse_args()
    repo = Path.cwd()

    if args.command == "status":
        print_status(repo)
        return 0
    if args.command == "check":
        return check_present(repo)
    if args.command == "require":
        paths = tuple(args.paths) if args.paths else FULL_CHECKOUT_PATHS
        return require_paths(repo, paths)
    raise AssertionError(args.command)


def print_status(repo: Path) -> None:
    print("checkout slices:")
    for checkout_slice in SLICES:
        state = "present" if slice_present(repo, checkout_slice) else "missing"
        path_list = ", ".join(checkout_slice.paths)
        print(f"  {checkout_slice.name:9} {state:7} {path_list}")


def check_present(repo: Path) -> int:
    ran = 0
    present = 0
    for checkout_slice in SLICES:
        if not slice_present(repo, checkout_slice):
            print(f"{checkout_slice.name}: skipped; not checked out", flush=True)
            continue
        present += 1
        if checkout_slice.check_task == "":
            print(f"{checkout_slice.name}: present; no slice check is wired yet", flush=True)
            continue
        ran += 1
        print(f"{checkout_slice.name}: running task {checkout_slice.check_task}", flush=True)
        result = subprocess.run(["task", checkout_slice.check_task], cwd=repo, check=False)
        if result.returncode != 0:
            return result.returncode
    if present == 0:
        print("no recognized checkout slices are present")
        return 1
    return 0


def require_paths(repo: Path, paths: tuple[str, ...]) -> int:
    missing = [path for path in paths if not (repo / path).exists()]
    if not missing:
        return 0
    print("this task requires paths that are not checked out:", file=sys.stderr)
    for path in missing:
        print(f"  - {path}", file=sys.stderr)
    print("use `task check` to run the checks available in this partial checkout", file=sys.stderr)
    return 2


def slice_present(repo: Path, checkout_slice: Slice) -> bool:
    return all((repo / path).exists() for path in checkout_slice.paths)


if __name__ == "__main__":
    raise SystemExit(main())
