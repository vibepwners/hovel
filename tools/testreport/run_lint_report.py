#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

import lintreport


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize declared lint diagnostics as hovel.lint-report/v1 evidence.")
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=Path("tools/testreport/lint_tools.json"))
    parser.add_argument("--output", type=Path, default=Path(".test-report/linters"))
    parser.add_argument("--tool", action="append", default=[], help="Run only the named tool id; may be repeated.")
    parser.add_argument("--result-dir", action="append", type=Path, default=[])
    parser.add_argument("--verified-native", action="append", default=[])
    args = parser.parse_args()

    repo = (args.repo_root or Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd()))).resolve()
    manifest = resolve(repo, args.manifest)
    output = resolve(repo, args.output)
    roots = [Path.cwd(), Path(os.environ.get("RUNFILES_DIR", ".")) / "_main"]
    directories = []
    for directory in args.result_dir:
        found = next((root / directory for root in roots if (root / directory).is_dir()), None)
        if found is None:
            raise SystemExit("missing declared lint output: " + str(directory))
        directories.append(found)
    return lintreport.materialize_results(repo, manifest, output, directories,
        verified_native=set(args.verified_native), selected=set(args.tool) or None)


def resolve(repo: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (repo / path).resolve()


if __name__ == "__main__":
    raise SystemExit(main())
