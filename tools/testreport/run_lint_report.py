#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

import lintreport


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Task-backed linters and emit hovel.lint-report/v1 evidence.")
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=Path("tools/testreport/lint_tools.json"))
    parser.add_argument("--output", type=Path, default=Path(".test-report/linters"))
    parser.add_argument("--tool", action="append", default=[], help="Run only the named tool id; may be repeated.")
    args = parser.parse_args()

    repo = (args.repo_root or Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd()))).resolve()
    manifest = resolve(repo, args.manifest)
    output = resolve(repo, args.output)
    return lintreport.run_manifest(repo, manifest, output, selected=set(args.tool) or None)


def resolve(repo: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (repo / path).resolve()


if __name__ == "__main__":
    raise SystemExit(main())
