#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path


REPORT_DIRECTORIES = ("data", "logs", "xml", "artifacts", "jobs", "coverage")


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize an assembled documentation tree into _site/.")
    parser.add_argument("--site", required=True)
    parser.add_argument("--report-dir", default=None)
    args = parser.parse_args()

    workspace = Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()
    source = resolve_runfile(args.site)
    destination = workspace / "_site"
    if destination.exists():
        shutil.rmtree(destination)
    copy_tree(source, destination)

    report_state = "status page"
    if args.report_dir is not None:
        report = resolve_workspace_path(workspace, args.report_dir)
        copy_report(report, destination / "reports/tests/latest")
        report_state = "generated evidence"

    version = published_version(destination / "index.html")
    print(f"docs site materialized: _site (version {version}, reports: {report_state})")
    return 0


def resolve_workspace_path(workspace: Path, raw: str) -> Path:
    path = Path(raw)
    return path.resolve() if path.is_absolute() else (workspace / path).resolve()


def resolve_runfile(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute() and path.exists():
        return path.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / raw
            if candidate.exists():
                return candidate.resolve()
    candidate = Path.cwd() / raw
    if candidate.exists():
        return candidate.resolve()
    raise SystemExit(f"missing assembled site runfile: {raw}")


def copy_tree(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def copy_report(source: Path, destination: Path) -> None:
    data = source / "data/report.json"
    if not data.is_file():
        raise SystemExit(f"missing generated report evidence: {data}; run `task test:report`")
    for name in REPORT_DIRECTORIES:
        child = source / name
        if child.is_dir():
            copy_tree(child, destination / name)
    validate_report_references(destination)


def validate_report_references(report: Path) -> None:
    data = json.loads((report / "data/report.json").read_text(encoding="utf-8"))
    references = [
        *(target.get(key, "") for target in data.get("targets", []) for key in ("log_path", "xml_path")),
        *(job.get("log_path", "") for job in data.get("jobs", [])),
        *(metric.get("source_path", "") for metric in data.get("coverage", [])),
    ]
    missing = [reference for reference in references if reference and not (report / reference).is_file()]
    if missing:
        raise SystemExit(f"generated report references missing evidence: {', '.join(sorted(missing))}")


def published_version(index: Path) -> str:
    match = re.search(r"// v([^<]+)", index.read_text(encoding="utf-8"))
    return match.group(1).strip() if match else "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
