#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import testreport


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Hovel test-report evidence for the Astro report application.")
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path(".test-report/evidence"))
    parser.add_argument("--title", default="Hovel Test Report")
    parser.add_argument("--bep", action="append", default=[], help="Bazel BEP JSON file to ingest.")
    parser.add_argument(
        "--cache-root",
        action="append",
        default=[],
        help="Bazel disk cache root used to recover bytestream CAS blobs.",
    )
    parser.add_argument(
        "--scan-testlogs",
        action="append",
        default=[],
        help="bazel-testlogs directory to scan as a fallback or enrichment source.",
    )
    parser.add_argument("--workflow", default=os.environ.get("GITHUB_WORKFLOW", "local"))
    parser.add_argument("--job", default=os.environ.get("GITHUB_JOB", "local"))
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME", ""))
    args = parser.parse_args()

    repo = args.repo_root or Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd()))
    repo = repo.resolve()
    beps = [resolve(repo, item) for item in args.bep]
    cache_roots = [resolve(repo, item) for item in args.cache_root]
    scan_roots = [resolve(repo, item) for item in args.scan_testlogs]
    if not scan_roots:
        scan_roots = [repo / "bazel-testlogs", repo / "core/bazel-testlogs"]
    if not cache_roots:
        cache_roots = [Path("/var/tmp/bazel-cache/hovel")]

    commit = args.commit or current_commit(repo)
    report = testreport.build_report(
        repo=repo,
        title=args.title,
        bep_files=beps,
        testlog_roots=scan_roots,
        cache_roots=cache_roots,
        workflow=args.workflow,
        job=args.job,
        commit=commit,
        ref=args.ref,
    )
    testreport.render_report(report, repo=repo, output=resolve(repo, args.output))
    return 0


def resolve(repo: Path, value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return repo / path


def current_commit(repo: Path) -> str:
    for command in (
        ["sl", "log", "-r", ".", "-T", "{node}"],
        ["git", "rev-parse", "HEAD"],
    ):
        try:
            result = subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        commit = result.stdout.strip()
        if commit:
            return commit
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
