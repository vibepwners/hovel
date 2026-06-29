#!/usr/bin/env python3
"""Append concise GitHub Actions job summaries for Hovel workflows."""

from __future__ import annotations

import argparse
import os
import pathlib
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class JobSummary:
    title: str
    commands: tuple[str, ...]
    details: tuple[str, ...] = ()
    coverage: bool = False
    artifact_glob: str | None = None
    site_root: str | None = None


JOBS = {
    "ci-build-test": JobSummary(
        title="CI Build and Test",
        commands=(
            "task build",
            "task release:hovel-wheels",
            "task test",
            "task test:race",
            "task fuzz:smoke",
            "task coverage",
        ),
        details=("Bazel test logs are uploaded as an artifact when this job fails.",),
        coverage=True,
    ),
    "ci-demos": JobSummary(
        title="CI Demos",
        commands=("task demos", "task demo:squatter-wine"),
        artifact_glob="demo/out/*.gif",
    ),
    "ci-docs": JobSummary(
        title="CI Docs",
        commands=("task docs:stage",),
        details=("This job stages the GitHub Pages site from generated demo artifacts.",),
        site_root="_site",
    ),
    "ci-squatter-wine": JobSummary(
        title="CI Squatter Wine",
        commands=("task squatter:test:wine",),
        details=("Bazel test logs are uploaded as an artifact when this job fails.",),
    ),
    "ci-lint": JobSummary(
        title="CI Lint",
        commands=("task lint",),
        details=("Includes Go formatting, Gazelle, Rust checks, Python checks, and Squatter C checks.",),
    ),
    "pages-build": JobSummary(
        title="Pages Build",
        commands=("task docs", "actions/upload-pages-artifact"),
        details=("This job rebuilds the full Pages site before deployment.",),
        site_root="_site",
    ),
    "publish-hovel-build": JobSummary(
        title="Publish Hovel Wheels",
        commands=("task release:hovel-wheels", "actions/upload-artifact"),
        details=("The release tag must match the committed VERSION before wheels are built.",),
        artifact_glob="dist/hovel-*.whl",
    ),
    "publish-hovel-modules": JobSummary(
        title="Publish Hovel Module Packages",
        commands=("task modules:package", "actions/upload-artifact", "gh release upload"),
        details=("Release uploads run only for published-release events and include the bulk-install manifest.",),
        artifact_glob="dist/modules/*",
    ),
    "publish-sdk-build": JobSummary(
        title="Publish Hovel SDK Distribution",
        commands=("task release:hovel-sdk-dist", "actions/upload-artifact"),
        details=("The release tag must match the committed VERSION before the SDK distribution is built.",),
        artifact_glob="dist/*",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job", choices=sorted(JOBS))
    args = parser.parse_args()

    summary = render_summary(JOBS[args.job])
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with pathlib.Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(summary)
    else:
        print(summary, end="")
    return 0


def render_summary(job: JobSummary) -> str:
    lines = [
        f"## {job.title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Status | {os.environ.get('JOB_STATUS', 'unknown')} |",
        f"| Workflow | {os.environ.get('GITHUB_WORKFLOW', 'local')} |",
        f"| Job | {os.environ.get('GITHUB_JOB', 'local')} |",
    ]
    ref = os.environ.get("GITHUB_REF_NAME")
    if ref:
        lines.append(f"| Ref | `{ref}` |")
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        lines.append(f"| Commit | `{sha[:12]}` |")

    if job.commands:
        lines.extend(["", "### Commands", "", "| Command |", "| --- |"])
        lines.extend(f"| `{command}` |" for command in job.commands)

    if job.details:
        lines.extend(["", "### Notes", ""])
        lines.extend(f"- {detail}" for detail in job.details)

    if job.coverage:
        lines.extend(read_coverage_summary())

    if job.artifact_glob:
        lines.extend(render_artifacts(job.artifact_glob))

    if job.site_root:
        lines.extend(render_site_stats(job.site_root))

    return "\n".join(lines) + "\n"


def read_coverage_summary() -> list[str]:
    path = ROOT / "coverage/summary.md"
    if not path.exists():
        return ["", "### Coverage Ratchets", "", "Coverage summary was not generated."]
    return ["", path.read_text(encoding="utf-8").strip()]


def render_artifacts(pattern: str) -> list[str]:
    files = sorted(ROOT.glob(pattern))
    lines = ["", "### Artifacts", "", f"{len(files)} file(s) matched `{pattern}`."]
    if files:
        lines.extend(["", "| File | Size |", "| --- | ---: |"])
        for path in files[:20]:
            lines.append(f"| `{path.relative_to(ROOT)}` | {format_bytes(path.stat().st_size)} |")
        if len(files) > 20:
            lines.append(f"| ... | {len(files) - 20} more |")
    return lines


def render_site_stats(site_root: str) -> list[str]:
    root = ROOT / site_root
    if not root.exists():
        return ["", "### Site", "", f"`{site_root}` was not generated."]
    html_files = list(root.rglob("*.html"))
    lines = [
        "",
        "### Site",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| HTML pages | {len(html_files)} |",
        f"| Total size | {format_bytes(sum(path.stat().st_size for path in root.rglob('*') if path.is_file()))} |",
    ]
    return lines


def format_bytes(size: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
