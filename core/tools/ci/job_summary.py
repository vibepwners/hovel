#!/usr/bin/env python3
"""Append concise GitHub Actions job summaries for Hovel workflows."""

from __future__ import annotations

import argparse
import os
import pathlib
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
REPO_ROOT = ROOT.parent


@dataclass(frozen=True)
class JobSummary:
    title: str
    purpose: str
    commands: tuple[str, ...]
    proves: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    coverage: bool = False
    artifact_globs: tuple[str, ...] = ()
    site_root: str | None = None


JOBS = {
    "ci-build-test": JobSummary(
        title="CI Core Gate",
        purpose="Validates the self-contained core/ workspace: formatting, lint, build, tests, race/fuzz smoke, coverage ratchets, and release wheel buildability for the Hovel binary.",
        commands=(
            "task checkout:status",
            "task lint",
            "task build -- //:build",
            "task test -- //:ci_test",
            "task test -- //:race_test //:fuzz_smoke_test",
            "task coverage",
            "task release:hovel-wheels",
        ),
        proves=(
            "Core Go/Gazelle formatting and lint rules are clean.",
            "The hoveld/CLI/TUI/MCP mono-binary builds from core/.",
            "Core tests, race tests, fuzz smoke tests, and coverage ratchets pass.",
            "The PyPI hovel wheel task can cross-build all configured platform wheels.",
        ),
        details=(
            "This job intentionally exercises the core workspace directly; non-core slices have separate jobs.",
            "Bazel test logs are uploaded as an artifact when this job fails.",
        ),
        coverage=True,
        artifact_globs=("dist/hovel-*.whl",),
    ),
    "sdk-ci": JobSummary(
        title="CI SDK Gate",
        purpose="Validates the language SDK slice outside core/: Go, Python, and Rust SDK build and test targets.",
        commands=("task sdk:ci",),
        proves=(
            "The root integration workspace can build the Go, Python, and Rust SDK targets against core contracts.",
            "SDK unit and protocol tests pass for all wired SDK languages.",
        ),
        details=("SDK versions are kept in lockstep with the root/core Hovel version, but SDK source stays outside core/ for partial checkout work.",),
    ),
    "modules-ci": JobSummary(
        title="CI Modules Gate",
        purpose="Validates in-repo modules, Squatter provider/payload build rules, package checks, workspace installation behavior, and module release package generation.",
        commands=("task modules:ci", "task release:modules-package", "actions/upload-artifact module-packages"),
        proves=(
            "Go and Rust example modules build.",
            "Squatter provider and Windows payload targets build.",
            "Module package tests and workspace install tests pass.",
            "Release module .tgz packages, index, bulk install manifest, and checksums are generated.",
        ),
        details=(
            "Compiled module packages currently advertise Linux and Darwin launchers; Windows Squatter behavior is covered by the dedicated Wine job.",
            "The module-packages artifact contains dist/modules/.",
        ),
        artifact_globs=("../dist/modules/*",),
    ),
    "docs-ci": JobSummary(
        title="CI Docs And Demos Gate",
        purpose="Builds docs tooling, verifies demo harnesses, renders standard terminal GIF demos, generates API documentation, stages _site/, and checks internal links.",
        commands=("task docs:ci", "actions/upload-artifact docs-site"),
        proves=(
            "Docs tooling and demo verification tests pass.",
            "Standard VHS demos render and materialize into docs/demo/out/.",
            "The GitHub Pages site stages into _site/ with SDK API docs and link checks.",
        ),
        details=("The docs-site artifact contains the staged _site/ directory.",),
        artifact_globs=("../docs/demo/out/*.gif",),
        site_root="../_site",
    ),
    "squatter-wine": JobSummary(
        title="CI Squatter Wine Gate",
        purpose="Runs the Windows Squatter payload under Wine and renders the Docker/Wine-backed documentation demo.",
        commands=("apt install wine32 wine64", "task modules:wine-test", "task docs:demos:wine"),
        proves=(
            "The Windows x86 Squatter payload can execute through Wine-backed tests.",
            "The Squatter MCP demo can drive provider commands end to end and produce a GIF.",
        ),
        details=(
            "This job exists separately because it needs host Wine support and is slower than normal module tests.",
            "The Docker-backed demo materializes docs/demo/out/mcp-agent-02-squatter-wine.gif.",
        ),
        artifact_globs=("../docs/demo/out/mcp-agent-02-squatter-wine.gif",),
    ),
    "pages-build": JobSummary(
        title="Pages Build",
        purpose="Rebuilds the docs slice after a successful CI run and uploads the staged _site/ tree for GitHub Pages.",
        commands=("task docs:ci", "actions/configure-pages", "actions/upload-pages-artifact"),
        proves=(
            "The Pages deployment artifact is generated from the same docs task used by CI.",
            "Rendered demos, SDK API docs, and link-checked static pages are present in _site/.",
        ),
        details=("Pages runs only after the CI workflow succeeds on main, or when manually dispatched.",),
        artifact_globs=("../docs/demo/out/*.gif",),
        site_root="../_site",
    ),
    "publish-hovel-build": JobSummary(
        title="Publish Hovel Wheels",
        purpose="Builds the hovel PyPI wheel set that packages the matching Hovel Go binary.",
        commands=("task release:hovel-wheels", "actions/upload-artifact"),
        proves=(
            "Root VERSION, core/VERSION, and sdk/python/pyproject.toml agree.",
            "The release tag matches the committed version on release-triggered runs.",
            "All configured hovel platform wheels are generated under core/dist/.",
        ),
        details=("The hovel-wheels artifact is consumed by the publish job.",),
        artifact_globs=("dist/hovel-*.whl",),
    ),
    "publish-sdk-build": JobSummary(
        title="Publish Hovel SDK Distribution",
        purpose="Builds the hovel-sdk Python source distribution and wheel for PyPI.",
        commands=("task release:hovel-sdk-dist", "actions/upload-artifact"),
        proves=(
            "Root VERSION, core/VERSION, and sdk/python/pyproject.toml agree.",
            "The release tag matches the committed version on release-triggered runs.",
            "The Python SDK sdist and wheel are generated under dist/.",
        ),
        details=("The hovel-sdk-dist artifact is consumed by the publish job.",),
        artifact_globs=("../dist/*",),
    ),
    "publish-modules-build": JobSummary(
        title="Publish Module Packages",
        purpose="Builds release assets for in-repo module packages and their install indexes.",
        commands=("task release:modules-package", "actions/upload-artifact"),
        proves=(
            "Root/core/SDK versions agree before release assets are produced.",
            "Module binaries are staged into modules/examples/bin/.",
            "Module packages, module-index.yaml, module-install-set.yaml, and SHA256SUMS are generated under dist/modules/.",
        ),
        details=("The module-packages artifact is consumed by the release asset attachment job.",),
        artifact_globs=("../dist/modules/*",),
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
        job.purpose,
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

    if job.proves:
        lines.extend(["", "### What This Proves", ""])
        lines.extend(f"- {item}" for item in job.proves)

    if job.details:
        lines.extend(["", "### Notes", ""])
        lines.extend(f"- {detail}" for detail in job.details)

    if job.coverage:
        lines.extend(read_coverage_summary())

    for artifact_glob in job.artifact_globs:
        lines.extend(render_artifacts(artifact_glob))

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
    lines = ["", "### Artifacts", "", f"{len(files)} file(s) matched `{display_pattern(pattern)}`."]
    if files:
        lines.extend(["", "| File | Size |", "| --- | ---: |"])
        for path in files[:20]:
            lines.append(f"| `{display_path(path)}` | {format_bytes(path.stat().st_size)} |")
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


def display_path(path: pathlib.Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def display_pattern(pattern: str) -> str:
    if pattern.startswith("../"):
        return pattern[3:]
    return f"core/{pattern}"


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
