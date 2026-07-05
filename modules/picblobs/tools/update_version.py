#!/usr/bin/env python3
"""Update picblobs package versions across release-critical files.

Usage:
    python tools/update_version.py 0.2.0
    python tools/update_version.py v0.2.0 --dry-run
    python tools/update_version.py 0.2.0 --check
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_VERSION_RE = re.compile(
    r"""
    ^
    (?:0|[1-9]\d*)
    (?:\.(?:0|[1-9]\d*))+
    (?:(?:a|b|rc)(?:0|[1-9]\d*))?
    (?:\.post(?:0|[1-9]\d*))?
    (?:\.dev(?:0|[1-9]\d*))?
    (?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class VersionTarget:
    """One version occurrence that must stay in sync."""

    path: Path
    description: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Change:
    """A version replacement made by the updater."""

    path: Path
    description: str
    old: str
    new: str


class VersionUpdateError(RuntimeError):
    """Raised when a target file is missing or does not match expectations."""


@dataclass(frozen=True)
class TargetState:
    """Current matched version state for one version target."""

    target: VersionTarget
    text: str
    old: str


VERSION_TARGETS: tuple[VersionTarget, ...] = (
    VersionTarget(
        Path("python/pyproject.toml"),
        "picblobs package metadata",
        re.compile(r'(?m)^(version = ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path("python/picblobs/__init__.py"),
        "picblobs runtime __version__",
        re.compile(r'(?m)^(__version__ = ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path("python_cli/pyproject.toml"),
        "picblobs-cli package metadata",
        re.compile(r'(?m)^(version = ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path("python_cli/pyproject.toml"),
        "picblobs-cli picblobs dependency floor",
        re.compile(r'(?m)^(\s*"picblobs>=)([^"]+)(",)$'),
    ),
    VersionTarget(
        Path("python/uv.lock"),
        "editable picblobs uv lock entry",
        re.compile(
            r'(?m)^(\[\[package\]\]\nname = "picblobs"\nversion = ")([^"]+)(")$'
        ),
    ),
    VersionTarget(
        Path(".github/workflows/picblobs.yml"),
        "picblobs release workflow default",
        re.compile(r'(?m)^(\s+default: ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path(".github/workflows/picblobs-cli.yml"),
        "picblobs-cli release workflow default",
        re.compile(r'(?m)^(\s+default: ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path("CLAUDE.md"),
        "project version summary",
        re.compile(r"(?m)^(\*\*Version\*\*: )([^ |]+)( \|.*)$"),
    ),
    VersionTarget(
        Path("docs/guide/picblobs-cli.html"),
        "picblobs-cli info example, library version",
        re.compile(r"(?m)^(picblobs:\s+)(\S+)()$"),
    ),
    VersionTarget(
        Path("docs/guide/picblobs-cli.html"),
        "picblobs-cli info example, CLI version",
        re.compile(r"(?m)^(picblobs-cli:\s+)(\S+)()$"),
    ),
    VersionTarget(
        Path("spec/requirements/REQ-020-picblobs-cli.md"),
        "picblobs-cli requirement example",
        re.compile(r'(?m)^(\s+"picblobs>=)([^"]+)(",)$'),
    ),
    VersionTarget(
        Path("spec/models/MOD-007-release-tarball-format.md"),
        "release manifest version example",
        re.compile(r'(?m)^(\s+"picblobs_version": ")([^"]+)(",)$'),
    ),
    VersionTarget(
        Path("tools/extract_release.py"),
        "extract_release version parsing comment",
        re.compile(r'(?m)^(\s+# version = ")([^"]+)(")$'),
    ),
    VersionTarget(
        Path("python/tests/test_release_loading.py"),
        "extract_release test version fixture",
        re.compile(
            r"(?m)^(\s*monkeypatch\.setattr\("
            r'"tools\.extract_release\._get_version", lambda: ")([^"]+)("\))$'
        ),
    ),
)


def normalize_version(version: str) -> str:
    """Return a package version string, accepting an optional tag-style v prefix."""
    normalized = version.strip()
    if normalized.startswith(("v", "V")):
        normalized = normalized[1:]
    if not _VERSION_RE.fullmatch(normalized):
        raise VersionUpdateError(
            f"invalid version {version!r}; expected a PEP 440-style version "
            "such as 0.2.0, 1.0.0rc1, or 1.0.0.post1"
        )
    return normalized


def _replace_target(root: Path, target: VersionTarget, version: str) -> Change | None:
    state = _target_state(root, target)
    if state.old == version:
        return None

    updated = target.pattern.sub(
        lambda match: f"{match.group(1)}{version}{match.group(3)}",
        state.text,
        count=1,
    )
    (root / target.path).write_text(updated)
    return Change(target.path, target.description, state.old, version)


def _target_state(root: Path, target: VersionTarget) -> TargetState:
    path = root / target.path
    if not path.exists():
        raise VersionUpdateError(f"{target.path}: file does not exist")

    text = path.read_text()
    matches = list(target.pattern.finditer(text))
    if len(matches) != 1:
        raise VersionUpdateError(
            f"{target.path}: expected exactly one match for "
            f"{target.description}, found {len(matches)}"
        )
    return TargetState(target, text, matches[0].group(2))


def _pending_changes(root: Path, version: str) -> list[Change]:
    return [
        Change(state.target.path, state.target.description, state.old, version)
        for target in VERSION_TARGETS
        if (state := _target_state(root, target)).old != version
    ]


def _raise_if_check_failed(changes: list[Change]) -> None:
    if not changes:
        return
    details = "\n".join(
        f"  {change.path}: {change.old} != {change.new}" for change in changes
    )
    raise VersionUpdateError(f"version check failed:\n{details}")


def _apply_changes(root: Path, version: str) -> list[Change]:
    return [
        change
        for target in VERSION_TARGETS
        if (change := _replace_target(root, target, version)) is not None
    ]


def update_version(
    root: Path,
    version: str,
    *,
    dry_run: bool = False,
    check: bool = False,
) -> list[Change]:
    """Update all known version targets under *root*.

    Args:
        root: Repository root.
        version: New package version.
        dry_run: Report changes without writing files.
        check: Fail if any target is not already at *version*.

    Returns:
        List of required or applied changes.
    """
    normalized = normalize_version(version)
    changes = _pending_changes(root, normalized)

    if check:
        _raise_if_check_failed(changes)
        return []

    if dry_run:
        return changes

    return _apply_changes(root, normalized)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="New version, e.g. 0.2.0 or v0.2.0")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print changes without writing files",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if files are not already set to the requested version",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    try:
        changes = update_version(
            args.root.resolve(),
            args.version,
            dry_run=args.dry_run,
            check=args.check,
        )
    except VersionUpdateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.check:
        print(f"all version targets are {normalize_version(args.version)}")
        return 0

    action = "would update" if args.dry_run else "updated"
    if not changes:
        print(f"all version targets already set to {normalize_version(args.version)}")
        return 0

    for change in changes:
        print(f"{action} {change.path}: {change.old} -> {change.new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
