"""Enforce an aggregate line-coverage floor for a Bazel LCOV report."""

from __future__ import annotations

import argparse
from pathlib import Path


def totals(report: str) -> tuple[int, int]:
    """Return aggregate (lines hit, lines found) from an LCOV report."""
    lines_hit = 0
    lines_found = 0
    for raw_line in report.splitlines():
        key, separator, value = raw_line.partition(":")
        if not separator:
            continue
        if key == "LH":
            lines_hit += int(value)
        elif key == "LF":
            lines_found += int(value)
    if lines_found == 0:
        raise ValueError("LCOV report contains no instrumented lines")
    if lines_hit > lines_found:
        raise ValueError(
            f"LCOV report has more hit lines than found lines: {lines_hit}/{lines_found}"
        )
    return lines_hit, lines_found


def percentage(lines_hit: int, lines_found: int) -> float:
    return 100.0 * lines_hit / lines_found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--minimum", type=float, required=True)
    args = parser.parse_args()
    if not 0.0 <= args.minimum <= 100.0:
        parser.error("--minimum must be between 0 and 100")

    try:
        lines_hit, lines_found = totals(args.lcov.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    actual = percentage(lines_hit, lines_found)
    print(
        "Squatter Go aggregate line coverage: "
        f"{actual:.2f}% ({lines_hit}/{lines_found}); required {args.minimum:.2f}%"
    )
    return 0 if actual >= args.minimum else 1


if __name__ == "__main__":
    raise SystemExit(main())
