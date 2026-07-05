#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


FUZZ_COVERAGE_WARNING = (
    "warning: the test binary was not built with coverage instrumentation, "
    "so fuzzing will run without coverage guidance and may be inefficient"
)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <event_test_binary>", file=sys.stderr)
        return 2
    event_test = resolve_path(sys.argv[1])
    fuzz_cache = Path(os.environ.get("TEST_TMPDIR", "/tmp")) / "event-type-fuzz-cache"
    fuzz_cache.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            str(event_test),
            "-test.fuzz=FuzzNewTypeNeverAcceptsUntrimmedOrSingleSegmentValues",
            "-test.fuzztime=5s",
            f"-test.fuzzcachedir={fuzz_cache}",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    write_filtered(sys.stdout, completed.stdout)
    write_filtered(sys.stderr, completed.stderr)
    return completed.returncode


def write_filtered(stream, text: str) -> None:
    for line in text.splitlines():
        if line.strip() == FUZZ_COVERAGE_WARNING:
            continue
        print(line, file=stream)


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / path
            if candidate.exists():
                return candidate.resolve()
    raise SystemExit(f"missing runfile: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
