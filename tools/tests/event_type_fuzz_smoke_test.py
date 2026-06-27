#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <event_test_binary>", file=sys.stderr)
        return 2
    event_test = resolve_path(sys.argv[1])
    fuzz_cache = Path(os.environ.get("TEST_TMPDIR", "/tmp")) / "event-type-fuzz-cache"
    fuzz_cache.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [
            str(event_test),
            "-test.fuzz=FuzzNewTypeNeverAcceptsUntrimmedOrSingleSegmentValues",
            "-test.fuzztime=5s",
            f"-test.fuzzcachedir={fuzz_cache}",
        ],
        check=False,
    ).returncode


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
