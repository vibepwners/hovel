#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    for raw in sys.argv[1:]:
        path = Path(raw)
        if not path.is_file():
            print(f"site_smoke_test: expected file not found: {path}", file=sys.stderr)
            return 1
        if "assets/site.css" not in path.read_text(encoding="utf-8"):
            print(f"site_smoke_test: {path} is missing the shared stylesheet link", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
