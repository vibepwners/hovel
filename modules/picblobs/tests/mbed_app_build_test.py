from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mbed_app_build_test.py <mbed-app-binary>", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1])
    if not binary.is_file() or binary.stat().st_size == 0:
        print(f"missing or empty Mbed app build: {binary}", file=sys.stderr)
        return 1
    print(f"Mbed app compile/link smoke: {binary} ({binary.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
