"""Fail the verification gate when a cached lint action reports diagnostics."""
import json
from pathlib import Path
import sys


def main() -> int:
    failed = False
    for argument in sys.argv[1:]:
        root = Path(argument)
        result = json.loads((root / "result.json").read_text())
        print(result["id"], result["status"])
        print((root / "diagnostics.log").read_text())
        failed |= result["status"] != "PASSED"
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
