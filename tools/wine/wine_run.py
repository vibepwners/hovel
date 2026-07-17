"""Bazel run-under adapter for executing Windows tests with host Wine."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Mapping, Sequence


def _wine_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Return an isolated, headless-friendly Wine environment."""
    environment = dict(source)
    test_tmpdir = source.get("TEST_TMPDIR")
    scratch = Path(test_tmpdir) if test_tmpdir else Path(
        tempfile.mkdtemp(prefix="hovel-wine-")
    )

    runtime_dir = Path(source.get("XDG_RUNTIME_DIR", scratch / "xdg-runtime"))
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime_dir.chmod(0o700)

    environment["WINEPREFIX"] = source.get(
        "WINEPREFIX", str(scratch / "wine-prefix")
    )
    environment["XDG_RUNTIME_DIR"] = str(runtime_dir)
    environment.setdefault("WINEDEBUG", "-all")
    return environment


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print("wine_run: expected a Windows test executable", file=sys.stderr)
        return 2

    try:
        # Bazel invokes run-under tools from the test's runfiles directory. The
        # apparent executable is a long symlink which can cross Wine's legacy
        # MAX_PATH boundary. Resolve it before Wine translates the Unix path.
        executable = Path(arguments[0]).resolve(strict=True)
    except OSError as error:
        print(f"wine_run: cannot resolve {arguments[0]}: {error}", file=sys.stderr)
        return 2

    environment = _wine_environment(os.environ)
    wine = environment.get("HOVEL_WINE_BIN", "wine")
    try:
        result = subprocess.run(
            [wine, str(executable), *arguments[1:]],
            check=False,
            env=environment,
        )
    except FileNotFoundError:
        print(f"wine_run: Wine executable not found: {wine}", file=sys.stderr)
        return 127
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
