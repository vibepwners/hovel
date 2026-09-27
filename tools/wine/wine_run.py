"""Run Windows tests with the pinned Wine container or an explicit host override."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Mapping, Sequence
from tools.wine.environment import image_ref


def container_command(executable: Path, arguments: list[str], environment: Mapping[str, str]) -> list[str]:
    output_root = next((p.parent for p in executable.parents if p.name == "execroot"), executable.parent)
    scratch = Path(environment["TEST_TMPDIR"]).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    command = [
        "docker", "run", "--rm", "--init", "--network=none",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--volume", f"{output_root}:{output_root}:ro",
        "--volume", f"{scratch}:/work", "--workdir", "/work",
    ]
    environment = dict(environment) | {
        "WINEPREFIX": "/work/wine-prefix",
        "TEST_TMPDIR": "/work",
        "XDG_RUNTIME_DIR": "/work/xdg-runtime",
    }
    writable = set()
    if environment.get("XML_OUTPUT_FILE"):
        writable.add(Path(environment["XML_OUTPUT_FILE"]).resolve().parent)
    if environment.get("TEST_UNDECLARED_OUTPUTS_DIR"):
        writable.add(Path(environment["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve())
    for path in sorted(writable):
        path.mkdir(parents=True, exist_ok=True)
        command.extend(["--volume", f"{path}:{path}"])
    for name in ["WINEPREFIX", "WINEARCH", "WINEDEBUG", "XDG_RUNTIME_DIR", "TEST_TMPDIR", "XML_OUTPUT_FILE", "GTEST_OUTPUT", "TEST_UNDECLARED_OUTPUTS_DIR"]:
        if name in environment:
            command.extend(["--env", name + "=" + environment[name]])
    command.extend(["--env", "HOME=" + environment["TEST_TMPDIR"], "--entrypoint=wine", image_ref(), str(executable), *arguments])
    return command


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
    environment["TEST_TMPDIR"] = str(scratch)
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
    wine = environment.get("HOVEL_WINE_BIN")
    command = [wine, str(executable), *arguments[1:]] if wine else container_command(executable, arguments[1:], environment)
    try:
        result = subprocess.run(
            command,
            check=False,
            env=environment,
        )
    except FileNotFoundError:
        print(f"wine_run: executable not found: {command[0]}", file=sys.stderr)
        return 127
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
