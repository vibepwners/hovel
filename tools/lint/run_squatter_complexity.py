#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run lizard complexity checks over Squatter C sources.")
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    env = os.environ.copy()
    extra_paths = []
    home = env.get("HOME")
    if home:
        extra_paths.append(f"{home}/.local/bin")
    extra_paths.extend(["/home/user/.local/bin", "/home/runner/.local/bin"])
    env["PATH"] = ":".join(extra_paths + [env.get("PATH", "")])

    lizard = shutil.which("lizard", path=env.get("PATH"))
    if lizard:
        command = [lizard, "-w", "-C", "10", *map(str, args.sources)]
    else:
        python = shutil.which("python3") or shutil.which("python")
        if python is None:
            print("lizard is required for task squatter:complexity", file=sys.stderr)
            return 127
        probe = subprocess.run([python, "-m", "lizard", "--version"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode != 0:
            print("lizard is required for task squatter:complexity", file=sys.stderr)
            print("Install it as a stable Python tool, then rerun: uv tool install lizard", file=sys.stderr)
            return 127
        command = [python, "-m", "lizard", "-w", "-C", "10", *map(str, args.sources)]

    subprocess.run(command, check=True, env=env)
    args.stamp.parent.mkdir(parents=True, exist_ok=True)
    args.stamp.write_text("ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
