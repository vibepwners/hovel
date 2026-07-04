#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def main() -> int:
    home_raw = os.environ.get("HOME")
    if not home_raw:
        raise SystemExit("HOME is not set")
    home = Path(home_raw).expanduser()

    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    runner_temp.mkdir(parents=True, exist_ok=True)
    ci_bazelrc = runner_temp / "bazel-ci.bazelrc"

    buildbuddy_api_key = os.environ.get("BUILDBUDDY_API_KEY", "")
    bazel_configs = ["--config=github-actions"]
    rc_lines = [
        f"build:github-actions --repository_cache={home / '.cache' / 'bazel-repository'}",
    ]

    if buildbuddy_api_key:
        print(f"::add-mask::{buildbuddy_api_key}")
        rc_lines.extend([
            "common --noannounce_rc",
            f"build:ci --remote_header=x-buildbuddy-api-key={buildbuddy_api_key}",
        ])
        bazel_configs.append("--config=ci")

    ci_bazelrc.write_text("\n".join(rc_lines) + "\n", encoding="utf-8")
    ci_bazelrc.chmod(stat.S_IRUSR | stat.S_IWUSR)

    github_env = os.environ.get("GITHUB_ENV")
    if not github_env:
        print(f"HOVEL_BAZEL_STARTUP_ARGS=--bazelrc={ci_bazelrc}")
        print(f"HOVEL_BAZEL_ARGS={' '.join(bazel_configs)}")
        return 0

    with Path(github_env).open("a", encoding="utf-8") as env_file:
        env_file.write(f"HOVEL_BAZEL_STARTUP_ARGS=--bazelrc={ci_bazelrc}\n")
        env_file.write(f"HOVEL_BAZEL_ARGS={' '.join(bazel_configs)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
