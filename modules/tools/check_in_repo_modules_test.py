#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    hovel_bin = resolve_path(required_arg(1, "missing hovel binary"))
    binaries = [resolve_path(arg) for arg in os.sys.argv[2:9]]
    if len(binaries) != 7:
        raise SystemExit("expected seven module binary arguments")

    python_root = find_first_runfile("modules/examples/python", "examples/python")
    sdk_root = find_runfile("sdk/python")

    with tempfile.TemporaryDirectory(prefix="hovel-module-check-", dir=test_tmpdir()) as tmp_raw:
        tmp = Path(tmp_raw)
        config = tmp / "hovel-modules.json"
        config.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "id": "ms17-010-survey",
                            "runtime": "jsonrpc-stdio",
                            "project_dir": str(python_root / "ms17_010_survey"),
                            "module": "hovel_ms17_010_survey",
                        },
                        {
                            "id": "ms17-010-exploit",
                            "runtime": "jsonrpc-stdio",
                            "project_dir": str(python_root / "ms17_010_exploit"),
                            "module": "hovel_ms17_010_exploit",
                        },
                        {
                            "id": "mock-survey",
                            "runtime": "jsonrpc-stdio",
                            "project_dir": str(python_root / "mock_survey"),
                            "module": "hovel_example_survey",
                        },
                        {
                            "id": "mock-exploit",
                            "runtime": "jsonrpc-stdio",
                            "project_dir": str(python_root / "mock_exploit"),
                            "module": "hovel_example_exploit",
                        },
                        {
                            "id": "mock-exploit-session",
                            "runtime": "jsonrpc-stdio",
                            "project_dir": str(python_root / "mock_exploit_session"),
                            "module": "hovel_example_exploit_session",
                        },
                        {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": [str(binaries[0])]},
                        {"id": "mock-exploit-go", "runtime": "jsonrpc-stdio", "command": [str(binaries[1])]},
                        {
                            "id": "mock-exploit-session-go",
                            "runtime": "jsonrpc-stdio",
                            "command": [str(binaries[2])],
                        },
                        {"id": "mock-survey-rust", "runtime": "jsonrpc-stdio", "command": [str(binaries[3])]},
                        {"id": "mock-exploit-rust", "runtime": "jsonrpc-stdio", "command": [str(binaries[4])]},
                        {
                            "id": "mock-exploit-session-rust",
                            "runtime": "jsonrpc-stdio",
                            "command": [str(binaries[5])],
                        },
                        {"id": "squatter", "runtime": "jsonrpc-stdio", "command": [str(binaries[6])]},
                    ]
                },
                indent=2,
            )
            + "\n"
        )

        env = os.environ | {
            "HOVEL_MODULE_CONFIG": str(config),
            "HOVEL_PYTHON_SDK_ROOT": str(sdk_root),
        }
        out = run([str(hovel_bin), "module", "check", "--all"], env=env)
        require_contains(out, "MODULE CHECKS")
        require_contains(out, "12 passed")
        require_contains(out, "squatter@v0.1.0")
        require_contains(out, "PASS")

        workspace = tmp / "workspace"
        run_out = run([str(hovel_bin), "run", "--workspace", str(workspace), "--", "module", "check", "mock-survey"], env=env)
        require_contains(run_out, "MODULE CHECK mock-survey")
        require_contains(run_out, "status")
        require_contains(run_out, "PASS")
        require_contains(run_out, "config schema")
        require_contains(run_out, "step contracts")
    return 0


def required_arg(index: int, message: str) -> str:
    try:
        return os.sys.argv[index]
    except IndexError as exc:
        raise SystemExit(message) from exc


def run(argv: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(argv, check=True, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    return result.stdout


def require_contains(text: str, expected: str) -> None:
    if expected not in text:
        raise AssertionError(f"expected output to include {expected!r}:\n{text}")


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    return find_runfile(path)


def find_runfile(rel: str) -> Path:
    return find_first_runfile(rel)


def find_first_runfile(*rels: str) -> Path:
    for root in runfile_roots():
        for prefix in ("", "_main", "hovel"):
            for rel in rels:
                candidate = root / prefix / rel
                if candidate.exists():
                    return candidate.resolve()
    raise SystemExit(f"missing runfile: {' or '.join(rels)}")


def runfile_roots() -> list[Path]:
    roots = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    return roots


def test_tmpdir() -> str | None:
    return "/tmp"


if __name__ == "__main__":
    raise SystemExit(main())
