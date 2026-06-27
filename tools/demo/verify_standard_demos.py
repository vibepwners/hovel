#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 6:
        raise SystemExit("usage: verify_standard_demos.py <hovel> <agent> <mock-survey> <mock-exploit-session> <chain>")
    hovel_bin = resolve_path(sys.argv[1])
    agent_bin = resolve_path(sys.argv[2])
    mock_survey_go = resolve_path(sys.argv[3])
    mock_exploit_session_go = resolve_path(sys.argv[4])
    chain_file = resolve_path(sys.argv[5])
    daemons: list[subprocess.Popen[str]] = []

    with tempfile.TemporaryDirectory(prefix="hovel-demo-verify-", dir=test_tmpdir()) as tmp_raw:
        tmp = Path(tmp_raw)
        config = tmp / "hovel-modules.json"
        config.write_text(
            json.dumps(
                {
                    "modules": [
                        {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": [str(mock_survey_go)]},
                        {
                            "id": "mock-exploit-session-go",
                            "runtime": "jsonrpc-stdio",
                            "command": [str(mock_exploit_session_go)],
                        },
                    ]
                },
                indent=2,
            )
            + "\n"
        )
        env = os.environ | {"HOVEL_MODULE_CONFIG": str(config)}
        try:
            verify_saved_chain(tmp, hovel_bin, chain_file, env, daemons)
            verify_constructed_chain(tmp, hovel_bin, env, daemons)
            verify_agent(tmp, hovel_bin, agent_bin, env, daemons)
        finally:
            for daemon in daemons:
                stop_process(daemon)
    return 0


def verify_saved_chain(tmp: Path, hovel_bin: Path, chain_file: Path, env: dict[str, str], daemons: list[subprocess.Popen[str]]) -> None:
    workspace = tmp / "w-verify-saved"
    workspace.mkdir()
    start_demo_daemon(workspace, hovel_bin, env, daemons)
    payload = run_json([str(hovel_bin), "throw", str(chain_file), "--workspace", str(workspace), "--now", "--json"], env)
    verify_mock_throw_json(payload, "mock-survey-exploit-demo")
    run([str(hovel_bin), "session", "send", "latest", "whoami", "--workspace", str(workspace)], env)
    session_output = run([str(hovel_bin), "session", "read", "latest", "--workspace", str(workspace)], env)
    require_contains(session_output, "mock-operator")


def verify_constructed_chain(tmp: Path, hovel_bin: Path, env: dict[str, str], daemons: list[subprocess.Popen[str]]) -> None:
    workspace = tmp / "w-verify-built"
    chain = "mock-survey-exploit-commands-verify"
    workspace.mkdir()
    start_demo_daemon(workspace, hovel_bin, env, daemons)
    configure_chain(hovel_bin, workspace, chain, env)
    payload = run_json(
        [str(hovel_bin), "run", "--workspace", str(workspace), "--op", "demo", "--chain", chain, "--", "throw", "--now", "--json"],
        env,
    )
    verify_mock_throw_json(payload, chain)
    run([str(hovel_bin), "run", "--workspace", str(workspace), "--op", "demo", "--chain", chain, "--", "session", "send", "latest", "whoami"], env)
    session_output = run([str(hovel_bin), "run", "--workspace", str(workspace), "--op", "demo", "--chain", chain, "--", "session", "read", "latest"], env)
    require_contains(session_output, "mock-operator")


def verify_agent(tmp: Path, hovel_bin: Path, agent_bin: Path, env: dict[str, str], daemons: list[subprocess.Popen[str]]) -> None:
    workspace = tmp / "w-verify-mcp-agent"
    chain = "mock-survey-exploit-agent-verify"
    workspace.mkdir()
    start_demo_daemon(workspace, hovel_bin, env, daemons)
    configure_chain(hovel_bin, workspace, chain, env)
    output = run(
        [
            str(agent_bin),
            "--hovel",
            str(hovel_bin),
            "--workspace",
            str(workspace),
            "--op",
            "demo",
            "--chain",
            chain,
            "--no-color",
            "--delay",
            "0",
        ],
        env,
    )
    for expected in (
        "tool: hovel_workspace_snapshot",
        "tool: hovel_throw_start",
        "mock://router-01",
        "mock-survey-go@v0.0.0-example",
        "mock exploit opened an interactive shell session",
        "Hovel throw completed",
    ):
        require_contains(output, expected)


def configure_chain(hovel_bin: Path, workspace: Path, chain: str, env: dict[str, str]) -> None:
    base = [str(hovel_bin), "run", "--workspace", str(workspace), "--op", "demo"]
    run([*base, "--", "chain", "create", chain], env)
    chain_base = [*base, "--chain", chain, "--"]
    run([*chain_base, "chain", "add", "mock-survey-go"], env)
    run([*chain_base, "chain", "add", "mock-exploit-session-go"], env)
    run([*chain_base, "target", "add", "mock://router-01"], env)
    run([*chain_base, "target", "config", "set", "mock://router-01", "target.host", "router-01"], env)
    run([*chain_base, "target", "config", "set", "mock://router-01", "target.port", "443"], env)
    run([*chain_base, "chain", "config", "set", "operator.confirmed_lab", "true"], env)


def verify_mock_throw_json(payload: dict[str, object], chain: str) -> None:
    assert payload["chain"] == chain, payload
    assert payload["targets"] == ["mock://router-01"], payload
    results = payload["results"]
    assert [item["moduleId"] for item in results] == [
        "mock-survey-go@v0.0.0-example",
        "mock-exploit-session-go@v0.0.0-example",
    ], results
    assert all(item["state"] == "succeeded" for item in results), results
    assert results[0]["summary"] == "example survey reached router-01:443", results[0]
    assert results[1]["summary"] == "mock exploit opened an interactive shell session", results[1]
    assert results[1]["findings"], results[1]
    assert len(results[1]["sessions"]) == 1, results[1]
    session = results[1]["sessions"][0]
    assert session["name"] == "mock shell on mock://router-01", session
    assert session["kind"] == "shell", session
    assert session["state"] == "active", session


def start_demo_daemon(workspace: Path, hovel_bin: Path, env: dict[str, str], daemons: list[subprocess.Popen[str]]) -> None:
    log = (workspace / "daemon.log").open("w")
    daemon = subprocess.Popen([str(hovel_bin), "daemon", "serve", "--workspace", str(workspace)], env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
    daemons.append(daemon)
    socket_path = workspace / "hoveld.sock"
    for _ in range(100):
        if daemon_socket_ready(socket_path):
            return
        if daemon.poll() is not None:
            raise SystemExit(f"demo verification daemon exited before becoming ready\n{(workspace / 'daemon.log').read_text(errors='replace')}")
        time.sleep(0.1)
    raise SystemExit(f"timed out waiting for demo verification daemon at {socket_path}\n{(workspace / 'daemon.log').read_text(errors='replace')}")


def daemon_socket_ready(socket_path: Path) -> bool:
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(0.2)
        sock.connect(str(socket_path))
        sock.close()
        return True
    except OSError:
        return False


def run(argv: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(argv, env=env, text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    return result.stdout


def run_json(argv: list[str], env: dict[str, str]) -> dict[str, object]:
    return json.loads(run(argv, env))


def require_contains(text: str, expected: str) -> None:
    if expected not in text:
        raise AssertionError(f"expected output to include {expected!r}:\n{text}")


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    for root in runfile_roots():
        for prefix in ("", "_main", "hovel"):
            candidate = root / prefix / path
            if candidate.exists():
                return candidate.resolve()
    raise SystemExit(f"missing runfile: {path}")


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
