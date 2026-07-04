#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <hovel binary>", file=sys.stderr)
        return 2
    hovel_bin = resolve_path(sys.argv[1])
    tmp_base = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    workspace = Path(tempfile.mkdtemp(prefix="hovel-binary-e2e.", dir=tmp_base))
    daemon: subprocess.Popen[str] | None = None
    try:
        env = os.environ | {
            "HOVEL_MODULE_CONFIG": str(find_runfile("modules/examples/python/hovel-modules.json")),
            "HOVEL_PYTHON_SDK_ROOT": str(find_runfile("sdk/python")),
        }
        daemon_out = (workspace / "daemon.out").open("w")
        daemon_err = (workspace / "daemon.err").open("w")
        daemon = subprocess.Popen(
            [str(hovel_bin), "daemon", "serve", "--workspace", str(workspace)],
            env=env,
            stdout=daemon_out,
            stderr=daemon_err,
            text=True,
        )
        wait_for_daemon(daemon, workspace)
        output = subprocess.check_output(
            [
                str(hovel_bin),
                "command",
                "throw",
                "--chain",
                "mock-exploit",
                "--target",
                "mock://target",
                "--workspace",
                str(workspace),
                "--now",
                "--json",
            ],
            env=env,
            text=True,
        )
        verify_output(workspace, output)
    finally:
        if daemon and daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


def wait_for_daemon(daemon: subprocess.Popen[str], workspace: Path) -> None:
    socket_path = workspace / "hoveld.sock"
    metadata_path = workspace / "daemon.json"
    for _ in range(200):
        if socket_path.exists() and metadata_path.exists():
            return
        if daemon.poll() is not None:
            fail_with_daemon_logs(workspace, "daemon exited before it was ready")
        time.sleep(0.05)
    fail_with_daemon_logs(workspace, "daemon socket was not created")


def fail_with_daemon_logs(workspace: Path, message: str) -> None:
    print(message, file=sys.stderr)
    for name in ("daemon.out", "daemon.err"):
        path = workspace / name
        if path.exists():
            print(path.read_text(errors="replace"), file=sys.stderr)
    raise SystemExit(1)


def verify_output(workspace: Path, output: str) -> None:
    payload = json.loads(output)
    assert payload["chain"] == "mock-exploit", payload
    assert payload["targets"] == ["mock://target"], payload
    assert len(payload["results"]) == 1, payload
    result = payload["results"][0]
    assert result["state"] == "succeeded", result
    assert result["moduleId"] == "mock-exploit@v0.0.0-example", result
    assert result["findings"], result
    assert result["artifacts"], result
    plan = payload["plan"]
    with sqlite3.connect(workspace / "workspace.db") as db:
        row = db.execute("select plan_json from throw_plans where id = ?", (plan["id"],)).fetchone()
        versions = [item[0] for item in db.execute("select version from schema_migrations order by version")]
    assert row, payload
    record = json.loads(row[0])
    assert record["id"] == plan["id"], record
    assert record["confirmationId"] == plan["confirmationId"], record
    assert record["workspace"] == str(workspace), record
    assert versions == [1, 2, 3, 4, 5], versions


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    return find_runfile(path)


def find_runfile(rel: str) -> Path:
    for root in runfile_roots():
        for prefix in ("", "_main", "hovel"):
            candidate = root / prefix / rel
            if candidate.exists():
                return candidate.resolve()
    raise SystemExit(f"missing runfile: {rel}")


def runfile_roots() -> list[Path]:
    roots = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    return roots


if __name__ == "__main__":
    raise SystemExit(main())
