#!/usr/bin/env python3
"""End-to-end NaCl encrypted handshake test without host shell tools."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXPECTED_MSG = "Hello from NaCl PIC blob!"


def main() -> int:
    paths = parse_args()
    if paths is None:
        return 2

    qemu, runner, server, client = paths
    print("=== NaCl E2E test ===")
    server_exit, client_exit, server_output, client_output = run_exchange(
        qemu,
        runner,
        server,
        client,
    )
    print_output("Server", server_output)
    print_output("Client", client_output)

    failures = check_exchange(server_exit, client_exit, server_output)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("=== FAIL ===")
        return 1

    print("=== PASS ===")
    return 0


def parse_args() -> tuple[Path, Path, Path, Path] | None:
    if len(sys.argv) == 5:
        return tuple(resolve_path(arg) for arg in sys.argv[1:])  # type: ignore[return-value]
    print(
        "usage: nacl_e2e_test.py <qemu> <runner> <server.bin> <client.bin>",
        file=sys.stderr,
    )
    return None


def run_exchange(
    qemu: Path,
    runner: Path,
    server: Path,
    client: Path,
) -> tuple[int, int, str, str]:
    with tempfile.TemporaryDirectory(
        prefix="nacl-e2e-", dir=os.environ.get("TEST_TMPDIR")
    ) as tmp_raw:
        tmp = Path(tmp_raw)
        server_log = tmp / "server.out"
        client_log = tmp / "client.out"

        with server_log.open("wb") as out:
            server_proc = subprocess.Popen(
                [str(qemu), str(runner), str(server)],
                stdout=out,
                stderr=subprocess.STDOUT,
            )

        try:
            time.sleep(1.0)
            with client_log.open("wb") as out:
                client_proc = subprocess.run(
                    [str(qemu), str(runner), str(client)],
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=30,
                )
            client_exit = client_proc.returncode
            server_exit = wait_server(server_proc)
        finally:
            if server_proc.poll() is None:
                server_proc.kill()
                server_proc.wait()

        server_output = read_text(server_log)
        client_output = read_text(client_log)
    return server_exit, client_exit, server_output, client_output


def wait_server(server_proc: subprocess.Popen[bytes]) -> int:
    try:
        return server_proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        server_proc.kill()
        return 124


def print_output(name: str, output: str) -> None:
    print(f"--- {name} output ---")
    print(output, end="" if output.endswith("\n") else "\n")


def check_exchange(server_exit: int, client_exit: int, server_output: str) -> list[str]:
    failures = check_process_exits(server_exit, client_exit)
    failures.extend(check_payload(server_output))
    failures.extend(check_channel(server_output))
    return failures


def check_process_exits(server_exit: int, client_exit: int) -> list[str]:
    failures: list[str] = []
    if server_exit != 0:
        failures.append(f"server exited {server_exit}")
    if client_exit != 0:
        failures.append(f"client exited {client_exit}")
    return failures


def check_payload(server_output: str) -> list[str]:
    actual_msg = decrypted_message(server_output)
    if actual_msg is None:
        return ["server did not print decrypted message"]

    expected_hash = sha256_text(EXPECTED_MSG)
    actual_hash = sha256_text(actual_msg)
    if expected_hash == actual_hash:
        print(f"OK: payload SHA256 match ({expected_hash})")
        return []
    return [
        "payload SHA256 mismatch\n"
        f"  expected: {expected_hash} ({EXPECTED_MSG})\n"
        f"  actual:   {actual_hash} ({actual_msg})",
    ]


def check_channel(server_output: str) -> list[str]:
    if "secure channel OK" in server_output:
        print("OK: secure channel confirmed")
        return []
    return ["server did not confirm secure channel"]


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root_raw = os.environ.get(root_name)
        if not root_raw:
            continue
        root = Path(root_raw)
        for candidate in (
            root / value,
            root / "_main" / value,
            root / "hovel_slices" / value,
        ):
            if candidate.exists():
                return candidate
    return path


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def decrypted_message(output: str) -> str | None:
    for line in output.splitlines():
        marker = "decrypted: "
        if marker in line:
            return line.split(marker, 1)[1]
    return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
