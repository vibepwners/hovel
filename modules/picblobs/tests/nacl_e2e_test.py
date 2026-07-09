#!/usr/bin/env python3
"""End-to-end NaCl encrypted handshake test without host shell tools."""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

EXPECTED_MSG = "Hello from NaCl PIC blob!"
EXPECTED_ACK = "OK"
E2E_AUTH_KEY = bytes(range(1, 33))
E2E_PROXY_PORT = 9999
E2E_SERVER_PORT = 9998
SERVER_CONFIG_SIZE = 34
CLIENT_CONFIG_SIZE = 38
NONCE_SIZE = 24
FRAME_HEADER_SIZE = NONCE_SIZE + 4
SECRETBOX_OVERHEAD = 16


def main() -> int:
    parsed = parse_args()
    if parsed is None:
        return 2

    qemu, runner, server, client, run_negative = parsed
    print("=== NaCl E2E test ===")
    exchange = run_exchange(
        qemu,
        runner,
        server,
        client,
    )
    server_exit, client_exit, server_output, client_output, to_server, to_client = (
        exchange
    )
    print_output("Server", server_output)
    print_output("Client", client_output)

    failures = check_exchange(
        server_exit,
        client_exit,
        server_output,
        client_output,
        to_server,
        to_client,
    )
    if run_negative and not failures:
        failures.extend(run_tamper_checks(qemu, runner, server, client))
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("=== FAIL ===")
        return 1

    print("=== PASS ===")
    return 0


def parse_args() -> tuple[Path, Path, Path, Path, bool] | None:
    args = sys.argv[1:]
    run_negative = False
    if "--negative" in args:
        args.remove("--negative")
        run_negative = True
    if len(args) == 4:
        paths = tuple(resolve_path(arg) for arg in args)
        return (*paths, run_negative)  # type: ignore[return-value]
    print(
        "usage: nacl_e2e_test.py <qemu> <runner> <server.bin> <client.bin> "
        "[--negative]",
        file=sys.stderr,
    )
    return None


def run_exchange(
    qemu: Path,
    runner: Path,
    server: Path,
    client: Path,
    tamper_direction: str | None = None,
) -> tuple[int, int, str, str, bytes, bytes]:
    with tempfile.TemporaryDirectory(
        prefix="nacl-e2e-", dir=os.environ.get("TEST_TMPDIR")
    ) as tmp_raw:
        tmp = Path(tmp_raw)
        server_log = tmp / "server.out"
        client_log = tmp / "client.out"
        configured_server = tmp / "server.bin"
        configured_client = tmp / "client.bin"
        configure_blob(server, configured_server, server_config())
        configure_blob(client, configured_client, client_config())

        proxy = WireProxy(tamper_direction)

        with server_log.open("wb") as out:
            server_proc = subprocess.Popen(
                [str(qemu), str(runner), str(configured_server)],
                stdout=out,
                stderr=subprocess.STDOUT,
            )

        try:
            proxy.start()
            time.sleep(1.0)
            with client_log.open("wb") as out:
                client_proc = subprocess.run(
                    [str(qemu), str(runner), str(configured_client)],
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
            proxy.close()

        server_output = read_text(server_log)
        client_output = read_text(client_log)
    proxy.raise_if_failed()
    return (
        server_exit,
        client_exit,
        server_output,
        client_output,
        bytes(proxy.to_server),
        bytes(proxy.to_client),
    )


class WireProxy:
    """Capture and relay framed traffic between the client and server."""

    def __init__(self, tamper_direction: str | None) -> None:
        self.tamper_direction = tamper_direction
        self.to_server = bytearray()
        self.to_client = bytearray()
        self.error: Exception | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", E2E_PROXY_PORT))
        self.listener.listen(1)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive() and self.error is None:
            self.error = TimeoutError("wire proxy did not stop")

    def raise_if_failed(self) -> None:
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        try:
            client, _ = self.listener.accept()
            server = connect_server()
            self._relay(client, server)
        except Exception as error:  # noqa: BLE001 - propagate from worker thread
            self.error = error

    def _relay(self, client: socket.socket, server: socket.socket) -> None:
        with client, server:
            to_server = threading.Thread(
                target=relay_frames,
                args=(
                    client,
                    server,
                    self.to_server,
                    self.tamper_direction == "to_server",
                ),
            )
            to_client = threading.Thread(
                target=relay_frames,
                args=(
                    server,
                    client,
                    self.to_client,
                    self.tamper_direction == "to_client",
                ),
            )
            to_server.start()
            to_client.start()
            to_server.join()
            to_client.join()


def connect_server() -> socket.socket:
    for _ in range(50):
        try:
            return socket.create_connection(
                ("127.0.0.1", E2E_SERVER_PORT), timeout=0.5
            )
        except OSError:
            time.sleep(0.1)
    raise ConnectionError("wire proxy could not connect to server")


def relay_frames(
    source: socket.socket,
    destination: socket.socket,
    capture: bytearray,
    tamper_application_frame: bool,
) -> None:
    pending = bytearray()
    frame_index = 0
    try:
        while chunk := source.recv(4096):
            pending.extend(chunk)
            for frame in take_complete_frames(pending):
                frame_index += 1
                if tamper_application_frame and frame_index == 2:
                    frame[-1] ^= 1
                capture.extend(frame)
                destination.sendall(frame)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        if pending:
            capture.extend(pending)
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def take_complete_frames(pending: bytearray) -> list[bytearray]:
    frames = []
    while len(pending) >= FRAME_HEADER_SIZE:
        ciphertext_size = struct.unpack_from("<I", pending, NONCE_SIZE)[0]
        frame_size = FRAME_HEADER_SIZE + ciphertext_size
        if len(pending) < frame_size:
            break
        frames.append(bytearray(pending[:frame_size]))
        del pending[:frame_size]
    return frames


def wait_server(server_proc: subprocess.Popen[bytes]) -> int:
    try:
        return server_proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        server_proc.kill()
        return 124


def print_output(name: str, output: str) -> None:
    print(f"--- {name} output ---")
    print(output, end="" if output.endswith("\n") else "\n")


def check_exchange(
    server_exit: int,
    client_exit: int,
    server_output: str,
    client_output: str,
    to_server: bytes,
    to_client: bytes,
) -> list[str]:
    failures = check_process_exits(server_exit, client_exit)
    failures.extend(check_payload(server_output))
    failures.extend(check_channels(server_output, client_output))
    failures.extend(check_ack(client_output))
    failures.extend(check_wire(to_server, to_client))
    return failures


def check_wire(to_server: bytes, to_client: bytes) -> list[str]:
    try:
        client_frames = parse_frames(to_server)
        server_frames = parse_frames(to_client)
    except ValueError as error:
        return [str(error)]

    failures = check_frame_sizes(client_frames, server_frames)
    nonces = [frame[0] for frame in client_frames + server_frames]
    if any(not any(nonce) for nonce in nonces):
        failures.append("wire capture contains an all-zero nonce")
    if len(set(nonces)) != len(nonces):
        failures.append("wire capture reused a nonce")
    if EXPECTED_MSG.encode() in to_server:
        failures.append("client plaintext appeared on the wire")
    if not failures:
        print("OK: wire capture contains encrypted, authenticated frames both ways")
    return failures


def check_frame_sizes(
    client_frames: list[tuple[bytes, bytes]],
    server_frames: list[tuple[bytes, bytes]],
) -> list[str]:
    if len(client_frames) != 2 or len(server_frames) != 2:
        return [
            "wire capture expected two frames each way, got "
            f"client={len(client_frames)} server={len(server_frames)}"
        ]
    expected_client = [32 + SECRETBOX_OVERHEAD, len(EXPECTED_MSG) + SECRETBOX_OVERHEAD]
    expected_server = [32 + SECRETBOX_OVERHEAD, len(EXPECTED_ACK) + SECRETBOX_OVERHEAD]
    actual_client = [len(ciphertext) for _, ciphertext in client_frames]
    actual_server = [len(ciphertext) for _, ciphertext in server_frames]
    if actual_client == expected_client and actual_server == expected_server:
        return []
    return [
        "wire ciphertext sizes did not include the secretbox authenticator: "
        f"client={actual_client} server={actual_server}"
    ]


def parse_frames(data: bytes) -> list[tuple[bytes, bytes]]:
    frames = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < FRAME_HEADER_SIZE:
            raise ValueError("wire capture ended inside a frame header")
        ciphertext_size = struct.unpack_from("<I", data, offset + NONCE_SIZE)[0]
        frame_end = offset + FRAME_HEADER_SIZE + ciphertext_size
        if frame_end > len(data):
            raise ValueError("wire capture ended inside frame ciphertext")
        nonce = data[offset : offset + NONCE_SIZE]
        ciphertext = data[offset + FRAME_HEADER_SIZE : frame_end]
        frames.append((nonce, ciphertext))
        offset = frame_end
    return frames


def run_tamper_checks(
    qemu: Path,
    runner: Path,
    server: Path,
    client: Path,
) -> list[str]:
    failures = []
    for direction in ("to_server", "to_client"):
        exchange = run_exchange(qemu, runner, server, client, direction)
        server_exit, client_exit, server_output, client_output, _, _ = exchange
        if tamper_was_rejected(direction, server_exit, client_exit, server_output, client_output):
            print(f"OK: {direction} ciphertext tampering was rejected")
        else:
            failures.append(f"{direction} ciphertext tampering was not rejected")
    return failures


def tamper_was_rejected(
    direction: str,
    server_exit: int,
    client_exit: int,
    server_output: str,
    client_output: str,
) -> bool:
    if direction == "to_server":
        return (
            server_exit != 0
            and client_exit != 0
            and "secure channel OK" not in server_output
        )
    return client_exit != 0 and "secure channel OK" not in client_output


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


def check_channels(server_output: str, client_output: str) -> list[str]:
    failures = []
    if "secure channel OK" not in server_output:
        failures.append("server did not confirm secure channel")
    if "secure channel OK" not in client_output:
        failures.append("client did not confirm secure channel")
    if not failures:
        print("OK: both peers confirmed the symmetric secure channel")
    return failures


def check_ack(client_output: str) -> list[str]:
    actual_ack = decrypted_ack(client_output)
    if actual_ack == EXPECTED_ACK:
        print("OK: client decrypted the server ACK")
        return []
    if actual_ack is None:
        return ["client did not print a decrypted ACK"]
    return [f"client decrypted unexpected ACK: {actual_ack!r}"]


def server_config() -> bytes:
    config = struct.pack("<H", E2E_SERVER_PORT) + E2E_AUTH_KEY
    if len(config) != SERVER_CONFIG_SIZE:
        raise AssertionError("server config size drifted")
    return config


def client_config() -> bytes:
    config = (
        struct.pack("<H", E2E_PROXY_PORT)
        + socket.inet_aton("127.0.0.1")
        + E2E_AUTH_KEY
    )
    if len(config) != CLIENT_CONFIG_SIZE:
        raise AssertionError("client config size drifted")
    return config


def configure_blob(source: Path, destination: Path, config: bytes) -> None:
    data = bytearray(source.read_bytes())
    if len(data) < len(config):
        raise ValueError(f"blob is smaller than its {len(config)}-byte config")
    data[-len(config) :] = config
    destination.write_bytes(data)


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


def decrypted_ack(output: str) -> str | None:
    for line in output.splitlines():
        marker = "decrypted ACK: "
        if marker in line:
            return line.split(marker, 1)[1]
    return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
