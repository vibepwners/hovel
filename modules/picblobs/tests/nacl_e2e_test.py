#!/usr/bin/env python3
"""End-to-end NaCl encrypted handshake test without host shell tools."""

from __future__ import annotations

import difflib
import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from nacl_protocol import (
    AUTH_KEY_SIZE,
    CLIENT_CONFIG_TEMPLATE,
    CLIENT_CONFIG_SIZE,
    CLIENT_MESSAGE,
    DEFAULT_SERVER_IPV4,
    FRAME_LENGTH_FORMAT,
    FRAME_HEADER_SIZE,
    HANDSHAKE_PUBLIC_KEY_SIZE,
    NONCE_SIZE,
    PORT_FORMAT,
    SECRETBOX_OVERHEAD,
    SERVER_ACK,
    SERVER_CONFIG_TEMPLATE,
    SERVER_CONFIG_SIZE,
    render_c_header,
)

EXPECTED_MSG = CLIENT_MESSAGE
EXPECTED_ACK = SERVER_ACK
E2E_AUTH_KEY = bytes(range(1, AUTH_KEY_SIZE + 1))
MISMATCH_AUTH_KEY = bytes(reversed(E2E_AUTH_KEY))
SILENT_PEER_MAX_SECONDS = 12
PROCESS_TIMEOUT_SECONDS = 30
PROXY_JOIN_TIMEOUT_SECONDS = 5
CONNECT_ATTEMPTS = 50
CONNECT_TIMEOUT_SECONDS = 0.5
CONNECT_RETRY_SECONDS = 0.1
RELAY_READ_SIZE = 4096
EXPECTED_FRAME_COUNT = 2
HANDSHAKE_FRAME_INDEX = 1
APPLICATION_FRAME_INDEX = 2
TIMEOUT_EXIT_CODE = 124
TAMPER_BIT = 1
TO_SERVER = "to_server"
TO_CLIENT = "to_client"
PROTOCOL_HEADER_PATH = "modules/picblobs/src/include/picblobs/nacl_protocol.h"


@dataclass(frozen=True)
class Tamper:
    direction: str
    frame_index: int


def main() -> int:
    if sys.argv[1:] == ["--check-protocol-header"]:
        return check_protocol_header()

    parsed = parse_args()
    if parsed is None:
        return 2

    qemu, runner, server, client, run_negative, run_silent_peer = parsed
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
        failures.extend(run_auth_key_mismatch_checks(qemu, runner, server, client))
    if run_silent_peer and not failures:
        failures.extend(run_silent_peer_check(qemu, runner, server))
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("=== FAIL ===")
        return 1

    print("=== PASS ===")
    return 0


def parse_args() -> tuple[Path, Path, Path, Path, bool, bool] | None:
    args = sys.argv[1:]
    run_negative = False
    if "--negative" in args:
        args.remove("--negative")
        run_negative = True
    run_silent_peer = False
    if "--silent-peer" in args:
        args.remove("--silent-peer")
        run_silent_peer = True
    if len(args) == 4:
        qemu_arg, runner_arg, server_arg, client_arg = args
        return (
            resolve_path(qemu_arg),
            resolve_path(runner_arg),
            resolve_path(server_arg),
            resolve_path(client_arg),
            run_negative,
            run_silent_peer,
        )
    print(
        "usage: nacl_e2e_test.py <qemu> <runner> <server.bin> <client.bin> "
        "[--negative] [--silent-peer]",
        file=sys.stderr,
    )
    return None


def run_exchange(
    qemu: Path,
    runner: Path,
    server: Path,
    client: Path,
    tamper: Tamper | None = None,
    server_auth_key: bytes = E2E_AUTH_KEY,
    client_auth_key: bytes = E2E_AUTH_KEY,
) -> tuple[int, int, str, str, bytes, bytes]:
    with tempfile.TemporaryDirectory(
        prefix="nacl-e2e-", dir=os.environ.get("TEST_TMPDIR")
    ) as tmp_raw:
        tmp = Path(tmp_raw)
        server_log = tmp / "server.out"
        client_log = tmp / "client.out"
        configured_server = tmp / "server.bin"
        configured_client = tmp / "client.bin"
        proxy = WireProxy(tamper)
        server_reservation, server_port = reserve_loopback_port()
        try:
            configure_blob(
                server,
                configured_server,
                server_config(server_port, server_auth_key),
                SERVER_CONFIG_TEMPLATE,
            )
            configure_blob(
                client,
                configured_client,
                client_config(proxy.port, client_auth_key),
                CLIENT_CONFIG_TEMPLATE,
            )
            proxy.server_port = server_port
        finally:
            server_reservation.close()

        with server_log.open("wb") as out:
            server_proc = subprocess.Popen(
                [str(qemu), str(runner), str(configured_server)],
                stdout=out,
                stderr=subprocess.STDOUT,
            )

        try:
            proxy.start()
            with client_log.open("wb") as out:
                client_proc = subprocess.run(
                    [str(qemu), str(runner), str(configured_client)],
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=PROCESS_TIMEOUT_SECONDS,
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

    def __init__(self, tamper: Tamper | None) -> None:
        self.tamper = tamper
        self.server_port: int | None = None
        self.to_server = bytearray()
        self.to_client = bytearray()
        self.error: Exception | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((DEFAULT_SERVER_IPV4, 0))
        self.listener.listen(1)
        self.port = int(self.listener.getsockname()[1])
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=PROXY_JOIN_TIMEOUT_SECONDS)
        if self.thread.is_alive() and self.error is None:
            self.error = TimeoutError("wire proxy did not stop")

    def raise_if_failed(self) -> None:
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        try:
            client, _ = self.listener.accept()
            if self.server_port is None:
                raise RuntimeError("wire proxy server port was not configured")
            server = connect_server(self.server_port)
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
                    tamper_frame_index(self.tamper, TO_SERVER),
                ),
            )
            to_client = threading.Thread(
                target=relay_frames,
                args=(
                    server,
                    client,
                    self.to_client,
                    tamper_frame_index(self.tamper, TO_CLIENT),
                ),
            )
            to_server.start()
            to_client.start()
            to_server.join()
            to_client.join()


def tamper_frame_index(tamper: Tamper | None, direction: str) -> int | None:
    if tamper is None or tamper.direction != direction:
        return None
    return tamper.frame_index


def reserve_loopback_port() -> tuple[socket.socket, int]:
    """Reserve a kernel-assigned loopback port until its consumer starts."""

    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind((DEFAULT_SERVER_IPV4, 0))
    return reservation, int(reservation.getsockname()[1])


def connect_server(port: int) -> socket.socket:
    for _ in range(CONNECT_ATTEMPTS):
        try:
            return socket.create_connection(
                (DEFAULT_SERVER_IPV4, port), timeout=CONNECT_TIMEOUT_SECONDS
            )
        except OSError:
            time.sleep(CONNECT_RETRY_SECONDS)
    raise ConnectionError("wire proxy could not connect to server")


def relay_frames(
    source: socket.socket,
    destination: socket.socket,
    capture: bytearray,
    tamper_frame: int | None,
) -> None:
    pending = bytearray()
    frame_index = 0
    try:
        while chunk := source.recv(RELAY_READ_SIZE):
            pending.extend(chunk)
            for frame in take_complete_frames(pending):
                frame_index += 1
                if tamper_frame == frame_index:
                    frame[-1] ^= TAMPER_BIT
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
        ciphertext_size = struct.unpack_from(
            FRAME_LENGTH_FORMAT, pending, NONCE_SIZE
        )[0]
        frame_size = FRAME_HEADER_SIZE + ciphertext_size
        if len(pending) < frame_size:
            break
        frames.append(bytearray(pending[:frame_size]))
        del pending[:frame_size]
    return frames


def wait_server(server_proc: subprocess.Popen[bytes]) -> int:
    try:
        return server_proc.wait(timeout=PROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        server_proc.kill()
        return TIMEOUT_EXIT_CODE


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
    if EXPECTED_ACK.encode() in to_client:
        failures.append("server ACK plaintext appeared on the wire")
    if not failures:
        print("OK: wire capture contains encrypted, authenticated frames both ways")
    return failures


def check_frame_sizes(
    client_frames: list[tuple[bytes, bytes]],
    server_frames: list[tuple[bytes, bytes]],
) -> list[str]:
    if (
        len(client_frames) != EXPECTED_FRAME_COUNT
        or len(server_frames) != EXPECTED_FRAME_COUNT
    ):
        return [
            "wire capture expected two frames each way, got "
            f"client={len(client_frames)} server={len(server_frames)}"
        ]
    expected_client = [
        HANDSHAKE_PUBLIC_KEY_SIZE + SECRETBOX_OVERHEAD,
        len(EXPECTED_MSG) + SECRETBOX_OVERHEAD,
    ]
    expected_server = [
        HANDSHAKE_PUBLIC_KEY_SIZE + SECRETBOX_OVERHEAD,
        len(EXPECTED_ACK) + SECRETBOX_OVERHEAD,
    ]
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
        ciphertext_size = struct.unpack_from(
            FRAME_LENGTH_FORMAT, data, offset + NONCE_SIZE
        )[0]
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
    frames = (
        (HANDSHAKE_FRAME_INDEX, "handshake"),
        (APPLICATION_FRAME_INDEX, "application"),
    )
    for frame_index, frame_name in frames:
        for direction in (TO_SERVER, TO_CLIENT):
            tamper = Tamper(direction=direction, frame_index=frame_index)
            exchange = run_exchange(qemu, runner, server, client, tamper)
            server_exit, client_exit, server_output, client_output, _, _ = exchange
            if tamper_was_rejected(
                direction,
                server_exit,
                client_exit,
                server_output,
                client_output,
            ):
                print(f"OK: {direction} {frame_name} ciphertext tampering was rejected")
            else:
                failures.append(
                    f"{direction} {frame_name} ciphertext tampering was not rejected"
                )
    return failures


def run_auth_key_mismatch_checks(
    qemu: Path,
    runner: Path,
    server: Path,
    client: Path,
) -> list[str]:
    failures = []
    cases = (
        ("server", MISMATCH_AUTH_KEY, E2E_AUTH_KEY),
        ("client", E2E_AUTH_KEY, MISMATCH_AUTH_KEY),
    )
    for role, server_key, client_key in cases:
        exchange = run_exchange(
            qemu,
            runner,
            server,
            client,
            server_auth_key=server_key,
            client_auth_key=client_key,
        )
        server_exit, client_exit, server_output, client_output, _, _ = exchange
        if auth_key_mismatch_was_rejected(
            server_exit, client_exit, server_output, client_output
        ):
            print(f"OK: mismatched {role} deployment authentication key was rejected")
        else:
            failures.append(
                f"mismatched {role} deployment authentication key was not rejected"
            )
    return failures


def run_silent_peer_check(qemu: Path, runner: Path, server: Path) -> list[str]:
    with tempfile.TemporaryDirectory(
        prefix="nacl-silent-peer-", dir=os.environ.get("TEST_TMPDIR")
    ) as tmp_raw:
        tmp = Path(tmp_raw)
        server_log = tmp / "server.out"
        configured_server = tmp / "server.bin"
        server_reservation, server_port = reserve_loopback_port()
        try:
            configure_blob(
                server,
                configured_server,
                server_config(server_port, E2E_AUTH_KEY),
                SERVER_CONFIG_TEMPLATE,
            )
        finally:
            server_reservation.close()

        with server_log.open("wb") as output:
            server_proc = subprocess.Popen(
                [str(qemu), str(runner), str(configured_server)],
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        started = time.monotonic()
        try:
            with connect_server(server_port):
                server_exit = wait_server(server_proc)
        finally:
            if server_proc.poll() is None:
                server_proc.kill()
                server_proc.wait()
        elapsed = time.monotonic() - started
        server_output = read_text(server_log)

    if (
        server_exit != 0
        and server_exit != TIMEOUT_EXIT_CODE
        and elapsed <= SILENT_PEER_MAX_SECONDS
        and "secure channel OK" not in server_output
    ):
        print("OK: silent peer was disconnected by the bounded Mbed socket timeout")
        return []
    return [
        "silent peer did not fail closed within the Mbed socket timeout: "
        f"exit={server_exit} elapsed={elapsed:.2f}s"
    ]


def tamper_was_rejected(
    direction: str,
    server_exit: int,
    client_exit: int,
    server_output: str,
    client_output: str,
) -> bool:
    if direction == TO_SERVER:
        return (
            server_exit != 0
            and client_exit != 0
            and "secure channel OK" not in server_output
        )
    return client_exit != 0 and "secure channel OK" not in client_output


def auth_key_mismatch_was_rejected(
    server_exit: int,
    client_exit: int,
    server_output: str,
    client_output: str,
) -> bool:
    return (
        server_exit != 0
        and client_exit != 0
        and "secure channel OK" not in server_output
        and "secure channel OK" not in client_output
        and "decrypted:" not in server_output
        and "decrypted ACK:" not in client_output
    )


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


def server_config(port: int, auth_key: bytes) -> bytes:
    config = struct.pack(PORT_FORMAT, port) + auth_key
    if len(config) != SERVER_CONFIG_SIZE:
        raise AssertionError("server config size drifted")
    return config


def client_config(port: int, auth_key: bytes) -> bytes:
    config = (
        struct.pack(PORT_FORMAT, port)
        + socket.inet_aton(DEFAULT_SERVER_IPV4)
        + auth_key
    )
    if len(config) != CLIENT_CONFIG_SIZE:
        raise AssertionError("client config size drifted")
    return config


def configure_blob(
    source: Path,
    destination: Path,
    config: bytes,
    template: bytes,
) -> None:
    data = bytearray(source.read_bytes())
    if len(data) < len(config):
        raise ValueError(f"blob is smaller than its {len(config)}-byte config")
    if len(config) != len(template):
        raise ValueError("blob config and canonical template sizes differ")
    if not data.endswith(template):
        raise ValueError("blob does not end with the canonical config template")
    data[-len(config) :] = config
    destination.write_bytes(data)


def check_protocol_header() -> int:
    header = resolve_path(PROTOCOL_HEADER_PATH)
    if not header.exists():
        print(f"FAIL: generated protocol header not found: {header}")
        return 1
    actual = header.read_text(encoding="utf-8")
    expected = render_c_header()
    if actual != expected:
        print(
            "FAIL: picblobs/nacl_protocol.h does not match "
            "nacl_protocol.py; regenerate it"
        )
        print(
            "".join(
                difflib.unified_diff(
                    actual.splitlines(keepends=True),
                    expected.splitlines(keepends=True),
                    fromfile="checked-in header",
                    tofile="generated header",
                )
            )
        )
        return 1
    print("OK: generated C protocol header matches canonical Python contract")
    return 0


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
