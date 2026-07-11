"""Payload tests for NaCl crypto blobs.

- nacl_hello: standalone self-test (encrypt/decrypt round-trip)
- nacl_client + nacl_server: paired e2e encrypted TCP handshake

See: spec/verification/TEST-011-payload-pytest-suite.md
"""

from __future__ import annotations

import socket
import struct

import pytest
from payload_defs import (
    EXPECTATIONS,
    OPERATING_SYSTEMS,
    PAYLOAD_PLATFORMS,
    RUNNER_TYPE,
    runtime_test_arches,
)
from picblobs import get_blob
from picblobs.runner import (
    find_runner,
    is_arch_skip_rosetta,
    reserve_tcp_port,
    run_blob,
    run_blob_pair,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nacl_combos() -> list[tuple[str, str, str]]:
    """Return (blob_type, os, arch) for nacl_hello."""
    combos = []
    for os_name in PAYLOAD_PLATFORMS.get("nacl_hello", []):
        os_entry = OPERATING_SYSTEMS.get(os_name)
        if os_entry is None:
            continue
        combos.extend(
            ("nacl_hello", os_name, arch) for arch in runtime_test_arches(os_name)
        )
    return sorted(combos)


def _e2e_combos() -> list[tuple[str, str]]:
    """Return (os, arch) combos where both nacl_client and nacl_server can run."""
    combos = []
    for os_name in PAYLOAD_PLATFORMS.get("nacl_hello", []):
        os_entry = OPERATING_SYSTEMS.get(os_name)
        if os_entry is None:
            continue
        combos.extend((os_name, arch) for arch in runtime_test_arches(os_name))
    return sorted(combos)


def _blob_exists(blob_type: str, target_os: str, target_arch: str) -> bool:
    try:
        get_blob(blob_type, target_os, target_arch)
    except FileNotFoundError:
        return False
    else:
        return True


# ---------------------------------------------------------------------------
# nacl_hello: standalone self-test
# ---------------------------------------------------------------------------


class TestNaClPayload:
    """Run nacl_hello on every supported platform."""

    @pytest.mark.requires_qemu
    @pytest.mark.parametrize(
        "blob_type,target_os,target_arch",
        _nacl_combos(),
        ids=[f"{bt}:{os}:{arch}" for bt, os, arch in _nacl_combos()],
    )
    def test_nacl_hello_selftest(
        self,
        blob_type: str,
        target_os: str,
        target_arch: str,
    ) -> None:
        if not _blob_exists(blob_type, target_os, target_arch):
            pytest.skip(f"Blob not staged: {blob_type}/{target_os}/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        runner_type = RUNNER_TYPE[target_os]
        if runner_type != "linux":
            try:
                find_runner(runner_type, target_arch)
            except FileNotFoundError:
                pytest.skip(f"No {runner_type} runner for {target_arch}")

        exp = EXPECTATIONS[blob_type]
        blob = get_blob(blob_type, target_os, target_arch)
        result = run_blob(blob, timeout=exp.timeout)

        assert result.exit_code == exp.exit_code, (
            f"{blob_type} {target_os}:{target_arch}: "
            f"exit_code={result.exit_code}, expected={exp.exit_code}, "
            f"stderr={result.stderr!r}"
        )
        assert result.stdout == exp.stdout, (
            f"{blob_type} {target_os}:{target_arch}: "
            f"stdout={result.stdout!r}, expected={exp.stdout!r}"
        )


# ---------------------------------------------------------------------------
# nacl_client + nacl_server: paired e2e test
# ---------------------------------------------------------------------------

EXPECTED_PLAINTEXT = b"Hello from NaCl PIC blob!"
E2E_TIMEOUT = 30.0

# 32-byte handshake auth key injected into both blobs' config. The client and
# server must share it to authenticate the ephemeral X25519 exchange; a wire
# attacker without it cannot MITM. A fixed non-secret value is fine for tests.
E2E_AUTH_KEY = bytes(range(1, 33))

_E2E_SKIP_ARCHES: frozenset[str] = frozenset()


class TestNaClE2E:
    """Run nacl_server + nacl_client in parallel on each architecture.

    Protocol:
      1. Server binds 0.0.0.0:9999, accepts one connection.
      2. Client connects to 127.0.0.1:9999, sends encrypted message.
      3. Server decrypts, prints plaintext, sends encrypted ACK.
      4. Client decrypts ACK, both exit 0.
    """

    @pytest.mark.requires_qemu
    @pytest.mark.requires_local_tcp
    @pytest.mark.parametrize(
        "target_os,target_arch",
        _e2e_combos(),
        ids=[f"{os}:{arch}" for os, arch in _e2e_combos()],
    )
    def test_nacl_e2e_handshake(
        self,
        target_os: str,
        target_arch: str,
    ) -> None:
        # Skip if blobs not staged.
        for bt in ("nacl_server", "nacl_client"):
            if not _blob_exists(bt, target_os, target_arch):
                pytest.skip(f"Blob not staged: {bt}/{target_os}/{target_arch}")

        if is_arch_skip_rosetta(target_arch):
            pytest.skip(f"QEMU {target_arch} crashes under Rosetta")

        runner_type = RUNNER_TYPE[target_os]
        runner_path = None
        if runner_type != "linux":
            try:
                runner_path = find_runner(runner_type, target_arch)
            except FileNotFoundError:
                pytest.skip(f"No {runner_type} runner for {target_arch}")

        server_blob = get_blob("nacl_server", target_os, target_arch)
        client_blob = get_blob("nacl_client", target_os, target_arch)

        if target_arch in _E2E_SKIP_ARCHES:
            pytest.skip(
                f"QEMU {target_arch} too slow for NaCl e2e handshake "
                f"(crypto proven by nacl_hello)"
            )

        port = reserve_tcp_port()
        server_config = struct.pack("<H", port) + E2E_AUTH_KEY
        client_config = (
            struct.pack("<H", port) + socket.inet_aton("127.0.0.1") + E2E_AUTH_KEY
        )
        try:
            result = run_blob_pair(
                server_blob,
                client_blob,
                runner_path,
                runner_type,
                server_config=server_config,
                client_config=client_config,
                timeout=E2E_TIMEOUT,
            )
        except RuntimeError as e:
            pytest.fail(f"NaCl e2e failed on {target_os}:{target_arch}: {e}")

        # Both must exit 0.
        assert result.server_exit == 0, (
            f"server {target_os}:{target_arch}: exit={result.server_exit}\n"
            f"  stdout: {result.server_stdout!r}\n  stderr: {result.server_stderr!r}"
        )
        assert result.client_exit == 0, (
            f"client {target_os}:{target_arch}: exit={result.client_exit}\n"
            f"  stdout: {result.client_stdout!r}\n  stderr: {result.client_stderr!r}"
        )

        # Server must have decrypted the expected plaintext.
        assert EXPECTED_PLAINTEXT in result.server_stdout, (
            f"server {target_os}:{target_arch}: plaintext not found in output\n"
            f"  stdout: {result.server_stdout!r}"
        )

        # Both must confirm secure channel.
        assert b"secure channel OK" in result.server_stdout, (
            f"server {target_os}:{target_arch}: no channel confirmation\n"
            f"  stdout: {result.server_stdout!r}"
        )
        assert b"secure channel OK" in result.client_stdout, (
            f"client {target_os}:{target_arch}: no channel confirmation\n"
            f"  stdout: {result.client_stdout!r}"
        )
