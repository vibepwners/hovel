from __future__ import annotations

import socket
import threading

import pytest

from hovel_sdk.mesh_bridge import (
    MeshBridgeEndpoint,
    MeshBridgeNetwork,
    connect_mesh_bridge,
)

_CAPABILITY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
_PAYLOAD = b"ping"
_TIMEOUT_SECONDS = 5.0


def test_connect_mesh_bridge_tcp_authenticates_before_payload() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received: list[bytes] = []
    failures: list[BaseException] = []

    def accept() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                stream = connection.makefile("rb")
                capability = stream.readline().removesuffix(b"\n")
                received.append(capability + b":" + stream.read(len(_PAYLOAD)))
        except OSError as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    worker = threading.Thread(target=accept)
    worker.start()
    try:
        endpoint = MeshBridgeEndpoint("127.0.0.1", listener.getsockname()[1], _CAPABILITY)
        with connect_mesh_bridge(endpoint, MeshBridgeNetwork.TCP, timeout=_TIMEOUT_SECONDS) as connection:
            connection.sendall(_PAYLOAD)
        worker.join(_TIMEOUT_SECONDS)
    finally:
        listener.close()
    assert not worker.is_alive()
    assert failures == []
    assert received == [_CAPABILITY.encode("ascii") + b":" + _PAYLOAD]


def test_connect_mesh_bridge_udp_authenticates_with_separate_datagram() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(_TIMEOUT_SECONDS)
    endpoint = MeshBridgeEndpoint("127.0.0.1", listener.getsockname()[1], _CAPABILITY)
    try:
        with connect_mesh_bridge(endpoint, MeshBridgeNetwork.UDP, timeout=_TIMEOUT_SECONDS) as connection:
            connection.send(_PAYLOAD)
            capability, _ = listener.recvfrom(128)
            payload, _ = listener.recvfrom(128)
    finally:
        listener.close()
    assert capability == _CAPABILITY.encode("ascii")
    assert payload == _PAYLOAD


def test_mesh_bridge_endpoint_rejects_invalid_values() -> None:
    cases: tuple[tuple[str, int, str, type[Exception]], ...] = (
        ("", 1, _CAPABILITY, ValueError),
        ("192.0.2.10", 1, _CAPABILITY, ValueError),
        ("127.0.0.1", 0, _CAPABILITY, ValueError),
        ("127.0.0.1", 65_536, _CAPABILITY, ValueError),
        ("127.0.0.1", True, _CAPABILITY, TypeError),
        ("127.0.0.1", 1, "short", ValueError),
        ("127.0.0.1", 1, _CAPABILITY + "=", ValueError),
        ("127.0.0.1", 1, " " + _CAPABILITY, ValueError),
    )
    for host, port, capability, error_type in cases:
        with pytest.raises(error_type):
            MeshBridgeEndpoint(host, port, capability)


def test_connect_mesh_bridge_rejects_untyped_network_and_timeout() -> None:
    endpoint = MeshBridgeEndpoint("localhost", 1, _CAPABILITY)
    with pytest.raises(TypeError, match="network must be a MeshBridgeNetwork"):
        connect_mesh_bridge(endpoint, "tcp")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timeout must be a positive finite number"):
        connect_mesh_bridge(endpoint, MeshBridgeNetwork.TCP, timeout=float("inf"))
