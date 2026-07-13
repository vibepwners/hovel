from __future__ import annotations

import socket
import threading
from dataclasses import asdict
from unittest.mock import patch

import pytest

from hovel_sdk.mesh_bridge import (
    MeshBridgeCapability,
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
        endpoint = MeshBridgeEndpoint(
            "127.0.0.1",
            listener.getsockname()[1],
            MeshBridgeNetwork.TCP,
            MeshBridgeCapability(_CAPABILITY),
        )
        with connect_mesh_bridge(endpoint, timeout=_TIMEOUT_SECONDS) as connection:
            assert connection.gettimeout() is None
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
    endpoint = MeshBridgeEndpoint(
        "127.0.0.1",
        listener.getsockname()[1],
        MeshBridgeNetwork.UDP,
        MeshBridgeCapability(_CAPABILITY),
    )
    try:
        with connect_mesh_bridge(endpoint, timeout=_TIMEOUT_SECONDS) as connection:
            assert connection.gettimeout() is None
            connection.send(_PAYLOAD)
            capability, _ = listener.recvfrom(128)
            payload, _ = listener.recvfrom(128)
    finally:
        listener.close()
    assert capability == _CAPABILITY.encode("ascii")
    assert payload == _PAYLOAD


def test_mesh_bridge_endpoint_rejects_invalid_values() -> None:
    capability = MeshBridgeCapability(_CAPABILITY)
    cases: tuple[tuple[str, int, MeshBridgeNetwork, MeshBridgeCapability, type[Exception]], ...] = (
        ("", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("localhost", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("example.test", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("192.0.2.10", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("::1%lo", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("::ffff:127.0.0.1", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("0:0:0:0:0:0:0:1", 1, MeshBridgeNetwork.TCP, capability, ValueError),
        ("127.0.0.1", 0, MeshBridgeNetwork.TCP, capability, ValueError),
        ("127.0.0.1", 65_536, MeshBridgeNetwork.TCP, capability, ValueError),
    )
    for host, port, network, capability, error_type in cases:
        with pytest.raises(error_type):
            MeshBridgeEndpoint(host, port, network, capability)

    invalid_port = True
    with pytest.raises(TypeError, match="port must be an integer"):
        MeshBridgeEndpoint("127.0.0.1", invalid_port, MeshBridgeNetwork.TCP, capability)
    with pytest.raises(TypeError, match="local network must be a MeshBridgeNetwork"):
        MeshBridgeEndpoint("127.0.0.1", 1, "tcp", capability)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a MeshBridgeCapability"):
        MeshBridgeEndpoint("127.0.0.1", 1, MeshBridgeNetwork.TCP, _CAPABILITY)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="host must be a string"):
        MeshBridgeEndpoint(1, 1, MeshBridgeNetwork.TCP, capability)  # type: ignore[arg-type]

    for host in ("127.0.0.1", "::1"):
        endpoint = MeshBridgeEndpoint(host, 1, MeshBridgeNetwork.TCP, capability)
        assert endpoint.local_host == host

    for raw_capability in ("short", _CAPABILITY + "=", " " + _CAPABILITY):
        with pytest.raises(ValueError, match="canonical 256-bit base64url"):
            MeshBridgeCapability(raw_capability)


def test_mesh_bridge_capability_is_redacted_from_repr() -> None:
    endpoint = MeshBridgeEndpoint.from_rpc(
        {
            "localHost": "127.0.0.1",
            "localPort": 1,
            "localNetwork": "udp",
            "capability": _CAPABILITY,
        }
    )
    diagnostics = (
        str(endpoint.capability),
        repr(endpoint.capability),
        repr(endpoint),
        repr(asdict(endpoint)),
        repr((endpoint,)),
        repr({"endpoint": endpoint}),
    )
    assert all(_CAPABILITY not in diagnostic for diagnostic in diagnostics)
    assert endpoint.capability.value == _CAPABILITY
    assert endpoint.capability.reveal() == _CAPABILITY
    assert endpoint.local_network is MeshBridgeNetwork.UDP


def test_connect_mesh_bridge_rejects_invalid_response_and_timeout() -> None:
    endpoint = MeshBridgeEndpoint(
        "127.0.0.1",
        1,
        MeshBridgeNetwork.TCP,
        MeshBridgeCapability(_CAPABILITY),
    )
    with pytest.raises(ValueError, match="icmp"):
        MeshBridgeEndpoint.from_rpc(
            {
                "localHost": "127.0.0.1",
                "localPort": 1,
                "localNetwork": "icmp",
                "capability": _CAPABILITY,
            }
        )
    with pytest.raises(TypeError, match="localNetwork must be a string"):
        MeshBridgeEndpoint.from_rpc(
            {
                "localHost": "127.0.0.1",
                "localPort": 1,
                "capability": _CAPABILITY,
            }
        )
    with pytest.raises(ValueError, match="timeout must be a positive finite number"):
        connect_mesh_bridge(endpoint, timeout=float("inf"))


def test_connect_mesh_bridge_closes_socket_when_authentication_fails() -> None:
    class FailingSocket:
        def __init__(self) -> None:
            self.closed = False
            self.timeouts: list[float | None] = []

        def settimeout(self, timeout: float | None) -> None:
            self.timeouts.append(timeout)

        def connect(self, _address: object) -> None:
            pass

        def sendall(self, _data: bytes) -> None:
            raise OSError("authentication failed")

        def send(self, _data: bytes) -> int:
            raise OSError("authentication failed")

        def close(self) -> None:
            self.closed = True

    for network in (MeshBridgeNetwork.TCP, MeshBridgeNetwork.UDP):
        connection = FailingSocket()
        endpoint = MeshBridgeEndpoint(
            "127.0.0.1",
            1,
            network,
            MeshBridgeCapability(_CAPABILITY),
        )

        with (
            patch.object(socket, "socket", return_value=connection),
            pytest.raises(OSError, match="authentication failed"),
        ):
            connect_mesh_bridge(endpoint, timeout=_TIMEOUT_SECONDS)

        assert connection.closed
        assert connection.timeouts == [_TIMEOUT_SECONDS]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
