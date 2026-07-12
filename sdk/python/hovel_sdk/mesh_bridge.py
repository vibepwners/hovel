from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import socket
from dataclasses import dataclass
from enum import StrEnum

_MESH_BRIDGE_CAPABILITY_BYTES = 32
_MAX_NETWORK_PORT = (1 << 16) - 1


class MeshBridgeNetwork(StrEnum):
    """Daemon-owned local socket adapters supported by Mesh bridges."""

    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class MeshBridgeEndpoint:
    """Authenticated loopback endpoint returned by ``OpenMeshBridge``.

    ``capability`` is an ephemeral bearer secret. Keep it in memory and never
    log, persist, or cache it.
    """

    local_host: str
    local_port: int
    capability: str

    def __post_init__(self) -> None:
        host = self.local_host.strip()
        capability = self.capability.strip()
        if host != self.local_host:
            raise ValueError("mesh bridge host must be canonical")
        if capability != self.capability:
            raise ValueError("mesh bridge capability must be canonical")
        if not _is_loopback(host):
            raise ValueError("mesh bridge host must be loopback")
        if isinstance(self.local_port, bool) or not isinstance(self.local_port, int):
            raise TypeError("mesh bridge port must be an integer")
        if not 1 <= self.local_port <= _MAX_NETWORK_PORT:
            raise ValueError("mesh bridge port is outside the valid range")
        if not _is_canonical_capability(capability):
            raise ValueError("mesh bridge capability must be canonical 256-bit base64url")
        object.__setattr__(self, "local_host", host)
        object.__setattr__(self, "capability", capability)


def connect_mesh_bridge(
    endpoint: MeshBridgeEndpoint,
    network: MeshBridgeNetwork,
    *,
    timeout: float | None = None,
) -> socket.socket:
    """Connect and authenticate, returning a normal TCP or UDP socket.

    Hovel consumes the authentication preface before forwarding application
    bytes to the provider-owned Mesh stream. For UDP, every later ``send`` is
    one application datagram.
    """

    if not isinstance(endpoint, MeshBridgeEndpoint):
        raise TypeError("mesh bridge endpoint must be a MeshBridgeEndpoint")
    if not isinstance(network, MeshBridgeNetwork):
        raise TypeError("mesh bridge network must be a MeshBridgeNetwork")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int | float) or not math.isfinite(timeout) or timeout <= 0
    ):
        raise ValueError("mesh bridge timeout must be a positive finite number")

    if network is MeshBridgeNetwork.TCP:
        connection = socket.create_connection((endpoint.local_host, endpoint.local_port), timeout=timeout)
        try:
            connection.sendall(endpoint.capability.encode("ascii") + b"\n")
        except Exception:
            connection.close()
            raise
        return connection

    addresses = socket.getaddrinfo(
        endpoint.local_host,
        endpoint.local_port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
    )
    if not addresses:
        raise OSError("mesh bridge UDP endpoint did not resolve")
    family, socktype, proto, _, address = addresses[0]
    connection = socket.socket(family, socktype, proto)
    authentication = endpoint.capability.encode("ascii")
    try:
        connection.settimeout(timeout)
        connection.connect(address)
        _authenticate_udp(connection, authentication)
    except Exception:
        connection.close()
        raise
    return connection


def _authenticate_udp(connection: socket.socket, authentication: bytes) -> None:
    written = connection.send(authentication)
    if written != len(authentication):
        raise OSError("mesh bridge authentication datagram was truncated")


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_canonical_capability(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return (
        len(decoded) == _MESH_BRIDGE_CAPABILITY_BYTES
        and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value
    )
