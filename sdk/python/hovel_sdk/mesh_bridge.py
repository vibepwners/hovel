from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_MESH_BRIDGE_CAPABILITY_BYTES = 32
_MAX_NETWORK_PORT = (1 << 16) - 1
_REDACTED_MESH_BRIDGE_CAPABILITY = "<mesh bridge capability redacted>"


class MeshBridgeNetwork(StrEnum):
    """Daemon-owned local socket adapters supported by Mesh bridges."""

    TCP = "tcp"
    UDP = "udp"


class MeshBridgeCapability:
    """Validated bearer capability with secret-safe formatting."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("mesh bridge capability must be a string")
        if value != value.strip() or not _is_canonical_capability(value):
            raise ValueError("mesh bridge capability must be canonical 256-bit base64url")
        self.__value = value

    @property
    def value(self) -> str:
        """Reveal the capability for an explicit protocol-boundary operation."""
        return self.__value

    def reveal(self) -> str:
        """Reveal the capability for an explicit protocol-boundary operation."""
        return self.__value

    def __repr__(self) -> str:
        return _REDACTED_MESH_BRIDGE_CAPABILITY

    def __str__(self) -> str:
        return _REDACTED_MESH_BRIDGE_CAPABILITY


@dataclass(frozen=True)
class MeshBridgeEndpoint:
    """Authenticated loopback endpoint returned by ``OpenMeshBridge``.

    ``capability`` is an ephemeral bearer secret. Keep it in memory and never
    log, persist, or cache it.
    """

    local_host: str
    local_port: int
    local_network: MeshBridgeNetwork
    capability: MeshBridgeCapability

    def __post_init__(self) -> None:
        if not isinstance(self.local_host, str):
            raise TypeError("mesh bridge host must be a string")
        host = self.local_host.strip()
        if host != self.local_host:
            raise ValueError("mesh bridge host must be canonical")
        if not _is_loopback(host):
            raise ValueError("mesh bridge host must be a canonical numeric loopback IP")
        if isinstance(self.local_port, bool) or not isinstance(self.local_port, int):
            raise TypeError("mesh bridge port must be an integer")
        if not 1 <= self.local_port <= _MAX_NETWORK_PORT:
            raise ValueError("mesh bridge port is outside the valid range")

        if not isinstance(self.local_network, MeshBridgeNetwork):
            raise TypeError("mesh bridge local network must be a MeshBridgeNetwork")
        if not isinstance(self.capability, MeshBridgeCapability):
            raise TypeError("mesh bridge capability must be a MeshBridgeCapability")

    @classmethod
    def from_rpc(cls, value: Mapping[str, Any]) -> MeshBridgeEndpoint:
        """Validate and wrap an ``OpenMeshBridge`` response."""
        host = value.get("localHost")
        port = value.get("localPort")
        network = value.get("localNetwork")
        capability = value.get("capability")
        if not isinstance(host, str):
            raise TypeError("mesh bridge localHost must be a string")
        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("mesh bridge localPort must be an integer")
        if not isinstance(network, str):
            raise TypeError("mesh bridge localNetwork must be a string")
        if not isinstance(capability, str):
            raise TypeError("mesh bridge capability must be a string")
        return cls(
            host,
            port,
            MeshBridgeNetwork(network),
            MeshBridgeCapability(capability),
        )


def connect_mesh_bridge(
    endpoint: MeshBridgeEndpoint,
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
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int | float) or not math.isfinite(timeout) or timeout <= 0
    ):
        raise ValueError("mesh bridge timeout must be a positive finite number")

    family, address = _numeric_socket_endpoint(endpoint)
    socket_type = socket.SOCK_STREAM if endpoint.local_network is MeshBridgeNetwork.TCP else socket.SOCK_DGRAM
    protocol = socket.IPPROTO_TCP if endpoint.local_network is MeshBridgeNetwork.TCP else socket.IPPROTO_UDP
    connection = socket.socket(family, socket_type, protocol)
    authentication = endpoint.capability.reveal().encode("ascii")
    try:
        connection.settimeout(timeout)
        connection.connect(address)
        if endpoint.local_network is MeshBridgeNetwork.TCP:
            connection.sendall(authentication + b"\n")
        else:
            _authenticate_udp(connection, authentication)
        connection.settimeout(None)
    except Exception:
        connection.close()
        raise
    return connection


def _authenticate_udp(connection: socket.socket, authentication: bytes) -> None:
    written = connection.send(authentication)
    if written != len(authentication):
        raise OSError("mesh bridge authentication datagram was truncated")


def _is_loopback(host: str) -> bool:
    if "%" in host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return address.is_loopback and str(address) == host


def _numeric_socket_endpoint(
    endpoint: MeshBridgeEndpoint,
) -> tuple[socket.AddressFamily, tuple[str, int] | tuple[str, int, int, int]]:
    address = ipaddress.ip_address(endpoint.local_host)
    if isinstance(address, ipaddress.IPv4Address):
        return socket.AF_INET, (endpoint.local_host, endpoint.local_port)
    return socket.AF_INET6, (endpoint.local_host, endpoint.local_port, 0, 0)


def _is_canonical_capability(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return (
        len(decoded) == _MESH_BRIDGE_CAPABILITY_BYTES
        and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value
    )
