//! Authenticated local Mesh bridge helpers.
//!
//! These helpers hide the daemon's capability preface so consumer protocol
//! code receives a normal connected TCP stream or UDP socket. The local socket
//! network is independent of the provider-defined protocol carried through the
//! Mesh.

use crate::base64;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

const MESH_BRIDGE_CAPABILITY_BYTES: usize = 32;
const MESH_BRIDGE_CAPABILITY_CHARACTERS: usize = 43;
const MESH_BRIDGE_CAPABILITY_REDACTED: &str = "<mesh bridge capability redacted>";
const MESH_BRIDGE_NETWORK_TCP_VALUE: &str = "tcp";
const MESH_BRIDGE_NETWORK_UDP_VALUE: &str = "udp";
const MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX: &[u8] = b"\n";
const EPHEMERAL_PORT: u16 = 0;

/// Daemon-owned loopback socket adapters supported by Mesh bridges.
///
/// This value describes only the local socket returned by `OpenMeshBridge`.
/// It does not constrain or reinterpret the provider-defined remote protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MeshBridgeNetwork {
    Tcp,
    Udp,
}

impl MeshBridgeNetwork {
    /// Returns the canonical daemon/OpenAPI wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => MESH_BRIDGE_NETWORK_TCP_VALUE,
            Self::Udp => MESH_BRIDGE_NETWORK_UDP_VALUE,
        }
    }
}

impl fmt::Display for MeshBridgeNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for MeshBridgeNetwork {
    type Err = ParseMeshBridgeNetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            MESH_BRIDGE_NETWORK_TCP_VALUE => Ok(Self::Tcp),
            MESH_BRIDGE_NETWORK_UDP_VALUE => Ok(Self::Udp),
            _ => Err(ParseMeshBridgeNetworkError),
        }
    }
}

impl TryFrom<&str> for MeshBridgeNetwork {
    type Error = ParseMeshBridgeNetworkError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Error returned when an `OpenMeshBridge` response names an unsupported local
/// socket network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMeshBridgeNetworkError;

impl fmt::Display for ParseMeshBridgeNetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsupported local Mesh bridge network")
    }
}

impl Error for ParseMeshBridgeNetworkError {}

/// Ephemeral 256-bit bearer secret returned by `OpenMeshBridge`.
///
/// Keep this value in memory and never log, persist, or cache it. Both
/// [`Debug`](fmt::Debug) and [`Display`](fmt::Display) redact the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshBridgeCapability(String);

impl MeshBridgeCapability {
    pub fn new(value: impl Into<String>) -> Result<MeshBridgeCapability, String> {
        let value = value.into();
        if value.trim() != value {
            return Err("mesh bridge capability must be canonical".into());
        }
        if value.len() != MESH_BRIDGE_CAPABILITY_CHARACTERS {
            return Err(format!(
                "mesh bridge capability must contain {MESH_BRIDGE_CAPABILITY_CHARACTERS} base64url characters"
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("mesh bridge capability contains a non-base64url character".into());
        }
        let standard = value.replace('-', "+").replace('_', "/") + "=";
        let decoded = base64::decode(&standard)?;
        let canonical = base64::encode(&decoded)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_");
        if decoded.len() != MESH_BRIDGE_CAPABILITY_BYTES || canonical != value {
            return Err("mesh bridge capability must be canonical 256-bit base64url".into());
        }
        Ok(MeshBridgeCapability(value))
    }

    /// Explicitly reveals the bearer secret for the authentication handshake.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MeshBridgeCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MESH_BRIDGE_CAPABILITY_REDACTED)
    }
}

impl fmt::Display for MeshBridgeCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MESH_BRIDGE_CAPABILITY_REDACTED)
    }
}

/// Authenticated loopback endpoint returned by the daemon control API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshBridgeEndpoint {
    local_ip: IpAddr,
    local_port: u16,
    local_network: MeshBridgeNetwork,
    capability: MeshBridgeCapability,
}

impl MeshBridgeEndpoint {
    pub fn new(
        local_host: impl AsRef<str>,
        local_port: u16,
        local_network: MeshBridgeNetwork,
        capability: MeshBridgeCapability,
    ) -> Result<MeshBridgeEndpoint, String> {
        let local_host = local_host.as_ref();
        if local_host.trim() != local_host {
            return Err("mesh bridge host must be canonical".into());
        }
        if local_port == EPHEMERAL_PORT {
            return Err("mesh bridge port must be nonzero".into());
        }
        let local_ip = local_host
            .parse::<IpAddr>()
            .map_err(|_| "mesh bridge host must be a canonical numeric loopback IP")?;
        if !local_ip.is_loopback() || local_ip.to_string() != local_host {
            return Err("mesh bridge host must be a canonical numeric loopback IP".into());
        }
        Ok(MeshBridgeEndpoint {
            local_ip,
            local_port,
            local_network,
            capability,
        })
    }

    /// Validates and wraps the wire values from an `OpenMeshBridge` response.
    pub fn from_response(
        local_host: impl AsRef<str>,
        local_port: u16,
        local_network: &str,
        capability: impl Into<String>,
    ) -> Result<MeshBridgeEndpoint, String> {
        let local_network = local_network
            .parse::<MeshBridgeNetwork>()
            .map_err(|error| error.to_string())?;
        let capability = MeshBridgeCapability::new(capability)?;
        Self::new(local_host, local_port, local_network, capability)
    }

    pub const fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    pub const fn local_port(&self) -> u16 {
        self.local_port
    }

    pub const fn local_network(&self) -> MeshBridgeNetwork {
        self.local_network
    }

    pub fn capability(&self) -> &MeshBridgeCapability {
        &self.capability
    }

    const fn address(&self) -> SocketAddr {
        SocketAddr::new(self.local_ip, self.local_port)
    }
}

/// Authenticated socket selected by an `OpenMeshBridge` response.
///
/// Matching the enum keeps the concrete standard-library socket type visible;
/// callers that already know the response network can use the specialized
/// connection helpers instead.
#[derive(Debug)]
pub enum MeshBridgeConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl MeshBridgeConnection {
    pub const fn local_network(&self) -> MeshBridgeNetwork {
        match self {
            Self::Tcp(_) => MeshBridgeNetwork::Tcp,
            Self::Udp(_) => MeshBridgeNetwork::Udp,
        }
    }
}

/// Connects and authenticates using the local network from the daemon response.
pub fn connect_mesh_bridge(
    endpoint: &MeshBridgeEndpoint,
    timeout: Option<Duration>,
) -> io::Result<MeshBridgeConnection> {
    match endpoint.local_network() {
        MeshBridgeNetwork::Tcp => {
            connect_mesh_bridge_tcp(endpoint, timeout).map(MeshBridgeConnection::Tcp)
        }
        MeshBridgeNetwork::Udp => {
            connect_mesh_bridge_udp(endpoint, timeout).map(MeshBridgeConnection::Udp)
        }
    }
}

/// Connects to a local TCP Mesh bridge and consumes its capability handshake.
///
/// Returns `InvalidInput` if the endpoint came from a UDP bridge response.
pub fn connect_mesh_bridge_tcp(
    endpoint: &MeshBridgeEndpoint,
    timeout: Option<Duration>,
) -> io::Result<TcpStream> {
    require_local_network(endpoint, MeshBridgeNetwork::Tcp)?;
    let address = endpoint.address();
    let mut stream = match timeout {
        Some(timeout) => TcpStream::connect_timeout(&address, timeout)?,
        None => TcpStream::connect(address)?,
    };
    stream.set_write_timeout(timeout)?;
    stream.write_all(endpoint.capability.expose().as_bytes())?;
    stream.write_all(MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

/// Connects to a local UDP Mesh bridge and sends its capability as one
/// standalone authentication datagram.
///
/// Returns `InvalidInput` if the endpoint came from a TCP bridge response.
pub fn connect_mesh_bridge_udp(
    endpoint: &MeshBridgeEndpoint,
    timeout: Option<Duration>,
) -> io::Result<UdpSocket> {
    require_local_network(endpoint, MeshBridgeNetwork::Udp)?;
    let remote = endpoint.address();
    let local = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, EPHEMERAL_PORT)),
    };
    let socket = UdpSocket::bind(local)?;
    socket.set_write_timeout(timeout)?;
    socket.connect(remote)?;
    let authentication = endpoint.capability.expose().as_bytes();
    if socket.send(authentication)? != authentication.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "mesh bridge authentication datagram was truncated",
        ));
    }
    socket.set_write_timeout(None)?;
    Ok(socket)
}

fn require_local_network(
    endpoint: &MeshBridgeEndpoint,
    expected: MeshBridgeNetwork,
) -> io::Result<()> {
    let actual = endpoint.local_network();
    if actual == expected {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("expected a {expected} Mesh bridge endpoint, received {actual}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    const CAPABILITY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const NON_LOOPBACK: &str = "192.0.2.10";
    const PAYLOAD: &[u8] = b"ping";
    const RECEIVE_BUFFER_BYTES: usize = 128;
    const TIMEOUT: Duration = Duration::from_secs(5);
    const VALID_TEST_PORT: u16 = 1;

    #[test]
    fn local_network_matches_daemon_wire_values() {
        assert_eq!(MeshBridgeNetwork::Tcp.as_str(), "tcp");
        assert_eq!(MeshBridgeNetwork::Udp.as_str(), "udp");
        assert_eq!("tcp".parse(), Ok(MeshBridgeNetwork::Tcp));
        assert_eq!("udp".parse(), Ok(MeshBridgeNetwork::Udp));

        for invalid in ["", "TCP", "udp ", "icmp"] {
            assert_eq!(
                invalid.parse::<MeshBridgeNetwork>(),
                Err(ParseMeshBridgeNetworkError)
            );
        }
    }

    #[test]
    fn tcp_helper_authenticates_before_payload() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)).unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap(), MeshBridgeNetwork::Tcp);
        let receiver = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received =
                vec![
                    0;
                    CAPABILITY.len() + MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX.len() + PAYLOAD.len()
                ];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let mut stream = connect_mesh_bridge_tcp(&endpoint, Some(TIMEOUT)).unwrap();
        stream.write_all(PAYLOAD).unwrap();
        let mut expected = CAPABILITY.as_bytes().to_vec();
        expected.extend_from_slice(MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX);
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(receiver.join().unwrap(), expected);
    }

    #[test]
    fn udp_helper_authenticates_with_separate_datagram() {
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)).unwrap();
        listener.set_read_timeout(Some(TIMEOUT)).unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap(), MeshBridgeNetwork::Udp);
        let socket = connect_mesh_bridge_udp(&endpoint, Some(TIMEOUT)).unwrap();
        socket.send(PAYLOAD).unwrap();
        assert!(socket.local_addr().unwrap().ip().is_loopback());
        let mut buffer = [0_u8; RECEIVE_BUFFER_BYTES];
        let (capability_bytes, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..capability_bytes], CAPABILITY.as_bytes());
        let (payload_bytes, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..payload_bytes], PAYLOAD);
    }

    #[test]
    fn response_network_dispatch_preserves_concrete_socket_type() {
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)).unwrap();
        let tcp_endpoint = endpoint(tcp_listener.local_addr().unwrap(), MeshBridgeNetwork::Tcp);
        let tcp_receiver = thread::spawn(move || {
            let (mut stream, _) = tcp_listener.accept().unwrap();
            let mut authentication =
                vec![0; CAPABILITY.len() + MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX.len()];
            stream.read_exact(&mut authentication).unwrap();
            authentication
        });
        let connection = connect_mesh_bridge(&tcp_endpoint, Some(TIMEOUT)).unwrap();
        assert_eq!(connection.local_network(), MeshBridgeNetwork::Tcp);
        assert!(matches!(connection, MeshBridgeConnection::Tcp(_)));
        let mut expected = CAPABILITY.as_bytes().to_vec();
        expected.extend_from_slice(MESH_BRIDGE_TCP_AUTHENTICATION_SUFFIX);
        assert_eq!(tcp_receiver.join().unwrap(), expected);

        let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)).unwrap();
        udp_listener.set_read_timeout(Some(TIMEOUT)).unwrap();
        let udp_endpoint = endpoint(udp_listener.local_addr().unwrap(), MeshBridgeNetwork::Udp);
        let connection = connect_mesh_bridge(&udp_endpoint, Some(TIMEOUT)).unwrap();
        assert_eq!(connection.local_network(), MeshBridgeNetwork::Udp);
        assert!(matches!(connection, MeshBridgeConnection::Udp(_)));
        let mut authentication = [0_u8; RECEIVE_BUFFER_BYTES];
        let (received, _) = udp_listener.recv_from(&mut authentication).unwrap();
        assert_eq!(&authentication[..received], CAPABILITY.as_bytes());
    }

    #[test]
    fn specialized_helpers_reject_the_wrong_response_network() {
        let tcp_endpoint = MeshBridgeEndpoint::new(
            Ipv4Addr::LOCALHOST.to_string(),
            VALID_TEST_PORT,
            MeshBridgeNetwork::Tcp,
            MeshBridgeCapability::new(CAPABILITY).unwrap(),
        )
        .unwrap();
        let udp_endpoint = MeshBridgeEndpoint::new(
            Ipv4Addr::LOCALHOST.to_string(),
            VALID_TEST_PORT,
            MeshBridgeNetwork::Udp,
            MeshBridgeCapability::new(CAPABILITY).unwrap(),
        )
        .unwrap();

        assert_eq!(
            connect_mesh_bridge_udp(&tcp_endpoint, Some(TIMEOUT))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            connect_mesh_bridge_tcp(&udp_endpoint, Some(TIMEOUT))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn endpoint_rejects_malformed_or_non_loopback_values() {
        assert!(MeshBridgeCapability::new("short").is_err());
        assert!(MeshBridgeCapability::new(format!("{CAPABILITY}=")).is_err());
        assert!(MeshBridgeCapability::new(format!(" {CAPABILITY}")).is_err());
        let capability = MeshBridgeCapability::new(CAPABILITY).unwrap();
        assert!(MeshBridgeEndpoint::new(
            NON_LOOPBACK,
            VALID_TEST_PORT,
            MeshBridgeNetwork::Tcp,
            capability.clone(),
        )
        .is_err());
        assert!(MeshBridgeEndpoint::new(
            "localhost",
            VALID_TEST_PORT,
            MeshBridgeNetwork::Tcp,
            capability.clone(),
        )
        .is_err());
        assert!(MeshBridgeEndpoint::new(
            "0:0:0:0:0:0:0:1",
            VALID_TEST_PORT,
            MeshBridgeNetwork::Tcp,
            capability.clone(),
        )
        .is_err());
        assert!(MeshBridgeEndpoint::new(
            Ipv4Addr::LOCALHOST.to_string(),
            EPHEMERAL_PORT,
            MeshBridgeNetwork::Tcp,
            capability,
        )
        .is_err());
    }

    #[test]
    fn response_constructor_rejects_unknown_networks_without_resolving_hosts() {
        assert!(MeshBridgeEndpoint::from_response(
            "localhost",
            VALID_TEST_PORT,
            "icmp",
            CAPABILITY,
        )
        .is_err());
        let endpoint = MeshBridgeEndpoint::from_response(
            Ipv4Addr::LOCALHOST.to_string(),
            VALID_TEST_PORT,
            "udp",
            CAPABILITY,
        )
        .unwrap();
        assert_eq!(endpoint.local_ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.local_port(), VALID_TEST_PORT);
        assert_eq!(endpoint.local_network(), MeshBridgeNetwork::Udp);

        let ipv6_endpoint = MeshBridgeEndpoint::from_response(
            Ipv6Addr::LOCALHOST.to_string(),
            VALID_TEST_PORT,
            "tcp",
            CAPABILITY,
        )
        .unwrap();
        assert_eq!(ipv6_endpoint.local_ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn capability_is_redacted_from_ordinary_diagnostics() {
        let capability = MeshBridgeCapability::new(CAPABILITY).unwrap();
        let endpoint = MeshBridgeEndpoint::new(
            Ipv4Addr::LOCALHOST.to_string(),
            VALID_TEST_PORT,
            MeshBridgeNetwork::Tcp,
            capability.clone(),
        )
        .unwrap();
        let diagnostic =
            format!("{capability} {capability:?} {capability:#?} {endpoint:?} {endpoint:#?}");
        assert!(
            !diagnostic.contains(CAPABILITY),
            "diagnostics leaked mesh bridge capability: {diagnostic}"
        );
        assert_eq!(capability.expose(), CAPABILITY);
        assert_eq!(endpoint.capability().expose(), CAPABILITY);
    }

    fn endpoint(address: SocketAddr, network: MeshBridgeNetwork) -> MeshBridgeEndpoint {
        MeshBridgeEndpoint::new(
            address.ip().to_string(),
            address.port(),
            network,
            MeshBridgeCapability::new(CAPABILITY).unwrap(),
        )
        .unwrap()
    }
}
