//! Authenticated local Mesh bridge helpers.
//!
//! These helpers hide the daemon's capability preface so consumer protocol
//! code receives a normal connected TCP stream or UDP socket.

use crate::base64;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

const MESH_BRIDGE_CAPABILITY_BYTES: usize = 32;
const MESH_BRIDGE_CAPABILITY_CHARACTERS: usize = 43;

/// Ephemeral 256-bit bearer secret returned by `OpenMeshBridge`.
///
/// Keep this value in memory and never log, persist, or cache it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshBridgeCapability(String);

impl MeshBridgeCapability {
    pub fn new(value: impl Into<String>) -> Result<MeshBridgeCapability, String> {
        let value = value.into();
        if value.trim() != value {
            return Err("mesh bridge capability must be canonical".into());
        }
        if value.len() != MESH_BRIDGE_CAPABILITY_CHARACTERS {
            return Err("mesh bridge capability must contain 43 base64url characters".into());
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

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authenticated loopback endpoint returned by the daemon control API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshBridgeEndpoint {
    local_host: String,
    local_port: u16,
    capability: MeshBridgeCapability,
}

impl MeshBridgeEndpoint {
    pub fn new(
        local_host: impl Into<String>,
        local_port: u16,
        capability: MeshBridgeCapability,
    ) -> Result<MeshBridgeEndpoint, String> {
        let local_host = local_host.into();
        if local_host.trim() != local_host {
            return Err("mesh bridge host must be canonical".into());
        }
        if local_port == 0 {
            return Err("mesh bridge port must be nonzero".into());
        }
        if !is_loopback_host(&local_host) {
            return Err("mesh bridge host must be loopback".into());
        }
        Ok(MeshBridgeEndpoint {
            local_host,
            local_port,
            capability,
        })
    }

    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn capability(&self) -> &MeshBridgeCapability {
        &self.capability
    }

    fn addresses(&self) -> io::Result<Vec<SocketAddr>> {
        let addresses: Vec<_> = (self.local_host.as_str(), self.local_port)
            .to_socket_addrs()?
            .filter(|address| address.ip().is_loopback())
            .collect();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "mesh bridge endpoint did not resolve to loopback",
            ));
        }
        Ok(addresses)
    }
}

/// Connects to a local TCP Mesh bridge and consumes its capability handshake.
pub fn connect_mesh_bridge_tcp(
    endpoint: &MeshBridgeEndpoint,
    timeout: Option<Duration>,
) -> io::Result<TcpStream> {
    let addresses = endpoint.addresses()?;
    let mut stream = connect_tcp_addresses(&addresses, timeout)?;
    stream.set_write_timeout(timeout)?;
    let authentication = endpoint.capability.as_str().as_bytes();
    stream.write_all(authentication)?;
    stream.write_all(b"\n")?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

/// Connects to a local UDP Mesh bridge and sends its capability as one
/// standalone authentication datagram.
pub fn connect_mesh_bridge_udp(
    endpoint: &MeshBridgeEndpoint,
    timeout: Option<Duration>,
) -> io::Result<UdpSocket> {
    let addresses = endpoint.addresses()?;
    let remote = addresses[0];
    let local = if remote.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(local)?;
    socket.set_write_timeout(timeout)?;
    socket.connect(remote)?;
    let authentication = endpoint.capability.as_str().as_bytes();
    if socket.send(authentication)? != authentication.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "mesh bridge authentication datagram was truncated",
        ));
    }
    socket.set_write_timeout(None)?;
    Ok(socket)
}

fn connect_tcp_addresses(
    addresses: &[SocketAddr],
    timeout: Option<Duration>,
) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        let result = match timeout {
            Some(timeout) => TcpStream::connect_timeout(address, timeout),
            None => TcpStream::connect(address),
        };
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "mesh bridge endpoint has no addresses",
        )
    }))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    const CAPABILITY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PAYLOAD: &[u8] = b"ping";
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn tcp_helper_authenticates_before_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let receiver = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; CAPABILITY.len() + 1 + PAYLOAD.len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let mut stream = connect_mesh_bridge_tcp(&endpoint, Some(TIMEOUT)).unwrap();
        stream.write_all(PAYLOAD).unwrap();
        let mut expected = CAPABILITY.as_bytes().to_vec();
        expected.push(b'\n');
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(receiver.join().unwrap(), expected);
    }

    #[test]
    fn udp_helper_authenticates_with_separate_datagram() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_read_timeout(Some(TIMEOUT)).unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let socket = connect_mesh_bridge_udp(&endpoint, Some(TIMEOUT)).unwrap();
        socket.send(PAYLOAD).unwrap();
        let mut buffer = [0_u8; 128];
        let (capability_bytes, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..capability_bytes], CAPABILITY.as_bytes());
        let (payload_bytes, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..payload_bytes], PAYLOAD);
    }

    #[test]
    fn endpoint_rejects_malformed_or_non_loopback_values() {
        assert!(MeshBridgeCapability::new("short").is_err());
        assert!(MeshBridgeCapability::new(format!("{CAPABILITY}=")).is_err());
        assert!(MeshBridgeCapability::new(format!(" {CAPABILITY}")).is_err());
        let capability = MeshBridgeCapability::new(CAPABILITY).unwrap();
        assert!(MeshBridgeEndpoint::new("192.0.2.10", 1, capability.clone()).is_err());
        assert!(MeshBridgeEndpoint::new("127.0.0.1", 0, capability).is_err());
    }

    fn endpoint(address: SocketAddr) -> MeshBridgeEndpoint {
        MeshBridgeEndpoint::new(
            address.ip().to_string(),
            address.port(),
            MeshBridgeCapability::new(CAPABILITY).unwrap(),
        )
        .unwrap()
    }
}
