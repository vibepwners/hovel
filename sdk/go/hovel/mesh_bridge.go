package hovel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	meshBridgeCapabilityBytes = 32
	meshBridgeMaximumPort     = 1<<16 - 1

	// MeshBridgeNetworkTCP selects a connected TCP stream.
	MeshBridgeNetworkTCP MeshBridgeNetwork = "tcp"
	// MeshBridgeNetworkUDP selects a connected UDP socket. Each Write is one
	// datagram and the authentication preface is sent as its own datagram.
	MeshBridgeNetworkUDP MeshBridgeNetwork = "udp"
)

// MeshBridgeNetwork selects the daemon-owned local socket adapter used by a
// Mesh bridge. Provider-defined Mesh protocols remain opaque; this value only
// describes the local TCP or UDP adapter returned by the daemon.
type MeshBridgeNetwork string

// MeshBridgeCapability is the ephemeral bearer secret returned by
// OpenMeshBridge. Keep it in memory and never log or persist it.
type MeshBridgeCapability string

// MeshBridgeEndpoint is the authenticated loopback endpoint returned by the
// daemon control API. It lets consumer modules use a Mesh route without
// understanding provider-specific topology or routing contracts.
type MeshBridgeEndpoint struct {
	LocalHost  string
	LocalPort  int
	Capability MeshBridgeCapability
}

// NewMeshBridgeEndpoint validates an OpenMeshBridge response before use.
func NewMeshBridgeEndpoint(
	localHost string,
	localPort int,
	capability MeshBridgeCapability,
) (MeshBridgeEndpoint, error) {
	endpoint := MeshBridgeEndpoint{
		LocalHost:  localHost,
		LocalPort:  localPort,
		Capability: capability,
	}
	if err := endpoint.Validate(); err != nil {
		return MeshBridgeEndpoint{}, err
	}
	return endpoint, nil
}

// Validate rejects non-loopback endpoints and malformed capabilities.
func (e MeshBridgeEndpoint) Validate() error {
	if strings.TrimSpace(e.LocalHost) != e.LocalHost {
		return errors.New("hovel: mesh bridge host must be canonical")
	}
	if !isMeshBridgeLoopback(e.LocalHost) {
		return errors.New("hovel: mesh bridge host must be loopback")
	}
	if e.LocalPort < 1 || e.LocalPort > meshBridgeMaximumPort {
		return errors.New("hovel: mesh bridge port is outside the valid range")
	}
	encoded := strings.TrimSpace(string(e.Capability))
	if encoded != string(e.Capability) {
		return errors.New("hovel: mesh bridge capability must be canonical")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != meshBridgeCapabilityBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return errors.New("hovel: mesh bridge capability must be canonical 256-bit base64url")
	}
	return nil
}

// Address returns the canonical host:port form accepted by net.Dialer.
func (e MeshBridgeEndpoint) Address() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	return net.JoinHostPort(e.LocalHost, strconv.Itoa(e.LocalPort)), nil
}

// DialMeshBridge connects to a daemon-owned local Mesh bridge and performs its
// capability handshake. The returned connection carries only application
// bytes; Hovel consumes the authentication preface before forwarding data to
// the provider-owned Mesh stream.
func DialMeshBridge(
	ctx context.Context,
	network MeshBridgeNetwork,
	endpoint MeshBridgeEndpoint,
) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("hovel: mesh bridge dial context is required")
	}
	switch network {
	case MeshBridgeNetworkTCP, MeshBridgeNetworkUDP:
	default:
		return nil, fmt.Errorf("hovel: unsupported local mesh bridge network %q", network)
	}
	address, err := endpoint.Address()
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, string(network), address)
	if err != nil {
		return nil, fmt.Errorf("hovel: dial local mesh bridge: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return nil, errors.Join(err, connection.Close())
		}
	}
	preface := []byte(endpoint.Capability)
	var authenticateErr error
	if network == MeshBridgeNetworkTCP {
		authenticateErr = writeMeshBridgePreface(connection, append(preface, '\n'))
	} else {
		written, err := connection.Write(preface)
		if err != nil {
			authenticateErr = err
		} else if written != len(preface) {
			authenticateErr = errors.New("mesh bridge authentication datagram was truncated")
		}
	}
	if authenticateErr != nil {
		return nil, errors.Join(
			fmt.Errorf("hovel: authenticate local mesh bridge: %w", authenticateErr),
			connection.Close(),
		)
	}
	if err := connection.SetWriteDeadline(time.Time{}); err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	return connection, nil
}

func writeMeshBridgePreface(connection net.Conn, preface []byte) error {
	for len(preface) > 0 {
		written, err := connection.Write(preface)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("mesh bridge authentication write made no progress")
		}
		preface = preface[written:]
	}
	return nil
}

func isMeshBridgeLoopback(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
