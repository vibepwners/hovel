package hovel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	meshBridgeCapabilityBytes    = 32
	meshBridgeMaximumPort        = 1<<16 - 1
	redactedMeshBridgeCapability = "<mesh bridge capability redacted>"

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
// OpenMeshBridge. Keep it in memory and never log or persist it. The value is
// pointer-boxed so even unsupported fmt verbs cannot embed the secret in a
// formatting diagnostic.
type MeshBridgeCapability struct {
	value *string
}

func (MeshBridgeCapability) String() string { return redactedMeshBridgeCapability }

func (MeshBridgeCapability) GoString() string { return redactedMeshBridgeCapability }

// Format redacts the capability for fmt value-formatting verbs, including
// verbs that do not use String or GoString.
func (MeshBridgeCapability) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedMeshBridgeCapability)
}

// NewMeshBridgeCapability validates and wraps a bearer capability.
func NewMeshBridgeCapability(value string) (MeshBridgeCapability, error) {
	if strings.TrimSpace(value) != value {
		return MeshBridgeCapability{}, errors.New(
			"hovel: mesh bridge capability must be canonical",
		)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != meshBridgeCapabilityBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return MeshBridgeCapability{}, errors.New(
			"hovel: mesh bridge capability must be canonical 256-bit base64url",
		)
	}
	return MeshBridgeCapability{value: &value}, nil
}

// Reveal returns the bearer capability for an explicit authentication
// boundary. Ordinary formatting remains redacted.
func (c MeshBridgeCapability) Reveal() string {
	if c.value == nil {
		return ""
	}
	return *c.value
}

// MeshBridgeEndpoint is the authenticated loopback endpoint returned by the
// daemon control API. It lets consumer modules use a Mesh route without
// understanding provider-specific topology or routing contracts.
type MeshBridgeEndpoint struct {
	LocalHost    string
	LocalPort    int
	LocalNetwork MeshBridgeNetwork
	Capability   MeshBridgeCapability
}

// NewMeshBridgeEndpoint validates an OpenMeshBridge response before use.
func NewMeshBridgeEndpoint(
	localHost string,
	localPort int,
	localNetwork MeshBridgeNetwork,
	capability string,
) (MeshBridgeEndpoint, error) {
	parsedCapability, err := NewMeshBridgeCapability(capability)
	if err != nil {
		return MeshBridgeEndpoint{}, err
	}
	endpoint := MeshBridgeEndpoint{
		LocalHost:    localHost,
		LocalPort:    localPort,
		LocalNetwork: localNetwork,
		Capability:   parsedCapability,
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
	switch e.LocalNetwork {
	case MeshBridgeNetworkTCP, MeshBridgeNetworkUDP:
	default:
		return fmt.Errorf(
			"hovel: unsupported local mesh bridge network %q",
			e.LocalNetwork,
		)
	}
	encoded := e.Capability.Reveal()
	if _, err := NewMeshBridgeCapability(encoded); err != nil {
		return err
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
	endpoint MeshBridgeEndpoint,
) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("hovel: mesh bridge dial context is required")
	}
	address, err := endpoint.Address()
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		string(endpoint.LocalNetwork),
		address,
	)
	if err != nil {
		return nil, fmt.Errorf("hovel: dial local mesh bridge: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return nil, errors.Join(err, connection.Close())
		}
	}
	preface := []byte(endpoint.Capability.Reveal())
	var authenticateErr error
	if endpoint.LocalNetwork == MeshBridgeNetworkTCP {
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
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && !ip.Is4In6() &&
		ip.IsLoopback() && ip.String() == host
}
