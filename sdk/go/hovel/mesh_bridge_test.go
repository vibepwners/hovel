package hovel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testMeshBridgeCapability = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testMeshBridgePayload    = "ping"
	testMeshBridgeTimeout    = 5 * time.Second
)

var diagnosticFormats = []string{
	"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%p",
}

func TestDialMeshBridgeTCPAuthenticatesBeforePayload(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	errors := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		capability, err := reader.ReadString('\n')
		if err != nil {
			errors <- err
			return
		}
		payload := make([]byte, len(testMeshBridgePayload))
		if _, err := io.ReadFull(reader, payload); err != nil {
			errors <- err
			return
		}
		received <- strings.TrimSuffix(capability, "\n") + ":" + string(payload)
	}()

	endpoint := testMeshBridgeEndpoint(t, listener.Addr(), MeshBridgeNetworkTCP)
	ctx, cancel := context.WithTimeout(t.Context(), testMeshBridgeTimeout)
	defer cancel()
	connection, err := DialMeshBridge(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, testMeshBridgePayload); err != nil {
		t.Fatal(err)
	}

	want := testMeshBridgeCapability + ":" + testMeshBridgePayload
	select {
	case err := <-errors:
		t.Fatal(err)
	case got := <-received:
		if got != want {
			t.Fatalf("authenticated payload = %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestDialMeshBridgeUDPAuthenticatesWithSeparateDatagram(t *testing.T) {
	t.Parallel()

	packetConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	received := make(chan string, 1)
	errors := make(chan error, 1)
	go func() {
		buffer := make([]byte, 128)
		capabilityBytes, _, err := packetConnection.ReadFrom(buffer)
		if err != nil {
			errors <- err
			return
		}
		capability := string(buffer[:capabilityBytes])
		payloadBytes, _, err := packetConnection.ReadFrom(buffer)
		if err != nil {
			errors <- err
			return
		}
		received <- capability + ":" + string(buffer[:payloadBytes])
	}()

	endpoint := testMeshBridgeEndpoint(t, packetConnection.LocalAddr(), MeshBridgeNetworkUDP)
	ctx, cancel := context.WithTimeout(t.Context(), testMeshBridgeTimeout)
	defer cancel()
	connection, err := DialMeshBridge(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, testMeshBridgePayload); err != nil {
		t.Fatal(err)
	}

	want := testMeshBridgeCapability + ":" + testMeshBridgePayload
	select {
	case err := <-errors:
		t.Fatal(err)
	case got := <-received:
		if got != want {
			t.Fatalf("authenticated datagrams = %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestMeshBridgeEndpointRejectsUnsafeOrMalformedValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		host       string
		port       int
		network    MeshBridgeNetwork
		capability string
	}{
		{name: "empty host", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "hostname", host: "localhost", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "scoped ipv6", host: "::1%lo", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "mapped ipv4", host: "::ffff:127.0.0.1", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "noncanonical ipv6", host: "0:0:0:0:0:0:0:1", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "non-loopback host", host: "192.0.2.10", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "zero port", host: "127.0.0.1", network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "oversized port", host: "127.0.0.1", port: meshBridgeMaximumPort + 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability},
		{name: "missing network", host: "127.0.0.1", port: 1, capability: testMeshBridgeCapability},
		{name: "unsupported network", host: "127.0.0.1", port: 1, network: "icmp", capability: testMeshBridgeCapability},
		{name: "short capability", host: "127.0.0.1", port: 1, network: MeshBridgeNetworkTCP, capability: "short"},
		{name: "padded capability", host: "127.0.0.1", port: 1, network: MeshBridgeNetworkTCP, capability: testMeshBridgeCapability + "="},
		{name: "spaced capability", host: "127.0.0.1", port: 1, network: MeshBridgeNetworkTCP, capability: " " + testMeshBridgeCapability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewMeshBridgeEndpoint(
				test.host,
				test.port,
				test.network,
				test.capability,
			); err == nil {
				t.Fatal("NewMeshBridgeEndpoint() accepted an invalid endpoint")
			}
		})
	}

	for _, host := range []string{"127.0.0.1", "::1"} {
		if _, err := NewMeshBridgeEndpoint(
			host,
			1,
			MeshBridgeNetworkTCP,
			testMeshBridgeCapability,
		); err != nil {
			t.Fatalf("NewMeshBridgeEndpoint(%q) error = %v", host, err)
		}
	}

	endpoint, err := NewMeshBridgeEndpoint(
		"127.0.0.1",
		1,
		MeshBridgeNetworkTCP,
		testMeshBridgeCapability,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialMeshBridge(nil, endpoint); err == nil {
		t.Fatal("DialMeshBridge() accepted a nil context")
	}
}

func TestMeshBridgeCapabilityIsRedactedInDiagnostics(t *testing.T) {
	t.Parallel()

	endpoint, err := NewMeshBridgeEndpoint(
		"127.0.0.1",
		1,
		MeshBridgeNetworkTCP,
		testMeshBridgeCapability,
	)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics []string
	for _, format := range diagnosticFormats {
		diagnostics = append(diagnostics, fmt.Sprintf(format, endpoint.Capability))
	}
	diagnostics = append(diagnostics,
		fmt.Sprintf("%v", endpoint),
		fmt.Sprintf("%+v", endpoint),
		fmt.Sprintf("%#v", endpoint),
	)
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic, testMeshBridgeCapability) {
			t.Fatalf("mesh bridge diagnostic leaked capability: %s", diagnostic)
		}
	}
	if got := endpoint.Capability.Reveal(); got != testMeshBridgeCapability {
		t.Fatalf("capability accessor = %q, want original capability", got)
	}
}

func testMeshBridgeEndpoint(
	t *testing.T,
	address net.Addr,
	network MeshBridgeNetwork,
) MeshBridgeEndpoint {
	t.Helper()
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewMeshBridgeEndpoint(
		host,
		port,
		network,
		testMeshBridgeCapability,
	)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}
