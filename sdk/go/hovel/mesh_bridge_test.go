package hovel

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testMeshBridgeCapability = MeshBridgeCapability("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	testMeshBridgePayload    = "ping"
	testMeshBridgeTimeout    = 5 * time.Second
)

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

	endpoint := testMeshBridgeEndpoint(t, listener.Addr())
	ctx, cancel := context.WithTimeout(t.Context(), testMeshBridgeTimeout)
	defer cancel()
	connection, err := DialMeshBridge(ctx, MeshBridgeNetworkTCP, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, testMeshBridgePayload); err != nil {
		t.Fatal(err)
	}

	want := string(testMeshBridgeCapability) + ":" + testMeshBridgePayload
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

	endpoint := testMeshBridgeEndpoint(t, packetConnection.LocalAddr())
	ctx, cancel := context.WithTimeout(t.Context(), testMeshBridgeTimeout)
	defer cancel()
	connection, err := DialMeshBridge(ctx, MeshBridgeNetworkUDP, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, testMeshBridgePayload); err != nil {
		t.Fatal(err)
	}

	want := string(testMeshBridgeCapability) + ":" + testMeshBridgePayload
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
		capability MeshBridgeCapability
	}{
		{name: "empty host", port: 1, capability: testMeshBridgeCapability},
		{name: "non-loopback host", host: "192.0.2.10", port: 1, capability: testMeshBridgeCapability},
		{name: "zero port", host: "127.0.0.1", capability: testMeshBridgeCapability},
		{name: "oversized port", host: "127.0.0.1", port: meshBridgeMaximumPort + 1, capability: testMeshBridgeCapability},
		{name: "short capability", host: "127.0.0.1", port: 1, capability: "short"},
		{name: "padded capability", host: "127.0.0.1", port: 1, capability: testMeshBridgeCapability + "="},
		{name: "spaced capability", host: "127.0.0.1", port: 1, capability: " " + testMeshBridgeCapability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewMeshBridgeEndpoint(test.host, test.port, test.capability); err == nil {
				t.Fatal("NewMeshBridgeEndpoint() accepted an invalid endpoint")
			}
		})
	}

	endpoint, err := NewMeshBridgeEndpoint("localhost", 1, testMeshBridgeCapability)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialMeshBridge(t.Context(), "icmp", endpoint); err == nil {
		t.Fatal("DialMeshBridge() accepted an unsupported local adapter")
	}
	if _, err := DialMeshBridge(nil, MeshBridgeNetworkTCP, endpoint); err == nil {
		t.Fatal("DialMeshBridge() accepted a nil context")
	}
}

func testMeshBridgeEndpoint(t *testing.T, address net.Addr) MeshBridgeEndpoint {
	t.Helper()
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewMeshBridgeEndpoint(host, port, testMeshBridgeCapability)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}
