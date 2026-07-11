package daemonrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/mesh"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/testmodules/mockexploit"
)

func TestClientRunsMockExploitThroughDaemonRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	result, err := client.RunMockExploit(context.Background(), RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "mock exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
	if result.Artifacts[0].Data == "" {
		t.Fatalf("artifact = %#v, want inline data", result.Artifacts[0])
	}
}

func TestClientCanDialDaemonRPCOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, "tcp://"+address, runs)

	client, err := Dial("tcp://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	result, err := client.RunMockExploit(context.Background(), RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != "run-1" || result.State != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
}

func TestDaemonRPCTracksMeshTaskAndStreamOperations(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(recordingSessionBroker{}))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	task, err := client.RunMeshTask(context.Background(), MeshTaskRunRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.TaskRequest{
			RunID:           "run-mesh-1",
			TaskID:          "deliver-exploit",
			Kind:            string(mesh.TaskUploadExecute),
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
			Route:           &mesh.Route{ID: "route-relay-1", Nodes: []string{"controller", "relay-1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "succeeded" || task.DestinationHost != "10.10.10.10" {
		t.Fatalf("mesh task = %#v", task)
	}

	session, err := client.OpenMeshStream(context.Background(), MeshStreamOpenRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-2",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
			Config:          map[string]any{"bridge.localAddress": "127.0.0.1:1445"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "mesh-session-1" {
		t.Fatalf("mesh stream session = %#v", session)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		ModuleID: "mesh-provider@v0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 2 {
		t.Fatalf("mesh operations = %#v, want task and stream", operations.Operations)
	}
	taskOperation := operations.Operations[0]
	if taskOperation.Kind != "task" ||
		taskOperation.State != "succeeded" ||
		taskOperation.TaskKind != "upload_execute" ||
		taskOperation.SessionID != "mesh-task-session-1" ||
		taskOperation.DestinationHost != "10.10.10.10" ||
		taskOperation.DestinationPort != 445 ||
		taskOperation.RouteID != "route-relay-1" {
		t.Fatalf("task operation = %#v", taskOperation)
	}
	if !reflect.DeepEqual(taskOperation.SessionIDs, []string{"mesh-task-session-1", "mesh-task-session-2"}) {
		t.Fatalf("task operation sessions = %#v", taskOperation.SessionIDs)
	}
	streamOperation := operations.Operations[1]
	if streamOperation.Kind != "stream" ||
		streamOperation.State != "active" ||
		streamOperation.SessionID != "mesh-session-1" ||
		streamOperation.LocalAddress != "" {
		t.Fatalf("stream operation = %#v", streamOperation)
	}

	byTaskSession, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTaskSession.Operations) != 1 || byTaskSession.Operations[0].Kind != "task" {
		t.Fatalf("task session operations = %#v, want task operation", byTaskSession.Operations)
	}
	bySecondaryTaskSession, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-2",
		State:     "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bySecondaryTaskSession.Operations) != 0 {
		t.Fatalf("closed secondary task session operations = %#v, want none", bySecondaryTaskSession.Operations)
	}

	if err := client.CloseSession(context.Background(), "mesh-session-1"); err != nil {
		t.Fatal(err)
	}
	closed, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-session-1",
		State:     "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(closed.Operations) != 1 || closed.Operations[0].ClosedAt == "" {
		t.Fatalf("closed operations = %#v, want closed stream with timestamp", closed.Operations)
	}
	stillSucceeded, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-1",
		State:     "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stillSucceeded.Operations) != 1 || stillSucceeded.Operations[0].Kind != "task" {
		t.Fatalf("task operations after stream close = %#v, want succeeded task", stillSucceeded.Operations)
	}
}

func TestClientOpensTCPMeshBridgeAsLocalEndpoint(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:  "mesh-provider@v0.1.0",
		LocalHost: "127.0.0.1",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.OperationID == "" || bridge.SessionID != "mesh-session-1" {
		t.Fatalf("mesh bridge = %#v, want operation and mesh session", bridge)
	}
	if bridge.LocalHost != "127.0.0.1" || bridge.LocalPort == 0 || bridge.LocalAddress == "" {
		t.Fatalf("mesh bridge endpoint = %#v, want local loopback address", bridge)
	}

	conn, err := net.DialTimeout("tcp", bridge.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close bridge connection: %v", err)
		}
	}()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "ping" {
			t.Fatalf("session write = %q, want ping", string(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge to write to session")
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("pong")}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("local bridge read = %q, want pong", string(buf[:n]))
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for natural mesh bridge session close")
	}
	if _, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("CloseMeshBridge after natural close error = %v, want missing bridge", err)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:  "bridge",
		State: "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].ID != bridge.OperationID ||
		operations.Operations[0].LocalAddress != bridge.LocalAddress {
		t.Fatalf("closed bridge operations = %#v", operations.Operations)
	}
}

func TestClientOpensUDPMeshBridgeAsLocalEndpoint(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 15, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:  "mesh-provider@v0.1.0",
		LocalHost: "127.0.0.1",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-bridge",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.OperationID == "" || bridge.SessionID != "mesh-session-1" {
		t.Fatalf("mesh bridge = %#v, want operation and mesh session", bridge)
	}
	if bridge.LocalHost != "127.0.0.1" || bridge.LocalPort == 0 || bridge.LocalAddress == "" {
		t.Fatalf("mesh bridge endpoint = %#v, want local loopback address", bridge)
	}

	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close udp bridge connection: %v", err)
		}
	}()

	if _, err := conn.Write([]byte("dns?")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "dns?" {
			t.Fatalf("session datagram = %q, want dns?", string(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge to write UDP datagram to session")
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("dns!")}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "dns!" {
		t.Fatalf("local bridge datagram = %q, want dns!", string(buf[:n]))
	}

	closed, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		SessionID: bridge.SessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != "closed" || closed.OperationID != bridge.OperationID {
		t.Fatalf("closed bridge = %#v, want closed operation", closed)
	}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge session close")
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind: "bridge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].Protocol != "udp" ||
		operations.Operations[0].LocalAddress != bridge.LocalAddress {
		t.Fatalf("udp bridge operations = %#v", operations.Operations)
	}
}

func TestUDPMeshBridgePreservesProviderDatagramUntilLocalPeerArrives(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 18, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-early-reply",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, closeErr := client.CloseMeshBridge(
			context.Background(),
			MeshBridgeCloseRequest{OperationID: bridge.OperationID},
		)
		if closeErr != nil && !strings.Contains(closeErr.Error(), "does not exist") {
			t.Errorf("close UDP bridge: %v", closeErr)
		}
	}()

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("early")}
	select {
	case <-sessions.readDelivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for provider datagram read")
	}
	// Give the bridge pump time to process the provider read before a local peer
	// exists. The datagram must remain pending rather than being discarded.
	time.Sleep(25 * time.Millisecond)

	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close UDP peer: %v", err)
		}
	}()
	if _, err := conn.Write([]byte("claim")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "claim" {
			t.Fatalf("session datagram = %q, want claim", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local peer claim")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "early" {
		t.Fatalf("pending provider datagram = %q, want early", got)
	}
}

func TestUDPMeshBridgeClosesWhenProviderSessionEnds(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 20, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-close",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Closed: true}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for provider-closed UDP bridge cleanup")
	}
	if _, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("CloseMeshBridge after provider close error = %v, want missing bridge", err)
	}
	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:  "bridge",
		State: "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 || operations.Operations[0].ID != bridge.OperationID {
		t.Fatalf("closed UDP bridge operations = %#v", operations.Operations)
	}
}

func TestUDPMeshBridgeRequiresDatagramSessionCapability(t *testing.T) {
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	_, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-capability",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{omitDatagramCapability: true},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 13, 25, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err == nil || !strings.Contains(err.Error(), "datagram capability") {
		t.Fatalf("OpenMeshBridge error = %v, want datagram capability rejection", err)
	}
	select {
	case got := <-sessions.closes:
		if got != "mesh-session-1" {
			t.Fatalf("closed session = %q, want mesh-session-1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rejected UDP session cleanup")
	}
	if _, ok := manager.Find("mesh-op-1", ""); ok {
		t.Fatal("rejected UDP bridge remains tracked")
	}
	operations := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(operations) != 1 || !strings.Contains(operations[0].Error, "datagram capability") {
		t.Fatalf("failed UDP bridge operations = %#v", operations)
	}
}

func TestUDPMeshBridgeKeepsFirstLocalPeer(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 27, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-peer",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, closeErr := client.CloseMeshBridge(
			context.Background(),
			MeshBridgeCloseRequest{OperationID: bridge.OperationID},
		)
		if closeErr != nil && !strings.Contains(closeErr.Error(), "does not exist") {
			t.Errorf("close UDP bridge: %v", closeErr)
		}
	}()
	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	first, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := first.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close first UDP peer: %v", err)
		}
	}()
	second, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := second.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close second UDP peer: %v", err)
		}
	}()

	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "first" {
			t.Fatalf("first session datagram = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first UDP peer")
	}
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		t.Fatalf("second UDP peer reached session: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("reply")}
	if err := first.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	n, err := first.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("first UDP peer reply = %q", buf[:n])
	}
	if err := second.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(buf); err == nil {
		t.Fatal("second UDP peer received bridge reply")
	}
}

func TestMeshBridgeRejectsNonLoopbackLocalHost(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 30, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(newBridgeSessionBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	_, err = client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:  "mesh-provider@v0.1.0",
		LocalHost: "0.0.0.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("OpenMeshBridge error = %v, want loopback rejection", err)
	}
}

func TestMeshBridgeRejectsRawProtocolLocalEndpoint(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 45, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(newBridgeSessionBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	_, err = client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:  "mesh-provider@v0.1.0",
		LocalHost: "127.0.0.1",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			Protocol:        "icmp",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "local socket bridges currently support tcp or udp") {
		t.Fatalf("OpenMeshBridge error = %v, want local socket protocol rejection", err)
	}
}

func TestOpenMeshBridgeDefaultsClock(t *testing.T) {
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 0, 0, 0, time.UTC)},
		),
		Sessions: newBridgeSessionBroker(),
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	defer func() {
		if err := bridge.Close(context.Background()); err != nil {
			t.Fatalf("close bridge: %v", err)
		}
	}()

	operations := book.List(MeshOperationListRequest{Kind: "bridge"})
	if len(operations) != 1 {
		t.Fatalf("bridge operations = %#v, want one operation", operations)
	}
	if operations[0].StartedAt == "" || operations[0].UpdatedAt == "" {
		t.Fatalf("bridge operation timestamps = %#v, want defaulted clock timestamps", operations[0])
	}
}

func TestMeshBridgeDoesNotStoreConnectionAfterClose(t *testing.T) {
	bridge := &MeshBridge{}
	bridge.setClosed()
	client, server := net.Pipe()
	defer func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close client pipe: %v", err)
		}
	}()

	if bridge.setConn(server) {
		t.Fatal("setConn after close = true, want false")
	}
	if bridge.currentConn() != nil {
		t.Fatal("currentConn after close is set, want nil")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMeshBridgeWritesEntireSessionChunkToLocalStream(t *testing.T) {
	sessions := newBridgeSessionBroker()
	sessions.reads <- run.SessionChunk{SessionID: "mesh-session-1", Data: []byte("complete"), Closed: true}
	conn := &shortWriteConn{}
	bridge := &MeshBridge{sessions: sessions, sessionID: "mesh-session-1"}

	if err := bridge.copySessionToLocal(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if got := string(conn.data); got != "complete" {
		t.Fatalf("local stream write = %q, want complete", got)
	}
}

func TestMeshBridgeCloseReturnsStableErrorAndFailsBookkeeping(t *testing.T) {
	closeFailure := errors.New("provider close failed")
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	sessions.closeErr = closeFailure
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-close-error",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 5, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	if err := bridge.Close(context.Background()); !errors.Is(err, closeFailure) {
		t.Fatalf("first Close error = %v, want provider failure", err)
	}
	if err := bridge.Close(context.Background()); !errors.Is(err, closeFailure) {
		t.Fatalf("second Close error = %v, want stable provider failure", err)
	}
	if _, ok := manager.Find(response.OperationID, ""); ok {
		t.Fatal("failed-close bridge remains tracked")
	}
	operations := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(operations) != 1 || !strings.Contains(operations[0].Error, closeFailure.Error()) {
		t.Fatalf("failed-close bridge operations = %#v", operations)
	}
}

func TestMeshBridgeFinishRetainsTransferAndCleanupErrors(t *testing.T) {
	transferFailure := errors.New("bridge transfer failed")
	closeFailure := errors.New("provider close failed")
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	sessions.closeErr = closeFailure
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-transfer-error",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 7, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	bridge.finish(transferFailure)

	operations := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(operations) != 1 ||
		!strings.Contains(operations[0].Error, transferFailure.Error()) ||
		!strings.Contains(operations[0].Error, closeFailure.Error()) {
		t.Fatalf("failed bridge operations = %#v, want transfer and cleanup errors", operations)
	}
}

func TestCloseMeshBridgeRequiresExactlyOneSelector(t *testing.T) {
	server := &Server{}
	for _, req := range []MeshBridgeCloseRequest{
		{},
		{OperationID: "mesh-op-1", SessionID: "mesh-session-1"},
	} {
		_, err := server.closeMeshBridgeRPC(context.Background(), req)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("closeMeshBridgeRPC(%#v) error = %v, want selector rejection", req, err)
		}
	}
}

func TestMeshBookListDefensivelyCopiesSessionIDs(t *testing.T) {
	book := NewMeshBook()
	operation := book.StartStream("mesh-provider@v0.1.0", mesh.StreamRequest{}, time.Now())
	book.ActivateStream(operation.ID, run.SessionRef{ID: "mesh-session-1"}, time.Now())

	listed := book.List(MeshOperationListRequest{})
	listed[0].SessionIDs[0] = "mutated"
	listed = book.List(MeshOperationListRequest{})
	if got := listed[0].SessionIDs[0]; got != "mesh-session-1" {
		t.Fatalf("stored session id = %q, want defensive copy", got)
	}
}

func TestSessionClientPublishesModuleAddedLog(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	logs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) != 2 {
		t.Fatalf("log count = %d, want 2: %#v", len(logs.Logs), logs.Logs)
	}
	got := logs.Logs[1]
	if got.Chain != "c1" || got.Entry.Message != "module added" || got.Entry.Fields["module"] != "mock-survey" {
		t.Fatalf("published log = %#v", got)
	}
}

func TestPollChainLogsOnlyReturnsRequestedChain(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaLogs, err := client.PollChainLogs(context.Background(), "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alphaLogs.Logs) != 2 {
		t.Fatalf("alpha log count = %d, want 2: %#v", len(alphaLogs.Logs), alphaLogs.Logs)
	}
	for _, log := range alphaLogs.Logs {
		if log.Chain != "alpha" {
			t.Fatalf("alpha poll returned chain %q log: %#v", log.Chain, log)
		}
	}

	allLogs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(allLogs.Logs) != 4 {
		t.Fatalf("all log count = %d, want 4: %#v", len(allLogs.Logs), allLogs.Logs)
	}
}

func TestLogBrokerRetainsBoundedHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(3)
	for i := 1; i <= 10; i++ {
		chain := "alpha"
		if i%2 == 0 {
			chain = "beta"
		}
		broker.Publish("op", chain, operatorlog.Entry{Message: "log"})
	}

	last, logs := broker.Since(0)
	if last != 10 {
		t.Fatalf("last = %d, want 10", last)
	}
	if len(logs) != 3 {
		t.Fatalf("retained logs = %d, want 3", len(logs))
	}
	if logs[0].Seq != 8 || logs[2].Seq != 10 {
		t.Fatalf("retained seqs = %#v, want 8..10", logs)
	}

	last, alpha := broker.SinceChain("op", "alpha", 0)
	if last != 10 {
		t.Fatalf("chain last = %d, want 10", last)
	}
	if len(alpha) != 1 || alpha[0].Seq != 9 {
		t.Fatalf("alpha logs = %#v, want only retained alpha seq 9", alpha)
	}
}

func TestLogBrokerPublishDoesNotScanHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(32)
	started := time.Now()
	for i := 0; i < 10000; i++ {
		broker.Publish("op", "chain", operatorlog.Entry{Message: "log"})
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("publishing 10000 bounded logs took %s, want under 500ms", elapsed)
	}
	if len(broker.logs) != 32 {
		t.Fatalf("retained logs = %d, want 32", len(broker.logs))
	}
}

func TestSessionLogFloodIsBoundedThroughRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(64)))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("flood-op"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("flood"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if err := session.AppendLog(operatorlog.Info("flood", "log")); err != nil {
			t.Fatal(err)
		}
	}

	logs, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", 0)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Last < 250 {
		t.Fatalf("last = %d, want at least 250 flood logs", logs.Last)
	}
	if len(logs.Logs) != 64 {
		t.Fatalf("retained logs = %d, want broker limit 64", len(logs.Logs))
	}
	wantFirst := logs.Last - uint64(len(logs.Logs)) + 1
	if logs.Logs[0].Seq != wantFirst || logs.Logs[len(logs.Logs)-1].Seq != logs.Last {
		t.Fatalf("retained seq range = %d..%d, want contiguous tail %d..%d", logs.Logs[0].Seq, logs.Logs[len(logs.Logs)-1].Seq, wantFirst, logs.Last)
	}

	next, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", logs.Last)
	if err != nil {
		t.Fatal(err)
	}
	if next.Last != logs.Last || len(next.Logs) != 0 {
		t.Fatalf("poll after cursor = %#v, want no new logs", next)
	}
}

func TestConcurrentSessionClientsAppendLogsWithoutCrossChainContamination(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(512)))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	for _, setup := range []struct {
		name    string
		session *SessionClient
		chain   string
	}{
		{name: "alpha", session: alpha, chain: "alpha"},
		{name: "beta", session: beta, chain: "beta"},
	} {
		if err := setup.session.UseOperation("concurrent-op"); err != nil {
			t.Fatalf("%s operation: %v", setup.name, err)
		}
		if err := setup.session.UseChain(setup.chain); err != nil {
			t.Fatalf("%s chain: %v", setup.name, err)
		}
	}
	alphaCursor, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	betaCursor, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", 0)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	appendLogs := func(session *SessionClient, chain string) {
		<-start
		for i := 0; i < 50; i++ {
			if err := session.AppendLog(operatorlog.Info("concurrent", fmt.Sprintf("%s-%02d", chain, i))); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}
	go appendLogs(alpha, "alpha")
	go appendLogs(beta, "beta")
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", alphaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	betaLogs, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", betaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	assertConcurrentChainLogs(t, "alpha", alphaLogs.Logs)
	assertConcurrentChainLogs(t, "beta", betaLogs.Logs)
}

func assertConcurrentChainLogs(t *testing.T, chain string, logs []PublishedLog) {
	t.Helper()
	if len(logs) != 50 {
		t.Fatalf("%s log count = %d, want 50: %#v", chain, len(logs), logs)
	}
	for i, log := range logs {
		if log.Operation != "concurrent-op" || log.Chain != chain {
			t.Fatalf("%s log %d topic = %s/%s, want concurrent-op/%s: %#v", chain, i, log.Operation, log.Chain, chain, log)
		}
		wantMessage := fmt.Sprintf("%s-%02d", chain, i)
		if log.Entry.Message != wantMessage {
			t.Fatalf("%s log %d message = %q, want %q", chain, i, log.Entry.Message, wantMessage)
		}
	}
}

func TestSessionClientsKeepIndependentOperationChainAttachments(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	if err := alpha.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaState := alpha.Snapshot()
	if alphaState.ActiveOperation != "redteam-lab" || alphaState.ActiveChain != "alpha" {
		t.Fatalf("alpha attachment = %s/%s, want redteam-lab/alpha", alphaState.ActiveOperation, alphaState.ActiveChain)
	}
	if got, want := alphaState.OperationTargets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha operation targets = %#v, want %#v", got, want)
	}
	if got, want := alphaState.Targets, []string{"mock://alpha"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha chain targets = %#v, want %#v", got, want)
	}
	betaState := beta.Snapshot()
	if betaState.ActiveOperation != "redteam-lab" || betaState.ActiveChain != "beta" {
		t.Fatalf("beta attachment = %s/%s, want redteam-lab/beta", betaState.ActiveOperation, betaState.ActiveChain)
	}
	if got, want := betaState.OperationTargets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta operation targets = %#v, want %#v", got, want)
	}
	if got, want := betaState.Targets, []string{"mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta chain targets = %#v, want %#v", got, want)
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "redteam-lab", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, log := range alphaLogs.Logs {
		if log.Operation != "redteam-lab" || log.Chain != "alpha" {
			t.Fatalf("alpha poll returned wrong topic: %#v", log)
		}
	}
}

func TestSessionClientBindsAndUnbindsOperationTarget(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.BindTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	if got, want := session.Snapshot().Targets, []string{"mock://ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bound chain targets = %#v, want %#v", got, want)
	}

	if err := session.UnbindTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	state := session.Snapshot()
	if len(state.Targets) != 0 {
		t.Fatalf("chain targets after unbind = %#v, want none", state.Targets)
	}
	if got, want := state.OperationTargets, []string{"mock://ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("operation targets after unbind = %#v, want %#v", got, want)
	}
}

func TestSessionMutationsPersistSnapshots(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.CreateTargetSet("lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("lab", "mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	if len(persisted) == 0 {
		t.Fatal("no persisted snapshots")
	}
	last := persisted[len(persisted)-1]
	var gotOperation operatorsession.PersistedOperation
	var got operatorsession.PersistedChain
	for _, operation := range last.Operations {
		if operation.Name != "redteam-lab" {
			continue
		}
		gotOperation = operation
		for _, chain := range operation.Chains {
			if chain.Name == "alpha" {
				got = chain
			}
		}
	}
	if got.Name != "alpha" {
		t.Fatalf("persisted operations = %#v, want redteam-lab/alpha", last.Operations)
	}
	if !reflect.DeepEqual(gotOperation.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted operation targets = %#v", gotOperation.Targets)
	}
	if !reflect.DeepEqual(gotOperation.TargetSets, []operatorsession.TargetSet{{Name: "lab", Targets: []string{"mock://alpha"}}}) {
		t.Fatalf("persisted operation target sets = %#v", gotOperation.TargetSets)
	}
	if !reflect.DeepEqual(got.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted chain targets = %#v, want alpha", got.Targets)
	}
	if !reflect.DeepEqual(got.Steps, []operatorsession.Step{{ID: "step-1", ModuleID: "mock-survey"}}) {
		t.Fatalf("persisted steps = %#v", got.Steps)
	}
}

func TestActiveLogsDoesNotPersistSnapshot(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLogToChain("alpha", operatorlogEntryFromTest("existing log")); err != nil {
		t.Fatal(err)
	}
	persistCount := len(persisted)
	if persistCount == 0 {
		t.Fatal("setup did not persist")
	}

	logs := session.ActiveLogs()
	if len(logs) != 1 || logs[0].Message != "existing log" {
		t.Fatalf("active logs = %#v", logs)
	}
	if len(persisted) != persistCount {
		t.Fatalf("persist count = %d, want %d after read-only ActiveLogs", len(persisted), persistCount)
	}
}

func TestClientCanAttachHeartbeatAndDetachOperatorEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	clock := &mutableClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	serveTestDaemon(t, socketPath, runs, WithOperatorClock(clock))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	attached, err := client.AttachEntity(context.Background(), AttachEntityRequest{
		ID:           "entity-mcp",
		Kind:         "mcp",
		DisplayName:  "codex",
		Agent:        true,
		Operation:    "redteam-lab",
		ActiveChain:  "alpha",
		Capabilities: []string{"tools", "resources"},
		PolicyTags:   []string{"allow-plan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attached.Entity.ID != "entity-mcp" || attached.Entity.Kind != "mcp" || !attached.Entity.Agent {
		t.Fatalf("attached entity = %#v", attached.Entity)
	}
	if attached.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || attached.Entity.LastSeenAt != "2026-06-20T12:00:00Z" {
		t.Fatalf("attached times = %s/%s", attached.Entity.ConnectedAt, attached.Entity.LastSeenAt)
	}

	clock.now = clock.now.Add(30 * time.Second)
	heartbeat, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr("redteam-lab"),
		ActiveChain: stringPtr("bravo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || heartbeat.Entity.LastSeenAt != "2026-06-20T12:00:30Z" {
		t.Fatalf("heartbeat times = %s/%s", heartbeat.Entity.ConnectedAt, heartbeat.Entity.LastSeenAt)
	}
	if heartbeat.Entity.ActiveChain != "bravo" {
		t.Fatalf("heartbeat active chain = %q, want bravo", heartbeat.Entity.ActiveChain)
	}

	entities, err := client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entityIDs(entities.Entities), []string{"entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entities = %#v, want %#v", got, want)
	}

	cleared, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr(""),
		ActiveChain: stringPtr(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Entity.Operation != "" || cleared.Entity.ActiveChain != "" {
		t.Fatalf("cleared entity operation/chain = %q/%q, want empty", cleared.Entity.Operation, cleared.Entity.ActiveChain)
	}

	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after clearing operation = %#v, want none for redteam-lab", entities.Entities)
	}

	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-mcp"}); err != nil {
		t.Fatal(err)
	}
	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after detach = %#v, want none", entities.Entities)
	}
}

func TestOperatorEntityAttachmentsDoNotPersistSessionSnapshots(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{ID: "entity-cli", Operation: stringPtr("redteam-lab")}); err != nil {
		t.Fatal(err)
	}
	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-cli"}); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 0 {
		t.Fatalf("persisted snapshots = %#v, want none for live operator entity lifecycle", persisted)
	}
}

func TestClientCoordinatesLaunchKeyApprovalsFromLiveEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}

	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:             "pending-1",
		Operation:      "redteam-lab",
		Chain:          "alpha",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready {
		t.Fatalf("pending throw unexpectedly ready: %#v", pending)
	}
	if got, want := pending.MissingApproverIDs, []string{"entity-cli", "entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing approvers = %#v, want %#v", got, want)
	}

	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil error before approvals")
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-mcp",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready || !reflect.DeepEqual(pending.MissingApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after mcp approval = %#v, want entity-cli missing", pending)
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-cli",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || len(pending.MissingApproverIDs) != 0 {
		t.Fatalf("pending after all approvals = %#v, want ready", pending)
	}
	if ready, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil || !ready.Ready {
		t.Fatalf("RequirePendingThrowReady = %#v, %v; want ready", ready, err)
	}
}

func TestLaunchKeyPendingThrowSnapshotsRequiredEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:        "pending-1",
		Operation: "redteam-lab",
		Chain:     "alpha",
		PlanHash:  "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pending.RequiredApproverIDs, []string{"entity-cli"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required approvers = %#v, want snapshot %#v", got, want)
	}

	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:       "pending-1",
		EntityID: "entity-cli",
		PlanHash: "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || !reflect.DeepEqual(pending.RequiredApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after late attachment = %#v, want original snapshot ready", pending)
	}
}

func TestClientCancelsPendingLaunchKeyThrow(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{ID: "pending-1", Operation: "redteam-lab", Chain: "alpha", PlanHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelPendingThrow(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil after cancel")
	}
}

func TestClientQueriesAndOverridesLaunchKeyPolicy(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAnyone}),
	)
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	policy, err := client.GetLaunchKeyPolicy(context.Background(), LaunchKeyPolicyRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Policy.Mode != "anyone" {
		t.Fatalf("default policy = %#v, want anyone", policy)
	}
	policy, err = client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum", Quorum: 2, HeartbeatTimeout: "30s"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Operation != "redteam-lab" || policy.Policy.Mode != "quorum" || policy.Policy.Quorum != 2 || policy.Policy.HeartbeatTimeout != "30s" {
		t.Fatalf("set policy = %#v, want quorum override", policy)
	}
	if _, err := client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum"}); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("invalid quorum error = %v, want quorum error", err)
	}
}

func entityIDs(entities []OperatorEntity) []string {
	ids := make([]string, 0, len(entities))
	for _, entity := range entities {
		ids = append(ids, entity.ID)
	}
	return ids
}

func stringPtr(value string) *string {
	return &value
}

func TestSessionRPCPropagatesRequestContext(t *testing.T) {
	server := &Server{moduleSessions: contextCheckingSessionBroker{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.listSessionsRPC(ctx, EmptyRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list sessions error = %v, want context canceled", err)
	}
	if _, err := server.readSessionRPC(ctx, SessionReadRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("read session error = %v, want context canceled", err)
	}
	if _, err := server.tailSessionRPC(ctx, SessionTailRequest{SessionID: "s1", MaxLines: 20}); !errors.Is(err, context.Canceled) {
		t.Fatalf("tail session error = %v, want context canceled", err)
	}
	if _, err := server.writeSessionRPC(ctx, SessionWriteRequest{SessionID: "s1", Data: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write session error = %v, want context canceled", err)
	}
	if _, err := server.closeSessionRPC(ctx, SessionCloseRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("close session error = %v, want context canceled", err)
	}
	if _, err := server.listSessionCommandsRPC(ctx, SessionCommandListRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list session commands error = %v, want context canceled", err)
	}
	if _, err := server.runSessionCommandRPC(ctx, SessionCommandRunRequest{SessionID: "s1", Request: run.PayloadCommandRequest{Command: "process.list"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("run session command error = %v, want context canceled", err)
	}
}

func operatorlogEntryFromTest(message string) operatorlog.Entry {
	return operatorlog.Entry{Message: message}
}

type contextCheckingSessionBroker struct{}

func (contextCheckingSessionBroker) ListSessions(ctx context.Context) ([]run.SessionRef, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) WriteSession(ctx context.Context, _ string, _ []byte) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ReadSession(ctx context.Context, _ string, _ time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) TailSession(ctx context.Context, _ string, _ run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) CloseSession(ctx context.Context, _ string) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ListSessionCommands(ctx context.Context, _ string, _ run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) RunSessionCommand(ctx context.Context, _ string, _ run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, contextOrMissing(ctx)
}

func contextOrMissing(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("request context was not propagated")
}

type fakeMeshRunner struct {
	omitDatagramCapability bool
}

func (fakeMeshRunner) Run(_ context.Context, req run.Request) (run.Result, error) {
	return run.Succeeded(req, run.ResultArgs{Summary: "unused fake mesh run"})
}

func (fakeMeshRunner) DescribeMesh(
	_ context.Context,
	_ string,
	_ mesh.DescribeRequest,
) (mesh.Descriptor, error) {
	return mesh.Descriptor{Name: "mesh-provider"}, nil
}

func (fakeMeshRunner) MeshTopology(
	_ context.Context,
	_ string,
	_ mesh.TopologyRequest,
) (mesh.Topology, error) {
	return mesh.Topology{}, nil
}

func (fakeMeshRunner) ListMeshBeacons(
	_ context.Context,
	_ string,
	_ mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	return []mesh.Beacon{}, nil
}

func (fakeMeshRunner) RunMeshTask(
	_ context.Context,
	moduleID string,
	req mesh.TaskRequest,
) (mesh.TaskResult, error) {
	return mesh.TaskResult{
		TaskID:          req.TaskID,
		Status:          "succeeded",
		Summary:         "mesh task routed",
		NodeID:          req.NodeID,
		Route:           req.Route,
		DestinationHost: req.DestinationHost,
		DestinationPort: req.DestinationPort,
		Protocol:        req.Protocol,
		Sessions: []run.SessionRef{
			{
				ID:       "mesh-task-session-1",
				RunID:    req.RunID,
				ModuleID: moduleID,
				Target:   req.Target,
				Name:     "task-opened session",
				Kind:     "agent",
				State:    "active",
			},
			{
				ID:       "mesh-task-session-2",
				RunID:    req.RunID,
				ModuleID: moduleID,
				Target:   req.Target,
				Name:     "task-secondary session",
				Kind:     "stream",
				State:    "active",
			},
		},
	}, nil
}

func (r fakeMeshRunner) OpenMeshStream(
	_ context.Context,
	moduleID string,
	req mesh.StreamRequest,
) (run.SessionRef, error) {
	session := run.SessionRef{
		ID:        "mesh-session-1",
		RunID:     req.RunID,
		ModuleID:  moduleID,
		Target:    req.Target,
		Name:      "Mesh routed session",
		Kind:      "stream",
		State:     "active",
		Transport: "mesh-route",
	}
	if req.Protocol == "udp" && !r.omitDatagramCapability {
		session.Capabilities = []string{run.SessionCapabilityDatagram}
	}
	return session, nil
}

type recordingSessionBroker struct{}

func (recordingSessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	return []run.SessionRef{}, nil
}

func (recordingSessionBroker) WriteSession(context.Context, string, []byte) error {
	return nil
}

func (recordingSessionBroker) ReadSession(context.Context, string, time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (recordingSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (recordingSessionBroker) CloseSession(context.Context, string) error {
	return nil
}

func (recordingSessionBroker) ListSessionCommands(
	context.Context,
	string,
	run.PayloadCommandListRequest,
) ([]run.PayloadCommand, error) {
	return []run.PayloadCommand{}, nil
}

func (recordingSessionBroker) RunSessionCommand(
	context.Context,
	string,
	run.PayloadCommandRequest,
) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, nil
}

type bridgeSessionBroker struct {
	writes        chan []byte
	reads         chan run.SessionChunk
	readDelivered chan struct{}
	closes        chan string
	closeErr      error
}

func newBridgeSessionBroker() *bridgeSessionBroker {
	return &bridgeSessionBroker{
		writes:        make(chan []byte, 8),
		reads:         make(chan run.SessionChunk, 8),
		readDelivered: make(chan struct{}, 8),
		closes:        make(chan string, 8),
	}
}

func (b *bridgeSessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	return []run.SessionRef{}, nil
}

func (b *bridgeSessionBroker) WriteSession(ctx context.Context, _ string, data []byte) error {
	copied := append([]byte(nil), data...)
	select {
	case b.writes <- copied:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *bridgeSessionBroker) ReadSession(
	ctx context.Context,
	sessionID string,
	timeout time.Duration,
) (run.SessionChunk, error) {
	if timeout <= 0 {
		return run.SessionChunk{SessionID: sessionID}, nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case chunk := <-b.reads:
		select {
		case b.readDelivered <- struct{}{}:
		default:
		}
		if chunk.SessionID == "" {
			chunk.SessionID = sessionID
		}
		return chunk, nil
	case <-ctx.Done():
		return run.SessionChunk{}, ctx.Err()
	case <-timer.C:
		return run.SessionChunk{SessionID: sessionID}, nil
	}
}

func (b *bridgeSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (b *bridgeSessionBroker) CloseSession(ctx context.Context, sessionID string) error {
	select {
	case b.closes <- sessionID:
		return b.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

type shortWriteConn struct {
	data []byte
}

func (*shortWriteConn) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }

func (c *shortWriteConn) Write(data []byte) (int, error) {
	n := (len(data) + 1) / 2
	c.data = append(c.data, data[:n]...)
	return n, nil
}

func (*shortWriteConn) Close() error                     { return nil }
func (*shortWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*shortWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (*shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

func (b *bridgeSessionBroker) ListSessionCommands(
	context.Context,
	string,
	run.PayloadCommandListRequest,
) ([]run.PayloadCommand, error) {
	return []run.PayloadCommand{}, nil
}

func (b *bridgeSessionBroker) RunSessionCommand(
	context.Context,
	string,
	run.PayloadCommandRequest,
) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, nil
}

func serveTestDaemon(t *testing.T, endpoint string, runs services.RunService, options ...ServerOption) {
	t.Helper()
	parsed, err := ParseEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(parsed.Network, parsed.Address)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(runs, options...)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("serve test daemon: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("close test daemon server: %v", err)
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("close test daemon listener: %v", err)
		}
	})
}

func closeTestClient(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Logf("close daemon rpc client: %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "hovel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("remove temp dir: %v", err)
		}
	})
	return dir
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	return c.now
}
