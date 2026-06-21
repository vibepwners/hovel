package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAttachRegistersMCPAgentEntity(t *testing.T) {
	daemon := newFakeDaemon()

	server, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-test",
		DisplayName: "Claude reviewer",
		Operation:   "redteam-lab",
		ActiveChain: "alpha",
		PolicyTags:  []string{"review-required", "review-required"},
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}

	attach := daemon.attachRequests[0]
	if attach.ID != "mcp-test" || attach.Kind != "mcp" || !attach.Agent {
		t.Fatalf("attach request identity = %#v", attach)
	}
	if attach.DisplayName != "Claude reviewer" || attach.Operation != "redteam-lab" || attach.ActiveChain != "alpha" {
		t.Fatalf("attach request context = %#v", attach)
	}
	if got, want := attach.Capabilities, defaultCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
	if got, want := attach.PolicyTags, []string{"review-required"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy tags = %#v, want %#v", got, want)
	}

	if err := server.Detach(context.Background()); err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if got, want := daemon.detachedIDs, []string{"mcp-test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("detached IDs = %#v, want %#v", got, want)
	}
}

func TestMCPServerExposesTypedReadOnlyTools(t *testing.T) {
	daemon := newFakeDaemon()
	var throwRequest throwStartInput
	daemon.snapshot = daemonrpc.SnapshotResponse{State: operatorsession.PersistedState{
		ActiveOperation: "redteam-lab",
		ActiveChain:     "alpha",
		Operations: []operatorsession.PersistedOperation{{
			Name:    "redteam-lab",
			Targets: []string{"mock://router-01"},
			Chains: []operatorsession.PersistedChain{{
				Name:    "alpha",
				Targets: []string{"mock://router-01"},
				Steps: []operatorsession.Step{{
					ID:       "step-1",
					ModuleID: "mock-exploit@v0.0.0-example",
				}},
				Config:   map[string]string{"operator.confirmed_lab": "true"},
				LogTopic: "chain.redteam-lab.alpha",
			}},
		}},
	}}

	attached, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-test",
		DisplayName: "MCP test",
		Operation:   "redteam-lab",
		ActiveChain: "alpha",
		ThrowStarter: func(_ context.Context, input throwStartInput) (throwStartOutput, error) {
			throwRequest = input
			return throwStartOutput{
				Operation: input.Operation,
				Plan: commands.ThrowPlanPayload{
					ID:       "plan-1",
					PlanHash: "hash-1",
					Chain:    input.Chain,
					Targets:  []string{"mock://router-01"},
				},
				ThrowID: "throw-1",
				Chain:   input.Chain,
				Targets: []string{"mock://router-01"},
				Results: []commands.RunPayload{{
					RunID:    "run-1",
					ModuleID: "mock-exploit@v0.0.0-example",
					Target:   "mock://router-01",
					State:    "succeeded",
					Summary:  "mock exploit opened an interactive shell session",
				}},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sdkServer := attached.MCPServer()
	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- sdkServer.Run(ctx, serverTransport)
	}()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect returned error: %v", err)
	}
	defer func() {
		_ = session.Close()
		cancel()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("server run returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
	}()

	tools, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}
	names := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Name == ToolThrowStart {
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
				t.Fatalf("tool %s is missing destructive annotations", tool.Name)
			}
			continue
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool %s is missing read-only annotations", tool.Name)
		}
	}
	sort.Strings(names)
	wantNames := []string{ToolOperationList, ToolOperatorIdentity, ToolOperatorListEntities, ToolThrowStart, ToolWorkspaceSnapshot}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tool names = %#v, want %#v", names, wantNames)
	}

	identityResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: ToolOperatorIdentity})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolOperatorIdentity, err)
	}
	identity := decodeStructured[operatorIdentityOutput](t, identityResult)
	if identity.Entity.ID != "mcp-test" || identity.Entity.Kind != "mcp" || !identity.Entity.Agent {
		t.Fatalf("identity = %#v", identity.Entity)
	}

	listResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      ToolOperatorListEntities,
		Arguments: map[string]any{"operation": "redteam-lab"},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolOperatorListEntities, err)
	}
	entities := decodeStructured[operatorListEntitiesOutput](t, listResult)
	if entities.Operation != "redteam-lab" || len(entities.Entities) != 1 || entities.Entities[0].ID != "mcp-test" {
		t.Fatalf("entities = %#v", entities)
	}

	snapshotResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      ToolWorkspaceSnapshot,
		Arguments: map[string]any{"operation": "redteam-lab", "chain": "alpha"},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolWorkspaceSnapshot, err)
	}
	snapshot := decodeStructured[workspaceSnapshotOutput](t, snapshotResult)
	if snapshot.ActiveOperation != "redteam-lab" || snapshot.ActiveChain != "alpha" {
		t.Fatalf("snapshot context = %s/%s", snapshot.ActiveOperation, snapshot.ActiveChain)
	}
	if len(snapshot.Operations) != 1 || snapshot.Operations[0].Name != "redteam-lab" {
		t.Fatalf("operations = %#v", snapshot.Operations)
	}
	chain := snapshot.Operations[0].Chains[0]
	if chain.Name != "alpha" || len(chain.Steps) != 1 || chain.Steps[0].ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("chain = %#v", chain)
	}
	if got := chain.Config["operator.confirmed_lab"]; got != "true" {
		t.Fatalf("operator.confirmed_lab = %q, want true", got)
	}

	throwResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: ToolThrowStart,
		Arguments: map[string]any{
			"operation": "redteam-lab",
			"chain":     "alpha",
			"nowBypass": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolThrowStart, err)
	}
	throwOut := decodeStructured[throwStartOutput](t, throwResult)
	if throwOut.ThrowID != "throw-1" || throwOut.Chain != "alpha" || len(throwOut.Results) != 1 {
		t.Fatalf("throw output = %#v", throwOut)
	}
	if throwRequest.Operation != "redteam-lab" || throwRequest.Chain != "alpha" || !throwRequest.NowBypass {
		t.Fatalf("throw request = %#v", throwRequest)
	}

	if got := daemon.snapshotRequests[0]; got.Operation != "redteam-lab" || got.Chain != "alpha" {
		t.Fatalf("snapshot request = %#v", got)
	}
	if len(daemon.heartbeatRequests) == 0 {
		t.Fatal("expected tool calls to heartbeat the MCP operator entity")
	}
}

func decodeStructured[T any](t *testing.T, result *mcpsdk.CallToolResult) T {
	t.Helper()
	if result == nil {
		t.Fatal("tool result is nil")
	}
	if result.IsError {
		t.Fatalf("tool returned error content: %#v", result.Content)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode structured content %s: %v", data, err)
	}
	return out
}

type fakeDaemon struct {
	mu                sync.Mutex
	now               time.Time
	attachRequests    []daemonrpc.AttachEntityRequest
	heartbeatRequests []daemonrpc.HeartbeatEntityRequest
	listRequests      []daemonrpc.ListEntitiesRequest
	snapshotRequests  []daemonrpc.SnapshotRequest
	detachedIDs       []string
	entities          map[string]daemonrpc.OperatorEntity
	snapshot          daemonrpc.SnapshotResponse
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{
		now:      time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		entities: map[string]daemonrpc.OperatorEntity{},
	}
}

func (f *fakeDaemon) AttachEntity(_ context.Context, req daemonrpc.AttachEntityRequest) (daemonrpc.EntityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attachRequests = append(f.attachRequests, req)
	entity := daemonrpc.OperatorEntity{
		ID:           req.ID,
		Kind:         req.Kind,
		DisplayName:  req.DisplayName,
		Agent:        req.Agent,
		Operation:    req.Operation,
		ActiveChain:  req.ActiveChain,
		ConnectedAt:  f.now.Format(time.RFC3339Nano),
		LastSeenAt:   f.now.Format(time.RFC3339Nano),
		Capabilities: append([]string(nil), req.Capabilities...),
		PolicyTags:   append([]string(nil), req.PolicyTags...),
	}
	f.entities[entity.ID] = entity
	return daemonrpc.EntityResponse{Entity: entity}, nil
}

func (f *fakeDaemon) HeartbeatEntity(_ context.Context, req daemonrpc.HeartbeatEntityRequest) (daemonrpc.EntityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatRequests = append(f.heartbeatRequests, req)
	entity, ok := f.entities[req.ID]
	if !ok {
		return daemonrpc.EntityResponse{}, errors.New("entity is not attached")
	}
	if req.Operation != nil {
		entity.Operation = *req.Operation
	}
	if req.ActiveChain != nil {
		entity.ActiveChain = *req.ActiveChain
	}
	f.now = f.now.Add(time.Second)
	entity.LastSeenAt = f.now.Format(time.RFC3339Nano)
	f.entities[entity.ID] = entity
	return daemonrpc.EntityResponse{Entity: entity}, nil
}

func (f *fakeDaemon) DetachEntity(_ context.Context, req daemonrpc.DetachEntityRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachedIDs = append(f.detachedIDs, req.ID)
	delete(f.entities, req.ID)
	return nil
}

func (f *fakeDaemon) ListEntities(_ context.Context, req daemonrpc.ListEntitiesRequest) (daemonrpc.ListEntitiesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listRequests = append(f.listRequests, req)
	out := make([]daemonrpc.OperatorEntity, 0, len(f.entities))
	for _, entity := range f.entities {
		if req.Operation != "" && entity.Operation != req.Operation {
			continue
		}
		out = append(out, entity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return daemonrpc.ListEntitiesResponse{Entities: out}, nil
}

func (f *fakeDaemon) Snapshot(_ context.Context, req daemonrpc.SnapshotRequest) (daemonrpc.SnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshotRequests = append(f.snapshotRequests, req)
	return f.snapshot, nil
}

func (f *fakeDaemon) Close() error { return nil }
