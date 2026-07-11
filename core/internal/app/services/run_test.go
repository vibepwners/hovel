package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/mesh"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

func TestRunServiceExecutesMockExploitAndEmitsEvents(t *testing.T) {
	runner := &fakeModuleRunner{}
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"run-1", "event-1", "event-2"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewRunService(runner, events, ids, clock)

	result, err := service.ExecuteMockExploit(context.Background(), ExecuteMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.ID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.ID)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want %q", result.State, run.StateSucceeded)
	}
	if !runner.called {
		t.Fatal("runner was not called")
	}
	if runner.request.Target != "mock://target" {
		t.Fatalf("runner target = %q, want mock://target", runner.request.Target)
	}
	if len(events.events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events.events))
	}
	if events.events[0].Type.String() != "hovel.run.started" {
		t.Fatalf("first event = %q, want hovel.run.started", events.events[0].Type)
	}
	if events.events[1].Type.String() != "hovel.run.completed" {
		t.Fatalf("second event = %q, want hovel.run.completed", events.events[1].Type)
	}
}

func TestRunServiceValidatesBeforeCallingRunner(t *testing.T) {
	runner := &fakeModuleRunner{}
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"run-1"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewRunService(runner, events, ids, clock)

	_, err := service.ExecuteMockExploit(context.Background(), ExecuteMockExploitRequest{
		ModuleID: "mock-exploit",
	})
	if err == nil {
		t.Fatal("ExecuteMockExploit returned nil error for missing target")
	}
	if runner.called {
		t.Fatal("runner was called after invalid request")
	}
}

func TestRunServiceConvertsRunnerErrorToFailedRun(t *testing.T) {
	runner := &fakeModuleRunner{err: NewModuleExecutionFailure("module failed during startup", errors.New("module handshake failed: malformed frame"))}
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"run-1", "event-1", "event-2"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewRunService(runner, events, ids, clock)

	result, err := service.ExecuteModule(context.Background(), ExecuteModuleRequest{
		ModuleID: "broken",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateFailed {
		t.Fatalf("state = %q, want %q", result.State, run.StateFailed)
	}
	if result.Summary != "module failed during startup" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Logs) != 1 || result.Logs[0].Source != "host" || result.Logs[0].Fields["error"] != "module handshake failed: malformed frame" {
		t.Fatalf("failure logs = %#v", result.Logs)
	}
	if len(events.events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events.events))
	}
	if events.events[1].Type.String() != "hovel.run.failed" || events.events[1].Fields["summary"] != result.Summary {
		t.Fatalf("failed event = %#v", events.events[1])
	}
}

func TestRunServiceReturnsHostRunnerError(t *testing.T) {
	runnerErr := errors.New("could not locate sdk/python")
	runner := &fakeModuleRunner{err: runnerErr}
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"run-1", "event-1"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewRunService(runner, events, ids, clock)

	_, err := service.ExecuteModule(context.Background(), ExecuteModuleRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if !errors.Is(err, runnerErr) {
		t.Fatalf("error = %v, want %v", err, runnerErr)
	}
	if len(events.events) != 1 || events.events[0].Type.String() != "hovel.run.started" {
		t.Fatalf("events = %#v, want only hovel.run.started", events.events)
	}
}

func TestRunServiceNormalizesMeshStreamSessionID(t *testing.T) {
	runner := &fakeMeshServiceRunner{session: run.SessionRef{ID: "  mesh-session-1  "}}
	service := NewRunService(runner, nil, nil, nil)

	session, err := service.OpenMeshStream(context.Background(), "mesh-provider", mesh.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "mesh-session-1" {
		t.Fatalf("session id = %q, want normalized id", session.ID)
	}
}

func TestRunServiceRejectsMeshStreamWithoutSessionID(t *testing.T) {
	service := NewRunService(&fakeMeshServiceRunner{}, nil, nil, nil)

	_, err := service.OpenMeshStream(context.Background(), "mesh-provider", mesh.StreamRequest{})
	if err == nil || err.Error() != "mesh stream session id is required" {
		t.Fatalf("OpenMeshStream error = %v, want missing session id", err)
	}
}

func TestRunServiceNormalizesMeshTaskStatus(t *testing.T) {
	tests := []struct {
		name   string
		status mesh.TaskStatus
		want   mesh.TaskStatus
	}{
		{name: "blank defaults to success", status: "   ", want: mesh.TaskStatusSucceeded},
		{name: "custom status is trimmed", status: "  partial  ", want: "partial"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeMeshServiceRunner{result: mesh.TaskResult{Status: test.status}}
			service := NewRunService(runner, nil, nil, nil)

			result, err := service.RunMeshTask(context.Background(), "mesh-provider", mesh.TaskRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.want {
				t.Fatalf("status = %q, want %q", result.Status, test.want)
			}
		})
	}
}

func TestRunServiceStartsMeshListenerWithStableID(t *testing.T) {
	runner := &fakeMeshServiceRunner{
		listener: mesh.Listener{ID: "  listener-web  ", State: mesh.ListenerStateActive},
	}
	service := NewRunService(runner, nil, nil, nil)
	config := map[string]any{
		"auth": map[string]any{"token": "write-only-secret"},
	}

	listener, err := service.StartMeshListener(context.Background(), "mesh-provider", mesh.ListenerStartRequest{
		ListenerID: "  listener-web  ",
		Config:     config,
	})
	if err != nil {
		t.Fatal(err)
	}
	if listener.ID != "listener-web" {
		t.Fatalf("listener id = %q, want normalized stable id", listener.ID)
	}
	if runner.startListenerRequest.ListenerID != "listener-web" {
		t.Fatalf("provider listener id = %q, want normalized stable id", runner.startListenerRequest.ListenerID)
	}
	runner.startListenerRequest.Config["auth"].(map[string]any)["token"] = "mutated"
	if got := config["auth"].(map[string]any)["token"]; got != "write-only-secret" {
		t.Fatalf("caller listener config was mutated through provider request: %q", got)
	}
}

func TestRunServiceKeepsMeshListenerSupportOptional(t *testing.T) {
	base := &fakeMeshServiceRunner{}
	service := NewRunService(meshRunnerWithoutListeners{
		ModuleRunner: base,
		MeshRunner:   base,
	}, nil, nil, nil)

	if _, err := service.DescribeMesh(t.Context(), "mesh-provider", mesh.DescribeRequest{}); err != nil {
		t.Fatalf("DescribeMesh with core Mesh runner: %v", err)
	}
	if _, err := service.ListMeshListeners(t.Context(), "mesh-provider", mesh.ListenerListRequest{}); err == nil ||
		err.Error() != "mesh listener listing is not configured" {
		t.Fatalf("ListMeshListeners error = %v", err)
	}
	if _, err := service.StartMeshListener(t.Context(), "mesh-provider", mesh.ListenerStartRequest{
		ListenerID: "listener-web",
	}); err == nil || err.Error() != "mesh listener lifecycle is not configured" {
		t.Fatalf("StartMeshListener error = %v", err)
	}
}

func TestRunServiceNormalizesMeshListenerFilters(t *testing.T) {
	runner := &fakeMeshServiceRunner{}
	service := NewRunService(runner, nil, nil, nil)

	_, err := service.ListMeshListeners(context.Background(), "mesh-provider", mesh.ListenerListRequest{
		ListenerID: "  listener-web  ",
		State:      "  active  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.listListenerRequest.ListenerID != "listener-web" {
		t.Fatalf("provider listener filter = %q, want normalized id", runner.listListenerRequest.ListenerID)
	}
	if runner.listListenerRequest.State != mesh.ListenerStateActive {
		t.Fatalf("provider listener state = %q, want normalized state", runner.listListenerRequest.State)
	}
}

func TestRunServiceDefensivelyCopiesMeshListeners(t *testing.T) {
	runner := &fakeMeshServiceRunner{listeners: []mesh.Listener{{
		ID:        "listener-web",
		Addresses: []string{"https://127.0.0.1:8443"},
		Labels: map[string]any{
			"routing": map[string]any{"region": "west"},
		},
	}}}
	service := NewRunService(runner, nil, nil, nil)

	listeners, err := service.ListMeshListeners(context.Background(), "mesh-provider", mesh.ListenerListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	listeners[0].ID = "mutated"
	listeners[0].Addresses[0] = "mutated"
	listeners[0].Labels["routing"].(map[string]any)["region"] = "mutated"

	original := runner.listeners[0]
	if original.ID != "listener-web" || original.Addresses[0] != "https://127.0.0.1:8443" {
		t.Fatalf("provider listener was mutated through service result: %#v", original)
	}
	if got := original.Labels["routing"].(map[string]any)["region"]; got != "west" {
		t.Fatalf("provider listener labels were mutated through service result: %q", got)
	}
}

func TestRunServiceRejectsInvalidMeshListenerResults(t *testing.T) {
	t.Run("missing list id", func(t *testing.T) {
		service := NewRunService(&fakeMeshServiceRunner{
			listeners: []mesh.Listener{{State: mesh.ListenerStateActive}},
		}, nil, nil, nil)
		_, err := service.ListMeshListeners(context.Background(), "mesh-provider", mesh.ListenerListRequest{})
		if err == nil || err.Error() != "mesh listener result id is required" {
			t.Fatalf("ListMeshListeners error = %v", err)
		}
	})

	t.Run("duplicate list id", func(t *testing.T) {
		service := NewRunService(&fakeMeshServiceRunner{
			listeners: []mesh.Listener{{ID: "listener-1"}, {ID: " listener-1 "}},
		}, nil, nil, nil)
		_, err := service.ListMeshListeners(context.Background(), "mesh-provider", mesh.ListenerListRequest{})
		if err == nil || err.Error() != `mesh listener id "listener-1" is duplicated` {
			t.Fatalf("ListMeshListeners error = %v", err)
		}
	})

	t.Run("mismatched lifecycle id", func(t *testing.T) {
		service := NewRunService(&fakeMeshServiceRunner{
			listener: mesh.Listener{ID: "listener-other"},
		}, nil, nil, nil)
		_, err := service.StartMeshListener(context.Background(), "mesh-provider", mesh.ListenerStartRequest{
			ListenerID: "listener-requested",
		})
		if err == nil || err.Error() != `mesh listener result id "listener-other" does not match requested id "listener-requested"` {
			t.Fatalf("StartMeshListener error = %v", err)
		}
	})

	for _, test := range []struct {
		name    string
		request mesh.ListenerStartRequest
		want    string
	}{
		{
			name:    "unsupported request deployment",
			request: mesh.ListenerStartRequest{ListenerID: "listener-1", Deployment: "sidecar"},
			want:    `mesh listener deployment "sidecar" is unsupported`,
		},
		{
			name:    "unsupported request management",
			request: mesh.ListenerStartRequest{ListenerID: "listener-1", Management: "daemon"},
			want:    `mesh listener management "daemon" is unsupported`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeMeshServiceRunner{listener: mesh.Listener{ID: "listener-1"}}
			service := NewRunService(runner, nil, nil, nil)
			_, err := service.StartMeshListener(context.Background(), "mesh-provider", test.request)
			if err == nil || err.Error() != test.want {
				t.Fatalf("StartMeshListener error = %v, want %q", err, test.want)
			}
			if runner.startListenerRequest.ListenerID != "" {
				t.Fatal("provider was called with an invalid listener request")
			}
		})
	}

	t.Run("unsupported result deployment", func(t *testing.T) {
		service := NewRunService(&fakeMeshServiceRunner{
			listeners: []mesh.Listener{{ID: "listener-1", Deployment: "sidecar"}},
		}, nil, nil, nil)
		_, err := service.ListMeshListeners(context.Background(), "mesh-provider", mesh.ListenerListRequest{})
		if err == nil || err.Error() != `mesh listener deployment "sidecar" is unsupported` {
			t.Fatalf("ListMeshListeners error = %v", err)
		}
	})
}

type fakeModuleRunner struct {
	called  bool
	request run.Request
	err     error
}

type fakeMeshServiceRunner struct {
	session              run.SessionRef
	result               mesh.TaskResult
	listener             mesh.Listener
	listeners            []mesh.Listener
	listListenerRequest  mesh.ListenerListRequest
	startListenerRequest mesh.ListenerStartRequest
}

type meshRunnerWithoutListeners struct {
	ModuleRunner
	MeshRunner
}

func (r *fakeMeshServiceRunner) Run(context.Context, run.Request) (run.Result, error) {
	return run.Result{}, nil
}

func (r *fakeMeshServiceRunner) DescribeMesh(context.Context, string, mesh.DescribeRequest) (mesh.Descriptor, error) {
	return mesh.Descriptor{}, nil
}

func (r *fakeMeshServiceRunner) MeshTopology(context.Context, string, mesh.TopologyRequest) (mesh.Topology, error) {
	return mesh.Topology{}, nil
}

func (r *fakeMeshServiceRunner) ListMeshBeacons(context.Context, string, mesh.BeaconRequest) ([]mesh.Beacon, error) {
	return nil, nil
}

func (r *fakeMeshServiceRunner) ListMeshListeners(
	_ context.Context,
	_ string,
	request mesh.ListenerListRequest,
) ([]mesh.Listener, error) {
	r.listListenerRequest = request
	return r.listeners, nil
}

func (r *fakeMeshServiceRunner) StartMeshListener(
	_ context.Context,
	_ string,
	request mesh.ListenerStartRequest,
) (mesh.Listener, error) {
	r.startListenerRequest = request
	return r.listener, nil
}

func (r *fakeMeshServiceRunner) StopMeshListener(context.Context, string, mesh.ListenerStopRequest) (mesh.Listener, error) {
	return r.listener, nil
}

func (r *fakeMeshServiceRunner) RunMeshTask(context.Context, string, mesh.TaskRequest) (mesh.TaskResult, error) {
	return r.result, nil
}

func (r *fakeMeshServiceRunner) OpenMeshStream(context.Context, string, mesh.StreamRequest) (run.SessionRef, error) {
	return r.session, nil
}

func (r *fakeModuleRunner) Run(_ context.Context, request run.Request) (run.Result, error) {
	r.called = true
	r.request = request
	if r.err != nil {
		return run.Result{}, r.err
	}
	return run.Succeeded(request, run.ResultArgs{
		Summary: "mock exploit completed",
	})
}
