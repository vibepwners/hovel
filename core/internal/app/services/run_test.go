package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
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

func TestRunServiceRequiresExplicitTerminalMeshTaskStatus(t *testing.T) {
	tests := []struct {
		name   string
		status mesh.TaskStatus
		want   mesh.TaskStatus
		err    string
	}{
		{name: "success is accepted", status: "  succeeded  ", want: mesh.TaskStatusSucceeded},
		{name: "failure is accepted", status: "  failed  ", want: mesh.TaskStatusFailed},
		{name: "blank is rejected", status: "   ", err: "task status"},
		{name: "provider-defined status is rejected", status: "  partial  ", err: "not supported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeMeshServiceRunner{result: mesh.TaskResult{Status: test.status}}
			service := NewRunService(runner, nil, nil, nil)

			result, err := service.RunMeshTask(
				context.Background(),
				"mesh-provider",
				mesh.TaskRequest{Kind: mesh.TaskSurvey},
			)
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("RunMeshTask error = %v, want %q", err, test.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.want {
				t.Fatalf("status = %q, want %q", result.Status, test.want)
			}
		})
	}
}

func TestRunServiceValidatesMeshContractsAtProviderBoundary(t *testing.T) {
	t.Parallel()

	t.Run("descriptor", func(t *testing.T) {
		t.Parallel()

		service := NewRunService(&fakeMeshServiceRunner{descriptor: mesh.Descriptor{
			Tasks: []mesh.TaskSpec{{Kind: mesh.TaskSurvey}, {Kind: mesh.TaskSurvey}},
		}}, nil, nil, nil)
		_, err := service.DescribeMesh(t.Context(), "mesh-provider", mesh.DescribeRequest{})
		if err == nil || !strings.Contains(err.Error(), "duplicated") {
			t.Fatalf("DescribeMesh error = %v, want duplicate task rejection", err)
		}
	})

	t.Run("topology", func(t *testing.T) {
		t.Parallel()

		service := NewRunService(&fakeMeshServiceRunner{topology: mesh.Topology{
			Nodes: []mesh.Node{{ID: "node-1", ParentID: "missing"}},
		}}, nil, nil, nil)
		_, err := service.MeshTopology(t.Context(), "mesh-provider", mesh.TopologyRequest{})
		if err == nil || !strings.Contains(err.Error(), "missing parent") {
			t.Fatalf("MeshTopology error = %v, want missing parent rejection", err)
		}
	})

	t.Run("beacons", func(t *testing.T) {
		t.Parallel()

		service := NewRunService(&fakeMeshServiceRunner{beacons: []mesh.Beacon{
			{ID: "beacon-1", NodeID: "node-1"},
			{ID: "beacon-1", NodeID: "node-2"},
		}}, nil, nil, nil)
		_, err := service.ListMeshBeacons(t.Context(), "mesh-provider", mesh.BeaconRequest{})
		if err == nil || !strings.Contains(err.Error(), "duplicated") {
			t.Fatalf("ListMeshBeacons error = %v, want duplicate beacon rejection", err)
		}
	})

	t.Run("task request", func(t *testing.T) {
		t.Parallel()

		runner := &fakeMeshServiceRunner{}
		service := NewRunService(runner, nil, nil, nil)
		_, err := service.RunMeshTask(t.Context(), "mesh-provider", mesh.TaskRequest{})
		if err == nil || !strings.Contains(err.Error(), "task kind") {
			t.Fatalf("RunMeshTask error = %v, want missing kind rejection", err)
		}
		if runner.taskRequest.Kind != "" {
			t.Fatalf("invalid task reached provider: %#v", runner.taskRequest)
		}
	})

	t.Run("task result", func(t *testing.T) {
		t.Parallel()

		service := NewRunService(&fakeMeshServiceRunner{result: mesh.TaskResult{
			Status:  mesh.TaskStatusSucceeded,
			Beacons: []mesh.Beacon{{NodeID: "node-1"}},
		}}, nil, nil, nil)
		_, err := service.RunMeshTask(
			t.Context(),
			"mesh-provider",
			mesh.TaskRequest{Kind: mesh.TaskSurvey},
		)
		if err == nil || !strings.Contains(err.Error(), "beacon id") {
			t.Fatalf("RunMeshTask error = %v, want invalid result rejection", err)
		}
	})

	t.Run("stream request", func(t *testing.T) {
		t.Parallel()

		runner := &fakeMeshServiceRunner{}
		service := NewRunService(runner, nil, nil, nil)
		_, err := service.OpenMeshStream(t.Context(), "mesh-provider", mesh.StreamRequest{
			DestinationPort: mesh.MaximumNetworkPort + 1,
		})
		if err == nil || !strings.Contains(err.Error(), "destination port") {
			t.Fatalf("OpenMeshStream error = %v, want port rejection", err)
		}
		if runner.streamRequest.DestinationPort != 0 {
			t.Fatalf("invalid stream reached provider: %#v", runner.streamRequest)
		}
	})
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
		ModuleRunner:  base,
		MeshDescriber: base,
	}, nil, nil, nil)

	if _, err := service.DescribeMesh(t.Context(), "mesh-provider", mesh.DescribeRequest{}); err != nil {
		t.Fatalf("DescribeMesh with description-only Mesh runner: %v", err)
	}
	if _, err := service.MeshTopology(t.Context(), "mesh-provider", mesh.TopologyRequest{}); err == nil ||
		err.Error() != "mesh topology is not configured" {
		t.Fatalf("MeshTopology error = %v", err)
	}
	if _, err := service.RunMeshTask(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{Kind: mesh.TaskSurvey},
	); err == nil || err.Error() != "mesh task runner is not configured" {
		t.Fatalf("RunMeshTask error = %v", err)
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

func TestRunServiceResolvesCredentialsForMeshMutations(t *testing.T) {
	t.Parallel()

	descriptor := testCredentialDeliveryDescriptor(t)
	runner := &fakeMeshServiceRunner{
		module: modulecatalog.Module{
			ID:                 "mesh-provider@1.2.3",
			Version:            "1.2.3",
			CredentialDelivery: &descriptor,
		},
		listener: mesh.Listener{ID: "listener-edge"},
		result:   mesh.TaskResult{Status: mesh.TaskStatusSucceeded},
		session:  run.SessionRef{ID: "session-edge"},
	}
	resolver := &fakeCredentialOperationResolver{}
	service := NewRunService(
		runner,
		nil,
		nil,
		nil,
		WithCredentialOperationResolver(resolver),
	)
	selection := domainpki.CredentialSelections{{
		RequestID:    "credential-request-1",
		AssignmentID: "assignment-edge",
		SlotName:     "tls-server",
		Capability:   domainpki.DeliveryCapabilityRuntime,
		Material: domainpki.CredentialMaterialSelection{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
		},
	}}

	if _, err := service.StartMeshListenerWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.ListenerStartRequest{ListenerID: "listener-edge"},
		selection,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-listener"},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RunMeshTaskWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{
			RunID: "run-edge", Kind: mesh.TaskSurvey,
			ListenerID: "listener-edge", NodeID: "node-edge",
			DestinationHost: "10.10.10.20",
		},
		selection,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-task"},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenMeshStreamWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.StreamRequest{
			RunID: "run-edge", ListenerID: "listener-edge", NodeID: "node-edge", Target: "stream-target",
		},
		selection,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-stream"},
	); err != nil {
		t.Fatal(err)
	}

	if resolver.calls != 3 || resolver.closes != 3 {
		t.Fatalf("resolver calls/closes = %d/%d, want 3/3", resolver.calls, resolver.closes)
	}
	if resolver.revalidations != 6 {
		t.Fatalf("resolver revalidations = %d, want 6", resolver.revalidations)
	}
	if runner.credentialCalls != 3 {
		t.Fatalf("credential-aware runner calls = %d, want 3", runner.credentialCalls)
	}
	if runner.credentialModuleID != "mesh-provider@1.2.3" {
		t.Fatalf("credential module id = %q, want exact inspected id", runner.credentialModuleID)
	}
	if resolver.provider.ProviderID != "mesh-provider" ||
		resolver.provider.ProviderVersion != "1.2.3" {
		t.Fatalf("provider target = %#v", resolver.provider)
	}
	if len(resolver.consumers) != 3 ||
		resolver.consumers[0].ID != "mesh-provider" ||
		resolver.consumers[1].ID != "mesh-provider/listener-edge" ||
		resolver.consumers[2].ID != "mesh-provider/node-edge" {
		t.Fatalf("operation consumers = %#v", resolver.consumers)
	}
	if resolver.scope.OperationID != "mesh-operation-stream" ||
		resolver.scope.RunID != "run-edge" || resolver.scope.NodeID != "node-edge" ||
		resolver.scope.Target != "stream-target" {
		t.Fatalf("resolved operation scope = %#v", resolver.scope)
	}
	if len(resolver.scopes) != 3 || resolver.scopes[0].Target != "" ||
		resolver.scopes[1].Target != "10.10.10.20" || resolver.scopes[2].Target != "stream-target" {
		t.Fatalf("resolved operation targets = %#v", resolver.scopes)
	}
}

func TestMeshCredentialTargetUsesSDKPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		target          string
		destinationHost string
		nodeID          string
		want            string
	}{
		{name: "explicit target", target: "route-edge", destinationHost: "10.10.10.20", nodeID: "node-edge", want: "route-edge"},
		{name: "destination fallback", destinationHost: "10.10.10.20", nodeID: "node-edge", want: "10.10.10.20"},
		{name: "node fallback", nodeID: "node-edge", want: "node-edge"},
		{name: "empty", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := meshCredentialTarget(test.target, test.destinationHost, test.nodeID); got != test.want {
				t.Fatalf("meshCredentialTarget() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunServiceRejectsCredentialSelectionsWithoutResolver(t *testing.T) {
	t.Parallel()

	runner := &fakeMeshServiceRunner{}
	service := NewRunService(runner, nil, nil, nil)
	_, err := service.RunMeshTaskWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{Kind: mesh.TaskSurvey},
		domainpki.CredentialSelections{{
			RequestID: "credential-request-1", AssignmentID: "assignment-edge",
			SlotName: "tls-server", Capability: domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		}},
		domainpki.CredentialOperationScope{},
	)
	if err == nil || err.Error() != "credential operation resolver is not configured" {
		t.Fatalf("RunMeshTaskWithCredentialSelections() error = %v", err)
	}
}

func TestRunServiceRejectsCredentialOperationMutationBeforeDelivery(t *testing.T) {
	t.Parallel()

	descriptor := testCredentialDeliveryDescriptor(t)
	runner := &fakeMeshServiceRunner{
		module: modulecatalog.Module{
			ID:                 "mesh-provider@1.2.3",
			Version:            "1.2.3",
			CredentialDelivery: &descriptor,
		},
		result: mesh.TaskResult{Status: mesh.TaskStatusSucceeded},
	}
	resolver := &fakeCredentialOperationResolver{rejectRevalidation: 2}
	service := NewRunService(
		runner,
		nil,
		nil,
		nil,
		WithCredentialOperationResolver(resolver),
	)

	_, err := service.RunMeshTaskWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{Kind: mesh.TaskSurvey},
		testCredentialSelections(),
		domainpki.CredentialOperationScope{},
	)
	if err == nil || err.Error() != "credential assignment changed before delivery" {
		t.Fatalf("RunMeshTaskWithCredentialSelections() error = %v", err)
	}
	if resolver.revalidations != 2 || resolver.closes != 1 {
		t.Fatalf(
			"resolver revalidations/closes = %d/%d, want 2/1",
			resolver.revalidations,
			resolver.closes,
		)
	}
}

func TestRunServiceRejectsNilCredentialOperationResolution(t *testing.T) {
	t.Parallel()

	descriptor := testCredentialDeliveryDescriptor(t)
	runner := &fakeMeshServiceRunner{module: modulecatalog.Module{
		ID:                 "mesh-provider@1.2.3",
		Version:            "1.2.3",
		CredentialDelivery: &descriptor,
	}}
	resolver := &fakeCredentialOperationResolver{returnNil: true}
	service := NewRunService(
		runner,
		nil,
		nil,
		nil,
		WithCredentialOperationResolver(resolver),
	)

	_, err := service.RunMeshTaskWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{Kind: mesh.TaskSurvey},
		testCredentialSelections(),
		domainpki.CredentialOperationScope{},
	)
	if err == nil || err.Error() != "credential operation resolver returned no resolution" {
		t.Fatalf("RunMeshTaskWithCredentialSelections() error = %v", err)
	}
}

func TestRunServiceRejectsInvalidCredentialOperationResolution(t *testing.T) {
	t.Parallel()

	descriptor := testCredentialDeliveryDescriptor(t)
	runner := &fakeMeshServiceRunner{module: modulecatalog.Module{
		ID:                 "mesh-provider@1.2.3",
		Version:            "1.2.3",
		CredentialDelivery: &descriptor,
	}}
	resolver := &fakeCredentialOperationResolver{returnEmpty: true}
	service := NewRunService(
		runner,
		nil,
		nil,
		nil,
		WithCredentialOperationResolver(resolver),
	)

	_, err := service.RunMeshTaskWithCredentialSelections(
		t.Context(),
		"mesh-provider",
		mesh.TaskRequest{Kind: mesh.TaskSurvey},
		testCredentialSelections(),
		domainpki.CredentialOperationScope{},
	)
	if err == nil || err.Error() !=
		"credential operation resolver returned 0 deliveries for 1 selections" {
		t.Fatalf("RunMeshTaskWithCredentialSelections() error = %v", err)
	}
	if resolver.closes != 1 {
		t.Fatalf("invalid credential resolution closes = %d, want 1", resolver.closes)
	}
}

func TestCredentialOperationResolutionRejectsTypedNilLease(t *testing.T) {
	t.Parallel()

	var lease *fakeCredentialOperationLease
	resolution, err := NewCredentialOperationResolution(lease)
	if resolution != nil || err == nil {
		t.Fatalf(
			"NewCredentialOperationResolution() = (%#v, %v), want nil resolution and error",
			resolution,
			err,
		)
	}
}

type fakeModuleRunner struct {
	called  bool
	request run.Request
	err     error
}

type fakeMeshServiceRunner struct {
	session              run.SessionRef
	result               mesh.TaskResult
	descriptor           mesh.Descriptor
	topology             mesh.Topology
	beacons              []mesh.Beacon
	describeRequest      mesh.DescribeRequest
	topologyRequest      mesh.TopologyRequest
	beaconRequest        mesh.BeaconRequest
	taskRequest          mesh.TaskRequest
	streamRequest        mesh.StreamRequest
	listener             mesh.Listener
	listeners            []mesh.Listener
	listListenerRequest  mesh.ListenerListRequest
	startListenerRequest mesh.ListenerStartRequest
	module               modulecatalog.Module
	credentialCalls      int
	credentialModuleID   string
}

type fakeCredentialOperationResolver struct {
	calls              int
	closes             int
	revalidations      int
	rejectRevalidation int
	returnNil          bool
	returnEmpty        bool
	provider           domainpki.CredentialProviderTarget
	scope              domainpki.CredentialOperationScope
	scopes             []domainpki.CredentialOperationScope
	consumers          []domainpki.CredentialConsumerBinding
}

type fakeCredentialOperationLease struct {
	resolver   *fakeCredentialOperationResolver
	deliveries domainpki.CredentialOperationDeliveries
	isClosed   bool
}

type meshRunnerWithoutListeners struct {
	ModuleRunner
	MeshDescriber
}

func (r *fakeMeshServiceRunner) Run(context.Context, run.Request) (run.Result, error) {
	return run.Result{}, nil
}

func (r *fakeMeshServiceRunner) DescribeMesh(
	_ context.Context,
	_ string,
	request mesh.DescribeRequest,
) (mesh.Descriptor, error) {
	r.describeRequest = request
	return r.descriptor, nil
}

func (r *fakeMeshServiceRunner) MeshTopology(
	_ context.Context,
	_ string,
	request mesh.TopologyRequest,
) (mesh.Topology, error) {
	r.topologyRequest = request
	return r.topology, nil
}

func (r *fakeMeshServiceRunner) ListMeshBeacons(
	_ context.Context,
	_ string,
	request mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	r.beaconRequest = request
	return r.beacons, nil
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

func (r *fakeMeshServiceRunner) RunMeshTask(
	_ context.Context,
	_ string,
	request mesh.TaskRequest,
) (mesh.TaskResult, error) {
	r.taskRequest = request
	return r.result, nil
}

func (r *fakeMeshServiceRunner) OpenMeshStream(
	_ context.Context,
	_ string,
	request mesh.StreamRequest,
) (run.SessionRef, error) {
	r.streamRequest = request
	return r.session, nil
}

func (r *fakeMeshServiceRunner) Inspect(context.Context, string) (modulecatalog.Module, error) {
	return r.module, nil
}

func (r *fakeMeshServiceRunner) StartMeshListenerWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *CredentialOperationResolution,
	request mesh.ListenerStartRequest,
) (MeshListenerExecution, error) {
	if err := validateFakeCredentialResolution(ctx, resolution); err != nil {
		return MeshListenerExecution{}, err
	}
	r.credentialCalls++
	r.credentialModuleID = moduleID
	r.startListenerRequest = request
	return MeshListenerExecution{Listener: r.listener}, nil
}

func (r *fakeMeshServiceRunner) RunMeshTaskWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *CredentialOperationResolution,
	_ mesh.TaskRequest,
) (MeshTaskExecution, error) {
	if err := validateFakeCredentialResolution(ctx, resolution); err != nil {
		return MeshTaskExecution{}, err
	}
	r.credentialCalls++
	r.credentialModuleID = moduleID
	return MeshTaskExecution{Result: r.result}, nil
}

func (r *fakeMeshServiceRunner) OpenMeshStreamWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *CredentialOperationResolution,
	_ mesh.StreamRequest,
) (MeshStreamExecution, error) {
	if err := validateFakeCredentialResolution(ctx, resolution); err != nil {
		return MeshStreamExecution{}, err
	}
	r.credentialCalls++
	r.credentialModuleID = moduleID
	return MeshStreamExecution{Session: r.session}, nil
}

func (r *fakeCredentialOperationResolver) ResolveCredentialOperation(
	_ context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) (*CredentialOperationResolution, error) {
	r.calls++
	r.provider = provider
	r.scope = scope
	r.scopes = append(r.scopes, scope)
	r.consumers = append([]domainpki.CredentialConsumerBinding(nil), consumers...)
	if r.returnNil {
		return nil, nil
	}
	lease := &fakeCredentialOperationLease{
		resolver:   r,
		deliveries: fakeCredentialDeliveries(provider, descriptor, selections, scope),
	}
	if r.returnEmpty {
		lease.deliveries = domainpki.CredentialOperationDeliveries{}
	}
	return NewCredentialOperationResolution(lease)
}

func (l *fakeCredentialOperationLease) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	if l == nil || l.isClosed {
		return nil, ErrCredentialOperationResolutionClosed
	}
	return l.deliveries, nil
}

func (l *fakeCredentialOperationLease) Revalidate(context.Context) error {
	if l == nil || l.isClosed {
		return ErrCredentialOperationResolutionClosed
	}
	l.resolver.revalidations++
	if l.resolver.rejectRevalidation == l.resolver.revalidations {
		return errors.New("credential assignment changed before delivery")
	}
	return nil
}

func (l *fakeCredentialOperationLease) Close() {
	if l == nil || l.isClosed {
		return
	}
	l.deliveries.Clear()
	l.isClosed = true
	l.resolver.closes++
}

func validateFakeCredentialResolution(
	ctx context.Context,
	resolution *CredentialOperationResolution,
) error {
	if err := resolution.Revalidate(ctx); err != nil {
		return err
	}
	_, err := resolution.BorrowedDeliveries()
	return err
}

func fakeCredentialDeliveries(
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
) domainpki.CredentialOperationDeliveries {
	deliveries := make(domainpki.CredentialOperationDeliveries, 0, len(selections))
	for _, selection := range selections {
		var slot domainpki.CredentialSlot
		for _, candidate := range descriptor.Slots {
			if candidate.Name == selection.SlotName {
				slot = candidate
				break
			}
		}
		data := domainpki.CredentialBytes{1}
		digest := sha256.Sum256(data)
		request := domainpki.CredentialRuntimeRequest{
			SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
			Provider:      provider,
			RequestID:     selection.RequestID,
			AssignmentID:  selection.AssignmentID,
			SlotName:      selection.SlotName,
			Credential: domainpki.ResolvedCredentialMetadata{
				BundleVersion:         slot.AcceptedBundleVersions[0],
				Purpose:               slot.Purpose,
				ConsumerType:          slot.ConsumerType,
				ProfileID:             slot.AcceptedProfiles[0],
				CompatibilityTargetID: slot.AcceptedCompatibilityTargets[0],
			},
			Material: domainpki.ResolvedCredentialMaterial{
				Projection: selection.Material.Projection,
				Form:       selection.Material.Form,
				Encoding:   domainpki.EncodingBase64DER,
				SHA256:     hex.EncodeToString(digest[:]),
				Data:       data,
			},
			Scope: scope,
		}
		deliveries = append(deliveries, domainpki.CredentialOperationDelivery{
			Capability: domainpki.DeliveryCapabilityRuntime,
			Runtime:    &request,
		})
	}
	return deliveries
}

func testCredentialSelections() domainpki.CredentialSelections {
	return domainpki.CredentialSelections{{
		RequestID:    "credential-request-1",
		AssignmentID: "assignment-edge",
		SlotName:     "tls-server",
		Capability:   domainpki.DeliveryCapabilityRuntime,
		Material: domainpki.CredentialMaterialSelection{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
		},
	}}
}

func testCredentialDeliveryDescriptor(t *testing.T) domainpki.CredentialDeliveryDescriptor {
	t.Helper()
	descriptor, err := domainpki.NewCredentialDeliveryDescriptor(
		domainpki.CredentialDeliveryDescriptorArgs{
			SchemaVersion: domainpki.CredentialDeliverySchemaV1,
			Slots: []domainpki.CredentialSlot{{
				Name: "tls-server", Purpose: domainpki.PurposeTLSServer,
				EndpointRole:           domainpki.CredentialEndpointServer,
				ConsumerType:           domainpki.ConsumerMeshListener,
				AcceptedBundleVersions: []string{domainpki.BundleSchemaV1},
				AcceptedProfiles:       []domainpki.ProfileID{domainpki.ProfileTLSServer},
				AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{
					domainpki.CompatibilityPortableX509,
				},
				AcceptedProjections: []domainpki.CredentialProjection{
					domainpki.CredentialProjectionCertificateDER,
				},
				AcceptedMaterialForms: []domainpki.CredentialMaterialForm{
					domainpki.CredentialMaterialPublic,
				},
				MaximumEncodedBytes: 64 * 1024,
				RemainderPolicy:     domainpki.StampRemainderPreserve,
				PrivateMaterial:     domainpki.PrivateMaterialForbidden,
			}},
			Capabilities: []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityRuntime},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
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
