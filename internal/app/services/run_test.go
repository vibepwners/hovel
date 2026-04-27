package services

import (
	"context"
	"testing"
	"time"

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
	if events.events[0].Type.String() != "run.started" {
		t.Fatalf("first event = %q, want run.started", events.events[0].Type)
	}
	if events.events[1].Type.String() != "run.succeeded" {
		t.Fatalf("second event = %q, want run.succeeded", events.events[1].Type)
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

type fakeModuleRunner struct {
	called  bool
	request run.Request
}

func (r *fakeModuleRunner) Run(_ context.Context, request run.Request) (run.Result, error) {
	r.called = true
	r.request = request
	return run.Succeeded(request, run.ResultArgs{
		Summary: "mock exploit completed",
	})
}
