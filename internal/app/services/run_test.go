package services

import (
	"context"
	"errors"
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

type fakeModuleRunner struct {
	called  bool
	request run.Request
	err     error
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
