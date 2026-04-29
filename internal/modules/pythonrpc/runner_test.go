package pythonrpc

import (
	"context"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

func TestRunnerExecutesPythonMockModule(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	result, err := Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "example exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(events.events) == 0 || events.events[0].Type.String() != "module.log" {
		t.Fatalf("events = %#v, want module.log", events.events)
	}
}

func TestRunnerInspectsPythonModuleDeclaredSchema(t *testing.T) {
	module, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Inspect(context.Background(), "mock-exploit")
	if err != nil {
		t.Fatal(err)
	}
	if module.RuntimeKind != "python-rpc" {
		t.Fatalf("runtime = %q, want python-rpc", module.RuntimeKind)
	}
	if len(module.ChainConfig) != 1 || module.ChainConfig[0].Key != "operator.confirmed_lab" {
		t.Fatalf("chain config = %#v", module.ChainConfig)
	}
	if len(module.TargetConfig) != 2 || module.TargetConfig[0].Key != "target.host" {
		t.Fatalf("target config = %#v", module.TargetConfig)
	}
}

func TestRunnerLaunchesEveryBuiltInMockModule(t *testing.T) {
	for _, moduleID := range []string{"mock-survey", "mock-exploit"} {
		t.Run(moduleID, func(t *testing.T) {
			request, err := run.NewRequest(run.RequestArgs{
				ID:       "run-1",
				ModuleID: moduleID,
				Target:   "mock://target",
				ChainConfig: map[string]string{
					"delay":        "0s",
					"failure_mode": "execution",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Summary == "" {
				t.Fatal("summary is empty")
			}
		})
	}
}

func TestRunnerMapsFailedPythonResult(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:          "run-1",
		ModuleID:    "mock-exploit",
		Target:      "mock://target",
		ChainConfig: map[string]string{"failure_mode": "execution"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateFailed {
		t.Fatalf("state = %q, want failed", result.State)
	}
}

func TestRunnerCapturesModuleLogs(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-survey",
		Target:   "mock://target",
		TargetConfig: map[string]string{
			"target.host": "target",
			"target.port": "443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	_, err = Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(events.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events.events))
	}
}

func TestRunnerHasNoModulesWithoutConfig(t *testing.T) {
	catalog, err := Runner{}.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if modules := catalog.List(); len(modules) != 0 {
		t.Fatalf("modules = %#v, want none", modules)
	}
}

const exampleModuleConfig = "examples/python/hovel-modules.json"

type eventRecorder struct {
	events []event.Event
}

func (r *eventRecorder) Append(_ context.Context, evt event.Event) error {
	r.events = append(r.events, evt)
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
