package apptest

import (
	"context"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

func TestHarnessConstructsServicesWithoutDaemon(t *testing.T) {
	harness := NewHarness()

	result, err := harness.Workspaces.InitWorkspace(context.Background(), harness.InitWorkspace("lab", ".hovel"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created {
		t.Fatal("Created = false, want true")
	}
	if len(harness.Events.Events) != 1 {
		t.Fatalf("event count = %d, want 1", len(harness.Events.Events))
	}

	status, err := harness.Daemons.Status(context.Background(), harness.DaemonStatus(".hovel"))
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}

	runResult, err := harness.Runs.ExecuteMockExploit(context.Background(), harness.MockExploit("mock-exploit", "mock://target"))
	if err != nil {
		t.Fatal(err)
	}
	if runResult.State != run.StateSucceeded {
		t.Fatalf("run state = %q, want %q", runResult.State, run.StateSucceeded)
	}
}
