package commandmode

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestThrowMockExploitJSONCrossesDaemonRPC(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := testsupport.TempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           12345,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			IDs:           &sequenceIDs{values: []string{"run-1", "event-1", "event-2", "event-3", "event-4", "event-5"}},
			Clock:         fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()

	store := filesystem.NewWorkspaceStore()
	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit", "--target", "mock://target", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Chain   string   `json:"chain"`
		Targets []string `json:"targets"`
		Results []struct {
			RunID     string `json:"runId"`
			ModuleID  string `json:"moduleId"`
			Target    string `json:"target"`
			State     string `json:"state"`
			Summary   string `json:"summary"`
			Findings  []any  `json:"findings"`
			Artifacts []any  `json:"artifacts"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.Chain != "mock-exploit" {
		t.Fatalf("chain = %q, want mock-exploit", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("targets = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 {
		t.Fatalf("result count = %d, want 1", len(payload.Results))
	}
	result := payload.Results[0]
	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("module id = %q, want mock-exploit@v0.0.0-example", result.ModuleID)
	}
	if result.Target != "mock://target" {
		t.Fatalf("target = %q, want mock://target", result.Target)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
}

func TestThrowBrokenPythonModuleJSONRecordsFailedRun(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixture(
		t,
		"broken",
		`import sys; sys.stdout.write("not a frame\n"); sys.stdout.flush()`,
	))
	events := &eventRecorder{}
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Events:    events,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "broken", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Plan struct {
			ID         string   `json:"id"`
			ApprovalID string   `json:"approvalId"`
			Chain      string   `json:"chain"`
			Targets    []string `json:"targets"`
			Decision   string   `json:"decision"`
		} `json:"plan"`
		Chain   string   `json:"chain"`
		Targets []string `json:"targets"`
		Results []struct {
			RunID    string `json:"runId"`
			ModuleID string `json:"moduleId"`
			Target   string `json:"target"`
			State    string `json:"state"`
			Summary  string `json:"summary"`
			Logs     []struct {
				Level   string            `json:"level"`
				Source  string            `json:"source"`
				Message string            `json:"message"`
				Fields  map[string]string `json:"fields"`
			} `json:"logs"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.Chain != "broken" {
		t.Fatalf("chain = %q, want broken", payload.Chain)
	}
	if len(payload.Results) != 1 {
		t.Fatalf("result count = %d, want 1", len(payload.Results))
	}
	result := payload.Results[0]
	if result.RunID != "run-1" || result.ModuleID != "broken" || result.Target != "mock://target" || result.State != "failed" {
		t.Fatalf("result = %#v", result)
	}
	if result.Summary != "module failed during startup" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Logs) != 1 || result.Logs[0].Level != "error" || result.Logs[0].Source != "host" {
		t.Fatalf("logs = %#v", result.Logs)
	}
	detail := result.Logs[0].Fields["error"]
	if !strings.Contains(detail, "module handshake failed") || !strings.Contains(detail, "malformed frame") {
		t.Fatalf("log detail = %q", detail)
	}
	data, err := os.ReadFile(filepath.Join(fixture.WorkspacePath, "runs", payload.Plan.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan commands.ThrowPlanRecord
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.ID != payload.Plan.ID || plan.ApprovalID != payload.Plan.ApprovalID || plan.Chain != "broken" || plan.Workspace != fixture.WorkspacePath {
		t.Fatalf("persisted plan = %#v, payload plan = %#v", plan, payload.Plan)
	}
	if !hasEvent(events.events, "run.failed") {
		t.Fatalf("events = %#v, want run.failed", events.events)
	}
}

func TestThrowMissingModuleConfigReturnsCommandError(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "missing-modules.json")
	t.Setenv("HOVEL_MODULE_CONFIG", missingConfig)
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{values: []string{"run-1", "event-1"}},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "missing", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no JSON payload", stdout.String())
	}
	if !strings.Contains(stderr.String(), missingConfig) {
		t.Fatalf("stderr = %q, want missing module config path", stderr.String())
	}
}
