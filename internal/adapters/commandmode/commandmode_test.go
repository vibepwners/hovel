package commandmode

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

func TestHelpShowsCommandMenu(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel command", "control", "chain", "targets", "throw"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestThrowHelpShowsChainTargetAndWorkspace(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"throw", "--chain", "--target", "--workspace", "--json"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "_positionalArg") {
		t.Fatalf("help output leaked generated positional name:\n%s", output)
	}
}

func TestThrowRequiresTargetBeforeDaemonLookup(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit", "--workspace", t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "target is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestInitJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"control", "init", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Created   bool `json:"created"`
		Workspace struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
	if payload.Workspace.ID == "" {
		t.Fatal("workspace ID is empty")
	}
	if payload.Workspace.Path != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.Workspace.Path, workspacePath)
	}
}

func TestDaemonStatusJSONRunning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()
	socketPath := workspacePath + "/hoveld.sock"
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           12345,
		SocketPath:    socketPath,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	code := Run(context.Background(), []string{"control", "daemon", "status", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		State         string `json:"state"`
		WorkspacePath string `json:"workspacePath"`
		PID           int    `json:"pid"`
		SocketPath    string `json:"socketPath"`
		Health        string `json:"health"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.State != "running" {
		t.Fatalf("state = %q, want running", payload.State)
	}
	if payload.WorkspacePath != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.WorkspacePath, workspacePath)
	}
	if payload.PID != 12345 {
		t.Fatalf("pid = %d, want 12345", payload.PID)
	}
	if payload.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", payload.SocketPath, socketPath)
	}
	if payload.Health != "healthy" {
		t.Fatalf("health = %q, want healthy", payload.Health)
	}
}

func TestThrowMockExploitJSONCrossesDaemonRPC(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()
	socketPath := workspacePath + "/hoveld.sock"
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           12345,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			IDs:           &sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
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
	if result.ModuleID != "mock-exploit" {
		t.Fatalf("module id = %q, want mock-exploit", result.ModuleID)
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

func TestHumanOutputRendersOperatorLogWhenPresent(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"log-demo"},
		Summary: "Render log demo",
		Handler: func(context.Context, commands.Invocation) (commands.Result, error) {
			return commands.Result{
				Log: operatorlog.New("HOVEL//RUN", "demo -> target", []operatorlog.Entry{
					operatorlog.Info("run", "module staged"),
					operatorlog.Success("run", "completed"),
				}),
			}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"log-demo"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"HOVEL//RUN", "[*] run", "[+] run"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
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

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before deadline")
}
