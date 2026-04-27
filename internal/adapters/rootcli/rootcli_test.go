package rootcli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestCommandRoleDelegatesToCommandAdapter(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"command", "control", "init", "--workspace", t.TempDir(), "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Created bool `json:"created"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
}

func TestCLIRoleRejectsOneShotCommandArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"cli", "throw", "--chain", "mock-exploit"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "hovel command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRootHelpShowsRoleMenu(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel", "command", "cli", "daemon", "tui"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestDaemonServeHelpShowsOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"daemon", "serve", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"daemon serve", "--workspace", "--socket"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestTUIRoleIsExplicitlyUnimplemented(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"tui"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMonoBinaryDaemonAndCommandRunMockExploitFlow(t *testing.T) {
	workspacePath := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	daemonCodes := make(chan int, 1)
	var daemonStdout, daemonStderr bytes.Buffer

	go func() {
		daemonCodes <- Run(ctx, []string{"daemon", "serve", "--workspace", workspacePath}, &daemonStdout, &daemonStderr)
	}()
	defer func() {
		cancel()
		if code := <-daemonCodes; code != 0 {
			t.Fatalf("daemon exit code = %d, stderr = %s", code, daemonStderr.String())
		}
	}()

	store := filesystem.NewWorkspaceStore()
	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"command", "throw", "--chain", "mock-exploit", "--target", "mock://target", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Chain   string `json:"chain"`
		Results []struct {
			RunID     string `json:"runId"`
			ModuleID  string `json:"moduleId"`
			Target    string `json:"target"`
			State     string `json:"state"`
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
	if len(payload.Results) != 1 {
		t.Fatalf("result count = %d, want 1", len(payload.Results))
	}
	result := payload.Results[0]
	if result.RunID == "" {
		t.Fatal("run id is empty")
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
