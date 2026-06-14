package rootcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMonoBinaryDaemonAndCommandRunMockExploitFlow(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
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
	testsupport.WaitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"command", "throw", "--chain", "mock-exploit", "--target", "mock://target", "--workspace", workspacePath, "--now", "--json"}, &stdout, &stderr)
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

func TestRunCommandUsesDaemonSessionContextForThrow(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{})
	ctx := context.Background()
	run := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		full := append([]string{"run", "--workspace", fixture.WorkspacePath, "--op", "o1", "--chain", "mock"}, args...)
		code := Run(ctx, full, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("hovel %s exit code = %d, stderr = %s", strings.Join(full, " "), code, stderr.String())
		}
		return stdout.String()
	}

	run("chain", "add", "mock-exploit@v0.0.0-example")
	run("chain", "config", "set", "operator.confirmed_lab", "true")
	run("target", "add", "mock://target")
	run("target", "config", "set", "mock://target", "target.host", "mock.local")
	run("target", "config", "set", "mock://target", "target.port", "22")
	output := run("throw", "--now", "--json")

	var payload struct {
		Chain   string   `json:"chain"`
		Targets []string `json:"targets"`
		Results []struct {
			ModuleID string `json:"moduleId"`
			Target   string `json:"target"`
			State    string `json:"state"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", output, err)
	}
	if payload.Chain != "mock" {
		t.Fatalf("chain = %q, want mock", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("targets = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 || payload.Results[0].ModuleID != "mock-exploit@v0.0.0-example" || payload.Results[0].State != "succeeded" {
		t.Fatalf("results = %#v", payload.Results)
	}
}

func TestRunCommandPersistsSquatterAsModuleWithTypeConfig(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{})
	ctx := context.Background()
	run := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		full := append([]string{"run", "--workspace", fixture.WorkspacePath, "--op", "o1", "--chain", "etro"}, args...)
		code := Run(ctx, full, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("hovel %s exit code = %d, stderr = %s", strings.Join(full, " "), code, stderr.String())
		}
		return stdout.String()
	}

	run("add", "etro-survey@v0.1.0")
	run("add", "etro-exploit@v1.0.0")
	run("add", "squatter@v0.1.0")
	output := run("chain", "inspect")

	for _, want := range []string{"etro-survey@v0.1.0", "etro-exploit@v1.0.0", "squatter@v0.1.0"} {
		if !strings.Contains(output, want) {
			t.Fatalf("chain inspect missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "squatter.bind") {
		t.Fatalf("chain inspect contains legacy Squatter step:\n%s", output)
	}

	configOutput := run("chain", "config", "list")
	if !strings.Contains(configOutput, "squatter.type") || !strings.Contains(configOutput, "tcp-bind") {
		t.Fatalf("chain config list missing Squatter type config:\n%s", configOutput)
	}
}

func TestDaemonServeStopsOnContextCancellationAndClearsWorkspaceState(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	codes := make(chan int, 1)
	var stdout, stderr bytes.Buffer

	go func() {
		codes <- Run(ctx, []string{"daemon", "serve", "--workspace", workspacePath}, &stdout, &stderr)
	}()

	store := filesystem.NewWorkspaceStore()
	testsupport.WaitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	cancel()
	select {
	case code := <-codes:
		if code != 0 {
			t.Fatalf("daemon exit code = %d, stderr = %s", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop after context cancellation")
	}
	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("daemon state = %s, want not_running", status.State)
	}
	if _, err := os.Stat(workspacePath + "/hoveld.sock"); !os.IsNotExist(err) {
		t.Fatalf("socket still exists or stat failed unexpectedly: %v", err)
	}
}
