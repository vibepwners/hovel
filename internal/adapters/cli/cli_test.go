package cli

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

func TestInitHumanOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"init", "--workspace", t.TempDir()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Initialized workspace") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestInitJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"init", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
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

func TestInitIsIdempotent(t *testing.T) {
	workspacePath := t.TempDir()
	var stdout, stderr bytes.Buffer

	if code := Run(context.Background(), []string{"init", "--workspace", workspacePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("first exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := Run(context.Background(), []string{"init", "--workspace", workspacePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("second exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "already initialized") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDaemonStatusNotRunning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"daemon", "status", "--workspace", workspacePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "not running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDaemonStatusJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"daemon", "status", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		State         string `json:"state"`
		WorkspacePath string `json:"workspacePath"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.State != "not_running" {
		t.Fatalf("state = %q, want not_running", payload.State)
	}
	if payload.WorkspacePath != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.WorkspacePath, workspacePath)
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

	code := Run(context.Background(), []string{"daemon", "status", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
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
