package filesystem

import (
	"context"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestDaemonStatusMissingFileIsNotRunning(t *testing.T) {
	workspacePath := t.TempDir()
	store := NewWorkspaceStore()

	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}
	if status.WorkspacePath != workspacePath {
		t.Fatalf("workspace path = %q, want %q", status.WorkspacePath, workspacePath)
	}
}

func TestWriteAndClearDaemonStatus(t *testing.T) {
	workspacePath := t.TempDir()
	store := NewWorkspaceStore()
	startedAt := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           123,
		SocketPath:    workspacePath + "/hoveld.sock",
		StartedAt:     startedAt,
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateRunning)
	}
	if status.Identity.PID != 123 {
		t.Fatalf("pid = %d, want 123", status.Identity.PID)
	}
	if status.Identity.SocketPath != workspacePath+"/hoveld.sock" {
		t.Fatalf("socket path = %q", status.Identity.SocketPath)
	}

	if err := store.ClearDaemonStatus(context.Background(), workspacePath); err != nil {
		t.Fatal(err)
	}
	status, err = store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}
}
