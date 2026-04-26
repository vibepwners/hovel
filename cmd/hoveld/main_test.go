package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestRunPublishesStatusAndClearsOnCancel(t *testing.T) {
	workspacePath := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	codes := make(chan int, 1)
	var stdout, stderr bytes.Buffer

	go func() {
		codes <- run(ctx, []string{"--workspace", workspacePath}, &stdout, &stderr)
	}()

	store := filesystem.NewWorkspaceStore()
	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning && status.Identity.PID > 0
	})

	cancel()
	if code := <-codes; code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %s", code, stderr.String())
	}

	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
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
