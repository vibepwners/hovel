package daemonmanager

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

func TestEnsureStartsAndStopsOwnedDaemon(t *testing.T) {
	workspacePath := shortTempDir(t)
	manager := New()

	session, err := manager.Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	status := session.Status()
	if status.State != daemon.StateRunning {
		t.Fatalf("state = %s, want running", status.State)
	}

	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateNotRunning
	})
}

func TestEnsureAttachesToExistingDaemonAndLeavesItRunning(t *testing.T) {
	workspacePath := shortTempDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			PID:           12345,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()

	waitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	session, err := New().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("state after close = %s, want running", status.State)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "hovel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
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
