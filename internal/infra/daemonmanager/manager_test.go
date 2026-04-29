package daemonmanager

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", "examples/python/hovel-modules.json")
	os.Exit(m.Run())
}

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

func TestEnsureStartsManagedDaemonWhenStatusSocketIsStale(t *testing.T) {
	workspacePath := shortTempDir(t)
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           12345,
		SocketPath:    filepath.Join(workspacePath, "hoveld.sock"),
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	session, err := New().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	if session.Status().Identity.PID == 12345 {
		t.Fatal("session reused stale daemon identity")
	}
}

func TestEnsureAttachesToReachableWorkspaceSocketWithoutStatus(t *testing.T) {
	workspacePath := shortTempDir(t)
	socketPath := filepath.Join(workspacePath, "hoveld.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- conn.Close()
	}()

	session, err := New().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if session.Status().Identity.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", session.Status().Identity.SocketPath, socketPath)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAttachesWhenStatusSocketPathIsRelative(t *testing.T) {
	repoPath := shortTempDir(t)
	workspacePath := filepath.Join(repoPath, ".hovel")
	if err := os.MkdirAll(workspacePath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoPath)
	socketPath := filepath.Join(workspacePath, "hoveld.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- conn.Close()
	}()

	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           12345,
		SocketPath:    ".hovel/hoveld.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	session, err := New().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if session.Status().Identity.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", session.Status().Identity.SocketPath, socketPath)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
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
