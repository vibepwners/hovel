package daemonmanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfigPath())
	os.Exit(m.Run())
}

func TestEnsureStartsAndStopsOwnedDaemon(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
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
	testsupport.WaitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateNotRunning
	})
}

func TestEnsureWithModuleConfigPassesConfigToStartedDaemon(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	moduleConfig := filepath.Join(testsupport.TempDir(t), "modules.json")
	argsSeen := make(chan daemonruntime.Args, 1)
	manager := New()
	manager.Serve = func(ctx context.Context, args daemonruntime.Args) error {
		argsSeen <- args
		identity, err := daemon.NewIdentity(daemon.IdentityArgs{
			WorkspacePath: args.WorkspacePath,
			PID:           123,
			SocketPath:    filepath.Join(args.WorkspacePath, "hoveld.sock"),
			StartedAt:     time.Now().UTC(),
			Health:        daemon.HealthHealthy,
		})
		if err != nil {
			return err
		}
		if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(ctx, identity); err != nil {
			return err
		}
		<-ctx.Done()
		_ = filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), args.WorkspacePath)
		return ctx.Err()
	}

	session, err := manager.EnsureWithModuleConfig(context.Background(), workspacePath, moduleConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	args := <-argsSeen
	if args.ModuleConfig != moduleConfig {
		t.Fatalf("ModuleConfig = %q, want %q", args.ModuleConfig, moduleConfig)
	}
}

func TestEnsureAttachesToExistingDaemonAndLeavesItRunning(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		PID:       12345,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	workspacePath := fixture.WorkspacePath

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
	workspacePath := testsupport.TempDir(t)
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
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		PID:       12345,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	workspacePath := fixture.WorkspacePath
	socketPath := fixture.SocketPath
	if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), workspacePath); err != nil {
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
}

func TestEnsureAttachesWhenStatusSocketPathIsRelative(t *testing.T) {
	repoPath := testsupport.TempDir(t)
	workspacePath := filepath.Join(repoPath, ".hovel")
	t.Chdir(repoPath)
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		WorkspacePath: workspacePath,
		PID:           12345,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	socketPath := fixture.SocketPath

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
}
