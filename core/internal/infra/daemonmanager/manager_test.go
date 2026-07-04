package daemonmanager

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	if err := os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfigPath()); err != nil {
		panic(err)
	}
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
		if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), args.WorkspacePath); err != nil {
			t.Logf("clear daemon status: %v", err)
		}
		return ctx.Err()
	}

	session, err := manager.EnsureWithModuleConfig(context.Background(), workspacePath, moduleConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagerSession(t, session)
	args := <-argsSeen
	if args.ModuleConfig != moduleConfig {
		t.Fatalf("ModuleConfig = %q, want %q", args.ModuleConfig, moduleConfig)
	}
}

func TestEnsureWithConfigPassesHovelConfigToStartedDaemon(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	hovelConfig := filepath.Join(testsupport.TempDir(t), "config.yaml")
	argsSeen := make(chan daemonruntime.Args, 1)
	manager := New()
	manager.Serve = func(ctx context.Context, args daemonruntime.Args) error {
		argsSeen <- args
		identity, err := daemon.NewIdentity(daemon.IdentityArgs{
			WorkspacePath: args.WorkspacePath,
			PID:           123,
			SocketPath:    filepath.Join(args.WorkspacePath, "hoveld.sock"),
			HovelConfig:   args.HovelConfig,
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
		if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), args.WorkspacePath); err != nil {
			t.Logf("clear daemon status: %v", err)
		}
		return ctx.Err()
	}

	session, err := manager.EnsureWithConfig(context.Background(), workspacePath, "", hovelConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagerSession(t, session)
	args := <-argsSeen
	if args.HovelConfig != hovelConfig {
		t.Fatalf("HovelConfig = %q, want %q", args.HovelConfig, hovelConfig)
	}
}

func TestEnsureRejectsRunningDaemonWithDifferentHovelConfig(t *testing.T) {
	firstConfig := filepath.Join(testsupport.TempDir(t), "first.yaml")
	secondConfig := filepath.Join(testsupport.TempDir(t), "second.yaml")
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{HovelConfig: firstConfig})

	session, err := New().EnsureWithConfig(context.Background(), fixture.WorkspacePath, "", secondConfig)
	if err == nil {
		closeManagerSession(t, session)
		t.Fatal("EnsureWithConfig succeeded, want config mismatch error")
	}
	if !strings.Contains(err.Error(), "different hovel config") {
		t.Fatalf("error = %v, want config mismatch", err)
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
	defer closeManagerSession(t, session)

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

func closeManagerSession(t *testing.T, session *Session) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Logf("close daemon manager session: %v", err)
	}
}
