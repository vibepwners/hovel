package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", "examples/python/hovel-modules.json")
	os.Exit(m.Run())
}

func TestServeWritesStatusAndClearsOnCancel(t *testing.T) {
	workspacePath := shortTempDir(t)
	store := filesystem.NewWorkspaceStore()
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)

	go func() {
		errs <- Serve(ctx, Args{
			WorkspacePath: workspacePath,
			SocketPath:    workspacePath + "/hoveld.sock",
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		})
	}()

	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning && status.Identity.PID == 123
	})

	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}
}

func TestServeRejectsDuplicateWorkspace(t *testing.T) {
	workspacePath := shortTempDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, Args{
			WorkspacePath: workspacePath,
			SocketPath:    workspacePath + "/hoveld.sock",
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
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

	err := Serve(context.Background(), Args{
		WorkspacePath: workspacePath,
		SocketPath:    workspacePath + "/other.sock",
		PID:           456,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("Serve returned nil error for duplicate workspace")
	}
	if !strings.Contains(err.Error(), "already locked") {
		t.Fatalf("error = %v", err)
	}
}

func TestServeRunsMockExploitOverRPC(t *testing.T) {
	workspacePath := shortTempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			IDs:           &sequenceIDs{values: []string{"run-1", "event-1", "event-2", "event-3", "event-4", "event-5"}},
			Clock:         fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()

	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		client.Close()
		return true
	})

	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.RunMockExploit(context.Background(), daemonrpc.RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
}

func TestServeRestoresOperatorSessionFromWorkspaceDatabase(t *testing.T) {
	workspacePath := shortTempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	store := filesystem.NewWorkspaceStore()

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		})
	}()
	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		client.Close()
		return true
	})

	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	session := daemonrpc.NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	client.Close()
	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}

	persisted, ok, err := store.LoadOperatorSession(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("operator session was not persisted")
	}
	if len(persisted.Operations) == 0 {
		t.Fatalf("persisted state has no operations: %#v", persisted)
	}

	socketPath = workspacePath + "/hoveld-restarted.sock"
	ctx, cancel = context.WithCancel(context.Background())
	errs = make(chan error, 1)
	go func() {
		errs <- Serve(ctx, Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           456,
			StartedAt:     time.Date(2026, 4, 26, 12, 1, 0, 0, time.UTC),
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()
	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		client.Close()
		return true
	})

	client, err = daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	restored := daemonrpc.NewSessionClient(context.Background(), client)
	if err := restored.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := restored.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	state := restored.Snapshot()
	if len(state.Targets) != 1 || state.Targets[0] != "mock://alpha" {
		t.Fatalf("restored targets = %#v", state.Targets)
	}
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "mock-survey" {
		t.Fatalf("restored steps = %#v", state.Steps)
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

func TestServeReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Serve(ctx, Args{
		WorkspacePath: t.TempDir(),
		SocketPath:    "hoveld.sock",
		PID:           123,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	if s.next >= len(s.values) {
		s.next++
		return fmt.Sprintf("event-%d", s.next)
	}
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
