package services

import (
	"context"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestDaemonStatusDefaultsWorkspacePath(t *testing.T) {
	store := &fakeDaemonStore{}
	service := NewDaemonService(store)

	status, err := service.Status(context.Background(), DaemonStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}
	if store.path != ".hovel" {
		t.Fatalf("store path = %q, want .hovel", store.path)
	}
}

func TestDaemonStatusRunningReturnsIdentity(t *testing.T) {
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: "/tmp/test",
		PID:           123,
		SocketPath:    "/tmp/test.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeRunningDaemonStore{identity: identity}
	service := NewDaemonService(store)

	status, err := service.Status(context.Background(), DaemonStatusRequest{WorkspacePath: "/tmp/test"})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateRunning)
	}
	if status.Identity.PID != 123 {
		t.Fatalf("pid = %d, want 123", status.Identity.PID)
	}
	if status.Identity.SocketPath != "/tmp/test.sock" {
		t.Fatalf("socket path = %q, want /tmp/test.sock", status.Identity.SocketPath)
	}
}

type fakeDaemonStore struct {
	path string
}

func (s *fakeDaemonStore) DaemonStatus(_ context.Context, workspacePath string) (daemon.Status, error) {
	s.path = workspacePath
	return daemon.NotRunning(workspacePath), nil
}

type fakeRunningDaemonStore struct {
	identity daemon.Identity
}

func (s *fakeRunningDaemonStore) DaemonStatus(_ context.Context, _ string) (daemon.Status, error) {
	return daemon.Running(s.identity), nil
}
