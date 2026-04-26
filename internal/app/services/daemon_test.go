package services

import (
	"context"
	"testing"

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

type fakeDaemonStore struct {
	path string
}

func (s *fakeDaemonStore) DaemonStatus(_ context.Context, workspacePath string) (daemon.Status, error) {
	s.path = workspacePath
	return daemon.NotRunning(workspacePath), nil
}
