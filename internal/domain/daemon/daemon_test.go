package daemon

import (
	"testing"
	"time"
)

func TestNewIdentityRequiresFields(t *testing.T) {
	started := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	if _, err := NewIdentity(IdentityArgs{PID: 1, SocketPath: "/tmp/hovel.sock", StartedAt: started, Health: HealthHealthy}); err == nil {
		t.Fatal("NewIdentity returned nil error without workspace path")
	}
	if _, err := NewIdentity(IdentityArgs{WorkspacePath: ".hovel", SocketPath: "/tmp/hovel.sock", StartedAt: started, Health: HealthHealthy}); err == nil {
		t.Fatal("NewIdentity returned nil error without PID")
	}
	if _, err := NewIdentity(IdentityArgs{WorkspacePath: ".hovel", PID: 1, StartedAt: started, Health: HealthHealthy}); err == nil {
		t.Fatal("NewIdentity returned nil error without socket path")
	}
	if _, err := NewIdentity(IdentityArgs{WorkspacePath: ".hovel", PID: 1, SocketPath: "/tmp/hovel.sock", Health: HealthHealthy}); err == nil {
		t.Fatal("NewIdentity returned nil error without start time")
	}
}

func TestStatusNotRunning(t *testing.T) {
	status := NotRunning(".hovel")
	if status.State != StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, StateNotRunning)
	}
	if status.WorkspacePath != ".hovel" {
		t.Fatalf("workspace path = %q", status.WorkspacePath)
	}
}

func TestStatusRunningCarriesIdentity(t *testing.T) {
	started := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	identity, err := NewIdentity(IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           123,
		SocketPath:    "/tmp/hovel.sock",
		StartedAt:     started,
		Health:        HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}

	status := Running(identity)
	if status.State != StateRunning {
		t.Fatalf("state = %q, want %q", status.State, StateRunning)
	}
	if status.Identity.PID != 123 {
		t.Fatalf("pid = %d, want 123", status.Identity.PID)
	}
	if status.Identity.Health != HealthHealthy {
		t.Fatalf("health = %q, want %q", status.Identity.Health, HealthHealthy)
	}
}
