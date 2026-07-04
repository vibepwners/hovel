package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceLockRejectsDuplicateOwner(t *testing.T) {
	workspacePath := t.TempDir()

	lock, err := AcquireWorkspaceLock(workspacePath, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Release(); err != nil {
			t.Logf("release workspace lock: %v", err)
		}
	})

	if _, err := AcquireWorkspaceLock(workspacePath, "owner-2"); err == nil {
		t.Fatal("second lock acquisition returned nil error")
	}
}

func TestWorkspaceLockReleaseAllowsReacquire(t *testing.T) {
	workspacePath := t.TempDir()

	lock, err := AcquireWorkspaceLock(workspacePath, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	second, err := AcquireWorkspaceLock(workspacePath, "owner-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Release(); err != nil {
			t.Logf("release reacquired workspace lock: %v", err)
		}
	})
}

func TestWorkspaceLockStaleLockFileIsConservativelyRejected(t *testing.T) {
	tmpdir := t.TempDir()

	// Simulate a crashed process that left its lock file behind.
	if err := os.WriteFile(filepath.Join(tmpdir, "daemon.lock"), []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := AcquireWorkspaceLock(tmpdir, "new-owner")
	if err == nil {
		t.Fatal("expected error when stale lock file exists, got nil")
	}
}

func TestWorkspaceLockReclaimsDeadPIDOwner(t *testing.T) {
	if !stalePIDLockDetectionSupported() {
		t.Skip("pid-based stale lock detection is not supported on this platform")
	}
	workspacePath := t.TempDir()
	stalePID := 999999999
	if processRunning(stalePID) {
		t.Skipf("test pid %d exists on this machine", stalePID)
	}
	if err := os.WriteFile(filepath.Join(workspacePath, "daemon.lock"), []byte(fmt.Sprintf("pid:%d\n", stalePID)), 0o644); err != nil {
		t.Fatal(err)
	}

	lock, err := AcquireWorkspaceLock(workspacePath, "owner-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Release(); err != nil {
			t.Logf("release reclaimed workspace lock: %v", err)
		}
	})
}
