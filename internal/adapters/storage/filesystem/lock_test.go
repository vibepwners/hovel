package filesystem

import (
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
	defer lock.Release()

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
	defer second.Release()
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
