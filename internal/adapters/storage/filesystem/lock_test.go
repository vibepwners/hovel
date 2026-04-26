package filesystem

import "testing"

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
