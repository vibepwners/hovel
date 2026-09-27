package sqlite

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
)

func TestWALLifetimeLock(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.open(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := exec.Command(executable, "-test.run=^TestWALLifetimeLockProbe$")
	probe.Env = append(os.Environ(), "HOVEL_TEST_WAL="+store.Path()+"-shm", "HOVEL_TEST_WAL_OWNER="+strconv.Itoa(os.Getpid()))
	if output, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("WAL lifetime lock probe: %v\n%s", err, output)
	}
}

func TestWALLifetimeLockProbe(t *testing.T) {
	path := os.Getenv("HOVEL_TEST_WAL")
	if path == "" {
		t.Skip("subprocess probe")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	// Query SQLite's Unix WAL lifetime lock from another process because
	// F_GETLK ignores locks held by the calling process.
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Start: 128, Len: 1}
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, &lock); err != nil {
		t.Fatal(err)
	}
	owner, err := strconv.Atoi(os.Getenv("HOVEL_TEST_WAL_OWNER"))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Type != syscall.F_RDLCK || int(lock.Pid) != owner {
		t.Fatalf("live SQLite owner %d lost WAL lifetime lock: type=%d owner=%d", owner, lock.Type, lock.Pid)
	}
}
