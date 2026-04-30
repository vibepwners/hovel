package testsupport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

const ExampleModuleConfig = "examples/python/hovel-modules.json"

func UseExampleModuleConfig(t testing.TB) {
	t.Helper()
	t.Setenv("HOVEL_MODULE_CONFIG", ExampleModuleConfig)
}

func TempDir(t testing.TB) string {
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

func WaitFor(t testing.TB, condition func() bool) {
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

type DaemonFixture struct {
	WorkspacePath string
	SocketPath    string
	cancel        context.CancelFunc
	errs          chan error
}

func StartDaemon(t testing.TB, args daemonruntime.Args) DaemonFixture {
	t.Helper()
	if args.WorkspacePath == "" {
		args.WorkspacePath = TempDir(t)
	}
	if args.SocketPath == "" {
		args.SocketPath = filepath.Join(args.WorkspacePath, "hoveld.sock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, args)
	}()
	fixture := DaemonFixture{
		WorkspacePath: args.WorkspacePath,
		SocketPath:    args.SocketPath,
		cancel:        cancel,
		errs:          errs,
	}
	WaitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), args.WorkspacePath)
		return err == nil && status.State == daemon.StateRunning
	})
	t.Cleanup(fixture.Stop)
	return fixture
}

func (f DaemonFixture) Stop() {
	if f.cancel == nil || f.errs == nil {
		return
	}
	f.cancel()
	select {
	case <-f.errs:
	case <-time.After(2 * time.Second):
	}
}
