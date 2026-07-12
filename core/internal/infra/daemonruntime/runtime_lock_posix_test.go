//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package daemonruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/adapters/storage/filesystem"
	"github.com/vibepwners/hovel/internal/domain/daemon"
)

func TestServeReclaimsDeadPIDWorkspaceLock(t *testing.T) {
	workspacePath := shortTempDir(t)
	if err := os.WriteFile(filepath.Join(workspacePath, "daemon.lock"), []byte("pid:999999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, runtimeTestArgs(Args{
			WorkspacePath: workspacePath,
			SocketPath:    workspacePath + "/hoveld.sock",
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		}))
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
}
