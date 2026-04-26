package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

type Args struct {
	WorkspacePath string
	SocketPath    string
	PID           int
	StartedAt     time.Time
}

func Serve(ctx context.Context, args Args) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	workspacePath := workspace.ResolvePath(args.WorkspacePath)
	socketPath := args.SocketPath
	if socketPath == "" {
		socketPath = filepath.Join(workspacePath, "hoveld.sock")
	}
	pid := args.PID
	if pid == 0 {
		pid = os.Getpid()
	}
	startedAt := args.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	lock, err := filesystem.AcquireWorkspaceLock(workspacePath, fmt.Sprintf("pid:%d", pid))
	if err != nil {
		return err
	}
	defer lock.Release()

	store := filesystem.NewWorkspaceStore()
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           pid,
		SocketPath:    socketPath,
		StartedAt:     startedAt,
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		return err
	}
	if err := store.WriteDaemonStatus(ctx, identity); err != nil {
		return err
	}

	<-ctx.Done()
	clearErr := store.ClearDaemonStatus(context.Background(), workspacePath)
	if clearErr != nil {
		return errors.Join(ctx.Err(), clearErr)
	}
	return nil
}
