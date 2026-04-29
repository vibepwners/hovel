package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
)

type Args struct {
	WorkspacePath string
	SocketPath    string
	PID           int
	StartedAt     time.Time
	IDs           services.IDGenerator
	Clock         services.Clock
	Events        services.EventSink
	ModuleRunner  services.ModuleRunner
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
	ids := args.IDs
	if ids == nil {
		ids = runtimeIDs{}
	}
	clock := args.Clock
	if clock == nil {
		clock = systemClock{}
	}
	events := args.Events
	if events == nil {
		events = discardEvents{}
	}
	runner := args.ModuleRunner
	if runner == nil {
		runner = pythonrpc.Runner{
			Events: events,
			IDs:    ids,
			Clock:  clock,
		}
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

	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	defer listener.Close()

	server := rpc.NewServer()
	runs := services.NewRunService(runner, events, ids, clock)
	session := operatorsession.New()
	logs := daemonrpc.NewLogBroker()
	if err := daemonrpc.Register(server, runs, daemonrpc.WithSession(session), daemonrpc.WithLogBroker(logs)); err != nil {
		return err
	}
	acceptErrs := make(chan error, 1)
	go serveRPC(listener, server, acceptErrs)

	if err := store.WriteDaemonStatus(ctx, identity); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
	case err := <-acceptErrs:
		clearErr := store.ClearDaemonStatus(context.Background(), workspacePath)
		if clearErr != nil {
			return errors.Join(err, clearErr)
		}
		return err
	}

	clearErr := store.ClearDaemonStatus(context.Background(), workspacePath)
	if clearErr != nil {
		return errors.Join(ctx.Err(), clearErr)
	}
	return nil
}

func serveRPC(listener net.Listener, server *rpc.Server, errs chan<- error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		go server.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

type runtimeIDs struct{}

var runtimeIDCounter atomic.Uint64

func (runtimeIDs) NewID() string {
	return fmt.Sprintf("id-%d-%d", os.Getpid(), runtimeIDCounter.Add(1))
}
