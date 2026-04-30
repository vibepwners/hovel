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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
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
	baseEvents := args.Events
	if baseEvents == nil {
		baseEvents = discardEvents{}
	}
	session := operatorsession.New()
	logs := daemonrpc.NewLogBroker()
	events := newPublishingEventSink(baseEvents, session, logs)
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

type publishingEventSink struct {
	mu          sync.Mutex
	next        services.EventSink
	session     *operatorsession.Session
	logs        *daemonrpc.LogBroker
	runStarts   map[string]time.Time
	throwStarts map[string]time.Time
}

func newPublishingEventSink(next services.EventSink, session *operatorsession.Session, logs *daemonrpc.LogBroker) *publishingEventSink {
	return &publishingEventSink{
		next:        next,
		session:     session,
		logs:        logs,
		runStarts:   map[string]time.Time{},
		throwStarts: map[string]time.Time{},
	}
}

func (s *publishingEventSink) Append(ctx context.Context, evt event.Event) error {
	if err := s.next.Append(ctx, evt); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.session.Snapshot().ActiveChain
	if chain == "" {
		return nil
	}
	switch evt.Type.String() {
	case "run.started":
		s.runStarts[evt.Refs.RunID] = evt.Timestamp
		if throwStarted, ok := evt.Fields["throwStarted"]; ok {
			if at, err := time.Parse(time.RFC3339Nano, throwStarted); err == nil && !at.IsZero() {
				s.throwStarts[chain] = at
			}
		}
		if s.throwStarts[chain].IsZero() {
			s.throwStarts[chain] = evt.Timestamp
		}
	case "module.log":
		entry := s.moduleLogEntry(chain, evt)
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(chain, entry)
	case "run.succeeded":
		entry := s.runEventEntry(chain, evt, operatorlog.Success("throw", "run completed"))
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(chain, entry)
	case "run.failed":
		entry := s.runEventEntry(chain, evt, operatorlog.Finding("throw", "run failed"))
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(chain, entry)
	}
	return nil
}

func (s *publishingEventSink) moduleLogEntry(chain string, evt event.Event) operatorlog.Entry {
	fields := make([]operatorlog.Field, 0, len(evt.Fields))
	for key, value := range evt.Fields {
		if key == "message" {
			continue
		}
		fields = append(fields, operatorlog.Field{Name: key, Value: value})
	}
	entry := operatorlog.Info("module", evt.Fields["message"], fields...)
	return s.runEventEntry(chain, evt, entry)
}

func (s *publishingEventSink) runEventEntry(chain string, evt event.Event, entry operatorlog.Entry) operatorlog.Entry {
	started := s.throwStarts[chain]
	if started.IsZero() {
		started = s.runStarts[evt.Refs.RunID]
	}
	if started.IsZero() {
		started = evt.Timestamp
	}
	return entry.
		WithElapsed(evt.Timestamp.Sub(started).Seconds()).
		WithChain(chain).
		WithRun(evt.Refs.RunID).
		WithTarget(evt.Refs.TargetID).
		WithModule(evt.Refs.ModuleID).
		WithTopic("chain/" + chain + "/logs")
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
