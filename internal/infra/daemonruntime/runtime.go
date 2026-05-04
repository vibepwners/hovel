package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
)

type Args struct {
	WorkspacePath  string
	SocketPath     string
	ListenAddress  string
	PID            int
	StartedAt      time.Time
	IDs            services.IDGenerator
	Clock          services.Clock
	Events         services.EventSink
	ModuleRunner   services.ModuleRunner
	ModuleSessions services.SessionBroker
}

func Serve(ctx context.Context, args Args) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	workspacePath := workspace.ResolvePath(args.WorkspacePath)
	listenAddress := args.ListenAddress
	if listenAddress == "" {
		listenAddress = args.SocketPath
	}
	if listenAddress == "" {
		listenAddress = filepath.Join(workspacePath, "hoveld.sock")
	}
	endpoint, err := daemonrpc.ParseEndpoint(listenAddress)
	if err != nil {
		return err
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
		baseEvents = sqlitestore.NewStore(workspacePath)
	}

	lock, err := filesystem.AcquireWorkspaceLock(workspacePath, fmt.Sprintf("pid:%d", os.Getpid()))
	if err != nil {
		return err
	}
	defer lock.Release()

	store := filesystem.NewWorkspaceStore()
	if err := store.EnsureWorkspaceDatabase(ctx, workspacePath); err != nil {
		return err
	}
	session := operatorsession.New()
	if state, ok, err := store.LoadOperatorSession(ctx, workspacePath); err != nil {
		return err
	} else if ok {
		session.Import(state)
	}
	persistSession := func(state operatorsession.PersistedState) error {
		return store.SaveOperatorSession(context.Background(), workspacePath, state)
	}
	logs := daemonrpc.NewLogBroker()
	events := newPublishingEventSink(baseEvents, session, logs, func() error {
		return persistSession(session.Export())
	})
	runner := args.ModuleRunner
	sessionBroker := args.ModuleSessions
	if runner == nil {
		pythonSessions := pythonrpc.NewSessionBroker()
		sessionBroker = pythonSessions
		runner = pythonrpc.Runner{
			Events:   events,
			IDs:      ids,
			Clock:    clock,
			Sessions: pythonSessions,
		}
	}

	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           pid,
		SocketPath:    endpoint.String(),
		StartedAt:     startedAt,
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		return err
	}

	if endpoint.Network == "unix" {
		if err := os.Remove(endpoint.Address); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	listener, err := net.Listen(endpoint.Network, endpoint.Address)
	if err != nil {
		return err
	}
	if endpoint.Network == "unix" {
		defer os.Remove(endpoint.Address)
	}
	defer listener.Close()

	runs := services.NewRunService(runner, events, ids, clock)
	handler, err := daemonrpc.NewHandler(runs, daemonrpc.WithSession(session), daemonrpc.WithLogBroker(logs), daemonrpc.WithSessionPersistence(persistSession), daemonrpc.WithModuleSessions(sessionBroker))
	if err != nil {
		return err
	}
	acceptErrs := make(chan error, 1)
	httpServer := &http.Server{Handler: handler}
	go serveRPC(listener, httpServer, acceptErrs)

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

func serveRPC(listener net.Listener, server *http.Server, errs chan<- error) {
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs <- err
		return
	}
	errs <- nil
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
	persist     func() error
	runStarts   map[string]time.Time
	throwStarts map[string]time.Time
}

func newPublishingEventSink(next services.EventSink, session *operatorsession.Session, logs *daemonrpc.LogBroker, persist func() error) *publishingEventSink {
	return &publishingEventSink{
		next:        next,
		session:     session,
		logs:        logs,
		persist:     persist,
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
	operation := evt.Refs.Operation
	chain := evt.Refs.Chain
	if operation == "" || chain == "" {
		state := s.session.Snapshot()
		if operation == "" {
			operation = state.ActiveOperation
		}
		if chain == "" {
			chain = state.ActiveChain
		}
	}
	if chain == "" {
		return nil
	}
	switch evt.Type.String() {
	case "hovel.run.started", "run.started":
		s.runStarts[evt.Refs.RunID] = evt.Timestamp
		if throwStarted, ok := evt.Fields["throwStarted"]; ok {
			if at, err := time.Parse(time.RFC3339Nano, throwStarted); err == nil && !at.IsZero() {
				s.throwStarts[chain] = at
			}
		}
		if s.throwStarts[chain].IsZero() {
			s.throwStarts[chain] = evt.Timestamp
		}
	case "hovel.module.log", "module.log":
		entry := s.moduleLogEntry(operation, chain, evt)
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.session.created", "session.created":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Info("session", "session opened",
			operatorlog.Field{Name: "session", Value: evt.Fields["sessionId"]},
			operatorlog.Field{Name: "kind", Value: evt.Fields["kind"]},
			operatorlog.Field{Name: "state", Value: evt.Fields["state"]},
		))
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.run.completed", "run.succeeded":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Success("throw", "run completed"))
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.run.failed", "run.failed":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Finding("throw", "run failed"))
		_ = s.session.AppendLogToChain(chain, entry)
		s.logs.Publish(operation, chain, entry)
		return s.persistIfConfigured()
	}
	return nil
}

func (s *publishingEventSink) persistIfConfigured() error {
	if s.persist == nil {
		return nil
	}
	return s.persist()
}

func (s *publishingEventSink) moduleLogEntry(operation, chain string, evt event.Event) operatorlog.Entry {
	fields := make([]operatorlog.Field, 0, len(evt.Fields))
	for key, value := range evt.Fields {
		if key == "message" {
			continue
		}
		fields = append(fields, operatorlog.Field{Name: key, Value: value})
	}
	entry := operatorlog.Info("module", evt.Fields["message"], fields...)
	return s.runEventEntry(operation, chain, evt, entry)
}

func (s *publishingEventSink) runEventEntry(operation, chain string, evt event.Event, entry operatorlog.Entry) operatorlog.Entry {
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
		WithTopic("operation/" + operation + "/chain/" + chain + "/logs")
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
