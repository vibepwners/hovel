package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/hovelconfig"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

type Endpoint struct {
	Network string
	Address string
	Display string
}

func (e Endpoint) String() string {
	if e.Display != "" {
		return e.Display
	}
	if e.Network == "tcp" {
		return "tcp://" + e.Address
	}
	return e.Address
}

type EndpointParser func(string) (Endpoint, error)

type WorkspaceLock interface {
	Release() error
}

type WorkspaceLockFactory func(workspacePath, owner string) (WorkspaceLock, error)

type WorkspaceStore interface {
	EnsureWorkspaceDatabase(context.Context, string) error
	SaveOperatorSession(context.Context, string, operatorsession.PersistedState) error
	LoadOperatorSession(context.Context, string) (operatorsession.PersistedState, bool, error)
	WriteDaemonStatus(context.Context, daemon.Identity) error
	ClearDaemonStatus(context.Context, string) error
}

type EventSinkFactory func(workspacePath string) services.EventSink

type LogPublisher interface {
	Publish(operation, chain string, entries ...operatorlog.Entry)
}

type LogPublisherFactory func() LogPublisher

type RPCServerConfig struct {
	Runs            services.RunService
	Session         *operatorsession.Session
	Logs            LogPublisher
	PersistSession  func(operatorsession.PersistedState) error
	ModuleSessions  services.SessionBroker
	LaunchKeyPolicy operatordomain.LaunchKeyPolicy
}

type RPCServerFactory func(RPCServerConfig) (http.Handler, error)

type ModuleRuntimeConfig struct {
	ModuleConfig  string
	HovelConfig   string
	WorkspacePath string
	Events        services.EventSink
	IDs           services.IDGenerator
	Clock         services.Clock
}

type ModuleRuntimeFactory func(ModuleRuntimeConfig) (services.ModuleRunner, services.SessionBroker)

type Args struct {
	WorkspacePath        string
	SocketPath           string
	ListenAddress        string
	ModuleConfig         string
	HovelConfig          string
	PID                  int
	StartedAt            time.Time
	IDs                  services.IDGenerator
	Clock                services.Clock
	Events               services.EventSink
	ModuleRunner         services.ModuleRunner
	ModuleSessions       services.SessionBroker
	ParseEndpoint        EndpointParser
	Store                WorkspaceStore
	AcquireWorkspaceLock WorkspaceLockFactory
	NewEventSink         EventSinkFactory
	NewLogPublisher      LogPublisherFactory
	NewRPCServer         RPCServerFactory
	NewModuleRuntime     ModuleRuntimeFactory
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
	if args.ParseEndpoint == nil {
		return errors.New("daemon runtime endpoint parser is not configured")
	}
	endpoint, err := args.ParseEndpoint(listenAddress)
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
		if args.NewEventSink == nil {
			return errors.New("daemon runtime event sink factory is not configured")
		}
		baseEvents = args.NewEventSink(workspacePath)
	}
	store := args.Store
	if store == nil {
		return errors.New("daemon runtime workspace store is not configured")
	}
	if args.AcquireWorkspaceLock == nil {
		return errors.New("daemon runtime workspace lock factory is not configured")
	}
	if args.NewLogPublisher == nil {
		return errors.New("daemon runtime log publisher factory is not configured")
	}
	if args.NewRPCServer == nil {
		return errors.New("daemon runtime rpc server factory is not configured")
	}

	lock, err := args.AcquireWorkspaceLock(workspacePath, fmt.Sprintf("pid:%d", os.Getpid()))
	if err != nil {
		return err
	}
	defer func() { logDaemonRuntimeError("release workspace lock", lock.Release()) }()

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
	logs := args.NewLogPublisher()
	events := newPublishingEventSink(baseEvents, session, logs, func() error {
		return persistSession(session.Export())
	})
	runner := args.ModuleRunner
	sessionBroker := args.ModuleSessions
	if runner == nil {
		if args.NewModuleRuntime == nil {
			return errors.New("daemon runtime module runtime factory is not configured")
		}
		runner, sessionBroker = args.NewModuleRuntime(ModuleRuntimeConfig{
			ModuleConfig:  args.ModuleConfig,
			HovelConfig:   args.HovelConfig,
			WorkspacePath: workspacePath,
			Events:        events,
			IDs:           ids,
			Clock:         clock,
		})
		if runner == nil {
			return errors.New("daemon runtime module runner factory returned nil")
		}
	}

	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           pid,
		SocketPath:    endpoint.String(),
		HovelConfig:   args.HovelConfig,
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
		defer func() { logDaemonRuntimeError("remove daemon socket", os.Remove(endpoint.Address)) }()
	}
	defer func() { logDaemonRuntimeError("close daemon listener", listener.Close()) }()

	runs := services.NewRunService(runner, events, ids, clock)
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    workspacePath,
		ExplicitPath: args.HovelConfig,
	})
	if err != nil {
		return err
	}
	handler, err := args.NewRPCServer(RPCServerConfig{
		Runs:            runs,
		Session:         session,
		Logs:            logs,
		PersistSession:  persistSession,
		ModuleSessions:  sessionBroker,
		LaunchKeyPolicy: launchKeyPolicyFromConfig(config.Policy.LaunchKey),
	})
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

func launchKeyPolicyFromConfig(config hovelconfig.LaunchKeyPolicy) operatordomain.LaunchKeyPolicy {
	policy := operatordomain.LaunchKeyPolicy{
		Mode:   operatordomain.LaunchKeyMode(config.Mode),
		Quorum: config.Quorum,
	}
	if timeout := config.HeartbeatTimeout; timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil {
			policy.HeartbeatTimeout = parsed
		}
	}
	return operatordomain.NormalizeLaunchKeyPolicy(policy)
}

func serveRPC(listener net.Listener, server *http.Server, errs chan<- error) {
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs <- err
		return
	}
	errs <- nil
}

type publishingEventSink struct {
	mu          sync.Mutex
	next        services.EventSink
	session     *operatorsession.Session
	logs        LogPublisher
	persist     func() error
	runStarts   map[string]time.Time
	throwStarts map[string]time.Time
}

func newPublishingEventSink(next services.EventSink, session *operatorsession.Session, logs LogPublisher, persist func() error) *publishingEventSink {
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
		if err := s.session.AppendLogToChain(chain, entry); err != nil {
			return err
		}
		s.publishLog(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.session.created", "session.created":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Info("session", "session opened",
			operatorlog.Field{Name: "session", Value: evt.Fields["sessionId"]},
			operatorlog.Field{Name: "kind", Value: evt.Fields["kind"]},
			operatorlog.Field{Name: "state", Value: evt.Fields["state"]},
		))
		if err := s.session.AppendLogToChain(chain, entry); err != nil {
			return err
		}
		s.publishLog(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.run.completed", "run.succeeded":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Success("throw", "run completed"))
		if err := s.session.AppendLogToChain(chain, entry); err != nil {
			return err
		}
		s.publishLog(operation, chain, entry)
		return s.persistIfConfigured()
	case "hovel.run.failed", "run.failed":
		entry := s.runEventEntry(operation, chain, evt, operatorlog.Finding("throw", "run failed"))
		if err := s.session.AppendLogToChain(chain, entry); err != nil {
			return err
		}
		s.publishLog(operation, chain, entry)
		return s.persistIfConfigured()
	}
	return nil
}

func (s *publishingEventSink) publishLog(operation, chain string, entry operatorlog.Entry) {
	if s.logs != nil {
		s.logs.Publish(operation, chain, entry)
	}
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
	entry := operatorlog.Info("module", evt.Fields["message"], fields...).WithLevel(operatorlog.Level(evt.Level))
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

func logDaemonRuntimeError(action string, err error) {
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, net.ErrClosed) {
		log.Printf("hovel daemon runtime: %s: %v", action, err)
	}
}

type runtimeIDs struct{}

var runtimeIDCounter atomic.Uint64

func (runtimeIDs) NewID() string {
	return fmt.Sprintf("id-%d-%d", os.Getpid(), runtimeIDCounter.Add(1))
}
