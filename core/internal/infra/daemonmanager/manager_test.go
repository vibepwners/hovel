package daemonmanager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/moduleruntime/pythonrpc"
)

func TestMain(m *testing.M) {
	if err := os.Setenv("HOVEL_MODULE_CONFIG", "modules/examples/python/hovel-modules.json"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestEnsureStartsAndStopsOwnedDaemon(t *testing.T) {
	workspacePath := tempDir(t)
	manager := newTestManager()

	session, err := manager.Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	status := session.Status()
	if status.State != daemon.StateRunning {
		t.Fatalf("state = %s, want running", status.State)
	}

	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateNotRunning
	})
}

func TestEnsureWithModuleConfigPassesConfigToStartedDaemon(t *testing.T) {
	workspacePath := tempDir(t)
	moduleConfig := filepath.Join(tempDir(t), "modules.json")
	argsSeen := make(chan daemonruntime.Args, 1)
	manager := newTestManager()
	manager.Serve = func(ctx context.Context, args daemonruntime.Args) error {
		argsSeen <- args
		identity, err := daemon.NewIdentity(daemon.IdentityArgs{
			WorkspacePath: args.WorkspacePath,
			PID:           123,
			SocketPath:    filepath.Join(args.WorkspacePath, "hoveld.sock"),
			StartedAt:     time.Now().UTC(),
			Health:        daemon.HealthHealthy,
		})
		if err != nil {
			return err
		}
		if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(ctx, identity); err != nil {
			return err
		}
		<-ctx.Done()
		if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), args.WorkspacePath); err != nil {
			t.Logf("clear daemon status: %v", err)
		}
		return ctx.Err()
	}

	session, err := manager.EnsureWithModuleConfig(context.Background(), workspacePath, moduleConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagerSession(t, session)
	args := <-argsSeen
	if args.ModuleConfig != moduleConfig {
		t.Fatalf("ModuleConfig = %q, want %q", args.ModuleConfig, moduleConfig)
	}
}

func TestEnsureWithConfigPassesHovelConfigToStartedDaemon(t *testing.T) {
	workspacePath := tempDir(t)
	hovelConfig := filepath.Join(tempDir(t), "config.yaml")
	argsSeen := make(chan daemonruntime.Args, 1)
	manager := newTestManager()
	manager.Serve = func(ctx context.Context, args daemonruntime.Args) error {
		argsSeen <- args
		identity, err := daemon.NewIdentity(daemon.IdentityArgs{
			WorkspacePath: args.WorkspacePath,
			PID:           123,
			SocketPath:    filepath.Join(args.WorkspacePath, "hoveld.sock"),
			HovelConfig:   args.HovelConfig,
			StartedAt:     time.Now().UTC(),
			Health:        daemon.HealthHealthy,
		})
		if err != nil {
			return err
		}
		if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(ctx, identity); err != nil {
			return err
		}
		<-ctx.Done()
		if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), args.WorkspacePath); err != nil {
			t.Logf("clear daemon status: %v", err)
		}
		return ctx.Err()
	}

	session, err := manager.EnsureWithConfig(context.Background(), workspacePath, "", hovelConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagerSession(t, session)
	args := <-argsSeen
	if args.HovelConfig != hovelConfig {
		t.Fatalf("HovelConfig = %q, want %q", args.HovelConfig, hovelConfig)
	}
}

func TestEnsureRejectsRunningDaemonWithDifferentHovelConfig(t *testing.T) {
	firstConfig := filepath.Join(tempDir(t), "first.yaml")
	secondConfig := filepath.Join(tempDir(t), "second.yaml")
	fixture := startDaemon(t, daemonruntime.Args{HovelConfig: firstConfig})

	session, err := newTestManager().EnsureWithConfig(context.Background(), fixture.WorkspacePath, "", secondConfig)
	if err == nil {
		closeManagerSession(t, session)
		t.Fatal("EnsureWithConfig succeeded, want config mismatch error")
	}
	if !strings.Contains(err.Error(), "different hovel config") {
		t.Fatalf("error = %v, want config mismatch", err)
	}
}

func TestEnsureAttachesToExistingDaemonAndLeavesItRunning(t *testing.T) {
	fixture := startDaemon(t, daemonruntime.Args{
		PID:       12345,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	workspacePath := fixture.WorkspacePath

	session, err := newTestManager().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("state after close = %s, want running", status.State)
	}
}

func TestEnsureStartsManagedDaemonWhenStatusSocketIsStale(t *testing.T) {
	workspacePath := tempDir(t)
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           12345,
		SocketPath:    filepath.Join(workspacePath, "hoveld.sock"),
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	session, err := newTestManager().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagerSession(t, session)

	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	if session.Status().Identity.PID == 12345 {
		t.Fatal("session reused stale daemon identity")
	}
}

func TestEnsureAttachesToReachableWorkspaceSocketWithoutStatus(t *testing.T) {
	fixture := startDaemon(t, daemonruntime.Args{
		PID:       12345,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	workspacePath := fixture.WorkspacePath
	socketPath := fixture.SocketPath
	if err := filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), workspacePath); err != nil {
		t.Fatal(err)
	}

	session, err := newTestManager().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if session.Status().Identity.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", session.Status().Identity.SocketPath, socketPath)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAttachesWhenStatusSocketPathIsRelative(t *testing.T) {
	repoPath := tempDir(t)
	workspacePath := filepath.Join(repoPath, ".hovel")
	t.Chdir(repoPath)
	fixture := startDaemon(t, daemonruntime.Args{
		WorkspacePath: workspacePath,
		PID:           12345,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	socketPath := fixture.SocketPath

	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           12345,
		SocketPath:    ".hovel/hoveld.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	session, err := newTestManager().Ensure(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	if session.Status().Identity.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", session.Status().Identity.SocketPath, socketPath)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func closeManagerSession(t *testing.T, session *Session) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Logf("close daemon manager session: %v", err)
	}
}

type daemonFixture struct {
	WorkspacePath string
	SocketPath    string
	cancel        context.CancelFunc
	errs          chan error
}

func startDaemon(t testing.TB, args daemonruntime.Args) daemonFixture {
	t.Helper()
	if args.WorkspacePath == "" {
		args.WorkspacePath = tempDir(t)
	}
	if args.SocketPath == "" {
		args.SocketPath = filepath.Join(args.WorkspacePath, "hoveld.sock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, testRuntimeArgs(args))
	}()
	fixture := daemonFixture{
		WorkspacePath: args.WorkspacePath,
		SocketPath:    args.SocketPath,
		cancel:        cancel,
		errs:          errs,
	}
	var lastStatus string
	waitFor(t, func() bool {
		select {
		case err := <-errs:
			cancel()
			t.Fatalf("daemon exited before reporting running status: %v", err)
		default:
		}
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), args.WorkspacePath)
		lastStatus = fmt.Sprintf("workspace=%s socket=%s status=%#v err=%v", args.WorkspacePath, args.SocketPath, status, err)
		return err == nil && status.State == daemon.StateRunning
	}, func() string {
		return lastStatus
	})
	t.Cleanup(func() { fixture.stop(t) })
	return fixture
}

func (f daemonFixture) stop(t testing.TB) {
	t.Helper()
	if f.cancel == nil || f.errs == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.errs:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("daemon did not stop within 2s for workspace %s", f.WorkspacePath)
	}
}

func tempDir(t testing.TB) string {
	t.Helper()
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "hovel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("remove test temp dir: %v", err)
		}
	})
	return dir
}

func waitFor(t testing.TB, condition func() bool, details ...func() string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	var extra []string
	for _, detail := range details {
		if text := strings.TrimSpace(detail()); text != "" {
			extra = append(extra, text)
		}
	}
	if len(extra) == 0 {
		t.Fatal("condition was not met before deadline")
	}
	t.Fatalf("condition was not met before deadline:\n%s", strings.Join(extra, "\n"))
}

func newTestManager() Manager {
	store := filesystem.NewWorkspaceStore()
	return New(store, testSocketReachable, testEndpointNetwork, testServe)
}

func testServe(ctx context.Context, args daemonruntime.Args) error {
	return daemonruntime.Serve(ctx, testRuntimeArgs(args))
}

func testRuntimeArgs(args daemonruntime.Args) daemonruntime.Args {
	if args.ParseEndpoint == nil {
		args.ParseEndpoint = testParseEndpoint
	}
	if args.Store == nil {
		args.Store = filesystem.NewWorkspaceStore()
	}
	if args.AcquireWorkspaceLock == nil {
		args.AcquireWorkspaceLock = func(workspacePath, owner string) (daemonruntime.WorkspaceLock, error) {
			return filesystem.AcquireWorkspaceLock(workspacePath, owner)
		}
	}
	if args.NewEventSink == nil {
		args.NewEventSink = func(workspacePath string) services.EventSink {
			return sqlitestore.NewStore(workspacePath)
		}
	}
	if args.NewLogPublisher == nil {
		args.NewLogPublisher = func() daemonruntime.LogPublisher {
			return daemonrpc.NewLogBroker()
		}
	}
	if args.NewRPCServer == nil {
		args.NewRPCServer = testNewRPCServer
	}
	if args.NewModuleRuntime == nil {
		args.NewModuleRuntime = testNewModuleRuntime
	}
	return args
}

func testParseEndpoint(value string) (daemonruntime.Endpoint, error) {
	endpoint, err := daemonrpc.ParseEndpoint(value)
	if err != nil {
		return daemonruntime.Endpoint{}, err
	}
	return daemonruntime.Endpoint{
		Network: endpoint.Network,
		Address: endpoint.Address,
		Display: endpoint.String(),
	}, nil
}

func testEndpointNetwork(value string) (string, bool) {
	endpoint, err := daemonrpc.ParseEndpoint(value)
	if err != nil {
		return "", false
	}
	return endpoint.Network, true
}

func testSocketReachable(ctx context.Context, socketPath string) bool {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return false
	}
	defer func() { logDaemonManagerError("close daemon health-check client", client.Close()) }()
	_, err = client.PollLogs(ctx, 0)
	return err == nil
}

func testNewRPCServer(config daemonruntime.RPCServerConfig) (http.Handler, error) {
	logs, ok := config.Logs.(*daemonrpc.LogBroker)
	if !ok {
		return nil, errors.New("test rpc server requires daemonrpc log broker")
	}
	return daemonrpc.NewHandler(
		config.Runs,
		daemonrpc.WithSession(config.Session),
		daemonrpc.WithLogBroker(logs),
		daemonrpc.WithSessionPersistence(config.PersistSession),
		daemonrpc.WithModuleSessions(config.ModuleSessions),
		daemonrpc.WithLaunchKeyPolicy(config.LaunchKeyPolicy),
	)
}

func testNewModuleRuntime(config daemonruntime.ModuleRuntimeConfig) (services.ModuleRunner, services.SessionBroker) {
	sessions := pythonrpc.NewSessionBroker()
	return pythonrpc.Runner{
		ConfigPath:    config.ModuleConfig,
		HovelConfig:   config.HovelConfig,
		WorkspacePath: config.WorkspacePath,
		Events:        config.Events,
		IDs:           config.IDs,
		Clock:         config.Clock,
		Sessions:      sessions,
	}, sessions
}
