package daemonruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/moduleruntime/pythonrpc"
)

func TestServeWritesStatusAndClearsOnCancel(t *testing.T) {
	workspacePath := shortTempDir(t)
	store := filesystem.NewWorkspaceStore()
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

	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning && status.Identity.PID == 123
	})

	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	status, err := store.DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateNotRunning {
		t.Fatalf("state = %q, want %q", status.State, daemon.StateNotRunning)
	}
}

func TestServeRejectsDuplicateWorkspace(t *testing.T) {
	workspacePath := shortTempDir(t)
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

	err := Serve(context.Background(), runtimeTestArgs(Args{
		WorkspacePath: workspacePath,
		SocketPath:    workspacePath + "/other.sock",
		PID:           456,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	}))
	if err == nil {
		t.Fatal("Serve returned nil error for duplicate workspace")
	}
	if !strings.Contains(err.Error(), "already locked") {
		t.Fatalf("error = %v", err)
	}
}

func TestServeRunsMockExploitOverRPC(t *testing.T) {
	workspacePath := shortTempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	moduleConfig := writeRuntimeModuleConfig(t, runtimeModule{
		ID:             "mock-exploit",
		ModuleType:     "exploit",
		Summary:        "test mock exploit",
		ExecuteSummary: "mock exploit completed without target interaction",
		FindingTitle:   "mock exploit path verified",
	})
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, runtimeTestArgs(Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			ModuleConfig:  moduleConfig,
			IDs:           &sequenceIDs{values: []string{"run-1", "event-1", "event-2", "event-3", "event-4", "event-5"}},
			Clock:         fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		}))
	}()
	defer func() {
		cancel()
		<-errs
	}()

	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		closeRuntimeClient(t, client)
		return true
	})

	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntimeClient(t, client)

	result, err := client.RunMockExploit(context.Background(), daemonrpc.RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
}

func TestServeRestoresOperatorSessionFromWorkspaceDatabase(t *testing.T) {
	workspacePath := shortTempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	moduleConfig := writeRuntimeModuleConfig(t, runtimeModule{
		ID:         "mock-survey",
		ModuleType: "survey",
		Summary:    "test mock survey",
	})
	store := filesystem.NewWorkspaceStore()

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- Serve(ctx, runtimeTestArgs(Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           123,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			ModuleConfig:  moduleConfig,
		}))
	}()
	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		closeRuntimeClient(t, client)
		return true
	})

	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	session := daemonrpc.NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	closeRuntimeClient(t, client)
	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}

	persisted, ok, err := store.LoadOperatorSession(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("operator session was not persisted")
	}
	if len(persisted.Operations) == 0 {
		t.Fatalf("persisted state has no operations: %#v", persisted)
	}

	socketPath = workspacePath + "/hoveld-restarted.sock"
	ctx, cancel = context.WithCancel(context.Background())
	errs = make(chan error, 1)
	go func() {
		errs <- Serve(ctx, runtimeTestArgs(Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           456,
			StartedAt:     time.Date(2026, 4, 26, 12, 1, 0, 0, time.UTC),
			ModuleConfig:  moduleConfig,
		}))
	}()
	defer func() {
		cancel()
		<-errs
	}()
	waitFor(t, func() bool {
		client, err := daemonrpc.Dial(socketPath)
		if err != nil {
			return false
		}
		closeRuntimeClient(t, client)
		return true
	})

	client, err = daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntimeClient(t, client)
	restored := daemonrpc.NewSessionClient(context.Background(), client)
	if err := restored.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := restored.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	state := restored.Snapshot()
	if len(state.Targets) != 1 || state.Targets[0] != "mock://alpha" {
		t.Fatalf("restored targets = %#v", state.Targets)
	}
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "mock-survey" {
		t.Fatalf("restored steps = %#v", state.Steps)
	}
}

func shortTempDir(t *testing.T) string {
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
			t.Logf("remove test daemon dir: %v", err)
		}
	})
	return dir
}

func TestServeReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Serve(ctx, Args{
		WorkspacePath: t.TempDir(),
		SocketPath:    "hoveld.sock",
		PID:           123,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	if s.next >= len(s.values) {
		s.next++
		return fmt.Sprintf("event-%d", s.next)
	}
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func waitFor(t *testing.T, condition func() bool) {
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

func closeRuntimeClient(t *testing.T, client *daemonrpc.Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Logf("close daemon runtime client: %v", err)
	}
}

type runtimeModule struct {
	ID             string
	ModuleType     string
	Summary        string
	ExecuteSummary string
	FindingTitle   string
}

func writeRuntimeModuleConfig(t *testing.T, modules ...runtimeModule) string {
	t.Helper()
	root := t.TempDir()
	config := pythonrpc.ModuleConfig{}
	for _, module := range modules {
		if module.ID == "" {
			t.Fatal("runtime module fixture id is required")
		}
		moduleType := module.ModuleType
		if moduleType == "" {
			moduleType = "survey"
		}
		summary := module.Summary
		if summary == "" {
			summary = module.ID + " fixture"
		}
		executeSummary := module.ExecuteSummary
		if executeSummary == "" {
			executeSummary = module.ID + " executed"
		}
		findingTitle := module.FindingTitle
		if findingTitle == "" {
			findingTitle = module.ID + " finding"
		}
		config.Modules = append(config.Modules, pythonrpc.ModuleEntry{
			ID:      module.ID,
			Runtime: "jsonrpc-stdio",
			Command: []string{
				os.Args[0],
				"-test.run=TestRuntimeModuleProcess",
				"--",
				"--runtime-module-helper",
				module.ID,
				moduleType,
				summary,
				executeSummary,
				findingTitle,
			},
		})
	}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestRuntimeModuleProcess(t *testing.T) {
	args := runtimeModuleProcessArgs()
	if args == nil {
		return
	}
	if err := runRuntimeModuleProcess(os.Stdin, os.Stdout, args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runtimeModuleProcessArgs() []string {
	for i, arg := range os.Args {
		if arg == "--runtime-module-helper" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func runRuntimeModuleProcess(in io.Reader, out io.Writer, args []string) error {
	if len(args) != 5 {
		return fmt.Errorf("usage: --runtime-module-helper <name> <type> <summary> <execute-summary> <finding-title>")
	}
	module := runtimeModule{
		ID:             args[0],
		ModuleType:     args[1],
		Summary:        args[2],
		ExecuteSummary: args[3],
		FindingTitle:   args[4],
	}
	reader := bufio.NewReader(in)
	for {
		request, ok, err := readRuntimeModuleRequest(reader)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		id := request["id"]
		method, _ := request["method"].(string)
		switch method {
		case "handshake":
			if err := writeRuntimeModuleResponse(out, id, map[string]any{
				"name":       module.ID,
				"version":    "v0.0.0-test",
				"moduleType": module.ModuleType,
				"summary":    module.Summary,
				"tags":       []string{},
			}); err != nil {
				return err
			}
		case "schema":
			if err := writeRuntimeModuleResponse(out, id, map[string]any{
				"chainConfig":  []any{},
				"targetConfig": []any{},
				"outputs":      map[string]any{},
			}); err != nil {
				return err
			}
		case "execute":
			if err := writeRuntimeModuleResponse(out, id, map[string]any{
				"status":    "succeeded",
				"summary":   module.ExecuteSummary,
				"findings":  []any{map[string]any{"title": module.FindingTitle, "severity": "info", "detail": ""}},
				"artifacts": []any{},
				"outputs":   map[string]any{},
				"sessions":  []any{},
			}); err != nil {
				return err
			}
		case "shutdown":
			if err := writeRuntimeModuleResponse(out, id, map[string]any{"status": "ok"}); err != nil {
				return err
			}
			return nil
		default:
			if err := writeRuntimeModuleError(out, id, "unknown method "+method); err != nil {
				return err
			}
		}
	}
}

func readRuntimeModuleRequest(reader *bufio.Reader) (map[string]any, bool, error) {
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) && line == "" {
			return nil, false, nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, false, fmt.Errorf("invalid header line %q", line)
		}
		headers[strings.ToLower(name)] = strings.TrimSpace(value)
	}
	length, err := strconv.Atoi(headers["content-length"])
	if err != nil {
		return nil, false, fmt.Errorf("invalid content-length: %w", err)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, false, err
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, false, err
	}
	return request, true, nil
}

func writeRuntimeModuleResponse(out io.Writer, id any, result map[string]any) error {
	return writeRuntimeModuleMessage(out, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func writeRuntimeModuleError(out io.Writer, id any, message string) error {
	return writeRuntimeModuleMessage(out, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"message": message},
	})
}

func writeRuntimeModuleMessage(out io.Writer, message map[string]any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err = out.Write(body)
	return err
}

func runtimeTestArgs(args Args) Args {
	if args.ParseEndpoint == nil {
		args.ParseEndpoint = runtimeTestParseEndpoint
	}
	if args.Store == nil {
		args.Store = filesystem.NewWorkspaceStore()
	}
	if args.AcquireWorkspaceLock == nil {
		args.AcquireWorkspaceLock = func(workspacePath, owner string) (WorkspaceLock, error) {
			return filesystem.AcquireWorkspaceLock(workspacePath, owner)
		}
	}
	if args.NewEventSink == nil {
		args.NewEventSink = func(workspacePath string) services.EventSink {
			return sqlitestore.NewStore(workspacePath)
		}
	}
	if args.NewLogPublisher == nil {
		args.NewLogPublisher = func() LogPublisher {
			return daemonrpc.NewLogBroker()
		}
	}
	if args.NewRPCServer == nil {
		args.NewRPCServer = runtimeTestNewRPCServer
	}
	if args.NewModuleRuntime == nil {
		args.NewModuleRuntime = runtimeTestNewModuleRuntime
	}
	return args
}

func runtimeTestParseEndpoint(value string) (Endpoint, error) {
	endpoint, err := daemonrpc.ParseEndpoint(value)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{
		Network: endpoint.Network,
		Address: endpoint.Address,
		Display: endpoint.String(),
	}, nil
}

func runtimeTestNewRPCServer(config RPCServerConfig) (http.Handler, error) {
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

func runtimeTestNewModuleRuntime(config ModuleRuntimeConfig) (services.ModuleRunner, services.SessionBroker) {
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
