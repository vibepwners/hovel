package daemonrpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/modules/mockexploit"
)

func TestClientRunsMockExploitThroughConnectRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.RunMockExploit(context.Background(), RunMockExploitRequest{
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
	if result.Summary != "mock exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
	if result.Artifacts[0].Data == "" {
		t.Fatalf("artifact = %#v, want inline data", result.Artifacts[0])
	}
}

func TestClientCanDialConnectRPCOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, "tcp://"+address, runs)

	client, err := Dial("tcp://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.RunMockExploit(context.Background(), RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != "run-1" || result.State != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSessionClientPublishesModuleAddedLog(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	logs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) != 2 {
		t.Fatalf("log count = %d, want 2: %#v", len(logs.Logs), logs.Logs)
	}
	got := logs.Logs[1]
	if got.Chain != "c1" || got.Entry.Message != "module added" || got.Entry.Fields["module"] != "mock-survey" {
		t.Fatalf("published log = %#v", got)
	}
}

func TestPollChainLogsOnlyReturnsRequestedChain(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaLogs, err := client.PollChainLogs(context.Background(), "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alphaLogs.Logs) != 2 {
		t.Fatalf("alpha log count = %d, want 2: %#v", len(alphaLogs.Logs), alphaLogs.Logs)
	}
	for _, log := range alphaLogs.Logs {
		if log.Chain != "alpha" {
			t.Fatalf("alpha poll returned chain %q log: %#v", log.Chain, log)
		}
	}

	allLogs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(allLogs.Logs) != 4 {
		t.Fatalf("all log count = %d, want 4: %#v", len(allLogs.Logs), allLogs.Logs)
	}
}

func TestLogBrokerRetainsBoundedHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(3)
	for i := 1; i <= 10; i++ {
		chain := "alpha"
		if i%2 == 0 {
			chain = "beta"
		}
		broker.Publish("op", chain, operatorlog.Entry{Message: "log"})
	}

	last, logs := broker.Since(0)
	if last != 10 {
		t.Fatalf("last = %d, want 10", last)
	}
	if len(logs) != 3 {
		t.Fatalf("retained logs = %d, want 3", len(logs))
	}
	if logs[0].Seq != 8 || logs[2].Seq != 10 {
		t.Fatalf("retained seqs = %#v, want 8..10", logs)
	}

	last, alpha := broker.SinceChain("op", "alpha", 0)
	if last != 10 {
		t.Fatalf("chain last = %d, want 10", last)
	}
	if len(alpha) != 1 || alpha[0].Seq != 9 {
		t.Fatalf("alpha logs = %#v, want only retained alpha seq 9", alpha)
	}
}

func TestLogBrokerPublishDoesNotScanHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(32)
	started := time.Now()
	for i := 0; i < 10000; i++ {
		broker.Publish("op", "chain", operatorlog.Entry{Message: "log"})
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("publishing 10000 bounded logs took %s, want under 500ms", elapsed)
	}
	if len(broker.logs) != 32 {
		t.Fatalf("retained logs = %d, want 32", len(broker.logs))
	}
}

func TestSessionClientsKeepIndependentOperationChainAttachments(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	if err := alpha.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaState := alpha.Snapshot()
	if alphaState.ActiveOperation != "redteam-lab" || alphaState.ActiveChain != "alpha" {
		t.Fatalf("alpha attachment = %s/%s, want redteam-lab/alpha", alphaState.ActiveOperation, alphaState.ActiveChain)
	}
	if len(alphaState.Targets) != 1 || alphaState.Targets[0] != "mock://alpha" {
		t.Fatalf("alpha targets = %#v", alphaState.Targets)
	}
	betaState := beta.Snapshot()
	if betaState.ActiveOperation != "redteam-lab" || betaState.ActiveChain != "beta" {
		t.Fatalf("beta attachment = %s/%s, want redteam-lab/beta", betaState.ActiveOperation, betaState.ActiveChain)
	}
	if len(betaState.Targets) != 1 || betaState.Targets[0] != "mock://beta" {
		t.Fatalf("beta targets = %#v", betaState.Targets)
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "redteam-lab", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, log := range alphaLogs.Logs {
		if log.Operation != "redteam-lab" || log.Chain != "alpha" {
			t.Fatalf("alpha poll returned wrong topic: %#v", log)
		}
	}
}

func TestSessionMutationsPersistSnapshots(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := NewSessionClient(context.Background(), client)
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

	if len(persisted) == 0 {
		t.Fatal("no persisted snapshots")
	}
	last := persisted[len(persisted)-1]
	var got operatorsession.PersistedChain
	for _, operation := range last.Operations {
		if operation.Name != "redteam-lab" {
			continue
		}
		for _, chain := range operation.Chains {
			if chain.Name == "alpha" {
				got = chain
			}
		}
	}
	if got.Name != "alpha" {
		t.Fatalf("persisted operations = %#v, want redteam-lab/alpha", last.Operations)
	}
	if !reflect.DeepEqual(got.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted targets = %#v", got.Targets)
	}
	if !reflect.DeepEqual(got.Steps, []operatorsession.Step{{ID: "step-1", ModuleID: "mock-survey"}}) {
		t.Fatalf("persisted steps = %#v", got.Steps)
	}
}

func TestActiveLogsDoesNotPersistSnapshot(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLogToChain("alpha", operatorlogEntryFromTest("existing log")); err != nil {
		t.Fatal(err)
	}
	persistCount := len(persisted)
	if persistCount == 0 {
		t.Fatal("setup did not persist")
	}

	logs := session.ActiveLogs()
	if len(logs) != 1 || logs[0].Message != "existing log" {
		t.Fatalf("active logs = %#v", logs)
	}
	if len(persisted) != persistCount {
		t.Fatalf("persist count = %d, want %d after read-only ActiveLogs", len(persisted), persistCount)
	}
}

func TestSessionRPCPropagatesRequestContext(t *testing.T) {
	server := &Server{moduleSessions: contextCheckingSessionBroker{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.listSessionsRPC(ctx, EmptyRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list sessions error = %v, want context canceled", err)
	}
	if _, err := server.readSessionRPC(ctx, SessionReadRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("read session error = %v, want context canceled", err)
	}
	if _, err := server.writeSessionRPC(ctx, SessionWriteRequest{SessionID: "s1", Data: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write session error = %v, want context canceled", err)
	}
	if _, err := server.closeSessionRPC(ctx, SessionCloseRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("close session error = %v, want context canceled", err)
	}
}

func operatorlogEntryFromTest(message string) operatorlog.Entry {
	return operatorlog.Entry{Message: message}
}

type contextCheckingSessionBroker struct{}

func (contextCheckingSessionBroker) ListSessions(ctx context.Context) ([]run.SessionRef, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) WriteSession(ctx context.Context, _ string, _ []byte) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ReadSession(ctx context.Context, _ string, _ time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) CloseSession(ctx context.Context, _ string) error {
	return contextOrMissing(ctx)
}

func contextOrMissing(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("request context was not propagated")
}

func serveTestDaemon(t *testing.T, endpoint string, runs services.RunService, options ...ServerOption) {
	t.Helper()
	parsed, err := ParseEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(parsed.Network, parsed.Address)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(runs, options...)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
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
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
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
