package daemonrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/testmodules/mockexploit"
)

func TestClientRunsMockExploitThroughDaemonRPC(t *testing.T) {
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
	defer closeTestClient(t, client)

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

func TestClientCanDialDaemonRPCOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
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
	defer closeTestClient(t, client)

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
	defer closeTestClient(t, client)
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
	defer closeTestClient(t, client)
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

func TestSessionLogFloodIsBoundedThroughRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(64)))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("flood-op"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("flood"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if err := session.AppendLog(operatorlog.Info("flood", "log")); err != nil {
			t.Fatal(err)
		}
	}

	logs, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", 0)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Last < 250 {
		t.Fatalf("last = %d, want at least 250 flood logs", logs.Last)
	}
	if len(logs.Logs) != 64 {
		t.Fatalf("retained logs = %d, want broker limit 64", len(logs.Logs))
	}
	wantFirst := logs.Last - uint64(len(logs.Logs)) + 1
	if logs.Logs[0].Seq != wantFirst || logs.Logs[len(logs.Logs)-1].Seq != logs.Last {
		t.Fatalf("retained seq range = %d..%d, want contiguous tail %d..%d", logs.Logs[0].Seq, logs.Logs[len(logs.Logs)-1].Seq, wantFirst, logs.Last)
	}

	next, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", logs.Last)
	if err != nil {
		t.Fatal(err)
	}
	if next.Last != logs.Last || len(next.Logs) != 0 {
		t.Fatalf("poll after cursor = %#v, want no new logs", next)
	}
}

func TestConcurrentSessionClientsAppendLogsWithoutCrossChainContamination(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(512)))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	for _, setup := range []struct {
		name    string
		session *SessionClient
		chain   string
	}{
		{name: "alpha", session: alpha, chain: "alpha"},
		{name: "beta", session: beta, chain: "beta"},
	} {
		if err := setup.session.UseOperation("concurrent-op"); err != nil {
			t.Fatalf("%s operation: %v", setup.name, err)
		}
		if err := setup.session.UseChain(setup.chain); err != nil {
			t.Fatalf("%s chain: %v", setup.name, err)
		}
	}
	alphaCursor, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	betaCursor, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", 0)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	appendLogs := func(session *SessionClient, chain string) {
		<-start
		for i := 0; i < 50; i++ {
			if err := session.AppendLog(operatorlog.Info("concurrent", fmt.Sprintf("%s-%02d", chain, i))); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}
	go appendLogs(alpha, "alpha")
	go appendLogs(beta, "beta")
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", alphaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	betaLogs, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", betaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	assertConcurrentChainLogs(t, "alpha", alphaLogs.Logs)
	assertConcurrentChainLogs(t, "beta", betaLogs.Logs)
}

func assertConcurrentChainLogs(t *testing.T, chain string, logs []PublishedLog) {
	t.Helper()
	if len(logs) != 50 {
		t.Fatalf("%s log count = %d, want 50: %#v", chain, len(logs), logs)
	}
	for i, log := range logs {
		if log.Operation != "concurrent-op" || log.Chain != chain {
			t.Fatalf("%s log %d topic = %s/%s, want concurrent-op/%s: %#v", chain, i, log.Operation, log.Chain, chain, log)
		}
		wantMessage := fmt.Sprintf("%s-%02d", chain, i)
		if log.Entry.Message != wantMessage {
			t.Fatalf("%s log %d message = %q, want %q", chain, i, log.Entry.Message, wantMessage)
		}
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
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

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
	if got, want := alphaState.Targets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha targets = %#v, want %#v", got, want)
	}
	betaState := beta.Snapshot()
	if betaState.ActiveOperation != "redteam-lab" || betaState.ActiveChain != "beta" {
		t.Fatalf("beta attachment = %s/%s, want redteam-lab/beta", betaState.ActiveOperation, betaState.ActiveChain)
	}
	if got, want := betaState.Targets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta targets = %#v, want %#v", got, want)
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
	defer closeTestClient(t, client)
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
	if err := session.CreateTargetSet("lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("lab", "mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	if len(persisted) == 0 {
		t.Fatal("no persisted snapshots")
	}
	last := persisted[len(persisted)-1]
	var gotOperation operatorsession.PersistedOperation
	var got operatorsession.PersistedChain
	for _, operation := range last.Operations {
		if operation.Name != "redteam-lab" {
			continue
		}
		gotOperation = operation
		for _, chain := range operation.Chains {
			if chain.Name == "alpha" {
				got = chain
			}
		}
	}
	if got.Name != "alpha" {
		t.Fatalf("persisted operations = %#v, want redteam-lab/alpha", last.Operations)
	}
	if !reflect.DeepEqual(gotOperation.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted operation targets = %#v", gotOperation.Targets)
	}
	if !reflect.DeepEqual(gotOperation.TargetSets, []operatorsession.TargetSet{{Name: "lab", Targets: []string{"mock://alpha"}}}) {
		t.Fatalf("persisted operation target sets = %#v", gotOperation.TargetSets)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("persisted chain targets = %#v, want none", got.Targets)
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
	defer closeTestClient(t, client)
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

func TestClientCanAttachHeartbeatAndDetachOperatorEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	clock := &mutableClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	serveTestDaemon(t, socketPath, runs, WithOperatorClock(clock))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	attached, err := client.AttachEntity(context.Background(), AttachEntityRequest{
		ID:           "entity-mcp",
		Kind:         "mcp",
		DisplayName:  "codex",
		Agent:        true,
		Operation:    "redteam-lab",
		ActiveChain:  "alpha",
		Capabilities: []string{"tools", "resources"},
		PolicyTags:   []string{"allow-plan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attached.Entity.ID != "entity-mcp" || attached.Entity.Kind != "mcp" || !attached.Entity.Agent {
		t.Fatalf("attached entity = %#v", attached.Entity)
	}
	if attached.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || attached.Entity.LastSeenAt != "2026-06-20T12:00:00Z" {
		t.Fatalf("attached times = %s/%s", attached.Entity.ConnectedAt, attached.Entity.LastSeenAt)
	}

	clock.now = clock.now.Add(30 * time.Second)
	heartbeat, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr("redteam-lab"),
		ActiveChain: stringPtr("bravo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || heartbeat.Entity.LastSeenAt != "2026-06-20T12:00:30Z" {
		t.Fatalf("heartbeat times = %s/%s", heartbeat.Entity.ConnectedAt, heartbeat.Entity.LastSeenAt)
	}
	if heartbeat.Entity.ActiveChain != "bravo" {
		t.Fatalf("heartbeat active chain = %q, want bravo", heartbeat.Entity.ActiveChain)
	}

	entities, err := client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entityIDs(entities.Entities), []string{"entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entities = %#v, want %#v", got, want)
	}

	cleared, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr(""),
		ActiveChain: stringPtr(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Entity.Operation != "" || cleared.Entity.ActiveChain != "" {
		t.Fatalf("cleared entity operation/chain = %q/%q, want empty", cleared.Entity.Operation, cleared.Entity.ActiveChain)
	}

	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after clearing operation = %#v, want none for redteam-lab", entities.Entities)
	}

	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-mcp"}); err != nil {
		t.Fatal(err)
	}
	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after detach = %#v, want none", entities.Entities)
	}
}

func TestOperatorEntityAttachmentsDoNotPersistSessionSnapshots(t *testing.T) {
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
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{ID: "entity-cli", Operation: stringPtr("redteam-lab")}); err != nil {
		t.Fatal(err)
	}
	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-cli"}); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 0 {
		t.Fatalf("persisted snapshots = %#v, want none for live operator entity lifecycle", persisted)
	}
}

func TestClientCoordinatesLaunchKeyApprovalsFromLiveEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}

	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:             "pending-1",
		Operation:      "redteam-lab",
		Chain:          "alpha",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready {
		t.Fatalf("pending throw unexpectedly ready: %#v", pending)
	}
	if got, want := pending.MissingApproverIDs, []string{"entity-cli", "entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing approvers = %#v, want %#v", got, want)
	}

	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil error before approvals")
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-mcp",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready || !reflect.DeepEqual(pending.MissingApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after mcp approval = %#v, want entity-cli missing", pending)
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-cli",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || len(pending.MissingApproverIDs) != 0 {
		t.Fatalf("pending after all approvals = %#v, want ready", pending)
	}
	if ready, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil || !ready.Ready {
		t.Fatalf("RequirePendingThrowReady = %#v, %v; want ready", ready, err)
	}
}

func TestLaunchKeyPendingThrowSnapshotsRequiredEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:        "pending-1",
		Operation: "redteam-lab",
		Chain:     "alpha",
		PlanHash:  "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pending.RequiredApproverIDs, []string{"entity-cli"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required approvers = %#v, want snapshot %#v", got, want)
	}

	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:       "pending-1",
		EntityID: "entity-cli",
		PlanHash: "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || !reflect.DeepEqual(pending.RequiredApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after late attachment = %#v, want original snapshot ready", pending)
	}
}

func TestClientCancelsPendingLaunchKeyThrow(t *testing.T) {
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
	defer closeTestClient(t, client)
	if _, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{ID: "pending-1", Operation: "redteam-lab", Chain: "alpha", PlanHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelPendingThrow(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil after cancel")
	}
}

func TestClientQueriesAndOverridesLaunchKeyPolicy(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAnyone}),
	)
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	policy, err := client.GetLaunchKeyPolicy(context.Background(), LaunchKeyPolicyRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Policy.Mode != "anyone" {
		t.Fatalf("default policy = %#v, want anyone", policy)
	}
	policy, err = client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum", Quorum: 2, HeartbeatTimeout: "30s"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Operation != "redteam-lab" || policy.Policy.Mode != "quorum" || policy.Policy.Quorum != 2 || policy.Policy.HeartbeatTimeout != "30s" {
		t.Fatalf("set policy = %#v, want quorum override", policy)
	}
	if _, err := client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum"}); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("invalid quorum error = %v, want quorum error", err)
	}
}

func entityIDs(entities []OperatorEntity) []string {
	ids := make([]string, 0, len(entities))
	for _, entity := range entities {
		ids = append(ids, entity.ID)
	}
	return ids
}

func stringPtr(value string) *string {
	return &value
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
	if _, err := server.tailSessionRPC(ctx, SessionTailRequest{SessionID: "s1", MaxLines: 20}); !errors.Is(err, context.Canceled) {
		t.Fatalf("tail session error = %v, want context canceled", err)
	}
	if _, err := server.writeSessionRPC(ctx, SessionWriteRequest{SessionID: "s1", Data: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write session error = %v, want context canceled", err)
	}
	if _, err := server.closeSessionRPC(ctx, SessionCloseRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("close session error = %v, want context canceled", err)
	}
	if _, err := server.listSessionCommandsRPC(ctx, SessionCommandListRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list session commands error = %v, want context canceled", err)
	}
	if _, err := server.runSessionCommandRPC(ctx, SessionCommandRunRequest{SessionID: "s1", Request: run.PayloadCommandRequest{Command: "process.list"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("run session command error = %v, want context canceled", err)
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

func (contextCheckingSessionBroker) TailSession(ctx context.Context, _ string, _ run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) CloseSession(ctx context.Context, _ string) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ListSessionCommands(ctx context.Context, _ string, _ run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) RunSessionCommand(ctx context.Context, _ string, _ run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, contextOrMissing(ctx)
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
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("serve test daemon: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("close test daemon server: %v", err)
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("close test daemon listener: %v", err)
		}
	})
}

func closeTestClient(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Logf("close daemon rpc client: %v", err)
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
			t.Logf("remove temp dir: %v", err)
		}
	})
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

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	return c.now
}
