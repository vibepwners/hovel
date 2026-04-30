package daemonrpc

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/modules/mockexploit"
)

func TestClientRunsMockExploitThroughJSONRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := rpc.NewServer()
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	if err := Register(server, runs); err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server.ServeCodec(jsonrpc.NewServerCodec(conn))
	}()

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
}

func TestSessionClientPublishesModuleAddedLog(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := rpc.NewServer()
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	if err := Register(server, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker())); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

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
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := rpc.NewServer()
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	if err := Register(server, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker())); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

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
