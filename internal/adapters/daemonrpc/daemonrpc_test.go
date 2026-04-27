package daemonrpc

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/modules/mockexploit"
)

func TestClientRunsMockExploitThroughJSONRPC(t *testing.T) {
	socketPath := t.TempDir() + "/hoveld.sock"
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
