package pythonrpc

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/vibepwners/hovel/internal/domain/run"
)

func TestBrokerSessionHistoryIsBounded(t *testing.T) {
	session := newBrokerSession(run.SessionRef{ID: "s1"}, nil, 5)

	session.appendData([]byte("hello"))
	session.appendData([]byte(" world"))

	chunk := session.tail("s1", run.SessionTailOptions{})
	if got := string(chunk.Data); got != "world" {
		t.Fatalf("history = %q, want last bounded bytes", got)
	}
}

func TestBrokerSessionTailLinesHandlesLFAndCRLF(t *testing.T) {
	session := newBrokerSession(run.SessionRef{ID: "s1"}, nil, 1024)
	session.appendData([]byte("one\r\ntwo\nthree\r\nfour\n"))

	chunk := session.tail("s1", run.SessionTailOptions{MaxLines: 2})
	if got := string(chunk.Data); got != "three\r\nfour\n" {
		t.Fatalf("tail lines = %q, want last two lines", got)
	}
}

func TestBrokerSessionTailConsumeClearsPendingBytes(t *testing.T) {
	session := newBrokerSession(run.SessionRef{ID: "s1"}, nil, 1024)
	session.appendData([]byte("old\nnew\n"))

	chunk := session.tail("s1", run.SessionTailOptions{MaxLines: 1, Consume: true})
	if got := string(chunk.Data); got != "new\n" {
		t.Fatalf("tail lines = %q, want last line", got)
	}
	chunk, err := session.read(context.Background(), "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.Data) != 0 {
		t.Fatalf("pending data = %q, want consumed", string(chunk.Data))
	}
}

func TestBrokerSessionPreservesDatagramBoundaries(t *testing.T) {
	session := newBrokerSession(run.SessionRef{
		ID:           "s1",
		Capabilities: []string{run.SessionCapabilityDatagram},
	}, nil, 1024)
	session.appendData([]byte("first"))
	session.appendData([]byte("second"))

	first, err := session.read(context.Background(), "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.read(context.Background(), "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Data) != "first" || string(second.Data) != "second" {
		t.Fatalf("datagrams = %q, %q; want preserved frames", first.Data, second.Data)
	}
}

func TestBrokerSessionTailConsumeClearsPendingDatagrams(t *testing.T) {
	session := newBrokerSession(run.SessionRef{
		ID:           "s1",
		Capabilities: []string{run.SessionCapabilityDatagram},
	}, nil, 1024)
	session.appendData([]byte("datagram"))
	session.tail("s1", run.SessionTailOptions{Consume: true})

	chunk, err := session.read(context.Background(), "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.Data) != 0 {
		t.Fatalf("pending datagram = %q, want consumed", chunk.Data)
	}
}

func TestBrokerSessionCloseCancelsPumpContext(t *testing.T) {
	session := newBrokerSession(run.SessionRef{ID: "s1"}, nil, 1024)
	session.closeLocal()

	select {
	case <-session.ctx.Done():
	default:
		t.Fatal("session pump context was not canceled")
	}
}

func TestSessionBrokerListsSessionsInAdoptionOrder(t *testing.T) {
	broker := NewSessionBroker()
	broker.sessions["session-z"] = &brokerSession{ref: run.SessionRef{ID: "session-z"}, order: 0}
	broker.sessions["session-a"] = &brokerSession{ref: run.SessionRef{ID: "session-a"}, order: 1}

	sessions, err := broker.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %#v, want two sessions", sessions)
	}
	if sessions[0].ID != "session-z" || sessions[1].ID != "session-a" {
		t.Fatalf("session order = %q, %q; want adoption order", sessions[0].ID, sessions[1].ID)
	}
}

func TestSessionBrokerRejectsDuplicateSessionWithoutReplacingExisting(t *testing.T) {
	broker := NewSessionBroker()
	existing := &brokerSession{ref: run.SessionRef{ID: "session-1"}}
	broker.sessions["session-1"] = existing

	err := broker.adopt(&moduleProcess{}, []run.SessionRef{{ID: "  session-1  "}})
	if err == nil || !strings.Contains(err.Error(), "already tracked") {
		t.Fatalf("adopt error = %v, want duplicate session rejection", err)
	}
	if broker.sessions["session-1"] != existing {
		t.Fatal("duplicate adoption replaced the existing session")
	}
}

func TestNormalizeSessionRefsRejectsInvalidIDs(t *testing.T) {
	tests := []struct {
		name     string
		sessions []run.SessionRef
	}{
		{name: "blank", sessions: []run.SessionRef{{ID: "   "}}},
		{name: "duplicate", sessions: []run.SessionRef{{ID: "session-1"}, {ID: " session-1 "}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeSessionRefs(test.sessions); err == nil {
				t.Fatal("normalizeSessionRefs returned nil error")
			}
		})
	}
}

func TestSessionBrokerRemovesExpectedSessionOnce(t *testing.T) {
	broker := NewSessionBroker()
	expected := newBrokerSession(
		run.SessionRef{ID: "session-1"},
		&moduleProcess{},
		defaultSessionHistoryBytes,
	)
	broker.sessions["session-1"] = expected

	const callers = 8
	start := make(chan struct{})
	results := make(chan bool, callers)
	var calls sync.WaitGroup
	for range callers {
		calls.Add(1)
		go func() {
			defer calls.Done()
			<-start
			_, removed := broker.removeSession("session-1", expected)
			results <- removed
		}()
	}
	close(start)
	calls.Wait()
	close(results)

	owners := 0
	for removed := range results {
		if removed {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("successful removals = %d, want 1", owners)
	}
}
