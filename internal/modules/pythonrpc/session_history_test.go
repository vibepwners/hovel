package pythonrpc

import (
	"context"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/domain/run"
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
