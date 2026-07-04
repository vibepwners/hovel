package services

import (
	"context"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

func TestInitWorkspaceCreatesModelAndEmitsEvent(t *testing.T) {
	store := newFakeWorkspaceStore()
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"workspace-1", "event-1"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewWorkspaceService(store, events, ids, clock)

	result, err := service.InitWorkspace(context.Background(), InitWorkspaceRequest{
		Name: "lab",
		Path: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created {
		t.Fatal("Created = false, want true")
	}
	if result.Workspace.ID.String() != "workspace-1" {
		t.Fatalf("workspace ID = %q", result.Workspace.ID)
	}
	if result.Workspace.Name.String() != "lab" {
		t.Fatalf("workspace name = %q", result.Workspace.Name)
	}
	if result.Workspace.Path != ".hovel" {
		t.Fatalf("workspace path = %q", result.Workspace.Path)
	}
	if len(events.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events.events))
	}
	if events.events[0].Type.String() != "workspace.initialized" {
		t.Fatalf("event type = %q", events.events[0].Type)
	}
	if events.events[0].Refs.WorkspaceID != "workspace-1" {
		t.Fatalf("workspace ref = %q", events.events[0].Refs.WorkspaceID)
	}
}

func TestInitWorkspaceIsIdempotent(t *testing.T) {
	store := newFakeWorkspaceStore()
	events := &fakeEventSink{}
	ids := &sequenceIDs{values: []string{"workspace-1", "event-1", "workspace-2", "event-2"}}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	service := NewWorkspaceService(store, events, ids, clock)

	first, err := service.InitWorkspace(context.Background(), InitWorkspaceRequest{Name: "lab", Path: ".hovel"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.InitWorkspace(context.Background(), InitWorkspaceRequest{Name: "lab", Path: ".hovel"})
	if err != nil {
		t.Fatal(err)
	}

	if !first.Created {
		t.Fatal("first Created = false, want true")
	}
	if second.Created {
		t.Fatal("second Created = true, want false")
	}
	if second.Workspace.ID != first.Workspace.ID {
		t.Fatalf("second workspace ID = %q, want %q", second.Workspace.ID, first.Workspace.ID)
	}
	if len(events.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events.events))
	}
}

type fakeWorkspaceStore struct {
	workspaces map[string]workspace.Workspace
}

func newFakeWorkspaceStore() *fakeWorkspaceStore {
	return &fakeWorkspaceStore{workspaces: map[string]workspace.Workspace{}}
}

func (s *fakeWorkspaceStore) InitWorkspace(_ context.Context, ws workspace.Workspace) (WorkspaceRecord, error) {
	if existing, ok := s.workspaces[ws.Path]; ok {
		return WorkspaceRecord{Workspace: existing, Created: false}, nil
	}
	s.workspaces[ws.Path] = ws
	return WorkspaceRecord{Workspace: ws, Created: true}, nil
}

type fakeEventSink struct {
	events []event.Event
}

func (s *fakeEventSink) Append(_ context.Context, evt event.Event) error {
	s.events = append(s.events, evt)
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
