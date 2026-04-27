package apptest

import (
	"context"
	"fmt"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/modules/mockexploit"
)

type Harness struct {
	Workspaces services.WorkspaceService
	Daemons    services.DaemonService
	Runs       services.RunService
	Events     *EventRecorder
}

func NewHarness() Harness {
	store := newMemoryStore()
	events := &EventRecorder{}
	ids := &sequenceIDs{}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	return Harness{
		Workspaces: services.NewWorkspaceService(store, events, ids, clock),
		Daemons:    services.NewDaemonService(store),
		Runs:       services.NewRunService(mockexploit.Runner{}, events, ids, clock),
		Events:     events,
	}
}

func (Harness) InitWorkspace(name, path string) services.InitWorkspaceRequest {
	return services.InitWorkspaceRequest{Name: name, Path: path}
}

func (Harness) DaemonStatus(path string) services.DaemonStatusRequest {
	return services.DaemonStatusRequest{WorkspacePath: path}
}

func (Harness) MockExploit(moduleID, target string) services.ExecuteMockExploitRequest {
	return services.ExecuteMockExploitRequest{ModuleID: moduleID, Target: target}
}

type memoryStore struct {
	workspaces map[string]workspace.Workspace
}

func newMemoryStore() *memoryStore {
	return &memoryStore{workspaces: map[string]workspace.Workspace{}}
}

func (s *memoryStore) InitWorkspace(_ context.Context, ws workspace.Workspace) (services.WorkspaceRecord, error) {
	if existing, ok := s.workspaces[ws.Path]; ok {
		return services.WorkspaceRecord{Workspace: existing, Created: false}, nil
	}
	s.workspaces[ws.Path] = ws
	return services.WorkspaceRecord{Workspace: ws, Created: true}, nil
}

func (s *memoryStore) DaemonStatus(_ context.Context, workspacePath string) (daemon.Status, error) {
	return daemon.NotRunning(workspacePath), nil
}

type EventRecorder struct {
	Events []event.Event
}

func (r *EventRecorder) Append(_ context.Context, evt event.Event) error {
	r.Events = append(r.Events, evt)
	return nil
}

type sequenceIDs struct {
	next int
}

func (s *sequenceIDs) NewID() string {
	s.next++
	return fmt.Sprintf("test-id-%d", s.next)
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}
