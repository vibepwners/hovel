package services

import (
	"context"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

type WorkspaceStore interface {
	InitWorkspace(context.Context, workspace.Workspace) (WorkspaceRecord, error)
}

type WorkspaceRecord struct {
	Workspace workspace.Workspace
	Created   bool
}

type EventSink interface {
	Append(context.Context, event.Event) error
}

type IDGenerator interface {
	NewID() string
}

type Clock interface {
	Now() time.Time
}

type InitWorkspaceRequest struct {
	Name string
	Path string
}

type InitWorkspaceResult struct {
	Workspace workspace.Workspace
	Created   bool
}

type WorkspaceService struct {
	store  WorkspaceStore
	events EventSink
	ids    IDGenerator
	clock  Clock
}

func NewWorkspaceService(store WorkspaceStore, events EventSink, ids IDGenerator, clock Clock) WorkspaceService {
	return WorkspaceService{
		store:  store,
		events: events,
		ids:    ids,
		clock:  clock,
	}
}

func (s WorkspaceService) InitWorkspace(ctx context.Context, req InitWorkspaceRequest) (InitWorkspaceResult, error) {
	id, err := workspace.NewID(s.ids.NewID())
	if err != nil {
		return InitWorkspaceResult{}, err
	}
	name, err := workspace.NewName(req.Name)
	if err != nil {
		return InitWorkspaceResult{}, err
	}
	ws, err := workspace.New(id, name, req.Path)
	if err != nil {
		return InitWorkspaceResult{}, err
	}

	record, err := s.store.InitWorkspace(ctx, ws)
	if err != nil {
		return InitWorkspaceResult{}, err
	}
	if record.Created {
		if err := s.appendWorkspaceInitialized(ctx, record.Workspace); err != nil {
			return InitWorkspaceResult{}, err
		}
	}

	return InitWorkspaceResult(record), nil
}

func (s WorkspaceService) appendWorkspaceInitialized(ctx context.Context, ws workspace.Workspace) error {
	id, err := event.NewID(s.ids.NewID())
	if err != nil {
		return err
	}
	typ, err := event.NewType("workspace.initialized")
	if err != nil {
		return err
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      typ,
		Message:   "workspace initialized",
		Timestamp: s.clock.Now(),
		Refs: event.Refs{
			WorkspaceID: ws.ID.String(),
		},
		Fields: map[string]string{
			"name": ws.Name.String(),
			"path": ws.Path,
		},
	})
	if err != nil {
		return err
	}
	return s.events.Append(ctx, evt)
}
