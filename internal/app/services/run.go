package services

import (
	"context"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

type ModuleRunner interface {
	Run(context.Context, run.Request) (run.Result, error)
}

type ExecuteMockExploitRequest struct {
	ModuleID string
	Target   string
}

type RunService struct {
	runner ModuleRunner
	events EventSink
	ids    IDGenerator
	clock  Clock
}

func NewRunService(runner ModuleRunner, events EventSink, ids IDGenerator, clock Clock) RunService {
	return RunService{
		runner: runner,
		events: events,
		ids:    ids,
		clock:  clock,
	}
}

func (s RunService) ExecuteMockExploit(ctx context.Context, req ExecuteMockExploitRequest) (run.Result, error) {
	runID := s.ids.NewID()
	request, err := run.NewRequest(run.RequestArgs{
		ID:       runID,
		ModuleID: req.ModuleID,
		Target:   req.Target,
	})
	if err != nil {
		return run.Result{}, err
	}
	if err := s.appendRunEvent(ctx, "run.started", request, nil); err != nil {
		return run.Result{}, err
	}
	result, err := s.runner.Run(ctx, request)
	if err != nil {
		return run.Result{}, err
	}
	if err := s.appendRunEvent(ctx, "run.succeeded", request, map[string]string{
		"summary": result.Summary,
	}); err != nil {
		return run.Result{}, err
	}
	return result, nil
}

func (s RunService) appendRunEvent(ctx context.Context, typ string, request run.Request, fields map[string]string) error {
	id, err := event.NewID(s.ids.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType(typ)
	if err != nil {
		return err
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Timestamp: s.clock.Now(),
		Refs: event.Refs{
			RunID:    request.ID,
			ModuleID: request.ModuleID,
			TargetID: request.Target,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return s.events.Append(ctx, evt)
}
