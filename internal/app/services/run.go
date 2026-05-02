package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

type ModuleRunner interface {
	Run(context.Context, run.Request) (run.Result, error)
}

type ModuleExecutionFailure interface {
	error
	ModuleFailureSummary() string
	ModuleFailureDetail() string
}

type moduleExecutionFailure struct {
	summary string
	err     error
}

func NewModuleExecutionFailure(summary string, err error) error {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = "module execution failed"
	}
	return moduleExecutionFailure{summary: summary, err: err}
}

func (e moduleExecutionFailure) Error() string {
	if e.err == nil {
		return e.summary
	}
	return e.summary + ": " + e.err.Error()
}

func (e moduleExecutionFailure) Unwrap() error {
	return e.err
}

func (e moduleExecutionFailure) ModuleFailureSummary() string {
	return e.summary
}

func (e moduleExecutionFailure) ModuleFailureDetail() string {
	if e.err == nil {
		return e.summary
	}
	return e.err.Error()
}

type ExecuteMockExploitRequest struct {
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted time.Time
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
	return s.ExecuteModule(ctx, ExecuteModuleRequest(req))
}

type ExecuteModuleRequest struct {
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted time.Time
}

func (s RunService) ExecuteModule(ctx context.Context, req ExecuteModuleRequest) (run.Result, error) {
	runID := s.ids.NewID()
	request, err := run.NewRequest(run.RequestArgs{
		ID:           runID,
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
	})
	if err != nil {
		return run.Result{}, err
	}
	startFields := map[string]string{}
	if !req.ThrowStarted.IsZero() {
		startFields["throwStarted"] = req.ThrowStarted.Format(time.RFC3339Nano)
	}
	if err := s.appendRunEvent(ctx, "run.started", request, startFields); err != nil {
		return run.Result{}, err
	}
	result, err := s.runner.Run(ctx, request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return run.Result{}, ctxErr
		}
		var moduleFailure ModuleExecutionFailure
		if !errors.As(err, &moduleFailure) {
			return run.Result{}, err
		}
		result, err = failedModuleResult(s.clock, request, moduleFailure)
		if err != nil {
			return run.Result{}, err
		}
	}
	eventType := "run.succeeded"
	if result.State == run.StateFailed {
		eventType = "run.failed"
	}
	if err := s.appendRunEvent(ctx, eventType, request, map[string]string{
		"summary": result.Summary,
	}); err != nil {
		return run.Result{}, err
	}
	return result, nil
}

func failedModuleResult(clock Clock, request run.Request, failure ModuleExecutionFailure) (run.Result, error) {
	summary := failure.ModuleFailureSummary()
	detail := failure.ModuleFailureDetail()
	return run.Failed(request, run.ResultArgs{
		Summary: summary,
		Logs: []run.LogEntry{{
			Kind:     "event",
			Time:     clock.Now().Format(time.RFC3339Nano),
			Level:    "error",
			Source:   "host",
			Message:  "module execution failed",
			RunID:    request.ID,
			Target:   request.Target,
			ModuleID: request.ModuleID,
			Fields:   map[string]string{"error": detail},
		}},
	})
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
