package run

import (
	"errors"
	"strings"
)

type State string

const (
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
)

type Severity string

const (
	SeverityInfo Severity = "info"
)

type RequestArgs struct {
	ID       string
	ModuleID string
	Target   string
}

type Request struct {
	ID       string
	ModuleID string
	Target   string
}

func NewRequest(args RequestArgs) (Request, error) {
	args.ID = strings.TrimSpace(args.ID)
	args.ModuleID = strings.TrimSpace(args.ModuleID)
	args.Target = strings.TrimSpace(args.Target)
	if args.ID == "" {
		return Request{}, errors.New("run id is required")
	}
	if args.ModuleID == "" {
		return Request{}, errors.New("run module is required")
	}
	if args.Target == "" {
		return Request{}, errors.New("run target is required")
	}
	return Request{
		ID:       args.ID,
		ModuleID: args.ModuleID,
		Target:   args.Target,
	}, nil
}

type Finding struct {
	Title    string
	Severity Severity
	Detail   string
}

type Artifact struct {
	Name string
	Kind string
	Data string
}

type ResultArgs struct {
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
}

type Result struct {
	ID        string
	ModuleID  string
	Target    string
	State     State
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
}

func Succeeded(request Request, args ResultArgs) (Result, error) {
	if strings.TrimSpace(args.Summary) == "" {
		return Result{}, errors.New("run summary is required")
	}
	return Result{
		ID:        request.ID,
		ModuleID:  request.ModuleID,
		Target:    request.Target,
		State:     StateSucceeded,
		Summary:   strings.TrimSpace(args.Summary),
		Findings:  append([]Finding(nil), args.Findings...),
		Artifacts: append([]Artifact(nil), args.Artifacts...),
	}, nil
}
