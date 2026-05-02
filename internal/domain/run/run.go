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
	ID           string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
}

type Request struct {
	ID           string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
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
		ID:           args.ID,
		ModuleID:     args.ModuleID,
		Target:       args.Target,
		Inputs:       cloneStringMap(args.Inputs),
		ChainConfig:  cloneStringMap(args.ChainConfig),
		TargetConfig: cloneStringMap(args.TargetConfig),
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

type SessionRef struct {
	ID           string
	RunID        string
	ModuleID     string
	Target       string
	Name         string
	Kind         string
	State        string
	Transport    string
	Capabilities []string
}

type SessionChunk struct {
	SessionID string
	Data      []byte
	Closed    bool
}

type LogEntry struct {
	ID             string
	Time           string
	Topic          string
	Kind           string
	Level          string
	Source         string
	Message        string
	Logger         string
	ChainID        string
	ChainName      string
	RunID          string
	Target         string
	ModuleID       string
	ElapsedSeconds *float64
	Fields         map[string]string
	Attributes     map[string]string
}

type ResultArgs struct {
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
	Logs      []LogEntry
	Sessions  []SessionRef
}

type Result struct {
	ID        string
	ModuleID  string
	Target    string
	State     State
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
	Logs      []LogEntry
	Sessions  []SessionRef
}

func Succeeded(request Request, args ResultArgs) (Result, error) {
	return resultWithState(request, StateSucceeded, args)
}

func Failed(request Request, args ResultArgs) (Result, error) {
	return resultWithState(request, StateFailed, args)
}

func resultWithState(request Request, state State, args ResultArgs) (Result, error) {
	if strings.TrimSpace(args.Summary) == "" {
		return Result{}, errors.New("run summary is required")
	}
	return Result{
		ID:        request.ID,
		ModuleID:  request.ModuleID,
		Target:    request.Target,
		State:     state,
		Summary:   strings.TrimSpace(args.Summary),
		Findings:  append([]Finding(nil), args.Findings...),
		Artifacts: append([]Artifact(nil), args.Artifacts...),
		Logs:      cloneLogs(args.Logs),
		Sessions:  cloneSessions(args.Sessions),
	}, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneLogs(logs []LogEntry) []LogEntry {
	out := make([]LogEntry, 0, len(logs))
	for _, log := range logs {
		out = append(out, LogEntry{
			ID:             log.ID,
			Time:           log.Time,
			Topic:          log.Topic,
			Kind:           log.Kind,
			Level:          log.Level,
			Source:         log.Source,
			Message:        log.Message,
			Logger:         log.Logger,
			ChainID:        log.ChainID,
			ChainName:      log.ChainName,
			RunID:          log.RunID,
			Target:         log.Target,
			ModuleID:       log.ModuleID,
			ElapsedSeconds: cloneFloat64(log.ElapsedSeconds),
			Fields:         cloneStringMap(log.Fields),
			Attributes:     cloneStringMap(log.Attributes),
		})
	}
	return out
}

func cloneSessions(sessions []SessionRef) []SessionRef {
	out := make([]SessionRef, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, SessionRef{
			ID:           session.ID,
			RunID:        session.RunID,
			ModuleID:     session.ModuleID,
			Target:       session.Target,
			Name:         session.Name,
			Kind:         session.Kind,
			State:        session.State,
			Transport:    session.Transport,
			Capabilities: append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}
