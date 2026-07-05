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
	Operation    string
	Chain        string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	Agent        *AgentContext
}

type Request struct {
	ID           string
	Operation    string
	Chain        string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	Agent        *AgentContext
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
		Operation:    strings.TrimSpace(args.Operation),
		Chain:        strings.TrimSpace(args.Chain),
		ModuleID:     args.ModuleID,
		Target:       args.Target,
		Inputs:       cloneStringMap(args.Inputs),
		ChainConfig:  cloneStringMap(args.ChainConfig),
		TargetConfig: cloneStringMap(args.TargetConfig),
		Agent:        cloneAgentContext(args.Agent),
	}, nil
}

type AgentEntity struct {
	ID          string `json:"id,omitempty"`
	Kind        string `json:"kind,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Agent       bool   `json:"agent,omitempty"`
}

type AgentContext struct {
	Schema        string      `json:"schema,omitempty"`
	Entity        AgentEntity `json:"entity,omitempty"`
	Operation     string      `json:"operation,omitempty"`
	Chain         string      `json:"chain,omitempty"`
	PlanID        string      `json:"planId,omitempty"`
	PlanHash      string      `json:"planHash,omitempty"`
	ApprovalState string      `json:"approvalState,omitempty"`
	Phase         string      `json:"phase,omitempty"`
	Resources     []string    `json:"resources,omitempty"`
}

type AgentHint struct {
	Schema     string            `json:"schema,omitempty"`
	Phase      string            `json:"phase,omitempty"`
	Audience   string            `json:"audience,omitempty"`
	Risk       string            `json:"risk,omitempty"`
	AppliesTo  map[string]string `json:"appliesTo,omitempty"`
	Text       string            `json:"text,omitempty"`
	Provenance map[string]string `json:"provenance,omitempty"`
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
	Path string
}

type SessionRef struct {
	ID                 string
	RunID              string
	ModuleID           string
	Target             string
	Name               string
	Kind               string
	State              string
	Transport          string
	InstalledPayloadID string
	Capabilities       []string
}

type SessionChunk struct {
	SessionID string
	Data      []byte
	Closed    bool
}

type SessionTailOptions struct {
	MaxBytes int
	MaxLines int
	Consume  bool
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
	Summary           string
	Findings          []Finding
	Artifacts         []Artifact
	Logs              []LogEntry
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
	AgentHints        []AgentHint
}

type Result struct {
	ID                string
	ModuleID          string
	Target            string
	State             State
	Summary           string
	Findings          []Finding
	Artifacts         []Artifact
	Logs              []LogEntry
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
	AgentHints        []AgentHint
}

type PayloadProviderRecord struct {
	ProviderID    string         `json:"providerId,omitempty"`
	Schema        string         `json:"schema,omitempty"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
	Descriptor    map[string]any `json:"descriptor,omitempty"`
}

type InstalledPayloadDescriptor struct {
	Provider                 string                 `json:"provider"`
	PayloadID                string                 `json:"payloadId"`
	PayloadVersion           string                 `json:"payloadVersion,omitempty"`
	Target                   string                 `json:"target"`
	TargetID                 string                 `json:"targetId,omitempty"`
	State                    string                 `json:"state,omitempty"`
	Transport                string                 `json:"transport,omitempty"`
	Endpoint                 string                 `json:"endpoint,omitempty"`
	InstanceKey              string                 `json:"instanceKey,omitempty"`
	StampID                  string                 `json:"stampId,omitempty"`
	ArtifactIDs              []string               `json:"artifactIds,omitempty"`
	SupportsReconnect        bool                   `json:"supportsReconnect,omitempty"`
	SupportsMultipleSessions bool                   `json:"supportsMultipleSessions,omitempty"`
	Reconnect                *PayloadProviderRecord `json:"reconnect,omitempty"`
	Cleanup                  *PayloadProviderRecord `json:"cleanup,omitempty"`
	Metadata                 map[string]string      `json:"metadata,omitempty"`
}

type PayloadQuery struct {
	Target       string            `json:"target,omitempty"`
	Kind         string            `json:"kind,omitempty"`
	Platform     string            `json:"platform,omitempty"`
	OS           string            `json:"os,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Format       string            `json:"format,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Transport    string            `json:"transport,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

type PayloadInfo struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Kind         string           `json:"kind,omitempty"`
	Platform     string           `json:"platform"`
	OS           string           `json:"os,omitempty"`
	Arch         string           `json:"arch"`
	MinOS        string           `json:"minOS,omitempty"`
	TestedOS     []string         `json:"testedOS,omitempty"`
	Formats      []string         `json:"formats"`
	Tags         []string         `json:"tags,omitempty"`
	Capabilities []string         `json:"capabilities"`
	Transport    PayloadTransport `json:"transport"`
	Session      PayloadSession   `json:"session"`
}

type PayloadTransport struct {
	Kind      string `json:"kind"`
	Encrypted bool   `json:"encrypted"`
}

type PayloadSession struct {
	Kind                     string `json:"kind"`
	Acquisition              string `json:"acquisition"`
	RequiresPreThrowListener bool   `json:"requiresPreThrowListener"`
	RequiresPostThrowConnect bool   `json:"requiresPostThrowConnect"`
	Owner                    string `json:"owner"`
}

type GeneratePayloadRequest struct {
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target"`
	PayloadID string            `json:"payloadId"`
	Format    string            `json:"format"`
	Config    map[string]string `json:"config,omitempty"`
}

type PayloadArtifactSet struct {
	Primary   PayloadArtifact   `json:"primary"`
	Artifacts []PayloadArtifact `json:"artifacts"`
}

type PayloadArtifact struct {
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Kind     string   `json:"kind,omitempty"`
	Format   string   `json:"format"`
	OS       string   `json:"os,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Encoding string   `json:"encoding"`
	Bytes    string   `json:"bytes,omitempty"`
	Handle   string   `json:"handle,omitempty"`
	Size     int64    `json:"size,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
}

type PayloadCommandListRequest struct {
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Target             string                 `json:"target,omitempty"`
	PayloadID          string                 `json:"payloadId,omitempty"`
	Config             map[string]string      `json:"config,omitempty"`
	Reconnect          *PayloadProviderRecord `json:"reconnect,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type PayloadCommand struct {
	Name         string                   `json:"name"`
	Summary      string                   `json:"summary,omitempty"`
	Usage        string                   `json:"usage,omitempty"`
	ReadOnly     bool                     `json:"readOnly,omitempty"`
	Destructive  bool                     `json:"destructive,omitempty"`
	Capabilities []string                 `json:"capabilities,omitempty"`
	Arguments    []PayloadCommandArgument `json:"arguments,omitempty"`
}

type PayloadCommandArgument struct {
	Name     string `json:"name"`
	Help     string `json:"help,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type PayloadCommandRequest struct {
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Target             string                 `json:"target,omitempty"`
	PayloadID          string                 `json:"payloadId,omitempty"`
	Command            string                 `json:"command"`
	Args               []string               `json:"args,omitempty"`
	InputPath          string                 `json:"inputPath,omitempty"`
	InputData          string                 `json:"inputData,omitempty"`
	InputEncoding      string                 `json:"inputEncoding,omitempty"`
	Config             map[string]string      `json:"config,omitempty"`
	Reconnect          *PayloadProviderRecord `json:"reconnect,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type PayloadCommandResult struct {
	Command   string            `json:"command"`
	Summary   string            `json:"summary,omitempty"`
	Stdout    string            `json:"stdout,omitempty"`
	Stderr    string            `json:"stderr,omitempty"`
	Artifacts []Artifact        `json:"artifacts,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
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
		InstalledPayloads: CloneInstalledPayloads(
			args.InstalledPayloads,
		),
		AgentHints: cloneAgentHints(args.AgentHints),
	}, nil
}

func cloneAgentContext(agent *AgentContext) *AgentContext {
	if agent == nil {
		return nil
	}
	return &AgentContext{
		Schema:        agent.Schema,
		Entity:        agent.Entity,
		Operation:     agent.Operation,
		Chain:         agent.Chain,
		PlanID:        agent.PlanID,
		PlanHash:      agent.PlanHash,
		ApprovalState: agent.ApprovalState,
		Phase:         agent.Phase,
		Resources:     append([]string(nil), agent.Resources...),
	}
}

func cloneAgentHints(hints []AgentHint) []AgentHint {
	out := make([]AgentHint, 0, len(hints))
	for _, hint := range hints {
		out = append(out, AgentHint{
			Schema:     hint.Schema,
			Phase:      hint.Phase,
			Audience:   hint.Audience,
			Risk:       hint.Risk,
			AppliesTo:  cloneStringMap(hint.AppliesTo),
			Text:       hint.Text,
			Provenance: cloneStringMap(hint.Provenance),
		})
	}
	return out
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
			ID:                 session.ID,
			RunID:              session.RunID,
			ModuleID:           session.ModuleID,
			Target:             session.Target,
			Name:               session.Name,
			Kind:               session.Kind,
			State:              session.State,
			Transport:          session.Transport,
			InstalledPayloadID: session.InstalledPayloadID,
			Capabilities:       append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func CloneInstalledPayloads(payloads []InstalledPayloadDescriptor) []InstalledPayloadDescriptor {
	out := make([]InstalledPayloadDescriptor, 0, len(payloads))
	for _, payload := range payloads {
		out = append(out, InstalledPayloadDescriptor{
			Provider:                 payload.Provider,
			PayloadID:                payload.PayloadID,
			PayloadVersion:           payload.PayloadVersion,
			Target:                   payload.Target,
			TargetID:                 payload.TargetID,
			State:                    payload.State,
			Transport:                payload.Transport,
			Endpoint:                 payload.Endpoint,
			InstanceKey:              payload.InstanceKey,
			StampID:                  payload.StampID,
			ArtifactIDs:              append([]string(nil), payload.ArtifactIDs...),
			SupportsReconnect:        payload.SupportsReconnect,
			SupportsMultipleSessions: payload.SupportsMultipleSessions,
			Reconnect:                ClonePayloadProviderRecord(payload.Reconnect),
			Cleanup:                  ClonePayloadProviderRecord(payload.Cleanup),
			Metadata:                 cloneStringMap(payload.Metadata),
		})
	}
	return out
}

func ClonePayloadProviderRecord(record *PayloadProviderRecord) *PayloadProviderRecord {
	if record == nil {
		return nil
	}
	return &PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    cloneAnyMap(record.Descriptor),
	}
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
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
