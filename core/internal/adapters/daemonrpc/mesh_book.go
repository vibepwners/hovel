package daemonrpc

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/mesh"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const (
	// MeshOperationKindTask records a provider-owned task invocation.
	MeshOperationKindTask MeshOperationKind = "task"
	// MeshOperationKindStream records a provider-owned session flow.
	MeshOperationKindStream MeshOperationKind = "stream"
	// MeshOperationKindBridge records a daemon-owned local socket endpoint.
	MeshOperationKindBridge MeshOperationKind = "bridge"

	// MeshOperationStateStarted means invocation has begun but is not active.
	MeshOperationStateStarted MeshOperationState = "started"
	// MeshOperationStateActive means a long-lived session flow is available.
	MeshOperationStateActive MeshOperationState = "active"
	// MeshOperationStateSucceeded means a task completed successfully.
	MeshOperationStateSucceeded MeshOperationState = "succeeded"
	// MeshOperationStateFailed means invocation or cleanup failed.
	MeshOperationStateFailed MeshOperationState = "failed"
	// MeshOperationStateClosed means a stream or bridge closed cleanly.
	MeshOperationStateClosed MeshOperationState = "closed"
)

// MeshOperationKind identifies the daemon-side class of Mesh work.
type MeshOperationKind string

// MeshOperationState describes daemon-side Mesh bookkeeping lifecycle state.
type MeshOperationState string

// MeshOperation is daemon-side bookkeeping for provider-owned mesh work.
// It records enough routing context to audit node tasks, routed sessions, and
// daemon-owned local bridges, including future "throw through a node" flows
// that bridge an exploit to a destination reachable from a mesh node or route.
type MeshOperation struct {
	ID              string             `json:"id"`
	Kind            MeshOperationKind  `json:"kind"`
	State           MeshOperationState `json:"state"`
	ModuleID        string             `json:"moduleId"`
	RunID           string             `json:"runId,omitempty"`
	TaskID          string             `json:"taskId,omitempty"`
	TaskKind        mesh.TaskKind      `json:"taskKind,omitempty"`
	SessionID       string             `json:"sessionId,omitempty"`
	SessionIDs      []string           `json:"sessionIds,omitempty"`
	NodeID          string             `json:"nodeId,omitempty"`
	Target          string             `json:"target,omitempty"`
	RouteID         string             `json:"routeId,omitempty"`
	DestinationHost string             `json:"destinationHost,omitempty"`
	DestinationPort int                `json:"destinationPort,omitempty"`
	Protocol        string             `json:"protocol,omitempty"`
	LocalAddress    string             `json:"localAddress,omitempty"`
	Summary         string             `json:"summary,omitempty"`
	Error           string             `json:"error,omitempty"`
	StartedAt       string             `json:"startedAt"`
	UpdatedAt       string             `json:"updatedAt"`
	ClosedAt        string             `json:"closedAt,omitempty"`
}

// MeshOperationListRequest filters daemon Mesh bookkeeping records.
type MeshOperationListRequest struct {
	ModuleID  string             `json:"moduleId,omitempty"`
	RunID     string             `json:"runId,omitempty"`
	NodeID    string             `json:"nodeId,omitempty"`
	SessionID string             `json:"sessionId,omitempty"`
	Kind      MeshOperationKind  `json:"kind,omitempty"`
	State     MeshOperationState `json:"state,omitempty"`
}

// MeshOperationListResponse contains matching daemon Mesh bookkeeping records.
type MeshOperationListResponse struct {
	Operations []MeshOperation `json:"operations"`
}

// MeshBook stores in-memory daemon bookkeeping for mesh tasks, routed sessions,
// and local bridges.
type MeshBook struct {
	mu         sync.RWMutex
	next       uint64
	operations []MeshOperation
	byID       map[string]int
}

// NewMeshBook creates an empty in-memory Mesh operation book.
func NewMeshBook() *MeshBook {
	return &MeshBook{
		operations: []MeshOperation{},
		byID:       map[string]int{},
	}
}

// StartTask records a provider-owned Mesh task before it is invoked.
func (b *MeshBook) StartTask(moduleID string, request mesh.TaskRequest, now time.Time) MeshOperation {
	return b.start(MeshOperation{
		Kind:            MeshOperationKindTask,
		State:           MeshOperationStateStarted,
		ModuleID:        moduleID,
		RunID:           request.RunID,
		TaskID:          request.TaskID,
		TaskKind:        request.Kind,
		NodeID:          request.NodeID,
		Target:          request.Target,
		RouteID:         routeID(request.Route),
		DestinationHost: request.DestinationHost,
		DestinationPort: request.DestinationPort,
		Protocol:        request.Protocol,
	}, now)
}

// StartStream records a provider-owned Mesh stream before it is opened.
func (b *MeshBook) StartStream(moduleID string, request mesh.StreamRequest, now time.Time) MeshOperation {
	return b.start(meshStreamOperation(MeshOperationKindStream, moduleID, request, ""), now)
}

// StartBridge records a daemon-owned local endpoint before its Mesh stream opens.
func (b *MeshBook) StartBridge(
	moduleID string,
	request mesh.StreamRequest,
	localAddress string,
	now time.Time,
) MeshOperation {
	return b.start(meshStreamOperation(MeshOperationKindBridge, moduleID, request, localAddress), now)
}

// CompleteTask records the terminal result and any sessions opened by a task.
func (b *MeshBook) CompleteTask(id string, result mesh.TaskResult, now time.Time) {
	state := strings.TrimSpace(string(result.Status))
	if state == "" {
		state = string(MeshOperationStateSucceeded)
	}
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = MeshOperationState(state)
		operation.Summary = result.Summary
		if result.TaskID != "" {
			operation.TaskID = result.TaskID
		}
		if result.NodeID != "" {
			operation.NodeID = result.NodeID
		}
		if result.Route != nil {
			operation.RouteID = result.Route.ID
		}
		if result.DestinationHost != "" {
			operation.DestinationHost = result.DestinationHost
		}
		if result.DestinationPort != 0 {
			operation.DestinationPort = result.DestinationPort
		}
		if result.Protocol != "" {
			operation.Protocol = result.Protocol
		}
		ids := sessionIDs(result.Sessions)
		if len(ids) > 0 {
			operation.SessionIDs = ids
			if operation.SessionID == "" {
				operation.SessionID = ids[0]
			}
		}
	})
}

// ActivateStream associates an opened provider session with a stream operation.
func (b *MeshBook) ActivateStream(id string, session run.SessionRef, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		activateMeshSession(operation, session)
	})
}

// ActivateBridge associates an opened provider session and local endpoint with a bridge.
func (b *MeshBook) ActivateBridge(id string, session run.SessionRef, localAddress string, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		activateMeshSession(operation, session)
		if address := strings.TrimSpace(localAddress); address != "" {
			operation.LocalAddress = address
		}
	})
}

// Fail marks an operation failed and retains its error for audit queries.
func (b *MeshBook) Fail(id string, err error, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = MeshOperationStateFailed
		if err != nil {
			operation.Error = err.Error()
		}
	})
}

// CloseSession closes active stream and bridge operations backed by sessionID.
func (b *MeshBook) CloseSession(sessionID string, now time.Time) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	updatedAt := formatMeshTime(now)
	for i := range b.operations {
		operation := &b.operations[i]
		isClosableKind := operation.Kind == MeshOperationKindStream || operation.Kind == MeshOperationKindBridge
		isTerminal := operation.State == MeshOperationStateClosed || operation.State == MeshOperationStateFailed
		if !isClosableKind || operation.SessionID != sessionID || isTerminal {
			continue
		}
		operation.State = MeshOperationStateClosed
		operation.ClosedAt = updatedAt
		operation.UpdatedAt = updatedAt
	}
}

// List returns defensively copied operations matching filter.
func (b *MeshBook) List(filter MeshOperationListRequest) []MeshOperation {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]MeshOperation, 0, len(b.operations))
	for _, operation := range b.operations {
		if !meshOperationMatches(operation, filter) {
			continue
		}
		operation.SessionIDs = append([]string(nil), operation.SessionIDs...)
		out = append(out, operation)
	}
	return out
}

func (b *MeshBook) start(operation MeshOperation, now time.Time) MeshOperation {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	operation.ID = fmt.Sprintf("mesh-op-%d", b.next)
	if operation.State == "" {
		operation.State = MeshOperationStateStarted
	}
	timestamp := formatMeshTime(now)
	operation.StartedAt = timestamp
	operation.UpdatedAt = timestamp
	b.operations = append(b.operations, operation)
	if b.byID == nil {
		b.byID = map[string]int{}
	}
	b.byID[operation.ID] = len(b.operations) - 1
	return operation
}

func (b *MeshBook) update(id string, now time.Time, apply func(*MeshOperation)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	index, ok := b.byID[id]
	if !ok || index < 0 || index >= len(b.operations) {
		return
	}
	apply(&b.operations[index])
	b.operations[index].UpdatedAt = formatMeshTime(now)
}

func meshOperationMatches(operation MeshOperation, filter MeshOperationListRequest) bool {
	if filter.ModuleID != "" && filter.ModuleID != operation.ModuleID {
		return false
	}
	if filter.RunID != "" && filter.RunID != operation.RunID {
		return false
	}
	if filter.NodeID != "" && filter.NodeID != operation.NodeID {
		return false
	}
	if filter.SessionID != "" &&
		filter.SessionID != operation.SessionID &&
		!containsString(operation.SessionIDs, filter.SessionID) {
		return false
	}
	if filter.Kind != "" && filter.Kind != operation.Kind {
		return false
	}
	if filter.State != "" && filter.State != operation.State {
		return false
	}
	return true
}

func routeID(route *mesh.Route) string {
	if route == nil {
		return ""
	}
	return route.ID
}

func sessionIDs(sessions []run.SessionRef) []string {
	out := make([]string, 0, len(sessions))
	seen := map[string]struct{}{}
	for _, session := range sessions {
		id := strings.TrimSpace(session.ID)
		if _, exists := seen[id]; id == "" || exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func meshStreamOperation(
	kind MeshOperationKind,
	moduleID string,
	request mesh.StreamRequest,
	localAddress string,
) MeshOperation {
	return MeshOperation{
		Kind:            kind,
		State:           MeshOperationStateStarted,
		ModuleID:        moduleID,
		RunID:           request.RunID,
		NodeID:          request.NodeID,
		Target:          request.Target,
		RouteID:         routeID(request.Route),
		DestinationHost: request.DestinationHost,
		DestinationPort: request.DestinationPort,
		Protocol:        request.Protocol,
		LocalAddress:    strings.TrimSpace(localAddress),
	}
}

func activateMeshSession(operation *MeshOperation, session run.SessionRef) {
	session.ID = strings.TrimSpace(session.ID)
	operation.State = MeshOperationStateActive
	operation.SessionID = session.ID
	if session.ID != "" {
		operation.SessionIDs = []string{session.ID}
	}
	if operation.RunID == "" {
		operation.RunID = session.RunID
	}
	if operation.Target == "" {
		operation.Target = session.Target
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func formatMeshTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
