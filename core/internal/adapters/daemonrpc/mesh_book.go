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
	meshOperationTask   = "task"
	meshOperationStream = "stream"
	meshOperationBridge = "bridge"

	meshOperationStarted   = "started"
	meshOperationActive    = "active"
	meshOperationSucceeded = "succeeded"
	meshOperationFailed    = "failed"
	meshOperationClosed    = "closed"
)

// MeshOperation is daemon-side bookkeeping for provider-owned mesh work.
// It records enough routing context to audit node tasks, routed sessions, and
// daemon-owned local bridges, including future "throw through a node" flows
// that bridge an exploit to a destination reachable from a mesh node or route.
type MeshOperation struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	ModuleID        string   `json:"moduleId"`
	RunID           string   `json:"runId,omitempty"`
	TaskID          string   `json:"taskId,omitempty"`
	TaskKind        string   `json:"taskKind,omitempty"`
	SessionID       string   `json:"sessionId,omitempty"`
	SessionIDs      []string `json:"sessionIds,omitempty"`
	NodeID          string   `json:"nodeId,omitempty"`
	Target          string   `json:"target,omitempty"`
	RouteID         string   `json:"routeId,omitempty"`
	DestinationHost string   `json:"destinationHost,omitempty"`
	DestinationPort int      `json:"destinationPort,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	LocalAddress    string   `json:"localAddress,omitempty"`
	Summary         string   `json:"summary,omitempty"`
	Error           string   `json:"error,omitempty"`
	StartedAt       string   `json:"startedAt"`
	UpdatedAt       string   `json:"updatedAt"`
	ClosedAt        string   `json:"closedAt,omitempty"`
}

type MeshOperationListRequest struct {
	ModuleID  string `json:"moduleId,omitempty"`
	RunID     string `json:"runId,omitempty"`
	NodeID    string `json:"nodeId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	Kind      string `json:"kind,omitempty"`
	State     string `json:"state,omitempty"`
}

type MeshOperationListResponse struct {
	Operations []MeshOperation `json:"operations"`
}

// MeshBook stores in-memory daemon bookkeeping for mesh tasks, routed sessions,
// and local bridges.
type MeshBook struct {
	mu         sync.Mutex
	next       uint64
	operations []MeshOperation
}

func NewMeshBook() *MeshBook {
	return &MeshBook{
		operations: []MeshOperation{},
	}
}

func (b *MeshBook) StartTask(moduleID string, request mesh.TaskRequest, now time.Time) MeshOperation {
	return b.start(MeshOperation{
		Kind:            meshOperationTask,
		State:           meshOperationStarted,
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

func (b *MeshBook) StartStream(moduleID string, request mesh.StreamRequest, now time.Time) MeshOperation {
	return b.start(MeshOperation{
		Kind:            meshOperationStream,
		State:           meshOperationStarted,
		ModuleID:        moduleID,
		RunID:           request.RunID,
		NodeID:          request.NodeID,
		Target:          request.Target,
		RouteID:         routeID(request.Route),
		DestinationHost: request.DestinationHost,
		DestinationPort: request.DestinationPort,
		Protocol:        request.Protocol,
	}, now)
}

func (b *MeshBook) StartBridge(
	moduleID string,
	request mesh.StreamRequest,
	localAddress string,
	now time.Time,
) MeshOperation {
	return b.start(MeshOperation{
		Kind:            meshOperationBridge,
		State:           meshOperationStarted,
		ModuleID:        moduleID,
		RunID:           request.RunID,
		NodeID:          request.NodeID,
		Target:          request.Target,
		RouteID:         routeID(request.Route),
		DestinationHost: request.DestinationHost,
		DestinationPort: request.DestinationPort,
		Protocol:        request.Protocol,
		LocalAddress:    strings.TrimSpace(localAddress),
	}, now)
}

func (b *MeshBook) CompleteTask(id string, result mesh.TaskResult, now time.Time) {
	state := strings.TrimSpace(result.Status)
	if state == "" {
		state = meshOperationSucceeded
	}
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = state
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

func (b *MeshBook) ActivateStream(id string, session run.SessionRef, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = meshOperationActive
		operation.SessionID = session.ID
		if operation.RunID == "" {
			operation.RunID = session.RunID
		}
		if operation.Target == "" {
			operation.Target = session.Target
		}
		if session.ID != "" {
			operation.SessionIDs = []string{session.ID}
		}
	})
}

func (b *MeshBook) ActivateBridge(id string, session run.SessionRef, localAddress string, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = meshOperationActive
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
		if address := strings.TrimSpace(localAddress); address != "" {
			operation.LocalAddress = address
		}
	})
}

func (b *MeshBook) Fail(id string, err error, now time.Time) {
	b.update(id, now, func(operation *MeshOperation) {
		operation.State = meshOperationFailed
		if err != nil {
			operation.Error = err.Error()
		}
	})
}

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
		isClosableKind := operation.Kind == meshOperationStream || operation.Kind == meshOperationBridge
		isTerminal := operation.State == meshOperationClosed || operation.State == meshOperationFailed
		if !isClosableKind || operation.SessionID != sessionID || isTerminal {
			continue
		}
		operation.State = meshOperationClosed
		operation.ClosedAt = updatedAt
		operation.UpdatedAt = updatedAt
	}
}

func (b *MeshBook) List(filter MeshOperationListRequest) []MeshOperation {
	b.mu.Lock()
	defer b.mu.Unlock()
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
		operation.State = meshOperationStarted
	}
	timestamp := formatMeshTime(now)
	operation.StartedAt = timestamp
	operation.UpdatedAt = timestamp
	b.operations = append(b.operations, operation)
	return operation
}

func (b *MeshBook) update(id string, now time.Time, apply func(*MeshOperation)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	updatedAt := formatMeshTime(now)
	for i := range b.operations {
		if b.operations[i].ID != id {
			continue
		}
		apply(&b.operations[i])
		b.operations[i].UpdatedAt = updatedAt
		return
	}
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
	seen := map[string]bool{}
	for _, session := range sessions {
		id := strings.TrimSpace(session.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
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
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format(time.RFC3339Nano)
}
