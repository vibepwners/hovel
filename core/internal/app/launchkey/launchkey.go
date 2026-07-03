package launchkey

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
)

type CreatePendingRequest struct {
	ID        string
	Operation string
	Chain     string
	PlanHash  string
	Flags     operatordomain.ApprovalFlags
	Entities  []operatordomain.Entity
	Policy    operatordomain.LaunchKeyPolicy
	Now       time.Time
}

type ConfirmRequest struct {
	PendingID   string
	EntityID    string
	PlanHash    string
	Flags       operatordomain.ApprovalFlags
	ConfirmedAt time.Time
}

type PendingSnapshot struct {
	ID                  string
	Operation           string
	Chain               string
	PlanHash            string
	Flags               operatordomain.ApprovalFlags
	CreatedAt           time.Time
	Ready               bool
	RequiredApproverIDs []string
	MissingApproverIDs  []string
}

type Coordinator struct {
	mu      sync.Mutex
	pending map[string]operatordomain.PendingThrow
}

func NewCoordinator() *Coordinator {
	return &Coordinator{pending: map[string]operatordomain.PendingThrow{}}
}

func (c *Coordinator) CreatePending(req CreatePendingRequest) (PendingSnapshot, error) {
	pending, err := operatordomain.NewPendingThrow(operatordomain.PendingThrowArgs{
		ID:        req.ID,
		Operation: req.Operation,
		Chain:     req.Chain,
		PlanHash:  req.PlanHash,
		Flags:     req.Flags,
		Entities:  req.Entities,
		Policy:    req.Policy,
		Now:       req.Now,
	})
	if err != nil {
		return PendingSnapshot{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	if _, exists := c.pending[pending.ID]; exists {
		return PendingSnapshot{}, fmt.Errorf("pending throw %s already exists", pending.ID)
	}
	c.pending[pending.ID] = pending
	return snapshot(pending), nil
}

func (c *Coordinator) Confirm(req ConfirmRequest) (PendingSnapshot, error) {
	pendingID := strings.TrimSpace(req.PendingID)
	if pendingID == "" {
		return PendingSnapshot{}, errors.New("pending throw id is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	pending, ok := c.pending[pendingID]
	if !ok {
		return PendingSnapshot{}, notFound(pendingID)
	}
	next, err := pending.Approve(req.EntityID, req.PlanHash, req.Flags, req.ConfirmedAt)
	if err != nil {
		return PendingSnapshot{}, err
	}
	c.pending[pendingID] = next
	return snapshot(next), nil
}

func (c *Coordinator) RequireReady(pendingID string) (PendingSnapshot, error) {
	pendingID = strings.TrimSpace(pendingID)
	if pendingID == "" {
		return PendingSnapshot{}, errors.New("pending throw id is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	pending, ok := c.pending[pendingID]
	if !ok {
		return PendingSnapshot{}, notFound(pendingID)
	}
	out := snapshot(pending)
	if !out.Ready {
		return out, fmt.Errorf("launch-key approvals missing: %s", strings.Join(out.MissingApproverIDs, ", "))
	}
	return out, nil
}

func (c *Coordinator) Snapshot(pendingID string) (PendingSnapshot, bool) {
	pendingID = strings.TrimSpace(pendingID)
	if pendingID == "" {
		return PendingSnapshot{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	pending, ok := c.pending[pendingID]
	if !ok {
		return PendingSnapshot{}, false
	}
	return snapshot(pending), true
}

func (c *Coordinator) Cancel(pendingID string) bool {
	pendingID = strings.TrimSpace(pendingID)
	if pendingID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	if _, ok := c.pending[pendingID]; !ok {
		return false
	}
	delete(c.pending, pendingID)
	return true
}

func (c *Coordinator) ensureLocked() {
	if c.pending == nil {
		c.pending = map[string]operatordomain.PendingThrow{}
	}
}

func snapshot(pending operatordomain.PendingThrow) PendingSnapshot {
	decision := pending.Decision()
	return PendingSnapshot{
		ID:                  pending.ID,
		Operation:           pending.Operation,
		Chain:               pending.Chain,
		PlanHash:            pending.PlanHash,
		Flags:               pending.Flags,
		CreatedAt:           pending.CreatedAt,
		Ready:               decision.Ready,
		RequiredApproverIDs: decision.RequiredApproverIDs,
		MissingApproverIDs:  decision.MissingApproverIDs,
	}
}

func notFound(pendingID string) error {
	return fmt.Errorf("pending throw %s does not exist", pendingID)
}
