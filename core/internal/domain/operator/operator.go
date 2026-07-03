package operator

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type EntityKind string

const (
	KindUnknown EntityKind = "unknown"
	KindCLI     EntityKind = "cli"
	KindTUI     EntityKind = "tui"
	KindMCP     EntityKind = "mcp"
	KindREST    EntityKind = "rest"
	KindOneShot EntityKind = "one_shot"
	KindService EntityKind = "service"
)

type EntityArgs struct {
	ID           string
	Kind         EntityKind
	DisplayName  string
	Agent        bool
	Operation    string
	ActiveChain  string
	ConnectedAt  time.Time
	LastSeenAt   time.Time
	Capabilities []string
	PolicyTags   []string
}

type Entity struct {
	ID           string
	Kind         EntityKind
	DisplayName  string
	Agent        bool
	Operation    string
	ActiveChain  string
	ConnectedAt  time.Time
	LastSeenAt   time.Time
	Capabilities []string
	PolicyTags   []string
}

func NewEntity(args EntityArgs) (Entity, error) {
	args.ID = strings.TrimSpace(args.ID)
	args.Operation = strings.TrimSpace(args.Operation)
	args.ActiveChain = strings.TrimSpace(args.ActiveChain)
	args.DisplayName = strings.TrimSpace(args.DisplayName)
	if args.ID == "" {
		return Entity{}, errors.New("operator entity id is required")
	}
	kind, err := normalizeKind(args.Kind)
	if err != nil {
		return Entity{}, err
	}
	if args.DisplayName == "" {
		args.DisplayName = args.ID
	}
	if args.ConnectedAt.IsZero() {
		return Entity{}, errors.New("operator entity connected time is required")
	}
	if args.LastSeenAt.IsZero() {
		args.LastSeenAt = args.ConnectedAt
	}
	return Entity{
		ID:           args.ID,
		Kind:         kind,
		DisplayName:  args.DisplayName,
		Agent:        args.Agent,
		Operation:    args.Operation,
		ActiveChain:  args.ActiveChain,
		ConnectedAt:  args.ConnectedAt.UTC(),
		LastSeenAt:   args.LastSeenAt.UTC(),
		Capabilities: cloneStrings(args.Capabilities),
		PolicyTags:   cloneStrings(args.PolicyTags),
	}, nil
}

func normalizeKind(kind EntityKind) (EntityKind, error) {
	if kind == "" {
		return KindUnknown, nil
	}
	switch kind {
	case KindUnknown, KindCLI, KindTUI, KindMCP, KindREST, KindOneShot, KindService:
		return kind, nil
	default:
		return "", fmt.Errorf("operator entity kind %q is not supported", kind)
	}
}

type ApprovalFlags struct {
	AllowDangerous bool
	NowBypass      bool
}

type LaunchKeyMode string

const (
	LaunchKeyAnyone       LaunchKeyMode = "anyone"
	LaunchKeyQuorum       LaunchKeyMode = "quorum"
	LaunchKeyAllConnected LaunchKeyMode = "all_connected"
)

type LaunchKeyPolicy struct {
	Enabled          bool
	Mode             LaunchKeyMode
	Quorum           int
	HeartbeatTimeout time.Duration
}

type PendingThrowArgs struct {
	ID        string
	Operation string
	Chain     string
	PlanHash  string
	Flags     ApprovalFlags
	Entities  []Entity
	Policy    LaunchKeyPolicy
	Now       time.Time
}

type PendingThrow struct {
	ID        string
	Operation string
	Chain     string
	PlanHash  string
	Flags     ApprovalFlags
	CreatedAt time.Time

	requiredApproverIDs []string
	approvalThreshold   int
	approvals           map[string]Approval
}

type Approval struct {
	EntityID   string
	PlanHash   string
	Flags      ApprovalFlags
	ApprovedAt time.Time
}

type ApprovalDecision struct {
	Ready               bool
	RequiredApproverIDs []string
	MissingApproverIDs  []string
}

func NewPendingThrow(args PendingThrowArgs) (PendingThrow, error) {
	args.ID = strings.TrimSpace(args.ID)
	args.Operation = strings.TrimSpace(args.Operation)
	args.Chain = strings.TrimSpace(args.Chain)
	args.PlanHash = strings.TrimSpace(args.PlanHash)
	if args.ID == "" {
		return PendingThrow{}, errors.New("pending throw id is required")
	}
	if args.Operation == "" {
		return PendingThrow{}, errors.New("pending throw operation is required")
	}
	if args.Chain == "" {
		return PendingThrow{}, errors.New("pending throw chain is required")
	}
	if args.PlanHash == "" {
		return PendingThrow{}, errors.New("pending throw plan hash is required")
	}
	now := args.Now
	if now.IsZero() {
		now = time.Now()
	}
	pending := PendingThrow{
		ID:        args.ID,
		Operation: args.Operation,
		Chain:     args.Chain,
		PlanHash:  args.PlanHash,
		Flags:     args.Flags,
		CreatedAt: now.UTC(),
		approvals: map[string]Approval{},
	}
	policy := NormalizeLaunchKeyPolicy(args.Policy)
	if policy.Mode != LaunchKeyAnyone {
		pending.requiredApproverIDs = requiredApproverIDs(args.Entities, args.Operation, args.Chain, policy, now)
		pending.approvalThreshold = len(pending.requiredApproverIDs)
		if policy.Mode == LaunchKeyQuorum && policy.Quorum < pending.approvalThreshold {
			pending.approvalThreshold = policy.Quorum
		}
	}
	return pending, nil
}

func (p PendingThrow) RequiredApproverIDs() []string {
	return cloneStrings(p.requiredApproverIDs)
}

func (p PendingThrow) Decision() ApprovalDecision {
	missing := make([]string, 0, len(p.requiredApproverIDs))
	for _, id := range p.requiredApproverIDs {
		if _, ok := p.approvals[id]; !ok {
			missing = append(missing, id)
		}
	}
	threshold := p.approvalThreshold
	if threshold == 0 && len(p.requiredApproverIDs) > 0 {
		threshold = len(p.requiredApproverIDs)
	}
	ready := len(p.approvals) >= threshold
	if threshold == 0 {
		ready = true
	}
	if ready {
		missing = nil
	}
	return ApprovalDecision{
		Ready:               ready,
		RequiredApproverIDs: cloneStrings(p.requiredApproverIDs),
		MissingApproverIDs:  missing,
	}
}

func (p PendingThrow) Approve(entityID, planHash string, flags ApprovalFlags, approvedAt time.Time) (PendingThrow, error) {
	entityID = strings.TrimSpace(entityID)
	planHash = strings.TrimSpace(planHash)
	if entityID == "" {
		return PendingThrow{}, errors.New("approver entity id is required")
	}
	if planHash != p.PlanHash {
		return PendingThrow{}, fmt.Errorf("approval plan hash %q does not match pending throw plan hash %q", planHash, p.PlanHash)
	}
	if flags != p.Flags {
		return PendingThrow{}, fmt.Errorf("approval flags do not match pending throw flags")
	}
	if !p.requiresApprover(entityID) {
		// When the launch-key policy requires no approvers (e.g. the default
		// "anyone" mode) the pending throw is already ready, so confirming it is a
		// vacuous no-op rather than an error. This keeps the default
		// plan -> confirm -> start workflow working. An entity that is simply not
		// part of a non-empty required set is still rejected.
		if len(p.requiredApproverIDs) == 0 {
			return p.clone(), nil
		}
		return PendingThrow{}, fmt.Errorf("entity %s is not a required approver", entityID)
	}
	if approvedAt.IsZero() {
		approvedAt = time.Now()
	}
	next := p.clone()
	next.approvals[entityID] = Approval{
		EntityID:   entityID,
		PlanHash:   planHash,
		Flags:      flags,
		ApprovedAt: approvedAt.UTC(),
	}
	return next, nil
}

func (p PendingThrow) requiresApprover(entityID string) bool {
	for _, required := range p.requiredApproverIDs {
		if required == entityID {
			return true
		}
	}
	return false
}

func (p PendingThrow) clone() PendingThrow {
	out := p
	out.requiredApproverIDs = cloneStrings(p.requiredApproverIDs)
	out.approvals = make(map[string]Approval, len(p.approvals))
	for id, approval := range p.approvals {
		out.approvals[id] = approval
	}
	return out
}

func requiredApproverIDs(entities []Entity, operation, chain string, policy LaunchKeyPolicy, now time.Time) []string {
	seen := map[string]struct{}{}
	for _, entity := range entities {
		if entity.Operation != operation || entity.ActiveChain != chain {
			continue
		}
		if !entity.countsForLaunchKey() {
			continue
		}
		if !entity.live(now, policy.HeartbeatTimeout) {
			continue
		}
		seen[entity.ID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func NormalizeLaunchKeyPolicy(policy LaunchKeyPolicy) LaunchKeyPolicy {
	switch policy.Mode {
	case LaunchKeyAnyone, LaunchKeyQuorum, LaunchKeyAllConnected:
	case "":
		if policy.Enabled {
			policy.Mode = LaunchKeyAllConnected
		} else {
			policy.Mode = LaunchKeyAnyone
		}
	default:
		policy.Mode = LaunchKeyAnyone
	}
	if policy.Mode != LaunchKeyAnyone {
		policy.Enabled = true
	}
	if policy.Mode == LaunchKeyQuorum && policy.Quorum < 1 {
		policy.Quorum = 1
	}
	return policy
}

func (e Entity) countsForLaunchKey() bool {
	switch e.Kind {
	case KindOneShot, KindService:
		return false
	default:
		return true
	}
}

func (e Entity) live(now time.Time, timeout time.Duration) bool {
	if e.LastSeenAt.IsZero() {
		return false
	}
	if now.IsZero() || timeout <= 0 {
		return true
	}
	return !e.LastSeenAt.Add(timeout).Before(now.UTC())
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}
