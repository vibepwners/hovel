package operator

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPendingThrowRequiresEveryLiveEntityInOperation(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	entities := []Entity{
		mustEntity(t, EntityArgs{
			ID:          "entity-cli",
			Kind:        KindCLI,
			DisplayName: "human",
			Operation:   "op-alpha",
			ConnectedAt: now.Add(-time.Minute),
			LastSeenAt:  now,
		}),
		mustEntity(t, EntityArgs{
			ID:          "entity-mcp",
			Kind:        KindMCP,
			DisplayName: "codex",
			Agent:       true,
			Operation:   "op-alpha",
			ConnectedAt: now.Add(-time.Minute),
			LastSeenAt:  now,
		}),
		mustEntity(t, EntityArgs{
			ID:          "entity-other-op",
			Kind:        KindTUI,
			DisplayName: "observer",
			Operation:   "op-beta",
			ConnectedAt: now.Add(-time.Minute),
			LastSeenAt:  now,
		}),
		mustEntity(t, EntityArgs{
			ID:          "entity-no-op",
			Kind:        KindMCP,
			DisplayName: "unselected",
			Agent:       true,
			ConnectedAt: now.Add(-time.Minute),
			LastSeenAt:  now,
		}),
		mustEntity(t, EntityArgs{
			ID:          "entity-stale",
			Kind:        KindREST,
			DisplayName: "stale rest",
			Operation:   "op-alpha",
			ConnectedAt: now.Add(-time.Hour),
			LastSeenAt:  now.Add(-10 * time.Minute),
		}),
		mustEntity(t, EntityArgs{
			ID:          "entity-one-shot",
			Kind:        KindOneShot,
			DisplayName: "completed one-shot",
			Operation:   "op-alpha",
			ConnectedAt: now.Add(-time.Minute),
			LastSeenAt:  now,
		}),
	}
	pending, err := NewPendingThrow(PendingThrowArgs{
		ID:        "pending-1",
		Operation: "op-alpha",
		PlanHash:  "hash-1",
		Flags:     ApprovalFlags{AllowDangerous: true},
		Entities:  entities,
		Policy:    LaunchKeyPolicy{Enabled: true, HeartbeatTimeout: 2 * time.Minute},
		Now:       now,
	})
	if err != nil {
		t.Fatalf("NewPendingThrow returned error: %v", err)
	}
	if got, want := pending.RequiredApproverIDs(), []string{"entity-cli", "entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required approvers = %#v, want %#v", got, want)
	}
	if decision := pending.Decision(); decision.Ready {
		t.Fatalf("pending throw unexpectedly ready before approvals: %#v", decision)
	}
}

func TestEntityRejectsUnknownKind(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	if _, err := NewEntity(EntityArgs{ID: "entity-weird", Kind: EntityKind("browser"), ConnectedAt: now}); err == nil || !strings.Contains(err.Error(), "operator entity kind") {
		t.Fatalf("NewEntity unknown kind error = %v, want kind error", err)
	}

	entity, err := NewEntity(EntityArgs{ID: "entity-unknown", ConnectedAt: now})
	if err != nil {
		t.Fatalf("NewEntity blank kind returned error: %v", err)
	}
	if entity.Kind != KindUnknown {
		t.Fatalf("blank kind = %q, want %q", entity.Kind, KindUnknown)
	}
}

func TestPendingThrowApprovalsMustMatchPlanHashAndFlags(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	pending := mustPendingThrow(t, PendingThrowArgs{
		ID:        "pending-1",
		Operation: "op-alpha",
		PlanHash:  "hash-1",
		Flags:     ApprovalFlags{AllowDangerous: true, NowBypass: true},
		Entities: []Entity{
			mustEntity(t, EntityArgs{ID: "entity-cli", Kind: KindCLI, DisplayName: "human", Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
			mustEntity(t, EntityArgs{ID: "entity-mcp", Kind: KindMCP, DisplayName: "codex", Agent: true, Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
		},
		Policy: LaunchKeyPolicy{Enabled: true, HeartbeatTimeout: time.Minute},
		Now:    now,
	})

	if _, err := pending.Approve("entity-cli", "hash-2", ApprovalFlags{AllowDangerous: true, NowBypass: true}, now); err == nil || !strings.Contains(err.Error(), "plan hash") {
		t.Fatalf("wrong plan hash error = %v, want plan hash error", err)
	}
	if _, err := pending.Approve("entity-cli", "hash-1", ApprovalFlags{AllowDangerous: true}, now); err == nil || !strings.Contains(err.Error(), "approval flags") {
		t.Fatalf("wrong flags error = %v, want approval flags error", err)
	}

	var err error
	pending, err = pending.Approve("entity-mcp", "hash-1", ApprovalFlags{AllowDangerous: true, NowBypass: true}, now)
	if err != nil {
		t.Fatalf("Approve mcp returned error: %v", err)
	}
	if decision := pending.Decision(); decision.Ready || !reflect.DeepEqual(decision.MissingApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("decision after one approval = %#v, want missing entity-cli", decision)
	}
	pending, err = pending.Approve("entity-cli", "hash-1", ApprovalFlags{AllowDangerous: true, NowBypass: true}, now)
	if err != nil {
		t.Fatalf("Approve cli returned error: %v", err)
	}
	if decision := pending.Decision(); !decision.Ready || len(decision.MissingApproverIDs) != 0 {
		t.Fatalf("decision after all approvals = %#v, want ready", decision)
	}
}

func TestPendingThrowSnapshotsRequiredApprovers(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	pending := mustPendingThrow(t, PendingThrowArgs{
		ID:        "pending-1",
		Operation: "op-alpha",
		PlanHash:  "hash-1",
		Entities: []Entity{
			mustEntity(t, EntityArgs{ID: "entity-cli", Kind: KindCLI, DisplayName: "human", Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
			mustEntity(t, EntityArgs{ID: "entity-mcp", Kind: KindMCP, DisplayName: "codex", Agent: true, Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
		},
		Policy: LaunchKeyPolicy{Enabled: true, HeartbeatTimeout: time.Minute},
		Now:    now,
	})

	pending, err := pending.Approve("entity-cli", "hash-1", ApprovalFlags{}, now)
	if err != nil {
		t.Fatalf("Approve cli returned error: %v", err)
	}
	if decision := pending.Decision(); decision.Ready || !reflect.DeepEqual(decision.MissingApproverIDs, []string{"entity-mcp"}) {
		t.Fatalf("decision = %#v, want mcp still required from creation snapshot", decision)
	}
}

func TestLaunchKeyDisabledAddsNoRequiredApprovers(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	pending := mustPendingThrow(t, PendingThrowArgs{
		ID:        "pending-1",
		Operation: "op-alpha",
		PlanHash:  "hash-1",
		Entities: []Entity{
			mustEntity(t, EntityArgs{ID: "entity-cli", Kind: KindCLI, DisplayName: "human", Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
			mustEntity(t, EntityArgs{ID: "entity-mcp", Kind: KindMCP, DisplayName: "codex", Agent: true, Operation: "op-alpha", ConnectedAt: now, LastSeenAt: now}),
		},
		Policy: LaunchKeyPolicy{Enabled: false, HeartbeatTimeout: time.Minute},
		Now:    now,
	})
	if got := pending.RequiredApproverIDs(); len(got) != 0 {
		t.Fatalf("required approvers = %#v, want none when launch-key is disabled", got)
	}
	if decision := pending.Decision(); !decision.Ready {
		t.Fatalf("decision = %#v, want launch-key ready when disabled", decision)
	}
}

func mustEntity(t *testing.T, args EntityArgs) Entity {
	t.Helper()
	entity, err := NewEntity(args)
	if err != nil {
		t.Fatalf("NewEntity(%#v) returned error: %v", args, err)
	}
	return entity
}

func mustPendingThrow(t *testing.T, args PendingThrowArgs) PendingThrow {
	t.Helper()
	pending, err := NewPendingThrow(args)
	if err != nil {
		t.Fatalf("NewPendingThrow(%#v) returned error: %v", args, err)
	}
	return pending
}
