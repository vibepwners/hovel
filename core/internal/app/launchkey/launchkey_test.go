package launchkey

import (
	"reflect"
	"strings"
	"testing"
	"time"

	operatordomain "github.com/vibepwners/hovel/internal/domain/operator"
)

func TestCoordinatorBlocksStartUntilRequiredApproversConfirm(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	flags := operatordomain.ApprovalFlags{AllowDangerous: true}
	coordinator := NewCoordinator()

	pending, err := coordinator.CreatePending(CreatePendingRequest{
		ID:        "pending-1",
		Operation: "op-alpha",
		Chain:     "chain-alpha",
		PlanHash:  "hash-1",
		Flags:     flags,
		Entities: []operatordomain.Entity{
			mustEntity(t, operatordomain.EntityArgs{ID: "entity-cli", Kind: operatordomain.KindCLI, Operation: "op-alpha", ActiveChain: "chain-alpha", ConnectedAt: now, LastSeenAt: now}),
			mustEntity(t, operatordomain.EntityArgs{ID: "entity-mcp", Kind: operatordomain.KindMCP, Agent: true, Operation: "op-alpha", ActiveChain: "chain-alpha", ConnectedAt: now, LastSeenAt: now}),
		},
		Policy: operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready {
		t.Fatalf("pending throw unexpectedly ready: %#v", pending)
	}
	if got, want := pending.MissingApproverIDs, []string{"entity-cli", "entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing approvers = %#v, want %#v", got, want)
	}

	if _, err := coordinator.RequireReady("pending-1"); err == nil || !strings.Contains(err.Error(), "entity-cli, entity-mcp") {
		t.Fatalf("RequireReady error = %v, want missing approvers", err)
	}

	pending, err = coordinator.Confirm(ConfirmRequest{
		PendingID:   "pending-1",
		EntityID:    "entity-mcp",
		PlanHash:    "hash-1",
		Flags:       flags,
		ConfirmedAt: now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready || !reflect.DeepEqual(pending.MissingApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after one approval = %#v, want entity-cli missing", pending)
	}

	pending, err = coordinator.Confirm(ConfirmRequest{
		PendingID:   "pending-1",
		EntityID:    "entity-cli",
		PlanHash:    "hash-1",
		Flags:       flags,
		ConfirmedAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || len(pending.MissingApproverIDs) != 0 {
		t.Fatalf("pending after all approvals = %#v, want ready", pending)
	}
	if ready, err := coordinator.RequireReady("pending-1"); err != nil || !ready.Ready {
		t.Fatalf("RequireReady = %#v, %v; want ready", ready, err)
	}
}

func TestCoordinatorDoesNotSynthesizeMissingPendingThrow(t *testing.T) {
	coordinator := NewCoordinator()

	if _, err := coordinator.RequireReady("missing"); err == nil || !strings.Contains(err.Error(), "pending throw missing does not exist") {
		t.Fatalf("RequireReady missing error = %v", err)
	}
	if _, err := coordinator.Confirm(ConfirmRequest{PendingID: "missing", EntityID: "entity-cli", PlanHash: "hash-1"}); err == nil || !strings.Contains(err.Error(), "pending throw missing does not exist") {
		t.Fatalf("Confirm missing error = %v", err)
	}
}

func TestCoordinatorAllowsStartWhenLaunchKeyDisabled(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	coordinator := NewCoordinator()

	pending, err := coordinator.CreatePending(CreatePendingRequest{
		ID:        "pending-1",
		Operation: "op-alpha",
		Chain:     "chain-alpha",
		PlanHash:  "hash-1",
		Entities: []operatordomain.Entity{
			mustEntity(t, operatordomain.EntityArgs{ID: "entity-cli", Kind: operatordomain.KindCLI, Operation: "op-alpha", ActiveChain: "chain-alpha", ConnectedAt: now, LastSeenAt: now}),
		},
		Policy: operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAnyone, HeartbeatTimeout: time.Minute},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || len(pending.RequiredApproverIDs) != 0 || len(pending.MissingApproverIDs) != 0 {
		t.Fatalf("pending with launch-key disabled = %#v, want ready without approvers", pending)
	}
	if ready, err := coordinator.RequireReady("pending-1"); err != nil || !ready.Ready {
		t.Fatalf("RequireReady = %#v, %v; want ready", ready, err)
	}
}

func TestCoordinatorCancelRemovesPendingThrow(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	coordinator := NewCoordinator()
	if _, err := coordinator.CreatePending(CreatePendingRequest{
		ID:        "pending-1",
		Operation: "op-alpha",
		Chain:     "chain-alpha",
		PlanHash:  "hash-1",
		Policy:    operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAnyone},
		Now:       now,
	}); err != nil {
		t.Fatal(err)
	}

	if !coordinator.Cancel("pending-1") {
		t.Fatal("Cancel returned false, want true")
	}
	if _, err := coordinator.RequireReady("pending-1"); err == nil || !strings.Contains(err.Error(), "pending throw pending-1 does not exist") {
		t.Fatalf("RequireReady after cancel error = %v", err)
	}
	if coordinator.Cancel("pending-1") {
		t.Fatal("Cancel missing returned true, want false")
	}
}

func mustEntity(t *testing.T, args operatordomain.EntityArgs) operatordomain.Entity {
	t.Helper()
	entity, err := operatordomain.NewEntity(args)
	if err != nil {
		t.Fatalf("NewEntity(%#v) returned error: %v", args, err)
	}
	return entity
}
