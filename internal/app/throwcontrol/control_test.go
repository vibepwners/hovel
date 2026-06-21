package throwcontrol

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
)

func TestServicePlanPersistsPlanAndCreatesLaunchKeyPending(t *testing.T) {
	plans := &fakePlanRepository{}
	gate := &fakeLaunchKeyGate{}
	service := NewService(ServiceOptions{Plans: plans, LaunchKeys: gate, Clock: fixedClock{now: testNow()}})

	result, err := service.Plan(context.Background(), PlanRequest{
		Workspace:      ".hovel",
		Operation:      "redteam-lab",
		Chain:          "alpha",
		Targets:        []string{"mock://one"},
		Modules:        []string{"mock-exploit@v0.0.0-example"},
		ChainConfig:    map[string]string{"operator.confirmed_lab": "true"},
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans.records) != 1 {
		t.Fatalf("recorded plans = %#v, want one", plans.records)
	}
	plan := plans.records[0]
	if result.Plan.ID != plan.ID || result.Plan.PlanHash != plan.PlanHash {
		t.Fatalf("result plan = %#v, recorded = %#v", result.Plan, plan)
	}
	if plan.ID == "" || plan.PlanHash == "" || plan.ConfirmationID == "" {
		t.Fatalf("plan identifiers are incomplete: %#v", plan)
	}
	if plan.Operation != "redteam-lab" || plan.Chain != "alpha" || !reflect.DeepEqual(plan.Targets, []string{"mock://one"}) {
		t.Fatalf("plan route = %#v", plan)
	}
	if plan.Flags != (operatordomain.ApprovalFlags{AllowDangerous: true}) {
		t.Fatalf("plan flags = %#v", plan.Flags)
	}
	if len(gate.created) != 1 {
		t.Fatalf("launch-key creates = %#v, want one", gate.created)
	}
	if created := gate.created[0]; created.PendingID != plan.ID || created.Operation != "redteam-lab" || created.PlanHash != plan.PlanHash || created.Flags != plan.Flags {
		t.Fatalf("launch-key create = %#v, plan = %#v", created, plan)
	}
	if got, want := result.NextActions, []string{"review_plan", "confirm_plan", "start_throw"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("next actions = %#v, want %#v", got, want)
	}
}

func TestServicePlanRejectsMissingRoute(t *testing.T) {
	service := NewService(ServiceOptions{Plans: &fakePlanRepository{}, Clock: fixedClock{now: testNow()}})

	if _, err := service.Plan(context.Background(), PlanRequest{Workspace: ".hovel", Targets: []string{"mock://one"}}); err == nil || !strings.Contains(err.Error(), "chain is required") {
		t.Fatalf("missing chain error = %v", err)
	}
	if _, err := service.Plan(context.Background(), PlanRequest{Workspace: ".hovel", Chain: "alpha"}); err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Fatalf("missing target error = %v", err)
	}
}

func TestServiceConfirmRequiresExactPersistedPlanHash(t *testing.T) {
	plan := mustPlan(t, PlanRequest{
		Workspace: ".hovel",
		Operation: "redteam-lab",
		Chain:     "alpha",
		Targets:   []string{"mock://one"},
	})
	plans := &fakePlanRepository{records: []PlanRecord{plan}}
	confirmations := &fakeConfirmationRepository{}
	gate := &fakeLaunchKeyGate{}
	service := NewService(ServiceOptions{Plans: plans, Confirmations: confirmations, LaunchKeys: gate, Clock: fixedClock{now: testNow()}})

	if _, err := service.Confirm(context.Background(), ConfirmRequest{
		Workspace: ".hovel",
		PlanID:    plan.ID,
		PlanHash:  "wrong-hash",
		EntityID:  "entity-mcp",
		Method:    "mcp_confirm",
	}); err == nil || !strings.Contains(err.Error(), "plan hash") {
		t.Fatalf("wrong hash error = %v", err)
	}
	if len(confirmations.records) != 0 || len(gate.confirmed) != 0 {
		t.Fatalf("unexpected confirmations: repo=%#v gate=%#v", confirmations.records, gate.confirmed)
	}

	result, err := service.Confirm(context.Background(), ConfirmRequest{
		Workspace: ".hovel",
		PlanID:    plan.ID,
		PlanHash:  plan.PlanHash,
		EntityID:  "entity-mcp",
		Method:    "mcp_confirm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmations.records) != 1 {
		t.Fatalf("confirmations = %#v, want one", confirmations.records)
	}
	confirmation := confirmations.records[0]
	if confirmation.PlanID != plan.ID || confirmation.PlanHash != plan.PlanHash || confirmation.EntityID != "entity-mcp" || confirmation.Method != "mcp_confirm" {
		t.Fatalf("confirmation = %#v", confirmation)
	}
	if confirmation.ConfirmedAt != testNow().UTC().Format(time.RFC3339Nano) {
		t.Fatalf("confirmed at = %q", confirmation.ConfirmedAt)
	}
	if len(gate.confirmed) != 1 || gate.confirmed[0].PendingID != plan.ID || gate.confirmed[0].PlanHash != plan.PlanHash {
		t.Fatalf("launch-key confirmations = %#v", gate.confirmed)
	}
	if result.Confirmation.ID != confirmation.ID {
		t.Fatalf("result confirmation = %#v, recorded = %#v", result.Confirmation, confirmation)
	}
}

func TestServiceRequireStartReadyNeedsPlanConfirmationAndLaunchKey(t *testing.T) {
	plan := mustPlan(t, PlanRequest{Workspace: ".hovel", Operation: "redteam-lab", Chain: "alpha", Targets: []string{"mock://one"}})
	plans := &fakePlanRepository{records: []PlanRecord{plan}}
	confirmations := &fakeConfirmationRepository{}
	gate := &fakeLaunchKeyGate{requireErr: errLaunchKeyMissing}
	service := NewService(ServiceOptions{Plans: plans, Confirmations: confirmations, LaunchKeys: gate, Clock: fixedClock{now: testNow()}})

	if _, err := service.RequireStartReady(context.Background(), StartRequest{Workspace: ".hovel", PlanID: "missing"}); err == nil || !strings.Contains(err.Error(), "throw plan missing does not exist") {
		t.Fatalf("missing plan error = %v", err)
	}
	if _, err := service.RequireStartReady(context.Background(), StartRequest{Workspace: ".hovel", PlanID: plan.ID}); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("missing confirmation error = %v", err)
	}

	confirmations.records = append(confirmations.records, ConfirmationRecord{
		ID:          plan.ConfirmationID,
		Workspace:   ".hovel",
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		EntityID:    "entity-mcp",
		Method:      "mcp_confirm",
		ConfirmedAt: testNow().Format(time.RFC3339Nano),
	})
	if _, err := service.RequireStartReady(context.Background(), StartRequest{Workspace: ".hovel", PlanID: plan.ID}); err == nil || !strings.Contains(err.Error(), "launch-key") {
		t.Fatalf("launch-key error = %v", err)
	}
	if len(gate.required) != 1 || gate.required[0] != plan.ID {
		t.Fatalf("launch-key require calls = %#v, want plan id", gate.required)
	}

	gate.requireErr = nil
	result, err := service.RequireStartReady(context.Background(), StartRequest{Workspace: ".hovel", PlanID: plan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.Plan.ID != plan.ID || result.Confirmation.PlanHash != plan.PlanHash {
		t.Fatalf("start readiness = %#v", result)
	}
}

func mustPlan(t *testing.T, req PlanRequest) PlanRecord {
	t.Helper()
	service := NewService(ServiceOptions{Plans: &fakePlanRepository{}, Clock: fixedClock{now: testNow()}})
	plan, err := service.BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan(%#v) returned error: %v", req, err)
	}
	return plan
}

func testNow() time.Time {
	return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type fakePlanRepository struct {
	records []PlanRecord
}

func (r *fakePlanRepository) RecordPlan(_ context.Context, plan PlanRecord) error {
	r.records = append(r.records, plan)
	return nil
}

func (r *fakePlanRepository) GetPlan(_ context.Context, workspace, id string) (PlanRecord, bool, error) {
	for _, plan := range r.records {
		if plan.Workspace == workspace && plan.ID == id {
			return plan, true, nil
		}
	}
	return PlanRecord{}, false, nil
}

type fakeConfirmationRepository struct {
	records []ConfirmationRecord
}

func (r *fakeConfirmationRepository) RecordConfirmation(_ context.Context, confirmation ConfirmationRecord) error {
	r.records = append(r.records, confirmation)
	return nil
}

func (r *fakeConfirmationRepository) GetConfirmation(_ context.Context, workspace, planHash string) (ConfirmationRecord, bool, error) {
	for _, confirmation := range r.records {
		if confirmation.Workspace == workspace && confirmation.PlanHash == planHash {
			return confirmation, true, nil
		}
	}
	return ConfirmationRecord{}, false, nil
}

var errLaunchKeyMissing = errString("launch-key approvals missing: entity-cli")

type errString string

func (e errString) Error() string {
	return string(e)
}

type fakeLaunchKeyGate struct {
	created    []PendingRequest
	confirmed  []PendingConfirmation
	required   []string
	requireErr error
}

func (g *fakeLaunchKeyGate) CreatePending(_ context.Context, req PendingRequest) (PendingStatus, error) {
	g.created = append(g.created, req)
	return PendingStatus{ID: req.PendingID, Ready: true}, nil
}

func (g *fakeLaunchKeyGate) Confirm(_ context.Context, req PendingConfirmation) (PendingStatus, error) {
	g.confirmed = append(g.confirmed, req)
	return PendingStatus{ID: req.PendingID, Ready: true}, nil
}

func (g *fakeLaunchKeyGate) RequireReady(_ context.Context, pendingID string) (PendingStatus, error) {
	g.required = append(g.required, pendingID)
	if g.requireErr != nil {
		return PendingStatus{ID: pendingID, Ready: false, MissingApproverIDs: []string{"entity-cli"}}, g.requireErr
	}
	return PendingStatus{ID: pendingID, Ready: true}, nil
}
