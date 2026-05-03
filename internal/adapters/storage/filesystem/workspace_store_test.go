package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

func TestInitWorkspaceCreatesLayout(t *testing.T) {
	store := NewWorkspaceStore()
	ws := testWorkspace(t, filepath.Join(t.TempDir(), ".hovel"))

	record, err := store.InitWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Created {
		t.Fatal("Created = false, want true")
	}

	for _, rel := range []string{
		"workspace.json",
		"artifacts",
		"logs",
		"modules",
		"throws",
		"services",
		sqlitestore.DatabaseFile,
	} {
		if _, err := os.Stat(filepath.Join(ws.Path, rel)); err != nil {
			t.Fatalf("expected %s to exist: %v", rel, err)
		}
	}
}

func TestInitWorkspaceIsIdempotent(t *testing.T) {
	store := NewWorkspaceStore()
	ws := testWorkspace(t, filepath.Join(t.TempDir(), ".hovel"))

	first, err := store.InitWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.InitWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}

	if !first.Created {
		t.Fatal("first Created = false, want true")
	}
	if second.Created {
		t.Fatal("second Created = true, want false")
	}
	if second.Workspace.ID != first.Workspace.ID {
		t.Fatalf("workspace ID = %q, want %q", second.Workspace.ID, first.Workspace.ID)
	}
}

func TestRecordThrowPlanPersistsAuditablePlan(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	plan := commands.ThrowPlanRecord{
		ID:             "plan-mock",
		ConfirmationID: "confirmation-mock",
		PlanHash:       "hash-mock",
		Workspace:      workspacePath,
		Chain:          "mock-exploit",
		Targets:        []string{"mock://target"},
		Review:         "operator-confirmed",
		Intent:         "throw chain mock-exploit against 1 target(s)",
	}

	if err := store.RecordThrowPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetThrowPlan(context.Background(), workspacePath, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, plan) {
		t.Fatalf("plan = %#v, want %#v", got, plan)
	}
	plans, err := store.ListThrowPlans(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plans, []commands.ThrowPlanRecord{plan}) {
		t.Fatalf("plans = %#v, want %#v", plans, []commands.ThrowPlanRecord{plan})
	}
	inspected, err := store.GetThrowPlan(context.Background(), workspacePath, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inspected, plan) {
		t.Fatalf("inspected plan = %#v, want %#v", inspected, plan)
	}

	confirmation := commands.ThrowConfirmationRecord{
		ID:          plan.ConfirmationID,
		Workspace:   workspacePath,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		ClientID:    "command",
		Method:      "preconfirmed",
		ConfirmedAt: "2026-05-03T12:00:00Z",
	}
	if err := store.RecordThrowConfirmation(context.Background(), confirmation); err != nil {
		t.Fatal(err)
	}
	gotConfirmation, ok, err := store.GetThrowConfirmation(context.Background(), workspacePath, plan.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("confirmation not found")
	}
	if !reflect.DeepEqual(gotConfirmation, confirmation) {
		t.Fatalf("confirmation = %#v, want %#v", gotConfirmation, confirmation)
	}
}

func TestOperatorSessionPersistsInWorkspaceDatabase(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	state := operatorsession.PersistedState{
		ActiveOperation: "redteam-lab",
		ActiveChain:     "alpha",
		Operations: []operatorsession.PersistedOperation{
			{Name: "redteam-lab", Chains: []operatorsession.PersistedChain{{Name: "alpha"}}},
		},
	}

	if err := store.SaveOperatorSession(context.Background(), workspacePath, state); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadOperatorSession(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("operator session not found")
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("state = %#v, want %#v", got, state)
	}
}

func testWorkspace(t *testing.T, path string) workspace.Workspace {
	t.Helper()
	id, err := workspace.NewID("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	name, err := workspace.NewName("lab")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.New(id, name, path)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}
