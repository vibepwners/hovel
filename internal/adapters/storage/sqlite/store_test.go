package sqlite

import (
	"context"
	"reflect"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
)

func TestStorePersistsOperatorSession(t *testing.T) {
	store := NewStore(t.TempDir())
	state := operatorsession.PersistedState{
		ActiveOperation: "redteam-lab",
		ActiveChain:     "alpha",
		Operations: []operatorsession.PersistedOperation{
			{
				Name: "redteam-lab",
				Chains: []operatorsession.PersistedChain{
					{
						Name:    "alpha",
						Targets: []string{"mock://target"},
						Steps:   []operatorsession.Step{{ID: "step-1", ModuleID: "mock-exploit"}},
						Config:  map[string]string{"operator.confirmed_lab": "true"},
					},
				},
			},
		},
	}

	if err := store.SaveOperatorSession(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadOperatorSession(context.Background())
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

func TestStoreReportsMissingOperatorSession(t *testing.T) {
	store := NewStore(t.TempDir())
	_, ok, err := store.LoadOperatorSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("operator session found = true, want false")
	}
}

func TestStorePersistsThrowPlans(t *testing.T) {
	store := NewStore(t.TempDir())
	plan := commands.ThrowPlanRecord{
		ID:             "plan-mock",
		ConfirmationID: "confirmation-mock",
		PlanHash:       "hash-mock",
		Workspace:      ".hovel",
		Chain:          "mock-exploit",
		Targets:        []string{"mock://target"},
		Review:         "operator-confirmed",
		Intent:         "throw chain mock-exploit against 1 target(s)",
	}

	if err := store.RecordThrowPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	plans, err := store.ListThrowPlans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plans, []commands.ThrowPlanRecord{plan}) {
		t.Fatalf("plans = %#v, want %#v", plans, []commands.ThrowPlanRecord{plan})
	}
	got, err := store.GetThrowPlan(context.Background(), plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, plan) {
		t.Fatalf("plan = %#v, want %#v", got, plan)
	}
}

func TestStorePersistsThrowConfirmations(t *testing.T) {
	store := NewStore(t.TempDir())
	confirmation := commands.ThrowConfirmationRecord{
		ID:          "confirmation-mock",
		Workspace:   ".hovel",
		PlanID:      "plan-mock",
		PlanHash:    "hash-mock",
		ClientID:    "command",
		Method:      "preconfirmed",
		ConfirmedAt: "2026-05-03T12:00:00Z",
	}

	if err := store.RecordThrowConfirmation(context.Background(), confirmation); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.GetThrowConfirmation(context.Background(), confirmation.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("confirmation not found")
	}
	if !reflect.DeepEqual(got, confirmation) {
		t.Fatalf("confirmation = %#v, want %#v", got, confirmation)
	}
	_, ok, err = store.GetThrowConfirmation(context.Background(), "other-hash")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("unexpected confirmation for other hash")
	}
}

func TestStorePersistsThrowRecordsAndArtifactMetadata(t *testing.T) {
	store := NewStore(t.TempDir())
	record := commands.ThrowRecord{
		ID:          "throw-mock",
		Workspace:   ".hovel",
		PlanID:      "plan-mock",
		PlanHash:    "hash-mock",
		Chain:       "mock-exploit",
		Targets:     []string{"mock://target"},
		State:       "succeeded",
		StartedAt:   "2026-05-03T12:00:00Z",
		CompletedAt: "2026-05-03T12:00:01Z",
		Runs:        []commands.RunSummary{{RunID: "run-1", ModuleID: "mock-exploit", Target: "mock://target", State: "succeeded", Artifacts: 1}},
	}
	if err := store.RecordThrow(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	artifact := commands.ArtifactRecord{
		ID:        "artifact-mock",
		Workspace: ".hovel",
		ThrowID:   record.ID,
		RunID:     "run-1",
		ModuleID:  "mock-exploit",
		Target:    "mock://target",
		Name:      "transcript.txt",
		Kind:      "text/plain",
		Path:      "artifacts/throw-mock/run-1/transcript.txt",
		SHA256:    "abc123",
		Size:      12,
		CreatedAt: "2026-05-03T12:00:01Z",
	}
	if err := store.RecordArtifact(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
}
