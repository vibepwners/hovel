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

func TestMaterializeArtifactStoresBytesOutsideSQLite(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	record, err := store.MaterializeArtifact(context.Background(), commands.ArtifactMaterialization{
		Workspace: workspacePath,
		ThrowID:   "throw-mock",
		RunID:     "run-1",
		ModuleID:  "mock-exploit",
		Target:    "mock://target",
		Artifact: commands.Artifact{
			Name: "transcript.txt",
			Kind: "text/plain",
			Data: "operator transcript",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Size != len("operator transcript") || record.SHA256 == "" {
		t.Fatalf("artifact record = %#v", record)
	}
	data, err := os.ReadFile(filepath.Join(workspacePath, record.Path))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "operator transcript" {
		t.Fatalf("artifact bytes = %q", string(data))
	}
	artifacts, err := store.ListArtifacts(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(artifacts, []commands.ArtifactRecord{record}) {
		t.Fatalf("artifacts = %#v, want %#v", artifacts, []commands.ArtifactRecord{record})
	}
	got, err := store.GetArtifact(context.Background(), workspacePath, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, record) {
		t.Fatalf("artifact = %#v, want %#v", got, record)
	}
}

func TestMaterializeArtifactKeepsSameBytesDistinctAcrossThrows(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	materialization := commands.ArtifactMaterialization{
		Workspace: workspacePath,
		RunID:     "run-1",
		ModuleID:  "mock-exploit",
		Target:    "mock://target",
		Artifact: commands.Artifact{
			Name: "transcript.txt",
			Kind: "text/plain",
			Data: "same bytes",
		},
	}
	first := materialization
	first.ThrowID = "throw-one"
	firstRecord, err := store.MaterializeArtifact(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := materialization
	second.ThrowID = "throw-two"
	secondRecord, err := store.MaterializeArtifact(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}

	if firstRecord.ID == secondRecord.ID {
		t.Fatalf("artifact ids collided: %q", firstRecord.ID)
	}
	artifacts, err := store.ListArtifacts(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v, want two records", artifacts)
	}
}

func TestWorkspaceStoreDelegatesInstalledPayloadInventoryToSQLite(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	record := commands.InstalledPayloadRecord{
		Workspace:                workspacePath,
		Provider:                 "squatter",
		PayloadID:                "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		PayloadVersion:           "v0.1.0",
		Target:                   "192.168.122.142",
		TargetID:                 "t1",
		State:                    commands.PayloadStateInstalled,
		Transport:                "tcp-bind",
		Endpoint:                 "192.168.122.142:9101",
		InstanceKey:              "squatter:192.168.122.142:9101",
		SupportsReconnect:        true,
		SupportsMultipleSessions: true,
		Reconnect: &commands.PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"host": "192.168.122.142", "port": float64(9101)},
		},
		CreatedAt: "2026-05-03T12:00:00Z",
		UpdatedAt: "2026-05-03T12:00:00Z",
	}

	recorded, err := store.RecordInstalledPayload(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Handle != "p1" {
		t.Fatalf("handle = %q, want p1", recorded.Handle)
	}
	loaded, err := store.GetInstalledPayload(context.Background(), workspacePath, recorded.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, recorded) {
		t.Fatalf("loaded record = %#v, want %#v", loaded, recorded)
	}
	updated, err := store.UpdateInstalledPayloadState(context.Background(), workspacePath, recorded.Handle, commands.PayloadStateUnreachable, "connect failed")
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != commands.PayloadStateUnreachable {
		t.Fatalf("updated state = %q", updated.State)
	}
	list, err := store.ListInstalledPayloads(context.Background(), workspacePath, commands.InstalledPayloadFilter{State: commands.PayloadStateUnreachable})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Handle != recorded.Handle {
		t.Fatalf("filtered payloads = %#v", list)
	}
}

func TestMaterializeArtifactCopiesFileArtifactIntoWorkspace(t *testing.T) {
	store := NewWorkspaceStore()
	workspacePath := filepath.Join(t.TempDir(), ".hovel")
	sourcePath := filepath.Join(t.TempDir(), "loot.txt")
	if err := os.WriteFile(sourcePath, []byte("file artifact bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	record, err := store.MaterializeArtifact(context.Background(), commands.ArtifactMaterialization{
		Workspace: workspacePath,
		ThrowID:   "throw-mock",
		RunID:     "run-1",
		ModuleID:  "mock-exploit",
		Target:    "mock://target",
		Artifact: commands.Artifact{
			Name: "loot.txt",
			Kind: "text/plain",
			Path: sourcePath,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join("artifacts", "throw-mock", "run-1", "loot.txt")
	if record.Path != wantPath {
		t.Fatalf("path = %q, want workspace artifact path %q", record.Path, wantPath)
	}
	if record.Size != len("file artifact bytes") || record.SHA256 == "" {
		t.Fatalf("artifact record = %#v", record)
	}
	copied, err := os.ReadFile(filepath.Join(workspacePath, record.Path))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != "file artifact bytes" {
		t.Fatalf("copied artifact bytes = %q", string(copied))
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
