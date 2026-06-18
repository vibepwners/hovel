package sqlite

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
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
	refreshed := confirmation
	refreshed.Method = "reviewed_yes"
	refreshed.ConfirmedAt = "2026-05-03T12:05:00Z"
	if err := store.RecordThrowConfirmation(context.Background(), refreshed); err != nil {
		t.Fatal(err)
	}
	got, ok, err = store.GetThrowConfirmation(context.Background(), confirmation.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("refreshed confirmation not found")
	}
	if !reflect.DeepEqual(got, refreshed) {
		t.Fatalf("refreshed confirmation = %#v, want %#v", got, refreshed)
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
	artifacts, err := store.ListArtifacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(artifacts, []commands.ArtifactRecord{artifact}) {
		t.Fatalf("artifacts = %#v, want %#v", artifacts, []commands.ArtifactRecord{artifact})
	}
	got, err := store.GetArtifact(context.Background(), artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, artifact) {
		t.Fatalf("artifact = %#v, want %#v", got, artifact)
	}
}

func TestStorePersistsInstalledPayloadInventory(t *testing.T) {
	store := NewStore(t.TempDir())
	record := installedPayloadFixture(".hovel", "192.168.122.142", "9101")

	got, err := store.RecordInstalledPayload(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.Handle != "p1" {
		t.Fatalf("record identity = %#v, want generated id and p1 handle", got)
	}
	if got.State != commands.PayloadStateInstalled || got.CreatedAt != record.CreatedAt || got.UpdatedAt != record.UpdatedAt {
		t.Fatalf("record timestamps/state = %#v", got)
	}
	if got.Reconnect == nil || got.Reconnect.Descriptor["host"] != "192.168.122.142" {
		t.Fatalf("reconnect descriptor = %#v", got.Reconnect)
	}

	list, err := store.ListInstalledPayloads(context.Background(), ".hovel", commands.InstalledPayloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(list, []commands.InstalledPayloadRecord{got}) {
		t.Fatalf("installed payloads = %#v, want %#v", list, []commands.InstalledPayloadRecord{got})
	}
	inspected, err := store.GetInstalledPayload(context.Background(), ".hovel", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inspected, got) {
		t.Fatalf("inspected payload = %#v, want %#v", inspected, got)
	}
}

func TestStoreUpsertsInstalledPayloadByProviderInstance(t *testing.T) {
	store := NewStore(t.TempDir())
	first := installedPayloadFixture(".hovel", "192.168.122.142", "9101")
	recorded, err := store.RecordInstalledPayload(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}

	second := installedPayloadFixture(".hovel", "192.168.122.142", "9101")
	second.State = commands.PayloadStateConnected
	second.RunID = "run-2"
	second.UpdatedAt = "2026-05-03T12:02:00Z"
	second.LastSeenAt = "2026-05-03T12:02:00Z"
	upserted, err := store.RecordInstalledPayload(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if upserted.ID != recorded.ID || upserted.Handle != recorded.Handle || upserted.CreatedAt != recorded.CreatedAt {
		t.Fatalf("upserted identity = %#v, want id/handle/createdAt preserved from %#v", upserted, recorded)
	}
	if upserted.State != commands.PayloadStateConnected || upserted.RunID != "run-2" {
		t.Fatalf("upserted record = %#v", upserted)
	}
	list, err := store.ListInstalledPayloads(context.Background(), ".hovel", commands.InstalledPayloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RunID != "run-2" {
		t.Fatalf("installed payloads after upsert = %#v, want one updated record", list)
	}
}

func TestStoreInstalledPayloadStateTransitionsAndActiveFilter(t *testing.T) {
	store := NewStore(t.TempDir())
	first, err := store.RecordInstalledPayload(context.Background(), installedPayloadFixture(".hovel", "192.168.122.142", "9101"))
	if err != nil {
		t.Fatal(err)
	}
	second := installedPayloadFixture(".hovel", "192.168.122.143", "9102")
	second.InstanceKey = "squatter:192.168.122.143:9102"
	second.Endpoint = "192.168.122.143:9102"
	second.Reconnect.Descriptor["host"] = "192.168.122.143"
	second.Reconnect.Descriptor["port"] = float64(9102)
	second.Cleanup.Descriptor["remotePath"] = `C:\Windows\Temp\hovel-b.exe`
	second, err = store.RecordInstalledPayload(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := store.UpdateInstalledPayloadState(context.Background(), ".hovel", first.Handle, commands.PayloadStateRemoved, "operator cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if removed.State != commands.PayloadStateRemoved {
		t.Fatalf("removed payload state = %q", removed.State)
	}
	active, err := store.ListInstalledPayloads(context.Background(), ".hovel", commands.InstalledPayloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Handle != second.Handle {
		t.Fatalf("active payloads = %#v, want only second record", active)
	}
	all, err := store.ListInstalledPayloads(context.Background(), ".hovel", commands.InstalledPayloadFilter{IncludeRemoved: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all payloads = %#v, want removed and active records", all)
	}
	events, err := store.ListInstalledPayloadEvents(context.Background(), ".hovel", first.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "installed" || events[1].Type != "state_changed" || events[1].To != commands.PayloadStateRemoved {
		t.Fatalf("payload events = %#v", events)
	}
}

func TestStorePersistsStructuredEvents(t *testing.T) {
	store := NewStore(t.TempDir())
	id, _ := event.NewID("event-1")
	typ, _ := event.NewType("hovel.throw.started")
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      typ,
		Level:     event.LevelInfo,
		Message:   "throw started",
		Timestamp: mustTime("2026-05-03T12:00:00Z"),
		Topic:     "operation/default/chain/alpha/logs",
		Refs: event.Refs{
			WorkspaceID: ".hovel",
			Operation:   "default",
			Chain:       "alpha",
			ThrowID:     "throw-1",
			RunID:       "run-1",
			ModuleID:    "mock-exploit",
			TargetID:    "mock://target",
		},
		Fields: map[string]string{"planHash": "hash"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEvent(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(context.Background(), event.Filter{ThrowID: "throw-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v, want one deduped event", events)
	}
	if events[0].Message != "throw started" || events[0].Fields["planHash"] != "hash" {
		t.Fatalf("event = %#v", events[0])
	}
	events, err = store.ListEvents(context.Background(), event.Filter{Target: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events for other target = %#v", events)
	}
}

func installedPayloadFixture(workspacePath, target, port string) commands.InstalledPayloadRecord {
	return commands.InstalledPayloadRecord{
		Workspace:                workspacePath,
		Provider:                 "squatter",
		PayloadID:                "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		PayloadVersion:           "v0.1.0",
		Target:                   target,
		TargetID:                 "t1",
		State:                    commands.PayloadStateInstalled,
		Transport:                "tcp-bind",
		Endpoint:                 target + ":" + port,
		InstanceKey:              "squatter:" + target + ":" + port,
		StampID:                  "stamp-" + port,
		ArtifactIDs:              []string{"artifact-squatter"},
		SupportsReconnect:        true,
		SupportsMultipleSessions: true,
		Reconnect: &commands.PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"host": target, "port": float64(9101)},
		},
		Cleanup: &commands.PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.cleanup",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"remotePath": `C:\Windows\Temp\hovel-a.exe`},
		},
		Operation:  "default",
		Chain:      "c1",
		ThrowID:    "throw-1",
		RunID:      "run-1",
		CreatedAt:  "2026-05-03T12:00:00Z",
		UpdatedAt:  "2026-05-03T12:00:00Z",
		LastSeenAt: "2026-05-03T12:00:00Z",
		Metadata:   map[string]string{"profile": "XP_SP2SP3_X86"},
	}
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}
