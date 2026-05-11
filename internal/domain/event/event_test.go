package event

import (
	"context"
	"testing"
	"time"
)

func TestNewEventRequiresIdentityTypeAndTimestamp(t *testing.T) {
	typ, err := NewType("workspace.initialized")
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewID("event-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := New(Args{Type: typ, Timestamp: time.Now()}); err == nil {
		t.Fatal("New returned nil error without ID")
	}
	if _, err := New(Args{ID: id, Timestamp: time.Now()}); err == nil {
		t.Fatal("New returned nil error without type")
	}
	if _, err := New(Args{ID: id, Type: typ}); err == nil {
		t.Fatal("New returned nil error without timestamp")
	}
}

func TestNewEventCarriesReferencesAndFields(t *testing.T) {
	id, err := NewID("event-1")
	if err != nil {
		t.Fatal(err)
	}
	typ, err := NewType("workspace.initialized")
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	evt, err := New(Args{
		ID:        id,
		Type:      typ,
		Message:   "workspace initialized",
		Timestamp: ts,
		Refs: Refs{
			WorkspaceID: "workspace-1",
			Operation:   "op",
			Chain:       "chain",
			ThrowID:     "throw-1",
			RunID:       "run-1",
			ModuleID:    "module-1",
			ServiceID:   "service-1",
			TargetID:    "target-1",
		},
		Fields: map[string]string{"path": ".hovel"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if evt.ID != id || evt.Type != typ || !evt.Timestamp.Equal(ts) {
		t.Fatalf("event identity = %#v", evt)
	}
	if evt.SchemaVersion != "hovel.event/v1alpha1" || evt.Level != LevelInfo || evt.Message != "workspace initialized" {
		t.Fatalf("event envelope = %#v", evt)
	}
	if evt.Refs.WorkspaceID != "workspace-1" || evt.Refs.RunID != "run-1" {
		t.Fatalf("event refs = %#v", evt.Refs)
	}
	if evt.Fields["path"] != ".hovel" {
		t.Fatalf("event fields = %#v", evt.Fields)
	}
}

func TestFilterMatchesEnvelopeAndRefs(t *testing.T) {
	id, _ := NewID("event-1")
	typ, _ := NewType("hovel.throw.started")
	evt, err := New(Args{
		ID:        id,
		Type:      typ,
		Level:     LevelInfo,
		Message:   "throw started",
		Timestamp: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		Topic:     "operation/op/chain/chain/logs",
		Refs: Refs{
			WorkspaceID: ".hovel",
			Operation:   "op",
			Chain:       "chain",
			ThrowID:     "throw-1",
			RunID:       "run-1",
			ModuleID:    "module-1",
			TargetID:    "mock://target",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !(Filter{Workspace: ".hovel", Operation: "op", Chain: "chain", ThrowID: "throw-1", Type: "hovel.throw.started"}).Match(evt) {
		t.Fatal("filter did not match event")
	}
	if (Filter{Target: "other"}).Match(evt) {
		t.Fatal("filter matched wrong target")
	}
}

func TestBusFansOutToMatchingHandlers(t *testing.T) {
	id, _ := NewID("event-1")
	typ, _ := NewType("hovel.throw.started")
	evt, _ := New(Args{ID: id, Type: typ, Timestamp: time.Now(), Refs: Refs{Chain: "alpha"}})
	alpha := &Recorder{Filter: Filter{Chain: "alpha"}}
	beta := &Recorder{Filter: Filter{Chain: "beta"}}
	bus := NewBus(
		Subscription{Filter: alpha.Filter, Handler: alpha},
		Subscription{Filter: beta.Filter, Handler: beta},
	)
	if err := bus.Append(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if len(alpha.Events) != 1 {
		t.Fatalf("alpha events = %d, want 1", len(alpha.Events))
	}
	if len(beta.Events) != 0 {
		t.Fatalf("beta events = %d, want 0", len(beta.Events))
	}
}

func TestTypeRejectsInvalidValues(t *testing.T) {
	invalid := []string{"", " ", "workspace initialized", "workspace/initialized"}
	for _, value := range invalid {
		if _, err := NewType(value); err == nil {
			t.Fatalf("NewType(%q) returned nil error", value)
		}
	}
}
