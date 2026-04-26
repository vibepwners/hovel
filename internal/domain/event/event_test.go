package event

import (
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
		Timestamp: ts,
		Refs: Refs{
			WorkspaceID: "workspace-1",
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
	if evt.Refs.WorkspaceID != "workspace-1" || evt.Refs.RunID != "run-1" {
		t.Fatalf("event refs = %#v", evt.Refs)
	}
	if evt.Fields["path"] != ".hovel" {
		t.Fatalf("event fields = %#v", evt.Fields)
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
