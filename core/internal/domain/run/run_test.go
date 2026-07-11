package run

import "testing"

func TestSessionRefHasCapability(t *testing.T) {
	session := SessionRef{Capabilities: []string{"read", " datagram "}}
	if !session.HasCapability(SessionCapabilityDatagram) {
		t.Fatal("HasCapability(datagram) = false, want true")
	}
	if session.HasCapability("") || session.HasCapability("write") {
		t.Fatal("HasCapability reported an unadvertised capability")
	}
}

func TestNewRequestRequiresModuleAndTarget(t *testing.T) {
	_, err := NewRequest(RequestArgs{ID: "run-1", ModuleID: "mock-exploit", Target: ""})
	if err == nil {
		t.Fatal("NewRequest returned nil error for missing target")
	}

	_, err = NewRequest(RequestArgs{ID: "run-1", ModuleID: "", Target: "mock://target"})
	if err == nil {
		t.Fatal("NewRequest returned nil error for missing module")
	}
}

func TestSucceededResultCapturesMockExploitOutcome(t *testing.T) {
	request, err := NewRequest(RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Succeeded(request, ResultArgs{
		Summary: "mock exploit completed",
		Findings: []Finding{{
			Title:    "mock finding",
			Severity: SeverityInfo,
			Detail:   "no target interaction occurred",
		}},
		Artifacts: []Artifact{{
			Name: "mock-transcript.txt",
			Kind: "text/plain",
			Data: "mock transcript",
		}},
		Logs: []LogEntry{{
			Kind:       "event",
			Level:      "info",
			Source:     "module",
			Message:    "module started",
			RunID:      "run-1",
			Target:     "mock://target",
			ModuleID:   "mock-exploit",
			Fields:     map[string]string{"target": "mock://target"},
			Attributes: map[string]string{"logger": "mock"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.State != StateSucceeded {
		t.Fatalf("state = %q, want %q", result.State, StateSucceeded)
	}
	if result.ID != "run-1" {
		t.Fatalf("id = %q, want run-1", result.ID)
	}
	if result.ModuleID != "mock-exploit" {
		t.Fatalf("module = %q, want mock-exploit", result.ModuleID)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
	if len(result.Logs) != 1 {
		t.Fatalf("log count = %d, want 1", len(result.Logs))
	}
	if result.Logs[0].ModuleID != "mock-exploit" {
		t.Fatalf("log module = %q, want mock-exploit", result.Logs[0].ModuleID)
	}
	result.Logs[0].Fields["target"] = "mutated"
	if result.Logs[0].Fields["target"] != "mutated" {
		t.Fatal("sanity check failed")
	}
}

func TestFailedResultCapturesFailureState(t *testing.T) {
	request, err := NewRequest(RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Failed(request, ResultArgs{Summary: "mock failure"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateFailed {
		t.Fatalf("state = %q, want %q", result.State, StateFailed)
	}
}
