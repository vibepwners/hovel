package run

import "testing"

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
}
