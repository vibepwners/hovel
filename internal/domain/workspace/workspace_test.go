package workspace

import "testing"

func TestNewNameValidation(t *testing.T) {
	valid := []string{"lab", "router-01", "lab_2", "lab.prod"}
	for _, value := range valid {
		name, err := NewName(value)
		if err != nil {
			t.Fatalf("NewName(%q) returned error: %v", value, err)
		}
		if name.String() != value {
			t.Fatalf("NewName(%q) = %q", value, name.String())
		}
	}

	invalid := []string{"", " ", "../lab", "lab/name", "lab name"}
	for _, value := range invalid {
		if _, err := NewName(value); err == nil {
			t.Fatalf("NewName(%q) returned nil error", value)
		}
	}
}

func TestNewIDRejectsEmpty(t *testing.T) {
	if _, err := NewID(""); err == nil {
		t.Fatal("NewID returned nil error for empty value")
	}
}

func TestResolvePathUsesDefault(t *testing.T) {
	if got := ResolvePath(""); got != ".hovel" {
		t.Fatalf("ResolvePath(\"\") = %q, want .hovel", got)
	}
}

func TestNewWorkspace(t *testing.T) {
	id, err := NewID("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	name, err := NewName("lab")
	if err != nil {
		t.Fatal(err)
	}

	ws, err := New(id, name, ".hovel")
	if err != nil {
		t.Fatal(err)
	}
	if ws.ID != id {
		t.Fatalf("workspace ID = %q, want %q", ws.ID, id)
	}
	if ws.Name != name {
		t.Fatalf("workspace name = %q, want %q", ws.Name, name)
	}
	if ws.Path != ".hovel" {
		t.Fatalf("workspace path = %q, want .hovel", ws.Path)
	}
}
