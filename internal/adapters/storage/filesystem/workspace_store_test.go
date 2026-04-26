package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
		"runs",
		"services",
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
