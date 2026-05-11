package commandmode

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
)

func TestChainFileDiskStoreRoundTripsConfiguredChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alpha.chain.yaml")
	store := chainFileDiskStore{}
	want := commands.ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   commands.ChainFileMetadata{Name: "alpha"},
		Spec: commands.ChainFileSpec{
			Mode: "configured",
			Steps: []commands.ChainFileStep{
				{ID: "step-1", Uses: "module:mock-exploit@v0.0.0-example"},
				{ID: "step-2", Uses: "module:mock-survey@v0.0.0-example"},
			},
			Config: map[string]string{"operator.confirmed_lab": "true"},
			Targets: []commands.ChainFileTarget{
				{ID: "mock://alpha", Config: map[string]string{"target.host": "router-01"}},
				{ID: "mock://beta", Config: map[string]string{"target.host": "router-02", "target.port": "22"}},
			},
		},
	}

	if err := store.WriteChainFile(context.Background(), path, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.ReadChainFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain file = %#v, want %#v", got, want)
	}
}

func TestFormatChainFileOmitsConfiguredDataForTemplate(t *testing.T) {
	text := formatChainFile(commands.ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   commands.ChainFileMetadata{Name: "alpha"},
		Spec: commands.ChainFileSpec{
			Mode:    "template",
			Steps:   []commands.ChainFileStep{{ID: "step-1", Uses: "module:mock-exploit@v0.0.0-example"}},
			Config:  map[string]string{"operator.confirmed_lab": "true"},
			Targets: []commands.ChainFileTarget{{ID: "mock://alpha"}},
		},
	})

	for _, blocked := range []string{"operator.confirmed_lab", "targets:", "mock://alpha"} {
		if strings.Contains(text, blocked) {
			t.Fatalf("template output contains configured data %q:\n%s", blocked, text)
		}
	}
}
