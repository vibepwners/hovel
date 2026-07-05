package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
	"github.com/Vibe-Pwners/hovel/sdk/go/hoveltest"
)

func TestPayloadProviderContract(t *testing.T) {
	root := t.TempDir()
	blobDir := filepath.Join(root, "python", "picblobs", "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "hello.linux.x86_64.bin"), []byte("hello-picblob"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"catalog": map[string]any{
			"hello": map[string]any{
				"platforms": map[string][]string{"linux": []string{"x86_64"}},
			},
		},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "python", "picblobs", "manifest.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	hoveltest.AssertPayloadProviderContract(t, &Provider{Root: root}, hoveltest.PayloadProviderContract{
		Query: hovel.PayloadQuery{
			Target:   "hello",
			Platform: "linux",
			Arch:     "x86_64",
			Format:   "bin",
		},
		Target:           "lab-target",
		RunID:            "run-1",
		WantFormat:       "bin",
		WantTransport:    "stdio",
		WantCapabilities: []string{"payload.pic"},
	})
}
