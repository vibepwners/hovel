package commandmode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/internal/app/modulepackage"
)

func TestInstallProgressRendererPlainOutput(t *testing.T) {
	var out bytes.Buffer
	renderer := newInstallProgressRenderer(&out, 0, true)
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadStart,
		Source: "https://example.test/releases/module-install-set.yaml",
		Total:  1024,
	})
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadComplete,
		Source: "https://example.test/releases/module-install-set.yaml",
		Bytes:  1024,
		Total:  1024,
	})
	renderer.Handle(modulepackage.InstallProgress{
		Stage:   modulepackage.InstallProgressArchiveComplete,
		Name:    "mock-survey",
		Version: "v0.1.0",
	})

	text := out.String()
	for _, want := range []string{"download example.test/module-install-set.yaml", "downloaded example.test/module-install-set.yaml", "installed mock-survey@v0.1.0"} {
		if !strings.Contains(text, want) {
			t.Fatalf("progress output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("plain progress output contains ANSI escapes:\n%q", text)
	}
}
