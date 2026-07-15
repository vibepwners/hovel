package progressview

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/internal/app/modulepackage"
)

func TestInstallRendererPlainOutput(t *testing.T) {
	var out bytes.Buffer
	renderer := NewInstallRenderer(&out, 0, true)
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

func TestInstallRendererLiveOutputReachesComplete(t *testing.T) {
	var out bytes.Buffer
	renderer := NewInstallRenderer(&out, 80, true)
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadProgress,
		Source: "https://example.test/releases/archive.tgz",
		Bytes:  2048,
		Total:  2048,
	})
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadComplete,
		Source: "https://example.test/releases/archive.tgz",
		Bytes:  2048,
		Total:  2048,
	})

	text := out.String()
	if !strings.Contains(text, "100%") {
		t.Fatalf("progress output did not reach 100%%:\n%q", text)
	}
	if !strings.Contains(text, "downloaded example.test/archive.tgz") {
		t.Fatalf("progress output missing completion line:\n%q", text)
	}
}
