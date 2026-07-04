package uicatalog

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestListIncludesRegisteredDemos(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"list", "--no-color"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run code = %d, stderr = %s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"logs", "download-progress", "upload-progress", "module-card", "command-table", "status-panel"} {
		if !strings.Contains(text, want) {
			t.Fatalf("list output missing %q:\n%s", want, text)
		}
	}
}

func TestUnknownDemoReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"show", "missing-demo"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown demo "missing-demo"`) {
		t.Fatalf("stderr missing unknown demo message:\n%s", stderr.String())
	}
}

func TestStaticDemosRenderExpectedMarkers(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "logs", want: "HOVEL//RUN"},
		{name: "module-card", want: "MODULE"},
		{name: "command-table", want: "mock-survey-go"},
		{name: "status-panel", want: "UI CATALOG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"show", tt.name, "--width", "96", "--no-color"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run code = %d, stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.want) {
				t.Fatalf("demo output missing %q:\n%s", tt.want, stdout.String())
			}
			if strings.Contains(stdout.String(), "\x1b[") {
				t.Fatalf("demo output contains ANSI escapes:\n%q", stdout.String())
			}
		})
	}
}

func TestProgressDemoCanRenderStaticNoColor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"show", "download-progress", "--width", "96", "--frames", "2", "--delay", "0s", "--static", "--no-color"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run code = %d, stderr = %s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"download modules.example.test/mock-exploit-session.tgz", "downloaded modules.example.test/mock-exploit-session.tgz", "verified sha256", "installed mock-exploit-session@v0.0.0-example"} {
		if !strings.Contains(text, want) {
			t.Fatalf("progress demo missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("progress output contains ANSI escapes:\n%q", text)
	}
}

func TestUploadProgressDemoUsesUploadLabels(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"show", "upload-progress", "--width", "96", "--frames", "2", "--delay", "0s", "--static", "--no-color"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run code = %d, stderr = %s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"upload mock-survey-report.json", "uploaded mock-survey-report.json"} {
		if !strings.Contains(text, want) {
			t.Fatalf("upload progress demo missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "download") {
		t.Fatalf("upload progress demo used download label:\n%s", text)
	}
}
