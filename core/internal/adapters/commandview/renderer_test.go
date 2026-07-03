package commandview

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
)

func TestRendererUsesCharmTableForModuleInventory(t *testing.T) {
	rendered, ok := New(100).Render(commands.Result{JSON: commands.ModuleInventoryPayload{
		Modules: []commands.ModuleInventoryRecord{{
			ID:         "mock-exploit@v0.0.0-example",
			Type:       modulecatalog.TypeExploit,
			Scope:      "chain",
			SourceKind: "catalog",
			Summary:    "Run an example exploit flow.",
		}},
	}})
	if !ok {
		t.Fatal("renderer did not handle module inventory")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"╭", "ID", "TYPE", "SOURCE", "mock-exploit@v0.0.0-example", "Run an example exploit flow."} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered inventory missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererBuildsModuleInspectCard(t *testing.T) {
	rendered, ok := New(96).Render(commands.Result{JSON: commands.ModuleInspectPayload{
		ID:          "ms17-010-exploit@v1.0.0",
		Type:        modulecatalog.TypeExploit,
		Version:     "v1.0.0",
		RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
		Summary:     "SMB exploit module.",
		Description: "## Operator notes\n\nRun only after survey validation.",
		Enabled:     true,
		ChainConfig: []modulecatalog.Requirement{{
			Key:         "operator.confirmed_lab",
			Type:        modulecatalog.ValueBool,
			Required:    true,
			Description: "Operator confirmed this is an authorized lab.",
		}},
		Steps: []commands.ModuleStepPayload{{
			ID:    "smb.throw",
			Kind:  "exploit",
			Ready: true,
		}},
	}})
	if !ok {
		t.Fatal("renderer did not handle module inspect")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"MODULE", "ms17-010-exploit@v1.0.0", "Operator notes", "operator.confirmed_lab", "STEPS", "smb.throw", "Next: chain add ms17-010-exploit@v1.0.0"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered inspect missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererModuleInspectFitsDemoViewport(t *testing.T) {
	rendered, ok := New(96).Render(commands.Result{JSON: commands.ModuleInspectPayload{
		ID:          "mock-survey-go@v0.0.0-example",
		Type:        modulecatalog.TypeSurvey,
		Version:     "v0.0.0-example",
		RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
		Author:      "hovel",
		Summary:     "Collect example target facts.",
		Description: "Example Go survey module for the Hovel stdio JSON-RPC runtime.",
		Tags:        []string{"example", "survey", "go"},
		Enabled:     true,
		TargetConfig: []modulecatalog.Requirement{
			{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
			{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
		},
	}})
	if !ok {
		t.Fatal("renderer did not handle module inspect")
	}
	plain := stripANSI(rendered)
	if !strings.Contains(plain, "Next: chain add mock-survey-go@v0.0.0-example") {
		t.Fatalf("rendered inspect missing next command:\n%s", rendered)
	}
	lines := strings.Split(plain, "\n")
	if len(lines) > 34 {
		t.Fatalf("rendered inspect is too tall for demo viewport: got %d lines\n%s", len(lines), rendered)
	}
	for _, line := range lines {
		if width := utf8.RuneCountInString(line); width > 100 {
			t.Fatalf("rendered inspect line is too wide: got %d columns in %q\n%s", width, line, rendered)
		}
	}
}

func TestRendererUsesCharmTableForArtifacts(t *testing.T) {
	rendered, ok := New(100).Render(commands.Result{JSON: []commands.ArtifactRecord{{
		ID:      "artifact-abc",
		ThrowID: "throw-alpha",
		Name:    "transcript.txt",
		Kind:    "text/plain",
		Size:    1536,
		Path:    "artifacts/throw-alpha/run-1/transcript.txt",
	}}})
	if !ok {
		t.Fatal("renderer did not handle artifact list")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"╭", "ID", "THROW", "NAME", "transcript.txt", "1.5 KiB", "artifacts/throw-alpha"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered artifacts missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererUsesCharmTableForSessions(t *testing.T) {
	rendered, ok := New(100).Render(commands.Result{JSON: []commands.SessionRef{{
		ID:        "id-3601208-20-session-1",
		Kind:      "agent",
		State:     "active",
		Target:    "192.168.122.142",
		Name:      "Squatter session",
		Transport: "smb",
	}}})
	if !ok {
		t.Fatal("renderer did not handle session list")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"╭", "ID", "KIND", "STATE", "TARGET", "NAME", "id-3601208-20-session-1", "Squatter session"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered sessions missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(plain, "TRANSPORT") {
		t.Fatalf("session list should not include transport column:\n%s", rendered)
	}
}

func TestRendererUsesCharmTableForPayloadCommands(t *testing.T) {
	rendered, ok := New(100).Render(commands.Result{JSON: []commands.PayloadCommand{
		{Name: "process.list", ReadOnly: true, Summary: "list processes using the native process snapshot API"},
		{Name: "process.run", Destructive: true, Summary: "run a process"},
	}})
	if !ok {
		t.Fatal("renderer did not handle payload commands")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"╭", "COMMAND", "EFFECT", "SUMMARY", "process.list", "safe", "process.run", "destructive"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered payload commands missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererPrettyPrintsCommandResultJSON(t *testing.T) {
	rendered, ok := New(100).Render(commands.Result{
		Human: "Session command completed: process.list",
		JSON: commands.PayloadCommandResult{
			Command: "process.list",
			Stdout:  `[{"pid":520,"imageName":"85f70dc2654a.exe"}]`,
		},
	})
	if !ok {
		t.Fatal("renderer did not handle command result")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"SESSION COMMAND", "process.list", "STDOUT", "[", "  {", "    \"pid\": 520"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered command result missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererBuildsArtifactInspectCard(t *testing.T) {
	rendered, ok := New(96).Render(commands.Result{JSON: commands.ArtifactRecord{
		ID:        "artifact-abc",
		ThrowID:   "throw-alpha",
		RunID:     "run-1",
		ModuleID:  "mock-exploit@v0.0.0-example",
		Target:    "mock://router-01",
		Name:      "transcript.txt",
		Kind:      "text/plain",
		Size:      12,
		SHA256:    "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
		Path:      "artifacts/throw-alpha/run-1/transcript.txt",
		CreatedAt: "2026-06-27T12:00:00Z",
	}})
	if !ok {
		t.Fatal("renderer did not handle artifact inspect")
	}
	plain := stripANSI(rendered)
	for _, want := range []string{"ARTIFACT", "artifact-abc", "transcript.txt", "throw-alpha", "mock-exploit@v0.0.0-example", "12 B", "sha256", "path"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered artifact inspect missing %q:\n%s", want, rendered)
		}
	}
}

func stripANSI(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
