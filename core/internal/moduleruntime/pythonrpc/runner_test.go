package pythonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/chainruntime"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/mesh"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

func TestMain(m *testing.M) {
	defaultWorkspaceRoot, err := os.MkdirTemp("", "hovel-pythonrpc-default-workspace-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	previous, hadPrevious := os.LookupEnv("BUILD_WORKING_DIRECTORY")
	if err := os.Setenv("BUILD_WORKING_DIRECTORY", defaultWorkspaceRoot); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if hadPrevious {
		if err := os.Setenv("BUILD_WORKING_DIRECTORY", previous); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else {
		if err := os.Unsetenv("BUILD_WORKING_DIRECTORY"); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	if err := os.RemoveAll(defaultWorkspaceRoot); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

func TestRunnerExecutesPythonMockModule(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	result, err := Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1", "event-2", "event-3"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "example exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Data == "" {
		t.Fatalf("artifacts = %#v, want inline artifact data", result.Artifacts)
	}
	if len(events.events) == 0 || events.events[0].Type.String() != "hovel.module.log" {
		t.Fatalf("events = %#v, want hovel.module.log", events.events)
	}
}

func TestRunnerExecutesCommandModule(t *testing.T) {
	python, err := (Runner{}).pythonPath()
	if err != nil {
		t.Skipf("python interpreter unavailable: %v", err)
	}
	// A command-based entry launches an arbitrary executable that speaks the
	// stdio JSON-RPC protocol. We reuse the Python interpreter only as a generic
	// program here; the runner itself knows nothing about the language.
	script := filepath.Join(t.TempDir(), "command_module.py")
	body := `import json, sys

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    return json.loads(sys.stdin.buffer.read(length) or b"{}")

def send(message):
    out = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(out))
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()

while True:
    msg = read()
    method = msg.get("method")
    rid = msg.get("id")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "command-module", "version": "v0.0.0-test",
            "moduleType": "survey", "summary": "command launcher test", "tags": []}})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded", "summary": "command module executed",
            "findings": [{"title": "launched via command", "severity": "info", "detail": ""}],
            "artifacts": [], "outputs": {}, "sessions": []}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	config := ModuleConfig{Modules: []ModuleEntry{{
		ID:      "command-module",
		Runtime: "jsonrpc-stdio",
		Command: []string{python, script},
	}}}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}

	request, err := run.NewRequest(run.RequestArgs{ID: "run-cmd", ModuleID: "command-module", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{
		ConfigPath: configPath,
		Events:     &eventRecorder{},
		IDs:        &sequenceIDs{values: []string{"event-1"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "command module executed" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 || result.Findings[0].Title != "launched via command" {
		t.Fatalf("findings = %#v, want one launched-via-command finding", result.Findings)
	}
}

func TestRunnerPassesOptionalAgentContextAndPreservesHints(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "agent-aware", "version": "v0.0.0-test",
            "moduleType": "survey", "summary": "agent aware", "tags": []}})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "execute":
        params = request.get("params") or {}
        agent = params.get("agentContext")
        hints = []
        if agent:
            hints.append({
                "schema": "hovel.agent_hint.v1",
                "phase": "execute",
                "audience": "assistant",
                "risk": "low",
                "text": "Prefer read-only inspection before changing state.",
                "provenance": {"moduleId": "agent-aware@v0.0.0-test"}
            })
        entity = (agent or {}).get("entity") or {}
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded",
            "summary": "agent " + (entity.get("kind") or "absent"),
            "findings": [],
            "artifacts": [],
            "outputs": {},
            "sessions": [],
            "agentHints": hints}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	runner := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}

	ordinary, err := run.NewRequest(run.RequestArgs{ID: "run-ordinary", ModuleID: "broken", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}
	ordinaryResult, err := runner.Run(context.Background(), ordinary)
	if err != nil {
		t.Fatal(err)
	}
	if ordinaryResult.Summary != "agent absent" {
		t.Fatalf("ordinary summary = %q, want agent absent", ordinaryResult.Summary)
	}
	if len(ordinaryResult.AgentHints) != 0 {
		t.Fatalf("ordinary agent hints = %#v, want none", ordinaryResult.AgentHints)
	}

	agentRun, err := run.NewRequest(run.RequestArgs{
		ID:       "run-agent",
		ModuleID: "broken",
		Target:   "mock://target",
		Agent: &run.AgentContext{
			Schema: "hovel.agent_context.v1",
			Entity: run.AgentEntity{
				ID:          "entity-mcp",
				Kind:        "mcp",
				DisplayName: "Codex",
				Agent:       true,
			},
			Operation:     "redteam-lab",
			Chain:         "alpha",
			PlanID:        "plan-1",
			PlanHash:      "hash-1",
			ApprovalState: "pending",
			Phase:         "execute",
			Resources:     []string{"hovel://throw-plan/plan-1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentResult, err := runner.Run(context.Background(), agentRun)
	if err != nil {
		t.Fatal(err)
	}
	if agentResult.Summary != "agent mcp" {
		t.Fatalf("agent summary = %q, want agent mcp", agentResult.Summary)
	}
	if len(agentResult.AgentHints) != 1 {
		t.Fatalf("agent hints = %#v, want one", agentResult.AgentHints)
	}
	hint := agentResult.AgentHints[0]
	if hint.Schema != "hovel.agent_hint.v1" || hint.Text == "" || hint.Provenance["moduleId"] != "agent-aware@v0.0.0-test" {
		t.Fatalf("agent hint = %#v", hint)
	}
}

func TestModuleEntriesResolvesCommandPaths(t *testing.T) {
	root := t.TempDir()
	config := ModuleConfig{Modules: []ModuleEntry{
		{ID: "rel", Runtime: "jsonrpc-stdio", Command: []string{filepath.Join("bin", "mod-rel")}},
		{ID: "bare", Runtime: "jsonrpc-stdio", Command: []string{"go", "run", "."}},
	}}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := (Runner{ConfigPath: configPath}).moduleEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	// A relative path with a separator is resolved against the config directory.
	if want := filepath.Join(root, "bin", "mod-rel"); entries[0].Command[0] != want {
		t.Fatalf("rel command[0] = %q, want %q", entries[0].Command[0], want)
	}
	// A bare program name is left untouched for PATH lookup.
	if entries[1].Command[0] != "go" {
		t.Fatalf("bare command[0] = %q, want %q", entries[1].Command[0], "go")
	}
}

func TestModuleEntryPrefersExactVersionBeforeNameMatch(t *testing.T) {
	config := ModuleConfig{Modules: []ModuleEntry{
		{ID: "dupe@v1", Runtime: "jsonrpc-stdio", Command: []string{"/bin/sh"}},
		{ID: "dupe@v2", Runtime: "jsonrpc-stdio", Command: []string{"/bin/sh"}},
	}}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}

	entry, ok, err := (Runner{ConfigPath: configPath}).moduleEntry("dupe@v2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || entry.ID != "dupe@v2" {
		t.Fatalf("entry = %#v ok=%v, want exact v2 match", entry, ok)
	}
}

func TestModuleEntriesIncludeWorkspaceModuleLock(t *testing.T) {
	workspace := t.TempDir()
	moduleRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/locked"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "bin", "locked"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `apiVersion: hovel.dev/v1alpha1
kind: ModuleLock
modules:
  - name: locked
    version: 0.1.0
    source: ` + moduleRoot + `
    linked: true
    installedAt: "2026-06-22T18:00:00Z"
`
	if err := os.WriteFile(filepath.Join(workspace, "module-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := (Runner{WorkspacePath: workspace, ConfigPath: configPath}).moduleEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].ID != "locked@0.1.0" || entries[0].Command[0] != filepath.Join(moduleRoot, "bin", "locked") {
		t.Fatalf("entry = %#v", entries[0])
	}
}

func TestRunnerRunsInstalledPackageWithLaunchOnlyManifest(t *testing.T) {
	python, err := (Runner{}).pythonPath()
	if err != nil {
		t.Skipf("python interpreter unavailable: %v", err)
	}
	workspace := t.TempDir()
	moduleRoot := filepath.Join(workspace, "modules", "rpc-installed", "v1")
	if err := os.MkdirAll(moduleRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	script := writeCommandModuleScript(t, `{
            "name": "rpc-installed",
            "version": "v1",
            "moduleType": "survey",
            "summary": "installed from handshake"
        }`)
	manifest := fmt.Sprintf(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
launch:
  - selector: {}
    command: [%q, %q]
`, python, script)
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "module-lock.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModuleLock
modules:
  - name: rpc-installed
    version: v1
    source: `+moduleRoot+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	request, err := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "rpc-installed@v1", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Runner{WorkspacePath: workspace, ConfigPath: configPath, Timeout: 2 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ModuleID != "rpc-installed@v1" || result.Summary != "command module executed" {
		t.Fatalf("result = %#v, want RPC-installed module result", result)
	}
}

func TestModuleEntriesUseDefaultWorkspaceModuleLock(t *testing.T) {
	workdir := t.TempDir()
	t.Setenv("BUILD_WORKING_DIRECTORY", workdir)
	workspace := filepath.Join(workdir, ".hovel")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	moduleRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: default-locked
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/default-locked"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "bin", "default-locked"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `apiVersion: hovel.dev/v1alpha1
kind: ModuleLock
modules:
  - name: default-locked
    version: 0.1.0
    source: ` + moduleRoot + `
    linked: true
    installedAt: "2026-06-22T18:00:00Z"
`
	if err := os.WriteFile(filepath.Join(workspace, "module-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := (Runner{ConfigPath: configPath}).moduleEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].ID != "default-locked@0.1.0" || entries[0].Command[0] != filepath.Join(moduleRoot, "bin", "default-locked") {
		t.Fatalf("entry = %#v", entries[0])
	}
}

func TestModuleEntriesIncludeHovelConfigSearchPaths(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	packageParent := filepath.Join(workspace, "packages")
	moduleRoot := filepath.Join(packageParent, "configured")
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: configured
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - command: ["bin/configured"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "bin", "configured"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workspace, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
modules:
  searchPaths:
    - `+packageParent+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyConfigPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(legacyConfigPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := (Runner{WorkspacePath: workspace, ConfigPath: legacyConfigPath}).moduleEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].ID != "configured@0.1.0" || entries[0].Command[0] != filepath.Join(moduleRoot, "bin", "configured") {
		t.Fatalf("entry = %#v", entries[0])
	}
}

func TestRunnerRunsConfiguredPackageByRPCIdentityWhenManifestIsLaunchOnly(t *testing.T) {
	python, err := (Runner{}).pythonPath()
	if err != nil {
		t.Skipf("python interpreter unavailable: %v", err)
	}
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	packageParent := filepath.Join(workspace, "packages")
	moduleRoot := filepath.Join(packageParent, "configured")
	if err := os.MkdirAll(moduleRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	script := writeCommandModuleScript(t, `{
            "name": "rpc-configured",
            "version": "v2",
            "moduleType": "exploit",
            "summary": "configured from handshake"
        }`)
	manifest := fmt.Sprintf(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
launch:
  - command: [%q, %q]
`, python, script)
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "config.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
modules:
  searchPaths:
    - `+packageParent+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyConfigPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(legacyConfigPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	request, err := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "rpc-configured@v2", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Runner{WorkspacePath: workspace, ConfigPath: legacyConfigPath, Timeout: 2 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ModuleID != "rpc-configured@v2" || result.Summary != "command module executed" {
		t.Fatalf("result = %#v, want RPC-configured module result", result)
	}
}

func TestModuleEntriesPreserveInstalledPythonPackageRoot(t *testing.T) {
	workspace := t.TempDir()
	moduleRoot := filepath.Join(workspace, "modules", "installed-python", "0.1.0")
	if err := os.MkdirAll(filepath.Join(moduleRoot, "installed_python"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: installed-python
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    python:
      interpreter: /usr/bin/python3
      command: ["{python}", "-m", "installed_python"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "installed_python", "__main__.py"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "module-lock.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModuleLock
modules:
  - name: installed-python
    version: 0.1.0
    source: `+moduleRoot+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := (Runner{WorkspacePath: workspace, ConfigPath: configPath}).moduleEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].ID != "installed-python@0.1.0" {
		t.Fatalf("entry ID = %q", entries[0].ID)
	}
	if entries[0].ProjectDir != moduleRoot || entries[0].Module != "installed_python" {
		t.Fatalf("entry = %#v, want project dir %q and module installed_python", entries[0], moduleRoot)
	}
}

func TestModuleEntriesRejectsInvalidEntries(t *testing.T) {
	cases := []struct {
		name         string
		config       ModuleConfig
		wantFragment string
	}{
		{
			name: "missing id",
			config: ModuleConfig{Modules: []ModuleEntry{{
				Runtime:    "jsonrpc-stdio",
				ProjectDir: "project",
				Module:     "missing_id",
			}}},
			wantFragment: "module entry 1 missing id",
		},
		{
			name: "unsupported runtime",
			config: ModuleConfig{Modules: []ModuleEntry{{
				ID:      "not-jsonrpc",
				Runtime: "python",
				Command: []string{"python", "-m", "mod"},
			}}},
			wantFragment: `module "not-jsonrpc" uses unsupported runtime "python"`,
		},
		{
			name: "empty command",
			config: ModuleConfig{Modules: []ModuleEntry{{
				ID:      "empty-command",
				Runtime: "jsonrpc-stdio",
				Command: []string{""},
			}}},
			wantFragment: `module "empty-command" command[0] is required`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configBody, err := json.Marshal(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "modules.json")
			if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
				t.Fatal(err)
			}

			_, err = (Runner{ConfigPath: configPath}).moduleEntries()
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("error = %v, want %q", err, tc.wantFragment)
			}
		})
	}
}

func TestArtifactsFromRPCSupportsFileReferences(t *testing.T) {
	artifacts, err := artifactsFromRPC([]any{
		map[string]any{"name": "loot.txt", "kind": "text/plain", "path": "/tmp/loot.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifacts = %#v, want one", artifacts)
	}
	if artifacts[0].Path != "/tmp/loot.txt" || artifacts[0].Data != "" {
		t.Fatalf("artifact = %#v, want file reference without data", artifacts[0])
	}
}

func TestResultFromRPCRejectsMalformedCollections(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "broken", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		values       map[string]any
		wantFragment string
	}{
		{
			name: "finding is not object",
			values: map[string]any{
				"summary":  "bad result",
				"findings": []any{"not-an-object"},
			},
			wantFragment: "findings item 1 must be an object",
		},
		{
			name: "session missing id",
			values: map[string]any{
				"summary":  "bad result",
				"sessions": []any{map[string]any{"name": "missing id"}},
			},
			wantFragment: "sessions item 1 id is required",
		},
		{
			name: "installed payload missing payload id",
			values: map[string]any{
				"summary":           "bad result",
				"installedPayloads": []any{map[string]any{"provider": "squatter"}},
			},
			wantFragment: "installedPayloads item 1 payloadId is required",
		},
		{
			name: "installed payload artifact ids is not array",
			values: map[string]any{
				"summary": "bad result",
				"installedPayloads": []any{map[string]any{
					"provider":    "squatter",
					"payloadId":   "payload-1",
					"artifactIds": "artifact-1",
				}},
			},
			wantFragment: "installedPayloads item 1 artifactIds must be an array",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resultFromRPC(request, tc.values, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("error = %v, want %q", err, tc.wantFragment)
			}
		})
	}
}

func TestRunnerInspectsPythonModuleDeclaredSchema(t *testing.T) {
	module, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Inspect(context.Background(), "mock-exploit")
	if err != nil {
		t.Fatal(err)
	}
	if module.ID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("id = %q, want mock-exploit@v0.0.0-example", module.ID)
	}
	if module.RuntimeKind != "jsonrpc-stdio" {
		t.Fatalf("runtime = %q, want jsonrpc-stdio", module.RuntimeKind)
	}
	if len(module.ChainConfig) != 1 || module.ChainConfig[0].Key != "operator.confirmed_lab" {
		t.Fatalf("chain config = %#v", module.ChainConfig)
	}
	if len(module.TargetConfig) != 2 || module.TargetConfig[0].Key != "target.host" {
		t.Fatalf("target config = %#v", module.TargetConfig)
	}
}

func TestRunnerInspectEntryUsesHandshakeIdentityWithoutConfiguredID(t *testing.T) {
	python, err := (Runner{}).pythonPath()
	if err != nil {
		t.Skipf("python interpreter unavailable: %v", err)
	}
	script := writeCommandModuleScript(t, `{
            "name": "rpc-only",
            "version": "v0.0.1",
            "moduleType": "survey",
            "summary": "from handshake"
        }`)

	module, err := Runner{Timeout: 2 * time.Second}.InspectEntry(context.Background(), ModuleEntry{
		Runtime: "jsonrpc-stdio",
		Command: []string{python, script},
	})
	if err != nil {
		t.Fatal(err)
	}
	if module.ID != "rpc-only@v0.0.1" || module.Summary != "from handshake" {
		t.Fatalf("module = %#v, want RPC identity and metadata", module)
	}
}

func TestRunnerRequiresHandshakeIdentity(t *testing.T) {
	python, err := (Runner{}).pythonPath()
	if err != nil {
		t.Skipf("python interpreter unavailable: %v", err)
	}
	cases := []struct {
		name      string
		handshake string
		want      string
	}{
		{name: "missing name", handshake: `{"version":"v0.0.1","moduleType":"survey"}`, want: "module handshake missing name"},
		{name: "missing version", handshake: `{"name":"rpc-only","moduleType":"survey"}`, want: "module handshake missing version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := writeCommandModuleScript(t, tc.handshake)
			_, err := Runner{Timeout: 2 * time.Second}.InspectEntry(context.Background(), ModuleEntry{
				ID:      "configured-fallback@v9",
				Runtime: "jsonrpc-stdio",
				Command: []string{python, script},
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunnerRejectsMalformedSchemaRequirementShapes(t *testing.T) {
	cases := []struct {
		name           string
		handshakeExtra string
		schemaPayload  string
		wantFragment   string
	}{
		{
			name:           "tags is not array",
			handshakeExtra: `{"tags": "dangerous"}`,
			schemaPayload:  `{"chainConfig": [], "targetConfig": [], "outputs": {}}`,
			wantFragment:   "handshake tags must be an array",
		},
		{
			name:           "requirement is not object",
			handshakeExtra: `{}`,
			schemaPayload:  `{"chainConfig": [], "targetConfig": ["not-an-object"], "outputs": {}}`,
			wantFragment:   "targetConfig item 1 must be an object",
		},
		{
			name:           "requirement missing key",
			handshakeExtra: `{}`,
			schemaPayload:  `{"chainConfig": [{"type": "bool"}], "targetConfig": [], "outputs": {}}`,
			wantFragment:   "chainConfig item 1 key is required",
		},
		{
			name:           "unsupported type",
			handshakeExtra: `{}`,
			schemaPayload:  `{"chainConfig": [{"key": "target.meta", "type": "object"}], "targetConfig": [], "outputs": {}}`,
			wantFragment:   `chainConfig item 1 type "object" is unsupported`,
		},
		{
			name:           "allowed is not array",
			handshakeExtra: `{}`,
			schemaPayload:  `{"chainConfig": [{"key": "mode", "type": "enum", "allowed": "fast"}], "targetConfig": [], "outputs": {}}`,
			wantFragment:   "chainConfig item 1 allowed must be an array",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writePythonModuleFixture(t, fmt.Sprintf(`
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        result = {
            "name": "bad-schema",
            "version": "v0.0.0-test",
            "moduleType": "survey"
        }
        result.update(%s)
        send({"jsonrpc": "2.0", "id": rid, "result": result})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": %s})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"steps": []}})
    elif method == "execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded", "summary": "command module executed",
            "findings": [], "artifacts": [], "outputs": {}, "sessions": []}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`, tc.handshakeExtra, tc.schemaPayload))

			_, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.Inspect(context.Background(), "broken")
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("error = %v, want %q", err, tc.wantFragment)
			}
		})
	}
}

func TestRunnerInspectsPythonModuleStepContracts(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "stepper",
            "version": "v0.0.0-test",
            "moduleType": "payload_provider",
            "discoveryContext": {"summary": "Finds SMB paths", "keywords": ["ms17-010"]}
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {},
            "planningContext": {"risk": {"level": "medium", "reasons": ["opens a session"]}}
        }})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"version": "contracts-v1", "steps": [{
            "id": "squatter.connect_smb",
            "kind": "session.connector",
            "requires": [
                {"type": "PayloadInstance", "schemaVersion": "v1", "attributes": {"provider": "squatter", "transport": "smb-named-pipe"}, "states": ["installed", "unreachable"]},
                {"type": "CredentialCapability", "schemaVersion": "v1", "attributes": {"protocol": "smb"}, "states": ["active"]}
            ],
            "produces": [
                {"type": "SessionRef", "schemaVersion": "v1", "attributes": {"provider": "squatter", "transport": "smb-named-pipe"}}
            ],
            "context": {"summary": "Connect to SMB named-pipe payload", "capabilities": ["session.shell"]},
            "prepare": {"materializes": []}
        }]}})
    elif method == "mesh.describe":
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "module is not a mesh provider"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)

	module, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.Inspect(context.Background(), "broken")
	if err != nil {
		t.Fatal(err)
	}
	if module.ID != "stepper@v0.0.0-test" {
		t.Fatalf("id = %q, want stepper@v0.0.0-test", module.ID)
	}
	if module.StepContracts.Version != "contracts-v1" {
		t.Fatalf("contract version = %q", module.StepContracts.Version)
	}
	if module.Discovery.Summary != "Finds SMB paths" || module.Discovery.Keywords[0] != "ms17-010" {
		t.Fatalf("discovery context = %#v", module.Discovery)
	}
	if module.Planning.Risk.Level != "medium" {
		t.Fatalf("planning context = %#v", module.Planning)
	}
	if len(module.StepContracts.Steps) != 1 {
		t.Fatalf("steps = %#v, want one", module.StepContracts.Steps)
	}
	step := module.StepContracts.Steps[0]
	if step.ID != "squatter.connect_smb" || len(step.Requires) != 2 || len(step.Produces) != 1 {
		t.Fatalf("step contract = %#v", step)
	}
	if step.Requires[1].Attributes["protocol"] != "smb" {
		t.Fatalf("credential requirement = %#v", step.Requires[1])
	}
	if step.Context.Summary != "Connect to SMB named-pipe payload" || step.Context.Capabilities[0] != "session.shell" {
		t.Fatalf("step context = %#v", step.Context)
	}
}

func TestRunnerTreatsNonStepProviderAsLegacyModule(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "legacy-module",
            "version": "v0.0.0-test",
            "moduleType": "survey"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "module \"legacy-module\" is not a step provider"}})
    elif method == "mesh.describe":
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "module is not a mesh provider"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)

	module, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.Inspect(context.Background(), "broken")
	if err != nil {
		t.Fatal(err)
	}
	if module.ID != "legacy-module@v0.0.0-test" {
		t.Fatalf("id = %q, want legacy-module@v0.0.0-test", module.ID)
	}
	if len(module.StepContracts.Steps) != 0 {
		t.Fatalf("step contracts = %#v, want none", module.StepContracts)
	}
}

func TestRunnerCallsMeshProviderMethods(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
import base64
import time

last_stream_input = ""
prompt_sent = False
session_poll_seconds = 0.01

DESCRIPTOR = {
    "name": "mesh-provider",
    "version": "v0.0.0-test",
    "summary": "tree routed mesh",
    "capabilities": ["topology.tree", "listener.lifecycle", "task.survey", "stream.tcp"],
    "topology": {
        "root": "root",
        "nodes": [
            {"id": "root", "name": "controller", "kind": "controller", "state": "online"},
            {"id": "node-1", "parentId": "root", "name": "relay", "kind": "relay", "state": "online"},
            {"id": "node-2", "parentId": "node-1", "listenerId": "listener-primary", "name": "leaf", "kind": "agent", "state": "online"}
        ],
        "links": [
            {"id": "link-root-node-1", "source": "root", "target": "node-1", "kind": "relay", "state": "up"},
            {"id": "link-node-1-node-2", "source": "node-1", "target": "node-2", "kind": "relay", "state": "up"}
        ],
        "routes": [{
            "id": "route-node-2",
            "nodes": ["root", "node-1", "node-2"],
            "links": ["link-root-node-1", "link-node-1-node-2"]
        }]
    },
    "tasks": [
        {"kind": "survey", "summary": "survey node", "readOnly": True, "targetScopes": ["node"]},
        {"kind": "command", "summary": "run command", "targetScopes": ["node", "destination"]},
        {"kind": "upload_execute", "summary": "upload and execute", "destructive": True, "targetScopes": ["node", "destination"]}
    ],
    "listenerTypes": [{
        "kind": "https",
        "summary": "HTTPS beacon rendezvous",
        "deployments": ["separate"],
        "managementModes": ["provider", "external"],
        "protocols": ["https"],
        "configSchema": {"type": "object"},
        "capabilities": ["beacon"]
    }],
    "triggers": [{
        "id": "trig-beacon-command",
        "kind": "beacon",
        "nodeId": "node-2",
        "listenerId": "listener-primary",
        "state": "armed",
        "actionKind": "command"
    }]
}

while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "mesh-provider",
            "version": "v0.0.0-test",
            "moduleType": "payload_provider"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"steps": []}})
    elif method == "mesh.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": DESCRIPTOR})
    elif method == "mesh.topology":
        send({"jsonrpc": "2.0", "id": rid, "result": DESCRIPTOR["topology"]})
    elif method == "mesh.beacons":
        send({"jsonrpc": "2.0", "id": rid, "result": {"beacons": [{
            "id": "beacon-1",
            "nodeId": params.get("nodeId", "node-2"),
            "listenerId": params.get("listenerId", "listener-primary"),
            "state": "alive",
            "transport": "relay"
        }]}})
    elif method == "mesh.listeners":
        send({"jsonrpc": "2.0", "id": rid, "result": {"listeners": [{
            "id": params.get("listenerId", "listener-primary"),
            "name": "primary HTTPS listener",
            "kind": "https",
            "state": "active",
            "deployment": "separate",
            "management": "provider",
            "addresses": ["https://127.0.0.1:8443"],
            "protocols": ["https"]
        }]}})
    elif method == "mesh.listener.start":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "id": params.get("listenerId", ""),
            "name": params.get("name", ""),
            "kind": params.get("kind", ""),
            "state": "active",
            "deployment": params.get("deployment", ""),
            "management": params.get("management", ""),
            "addresses": ["https://127.0.0.1:8443"],
            "protocols": ["https"]
        }})
    elif method == "mesh.listener.stop":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "id": params.get("listenerId", ""),
            "state": "stopped",
            "deployment": "separate",
            "management": "provider"
        }})
    elif method == "mesh.task":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "taskId": params.get("taskId", ""),
            "status": "succeeded",
            "summary": "surveyed " + params.get("nodeId", ""),
            "nodeId": params.get("nodeId", ""),
            "listenerId": params.get("listenerId", ""),
            "destinationHost": params.get("destinationHost", ""),
            "destinationPort": params.get("destinationPort", 0),
            "protocol": params.get("protocol", ""),
            "outputs": {"os": "linux", "reachable": True},
            "beacons": [{"id": "beacon-task", "nodeId": params.get("nodeId", ""), "listenerId": params.get("listenerId", ""), "state": "alive"}]
        }})
    elif method == "mesh.open_stream":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "id": "mesh-session-1",
            "runId": params.get("runId", ""),
            "moduleId": "mesh-provider@v0.0.0-test",
            "target": params.get("target", ""),
            "name": "Mesh TCP stream",
            "kind": "stream",
            "state": "active",
            "transport": "mesh-route",
            "capabilities": ["read", "write", "close", "stream.tcp"]
        }})
    elif method == "session/read":
        if last_stream_input:
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "sessionId": "mesh-session-1",
                "data": base64.b64encode(("routed " + last_stream_input).encode()).decode(),
                "closed": False
            }})
            last_stream_input = ""
        elif not prompt_sent:
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "sessionId": "mesh-session-1",
                "data": base64.b64encode(b"mesh$ ").decode(),
                "closed": False
            }})
            prompt_sent = True
        else:
            time.sleep(session_poll_seconds)
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "sessionId": "mesh-session-1",
                "data": "",
                "closed": False
            }})
    elif method == "session/write":
        last_stream_input = base64.b64decode(params.get("data", "")).decode()
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
    elif method == "session/close":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
    else:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "unknown method " + str(method)}})
`)

	runner := Runner{ConfigPath: configPath, Timeout: 2 * time.Second, Sessions: NewSessionBroker()}
	module, err := runner.Inspect(context.Background(), "broken")
	if err != nil {
		t.Fatal(err)
	}
	if module.Mesh.Name != "mesh-provider" || len(module.Mesh.Tasks) != 3 ||
		len(module.Mesh.ListenerTypes) != 1 {
		t.Fatalf("catalog mesh descriptor = %#v", module.Mesh)
	}
	if module.Mesh.Topology == nil || len(module.Mesh.Topology.Nodes) != 3 {
		t.Fatalf("catalog mesh topology = %#v", module.Mesh.Topology)
	}

	descriptor, err := runner.DescribeMesh(context.Background(), "broken", mesh.DescribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Name != "mesh-provider" || len(descriptor.Triggers) != 1 ||
		descriptor.Triggers[0].ListenerID != "listener-primary" ||
		len(descriptor.ListenerTypes) != 1 ||
		descriptor.ListenerTypes[0].ManagementModes[1] != mesh.ListenerManagementExternal {
		t.Fatalf("mesh descriptor = %#v", descriptor)
	}
	topology, err := runner.MeshTopology(context.Background(), "broken", mesh.TopologyRequest{IncludeRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Nodes) != 3 || len(topology.Routes) != 1 {
		t.Fatalf("mesh topology = %#v", topology)
	}
	beacons, err := runner.ListMeshBeacons(context.Background(), "broken", mesh.BeaconRequest{
		NodeID:     "node-2",
		ListenerID: "listener-primary",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(beacons) != 1 || beacons[0].NodeID != "node-2" ||
		beacons[0].ListenerID != "listener-primary" {
		t.Fatalf("mesh beacons = %#v", beacons)
	}
	listeners, err := runner.ListMeshListeners(context.Background(), "broken", mesh.ListenerListRequest{
		ListenerID: "listener-primary",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 || listeners[0].ID != "listener-primary" ||
		listeners[0].Deployment != mesh.ListenerDeploymentSeparate {
		t.Fatalf("mesh listeners = %#v", listeners)
	}
	startedListener, err := runner.StartMeshListener(context.Background(), "broken", mesh.ListenerStartRequest{
		ListenerID: "listener-web",
		Name:       "web-controlled listener",
		Kind:       "https",
		Deployment: mesh.ListenerDeploymentSeparate,
		Management: mesh.ListenerManagementProvider,
		Config:     map[string]any{"token": "write-only-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if startedListener.ID != "listener-web" || startedListener.State != mesh.ListenerStateActive {
		t.Fatalf("started mesh listener = %#v", startedListener)
	}
	stoppedListener, err := runner.StopMeshListener(context.Background(), "broken", mesh.ListenerStopRequest{
		ListenerID: "listener-web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stoppedListener.ID != "listener-web" || stoppedListener.State != mesh.ListenerStateStopped {
		t.Fatalf("stopped mesh listener = %#v", stoppedListener)
	}
	task, err := runner.RunMeshTask(context.Background(), "broken", mesh.TaskRequest{
		RunID:           "run-mesh-1",
		TaskID:          "task-survey-1",
		Kind:            mesh.TaskSurvey,
		NodeID:          "node-2",
		ListenerID:      "listener-primary",
		DestinationHost: "10.10.10.10",
		DestinationPort: 445,
		Protocol:        "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != mesh.TaskStatusSucceeded ||
		task.Outputs["os"] != "linux" ||
		task.ListenerID != "listener-primary" ||
		len(task.Beacons) != 1 || task.Beacons[0].ListenerID != "listener-primary" ||
		task.DestinationHost != "10.10.10.10" {
		t.Fatalf("mesh task = %#v", task)
	}
	session, err := runner.OpenMeshStream(context.Background(), "broken", mesh.StreamRequest{
		RunID:           "run-mesh-2",
		Target:          "mock://mesh",
		NodeID:          "node-2",
		ListenerID:      "listener-primary",
		DestinationHost: "10.10.10.10",
		DestinationPort: 443,
		Protocol:        "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "mesh-session-1" || session.Transport != "mesh-route" {
		t.Fatalf("mesh stream session = %#v", session)
	}
	defer func() {
		if err := runner.Sessions.CloseSession(context.Background(), session.ID); err != nil {
			t.Logf("close mesh session: %v", err)
		}
	}()
	chunk, err := runner.Sessions.ReadSession(context.Background(), session.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chunk.Data), "mesh$ ") {
		t.Fatalf("mesh stream prompt = %q", string(chunk.Data))
	}
	if err := runner.Sessions.WriteSession(context.Background(), session.ID, []byte("GET / HTTP/1.0\n")); err != nil {
		t.Fatal(err)
	}
	chunk, err = runner.Sessions.ReadSession(context.Background(), session.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chunk.Data), "routed GET / HTTP/1.0") {
		t.Fatalf("mesh stream output = %q", string(chunk.Data))
	}
}

func TestIsMissingStepProviderRecognizesLegacyResponses(t *testing.T) {
	for _, message := range []string{
		"unknown method step.describe",
		`unknown method "step.describe"`,
		`module "mock-survey-go" is not a step provider`,
	} {
		if !isMissingStepProvider(errors.New(message)) {
			t.Fatalf("isMissingStepProvider(%q) = false, want true", message)
		}
	}
	if isMissingStepProvider(errors.New("step.describe exploded")) {
		t.Fatal("isMissingStepProvider accepted unrelated error")
	}
}

func TestIsMissingMeshProviderRecognizesLegacyResponses(t *testing.T) {
	for _, message := range []string{
		"unknown method mesh.describe",
		`unknown method "mesh.describe"`,
		`module "mock-survey-go" is not a mesh provider`,
	} {
		if !isMissingMeshProvider(errors.New(message)) {
			t.Fatalf("isMissingMeshProvider(%q) = false, want true", message)
		}
	}
	if isMissingMeshProvider(errors.New("mesh.describe exploded")) {
		t.Fatal("isMissingMeshProvider accepted unrelated error")
	}
}

func TestNormalizeModuleLogLevel(t *testing.T) {
	cases := map[string]event.Level{
		"debug":    event.LevelDebug,
		"info":     event.LevelInfo,
		"":         event.LevelInfo,
		"warn":     event.LevelWarn,
		"warning":  event.LevelWarn,
		"error":    event.LevelError,
		"critical": event.LevelError,
		"noisy":    event.LevelInfo,
	}
	for input, want := range cases {
		if got := normalizeModuleLogLevel(input); got != want {
			t.Fatalf("normalizeModuleLogLevel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRunnerRejectsMalformedStepContracts(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "bad-stepper",
            "version": "v0.0.0-test",
            "moduleType": "payload_provider"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"steps": [{
            "id": "squatter.connect_smb",
            "kind": "session.connector",
            "requires": [{"schemaVersion": "v1"}]
        }]}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)

	_, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.Inspect(context.Background(), "broken")
	if err == nil || !strings.Contains(err.Error(), "step contract invalid: squatter.connect_smb: requirement 1 type is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunnerRejectsMalformedStepContractShapes(t *testing.T) {
	cases := []struct {
		name         string
		stepPayload  string
		wantFragment string
	}{
		{
			name:         "step is not an object",
			stepPayload:  `"not-an-object"`,
			wantFragment: "step contract 1 must be an object",
		},
		{
			name:         "requirement is not an object",
			stepPayload:  `{"id": "broken.step", "kind": "session.connector", "requires": ["not-an-object"]}`,
			wantFragment: "step contract 1 requires item 1 must be an object",
		},
		{
			name:         "prepare is not an object",
			stepPayload:  `{"id": "broken.step", "kind": "session.connector", "prepare": "not-an-object"}`,
			wantFragment: "step contract 1 prepare must be an object",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writePythonModuleFixture(t, fmt.Sprintf(`
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "name": "bad-stepper",
            "version": "v0.0.0-test",
            "moduleType": "payload_provider"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"steps": [%s]}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`, tc.stepPayload))

			_, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.Inspect(context.Background(), "broken")
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("error = %v, want %q", err, tc.wantFragment)
			}
		})
	}
}

func TestRunnerCallsStepLifecycleMethods(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if method == "step.prepare":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "plannedOutputs": [{
                "id": "cap_credential_6mb8pq",
                "type": "CredentialCapability",
                "schemaVersion": "v1",
                "state": "planned",
                "producerStepId": params["stepId"],
                "attributes": {
                    "protocol": "smb",
                    "username": "m7q4z92d",
                    "password": "plain-high-entropy-password",
                    "sensitive": True
                }
            }],
            "preparedValues": {
                "password": {"value": "plain-high-entropy-password", "editable": True}
            }
        }})
    elif method == "step.execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded",
            "capabilities": [{
                "id": "cap_session_q8m2v4",
                "type": "SessionRef",
                "schemaVersion": "v1",
                "state": "connected",
                "producerStepId": params["stepId"]
            }]
        }})
    elif method == "step.cleanup":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "cleanup_verified"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	runner := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}

	prepared, err := runner.PrepareStep(context.Background(), StepCallRequest{
		ModuleID: "broken",
		Params: map[string]any{
			"preparedPlanId": "prep-1",
			"stepId":         "windows.credential.create_local_admin",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	values := prepared["preparedValues"].(map[string]any)
	password := values["password"].(map[string]any)
	if password["value"] != "plain-high-entropy-password" {
		t.Fatalf("prepared password = %#v", password)
	}

	executed, err := runner.ExecuteStep(context.Background(), StepCallRequest{
		ModuleID: "broken",
		Params:   map[string]any{"runId": "run-1", "stepId": "squatter.connect_smb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if executed["status"] != "succeeded" {
		t.Fatalf("execute result = %#v", executed)
	}

	cleanup, err := runner.CleanupStep(context.Background(), StepCallRequest{
		ModuleID: "broken",
		Params:   map[string]any{"runId": "run-1", "stepId": "squatter.cleanup_smb", "cleanupHandleId": "cap_cleanup_74m2wq"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup["status"] != "cleanup_verified" {
		t.Fatalf("cleanup result = %#v", cleanup)
	}
}

func TestRunnerListPayloadsDecodesArrayResult(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "list_payloads":
        send({"jsonrpc": "2.0", "id": rid, "result": [{
            "id": "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
            "name": "squatter",
            "version": "v0.1.0",
            "kind": "pe",
            "platform": "windows",
            "os": "windows",
            "arch": "x86",
            "formats": ["pe-exe", "pe"],
            "tags": ["pe", "windows"],
            "capabilities": ["file.get", "process.exec"],
            "transport": {"kind": "tcp-bind", "encrypted": False},
            "session": {"kind": "agent", "acquisition": "post_throw_connect", "owner": "payload_provider"}
        }]})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	payloads, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.ListPayloads(context.Background(), "broken", run.PayloadQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count = %d, want 1", len(payloads))
	}
	payload := payloads[0]
	if payload.ID != "squatter/windows/x86/windows-7/tcp-bind/pe-exe" ||
		payload.Kind != "pe" ||
		payload.Platform != "windows" ||
		payload.OS != "windows" ||
		payload.Arch != "x86" ||
		payload.Transport.Kind != "tcp-bind" ||
		len(payload.Formats) != 2 ||
		payload.Formats[0] != "pe-exe" ||
		payload.Formats[1] != "pe" ||
		len(payload.Tags) != 2 ||
		payload.Tags[0] != "pe" ||
		payload.Tags[1] != "windows" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestRunnerGeneratePayloadDecodesArtifactSet(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "generate_payload":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "primary": {
                "name": "squatter.exe",
                "role": "primary",
                "kind": "pe",
                "format": "pe-exe",
                "os": "windows",
                "arch": "x86",
                "tags": ["pe", "windows"],
                "encoding": "base64",
                "bytes": "TVo=",
                "size": 2,
                "sha256": "fake"
            },
            "artifacts": []
        }})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	payload, err := Runner{ConfigPath: configPath, Timeout: 2 * time.Second}.GeneratePayload(context.Background(), "broken", run.GeneratePayloadRequest{
		Target:    "192.0.2.10",
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Format:    "pe-exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload.Primary.Name != "squatter.exe" || payload.Primary.Encoding != "base64" || payload.Primary.Bytes != "TVo=" {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.Primary.Kind != "pe" || payload.Primary.OS != "windows" || payload.Primary.Arch != "x86" ||
		len(payload.Primary.Tags) != 2 || payload.Primary.Tags[0] != "pe" || payload.Primary.Tags[1] != "windows" {
		t.Fatalf("payload metadata = %#v", payload.Primary)
	}
}

func TestStepRuntimeRunnerExecutesCapabilityChain(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    step_id = params.get("stepId")
    if method == "step.prepare":
        if step_id == "ms17-010.exploit":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif step_id == "squatter.connect_smb":
            if params.get("inputs", [])[0]["capabilityId"] != "remote-1":
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "missing remote input"}})
            else:
                send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown step"}})
    elif method == "step.execute":
        if step_id == "ms17-010.exploit":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "status": "succeeded",
                "capabilities": [{
                    "id": "remote-1",
                    "type": "RemoteExecutionCapability",
                    "schemaVersion": "v1",
                    "state": "active",
                    "producerStepId": step_id
                }]
            }})
        elif step_id == "squatter.connect_smb":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "status": "succeeded",
                "capabilities": [{
                    "id": "session-1",
                    "type": "SessionRef",
                    "schemaVersion": "v1",
                    "state": "active",
                    "producerStepId": step_id,
                    "attributes": {"transport": "smb-named-pipe"}
                }],
                "evidence": [{
                    "id": "evidence-1",
                    "level": "info",
                    "kind": "session",
                    "sourceStepId": step_id,
                    "message": "session connected"
                }]
            }})
        else:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown step"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	catalog := modulecatalog.New(modulecatalog.Module{
		ID:      "broken@v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{
			{
				ID:   "ms17-010.exploit",
				Kind: "exploit.remote_execution",
			},
			{
				ID:   "squatter.connect_smb",
				Kind: "session.connector",
				Requires: []modulecatalog.CapabilityRequirement{{
					Type:   modulecatalog.CapabilityRemoteExecution,
					States: []string{"active"},
				}},
			},
		}},
	})
	runtime := chainruntime.New(catalog, StepRuntimeRunner{Runner: Runner{ConfigPath: configPath, Timeout: 2 * time.Second}})

	result, err := runtime.Execute(context.Background(), chainruntime.Request{
		RunID: "run-1",
		Steps: []chainruntime.StepRef{
			{ModuleID: "broken", StepID: "ms17-010.exploit"},
			{ModuleID: "broken", StepID: "squatter.connect_smb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", result.Status)
	}
	if len(result.Capabilities) != 2 || result.Capabilities[1].ID != "session-1" {
		t.Fatalf("capabilities = %#v", result.Capabilities)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Message != "session connected" {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
}

func TestStepRuntimeRunnerRejectsMalformedStepResult(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    if method == "step.prepare":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "plannedOutputs": ["not-an-object"]
        }})
    elif method == "step.execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded",
            "capabilities": [{"type": "SessionRef"}]
        }})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	runner := StepRuntimeRunner{Runner: Runner{ConfigPath: configPath, Timeout: 2 * time.Second}}

	_, err := runner.PrepareStep(context.Background(), chainruntime.StepPrepareRequest{
		ModuleID: "broken",
		RunID:    "run-1",
		StepID:   "broken.prepare",
	})
	if err == nil || !strings.Contains(err.Error(), "plannedOutputs item 1 must be an object") {
		t.Fatalf("prepare error = %v", err)
	}

	_, err = runner.ExecuteStep(context.Background(), chainruntime.StepExecuteRequest{
		ModuleID: "broken",
		RunID:    "run-1",
		StepID:   "broken.execute",
	})
	if err == nil || !strings.Contains(err.Error(), "capabilities item 1 id is required") {
		t.Fatalf("execute error = %v", err)
	}
}

func TestStepRuntimeRunnerKeepsStepProviderProcessForLiveChainStateAndAdoptsSessions(t *testing.T) {
	configPath := writePythonModuleFixture(t, `
import base64

listener_ready = False
session_open = False
reads = 0

while True:
    body = read()
    if not body:
        break
    request = json.loads(body)
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    step_id = params.get("stepId")
    if method == "step.prepare":
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "step.execute":
        if step_id == "squatter.listen_tcp_callback":
            listener_ready = True
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "status": "succeeded",
                "capabilities": [{
                    "id": "listener-1",
                    "type": "TransportEndpoint",
                    "schemaVersion": "v1",
                    "state": "active",
                    "producerStepId": step_id,
                    "attributes": {"kind": "tcp-listener"}
                }]
            }})
        elif step_id == "squatter.connect_tcp_callback":
            if not listener_ready:
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "listener state was lost"}})
            else:
                session_open = True
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "status": "succeeded",
                    "sessions": [{
                        "id": "session-1",
                        "runId": params.get("runId"),
                        "moduleId": "broken@v1",
                        "target": "target-1",
                        "name": "Squatter session",
                        "kind": "agent",
                        "state": "open",
                        "transport": "squatter/tcp-callback"
                    }],
                    "capabilities": [{
                        "id": "session-1",
                        "type": "SessionRef",
                        "schemaVersion": "v1",
                        "state": "active",
                        "producerStepId": step_id
                    }]
                }})
    elif method == "session/read":
        if session_open and reads == 0:
            reads += 1
            send({"jsonrpc": "2.0", "id": rid, "result": {"data": base64.b64encode(b"sq> ").decode()}})
        else:
            send({"jsonrpc": "2.0", "id": rid, "result": {"data": ""}})
    elif method == "session.command.list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"commands": [{"name": "process.list", "summary": "list processes", "readOnly": True}]}})
    elif method == "session.command.run":
        request = params.get("request", {})
        send({"jsonrpc": "2.0", "id": rid, "result": {"command": request.get("command", ""), "summary": "session command completed", "stdout": "[]"}})
    elif method == "session/close":
        session_open = False
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`)
	catalog := modulecatalog.New(modulecatalog.Module{
		ID:      "broken@v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{
			{ID: "squatter.listen_tcp_callback", Kind: "listener.start"},
			{ID: "squatter.connect_tcp_callback", Kind: "session.connector"},
		}},
	})
	sessions := NewSessionBroker()
	stepProcesses := NewStepProcessBroker()
	runtime := chainruntime.New(catalog, StepRuntimeRunner{Runner: Runner{
		ConfigPath:    configPath,
		Timeout:       2 * time.Second,
		Sessions:      sessions,
		StepProcesses: stepProcesses,
	}})

	result, err := runtime.Execute(context.Background(), chainruntime.Request{
		RunID: "run-1",
		Steps: []chainruntime.StepRef{
			{ModuleID: "broken", StepID: "squatter.listen_tcp_callback"},
			{ModuleID: "broken", StepID: "squatter.connect_tcp_callback"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", result.Status)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].ID != "session-1" {
		t.Fatalf("sessions = %#v, want adopted session", result.Sessions)
	}
	chunk, err := sessions.ReadSession(context.Background(), "session-1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Data) != "sq> " {
		t.Fatalf("session data = %q, want prompt", string(chunk.Data))
	}
	commands, err := sessions.ListSessionCommands(context.Background(), "session-1", run.PayloadCommandListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].Name != "process.list" {
		t.Fatalf("session commands = %#v, want process.list", commands)
	}
	commandResult, err := sessions.RunSessionCommand(context.Background(), "session-1", run.PayloadCommandRequest{Command: "process.list"})
	if err != nil {
		t.Fatal(err)
	}
	if commandResult.Command != "process.list" || commandResult.Stdout != "[]" {
		t.Fatalf("session command result = %#v", commandResult)
	}
	if err := sessions.CloseSession(context.Background(), "session-1"); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerLaunchesEveryBuiltInMockModule(t *testing.T) {
	for _, moduleID := range []string{"mock-survey", "mock-exploit", "mock-exploit-session"} {
		t.Run(moduleID, func(t *testing.T) {
			request, err := run.NewRequest(run.RequestArgs{
				ID:       "run-1",
				ModuleID: moduleID,
				Target:   "mock://target",
				ChainConfig: map[string]string{
					"delay":        "0s",
					"failure_mode": "execution",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Summary == "" {
				t.Fatal("summary is empty")
			}
		})
	}
}

func TestRunnerKeepsPythonSessionModuleAliveBehindBroker(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit-session",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := NewSessionBroker()
	result, err := Runner{
		ConfigPath: exampleModuleConfig,
		Timeout:    10 * time.Second,
		Sessions:   broker,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("sessions = %#v, want one session", result.Sessions)
	}
	sessionID := result.Sessions[0].ID
	sessions, err := broker.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != sessionID {
		t.Fatalf("broker sessions = %#v, want %s", sessions, sessionID)
	}
	prompt, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(prompt.Data) != "mock$ " {
		t.Fatalf("prompt = %q, want mock prompt", string(prompt.Data))
	}
	if err := broker.WriteSession(context.Background(), sessionID, []byte("whoami\n")); err != nil {
		t.Fatal(err)
	}
	echo, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(echo.Data) != "whoami\n" {
		t.Fatalf("echo = %q, want whoami", string(echo.Data))
	}
	output, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(output.Data) != "mock-operator\n" {
		t.Fatalf("output = %q, want mock operator", string(output.Data))
	}
	if err := broker.CloseSession(context.Background(), sessionID); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerExecutesCanonicalModuleReference(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit@v0.0.0-example",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
}

func TestRunnerMapsFailedPythonResult(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:          "run-1",
		ModuleID:    "mock-exploit",
		Target:      "mock://target",
		ChainConfig: map[string]string{"failure_mode": "execution"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateFailed {
		t.Fatalf("state = %q, want failed", result.State)
	}
}

func TestRunnerCapturesModuleLogs(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-survey",
		Target:   "mock://target",
		TargetConfig: map[string]string{
			"target.host": "target",
			"target.port": "443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	_, err = Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1", "event-2", "event-3"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(events.events) == 0 {
		t.Fatal("event count = 0, want module log events")
	}
}

func TestRunnerHasNoModulesWithEmptyConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := Runner{ConfigPath: configPath}.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if modules := catalog.List(); len(modules) != 0 {
		t.Fatalf("modules = %#v, want none", modules)
	}
}

func TestRunnerReportsPythonProtocolFailures(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		inspect bool
		timeout time.Duration
		want    string
	}{
		{
			name:    "handshake error includes stderr",
			body:    `import sys; print("handshake stderr", file=sys.stderr); send({"jsonrpc":"2.0","id":1,"error":{"message":"no handshake"}})`,
			inspect: true,
			want:    "module handshake failed: no handshake: handshake stderr",
		},
		{
			name:    "malformed frame",
			body:    `import sys; sys.stdout.buffer.write(b"Content-Length: 1\r\n\r\n{"); sys.stdout.buffer.flush()`,
			inspect: true,
			want:    "module handshake failed",
		},
		{
			name: "execute error",
			body: `read(); send({"jsonrpc":"2.0","id":1,"result":{"name":"broken","version":"v0.0.0-test","moduleType":"exploit"}}); read(); send({"jsonrpc":"2.0","id":2,"result":{"chainConfig":[],"targetConfig":[]}}); read(); send({"jsonrpc":"2.0","id":3,"error":{"message":"execute denied"}})`,
			want: "module execute failed: execute denied",
		},
		{
			name: "invalid schema blocks execution",
			body: `read(); send({"jsonrpc":"2.0","id":1,"result":{"name":"broken","version":"v0.0.0-test","moduleType":"exploit"}}); read(); send({"jsonrpc":"2.0","id":2,"result":{"chainConfig":[{"type":"bool"}],"targetConfig":[]}})`,
			want: "module metadata invalid: chainConfig item 1 key is required",
		},
		{
			name:    "timeout",
			body:    `import time; time.sleep(2)`,
			inspect: true,
			timeout: 50 * time.Millisecond,
			want:    "context deadline exceeded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writePythonModuleFixture(t, tc.body)
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			runner := Runner{ConfigPath: configPath, Timeout: timeout}
			var err error
			if tc.inspect {
				_, err = runner.Inspect(context.Background(), "broken")
			} else {
				request, requestErr := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "broken", Target: "mock://target"})
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				_, err = runner.Run(context.Background(), request)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestFrameDecoderRejectsOversizedFrameBeforeBodyRead(t *testing.T) {
	decoder := newFrameDecoder(strings.NewReader(fmt.Sprintf("Content-Length: %d\r\n\r\n", maxFrameBytes+1)))
	_, err := decoder.read()
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("error = %v, want frame size error", err)
	}
}

func TestCapturedStderrWaitsForLateWrite(t *testing.T) {
	stderr := newCapturedStderr()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(10 * time.Millisecond)
		if _, err := stderr.Write([]byte("late stderr")); err != nil {
			t.Errorf("write captured stderr: %v", err)
		}
	}()

	if got := stderr.StringAfter(time.Second); got != "late stderr" {
		t.Fatalf("stderr = %q, want late stderr", got)
	}
	<-done
}

func TestRPCClientTimeoutDoesNotCorruptNextCall(t *testing.T) {
	moduleStdoutReader, moduleStdoutWriter := io.Pipe()
	moduleStdinReader, moduleStdinWriter := io.Pipe()
	defer closeTestPipeReader(t, "module stdout reader", moduleStdoutReader)
	defer closeTestPipeWriter(t, "module stdout writer", moduleStdoutWriter)
	defer closeTestPipeReader(t, "module stdin reader", moduleStdinReader)
	defer closeTestPipeWriter(t, "module stdin writer", moduleStdinWriter)

	client := newClient(moduleStdoutReader, moduleStdinWriter)
	done := make(chan error, 1)
	go func() {
		decoder := newFrameDecoder(moduleStdinReader)
		first, err := decoder.read()
		if err != nil {
			done <- err
			return
		}
		time.Sleep(50 * time.Millisecond)
		if err := writeFrame(moduleStdoutWriter, map[string]any{
			"jsonrpc": "2.0",
			"id":      first.ID,
			"result":  map[string]any{"call": "late-first"},
		}); err != nil {
			done <- err
			return
		}
		second, err := decoder.read()
		if err != nil {
			done <- err
			return
		}
		if err := writeFrame(moduleStdoutWriter, map[string]any{
			"jsonrpc": "2.0",
			"id":      second.ID,
			"result":  map[string]any{"call": "second"},
		}); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err := client.call(ctx, "first", nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("first call error = %v, want deadline", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	result, err := client.call(ctx, "second", nil)
	cancel()
	if err != nil {
		t.Fatalf("second call failed after first timeout: %v", err)
	}
	if result["call"] != "second" {
		t.Fatalf("second result = %#v, want second response", result)
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

const exampleModuleConfig = "modules/examples/python/hovel-modules.json"

func TestRunnerConfigPathDiscoversRepoDefault(t *testing.T) {
	t.Setenv(ModuleConfigEnv, "")
	t.Setenv("HOVEL_REPO_ROOT", "")
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "modules", "examples", "hovel-modules.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Join(root, "modules", "examples"))

	if got := (Runner{}).configPath(); got != configPath {
		t.Fatalf("configPath() = %q, want %q", got, configPath)
	}
}

func TestRunnerConfigPathPrefersFullExampleCatalogOverPythonFixture(t *testing.T) {
	t.Setenv(ModuleConfigEnv, "")
	root := t.TempDir()
	pythonConfig := filepath.Join(root, "modules", "examples", "python", "hovel-modules.json")
	fullConfig := filepath.Join(root, "modules", "examples", "hovel-modules.json")
	if err := os.MkdirAll(filepath.Dir(pythonConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pythonConfig, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullConfig, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := (Runner{ConfigPath: pythonConfig}).configPath(); got != fullConfig {
		t.Fatalf("configPath() = %q, want %q", got, fullConfig)
	}
}

func TestRunnerConfigPathKeepsPythonFixtureWhenFullCatalogBinaryIsMissing(t *testing.T) {
	t.Setenv(ModuleConfigEnv, "")
	root := t.TempDir()
	pythonConfig := filepath.Join(root, "modules", "examples", "python", "hovel-modules.json")
	fullConfig := filepath.Join(root, "modules", "examples", "hovel-modules.json")
	if err := os.MkdirAll(filepath.Dir(pythonConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pythonConfig, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullConfig, []byte(`{"modules":[{"id":"squatter","command":["bin/squatter-provider"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := (Runner{ConfigPath: pythonConfig}).configPath(); got != pythonConfig {
		t.Fatalf("configPath() = %q, want %q", got, pythonConfig)
	}
}

func TestRunnerConfigPathUsesBuildWorkspaceCatalogBeforeRunfilesFixture(t *testing.T) {
	t.Setenv(ModuleConfigEnv, "")
	t.Setenv("HOVEL_REPO_ROOT", "")
	sourceRoot := t.TempDir()
	sourceConfig := filepath.Join(sourceRoot, "modules", "examples", "hovel-modules.json")
	sourceProvider := filepath.Join(sourceRoot, "modules", "examples", "bin", "squatter-provider")
	if err := os.MkdirAll(filepath.Dir(sourceProvider), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceProvider, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceConfig, []byte(`{"modules":[{"id":"squatter","command":["bin/squatter-provider"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	runfilesRoot := t.TempDir()
	runfilesPythonConfig := filepath.Join(runfilesRoot, "modules", "examples", "python", "hovel-modules.json")
	if err := os.MkdirAll(filepath.Dir(runfilesPythonConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runfilesPythonConfig, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", sourceRoot)
	t.Chdir(runfilesRoot)

	if got := (Runner{}).configPath(); got != sourceConfig {
		t.Fatalf("configPath() = %q, want %q", got, sourceConfig)
	}
}

func writePythonModuleFixture(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	packageDir := filepath.Join(projectDir, "broken_module")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	main := `import json
import sys

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    return sys.stdin.buffer.read(length)

def send(message):
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

` + body + "\n"
	if err := os.WriteFile(filepath.Join(packageDir, "__main__.py"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	config := ModuleConfig{Modules: []ModuleEntry{{
		ID:         "broken",
		Runtime:    "jsonrpc-stdio",
		ProjectDir: projectDir,
		Module:     "broken_module",
	}}}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func writeCommandModuleScript(t *testing.T, handshake string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "module.py")
	body := `import json
import sys

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    return json.loads(sys.stdin.buffer.read(length) or b"{}")

def send(message):
    out = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(out))
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()

while True:
    msg = read()
    method = msg.get("method")
    rid = msg.get("id")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": ` + handshake + `})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"steps": []}})
    elif method == "mesh.describe":
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "module is not a mesh provider"}})
    elif method == "execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "status": "succeeded", "summary": "command module executed",
            "findings": [], "artifacts": [], "outputs": {}, "sessions": []}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
`
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return script
}

type eventRecorder struct {
	events []event.Event
}

func (r *eventRecorder) Append(_ context.Context, evt event.Event) error {
	r.events = append(r.events, evt)
	return nil
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	if s.next >= len(s.values) {
		s.next++
		return fmt.Sprintf("event-%d", s.next)
	}
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func closeTestPipeReader(t *testing.T, name string, pipe *io.PipeReader) {
	t.Helper()
	if err := pipe.Close(); err != nil {
		t.Logf("close %s: %v", name, err)
	}
}

func closeTestPipeWriter(t *testing.T, name string, pipe *io.PipeWriter) {
	t.Helper()
	if err := pipe.Close(); err != nil {
		t.Logf("close %s: %v", name, err)
	}
}
