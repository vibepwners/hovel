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
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

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

func TestArtifactsFromRPCSupportsFileReferences(t *testing.T) {
	artifacts := artifactsFromRPC([]any{
		map[string]any{"name": "loot.txt", "kind": "text/plain", "path": "/tmp/loot.txt"},
	})
	if len(artifacts) != 1 {
		t.Fatalf("artifacts = %#v, want one", artifacts)
	}
	if artifacts[0].Path != "/tmp/loot.txt" || artifacts[0].Data != "" {
		t.Fatalf("artifact = %#v, want file reference without data", artifacts[0])
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
            "moduleType": "payload_provider"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": {"chainConfig": [], "targetConfig": [], "outputs": {}}})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": {"version": "contracts-v1", "steps": [{
            "id": "squatter.connect_smb",
            "kind": "session.connector",
            "requires": [
                {"type": "PayloadInstance", "schemaVersion": "v1", "attributes": {"provider": "squatter", "transport": "smb-named-pipe"}, "states": ["installed", "installed_unconnected"]},
                {"type": "CredentialCapability", "schemaVersion": "v1", "attributes": {"protocol": "smb"}, "states": ["active"]}
            ],
            "produces": [
                {"type": "SessionRef", "schemaVersion": "v1", "attributes": {"provider": "squatter", "transport": "smb-named-pipe"}}
            ],
            "prepare": {"materializes": []}
        }]}})
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
        if step_id == "etro.exploit":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif step_id == "squatter.connect_smb":
            if params.get("inputs", [])[0]["capabilityId"] != "remote-1":
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "missing remote input"}})
            else:
                send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown step"}})
    elif method == "step.execute":
        if step_id == "etro.exploit":
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
				ID:   "etro.exploit",
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
			{ModuleID: "broken", StepID: "etro.exploit"},
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

func TestRunnerHasNoModulesWithoutConfig(t *testing.T) {
	catalog, err := Runner{}.Catalog(context.Background())
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
			body: `read(); send({"jsonrpc":"2.0","id":1,"result":{"moduleType":"exploit"}}); read(); send({"jsonrpc":"2.0","id":2,"result":{}}); read(); send({"jsonrpc":"2.0","id":3,"error":{"message":"execute denied"}})`,
			want: "module execute failed: execute denied",
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

func TestRPCClientTimeoutDoesNotCorruptNextCall(t *testing.T) {
	moduleStdoutReader, moduleStdoutWriter := io.Pipe()
	moduleStdinReader, moduleStdinWriter := io.Pipe()
	defer moduleStdoutReader.Close()
	defer moduleStdoutWriter.Close()
	defer moduleStdinReader.Close()
	defer moduleStdinWriter.Close()

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

const exampleModuleConfig = "examples/python/hovel-modules.json"

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
