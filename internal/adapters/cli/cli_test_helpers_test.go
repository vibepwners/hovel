package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
	prompt "github.com/c-bata/go-prompt"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfigPath())
	os.Exit(m.Run())
}

func newTestApp() App {
	session := operatorsession.New()
	modules := testModuleCatalog()
	return newAppWithSessionAndModules(session, modules)
}

func enterTestOperation(t *testing.T, app App) {
	t.Helper()
	if app.session == nil {
		t.Fatal("test app has no session")
	}
	if err := app.session.UseOperation("test-op"); err != nil {
		t.Fatal(err)
	}
}

func testModuleCatalog() modulecatalog.Catalog {
	return modulecatalog.New(
		modulecatalog.Module{
			ID:          "mock-survey@v0.0.0-example",
			Name:        "Mock Survey",
			Type:        modulecatalog.TypeSurvey,
			Version:     "v0.0.0-example",
			Summary:     "Collect example target facts.",
			RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
			Enabled:     true,
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
		modulecatalog.Module{
			ID:          "mock-exploit@v0.0.0-example",
			Name:        "Mock Exploit",
			Type:        modulecatalog.TypeExploit,
			Version:     "v0.0.0-example",
			Summary:     "Run an example exploit flow.",
			RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
			Enabled:     true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "operator.confirmed_lab", Type: modulecatalog.ValueBool, Required: true, Description: "Operator confirmed this is an authorized lab."},
			},
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
		modulecatalog.Module{
			ID:          "mock-exploit-session@v0.0.0-example",
			Name:        "Mock Exploit Session",
			Type:        modulecatalog.TypeExploit,
			Version:     "v0.0.0-example",
			Summary:     "Open a mock interactive shell session.",
			RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
			Enabled:     true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "operator.confirmed_lab", Type: modulecatalog.ValueBool, Required: true, Description: "Operator confirmed this is an authorized lab."},
			},
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
	)
}

func writeRPCModulePackage(t *testing.T, name, moduleType, schemaJSON, stepsJSON string) string {
	t.Helper()
	moduleRoot := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: `+name+`
  version: 0.1.0
  moduleType: `+moduleType+`
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/`+name+`"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env python3
import json
import sys

INFO = {
    "name": ` + strconv.Quote(name) + `,
    "version": "0.1.0",
    "moduleType": ` + strconv.Quote(moduleType) + `,
    "summary": "installed test module",
    "tags": [],
}
SCHEMA = json.loads(` + strconv.Quote(schemaJSON) + `)
STEPS = json.loads(` + strconv.Quote(stepsJSON) + `)

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        key, value = line.decode().split(":", 1)
        headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length == 0:
        return None
    return json.loads(sys.stdin.buffer.read(length))

def send(message):
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

while True:
    request = read()
    if not request:
        break
    method = request.get("method")
    rid = request.get("id")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": rid, "result": INFO})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": rid, "result": SCHEMA})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": rid, "result": STEPS})
    elif method == "step.prepare":
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "step.execute":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "succeeded"}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": rid, "result": {"status": "ok"}})
        break
    else:
        send({"jsonrpc": "2.0", "id": rid, "error": {"message": "unknown method " + str(method)}})
`
	if err := os.WriteFile(filepath.Join(moduleRoot, "bin", name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return moduleRoot
}

func containsSuggestion(suggestions []prompt.Suggest, want string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Text == want {
			return true
		}
	}
	return false
}
