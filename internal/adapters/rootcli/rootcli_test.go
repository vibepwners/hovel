package rootcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandRoleDelegatesToCommandAdapter(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"command", "control", "init", "--workspace", t.TempDir(), "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Created bool `json:"created"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
}

func TestDirectCommandDelegatesToCommandAdapter(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"module", "available"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "mock-exploit") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestLeadingConfigOptionDelegatesToDirectCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	configPath := writeRootCLIModuleConfig(t)

	code := Run(context.Background(), []string{"--config", configPath, "module", "available"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "root-config-survey@0.1.0") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestLeadingConfigOptionMovesBeforeRunCommand(t *testing.T) {
	args := normalizeLeadingConfig([]string{"--config", "lab.yaml", "run", "module", "list"})
	want := []string{"run", "--config", "lab.yaml", "module", "list"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}

	args = normalizeLeadingConfig([]string{"--config=lab.yaml", "run", "module", "list"})
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestInitAliasDelegatesToControlInit(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"init", "--workspace", t.TempDir(), "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	var payload struct {
		Created bool `json:"created"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
}

func writeRootCLIModuleConfig(t *testing.T) string {
	t.Helper()
	searchRoot := t.TempDir()
	moduleRoot := filepath.Join(searchRoot, "root-config-survey")
	if err := os.MkdirAll(moduleRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
launch:
  - command: ["bin/root-config-survey"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(moduleRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	moduleScript := `#!/usr/bin/env python3
import json
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
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


while True:
    message = read()
    method = message.get("method")
    request_id = message.get("id")
    if method == "handshake":
        send({"jsonrpc": "2.0", "id": request_id, "result": {
            "name": "root-config-survey",
            "version": "0.1.0",
            "moduleType": "survey",
            "summary": "Root config module"
        }})
    elif method == "schema":
        send({"jsonrpc": "2.0", "id": request_id, "result": {
            "chainConfig": [],
            "targetConfig": [],
            "outputs": {}
        }})
    elif method == "step.describe":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"steps": []}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"status": "ok"}})
        break
`
	if err := os.WriteFile(filepath.Join(binDir, "root-config-survey"), []byte(moduleScript), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
modules:
  searchPaths:
    - `+searchRoot+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestCLIRoleRejectsOneShotCommandArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"cli", "throw", "--chain", "mock-exploit"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "hovel <command>") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRootHelpShowsRoleMenu(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel", "op", "chain", "module", "artifact", "target", "throw", "shell", "command", "run", "cli", "mcp", "daemon", "tui"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestMCPHelpShowsOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"mcp", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel mcp", "--workspace", "--op", "--operation", "--chain", "--entity-id", "--display-name", "--module-config", "--transport", "--http-addr"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestMCPRejectsUnsupportedTransportBeforeDaemonStartup(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"mcp", "--transport", "banana"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unsupported MCP transport") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCommandParserRequiresCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"run", "--op", "o1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "command is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCommandInjectsWorkspaceForDaemonCommands(t *testing.T) {
	args := injectWorkspaceForDaemonCommand([]string{"throw", "--now"}, "/tmp/hovel")
	want := []string{"throw", "--now", "--workspace", "/tmp/hovel"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	args = injectWorkspaceForDaemonCommand([]string{"module", "list"}, "/tmp/hovel")
	want = []string{"module", "list", "--workspace", "/tmp/hovel"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestRunCommandInjectsOptionsBeforePassthroughDelimiter(t *testing.T) {
	args := []string{"module", "manual-install", "devmod", "--", "stdio-cmd", "--workspace", "module-owned", "--config", "module.yaml"}
	args = injectWorkspaceForDaemonCommand(args, "/tmp/hovel")
	args = injectConfigForDaemonCommand(args, "/tmp/hovel.yaml")
	want := []string{
		"module", "manual-install", "devmod",
		"--workspace", "/tmp/hovel",
		"--config", "/tmp/hovel.yaml",
		"--",
		"stdio-cmd", "--workspace", "module-owned", "--config", "module.yaml",
	}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestRunCommandNormalizesActiveChainAliases(t *testing.T) {
	args := normalizeRunCommand([]string{"add", "squatter@v0.1.0"})
	want := []string{"chain", "add", "squatter@v0.1.0"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	args = normalizeRunCommand([]string{"target", "add", "t1"})
	want = []string{"target", "add", "t1"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestRunCommandPreservesManualInstallDelimiter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	parsed, ok, code := parseRunCommandArgs([]string{"--workspace", ".hovel", "--", "module", "manualinstall", "devmod", "--type", "survey", "--", "stdio-cmd", "--anotherarg"}, &stdout, &stderr)
	if !ok || code != 0 {
		t.Fatalf("parse failed: ok=%v code=%d stderr=%s", ok, code, stderr.String())
	}
	want := []string{"module", "manualinstall", "devmod", "--type", "survey", "--", "stdio-cmd", "--anotherarg"}
	if strings.Join(parsed.Command, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command = %#v, want %#v", parsed.Command, want)
	}
}

func TestDaemonServeHelpShowsOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"daemon", "serve", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"daemon serve", "--workspace", "--socket", "--listen"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestTUIRoleIsExplicitlyUnimplemented(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"tui"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestThrowFileArgDetectsOneShotChainFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "plain file", args: []string{"alpha.chain.yaml"}, want: "alpha.chain.yaml"},
		{name: "file after workspace", args: []string{"--workspace", ".hovel", "alpha.chain.yaml", "--now"}, want: "alpha.chain.yaml"},
		{name: "file before target override", args: []string{"alpha.chain.yaml", "--target", "mock://target"}, want: "alpha.chain.yaml"},
		{name: "subcommand list", args: []string{"list"}, want: ""},
		{name: "subcommand inspect", args: []string{"inspect", "plan-alpha"}, want: ""},
		{name: "legacy chain throw", args: []string{"--chain", "mock-exploit", "--target", "mock://target"}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := throwFileArg(tc.args); got != tc.want {
				t.Fatalf("throwFileArg(%#v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestThrowWorkspaceArgUsesDefaultAndOverride(t *testing.T) {
	if got := throwWorkspaceArg([]string{"alpha.chain.yaml"}); got != ".hovel" {
		t.Fatalf("workspace = %q, want .hovel", got)
	}
	if got := throwWorkspaceArg([]string{"--workspace", "/tmp/hovel", "alpha.chain.yaml"}); got != "/tmp/hovel" {
		t.Fatalf("workspace = %q, want override", got)
	}
	if got := throwWorkspaceArg([]string{"--workspace=/tmp/hovel", "alpha.chain.yaml"}); got != "/tmp/hovel" {
		t.Fatalf("workspace = %q, want override", got)
	}
}
