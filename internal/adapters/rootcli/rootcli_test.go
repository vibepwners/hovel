package rootcli

import (
	"bytes"
	"context"
	"encoding/json"
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

	code := Run(context.Background(), []string{"module", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "mock-exploit") {
		t.Fatalf("stdout = %q", stdout.String())
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
	for _, want := range []string{"hovel", "op", "chain", "module", "target", "throw", "shell", "command", "cli", "daemon", "tui"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestDaemonServeHelpShowsOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"daemon", "serve", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"daemon serve", "--workspace", "--socket"} {
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
