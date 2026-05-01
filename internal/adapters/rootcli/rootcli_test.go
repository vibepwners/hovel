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
