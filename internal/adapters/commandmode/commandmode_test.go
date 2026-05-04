package commandmode

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

func TestHelpShowsCommandMenu(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel command", "control", "chain", "target", "throw"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestThrowHelpShowsChainTargetAndWorkspace(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"throw", "--chain", "--target", "--workspace", "--json"} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "_positionalArg") {
		t.Fatalf("help output leaked generated positional name:\n%s", output)
	}
}

func TestEveryRegisteredCommandHasUsableHelp(t *testing.T) {
	registry := NewApp().Registry()
	for _, definition := range registry.Definitions() {
		t.Run(definition.PathString(), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, definition.Path...), "--help")
			code := Run(context.Background(), args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			output := stdout.String()
			if !strings.Contains(output, definition.PathString()) {
				t.Fatalf("help output missing command path %q:\n%s", definition.PathString(), output)
			}
			if strings.Contains(output, "_positionalArg") {
				t.Fatalf("help output leaked generated positional name:\n%s", output)
			}
			for _, option := range definition.Options {
				if !strings.Contains(output, "--"+option.Name) {
					t.Fatalf("help output missing option --%s:\n%s", option.Name, output)
				}
			}
		})
	}
}

func TestThrowRequiresTargetBeforeDaemonLookup(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit", "--workspace", t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "target is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestInitJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"control", "init", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Created   bool `json:"created"`
		Workspace struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
	if payload.Workspace.ID == "" {
		t.Fatal("workspace ID is empty")
	}
	if payload.Workspace.Path != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.Workspace.Path, workspacePath)
	}
}

func TestDaemonStatusJSONRunning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()
	socketPath := workspacePath + "/hoveld.sock"
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           12345,
		SocketPath:    socketPath,
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.NewWorkspaceStore().WriteDaemonStatus(context.Background(), identity); err != nil {
		t.Fatal(err)
	}

	code := Run(context.Background(), []string{"control", "daemon", "status", "--workspace", workspacePath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		State         string `json:"state"`
		WorkspacePath string `json:"workspacePath"`
		PID           int    `json:"pid"`
		SocketPath    string `json:"socketPath"`
		Health        string `json:"health"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.State != "running" {
		t.Fatalf("state = %q, want running", payload.State)
	}
	if payload.WorkspacePath != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.WorkspacePath, workspacePath)
	}
	if payload.PID != 12345 {
		t.Fatalf("pid = %d, want 12345", payload.PID)
	}
	if payload.SocketPath != socketPath {
		t.Fatalf("socket path = %q, want %q", payload.SocketPath, socketPath)
	}
	if payload.Health != "healthy" {
		t.Fatalf("health = %q, want healthy", payload.Health)
	}
}

func TestInitHumanOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"control", "init", "--workspace", workspacePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, workspacePath) {
		t.Fatalf("stdout missing workspace path %q:\n%s", workspacePath, output)
	}
	if strings.HasPrefix(strings.TrimSpace(output), "{") {
		t.Fatalf("stdout looks like JSON (unexpected): %s", output)
	}
	for _, want := range []string{"Initialized", workspacePath} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout missing %q:\n%s", want, output)
		}
	}
}

func TestInitInvalidWorkspacePath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"control", "init", "--workspace", "."}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr is empty, want error message")
	}
}

func TestInitInvalidWorkspaceName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := Run(context.Background(), []string{"control", "init", "--workspace", workspacePath, "--name", "invalid name"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr is empty, want non-empty error message")
	}
}

func TestHumanOutputRendersOperatorLogWhenPresent(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"log-demo"},
		Summary: "Render log demo",
		Handler: func(context.Context, commands.Invocation) (commands.Result, error) {
			return commands.Result{
				Log: operatorlog.New("HOVEL//RUN", "demo -> target", []operatorlog.Entry{
					operatorlog.Info("run", "module staged"),
					operatorlog.Success("run", "completed"),
				}),
			}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"log-demo"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"HOVEL//RUN", ":: run", "++ run"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestExecuteLinePreservesQuotedArguments(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"echo"},
		Summary: "Echo one value",
		Positionals: []commands.Positional{
			{Name: "value", Required: true},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: invocation.Positional("value")}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).ExecuteLine(context.Background(), `echo "hello operator"`, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "hello operator" {
		t.Fatalf("stdout = %q, want quoted value preserved", got)
	}
}

func TestExecuteLinePreservesLiteralBackslashes(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"echo"},
		Summary: "Echo one value",
		Positionals: []commands.Positional{
			{Name: "value", Required: true},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: invocation.Positional("value")}, nil
		},
	})

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "unquoted windows path",
			line: `echo C:\tmp\plan.yaml`,
			want: `C:\tmp\plan.yaml`,
		},
		{
			name: "quoted windows path with spaces",
			line: `echo "C:\Program Files\hovel\plan.yaml"`,
			want: `C:\Program Files\hovel\plan.yaml`,
		},
		{
			name: "escaped quote inside quoted value",
			line: `echo "operator \"quoted\" value"`,
			want: `operator "quoted" value`,
		},
		{
			name: "escaped backslash inside quoted value",
			line: `echo "C:\\tmp\\plan.yaml"`,
			want: `C:\tmp\plan.yaml`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := NewAppWithRegistry(registry).ExecuteLine(context.Background(), tc.line, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			if got := strings.TrimSpace(stdout.String()); got != tc.want {
				t.Fatalf("stdout = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExecuteLineRejectsUnterminatedQuotedArgument(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"echo"},
		Summary: "Echo one value",
		Handler: func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			return commands.Result{}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).ExecuteLine(context.Background(), `echo "unterminated`, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unterminated quoted string") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestTerminalInputRequiresLiteralYes(t *testing.T) {
	prompt := testConfirmationPrompt()
	var stdout strings.Builder
	input := terminalInput{in: strings.NewReader("yes\n"), out: &stdout}

	answer, err := input.Confirm(context.Background(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Confirmed(prompt) {
		t.Fatal("confirmation = false, want true")
	}
	for _, want := range []string{"THROW REVIEW", "plan-mock", "mock-exploit", "hash-mock", "Type yes to throw:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("prompt missing %q:\n%s", want, stdout.String())
		}
	}

	answer, err = (terminalInput{in: strings.NewReader("y\n")}).Confirm(context.Background(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Confirmed(prompt) {
		t.Fatal("confirmation = true, want false")
	}
}

func TestTerminalInputUsesPromptAction(t *testing.T) {
	prompt := testConfirmationPrompt()
	prompt.Action = "confirm review"
	var stdout strings.Builder
	input := terminalInput{in: strings.NewReader("yes\n"), out: &stdout}

	answer, err := input.Confirm(context.Background(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Confirmed(prompt) {
		t.Fatal("confirmation = false, want true")
	}
	if !strings.Contains(stdout.String(), "Type yes to confirm review:") {
		t.Fatalf("prompt = %q, want review action", stdout.String())
	}
}

func TestTerminalInputEchoesAnswerWhenRequested(t *testing.T) {
	prompt := testConfirmationPrompt()
	var stdout strings.Builder
	input := terminalInput{in: strings.NewReader("yes\n"), out: &stdout, echoAnswer: true}

	answer, err := input.Confirm(context.Background(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Confirmed(prompt) {
		t.Fatal("confirmation = false, want true")
	}
	if !strings.Contains(stdout.String(), "Type yes to throw: yes\n") {
		t.Fatalf("prompt = %q, want echoed answer", stdout.String())
	}
}

func testConfirmationPrompt() commands.ConfirmationPrompt {
	plan := commands.ThrowPlanRecord{
		ID:       "plan-mock",
		PlanHash: "hash-mock",
		Chain:    "mock-exploit",
		Targets:  []string{"mock://target"},
	}
	return commands.ConfirmationPrompt{
		Title:           "THROW REVIEW",
		Action:          "throw",
		RequiredLiteral: "yes",
		Plan:            plan,
		Fields: []commands.ConfirmationField{
			{Label: "chain", Value: plan.Chain},
			{Label: "targets", Value: strings.Join(plan.Targets, ", ")},
			{Label: "plan hash", Value: plan.PlanHash, Muted: true},
		},
	}
}
