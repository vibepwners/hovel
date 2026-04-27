package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

func TestSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := NewApp()

	root := app.Suggestions("ch")
	if len(root) != 1 || root[0].Text != "chain" {
		t.Fatalf("root suggestions = %#v, want chain", root)
	}

	controlChildren := app.Suggestions("control ")
	if len(controlChildren) != 2 || controlChildren[0].Text != "daemon" || controlChildren[1].Text != "init" {
		t.Fatalf("control suggestions = %#v, want daemon and init", controlChildren)
	}

	chainChildren := app.Suggestions("chain ")
	var chainNames []string
	for _, suggestion := range chainChildren {
		chainNames = append(chainNames, suggestion.Text)
	}
	for _, want := range []string{"create", "delete", "inspect", "list", "logs", "rename", "use"} {
		if !contains(chainNames, want) {
			t.Fatalf("chain suggestions = %#v, missing %s", chainNames, want)
		}
	}
}

func TestOptionSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := NewApp()

	suggestions := app.Suggestions("throw --")
	var names []string
	for _, suggestion := range suggestions {
		names = append(names, suggestion.Text)
	}
	for _, want := range []string{"--workspace", "--chain", "--target", "--json"} {
		if !contains(names, want) {
			t.Fatalf("suggestions = %#v, missing %s", names, want)
		}
	}
}

func TestExecuteLineUsesCommandMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := NewApp().ExecuteLine(context.Background(), "control init --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Created   bool `json:"created"`
		Workspace struct {
			Path string `json:"path"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if !payload.Created {
		t.Fatal("created = false, want true")
	}
	if payload.Workspace.Path != workspacePath {
		t.Fatalf("workspace path = %q, want %q", payload.Workspace.Path, workspacePath)
	}
}

func TestPromptPrefixTracksActiveChain(t *testing.T) {
	app := NewApp()
	var stdout, stderr bytes.Buffer

	if got := app.PromptPrefix(); got != "h0v3l> " {
		t.Fatalf("prompt prefix = %q, want default", got)
	}
	if code := app.ExecuteLine(context.Background(), "chain use mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l ( mock-exploit )> " {
		t.Fatalf("prompt prefix = %q, want active chain", got)
	}
}

func TestExecuteLineBuildsChainTargetsThenThrows(t *testing.T) {
	workspacePath := t.TempDir()
	socketPath := workspacePath + "/hoveld.sock"
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()

	waitFor(t, func() bool {
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	app := NewApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain use mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "targets add mock://target", &stdout, &stderr); code != 0 {
		t.Fatalf("targets exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Chain   string `json:"chain"`
		Targets []string
		Results []struct {
			Target string `json:"target"`
			State  string `json:"state"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.Chain != "mock-exploit" {
		t.Fatalf("chain = %q, want mock-exploit", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("targets = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 || payload.Results[0].State != "succeeded" {
		t.Fatalf("results = %#v", payload.Results)
	}
}

func TestRunRejectsOneShotCommandArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "hovel command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestWelcomeShowsOperatorAndDaemonState(t *testing.T) {
	app := NewApp()
	workspacePath := t.TempDir()
	session, err := app.EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	welcome := app.Welcome(session)
	for _, want := range []string{
		`.-"""-.`,
		"╭",
		"╰",
		"━",
		"┃",
		"▓██████▓",
		"modules:",
		"1",
		"hoveld:",
		"hoveld.sock",
		"mode:",
		"managed",
		"health:",
		"healthy",
	} {
		if !strings.Contains(welcome, want) {
			t.Fatalf("welcome missing %q:\n%s", want, welcome)
		}
	}
	if lines := strings.Split(welcome, "\n"); len(lines) < 14 {
		t.Fatalf("welcome line count = %d, want ascii art block:\n%s", len(lines), welcome)
	}
}

func TestEnsureDaemonStartsManagedDaemonForCLI(t *testing.T) {
	workspacePath := t.TempDir()
	session, err := NewApp().EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("daemon state = %s, want running", status.State)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before deadline")
}
