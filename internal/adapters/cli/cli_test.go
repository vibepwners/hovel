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
	prompt "github.com/c-bata/go-prompt"
)

func TestSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := NewApp()

	root := app.Suggestions("ch")
	if len(root) != 1 || root[0].Text != "chain" {
		t.Fatalf("root suggestions = %#v, want chain", root)
	}
	root = app.Suggestions("")
	for _, hidden := range []string{"add", "targets", "throw", "validate"} {
		if containsSuggestion(root, hidden) {
			t.Fatalf("root suggestions = %#v, should hide %s outside chain context", root, hidden)
		}
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
	for _, want := range []string{"create", "delete", "list", "rename", "use"} {
		if !contains(chainNames, want) {
			t.Fatalf("chain suggestions = %#v, missing %s", chainNames, want)
		}
	}
	for _, hidden := range []string{"add", "config", "inspect", "logs", "validate"} {
		if contains(chainNames, hidden) {
			t.Fatalf("chain suggestions = %#v, should hide active-chain command %s", chainNames, hidden)
		}
	}

	configChildren := app.Suggestions("chain config ")
	if len(configChildren) != 0 {
		t.Fatalf("chain config suggestions = %#v, want none outside chain context", configChildren)
	}

	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	configChildren = app.Suggestions("chain config ")
	var configNames []string
	for _, suggestion := range configChildren {
		configNames = append(configNames, suggestion.Text)
	}
	for _, want := range []string{"interactive", "list", "set", "unset"} {
		if !contains(configNames, want) {
			t.Fatalf("chain config suggestions = %#v, missing %s", configNames, want)
		}
	}

	moduleChildren := app.Suggestions("modules ")
	var moduleNames []string
	for _, suggestion := range moduleChildren {
		moduleNames = append(moduleNames, suggestion.Text)
	}
	for _, want := range []string{"inspect", "list", "search"} {
		if !contains(moduleNames, want) {
			t.Fatalf("module suggestions = %#v, missing %s", moduleNames, want)
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

func TestChainAddSuggestsModulesMatchingInput(t *testing.T) {
	app := NewApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}

	suggestions := app.Suggestions("chain add ")
	var names []string
	for _, suggestion := range suggestions {
		names = append(names, suggestion.Text)
	}
	for _, want := range []string{"mock-auth-survey", "mock-simple-exploit", "mock-target-survey"} {
		if !contains(names, want) {
			t.Fatalf("module suggestions = %#v, missing %s", names, want)
		}
	}

	suggestions = app.Suggestions("chain add auth")
	if len(suggestions) != 1 || suggestions[0].Text != "mock-auth-survey" {
		t.Fatalf("filtered module suggestions = %#v, want mock-auth-survey", suggestions)
	}
	if !strings.Contains(suggestions[0].Description, "survey") || !strings.Contains(suggestions[0].Description, "Validate mocked authentication inputs.") {
		t.Fatalf("module suggestion description = %q", suggestions[0].Description)
	}

	suggestions = app.Suggestions("add auth")
	if len(suggestions) != 1 || suggestions[0].Text != "mock-auth-survey" {
		t.Fatalf("filtered alias suggestions = %#v, want mock-auth-survey", suggestions)
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
	if got := app.PromptPrefix(); got != "h0v3l (mock-exploit) > " {
		t.Fatalf("prompt prefix = %q, want active chain", got)
	}
}

func TestChainCreateEntersContextAndRootAliasesOperateOnActiveChain(t *testing.T) {
	app := NewApp()
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l (lab) > " {
		t.Fatalf("prompt prefix = %q, want active chain", got)
	}

	root := app.Suggestions("")
	for _, want := range []string{"add", "config", "inspect", "logs", "rename", "validate"} {
		if !containsSuggestion(root, want) {
			t.Fatalf("root suggestions = %#v, missing active-chain alias %s", root, want)
		}
	}

	if code := app.ExecuteLine(context.Background(), "add mock-simple-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("add alias exit code = %d, stderr = %s", code, stderr.String())
	}
	state := app.session.Snapshot()
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "mock-simple-exploit" {
		t.Fatalf("steps = %#v, want mock-simple-exploit", state.Steps)
	}
}

func TestInteractiveConfigWizardEditsCurrentThenFillsRemainingConfig(t *testing.T) {
	app := NewApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"chain use lab",
		"chain add mock-simple-exploit",
		"targets add mock://router-01",
		"chain config set operator.confirmed_lab true",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s", line, code, stderr.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code := app.ExecuteLine(context.Background(), "chain config interactive", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l (lab) config select > " {
		t.Fatalf("prompt prefix = %q, want config select", got)
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "continue") || !containsSuggestion(suggestions, "1") {
		t.Fatalf("wizard suggestions = %#v, want continue and current item", suggestions)
	}

	for _, line := range []string{"1", "false", "c", "router-01", "22"} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s, stdout = %s", line, code, stderr.String(), stdout.String())
		}
	}
	for _, want := range []string{
		"Current configuration for chain lab",
		"1) chain operator.confirmed_lab=true",
		"chain operator.confirmed_lab (bool) [true]:",
		"Remaining configuration for chain lab",
		"target mock://router-01 target.host (host):",
		"Chain lab configuration complete",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("interactive output missing %q:\n%s", want, stdout.String())
		}
	}

	state := app.session.Snapshot()
	if state.Config["operator.confirmed_lab"] != "false" {
		t.Fatalf("chain config = %#v", state.Config)
	}
	if state.TargetConfigs["mock://router-01"]["target.host"] != "router-01" {
		t.Fatalf("target config = %#v", state.TargetConfigs)
	}
	if state.TargetConfigs["mock://router-01"]["target.port"] != "22" {
		t.Fatalf("target config = %#v", state.TargetConfigs)
	}
}

func TestInteractiveConfigWizardDoesNotBlockWhenThereIsNoCurrentConfig(t *testing.T) {
	app := NewApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"chain use lab",
		"chain add mock-simple-exploit",
		"targets add mock://router-01",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s", line, code, stderr.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "chain config interactive", &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{
		"No current config values.",
		"select config to edit or c to continue",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("interactive output missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "c", &stdout, &stderr); code != 0 {
		t.Fatalf("continue exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l (lab) config value > " {
		t.Fatalf("prompt prefix = %q, want config value", got)
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "true") || !containsSuggestion(suggestions, "false") {
		t.Fatalf("wizard value suggestions = %#v, want bool values", suggestions)
	}
	if !strings.Contains(stdout.String(), "chain operator.confirmed_lab (bool):") {
		t.Fatalf("continue output = %q", stdout.String())
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

func containsSuggestion(suggestions []prompt.Suggest, want string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Text == want {
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
