package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
	prompt "github.com/c-bata/go-prompt"
)

func TestSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := newTestApp()

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
	app := newTestApp()

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
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}

	suggestions := app.Suggestions("chain add ")
	var names []string
	for _, suggestion := range suggestions {
		names = append(names, suggestion.Text)
	}
	for _, want := range []string{"mock-survey@v0.0.0-example", "mock-exploit@v0.0.0-example"} {
		if !contains(names, want) {
			t.Fatalf("module suggestions = %#v, missing %s", names, want)
		}
	}

	suggestions = app.Suggestions("chain add surv")
	if len(suggestions) != 1 || suggestions[0].Text != "mock-survey@v0.0.0-example" {
		t.Fatalf("filtered module suggestions = %#v, want mock-survey@v0.0.0-example", suggestions)
	}
	if !strings.Contains(suggestions[0].Description, "survey") || !strings.Contains(suggestions[0].Description, "Collect example target facts.") {
		t.Fatalf("module suggestion description = %q", suggestions[0].Description)
	}

	suggestions = app.Suggestions("add surv")
	if len(suggestions) != 1 || suggestions[0].Text != "mock-survey@v0.0.0-example" {
		t.Fatalf("filtered alias suggestions = %#v, want mock-survey@v0.0.0-example", suggestions)
	}
}

func TestExecuteLineUsesCommandMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	code := newTestApp().ExecuteLine(context.Background(), "control init --workspace "+workspacePath+" --json", &stdout, &stderr)
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
	app := newTestApp()
	var stdout, stderr bytes.Buffer

	if got := app.PromptPrefix(); got != "h0v3l> " {
		t.Fatalf("prompt prefix = %q, want default", got)
	}
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l (lab) > " {
		t.Fatalf("prompt prefix = %q, want active chain", got)
	}
}

func TestChainCreateEntersContextAndRootAliasesOperateOnActiveChain(t *testing.T) {
	app := newTestApp()
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

	if code := app.ExecuteLine(context.Background(), "add mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("add alias exit code = %d, stderr = %s", code, stderr.String())
	}
	state := app.session.Snapshot()
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("steps = %#v, want mock-exploit@v0.0.0-example", state.Steps)
	}
}

func TestInteractiveConfigWizardEditsCurrentThenFillsRemainingConfig(t *testing.T) {
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"chain use lab",
		"chain add mock-exploit",
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
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"chain use lab",
		"chain add mock-exploit",
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

func TestInteractiveConfigWizardSupportsTypedSuggestionsInvalidRetryAndSecretRedaction(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseChain("typed"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("typed-module"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://router-01"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("api.token", "hunter2"); err != nil {
		t.Fatal(err)
	}
	modules := modulecatalog.New(modulecatalog.Module{
		ID:      "typed-module",
		Name:    "Typed Module",
		Type:    modulecatalog.TypeExploit,
		Enabled: true,
		ChainConfig: []modulecatalog.Requirement{
			{Key: "mode", Type: modulecatalog.ValueEnum, Required: true, Allowed: []string{"quiet", "loud"}, Description: "Execution mode."},
			{Key: "api.token", Type: modulecatalog.ValueSecret, Required: true, Secret: true},
			{Key: "delay", Type: modulecatalog.ValueDuration, Required: true, Default: "5s"},
		},
		TargetConfig: []modulecatalog.Requirement{
			{Key: "target.port", Type: modulecatalog.ValuePort, Required: true},
		},
	})
	app := App{
		commands: commandmode.NewAppWithSessionAndModules(session, modules),
		theme:    DefaultTheme(),
		session:  session,
		modules:  modules,
		wizard:   newInteractiveConfigWizard(session, modules),
	}
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "chain config interactive", &stdout, &stderr); code != 0 {
		t.Fatalf("interactive exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "chain api.token=<secret:set>") {
		t.Fatalf("current config should redact secret:\n%s", stdout.String())
	}
	if suggestions := app.Suggestions(""); containsSuggestion(suggestions, "hunter2") {
		t.Fatalf("secret current value leaked in suggestions: %#v", suggestions)
	}
	stdout.Reset()
	if code := app.ExecuteLine(context.Background(), "c", &stdout, &stderr); code != 0 {
		t.Fatalf("continue exit code = %d, stderr = %s", code, stderr.String())
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "5s") {
		t.Fatalf("duration default suggestions = %#v, want 5s", suggestions)
	}
	if code := app.ExecuteLine(context.Background(), "5s", &stdout, &stderr); code != 0 {
		t.Fatalf("duration exit code = %d, stderr = %s", code, stderr.String())
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "quiet") || !containsSuggestion(suggestions, "loud") {
		t.Fatalf("enum suggestions = %#v, want quiet and loud", suggestions)
	}
	if code := app.ExecuteLine(context.Background(), "nope", &stdout, &stderr); code != 0 {
		t.Fatalf("invalid enum exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "invalid value for mode") {
		t.Fatalf("invalid enum output = %q", stdout.String())
	}
	if code := app.ExecuteLine(context.Background(), "quiet", &stdout, &stderr); code != 0 {
		t.Fatalf("enum exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "22", &stdout, &stderr); code != 0 {
		t.Fatalf("port exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Chain typed configuration complete") {
		t.Fatalf("interactive output missing completion:\n%s", stdout.String())
	}
	state := session.Snapshot()
	if state.Config["mode"] != "quiet" || state.Config["delay"] != "5s" || state.Config["api.token"] != "hunter2" {
		t.Fatalf("chain config = %#v", state.Config)
	}
	if state.TargetConfigs["mock://router-01"]["target.port"] != "22" {
		t.Fatalf("target config = %#v", state.TargetConfigs)
	}
}

func TestRunRejectsOneShotCommandArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "hovel <command>") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestWorkspaceSessionIsSharedAcrossCLIInstances(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	first := newTestApp().withWorkspaceSession(workspacePath)
	second := newTestApp().withWorkspaceSession(workspacePath)
	var stdout, stderr bytes.Buffer

	if code := first.ExecuteLine(context.Background(), "chain create test", &stdout, &stderr); code != 0 {
		t.Fatalf("create exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := second.ExecuteLine(context.Background(), "chain list", &stdout, &stderr); code != 0 {
		t.Fatalf("list exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "test") {
		t.Fatalf("chain list output = %q, want test", stdout.String())
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
