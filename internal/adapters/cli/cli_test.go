package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
	prompt "github.com/c-bata/go-prompt"
)

func TestSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := newTestApp()

	root := app.Suggestions("ch")
	if len(root) != 0 {
		t.Fatalf("root suggestions = %#v, want no chain suggestions before operation", root)
	}
	root = app.Suggestions("")
	for _, hidden := range []string{"add", "chain", "module", "target", "throw", "validate"} {
		if containsSuggestion(root, hidden) {
			t.Fatalf("root suggestions = %#v, should hide %s outside chain context", root, hidden)
		}
	}
	if !containsSuggestion(root, "payloads") {
		t.Fatalf("root suggestions = %#v, want payloads before operation context", root)
	}

	controlChildren := app.Suggestions("control ")
	if len(controlChildren) != 2 || controlChildren[0].Text != "daemon" || controlChildren[1].Text != "init" {
		t.Fatalf("control suggestions = %#v, want daemon and init", controlChildren)
	}
	payloadChildren := app.Suggestions("payloads ")
	for _, want := range []string{"available", "installed", "inspect", "connect", "cleanup", "mark-removed", "refresh"} {
		if !containsSuggestion(payloadChildren, want) {
			t.Fatalf("payload suggestions = %#v, missing %s", payloadChildren, want)
		}
	}

	enterTestOperation(t, app)
	root = app.Suggestions("ch")
	if len(root) != 1 || root[0].Text != "chain" {
		t.Fatalf("root suggestions = %#v, want chain after operation", root)
	}
	if root = app.Suggestions("pay"); !containsSuggestion(root, "payloads") {
		t.Fatalf("root suggestions = %#v, want payloads after operation", root)
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
	if moduleChildren := app.Suggestions("module "); len(moduleChildren) != 0 {
		t.Fatalf("module suggestions = %#v, want none before chain context", moduleChildren)
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

	moduleChildren := app.Suggestions("module ")
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

func TestExecuteLineEnforcesOperationThenChainFlow(t *testing.T) {
	app := newTestApp()
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 1 {
		t.Fatalf("chain before op exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "select an operation first") {
		t.Fatalf("chain before op stderr = %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "op use engagement", &stdout, &stderr); code != 0 {
		t.Fatalf("op use exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "module list", &stdout, &stderr); code != 1 {
		t.Fatalf("module before chain exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "select a chain first") {
		t.Fatalf("module before chain stderr = %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "module list", &stdout, &stderr); code != 0 {
		t.Fatalf("module list exit code = %d, stderr = %s", code, stderr.String())
	}
}

func TestParseSessionConnectTracksExplicitHistoryLimit(t *testing.T) {
	parsed, err := ParseSessionConnectCommand(strings.Fields("session connect --workspace=/tmp/hovel --history-bytes=4096 session-1"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SessionID != "session-1" {
		t.Fatalf("sessionID = %q, want session-1", parsed.SessionID)
	}
	if parsed.Workspace != "/tmp/hovel" {
		t.Fatalf("workspace = %q, want /tmp/hovel", parsed.Workspace)
	}
	if !parsed.Options.HistoryLimitChosen || parsed.Options.HistoryBytes != 4096 || parsed.Options.HistoryLines != 0 {
		t.Fatalf("options = %#v, want explicit 4096-byte history limit", parsed.Options)
	}
}

func TestWriteSessionInputPreservesRawPTYBytes(t *testing.T) {
	writer := &fakeSessionInputWriter{}
	events := make(chan sessionConnectEvent, 1)

	writeSessionInput(context.Background(), writer, "session-1", strings.NewReader("dir\r\n"+string([]byte{sessionDetachByte})), events, sessionInputOptions{Raw: true})

	if got, want := writer.String(), "dir\r\n"; got != want {
		t.Fatalf("written bytes = %q, want %q", got, want)
	}
	if event := <-events; event.err != nil || event.closed {
		t.Fatalf("event = %#v, want clean detach", event)
	}
}

func TestWriteSessionInputNormalizesCookedNewlines(t *testing.T) {
	writer := &fakeSessionInputWriter{}
	events := make(chan sessionConnectEvent, 1)

	writeSessionInput(context.Background(), writer, "session-1", strings.NewReader("dir\r\n"+string([]byte{sessionDetachByte})), events, sessionInputOptions{})

	if got, want := writer.String(), "dir\n"; got != want {
		t.Fatalf("written bytes = %q, want %q", got, want)
	}
	if event := <-events; event.err != nil || event.closed {
		t.Fatalf("event = %#v, want clean detach", event)
	}
}

func TestOptionSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
	if err := app.session.UseChain("lab"); err != nil {
		t.Fatal(err)
	}

	suggestions := app.Suggestions("throw --")
	var names []string
	for _, suggestion := range suggestions {
		names = append(names, suggestion.Text)
	}
	for _, want := range []string{"--workspace", "--chain", "--target", "--target-set", "--json"} {
		if !contains(names, want) {
			t.Fatalf("suggestions = %#v, missing %s", names, want)
		}
	}
}

type fakeSessionInputWriter struct {
	data bytes.Buffer
}

func (w *fakeSessionInputWriter) WriteSession(_ context.Context, _ string, data []byte) error {
	_, err := w.data.Write(data)
	return err
}

func (w *fakeSessionInputWriter) String() string {
	return w.data.String()
}

func TestTargetCommandsWorkInOperationContextWithoutActiveChain(t *testing.T) {
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "op use engagement", &stdout, &stderr); code != 0 {
		t.Fatalf("op use exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, line := range []string{
		"target add mock://router-01",
		"target config set mock://router-01 target.host router-01",
		"target set create lab",
		"target set add lab mock://router-01",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s", line, code, stderr.String())
		}
	}
	state := app.session.Snapshot()
	if got, want := state.Targets, []string{"mock://router-01"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	if len(state.TargetSets) != 1 || state.TargetSets[0].Name != "lab" {
		t.Fatalf("target sets = %#v", state.TargetSets)
	}
	if code := app.ExecuteLine(context.Background(), "chain add mock-exploit", &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "select a chain first") {
		t.Fatalf("chain add exit code = %d, stderr = %s", code, stderr.String())
	}
}

func TestChainAddSuggestsModulesMatchingInput(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
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

func TestPositionalSuggestionsUseCurrentOperatorState(t *testing.T) {
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"op use engagement",
		"op use response",
		"op use engagement",
		"chain create lab",
		"chain create prod",
		"chain add mock-exploit-session",
		"target add mock://router-01",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s", line, code, stderr.String())
		}
	}

	for _, want := range []string{"engagement", "response"} {
		if suggestions := app.Suggestions("op use "); !containsSuggestion(suggestions, want) {
			t.Fatalf("op use suggestions = %#v, missing %s", suggestions, want)
		}
	}
	for _, want := range []string{"lab", "prod"} {
		if suggestions := app.Suggestions("chain use "); !containsSuggestion(suggestions, want) {
			t.Fatalf("chain use suggestions = %#v, missing %s", suggestions, want)
		}
		if suggestions := app.Suggestions("chain rename "); !containsSuggestion(suggestions, want) {
			t.Fatalf("chain rename suggestions = %#v, missing %s", suggestions, want)
		}
	}
	if suggestions := app.Suggestions("module inspect mock-exploit-s"); len(suggestions) != 1 || suggestions[0].Text != "mock-exploit-session@v0.0.0-example" {
		t.Fatalf("module inspect suggestions = %#v, want mock-exploit-session", suggestions)
	}
	if suggestions := app.Suggestions("chain config set "); !containsSuggestion(suggestions, "operator.confirmed_lab") {
		t.Fatalf("chain config key suggestions = %#v, missing operator.confirmed_lab", suggestions)
	}
	if suggestions := app.Suggestions("target config set "); !containsSuggestion(suggestions, "mock://router-01") {
		t.Fatalf("target suggestions = %#v, missing mock://router-01", suggestions)
	}
	if suggestions := app.Suggestions("target config set mock://router-01 target.p"); !containsSuggestion(suggestions, "target.port") {
		t.Fatalf("target config key suggestions = %#v, missing target.port", suggestions)
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
	if code := app.ExecuteLine(context.Background(), "op use engagement", &stdout, &stderr); code != 0 {
		t.Fatalf("operation exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l [engagement]> " {
		t.Fatalf("prompt prefix = %q, want active operation", got)
	}
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l [engagement/lab] > " {
		t.Fatalf("prompt prefix = %q, want active chain", got)
	}
}

func TestCLIWelcomeCanBeSuppressedByEnvironment(t *testing.T) {
	t.Setenv("HOVEL_CLI_NO_WELCOME", "")
	if !cliWelcomeEnabled() {
		t.Fatal("welcome disabled with empty environment")
	}

	t.Setenv("HOVEL_CLI_NO_WELCOME", "1")
	if cliWelcomeEnabled() {
		t.Fatal("welcome enabled when HOVEL_CLI_NO_WELCOME=1")
	}

	t.Setenv("HOVEL_CLI_NO_WELCOME", "false")
	if !cliWelcomeEnabled() {
		t.Fatal("welcome disabled when HOVEL_CLI_NO_WELCOME=false")
	}
}

func TestChainCreateEntersContextAndRootAliasesOperateOnActiveChain(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l [test-op/lab] > " {
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
		"op use test-op",
		"chain use lab",
		"chain add mock-exploit",
		"target add mock://router-01",
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
	if got := app.PromptPrefix(); got != "h0v3l [test-op/lab] config select > " {
		t.Fatalf("prompt prefix = %q, want config select", got)
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "continue") || !containsSuggestion(suggestions, "1") {
		t.Fatalf("wizard suggestions = %#v, want continue and current item", suggestions)
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "1", &stdout, &stderr); code != 0 {
		t.Fatalf("select current exit code = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if got, want := app.PromptPrefix(), "h0v3l [test-op/lab] chain operator.confirmed_lab (bool) [true]: "; got != want {
		t.Fatalf("prompt prefix = %q, want %q", got, want)
	}
	if !strings.Contains(stdout.String(), "Editing chain operator.confirmed_lab=true") {
		t.Fatalf("select output = %q, want editing line", stdout.String())
	}
	if strings.Contains(stdout.String(), "chain operator.confirmed_lab (bool) [true]:") {
		t.Fatalf("select output printed value prompt instead of using prompt prefix:\n%s", stdout.String())
	}

	for _, line := range []string{"false", "c", "router-01", "22"} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s, stdout = %s", line, code, stderr.String(), stdout.String())
		}
	}
	for _, want := range []string{
		"Available configuration for chain lab",
		"1) chain operator.confirmed_lab=false",
		"Remaining configuration for chain lab",
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
		"op use test-op",
		"chain use lab",
		"chain add mock-exploit",
		"target add mock://router-01",
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
		"Available configuration for chain lab",
		"chain operator.confirmed_lab=required",
		"target mock://router-01 target.host=required",
		"target mock://router-01 target.port=required",
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
	if got, want := app.PromptPrefix(), "h0v3l [test-op/lab] chain operator.confirmed_lab (bool): "; got != want {
		t.Fatalf("prompt prefix = %q, want %q", got, want)
	}
	if suggestions := app.Suggestions(""); !containsSuggestion(suggestions, "true") || !containsSuggestion(suggestions, "false") {
		t.Fatalf("wizard value suggestions = %#v, want bool values", suggestions)
	}
	if strings.Contains(stdout.String(), "chain operator.confirmed_lab (bool):") {
		t.Fatalf("continue output printed value prompt instead of using prompt prefix:\n%s", stdout.String())
	}
}

func TestInteractiveConfigWizardSupportsTypedSuggestionsInvalidRetryAndRedactsSecrets(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("test-op"); err != nil {
		t.Fatal(err)
	}
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
			{Key: "payload.bind_port", Type: modulecatalog.ValuePort, Required: false, Default: "9101"},
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
	if strings.Contains(stdout.String(), "hunter2") || !strings.Contains(stdout.String(), "chain api.token=********") {
		t.Fatalf("current config should redact secret:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "target mock://router-01 payload.bind_port=default 9101") {
		t.Fatalf("available config should show optional default:\n%s", stdout.String())
	}
	if suggestions := app.Suggestions(""); containsSuggestion(suggestions, "hunter2") || containsSuggestionDescription(suggestions, "hunter2") {
		t.Fatalf("secret current value leaked into suggestions: %#v", suggestions)
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

func TestInteractiveConfigSeesInstalledWorkspaceModule(t *testing.T) {
	workspace := t.TempDir()
	moduleRoot := filepath.Join(t.TempDir(), "installed-rpc")
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "hovel-module.yaml"), []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: installed-rpc
  version: 0.1.0
  moduleType: exploit
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/installed-rpc"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "bin", "installed-rpc"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := modulepackage.InstallLink(modulepackage.InstallOptions{
		Workspace: workspace,
		SourceDir: moduleRoot,
		HostOS:    "linux",
		HostArch:  "amd64",
		NoScripts: true,
	}); err != nil {
		t.Fatal(err)
	}

	session := operatorsession.New()
	if err := session.UseOperation("test-op"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("installed-rpc@0.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target-1"); err != nil {
		t.Fatal(err)
	}
	app := newAppWithSessionAndModules(session, modulecatalog.New())
	app.workspacePath = workspace

	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain config interactive", &stdout, &stderr); code != 0 {
		t.Fatalf("interactive exit code = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if code := app.ExecuteLine(context.Background(), "c", &stdout, &stderr); code != 0 {
		t.Fatalf("continue exit code = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "Chain lab configuration complete") {
		t.Fatalf("interactive output missing completion:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "module installed-rpc@0.1.0 does not exist") {
		t.Fatalf("interactive output rejected installed module:\n%s", stdout.String())
	}
}

func TestInteractiveConfigWizardUsesEffectiveValidationForSquatterBind(t *testing.T) {
	session := operatorsession.New()
	modules := modulecatalog.New(
		modulecatalog.Module{
			ID:      "etro-exploit@v1.0.0",
			Name:    "etro-exploit",
			Type:    modulecatalog.TypeExploit,
			Enabled: true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "operator.confirmed_lab", Type: modulecatalog.ValueBool, Required: true},
			},
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true},
			},
		},
		modulecatalog.Module{
			ID:      "squatter@v0.1.0",
			Name:    "squatter",
			Type:    modulecatalog.TypePayloadProvider,
			Enabled: true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "payload.transport", Type: modulecatalog.ValueEnum, Required: true, Allowed: []string{"tcp-bind", "smb-named-pipe"}},
				{Key: "payload.bind_port", Type: modulecatalog.ValuePort, Required: true},
				{Key: "payload.pipe", Type: modulecatalog.ValueString, Required: true},
				{Key: "smb.username", Type: modulecatalog.ValueString, Required: true},
			},
		},
	)
	app := newAppWithSessionAndModules(session, modules)
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"op use test-op",
		"chain use lab",
		"chain add etro-exploit@v1.0.0",
		"chain add squatter@v0.1.0",
		"target add t1",
		"chain config interactive",
		"c",
		"true",
		"192.168.122.142",
		"445",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s, stdout = %s", line, code, stderr.String(), stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "Chain lab configuration complete") {
		t.Fatalf("interactive output missing completion:\n%s", stdout.String())
	}
	for _, unexpected := range []string{"payload.transport", "payload.pipe", "smb.username"} {
		if strings.Contains(stdout.String(), "missing chain config "+unexpected) {
			t.Fatalf("interactive output surfaced raw Squatter provider requirement %s:\n%s", unexpected, stdout.String())
		}
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

func TestPromptExitCheckerOnlyExitsAfterSubmittedLine(t *testing.T) {
	if promptExitChecker("exit", false) {
		t.Fatal("exit checker fired before Enter")
	}
	if !promptExitChecker("exit", true) {
		t.Fatal("exit checker did not fire after submitted exit")
	}
	if !promptExitChecker(" quit ", true) {
		t.Fatal("exit checker did not accept quit")
	}
}

func TestThrowAnimationOnlyWrapsThrowExecution(t *testing.T) {
	for _, line := range []string{"throw", "throw --workspace .hovel", "throw --chain mock-exploit"} {
		if !isThrowExecutionCommand(line) {
			t.Fatalf("%q was not recognized as throw execution", line)
		}
	}
	for _, line := range []string{"throw", "throw --workspace .hovel", "throw --chain mock-exploit"} {
		if isAnimatedThrowExecutionCommand(line) {
			t.Fatalf("%q should not animate before confirmation", line)
		}
	}
	for _, line := range []string{"throw --now", "throw --workspace .hovel --now", "throw -n"} {
		if !isAnimatedThrowExecutionCommand(line) {
			t.Fatalf("%q should animate immediate throw", line)
		}
	}
	for _, line := range []string{"", "throw list", "throw inspect plan-1", "throws list", "chain throw"} {
		if isThrowExecutionCommand(line) {
			t.Fatalf("%q was recognized as throw execution", line)
		}
	}
	for _, line := range []string{"throw --now", "throw demo/chain.yaml --now"} {
		if !isLiveThrowExecutionCommand(line) {
			t.Fatalf("%q was not recognized as live throw execution", line)
		}
	}
	for _, line := range []string{"throw --now --json", "throw -j --now", "throw list"} {
		if isLiveThrowExecutionCommand(line) {
			t.Fatalf("%q should not render live throw logs", line)
		}
	}
}

func TestExecuteLineInjectsShellWorkspaceForWorkspaceCommands(t *testing.T) {
	var capturedWorkspace string
	registry, err := commands.NewRegistry(commands.Definition{
		Path:        []string{"throw"},
		Summary:     "Run a throw.",
		Positionals: []commands.Positional{{Name: "chain_file", Required: true}},
		Options: []commands.Option{
			{Name: "workspace", Short: "w", ValueName: "path", Kind: commands.OptionString},
			{Name: "now", Short: "n", Kind: commands.OptionBool},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			capturedWorkspace = invocation.Option("workspace")
			return commands.Result{Human: "ok"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := operatorsession.New()
	if err := session.UseOperation("demo"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("mock-survey-exploit-demo"); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(t.TempDir(), "workspace with space")
	app := App{
		commands:      commandmode.NewAppWithRegistry(registry),
		theme:         DefaultTheme(),
		session:       session,
		workspacePath: workspacePath,
	}
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "throw demo.chain --now", &stdout, &stderr); code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	if capturedWorkspace != workspacePath {
		t.Fatalf("workspace = %q, want %q", capturedWorkspace, workspacePath)
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "throw demo.chain --workspace explicit --now", &stdout, &stderr); code != 0 {
		t.Fatalf("throw explicit workspace exit code = %d, stderr = %s", code, stderr.String())
	}
	if capturedWorkspace != "explicit" {
		t.Fatalf("explicit workspace = %q, want explicit", capturedWorkspace)
	}
}

func TestWorkspaceSessionIsSharedAcrossCLIInstances(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	first := newTestApp().withWorkspaceSession(workspacePath)
	second := newTestApp().withWorkspaceSession(workspacePath)
	var stdout, stderr bytes.Buffer

	if code := first.ExecuteLine(context.Background(), "op use shared", &stdout, &stderr); code != 0 {
		t.Fatalf("op use exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

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
	if _, err := os.Stat(filepath.Join(workspacePath, sqlitestore.DatabaseFile)); err != nil {
		t.Fatalf("workspace database was not created: %v", err)
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

func containsSuggestionDescription(suggestions []prompt.Suggest, want string) bool {
	for _, suggestion := range suggestions {
		if strings.Contains(suggestion.Description, want) {
			return true
		}
	}
	return false
}
