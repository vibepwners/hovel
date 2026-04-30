package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
	prompt "github.com/c-bata/go-prompt"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfig)
	os.Exit(m.Run())
}

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
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l (lab) > " {
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

	if code := app.ExecuteLine(context.Background(), "add mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("add alias exit code = %d, stderr = %s", code, stderr.String())
	}
	state := app.session.Snapshot()
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("steps = %#v, want mock-exploit@v0.0.0-example", state.Steps)
	}
}

func TestInteractiveConfigWizardEditsCurrentThenFillsRemainingConfig(t *testing.T) {
	app := NewApp()
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
	app := NewApp()
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
		commands: commandmode.NewAppWithSession(session),
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

func TestExecuteLineBuildsChainTargetsThenThrows(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := NewApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "chain add mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("chain add exit code = %d, stderr = %s", code, stderr.String())
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
	if payload.Chain != "lab" {
		t.Fatalf("chain = %q, want lab", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("targets = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 || payload.Results[0].State != "succeeded" {
		t.Fatalf("results = %#v", payload.Results)
	}
}

func TestDaemonLogSubscriptionOnlyShowsActiveChain(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alphaClient, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer alphaClient.Close()
	betaClient, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer betaClient.Close()

	alpha := NewApp().withDaemonSession(ctx, alphaClient)
	beta := NewApp().withDaemonSession(ctx, betaClient)
	if err := alpha.session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}

	var alphaOut, betaOut bytes.Buffer
	stopAlpha := alpha.SubscribeLogs(ctx, alphaClient, nil, &alphaOut)
	defer stopAlpha()
	stopBeta := beta.SubscribeLogs(ctx, betaClient, nil, &betaOut)
	defer stopBeta()

	if _, err := alpha.session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	testsupport.WaitFor(t, func() bool {
		return strings.Contains(alphaOut.String(), "mock-survey") && strings.Contains(betaOut.String(), "mock-exploit")
	})
	if strings.Contains(alphaOut.String(), "mock-exploit") {
		t.Fatalf("alpha output leaked beta log:\n%s", alphaOut.String())
	}
	if strings.Contains(betaOut.String(), "mock-survey") {
		t.Fatalf("beta output leaked alpha log:\n%s", betaOut.String())
	}
}

func TestE2EExampleSurveyAuthChainUsesPythonModules(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := NewApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"chain use survey-example",
		"chain add mock-survey",
		"targets add mock://router-01",
		"targets config set mock://router-01 target.host router-01",
		"targets config set mock://router-01 target.port 22",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if payload.Chain != "survey-example" {
		t.Fatalf("chain = %q, want survey-example", payload.Chain)
	}
	if got, want := moduleIDs(payload.Results), []string{"mock-survey@v0.0.0-example"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("module order = %#v, want %#v", got, want)
	}
	for _, result := range payload.Results {
		if result.Target != "mock://router-01" || result.State != "succeeded" {
			t.Fatalf("result = %#v", result)
		}
	}
}

func TestE2EExamplePayloadExploitChainUsesPythonModules(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := NewApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"chain use survey-exploit",
		"chain add mock-survey",
		"chain add mock-exploit",
		"targets add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"targets config set mock://router-01 target.host router-01",
		"targets config set mock://router-01 target.port 22",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if got, want := moduleIDs(payload.Results), []string{"mock-survey@v0.0.0-example", "mock-exploit@v0.0.0-example"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("module order = %#v, want %#v", got, want)
	}
	exploit := payload.Results[1]
	if exploit.State != "succeeded" {
		t.Fatalf("exploit state = %q, want succeeded", exploit.State)
	}
	if len(exploit.Findings) != 1 {
		t.Fatalf("findings = %#v, want one finding", exploit.Findings)
	}
	if len(exploit.Artifacts) != 1 || exploit.Artifacts[0].Name != "mock-exploit-transcript.txt" {
		t.Fatalf("artifacts = %#v, want mock transcript", exploit.Artifacts)
	}
	if !hasPayloadLog(exploit.Logs, "example exploit started") {
		t.Fatalf("logs = %#v, want example exploit started", exploit.Logs)
	}
}

func TestE2EExampleFailingChainReportsFailedModule(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := NewApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"chain use failing-example",
		"chain add mock-exploit",
		"targets add mock://target",
		"chain config set operator.confirmed_lab true",
		"chain config set failure_mode execution",
		"targets config set mock://target target.host target",
		"targets config set mock://target target.port 443",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if len(payload.Results) != 1 {
		t.Fatalf("results = %#v, want one result", payload.Results)
	}
	result := payload.Results[0]
	if result.ModuleID != "mock-exploit@v0.0.0-example" || result.State != "failed" {
		t.Fatalf("result = %#v, want failed mock-exploit@v0.0.0-example", result)
	}
	if !strings.Contains(result.Summary, "failed during execution") {
		t.Fatalf("summary = %q", result.Summary)
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

func executeLines(t *testing.T, app App, stdout, stderr *bytes.Buffer, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if code := app.ExecuteLine(context.Background(), line, stdout, stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s, stdout = %s", line, code, stderr.String(), stdout.String())
		}
	}
}

type e2eThrowPayload struct {
	Chain   string   `json:"chain"`
	Targets []string `json:"targets"`
	Results []struct {
		RunID    string `json:"runId"`
		ModuleID string `json:"moduleId"`
		Target   string `json:"target"`
		State    string `json:"state"`
		Summary  string `json:"summary"`
		Findings []struct {
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Detail   string `json:"detail"`
		} `json:"findings"`
		Artifacts []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Data string `json:"data"`
		} `json:"artifacts"`
		Logs []struct {
			Level   string            `json:"level"`
			Message string            `json:"message"`
			Logger  string            `json:"logger"`
			Fields  map[string]string `json:"fields"`
		} `json:"logs"`
	} `json:"results"`
}

func decodeThrowJSON(t *testing.T, data []byte) e2eThrowPayload {
	t.Helper()
	var payload e2eThrowPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", string(data), err)
	}
	return payload
}

func moduleIDs(results []struct {
	RunID    string `json:"runId"`
	ModuleID string `json:"moduleId"`
	Target   string `json:"target"`
	State    string `json:"state"`
	Summary  string `json:"summary"`
	Findings []struct {
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Detail   string `json:"detail"`
	} `json:"findings"`
	Artifacts []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Data string `json:"data"`
	} `json:"artifacts"`
	Logs []struct {
		Level   string            `json:"level"`
		Message string            `json:"message"`
		Logger  string            `json:"logger"`
		Fields  map[string]string `json:"fields"`
	} `json:"logs"`
}) []string {
	ids := make([]string, 0, len(results))
	for _, result := range results {
		ids = append(ids, result.ModuleID)
	}
	return ids
}

func hasPayloadLog(logs []struct {
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Logger  string            `json:"logger"`
	Fields  map[string]string `json:"fields"`
}, message string) bool {
	for _, log := range logs {
		if log.Message == message {
			return true
		}
	}
	return false
}

func TestWelcomeShowsOperatorAndDaemonState(t *testing.T) {
	app := NewApp()
	workspacePath := testsupport.TempDir(t)
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
		"2",
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
	workspacePath := testsupport.TempDir(t)
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

func TestEnsureDaemonAttachesToWorkspaceDaemonForCLI(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := NewApp()
	session, err := app.EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	welcome := app.Welcome(session)
	for _, want := range []string{"mode:", "remote", "hoveld.sock"} {
		if !strings.Contains(welcome, want) {
			t.Fatalf("welcome missing %q:\n%s", want, welcome)
		}
	}
}

func TestWorkspaceSessionIsSharedAcrossCLIInstances(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	first := NewApp().withWorkspaceSession(workspacePath)
	second := NewApp().withWorkspaceSession(workspacePath)
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

func daemonruntimeArgs() daemonruntime.Args {
	return daemonruntime.Args{}
}
