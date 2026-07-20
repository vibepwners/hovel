package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	prompt "github.com/c-bata/go-prompt"
	"github.com/vibepwners/hovel/internal/adapters/commandmode"
	"github.com/vibepwners/hovel/internal/adapters/daemonrpc"
	sqlitestore "github.com/vibepwners/hovel/internal/adapters/storage/sqlite"
	"github.com/vibepwners/hovel/internal/app/commands"
	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/app/modulepackage"
	"github.com/vibepwners/hovel/internal/app/operatorsession"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/infra/daemonruntime"
	"github.com/vibepwners/hovel/internal/testsupport"
)

func TestSuggestionsComeFromCommandRegistry(t *testing.T) {
	app := newTestApp()

	root := app.Suggestions("ch")
	if len(root) != 0 {
		t.Fatalf("root suggestions = %#v, want no chain suggestions before operation", root)
	}
	root = app.Suggestions("")
	for _, hidden := range []string{"add", "chain", "target", "throw", "validate"} {
		if containsSuggestion(root, hidden) {
			t.Fatalf("root suggestions = %#v, should hide %s outside chain context", root, hidden)
		}
	}
	if !containsSuggestion(root, "module") {
		t.Fatalf("root suggestions = %#v, want module before operation context", root)
	}
	if !containsSuggestion(root, "payloads") {
		t.Fatalf("root suggestions = %#v, want payloads before operation context", root)
	}
	for _, want := range []string{"artifact", "confirm", "control", "launch-key", "pki", "review", "session"} {
		if !containsSuggestion(root, want) {
			t.Fatalf("root suggestions = %#v, missing context-independent CLI surface %s", root, want)
		}
	}

	controlChildren := app.Suggestions("control ")
	if len(controlChildren) != 2 || controlChildren[0].Text != "daemon" || controlChildren[1].Text != "init" {
		t.Fatalf("control suggestions = %#v, want daemon and init", controlChildren)
	}
	payloadChildren := app.Suggestions("payloads ")
	for _, want := range []string{"available", "installed", "inspect", "connect", "cleanup", "mark-removed", "refresh", "capabilities", "call"} {
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
	if root = app.Suggestions("tar"); !containsSuggestion(root, "target") {
		t.Fatalf("root suggestions = %#v, want target after operation", root)
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
	moduleChildren := app.Suggestions("module ")
	var moduleNames []string
	for _, suggestion := range moduleChildren {
		moduleNames = append(moduleNames, suggestion.Text)
	}
	for _, want := range []string{"available", "installed", "install", "list", "search"} {
		if !contains(moduleNames, want) {
			t.Fatalf("module suggestions = %#v, missing %s before chain context", moduleNames, want)
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

	moduleChildren = app.Suggestions("module ")
	moduleNames = nil
	for _, suggestion := range moduleChildren {
		moduleNames = append(moduleNames, suggestion.Text)
	}
	for _, want := range []string{"available", "installed", "inspect", "list", "search"} {
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

	if code := app.ExecuteLine(context.Background(), "module list", &stdout, &stderr); code != 0 {
		t.Fatalf("module before chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No installed modules") {
		t.Fatalf("module before chain stdout = %q", stdout.String())
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

func TestParseSessionConnectRejectsUnknownOptionsAndExtraPositionals(t *testing.T) {
	for _, fields := range [][]string{
		{"session", "connect", "session-1", "--bogus"},
		{"session", "connect", "session-1", "session-2"},
	} {
		if _, err := ParseSessionConnectCommand(fields); err == nil {
			t.Fatalf("ParseSessionConnectCommand(%q) succeeded, want error", fields)
		}
	}
}

func TestParseSessionConnectLineUsesShellQuoting(t *testing.T) {
	sessionID, options, err := parseSessionConnect(`session connect "session one" --workspace "workspace with spaces" --history-lines 12`)
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "session one" || options.HistoryLines != 12 {
		t.Fatalf("session = %q, options = %#v", sessionID, options)
	}
	parsed, err := ParseSessionConnectCommand([]string{"session", "connect", "session one", "--workspace", "workspace with spaces"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Workspace != "workspace with spaces" {
		t.Fatalf("workspace = %q", parsed.Workspace)
	}
}

func TestInteractiveSessionConnectUsesRegistryValidation(t *testing.T) {
	app := newTestApp()
	for _, line := range []string{"session connect", "session connect session-1 --not-an-option", "session connect session-1 extra"} {
		var stdout, stderr bytes.Buffer
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 2 {
			t.Errorf("ExecuteLine(%q) code = %d, want 2; stdout = %s; stderr = %s", line, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "usage: session connect") {
			t.Errorf("ExecuteLine(%q) did not render command usage: %s", line, stderr.String())
		}
		if strings.Contains(stderr.String(), "hovel command") {
			t.Errorf("ExecuteLine(%q) leaked the one-shot command prefix: %s", line, stderr.String())
		}
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
	for _, want := range []string{"--workspace", "--chain", "--target", "--target-set", "--target-group", "--json"} {
		if !contains(names, want) {
			t.Fatalf("suggestions = %#v, missing %s", names, want)
		}
	}
}

func TestEveryRegisteredOptionIsReachableThroughCompletion(t *testing.T) {
	app := newTestApp()
	registry := app.commands.Registry()
	for _, canonical := range registry.Definitions() {
		paths := append([][]string{canonical.Path}, canonical.Aliases...)
		for _, path := range paths {
			definition, ok := registry.Find(path...)
			if !ok {
				t.Fatalf("registry did not resolve %q", strings.Join(path, " "))
			}
			t.Run(strings.Join(path, "/"), func(t *testing.T) {
				longFields := append(append([]string(nil), path...), "--")
				longSuggestions := app.definitionSuggestions(definition, len(path), longFields, false)
				shortFields := append(append([]string(nil), path...), "-")
				shortSuggestions := app.definitionSuggestions(definition, len(path), shortFields, false)
				for _, option := range definition.Options {
					if !containsSuggestion(longSuggestions, "--"+option.Name) {
						t.Errorf("suggestions for %q omitted --%s: %#v", strings.Join(path, " "), option.Name, longSuggestions)
					}
					if option.Short != "" && !containsSuggestion(shortSuggestions, "-"+option.Short) {
						t.Errorf("suggestions for %q omitted -%s: %#v", strings.Join(path, " "), option.Short, shortSuggestions)
					}
				}
			})
		}
	}
}

func TestEveryCanonicalCommandIsReachableThroughInteractiveCompletion(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
	if err := app.session.UseChain("lab"); err != nil {
		t.Fatal(err)
	}
	for _, definition := range app.commands.Registry().Definitions() {
		for depth, want := range definition.Path {
			line := strings.Join(definition.Path[:depth], " ")
			if line != "" {
				line += " "
			}
			t.Run(definition.PathString()+"/segment-"+strconv.Itoa(depth), func(t *testing.T) {
				if suggestions := app.Suggestions(line); !containsSuggestion(suggestions, want) {
					t.Fatalf("Suggestions(%q) = %#v, missing canonical segment %q", line, suggestions, want)
				}
			})
		}
	}
}

func TestEveryActiveChainAliasHasAContextualRewrite(t *testing.T) {
	tests := map[string]struct {
		fields []string
		want   string
	}{
		"add":      {fields: []string{"add", "module@1.0.0"}, want: "chain add module@1.0.0"},
		"config":   {fields: []string{"config", "list"}, want: "chain config list"},
		"inspect":  {fields: []string{"inspect"}, want: "chain inspect"},
		"logs":     {fields: []string{"logs"}, want: "chain logs"},
		"rename":   {fields: []string{"rename", "new-name"}, want: "chain rename current-chain new-name"},
		"validate": {fields: []string{"validate"}, want: "chain validate"},
	}
	for _, alias := range activeChainAliases {
		test, ok := tests[alias.text]
		if !ok {
			t.Errorf("active-chain alias %q has no UX contract", alias.text)
			continue
		}
		got, ok := contextualCommandAlias(test.fields, "current-chain")
		if !ok || got != test.want {
			t.Errorf("contextualCommandAlias(%q) = %q, %t; want %q, true", test.fields, got, ok, test.want)
		}
		delete(tests, alias.text)
	}
	for alias := range tests {
		t.Errorf("UX contract for %q has no active-chain alias", alias)
	}
}

func TestEveryActiveChainAliasKeepsMalformedInputOnItsCanonicalCommand(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}

	tests := map[string]struct {
		line      string
		wantUsage string
		wantError string
	}{
		"add":      {line: "add", wantUsage: "usage: chain add", wantError: "module is required"},
		"config":   {line: "config", wantUsage: "usage: chain config", wantError: "subcommand is required"},
		"inspect":  {line: "inspect unexpected", wantUsage: "usage: chain inspect", wantError: "unknown arguments"},
		"logs":     {line: "logs unexpected", wantUsage: "usage: chain logs", wantError: "unknown arguments"},
		"rename":   {line: "rename", wantUsage: "usage: chain rename", wantError: "name is required"},
		"validate": {line: "validate unexpected", wantUsage: "usage: chain validate", wantError: "unknown arguments"},
	}
	for _, alias := range activeChainAliases {
		test, ok := tests[alias.text]
		if !ok {
			t.Errorf("active-chain alias %q has no malformed-input UX contract", alias.text)
			continue
		}
		t.Run(alias.text, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			if code := app.ExecuteLine(context.Background(), test.line, &stdout, &stderr); code != 2 {
				t.Fatalf("ExecuteLine(%q) code = %d, want 2; stdout = %s; stderr = %s", test.line, code, stdout.String(), stderr.String())
			}
			output := stderr.String()
			if !strings.Contains(output, test.wantUsage) {
				t.Fatalf("ExecuteLine(%q) missing local usage %q:\n%s", test.line, test.wantUsage, output)
			}
			if !strings.Contains(output, test.wantError) {
				t.Fatalf("ExecuteLine(%q) missing diagnosis %q:\n%s", test.line, test.wantError, output)
			}
			if strings.Contains(output, "unknown command") {
				t.Fatalf("ExecuteLine(%q) mislabeled an advertised alias as unknown:\n%s", test.line, output)
			}
			if strings.Contains(output, "hovel command") {
				t.Fatalf("ExecuteLine(%q) leaked the one-shot prefix:\n%s", test.line, output)
			}
		})
		delete(tests, alias.text)
	}
	for alias := range tests {
		t.Errorf("malformed-input UX contract for %q has no active-chain alias", alias)
	}
}

func TestRegisteredCompletionArgumentsHaveExplicitPolicies(t *testing.T) {
	positionalPolicies := stringSet(
		"artifact", "assignment", "authority", "capability", "chain", "command", "consumer", "crl", "data", "file", "generation", "key", "local", "manifest", "mode", "module", "name", "operation", "payload", "query", "remote", "revocation", "session", "source", "target", "throw", "trust-set", "value",
	)
	optionValuePolicies := stringSet(
		"anchors", "arg", "backend", "bytes", "chain", "config", "consumer-type", "crls", "duration", "effective-at", "end", "generation-id", "heartbeat-timeout", "history-bytes", "history-lines", "host", "id", "idempotency-key", "index", "input-data", "input-encoding", "input-file", "intermediates", "issuer", "issuer-generation", "key-id", "lines", "link", "name", "operation", "parent", "port", "profile", "purpose", "quorum", "reason", "revision", "role", "rotation-policy", "set", "sha256", "signature-algorithm", "state", "summary", "tag", "target", "target-group", "target-set", "trust-set", "type", "valid-for", "version", "workspace",
	)
	for _, definition := range newTestApp().commands.Registry().Definitions() {
		for _, positional := range definition.Positionals {
			if !positionalPolicies[positional.Name] {
				t.Errorf("command %q positional %q has no explicit completion policy", definition.PathString(), positional.Name)
			}
		}
		for _, option := range definition.Options {
			if option.Kind != commands.OptionBool && !optionValuePolicies[option.Name] {
				t.Errorf("command %q option --%s has no explicit value-completion policy", definition.PathString(), option.Name)
			}
		}
	}
}

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func TestCompletionCursorDoesNotCountOptionsAsPositionals(t *testing.T) {
	definition := commands.Definition{
		Path: []string{"demo"},
		Positionals: []commands.Positional{
			{Name: "first", Required: true},
			{Name: "second", Required: true},
		},
		Options: []commands.Option{
			{Name: "workspace", Short: "w", Kind: commands.OptionString},
			{Name: "tag", Kind: commands.OptionStringList},
			{Name: "json", Short: "j", Kind: commands.OptionBool},
		},
	}
	tests := []struct {
		name           string
		line           string
		endsWithSpace  bool
		positional     int
		prefix         string
		optionValue    string
		optionName     bool
		positionals    []string
		attachedPrefix string
	}{
		{name: "options before and between positionals", line: "demo --workspace lab first --json sec", positional: 1, prefix: "sec", positionals: []string{"first"}},
		{name: "combined short options", line: "demo -jw lab fir", positional: 0, prefix: "fir"},
		{name: "option value after positional", line: "demo first --workspace ", endsWithSpace: true, positional: 0, optionValue: "workspace", positionals: []string{"first"}},
		{name: "attached option value", line: "demo --workspace=la", positional: 0, prefix: "la", optionValue: "workspace", attachedPrefix: "--workspace="},
		{name: "attached combined short option value", line: "demo -jw=la", positional: 0, prefix: "la", optionValue: "workspace", attachedPrefix: "-jw="},
		{name: "option name", line: "demo first --j", positional: 0, prefix: "--j", optionName: true, positionals: []string{"first"}},
		{name: "delimiter disables options", line: "demo -- --json", positional: 0, prefix: "--json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cursor := completionCursorFor(definition, 1, strings.Fields(test.line), test.endsWithSpace)
			if cursor.positional != test.positional || cursor.prefix != test.prefix || cursor.optionName != test.optionName || cursor.attachedPrefix != test.attachedPrefix || !reflect.DeepEqual(cursor.positionals, test.positionals) {
				t.Fatalf("cursor = %#v", cursor)
			}
			gotOption := ""
			if cursor.option != nil {
				gotOption = cursor.option.Name
			}
			if cursor.optionValue != (test.optionValue != "") || gotOption != test.optionValue {
				t.Fatalf("option cursor = %#v, want option %q", cursor, test.optionValue)
			}
		})
	}
}

func TestCompletionContinuesPositionalsAroundOptions(t *testing.T) {
	app := newTestApp()
	var stdout, stderr bytes.Buffer
	for _, line := range []string{
		"op use engagement",
		"chain create lab",
		"chain add mock-exploit",
		"target add mock://router-01",
		"target set create routers",
	} {
		if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s", line, code, stderr.String())
		}
	}

	tests := []struct {
		line string
		want string
	}{
		{line: "chain add --config lab.yaml surv", want: "mock-survey@v0.0.0-example"},
		{line: "target config set --debug mock://router-01 target.p", want: "target.port"},
		{line: "target set add --config=lab.yaml routers mock", want: "mock://router-01"},
		{line: "throw --chain ", want: "lab"},
		{line: "throw --target mock", want: "mock://router-01"},
		{line: "throw --target-set ", want: "routers"},
		{line: "module installed --type ", want: "survey"},
		{line: "module installed --type=sur", want: "--type=survey"},
		{line: "pki authority create root --role ", want: "subordinate"},
		{line: "launch-key policy set ", want: "quorum"},
	}
	for _, test := range tests {
		if suggestions := app.Suggestions(test.line); !containsSuggestion(suggestions, test.want) {
			t.Errorf("Suggestions(%q) = %#v, missing %q", test.line, suggestions, test.want)
		}
	}
}

func TestFileCompletionCoversFilePositionalsAndOptions(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("HOME", root)
	t.Setenv("HOVEL_COMPLETION_ROOT", root)
	if err := os.WriteFile("demo.chain.yaml", []byte("demo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("configs", 0o700); err != nil {
		t.Fatal(err)
	}
	app := newTestApp()
	enterTestOperation(t, app)
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, test := range []struct {
		line string
		want string
	}{
		{line: "chain load demo", want: "demo.chain.yaml"},
		{line: "module bulk-install demo", want: "demo.chain.yaml"},
		{line: "module install --link con", want: "configs/"},
		{line: "module install --link ~/con", want: "~/configs/"},
		{line: "module install --link $HOVEL_COMPLETION_ROOT/con", want: "$HOVEL_COMPLETION_ROOT/configs/"},
		{line: "throw demo", want: "demo.chain.yaml"},
	} {
		if suggestions := app.Suggestions(test.line); !containsSuggestion(suggestions, test.want) {
			t.Errorf("Suggestions(%q) = %#v, missing %q", test.line, suggestions, test.want)
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

	suggestions = app.Suggestions("add")
	if !containsSuggestion(suggestions, "add mock-survey@v0.0.0-example") {
		t.Fatalf("exact alias suggestions = %#v, want qualified module command", suggestions)
	}
}

func TestChainAddCompletionSurfacesModulesReadyForAutomaticInstall(t *testing.T) {
	app := newTestApp()
	enterTestOperation(t, app)
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain create exit code = %d, stderr = %s", code, stderr.String())
	}
	app.moduleInventory = []commands.ModuleInventoryRecord{{
		ID:         "cached-survey@0.1.0",
		Name:       "cached-survey",
		Type:       modulecatalog.TypeSurvey,
		Summary:    "Cached survey module",
		SourceKind: "cache",
	}}

	for _, line := range []string{"chain add ", "add "} {
		suggestions := app.Suggestions(line)
		if !containsSuggestion(suggestions, "cached-survey@0.1.0") {
			t.Fatalf("%q suggestions = %#v, want cached module", line, suggestions)
		}
		if !containsSuggestionDescription(suggestions, "available from cache") {
			t.Fatalf("%q suggestions = %#v, want cache availability", line, suggestions)
		}
		if containsSuggestionDescription(suggestions, "install first") {
			t.Fatalf("%q suggestions = %#v, should not require a separate install step", line, suggestions)
		}
	}

	if suggestions := app.Suggestions("add"); !containsSuggestion(suggestions, "add cached-survey@0.1.0") {
		t.Fatalf("exact add suggestions = %#v, want qualified cached module", suggestions)
	}
	if suggestions := app.Suggestions("module install "); !containsSuggestion(suggestions, "cached-survey@0.1.0") {
		t.Fatalf("module install suggestions = %#v, want cached module", suggestions)
	}
}

func TestChainAddRefreshesCatalogAfterAutomaticInstall(t *testing.T) {
	for _, line := range []string{
		"chain add cached-survey@0.1.0",
		"chains add cached-survey@0.1.0",
		"module install cached-survey@0.1.0",
	} {
		if !moduleCatalogMutationCommand(line) {
			t.Errorf("moduleCatalogMutationCommand(%q) = false, want refresh", line)
		}
	}
	if moduleCatalogMutationCommand("chain validate") {
		t.Fatal("chain validate should not refresh the module catalog")
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

func TestSessionCommandSuggestionsUseDaemonState(t *testing.T) {
	broker := fakeCompletionSessionBroker{
		sessions: []run.SessionRef{
			{ID: "session-closed", Kind: "agent", State: "closed", Target: "mock://old"},
			{ID: "session-1", Kind: "agent", State: "active", Target: "mock://router-01", Name: "Squatter session"},
		},
		commands: []run.PayloadCommand{
			{Name: "process.list", Summary: "list processes", ReadOnly: true},
			{Name: "process.run", Summary: "run process", Destructive: true},
		},
	}
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		ModuleRunner:   fakeCompletionModuleRunner{},
		ModuleSessions: broker,
	})
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("close daemon rpc client: %v", err)
		}
	}()
	app := newTestApp().withDaemonSession(context.Background(), client)

	for _, line := range []string{"session call ", "session capabilities "} {
		if suggestions := app.Suggestions(line); !containsSuggestion(suggestions, "session-1") {
			t.Fatalf("%q suggestions = %#v, missing session-1", line, suggestions)
		}
	}
	if suggestions := app.Suggestions("session call session-1 "); !containsSuggestion(suggestions, "process.list") {
		t.Fatalf("session call capability suggestions = %#v, missing process.list", suggestions)
	}
	if suggestions := app.Suggestions("session call latest process."); !containsSuggestion(suggestions, "process.list") {
		t.Fatalf("latest session capability suggestions = %#v, missing process.list", suggestions)
	}
	if suggestions := app.Suggestions("pki authority create root --profile "); !containsSuggestion(suggestions, "root-modern") {
		t.Fatalf("PKI profile suggestions = %#v, missing root-modern", suggestions)
	}
	if suggestions := app.Suggestions("pki authority create root --backend "); !containsSuggestion(suggestions, "builtin-x509") {
		t.Fatalf("PKI backend suggestions = %#v, missing builtin-x509", suggestions)
	}
}

func TestExecuteLineUsesCommandMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := t.TempDir()

	app := newTestApp()
	code := app.ExecuteLine(context.Background(), "control init --workspace "+workspacePath+" --json", &stdout, &stderr)
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
	if got := app.PromptPrefix(); got != "h0v3l [op:engagement]> " {
		t.Fatalf("prompt prefix = %q, want active operation", got)
	}
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := app.PromptPrefix(); got != "h0v3l [engagement/lab | steps:0 targets:0] > " {
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
	if got := app.PromptPrefix(); got != "h0v3l [test-op/lab | steps:0 targets:0] > " {
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
	if got := app.PromptPrefix(); got != "h0v3l [test-op/lab | steps:1 targets:1] config select > " {
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
	if got, want := app.PromptPrefix(), "h0v3l [test-op/lab | steps:1 targets:1] chain operator.confirmed_lab (bool) [true]: "; got != want {
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
	if got, want := app.PromptPrefix(), "h0v3l [test-op/lab | steps:1 targets:1] chain operator.confirmed_lab (bool): "; got != want {
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

func TestHuhConfigValuesUseCurrentValuesDefaultsAndChoices(t *testing.T) {
	items := []configItem{
		{
			Scope: modulecatalog.ScopeChain,
			Key:   "mode",
			Requirement: modulecatalog.Requirement{
				Key:      "mode",
				Type:     modulecatalog.ValueEnum,
				Required: true,
				Allowed:  []string{"quiet", "loud"},
			},
		},
		{
			Scope: modulecatalog.ScopeChain,
			Key:   "delay",
			Requirement: modulecatalog.Requirement{
				Key:     "delay",
				Type:    modulecatalog.ValueDuration,
				Default: "5s",
			},
		},
		{
			Scope:  modulecatalog.ScopeTarget,
			Target: "mock://router-01",
			Key:    "target.port",
			Value:  "22",
			Requirement: modulecatalog.Requirement{
				Key:  "target.port",
				Type: modulecatalog.ValuePort,
			},
		},
	}

	values := newHuhConfigValues(items)
	if len(values) != 3 {
		t.Fatalf("values = %#v, want 3", values)
	}
	if values[0].Value != "quiet" {
		t.Fatalf("enum initial value = %q, want first allowed value", values[0].Value)
	}
	if values[1].Value != "5s" {
		t.Fatalf("default initial value = %q, want 5s", values[1].Value)
	}
	if values[2].Value != "22" {
		t.Fatalf("current initial value = %q, want 22", values[2].Value)
	}
	if got := huhConfigKey(values[2].Item); got != "target:mock://router-01:target.port" {
		t.Fatalf("target key = %q", got)
	}
}

func TestInteractiveConfigSeesInstalledWorkspaceModule(t *testing.T) {
	workspace := t.TempDir()
	installRPCModulePackage(t, workspace, "installed-rpc", "exploit", emptyRPCSchema, emptyRPCSteps)

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

func TestInteractiveConfigRefreshUsesDefaultWorkspace(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)
	installRPCModulePackage(t, ".hovel", "default-rpc", "exploit", emptyRPCSchema, emptyRPCSteps)

	app := newAppWithSessionAndModules(operatorsession.New(), modulecatalog.New())
	if err := app.refreshWorkspaceModules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.modules.Find("default-rpc@0.1.0"); !ok {
		t.Fatalf("modules = %#v, want default-rpc from .hovel/module-lock.yaml", app.modules.List())
	}
}

func TestInstalledWorkspaceModulesAreInspected(t *testing.T) {
	workspace := t.TempDir()
	installRPCModulePackage(t, workspace, "configured-rpc", "exploit", `{
  "chainConfig": [{"key": "operator.confirmed_lab", "type": "bool", "required": true}],
  "targetConfig": [{"key": "target.host", "type": "host", "required": true}],
  "outputs": {}
}`, `{
  "version": "contracts-v1",
  "steps": [{"id": "collect", "kind": "action", "requires": [], "produces": []}]
}`)

	modules, err := installedWorkspaceModules(context.Background(), workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 1 {
		t.Fatalf("modules = %#v", modules)
	}
	module := modules[0]
	if len(module.ChainConfig) != 1 || module.ChainConfig[0].Key != "operator.confirmed_lab" {
		t.Fatalf("chain config = %#v", module.ChainConfig)
	}
	if len(module.TargetConfig) != 1 || module.TargetConfig[0].Key != "target.host" {
		t.Fatalf("target config = %#v", module.TargetConfig)
	}
	if module.StepContracts.Version != "contracts-v1" || len(module.StepContracts.Steps) != 1 || module.StepContracts.Steps[0].ID != "collect" {
		t.Fatalf("step contracts = %#v", module.StepContracts)
	}
}

func TestInteractiveConfigWizardUsesEffectiveValidationForSquatterBind(t *testing.T) {
	session := operatorsession.New()
	modules := modulecatalog.New(
		modulecatalog.Module{
			ID:      "ms17-010-exploit@v1.0.0",
			Name:    "ms17-010-exploit",
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
		"chain add ms17-010-exploit@v1.0.0",
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

const (
	emptyRPCSchema = `{"chainConfig": [], "targetConfig": [], "outputs": {}}`
	emptyRPCSteps  = `{"steps": []}`
)

func installRPCModulePackage(t *testing.T, workspace, name, moduleType, schemaJSON, stepsJSON string) {
	t.Helper()
	moduleRoot := writeRPCModulePackage(t, name, moduleType, schemaJSON, stepsJSON)
	if _, err := modulepackage.InstallLink(modulepackage.InstallOptions{
		Workspace: workspace,
		SourceDir: moduleRoot,
		HostOS:    "linux",
		HostArch:  "amd64",
		NoScripts: true,
	}); err != nil {
		t.Fatal(err)
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
	registry, err := commands.NewRegistry(
		commands.Definition{
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
		},
		commands.Definition{
			Path:        []string{"payloads", "call"},
			Summary:     "Call a payload.",
			Positionals: []commands.Positional{{Name: "payload", Required: true}, {Name: "capability", Required: true}},
			Options: []commands.Option{
				{Name: "workspace", Short: "w", ValueName: "path", Kind: commands.OptionString},
			},
			Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
				capturedWorkspace = invocation.Option("workspace")
				return commands.Result{Human: "ok"}, nil
			},
		},
	)
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
	if code := app.ExecuteLine(context.Background(), "payloads call p1 wininfo", &stdout, &stderr); code != 0 {
		t.Fatalf("payload call exit code = %d, stderr = %s", code, stderr.String())
	}
	if capturedWorkspace != workspacePath {
		t.Fatalf("payload workspace = %q, want %q", capturedWorkspace, workspacePath)
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "throw demo.chain --workspace explicit --now", &stdout, &stderr); code != 0 {
		t.Fatalf("throw explicit workspace exit code = %d, stderr = %s", code, stderr.String())
	}
	if capturedWorkspace != "explicit" {
		t.Fatalf("explicit workspace = %q, want explicit", capturedWorkspace)
	}
	stdout.Reset()
	stderr.Reset()

	workdir := t.TempDir()
	t.Setenv("BUILD_WORKING_DIRECTORY", workdir)
	app.workspacePath = ""
	if code := app.ExecuteLine(context.Background(), "throw demo.chain --now", &stdout, &stderr); code != 0 {
		t.Fatalf("throw default workspace exit code = %d, stderr = %s", code, stderr.String())
	}
	if want := filepath.Join(workdir, ".hovel"); capturedWorkspace != want {
		t.Fatalf("default workspace = %q, want %q", capturedWorkspace, want)
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

func containsSuggestionDescription(suggestions []prompt.Suggest, want string) bool {
	for _, suggestion := range suggestions {
		if strings.Contains(suggestion.Description, want) {
			return true
		}
	}
	return false
}

type fakeCompletionModuleRunner struct{}

func (fakeCompletionModuleRunner) Run(context.Context, run.Request) (run.Result, error) {
	return run.Result{}, errors.New("module runner is not used by completion tests")
}

type fakeCompletionSessionBroker struct {
	sessions []run.SessionRef
	commands []run.PayloadCommand
}

func (b fakeCompletionSessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	return append([]run.SessionRef(nil), b.sessions...), nil
}

func (fakeCompletionSessionBroker) WriteSession(context.Context, string, []byte) error {
	return nil
}

func (fakeCompletionSessionBroker) ReadSession(context.Context, string, time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (fakeCompletionSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (fakeCompletionSessionBroker) CloseSession(context.Context, string) error {
	return nil
}

func (b fakeCompletionSessionBroker) ListSessionCommands(context.Context, string, run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	return append([]run.PayloadCommand(nil), b.commands...), nil
}

func (fakeCompletionSessionBroker) RunSessionCommand(context.Context, string, run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, nil
}
