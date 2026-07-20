package commandmode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/adapters/storage/filesystem"
	"github.com/vibepwners/hovel/internal/app/chainruntime"
	"github.com/vibepwners/hovel/internal/app/commands"
	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/app/operatorlog"
	"github.com/vibepwners/hovel/internal/domain/daemon"
	"github.com/vibepwners/hovel/internal/domain/run"
)

func TestHelpShowsCommandMenu(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"hovel command", "control", "chain", "payloads", "target", "throw"} {
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

func TestLeadingConfigOptionIsForwardedToCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"show"},
		Summary: "Show config.",
		Options: []commands.Option{
			{Name: "config", Kind: commands.OptionString},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: invocation.Option("config")}, nil
		},
	})

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"--config", "lab.yaml", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "lab.yaml" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestStringListOptionsAreForwardedToCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"collect"},
		Summary: "Collect values.",
		Options: []commands.Option{
			{Name: "arg", Kind: commands.OptionStringList},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: strings.Join(invocation.OptionList("arg"), ",")}, nil
		},
	})

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"collect", "--arg", "one", "--arg", "two"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "one,two" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestStrictOptionValidationPreservesCombinedShortFlags(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:        []string{"collect"},
		Summary:     "Collect a value.",
		Positionals: []commands.Positional{{Name: "value", Required: true}},
		Options: []commands.Option{
			{Name: "force", Short: "f", Kind: commands.OptionBool},
			{Name: "dry-run", Short: "d", Kind: commands.OptionBool},
			{Name: "workspace", Short: "w", Kind: commands.OptionString},
		},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: fmt.Sprintf("%t:%t:%s:%s", invocation.Flag("force"), invocation.Flag("dry-run"), invocation.Option("workspace"), invocation.Positional("value"))}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"collect", "-fdw", "lab", "item"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "true:true:lab:item" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestEndOfOptionsAllowsDashPrefixedPositional(t *testing.T) {
	registry := commands.MustRegistry(commands.Definition{
		Path:        []string{"send"},
		Summary:     "Send data.",
		Positionals: []commands.Positional{{Name: "data", Required: true}},
		Options:     []commands.Option{{Name: "json", Short: "j", Kind: commands.OptionBool}},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: invocation.Positional("data")}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"send", "--", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "--json" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestPassthroughArgumentsAreForwardedAfterDelimiter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"module", "manual-install"},
		Summary: "Install manual module.",
		Positionals: []commands.Positional{
			{Name: "name", Required: true},
		},
		Passthrough: commands.Passthrough{Name: "command", Required: true},
		Handler: func(_ context.Context, invocation commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: invocation.Positional("name") + ":" + strings.Join(invocation.PassthroughArgs(), "|")}, nil
		},
	})

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"module", "manual-install", "devmod", "--", "stdio-cmd", "--help", "--flag"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "devmod:stdio-cmd|--help|--flag" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestPassthroughArgumentsAreRequiredWhenDeclared(t *testing.T) {
	var stdout, stderr bytes.Buffer
	registry := commands.MustRegistry(commands.Definition{
		Path:        []string{"install"},
		Summary:     "Install.",
		Passthrough: commands.Passthrough{Name: "command", Required: true},
		Handler: func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			return commands.Result{}, nil
		},
	})

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"install"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "command after -- is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRequiredPositionalsAreRejectedBeforeHandlerExecution(t *testing.T) {
	var handlerCalls int
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"inspect"},
		Summary: "Inspect a record.",
		Positionals: []commands.Positional{
			{Name: "record", Required: true},
		},
		Handler: func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			handlerCalls++
			return commands.Result{}, nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"inspect"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if handlerCalls != 0 {
		t.Fatalf("handler calls = %d, want 0", handlerCalls)
	}
	if !strings.Contains(stderr.String(), "record is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRegisteredRequiredPositionalsRejectMissingInput(t *testing.T) {
	registry := inertRegistry(NewApp().Registry())
	app := NewAppWithRegistry(registry)
	for _, definition := range registry.Definitions() {
		paths := append([][]string{definition.Path}, definition.Aliases...)
		for _, path := range paths {
			for index, positional := range definition.Positionals {
				if !positional.Required {
					continue
				}
				path := append([]string(nil), path...)
				index := index
				for _, surface := range []struct {
					name string
					run  func([]string, *bytes.Buffer, *bytes.Buffer) int
				}{
					{
						name: "one-shot",
						run: func(args []string, stdout, stderr *bytes.Buffer) int {
							return app.Run(context.Background(), args, stdout, stderr)
						},
					},
					{
						name: "interactive",
						run: func(args []string, stdout, stderr *bytes.Buffer) int {
							return app.ExecuteLine(context.Background(), strings.Join(args, " "), stdout, stderr)
						},
					},
				} {
					t.Run(strings.Join(path, "/")+"/"+positional.Name+"/"+surface.name, func(t *testing.T) {
						args := append([]string(nil), path...)
						for previous := 0; previous < index; previous++ {
							args = append(args, "test-value")
						}
						var stdout, stderr bytes.Buffer
						code := surface.run(args, &stdout, &stderr)
						if code != 2 {
							t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
						}
						want := positional.Name + " is required"
						if !strings.Contains(stderr.String(), want) {
							t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
						}
						if strings.Contains(stderr.String(), "unknown command") {
							t.Fatalf("registered command was mislabeled as unknown:\n%s", stderr.String())
						}
						if surface.name == "interactive" && strings.Contains(stderr.String(), "hovel command") {
							t.Fatalf("interactive error leaked one-shot prefix:\n%s", stderr.String())
						}
					})
				}
			}
		}
	}
}

func TestRegisteredRequiredPassthroughRejectsMissingInputOnEverySurface(t *testing.T) {
	registry := inertRegistry(NewApp().Registry())
	app := NewAppWithRegistry(registry)
	for _, definition := range registry.Definitions() {
		if !definition.Passthrough.Required {
			continue
		}
		for _, path := range commandDefinitionPaths(definition) {
			resolved, ok := registry.Find(path...)
			if !ok {
				t.Fatalf("registry did not resolve %q", strings.Join(path, " "))
			}
			args := append([]string(nil), path...)
			for _, positional := range resolved.Positionals {
				if positional.Required {
					args = append(args, "test-value")
				}
			}
			for _, surface := range []struct {
				name string
				run  func(*bytes.Buffer, *bytes.Buffer) int
			}{
				{
					name: "one-shot",
					run: func(stdout, stderr *bytes.Buffer) int {
						return app.Run(context.Background(), args, stdout, stderr)
					},
				},
				{
					name: "interactive",
					run: func(stdout, stderr *bytes.Buffer) int {
						return app.ExecuteLine(context.Background(), strings.Join(args, " "), stdout, stderr)
					},
				},
			} {
				t.Run(strings.Join(path, "/")+"/"+surface.name, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					if code := surface.run(&stdout, &stderr); code != 2 {
						t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
					}
					want := resolved.Passthrough.Name + " after -- is required"
					if !strings.Contains(stderr.String(), want) {
						t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
					}
					if surface.name == "interactive" && strings.Contains(stderr.String(), "hovel command") {
						t.Fatalf("interactive error leaked one-shot prefix:\n%s", stderr.String())
					}
				})
			}
		}
	}
}

func TestEveryRegisteredCommandRejectsUnknownOptionsAndExtraPositionals(t *testing.T) {
	registry := inertRegistry(NewApp().Registry())
	for _, definition := range registry.Definitions() {
		paths := append([][]string{definition.Path}, definition.Aliases...)
		for _, path := range paths {
			path := append([]string(nil), path...)
			t.Run(strings.Join(path, "/")+"/unknown-option", func(t *testing.T) {
				args := append(append([]string(nil), path...), "--definitely-not-an-option")
				var stdout, stderr bytes.Buffer
				if code := NewAppWithRegistry(registry).Run(context.Background(), args, &stdout, &stderr); code != 2 {
					t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
				}
			})
			if definition.Passthrough.Name != "" {
				continue
			}
			t.Run(strings.Join(path, "/")+"/extra-positional", func(t *testing.T) {
				args := append([]string(nil), path...)
				for range definition.Positionals {
					args = append(args, "test-value")
				}
				args = append(args, "unexpected-extra-value")
				var stdout, stderr bytes.Buffer
				if code := NewAppWithRegistry(registry).Run(context.Background(), args, &stdout, &stderr); code != 2 {
					t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func inertRegistry(source commands.Registry) commands.Registry {
	definitions := source.Definitions()
	for index := range definitions {
		definitions[index].Handler = func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			return commands.Result{}, nil
		}
	}
	return commands.MustRegistry(definitions...)
}

func TestRegisteredGroupsReportSubcommandErrorsWithLocalHelp(t *testing.T) {
	app := NewApp()
	registry := app.Registry()
	groups := map[string][]string{}
	for _, definition := range registry.Definitions() {
		for _, path := range append([][]string{definition.Path}, definition.Aliases...) {
			for length := 1; length < len(path); length++ {
				prefix := append([]string(nil), path[:length]...)
				if _, leaf := registry.Find(prefix...); leaf {
					continue
				}
				groups[strings.Join(prefix, " ")] = prefix
			}
		}
	}
	for name, group := range groups {
		group := group
		t.Run(name+"/missing", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := app.Run(context.Background(), group, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "subcommand is required") || strings.Contains(stderr.String(), "unknown command") {
				t.Fatalf("stderr did not contain local missing-subcommand error:\n%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "hovel command "+name) {
				t.Fatalf("stderr missing group usage for %q:\n%s", name, stderr.String())
			}
		})
		t.Run(name+"/unknown", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string(nil), group...), "not-a-command")
			if code := app.Run(context.Background(), args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "unknown subcommand") || strings.Contains(stderr.String(), "unknown command") {
				t.Fatalf("stderr did not contain local unknown-subcommand error:\n%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "hovel command "+name) {
				t.Fatalf("stderr missing group usage for %q:\n%s", name, stderr.String())
			}
		})
	}
}

func TestResultExitCodeIsReturnedAfterPrintingReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	registry := commands.MustRegistry(commands.Definition{
		Path:    []string{"check"},
		Summary: "Check something.",
		Handler: func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			return commands.Result{Human: "check failed", ExitCode: 1}, nil
		},
	})

	code := NewAppWithRegistry(registry).Run(context.Background(), []string{"check"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if strings.TrimSpace(stdout.String()) != "check failed" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestDefaultRuntimeWiresCapabilityChainRunner(t *testing.T) {
	runtime := defaultRuntime(nil)
	if runtime.CapabilityChains == nil {
		t.Fatal("CapabilityChains is nil, want command-mode capability chain runner")
	}
	if runtime.Payloads == nil {
		t.Fatal("Payloads is nil, want command-mode installed payload repository")
	}
	if runtime.PayloadProviders == nil {
		t.Fatal("PayloadProviders is nil, want command-mode payload provider service")
	}
}

func TestPayloadProviderServiceListsProviderAdvertisedPayloads(t *testing.T) {
	modules := modulecatalog.New(modulecatalog.Module{
		ID:      "squatter@v0.1.0",
		Name:    "Squatter",
		Type:    modulecatalog.TypePayloadProvider,
		Version: "v0.1.0",
		Enabled: true,
	})
	service := payloadProviderService{
		modules: modules,
		payloads: fakePayloadMetadataLister{payloads: map[string][]run.PayloadInfo{
			"squatter@v0.1.0": {
				{
					ID:           "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
					Name:         "squatter",
					Version:      "v0.1.0",
					Kind:         "pe",
					Platform:     "windows",
					OS:           "windows",
					Arch:         "x86",
					Formats:      []string{"pe-exe"},
					Tags:         []string{"pe", "windows"},
					Capabilities: []string{"file.get", "process.exec"},
					Transport:    run.PayloadTransport{Kind: "tcp-bind"},
				},
				{
					ID:        "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
					Name:      "squatter",
					Version:   "v0.1.0",
					Platform:  "windows",
					Arch:      "x86",
					Formats:   []string{"pe-exe"},
					Transport: run.PayloadTransport{Kind: "smb-named-pipe"},
				},
			},
		}},
	}

	payloads, err := service.ListAvailablePayloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("payload count = %d, want 2: %#v", len(payloads), payloads)
	}
	if payloads[0].PayloadID != "squatter/windows/x86/windows-7/tcp-bind/pe-exe" ||
		payloads[0].Kind != "pe" ||
		payloads[0].Platform != "windows" ||
		payloads[0].OS != "windows" ||
		payloads[0].Arch != "x86" ||
		payloads[0].Transport != "tcp-bind" ||
		strings.Join(payloads[0].Formats, ",") != "pe-exe" ||
		strings.Join(payloads[0].Tags, ",") != "pe,windows" ||
		!strings.Contains(strings.Join(payloads[0].Capabilities, ","), "process.exec") {
		t.Fatalf("first payload = %#v", payloads[0])
	}
	if payloads[1].Transport != "smb-named-pipe" {
		t.Fatalf("second payload = %#v", payloads[1])
	}
}

func TestCapabilityChainExecutorRunsStepsThroughChainRuntime(t *testing.T) {
	catalog := modulecatalog.New(
		modulecatalog.Module{
			ID:      "ms17-010@v1",
			Enabled: true,
			StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
				ID: "ms17-010.exploit",
				Produces: []modulecatalog.CapabilityRequirement{{
					Type: modulecatalog.CapabilityRemoteExecution,
				}},
			}}},
		},
		modulecatalog.Module{
			ID:      "squatter@v1",
			Enabled: true,
			StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
				ID: "squatter.connect_smb",
				Requires: []modulecatalog.CapabilityRequirement{{
					Type:   modulecatalog.CapabilityRemoteExecution,
					States: []string{"active"},
				}},
				Produces: []modulecatalog.CapabilityRequirement{{
					Type: modulecatalog.CapabilitySessionRef,
				}},
			}}},
		},
	)
	runner := &fakeStepRuntimeRunner{
		execute: map[string]chainruntime.StepExecuteResult{
			"ms17-010@v1/ms17-010.exploit": {
				Status: "succeeded",
				Capabilities: []modulecatalog.Capability{{
					ID:    "remote-1",
					Type:  modulecatalog.CapabilityRemoteExecution,
					State: "active",
				}},
			},
			"squatter@v1/squatter.connect_smb": {
				Status: "succeeded",
				Capabilities: []modulecatalog.Capability{{
					ID:             "session-1",
					Type:           modulecatalog.CapabilitySessionRef,
					SchemaVersion:  "v1",
					State:          "active",
					ProducerStepID: "squatter.connect_smb",
					Attributes:     map[string]any{"transport": "smb-named-pipe"},
				}},
				Evidence: []chainruntime.Evidence{{
					ID:           "ev-1",
					Level:        "info",
					Kind:         "session",
					SourceStepID: "squatter.connect_smb",
					Message:      "session established",
				}},
			},
		},
	}
	executor := capabilityChainExecutor{catalog: catalog, runner: runner}

	result, err := executor.ExecuteCapabilityChain(context.Background(), commands.CapabilityChainRequest{
		RunID:        "run-1",
		ChainConfig:  map[string]string{"payload.transport": "smb-named-pipe"},
		TargetConfig: map[string]string{"target.host": "192.0.2.10"},
		Steps: []commands.CapabilityChainStepRef{
			{ID: "exploit", ModuleID: "ms17-010@v1", StepID: "ms17-010.exploit"},
			{ID: "connect", ModuleID: "squatter@v1", StepID: "squatter.connect_smb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Capabilities) != 2 || result.Capabilities[1].ID != "session-1" {
		t.Fatalf("capabilities = %#v, want remote and session", result.Capabilities)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].SourceStepID != "squatter.connect_smb" {
		t.Fatalf("evidence = %#v, want squatter evidence", result.Evidence)
	}
	if got := runner.prepareConfigs[0]["payload.transport"]; got != "smb-named-pipe" {
		t.Fatalf("first prepare config payload.transport = %#v", got)
	}
	if got := runner.prepareConfigs[0]["target.host"]; got != "192.0.2.10" {
		t.Fatalf("first prepare config target.host = %#v", got)
	}
}

func TestEveryRegisteredCommandAndAliasHasUsableHelpOnEverySurface(t *testing.T) {
	app := NewApp()
	registry := app.Registry()
	for _, canonical := range registry.Definitions() {
		for _, path := range commandDefinitionPaths(canonical) {
			definition, ok := registry.Find(path...)
			if !ok {
				t.Fatalf("registry did not resolve %q", strings.Join(path, " "))
			}
			for _, surface := range []struct {
				name        string
				displayName string
				run         func(*bytes.Buffer, *bytes.Buffer) int
			}{
				{
					name:        "one-shot",
					displayName: "hovel command " + strings.Join(path, " "),
					run: func(stdout, stderr *bytes.Buffer) int {
						args := append(append([]string(nil), path...), "--help")
						return app.Run(context.Background(), args, stdout, stderr)
					},
				},
				{
					name:        "interactive",
					displayName: strings.Join(path, " "),
					run: func(stdout, stderr *bytes.Buffer) int {
						return app.ExecuteLine(context.Background(), strings.Join(path, " ")+" --help", stdout, stderr)
					},
				},
			} {
				t.Run(strings.Join(path, "/")+"/"+surface.name, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					if code := surface.run(&stdout, &stderr); code != 0 {
						t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
					}
					output := stdout.String()
					if !strings.Contains(output, "usage: "+surface.displayName) {
						t.Fatalf("help output missing local usage %q:\n%s", surface.displayName, output)
					}
					if !strings.Contains(strings.Join(strings.Fields(output), " "), strings.Join(strings.Fields(definition.Summary), " ")) {
						t.Fatalf("help output missing summary %q:\n%s", definition.Summary, output)
					}
					if surface.name == "interactive" && strings.Contains(output, "hovel command") {
						t.Fatalf("interactive help leaked one-shot prefix:\n%s", output)
					}
					if strings.Contains(output, "_positionalArg") {
						t.Fatalf("help output leaked generated positional name:\n%s", output)
					}
					for _, option := range definition.Options {
						if !strings.Contains(output, "--"+option.Name) {
							t.Fatalf("help output missing option --%s:\n%s", option.Name, output)
						}
						if option.Short != "" && !strings.Contains(output, "-"+option.Short) {
							t.Fatalf("help output missing short option -%s:\n%s", option.Short, output)
						}
					}
					for _, positional := range definition.Positionals {
						placeholder := "<" + positional.Name + ">"
						if !positional.Required {
							placeholder = "[" + placeholder + "]"
						}
						if !strings.Contains(output, placeholder) {
							t.Fatalf("help output missing positional %s:\n%s", placeholder, output)
						}
					}
					if definition.Passthrough.Name != "" && !strings.Contains(output, "-- <"+definition.Passthrough.Name+">...") {
						t.Fatalf("help output missing passthrough %s:\n%s", definition.Passthrough.Name, output)
					}
				})
			}
		}
	}
}

func TestEveryRegisteredCommandAndAliasRoutesMinimalValidInputOnEverySurface(t *testing.T) {
	source := NewApp().Registry()
	definitions := source.Definitions()
	calls := make(map[string]int, len(definitions))
	for index := range definitions {
		if definitions[index].Handler == nil {
			t.Fatalf("registered command %q has no handler", definitions[index].PathString())
		}
		canonical := definitions[index].PathString()
		definitions[index].Handler = func(_ context.Context, _ commands.Invocation) (commands.Result, error) {
			calls[canonical]++
			return commands.Result{Human: "routed " + canonical}, nil
		}
	}
	app := NewAppWithRegistry(commands.MustRegistry(definitions...))
	for _, canonical := range source.Definitions() {
		for _, path := range commandDefinitionPaths(canonical) {
			definition, ok := app.Registry().Find(path...)
			if !ok {
				t.Fatalf("registry did not resolve %q", strings.Join(path, " "))
			}
			args := minimalValidCommandArgs(definition)
			for _, surface := range []struct {
				name string
				run  func(*bytes.Buffer, *bytes.Buffer) int
			}{
				{
					name: "one-shot",
					run: func(stdout, stderr *bytes.Buffer) int {
						return app.Run(context.Background(), args, stdout, stderr)
					},
				},
				{
					name: "interactive",
					run: func(stdout, stderr *bytes.Buffer) int {
						return app.ExecuteLine(context.Background(), strings.Join(args, " "), stdout, stderr)
					},
				},
			} {
				t.Run(strings.Join(path, "/")+"/"+surface.name, func(t *testing.T) {
					before := calls[canonical.PathString()]
					var stdout, stderr bytes.Buffer
					if code := surface.run(&stdout, &stderr); code != 0 {
						t.Fatalf("exit code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
					}
					if calls[canonical.PathString()] != before+1 {
						t.Fatalf("handler calls = %d, want %d", calls[canonical.PathString()], before+1)
					}
					if !strings.Contains(stdout.String(), "routed "+canonical.PathString()) {
						t.Fatalf("stdout did not contain routed command identity: %s", stdout.String())
					}
					if stderr.Len() != 0 {
						t.Fatalf("stderr = %s, want empty", stderr.String())
					}
				})
			}
		}
	}
}

func TestEveryRegisteredCommandAndAliasKeepsInteractiveErrorsLocal(t *testing.T) {
	app := NewAppWithRegistry(inertRegistry(NewApp().Registry()))
	for _, definition := range app.Registry().Definitions() {
		for _, path := range commandDefinitionPaths(definition) {
			t.Run(strings.Join(path, "/"), func(t *testing.T) {
				line := strings.Join(path, " ") + " --definitely-not-an-option"
				var stdout, stderr bytes.Buffer
				if code := app.ExecuteLine(context.Background(), line, &stdout, &stderr); code != 2 {
					t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
				}
				output := stderr.String()
				if !strings.Contains(output, "usage: "+strings.Join(path, " ")) {
					t.Fatalf("error omitted command-local usage:\n%s", output)
				}
				if !strings.Contains(output, "unknown option") {
					t.Fatalf("error omitted unknown-option diagnosis:\n%s", output)
				}
				if strings.Contains(output, "unknown command") {
					t.Fatalf("valid command was mislabeled as unknown:\n%s", output)
				}
				if strings.Contains(output, "hovel command") {
					t.Fatalf("interactive error leaked one-shot prefix:\n%s", output)
				}
			})
		}
	}
}

func commandDefinitionPaths(definition commands.Definition) [][]string {
	paths := make([][]string, 0, 1+len(definition.Aliases))
	paths = append(paths, definition.Path)
	return append(paths, definition.Aliases...)
}

func minimalValidCommandArgs(definition commands.Definition) []string {
	args := append([]string(nil), definition.Path...)
	for _, positional := range definition.Positionals {
		if positional.Required {
			args = append(args, "test-value")
		}
	}
	for _, option := range definition.Options {
		if !option.Required {
			continue
		}
		args = append(args, "--"+option.Name)
		if option.Kind != commands.OptionBool {
			args = append(args, "test-value")
		}
	}
	if definition.Passthrough.Required {
		args = append(args, "--", "test-value")
	}
	return args
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

func TestModuleInspectJSONIncludesStepAvailability(t *testing.T) {
	modules := modulecatalog.New(modulecatalog.Module{
		ID:      "squatter-provider@v1",
		Type:    modulecatalog.TypePayloadProvider,
		Version: "v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
			ID:   "squatter.connect_smb",
			Kind: "session.connector",
			Requires: []modulecatalog.CapabilityRequirement{{
				Type:       modulecatalog.CapabilityTransport,
				Attributes: map[string]any{"kind": "smb-pipe"},
				States:     []string{"active"},
			}},
		}}},
	})
	var stdout, stderr bytes.Buffer

	code := NewAppWithSessionAndModules(nil, modules).Run(context.Background(), []string{"module", "inspect", "squatter-provider", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	var payload struct {
		ID    string `json:"id"`
		Steps []struct {
			ID      string `json:"id"`
			Ready   bool   `json:"ready"`
			Missing []struct {
				Type string `json:"type"`
			} `json:"missing"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.ID != "squatter-provider@v1" || len(payload.Steps) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.Steps[0].ID != "squatter.connect_smb" || payload.Steps[0].Ready || len(payload.Steps[0].Missing) != 1 {
		t.Fatalf("step payload = %#v", payload.Steps[0])
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

func TestInstallProgressIncludesAutomaticChainInstall(t *testing.T) {
	for _, path := range [][]string{
		{"chain", "add"},
		{"chains", "add"},
		{"module", "install"},
	} {
		if !installProgressCommand(commands.Definition{Path: path}) {
			t.Errorf("installProgressCommand(%q) = false, want progress", strings.Join(path, " "))
		}
	}
	if installProgressCommand(commands.Definition{Path: []string{"chain", "validate"}}) {
		t.Fatal("chain validate should not render install progress")
	}
}

func TestDefaultRuntimeRetainsWorkspaceForAutomaticModuleInstall(t *testing.T) {
	workspace := t.TempDir()
	runtime := defaultRuntimeWithCatalogAndWorkspace(nil, modulecatalog.New(), workspace)
	if runtime.WorkspacePath != workspace {
		t.Fatalf("runtime workspace = %q, want %q", runtime.WorkspacePath, workspace)
	}
}

type fakePayloadMetadataLister struct {
	payloads map[string][]run.PayloadInfo
}

func (l fakePayloadMetadataLister) ListPayloads(_ context.Context, moduleID string, _ run.PayloadQuery) ([]run.PayloadInfo, error) {
	return append([]run.PayloadInfo(nil), l.payloads[moduleID]...), nil
}

type fakeStepRuntimeRunner struct {
	prepareConfigs []map[string]any
	execute        map[string]chainruntime.StepExecuteResult
}

func (r *fakeStepRuntimeRunner) PrepareStep(_ context.Context, req chainruntime.StepPrepareRequest) (chainruntime.StepPrepareResult, error) {
	r.prepareConfigs = append(r.prepareConfigs, req.Config)
	return chainruntime.StepPrepareResult{}, nil
}

func (r *fakeStepRuntimeRunner) ExecuteStep(_ context.Context, req chainruntime.StepExecuteRequest) (chainruntime.StepExecuteResult, error) {
	return r.execute[req.ModuleID+"/"+req.StepID], nil
}
