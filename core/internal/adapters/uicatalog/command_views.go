package uicatalog

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/adapters/clistyle"
	"github.com/Vibe-Pwners/hovel/internal/adapters/commandview"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
)

func moduleCardDemo() Demo {
	return Demo{
		Name:    "module-card",
		Summary: "module inspect panel with metadata, config, tags, and step readiness",
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			rendered, ok := commandview.New(opts.Width).Render(commands.Result{JSON: sampleModuleInspect()})
			if !ok {
				return fmt.Errorf("module-card demo was not renderable")
			}
			writeLine(out, rendered)
			return nil
		},
	}
}

func commandTableDemo() Demo {
	return Demo{
		Name:    "command-table",
		Summary: "module inventory table rendered through commandview",
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			rendered, ok := commandview.New(opts.Width).Render(commands.Result{JSON: commands.ModuleInventoryPayload{
				Modules: []commands.ModuleInventoryRecord{
					{ID: "mock-survey-go@v0.0.0-example", Name: "mock-survey-go", Version: "v0.0.0-example", Type: modulecatalog.TypeSurvey, Scope: string(modulecatalog.ScopeChain), SourceKind: "installed", Summary: "Collect host and service metadata.", Installed: true},
					{ID: "mock-exploit-session-go@v0.0.0-example", Name: "mock-exploit-session-go", Version: "v0.0.0-example", Type: modulecatalog.TypeExploit, Scope: string(modulecatalog.ScopeTarget), SourceKind: "catalog", Summary: "Open an interactive target session.", Installed: false},
					{ID: "payload-provider-go@v0.0.0-example", Name: "payload-provider-go", Version: "v0.0.0-example", Type: modulecatalog.TypePayloadProvider, Scope: string(modulecatalog.ScopeChain), SourceKind: "catalog", Summary: "Build staged payload artifacts.", Installed: false},
				},
			}})
			if !ok {
				return fmt.Errorf("command-table demo was not renderable")
			}
			writeLine(out, rendered)
			return nil
		},
	}
}

func statusPanelDemo() Demo {
	return Demo{
		Name:    "status-panel",
		Summary: "shared status badges, key-value rows, and panel styling",
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			styles := clistyle.Default()
			if !opts.Color {
				styles = clistyle.Styles{}
			}
			body := strings.Join([]string{
				styles.KeyValue([][2]string{
					{"workspace", styles.Header.Render(".hovel")},
					{"daemon", styles.Status("healthy")},
					{"modules", styles.Badge("3 installed")},
					{"session", styles.Status("connected")},
				}),
				styles.Table([]string{"COMPONENT", "STATE", "DETAIL"}, [][]string{
					{"operator log", "ready", "rail, labels, elapsed"},
					{"progress", "ready", "download and upload"},
					{"command view", "ready", "tables and panels"},
				}, opts.Width-8),
			}, "\n\n")
			writeLine(out, styles.Panel("UI CATALOG", "component status", body, opts.Width))
			return nil
		},
	}
}

func sampleModuleInspect() commands.ModuleInspectPayload {
	return commands.ModuleInspectPayload{
		ID:          "mock-exploit-session-go@v0.0.0-example",
		Name:        "mock-exploit-session-go",
		Type:        modulecatalog.TypeExploit,
		Version:     "v0.0.0-example",
		Summary:     "Open an interactive target session after survey enrichment.",
		Description: "Demonstrates the rendered module inspection card used by command output and documentation tapes.",
		Tags:        []string{"demo", "session", "operator"},
		RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
		Author:      "Hovel",
		Enabled:     true,
		ChainConfig: []modulecatalog.Requirement{
			{Key: "listener", Type: modulecatalog.ValueHost, Required: true, Description: "Callback listener hostname"},
			{Key: "transport", Type: modulecatalog.ValueEnum, Required: false, Default: "stdio", Allowed: []string{"stdio", "tcp"}, Description: "Session transport"},
		},
		TargetConfig: []modulecatalog.Requirement{
			{Key: "target", Type: modulecatalog.ValueHost, Required: true, Description: "Target host or address"},
			{Key: "port", Type: modulecatalog.ValuePort, Required: false, Default: "443", Description: "Preferred service port"},
		},
		Steps: []commands.ModuleStepPayload{
			{ID: "prepare", Kind: "survey", Ready: true},
			{ID: "launch-session", Kind: "exploit", Ready: true},
			{ID: "collect-artifacts", Kind: "artifact", Ready: false, Missing: []modulecatalog.MissingCapability{{Type: "session"}}},
		},
	}
}
