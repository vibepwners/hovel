package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.Out = os.Stdout
	opts.Err = os.Stderr

	if err := run(context.Background(), opts); err != nil {
		fmt.Fprintf(os.Stderr, "hovel mock agent: %v\n", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (Options, error) {
	opts := Options{
		HovelPath:   envOrDefault("HOVEL_BIN", "hovel"),
		Workspace:   envOrDefault("HOVEL_WORKSPACE", workspace.DefaultPath),
		Operation:   envOrDefault("HOVEL_DEMO_OPERATION", "demo"),
		Chain:       os.Getenv("HOVEL_DEMO_CHAIN"),
		EntityID:    "demo-mock-agent",
		DisplayName: "Mock Codex",
		Delay:       defaultFrameDelay,
		TokenDelay:  defaultTokenDelay,
		Color:       os.Getenv("NO_COLOR") == "",
		Prompt:      os.Getenv("HOVEL_DEMO_AGENT_PROMPT"),
		Scenario:    envOrDefault("HOVEL_DEMO_AGENT_SCENARIO", "throw"),
		Payload:     envOrDefault("HOVEL_DEMO_PAYLOAD", "p1"),
	}

	fs := flag.NewFlagSet("hovel-mock-agent", flag.ContinueOnError)
	fs.StringVar(&opts.HovelPath, "hovel", opts.HovelPath, "path to the hovel binary")
	fs.StringVar(&opts.Workspace, "workspace", opts.Workspace, "Hovel workspace path")
	fs.StringVar(&opts.Operation, "op", opts.Operation, "operation name")
	fs.StringVar(&opts.Operation, "operation", opts.Operation, "operation name")
	fs.StringVar(&opts.Chain, "chain", opts.Chain, "chain name")
	fs.StringVar(&opts.EntityID, "entity-id", opts.EntityID, "MCP operator entity ID")
	fs.StringVar(&opts.DisplayName, "display-name", opts.DisplayName, "MCP operator display name")
	fs.StringVar(&opts.MCPReadPath, "mcp-read", opts.MCPReadPath, "path to read MCP server JSON-RPC messages from")
	fs.StringVar(&opts.MCPWritePath, "mcp-write", opts.MCPWritePath, "path to write MCP client JSON-RPC messages to")
	fs.StringVar(&opts.Prompt, "prompt", opts.Prompt, "mock agent prompt text")
	fs.StringVar(&opts.Scenario, "scenario", opts.Scenario, "demo scenario: throw or squatter")
	fs.StringVar(&opts.Payload, "payload", opts.Payload, "installed payload handle for squatter scenario")
	fs.DurationVar(&opts.Delay, "delay", opts.Delay, "delay between transcript frames")
	fs.DurationVar(&opts.TokenDelay, "token-delay", opts.TokenDelay, "delay between simulated assistant tokens")
	noColor := fs.Bool("no-color", false, "disable ANSI color")
	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}
	if *noColor {
		opts.Color = false
	}
	if opts.Chain == "" {
		opts.Chain = "mock-survey-exploit-demo"
	}
	return opts, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
