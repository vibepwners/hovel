package rootcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/adapters/cli"
	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	mcpadapter "github.com/Vibe-Pwners/hovel/internal/adapters/mcp"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
	"github.com/akamensky/argparse"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || helpRequested(args) && (args[0] == "-h" || args[0] == "--help") {
		parser := newRootParser()
		if helpRequested(args) {
			fmt.Fprint(stdout, parser.Usage(nil))
			return 0
		}
		fmt.Fprint(stderr, parser.Usage("role is required"))
		return 2
	}
	switch args[0] {
	case "command":
		return commandmode.Run(ctx, args[1:], stdout, stderr)
	case "run":
		return runDaemonCommand(ctx, args[1:], stdout, stderr)
	case "cli", "shell":
		return cli.Run(ctx, args[1:], stdout, stderr)
	case "mcp":
		return runMCP(ctx, args[1:], stdout, stderr)
	case "daemon":
		return runDaemon(ctx, args[1:], stdout, stderr)
	case "tui":
		if len(args) > 1 && helpRequested(args[1:]) {
			fmt.Fprint(stdout, newTUIParser().Usage(nil))
			return 0
		}
		fmt.Fprintln(stderr, "hovel tui is not implemented yet")
		return 1
	case "init":
		return commandmode.Run(ctx, append([]string{"control", "init"}, args[1:]...), stdout, stderr)
	case "status":
		return commandmode.Run(ctx, append([]string{"control", "daemon", "status"}, args[1:]...), stdout, stderr)
	default:
		if args[0] == "throw" && throwFileArg(args[1:]) != "" {
			return runOneShotThrow(ctx, args, stdout, stderr)
		}
		if isDirectSessionConnectCommand(args) {
			return runDirectSessionConnect(ctx, args, stdout, stderr)
		}
		if commandmode.NewApp().Registry().HasRoot(args[0]) {
			return commandmode.Run(ctx, args, stdout, stderr)
		}
		fmt.Fprint(stderr, newRootParser().Usage(fmt.Sprintf("unknown command or role %q", args[0])))
		return 2
	}
}

func isDirectSessionConnectCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	if args[0] != "session" && args[0] != "sessions" {
		return false
	}
	if args[1] != "connect" {
		return false
	}
	return !helpRequested(args[2:])
}

func runDirectSessionConnect(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	parsed, err := cli.ParseSessionConnectCommand(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	workspacePath := parsed.Workspace
	if workspacePath == "" {
		workspacePath = ".hovel"
	}
	status, err := daemonmanager.New().Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacePath})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if status.State != daemon.StateRunning {
		fmt.Fprintf(stderr, "daemon is not running for workspace %s\n", status.WorkspacePath)
		return 1
	}
	client, err := daemonrpc.Dial(status.Identity.SocketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()
	return cli.RunSessionConnect(ctx, client, parsed.SessionID, parsed.Options, stdout, stderr)
}

func runOneShotThrow(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	session, err := daemonmanager.New().Ensure(ctx, throwWorkspaceArg(args[1:]))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer session.Close()
	return commandmode.Run(ctx, args, stdout, stderr)
}

func runDaemon(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || helpRequested(args) && (args[0] == "-h" || args[0] == "--help") {
		parser := newDaemonParser()
		if helpRequested(args) {
			fmt.Fprint(stdout, parser.Usage(nil))
			return 0
		}
		fmt.Fprint(stderr, parser.Usage("daemon command is required"))
		return 2
	}
	switch args[0] {
	case "serve":
		return runDaemonServe(ctx, args[1:], stdout, stderr)
	case "status":
		return commandmode.Run(ctx, append([]string{"control", "daemon", "status"}, args[1:]...), stdout, stderr)
	default:
		fmt.Fprint(stderr, newDaemonParser().Usage(fmt.Sprintf("unknown daemon command %q", args[0])))
		return 2
	}
}

func runDaemonServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	parser := argparse.NewParser("hovel daemon serve", "Run the daemon role in the mono-binary.")
	workspacePath := parser.String("w", "workspace", &argparse.Options{Help: "Workspace path"})
	socketPath := parser.String("s", "socket", &argparse.Options{Help: "Local RPC socket path"})
	listenAddress := parser.String("", "listen", &argparse.Options{Help: "RPC listen endpoint, such as unix:/tmp/hoveld.sock or tcp://127.0.0.1:9090"})
	moduleConfig := parser.String("", "module-config", &argparse.Options{Help: "Module launch catalog path"})
	if ok, code := parseArgs(parser, args, stdout, stderr); !ok {
		return code
	}

	fmt.Fprintf(stdout, "serving hoveld role for workspace %s\n", displayWorkspace(*workspacePath))
	if err := daemonruntime.Serve(ctx, daemonruntime.Args{
		WorkspacePath: *workspacePath,
		SocketPath:    *socketPath,
		ListenAddress: *listenAddress,
		ModuleConfig:  *moduleConfig,
	}); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func newRootParser() *argparse.Parser {
	parser := argparse.NewParser("hovel", "Hovel operator console.")
	for _, definition := range commandmode.NewApp().Registry().FirstSegments() {
		parser.NewCommand(definition.Path[0], definition.Summary)
	}
	parser.NewCommand("init", "Initialize a workspace.")
	parser.NewCommand("status", "Inspect workspace and daemon status.")
	for _, role := range []struct {
		name    string
		summary string
	}{
		{"shell", "Launch the interactive prompt shell."},
		{"command", "Run one command from the shell. Compatibility alias for direct commands."},
		{"run", "Run one command against a daemon-backed operator session."},
		{"cli", "Launch the interactive prompt shell. Alias for shell."},
		{"mcp", "Launch the MCP agent interface."},
	} {
		parser.NewCommand(role.name, role.summary)
	}
	daemon := parser.NewCommand("daemon", "Run or inspect the daemon role.")
	daemon.NewCommand("serve", "Run the daemon role.")
	daemon.NewCommand("status", "Inspect daemon status.")
	parser.NewCommand("tui", "Launch the terminal UI.")
	return parser
}

type runCommandArgs struct {
	Workspace string
	Operation string
	Chain     string
	Command   []string
}

func runDaemonCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	parsed, ok, code := parseRunCommandArgs(args, stdout, stderr)
	if !ok {
		return code
	}
	session, err := daemonmanager.New().Ensure(ctx, parsed.Workspace)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer session.Close()

	client, err := daemonrpc.Dial(session.Status().Identity.SocketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()

	operatorSession := daemonrpc.NewSessionClient(ctx, client)
	if parsed.Operation != "" {
		if err := operatorSession.UseOperation(parsed.Operation); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if parsed.Chain != "" {
		if err := operatorSession.UseChain(parsed.Chain); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	commandArgs := injectWorkspaceForDaemonCommand(normalizeRunCommand(parsed.Command), parsed.Workspace)
	app := commandmode.NewAppWithSessionAndModules(operatorSession, pythonrpc.MustConfiguredCatalog())
	return app.Run(ctx, commandArgs, stdout, stderr)
}

func parseRunCommandArgs(args []string, stdout, stderr io.Writer) (runCommandArgs, bool, int) {
	if len(args) == 0 || helpRequested(args) && (args[0] == "-h" || args[0] == "--help") {
		parser := newRunParser()
		if helpRequested(args) {
			fmt.Fprint(stdout, parser.Usage(nil))
			return runCommandArgs{}, false, 0
		}
		fmt.Fprint(stderr, parser.Usage("command is required"))
		return runCommandArgs{}, false, 2
	}
	parsed := runCommandArgs{Workspace: ".hovel"}
	for len(args) > 0 {
		arg := args[0]
		switch {
		case arg == "--":
			args = args[1:]
			parsed.Command = append([]string(nil), args...)
			return validateRunCommandArgs(parsed, stderr)
		case arg == "--workspace" || arg == "-w":
			if len(args) < 2 {
				fmt.Fprint(stderr, newRunParser().Usage(arg+" requires a value"))
				return runCommandArgs{}, false, 2
			}
			parsed.Workspace = args[1]
			args = args[2:]
		case strings.HasPrefix(arg, "--workspace="):
			parsed.Workspace = strings.TrimPrefix(arg, "--workspace=")
			args = args[1:]
		case arg == "--op" || arg == "--operation":
			if len(args) < 2 {
				fmt.Fprint(stderr, newRunParser().Usage(arg+" requires a value"))
				return runCommandArgs{}, false, 2
			}
			parsed.Operation = args[1]
			args = args[2:]
		case strings.HasPrefix(arg, "--op="):
			parsed.Operation = strings.TrimPrefix(arg, "--op=")
			args = args[1:]
		case strings.HasPrefix(arg, "--operation="):
			parsed.Operation = strings.TrimPrefix(arg, "--operation=")
			args = args[1:]
		case arg == "--chain" || arg == "-c":
			if len(args) < 2 {
				fmt.Fprint(stderr, newRunParser().Usage(arg+" requires a value"))
				return runCommandArgs{}, false, 2
			}
			parsed.Chain = args[1]
			args = args[2:]
		case strings.HasPrefix(arg, "--chain="):
			parsed.Chain = strings.TrimPrefix(arg, "--chain=")
			args = args[1:]
		case strings.HasPrefix(arg, "-"):
			fmt.Fprint(stderr, newRunParser().Usage(fmt.Sprintf("unknown run option %q", arg)))
			return runCommandArgs{}, false, 2
		default:
			parsed.Command = append([]string(nil), args...)
			return validateRunCommandArgs(parsed, stderr)
		}
	}
	return validateRunCommandArgs(parsed, stderr)
}

func validateRunCommandArgs(parsed runCommandArgs, stderr io.Writer) (runCommandArgs, bool, int) {
	if len(parsed.Command) == 0 {
		fmt.Fprint(stderr, newRunParser().Usage("command is required"))
		return runCommandArgs{}, false, 2
	}
	return parsed, true, 0
}

func newRunParser() *argparse.Parser {
	parser := argparse.NewParser("hovel run", "Run one command against a daemon-backed operator session.")
	parser.String("w", "workspace", &argparse.Options{Help: "Workspace path"})
	parser.String("", "op", &argparse.Options{Help: "Operation context to select before running the command"})
	parser.String("", "operation", &argparse.Options{Help: "Operation context to select before running the command"})
	parser.String("c", "chain", &argparse.Options{Help: "Chain context to select before running the command"})
	parser.NewCommand("<command>", "Command and arguments to run in the selected context.")
	return parser
}

func injectWorkspaceForDaemonCommand(args []string, workspace string) []string {
	if workspace == "" || hasWorkspaceArg(args) || !commandUsesWorkspace(args) {
		return append([]string(nil), args...)
	}
	out := append([]string(nil), args...)
	return append(out, "--workspace", workspace)
}

func normalizeRunCommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "add", "config", "inspect", "logs", "validate":
		out := make([]string, 0, len(args)+1)
		out = append(out, "chain")
		out = append(out, args...)
		return out
	default:
		return append([]string(nil), args...)
	}
}

func hasWorkspaceArg(args []string) bool {
	for i, arg := range args {
		if arg == "--workspace" || arg == "-w" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(arg, "--workspace=") {
			return true
		}
	}
	return false
}

func commandUsesWorkspace(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "throw", "throws", "confirm", "review", "artifact", "artifacts", "session", "sessions":
		return true
	default:
		return false
	}
}

func newDaemonParser() *argparse.Parser {
	parser := argparse.NewParser("hovel daemon", "Run or inspect the daemon role.")
	parser.NewCommand("serve", "Run the daemon role.")
	parser.NewCommand("status", "Inspect daemon status.")
	return parser
}

func runMCP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	parser := newMCPParser()
	workspacePath := parser.String("w", "workspace", &argparse.Options{Help: "Workspace path"})
	operation := parser.String("", "op", &argparse.Options{Help: "Operation context for this MCP operator"})
	operationAlias := parser.String("", "operation", &argparse.Options{Help: "Alias for --op"})
	chain := parser.String("c", "chain", &argparse.Options{Help: "Chain context for this MCP operator"})
	entityID := parser.String("", "entity-id", &argparse.Options{Help: "Stable operator entity ID for launch-key approvals"})
	displayName := parser.String("", "display-name", &argparse.Options{Help: "Human-readable operator entity name"})
	moduleConfig := parser.String("", "module-config", &argparse.Options{Help: "Module launch catalog path for MCP tools"})
	transport := parser.String("", "transport", &argparse.Options{Help: "MCP transport: stdio or http (default stdio)"})
	httpAddr := parser.String("", "http-addr", &argparse.Options{Help: "HTTP MCP listen address when --transport=http (default 127.0.0.1:0)"})
	if ok, code := parseArgs(parser, args, stdout, stderr); !ok {
		return code
	}
	selectedTransport := strings.ToLower(strings.TrimSpace(*transport))
	if selectedTransport == "" {
		selectedTransport = mcpadapter.DefaultTransportMode
	}
	if selectedTransport != "stdio" && selectedTransport != "http" {
		fmt.Fprintf(stderr, "unsupported MCP transport %q; use stdio or http\n", *transport)
		return 2
	}
	selectedOperation := *operation
	if selectedOperation == "" {
		selectedOperation = *operationAlias
	}
	if err := mcpadapter.Run(ctx, mcpadapter.Config{
		Workspace:     *workspacePath,
		Operation:     selectedOperation,
		Chain:         *chain,
		EntityID:      *entityID,
		DisplayName:   *displayName,
		CatalogPath:   *moduleConfig,
		Output:        stdout,
		Status:        stderr,
		TransportMode: selectedTransport,
		HTTPAddr:      *httpAddr,
	}); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func newMCPParser() *argparse.Parser {
	return argparse.NewParser("hovel mcp", "Launch the MCP agent interface.")
}

func newTUIParser() *argparse.Parser {
	return argparse.NewParser("hovel tui", "Launch the terminal UI. This role is not implemented yet.")
}

func parseArgs(parser *argparse.Parser, args []string, stdout, stderr io.Writer) (bool, int) {
	parser.ExitOnHelp(false)
	if helpRequested(args) {
		fmt.Fprint(stdout, parser.Usage(nil))
		return false, 0
	}
	if err := parser.Parse(append([]string{"hovel"}, args...)); err != nil {
		fmt.Fprint(stderr, parser.Usage(err))
		return false, 2
	}
	return true, 0
}

func helpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func throwFileArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "list" || arg == "inspect":
			return ""
		case arg == "--workspace" || arg == "-w" || arg == "--chain" || arg == "-c" || arg == "--target" || arg == "-t":
			i++
		case strings.HasPrefix(arg, "--workspace=") || strings.HasPrefix(arg, "--chain=") || strings.HasPrefix(arg, "--target="):
		case strings.HasPrefix(arg, "-"):
		default:
			return arg
		}
	}
	return ""
}

func throwWorkspaceArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--workspace" || arg == "-w":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--workspace="):
			return strings.TrimPrefix(arg, "--workspace=")
		}
	}
	return ".hovel"
}

func displayWorkspace(path string) string {
	if path == "" {
		return ".hovel"
	}
	return path
}
