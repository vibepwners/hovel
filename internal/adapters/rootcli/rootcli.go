package rootcli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Vibe-Pwners/hovel/internal/adapters/cli"
	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
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
	case "cli", "shell":
		return cli.Run(ctx, args[1:], stdout, stderr)
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
		if commandmode.NewApp().Registry().HasRoot(args[0]) {
			return commandmode.Run(ctx, args, stdout, stderr)
		}
		fmt.Fprint(stderr, newRootParser().Usage(fmt.Sprintf("unknown command or role %q", args[0])))
		return 2
	}
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
	if ok, code := parseArgs(parser, args, stdout, stderr); !ok {
		return code
	}

	fmt.Fprintf(stdout, "serving hoveld role for workspace %s\n", displayWorkspace(*workspacePath))
	if err := daemonruntime.Serve(ctx, daemonruntime.Args{
		WorkspacePath: *workspacePath,
		SocketPath:    *socketPath,
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
	parser.NewCommand("chain", "Build and manage operator chains.")
	parser.NewCommand("modules", "Browse, search, and inspect modules.")
	parser.NewCommand("targets", "Add and configure chain targets.")
	parser.NewCommand("throw", "Execute the selected chain against targets.")
	parser.NewCommand("init", "Initialize a workspace.")
	parser.NewCommand("status", "Inspect workspace and daemon status.")
	parser.NewCommand("shell", "Launch the interactive prompt shell.")
	parser.NewCommand("command", "Run one command from the shell. Compatibility alias for direct commands.")
	parser.NewCommand("cli", "Launch the interactive prompt shell. Alias for shell.")
	daemon := parser.NewCommand("daemon", "Run or inspect the daemon role.")
	daemon.NewCommand("serve", "Run the daemon role.")
	daemon.NewCommand("status", "Inspect daemon status.")
	parser.NewCommand("tui", "Launch the terminal UI.")
	return parser
}

func newDaemonParser() *argparse.Parser {
	parser := argparse.NewParser("hovel daemon", "Run or inspect the daemon role.")
	parser.NewCommand("serve", "Run the daemon role.")
	parser.NewCommand("status", "Inspect daemon status.")
	return parser
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

func displayWorkspace(path string) string {
	if path == "" {
		return ".hovel"
	}
	return path
}
