package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("hoveld", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspacePath := flags.String("workspace", "", "workspace path")
	socketPath := flags.String("socket", "", "socket path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	fmt.Fprintf(stdout, "starting hoveld for workspace %s\n", displayWorkspace(*workspacePath))
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

func displayWorkspace(path string) string {
	if path == "" {
		return ".hovel"
	}
	return path
}
