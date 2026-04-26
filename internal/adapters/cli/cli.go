package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	app := NewApp()
	return app.Run(ctx, args, stdout, stderr)
}

type App struct {
	workspaces services.WorkspaceService
	daemons    services.DaemonService
}

func NewApp() App {
	store := filesystem.NewWorkspaceStore()
	return App{
		workspaces: services.NewWorkspaceService(
			store,
			discardEvents{},
			randomIDs{},
			systemClock{},
		),
		daemons: services.NewDaemonService(store),
	}
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: hovel <command>")
		return 2
	}
	switch args[0] {
	case "init":
		return a.runInit(ctx, args[1:], stdout, stderr)
	case "daemon":
		return a.runDaemon(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func (a App) runInit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspacePath := flags.String("workspace", "", "workspace path")
	name := flags.String("name", "", "workspace name")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	path := *workspacePath
	if path == "" {
		path = ".hovel"
	}
	workspaceName := *name
	if workspaceName == "" {
		workspaceName = defaultWorkspaceName(path)
	}

	result, err := a.workspaces.InitWorkspace(ctx, services.InitWorkspaceRequest{
		Name: workspaceName,
		Path: path,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if *jsonOutput {
		payload := struct {
			Created   bool `json:"created"`
			Workspace struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Path string `json:"path"`
			} `json:"workspace"`
		}{Created: result.Created}
		payload.Workspace.ID = result.Workspace.ID.String()
		payload.Workspace.Name = result.Workspace.Name.String()
		payload.Workspace.Path = result.Workspace.Path
		if err := json.NewEncoder(stdout).Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}

	if result.Created {
		fmt.Fprintf(stdout, "Initialized workspace %s at %s\n", result.Workspace.Name, result.Workspace.Path)
	} else {
		fmt.Fprintf(stdout, "Workspace %s already initialized at %s\n", result.Workspace.Name, result.Workspace.Path)
	}
	return 0
}

func (a App) runDaemon(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: hovel daemon <command>")
		return 2
	}
	switch args[0] {
	case "status":
		return a.runDaemonStatus(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown daemon command %q\n", args[0])
		return 2
	}
}

func (a App) runDaemonStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspacePath := flags.String("workspace", "", "workspace path")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	status, err := a.daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: *workspacePath})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *jsonOutput {
		if err := json.NewEncoder(stdout).Encode(daemonStatusPayload(status)); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if status.State == daemon.StateNotRunning {
		fmt.Fprintf(stdout, "Daemon not running for workspace %s\n", status.WorkspacePath)
		return 0
	}
	fmt.Fprintf(stdout, "Daemon running for workspace %s pid=%d health=%s\n", status.WorkspacePath, status.Identity.PID, status.Identity.Health)
	return 0
}

func daemonStatusPayload(status daemon.Status) struct {
	State         string `json:"state"`
	WorkspacePath string `json:"workspacePath"`
	PID           int    `json:"pid,omitempty"`
	SocketPath    string `json:"socketPath,omitempty"`
	Health        string `json:"health,omitempty"`
} {
	payload := struct {
		State         string `json:"state"`
		WorkspacePath string `json:"workspacePath"`
		PID           int    `json:"pid,omitempty"`
		SocketPath    string `json:"socketPath,omitempty"`
		Health        string `json:"health,omitempty"`
	}{
		State:         string(status.State),
		WorkspacePath: status.WorkspacePath,
	}
	if status.State == daemon.StateRunning {
		payload.PID = status.Identity.PID
		payload.SocketPath = status.Identity.SocketPath
		payload.Health = string(status.Identity.Health)
	}
	return payload
}

func defaultWorkspaceName(path string) string {
	base := filepath.Base(filepath.Clean(path))
	base = strings.TrimLeft(base, ".")
	var b strings.Builder
	for _, r := range base {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type randomIDs struct{}

func (randomIDs) NewID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	return "id-" + hex.EncodeToString(bytes[:])
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
