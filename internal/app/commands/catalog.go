package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

type WorkspaceInitializer interface {
	InitWorkspace(context.Context, services.InitWorkspaceRequest) (services.InitWorkspaceResult, error)
}

type DaemonStatusProvider interface {
	Status(context.Context, services.DaemonStatusRequest) (daemon.Status, error)
}

type RunClientFactory interface {
	DialRunClient(socketPath string) (RunClient, error)
}

type RunClient interface {
	Close() error
	RunMockExploit(context.Context, RunMockExploitRequest) (RunMockExploitResponse, error)
}

type OperatorSession interface {
	CreateChain(string) error
	UseChain(string) error
	RenameChain(string, string) error
	DeleteChain(string) error
	AddTarget(string) error
	ClearTargets()
	AppendLog(...operatorlog.Entry) error
	AppendLogToChain(string, ...operatorlog.Entry) error
	ActiveLogs() []operatorlog.Entry
	Snapshot() operatorsession.State
}

type Runtime struct {
	Workspaces WorkspaceInitializer
	Daemons    DaemonStatusProvider
	Runs       RunClientFactory
	Session    OperatorSession
}

type RunMockExploitRequest struct {
	ModuleID string
	Target   string
}

type Finding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Artifact struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Data string `json:"data"`
}

type RunMockExploitResponse struct {
	RunID     string
	ModuleID  string
	Target    string
	State     string
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
}

type InitPayload struct {
	Created   bool `json:"created"`
	Workspace struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"workspace"`
}

type DaemonStatusPayload struct {
	State         string `json:"state"`
	WorkspacePath string `json:"workspacePath"`
	PID           int    `json:"pid,omitempty"`
	SocketPath    string `json:"socketPath,omitempty"`
	Health        string `json:"health,omitempty"`
}

type RunPayload struct {
	RunID     string     `json:"runId"`
	ModuleID  string     `json:"moduleId"`
	Target    string     `json:"target"`
	State     string     `json:"state"`
	Summary   string     `json:"summary"`
	Findings  []Finding  `json:"findings"`
	Artifacts []Artifact `json:"artifacts"`
}

type ThrowPayload struct {
	Chain   string       `json:"chain"`
	Targets []string     `json:"targets"`
	Results []RunPayload `json:"results"`
}

func HovelRegistry(runtime Runtime) Registry {
	return MustRegistry(
		Definition{
			Path:    []string{"control", "init"},
			Summary: "Initialize a local Hovel workspace.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("name", "n", "Workspace name"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: initHandler(runtime),
		},
		Definition{
			Path:    []string{"control", "daemon", "status"},
			Summary: "Inspect daemon status for a workspace.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: daemonStatusHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "create"},
			Summary: "Create a chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "use"},
			Summary: "Select the active chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain or module identifier", Required: true},
			},
			Handler: chainUseHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "rename"},
			Summary: "Rename a chain and keep its targets and logs.",
			Positionals: []Positional{
				{Name: "chain", Help: "Current chain name", Required: true},
				{Name: "name", Help: "New chain name", Required: true},
			},
			Handler: chainRenameHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "list"},
			Summary: "List chains in the operator session.",
			Handler: chainListHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "inspect"},
			Summary: "Inspect the active chain.",
			Handler: chainInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "delete"},
			Summary: "Delete a chain from the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainDeleteHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "logs"},
			Summary: "Show logs for the active chain.",
			Handler: chainLogsHandler(runtime),
		},
		Definition{
			Path:    []string{"targets", "add"},
			Summary: "Add a target to the operator session.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsAddHandler(runtime),
		},
		Definition{
			Path:    []string{"targets", "clear"},
			Summary: "Clear targets from the operator session.",
			Handler: targetsClearHandler(runtime),
		},
		Definition{
			Path:           []string{"throw"},
			Summary:        "Throw the selected chain at configured targets.",
			RequiresDaemon: true,
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain or module identifier"),
				stringOption("target", "t", "Target identifier"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwHandler(runtime),
		},
	)
}

func stringOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionString}
}

func boolOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionBool}
}

func initHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Workspaces == nil {
			return Result{}, fmt.Errorf("workspace service is not configured")
		}
		path := invocation.Option("workspace")
		if path == "" {
			path = ".hovel"
		}
		name := invocation.Option("name")
		if name == "" {
			name = defaultWorkspaceName(path)
		}

		result, err := runtime.Workspaces.InitWorkspace(ctx, services.InitWorkspaceRequest{
			Name: name,
			Path: path,
		})
		if err != nil {
			return Result{}, err
		}

		payload := InitPayload{Created: result.Created}
		payload.Workspace.ID = result.Workspace.ID.String()
		payload.Workspace.Name = result.Workspace.Name.String()
		payload.Workspace.Path = result.Workspace.Path

		if result.Created {
			return Result{
				Human: fmt.Sprintf("Initialized workspace %s at %s", result.Workspace.Name, result.Workspace.Path),
				JSON:  payload,
			}, nil
		}
		return Result{
			Human: fmt.Sprintf("Workspace %s already initialized at %s", result.Workspace.Name, result.Workspace.Path),
			JSON:  payload,
		}, nil
	}
}

func daemonStatusHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: invocation.Option("workspace"),
		})
		if err != nil {
			return Result{}, err
		}
		payload := daemonStatusPayload(status)
		if status.State == daemon.StateNotRunning {
			return Result{
				Human: fmt.Sprintf("Daemon not running for workspace %s", status.WorkspacePath),
				JSON:  payload,
			}, nil
		}
		return Result{
			Human: fmt.Sprintf("Daemon running for workspace %s pid=%d health=%s", status.WorkspacePath, status.Identity.PID, status.Identity.Health),
			JSON:  payload,
		}, nil
	}
}

func chainCreateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{Human: fmt.Sprintf("Chain created: %s", chain)}, nil
		}
		if err := runtime.Session.CreateChain(chain); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Chain created: %s", chain)}, nil
	}
}

func chainUseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session != nil {
			if err := runtime.Session.UseChain(chain); err != nil {
				return Result{}, err
			}
		}
		return Result{Human: fmt.Sprintf("Chain selected: %s", chain)}, nil
	}
}

func chainRenameHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		name := invocation.Positional("name")
		if runtime.Session != nil {
			if err := runtime.Session.RenameChain(chain, name); err != nil {
				return Result{}, err
			}
		}
		return Result{Human: fmt.Sprintf("Chain renamed: %s -> %s", chain, name)}, nil
	}
}

func chainListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{Human: "No chains"}, nil
		}
		state := runtime.Session.Snapshot()
		if len(state.Chains) == 0 {
			return Result{Human: "No chains"}, nil
		}
		var lines []string
		for _, chain := range state.Chains {
			prefix := " "
			if chain.Name == state.ActiveChain {
				prefix = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s targets=%d topic=%s", prefix, chain.Name, len(chain.Targets), chain.LogTopic))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func chainInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, fmt.Errorf("active chain is required")
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, fmt.Errorf("active chain is required")
		}
		return Result{Human: fmt.Sprintf("Chain %s targets=%d topic=%s", state.ActiveChain, len(state.Targets), state.LogTopic)}, nil
	}
}

func chainDeleteHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session != nil {
			if err := runtime.Session.DeleteChain(chain); err != nil {
				return Result{}, err
			}
		}
		return Result{Human: fmt.Sprintf("Chain deleted: %s", chain)}, nil
	}
}

func chainLogsHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, fmt.Errorf("active chain is required")
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, fmt.Errorf("active chain is required")
		}
		logs := runtime.Session.ActiveLogs()
		if len(logs) == 0 {
			return Result{Human: fmt.Sprintf("No logs for chain %s", state.ActiveChain)}, nil
		}
		return Result{Log: operatorlog.New("HOVEL//CHAIN", state.ActiveChain, logs)}, nil
	}
}

func targetsAddHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		target := invocation.Positional("target")
		if runtime.Session != nil {
			if err := runtime.Session.AddTarget(target); err != nil {
				return Result{}, err
			}
		}
		return Result{Human: fmt.Sprintf("Target added: %s", target)}, nil
	}
}

func targetsClearHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session != nil {
			runtime.Session.ClearTargets()
		}
		return Result{Human: "Targets cleared"}, nil
	}
}

func throwHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		if runtime.Runs == nil {
			return Result{}, fmt.Errorf("run client factory is not configured")
		}
		chain, targets, err := throwInputs(runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: invocation.Option("workspace"),
		})
		if err != nil {
			return Result{}, err
		}
		if status.State != daemon.StateRunning {
			return Result{}, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
		}

		client, err := runtime.Runs.DialRunClient(status.Identity.SocketPath)
		if err != nil {
			return Result{}, err
		}
		defer client.Close()

		var payload ThrowPayload
		payload.Chain = chain
		payload.Targets = append([]string(nil), targets...)
		for _, target := range targets {
			result, err := client.RunMockExploit(ctx, RunMockExploitRequest{
				ModuleID: chain,
				Target:   target,
			})
			if err != nil {
				return Result{}, err
			}
			payload.Results = append(payload.Results, runPayload(result))
		}
		log := throwLog(payload)
		if runtime.Session != nil {
			_ = runtime.Session.AppendLogToChain(payload.Chain, log.Entries()...)
		}
		return Result{
			Human: fmt.Sprintf("Throw completed chain %s against %d target(s)", payload.Chain, len(payload.Targets)),
			JSON:  payload,
			Log:   log,
		}, nil
	}
}

func throwInputs(runtime Runtime, invocation Invocation) (string, []string, error) {
	chain := invocation.Option("chain")
	var targets []string
	if target := invocation.Option("target"); target != "" {
		targets = append(targets, target)
	}
	if runtime.Session != nil {
		state := runtime.Session.Snapshot()
		if chain == "" {
			chain = state.Chain
		}
		if len(targets) == 0 {
			targets = append(targets, targetsForChain(state, chain)...)
		}
	}
	if strings.TrimSpace(chain) == "" {
		return "", nil, fmt.Errorf("chain is required; set one with chain use <chain> or pass --chain")
	}
	if len(targets) == 0 {
		return "", nil, fmt.Errorf("target is required; add one with targets add <target> or pass --target")
	}
	return chain, targets, nil
}

func targetsForChain(state operatorsession.State, chain string) []string {
	if chain == "" || chain == state.ActiveChain {
		return append([]string(nil), state.Targets...)
	}
	for _, candidate := range state.Chains {
		if candidate.Name == chain {
			return append([]string(nil), candidate.Targets...)
		}
	}
	return nil
}

func daemonStatusPayload(status daemon.Status) DaemonStatusPayload {
	payload := DaemonStatusPayload{
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

func runPayload(result RunMockExploitResponse) RunPayload {
	return RunPayload{
		RunID:     result.RunID,
		ModuleID:  result.ModuleID,
		Target:    result.Target,
		State:     result.State,
		Summary:   result.Summary,
		Findings:  result.Findings,
		Artifacts: result.Artifacts,
	}
}

func throwLog(payload ThrowPayload) operatorlog.Log {
	entries := []operatorlog.Entry{
		operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		),
	}
	for _, result := range payload.Results {
		entries = append(entries, operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: result.RunID},
			operatorlog.Field{Name: "target", Value: result.Target},
		))
		if result.Summary != "" {
			entries = append(entries, operatorlog.Info("module", result.Summary))
		}
		for _, finding := range result.Findings {
			entries = append(entries, operatorlog.Finding("finding", finding.Title,
				operatorlog.Field{Name: "severity", Value: finding.Severity},
				operatorlog.Field{Name: "detail", Value: finding.Detail},
			))
		}
		for _, artifact := range result.Artifacts {
			entries = append(entries, operatorlog.Artifact("artifact", artifact.Name,
				operatorlog.Field{Name: "kind", Value: artifact.Kind},
			))
		}
	}
	entries = append(entries, operatorlog.Success("throw", "completed",
		operatorlog.Field{Name: "chain", Value: payload.Chain},
		operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
	))

	return operatorlog.New(
		"HOVEL//THROW",
		payload.Chain,
		entries,
	)
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
