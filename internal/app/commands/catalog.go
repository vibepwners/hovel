package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
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

type ThrowPlanRecorder interface {
	RecordThrowPlan(context.Context, ThrowPlanRecord) error
}

type OperatorSession interface {
	CreateChain(string) error
	UseChain(string) error
	RenameChain(string, string) error
	DeleteChain(string) error
	AddModule(string) (operatorsession.Step, error)
	AddTarget(string) error
	ClearTargets()
	SetChainConfig(string, string) error
	UnsetChainConfig(string) error
	SetTargetConfig(string, string, string) error
	UnsetTargetConfig(string, string) error
	AppendLog(...operatorlog.Entry) error
	AppendLogToChain(string, ...operatorlog.Entry) error
	ActiveLogs() []operatorlog.Entry
	Snapshot() operatorsession.State
}

type publishedFeedbackSession interface {
	RemoteFeedback() bool
}

type Runtime struct {
	Workspaces WorkspaceInitializer
	Daemons    DaemonStatusProvider
	Runs       RunClientFactory
	Plans      ThrowPlanRecorder
	Session    OperatorSession
	Modules    ModuleDatabase
}

type ModuleDatabase interface {
	List() []modulecatalog.Module
	ByType(modulecatalog.ModuleType) []modulecatalog.Module
	Search(string) []modulecatalog.Module
	Find(string) (modulecatalog.Module, bool)
	Validate(modulecatalog.ConfigView) modulecatalog.Validation
}

type RunMockExploitRequest struct {
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted string
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

type LogEntry struct {
	ID             string            `json:"id,omitempty"`
	Time           string            `json:"time,omitempty"`
	Topic          string            `json:"topic,omitempty"`
	Kind           string            `json:"kind,omitempty"`
	Level          string            `json:"level"`
	Source         string            `json:"source,omitempty"`
	Message        string            `json:"message"`
	Logger         string            `json:"logger,omitempty"`
	ChainID        string            `json:"chainId,omitempty"`
	ChainName      string            `json:"chainName,omitempty"`
	RunID          string            `json:"runId,omitempty"`
	Target         string            `json:"target,omitempty"`
	ModuleID       string            `json:"moduleId,omitempty"`
	ElapsedSeconds *float64          `json:"elapsedSeconds,omitempty"`
	Fields         map[string]string `json:"fields,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

type RunMockExploitResponse struct {
	RunID     string
	ModuleID  string
	Target    string
	State     string
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
	Logs      []LogEntry
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
	Logs      []LogEntry `json:"logs"`
}

type ThrowPayload struct {
	Plan    ThrowPlanPayload `json:"plan"`
	Chain   string           `json:"chain"`
	Targets []string         `json:"targets"`
	Results []RunPayload     `json:"results"`
}

type ThrowPlanPayload struct {
	ID         string   `json:"id"`
	ApprovalID string   `json:"approvalId"`
	Chain      string   `json:"chain"`
	Targets    []string `json:"targets"`
	Decision   string   `json:"decision"`
}

type ThrowPlanRecord struct {
	ID         string   `json:"id"`
	ApprovalID string   `json:"approvalId"`
	Workspace  string   `json:"workspace"`
	Chain      string   `json:"chain"`
	Targets    []string `json:"targets"`
	Decision   string   `json:"decision"`
	Intent     string   `json:"intent"`
}

func (r ThrowPlanRecord) Payload() ThrowPlanPayload {
	return ThrowPlanPayload{
		ID:         r.ID,
		ApprovalID: r.ApprovalID,
		Chain:      r.Chain,
		Targets:    append([]string(nil), r.Targets...),
		Decision:   r.Decision,
	}
}

type ValidationPayload struct {
	Valid  bool                  `json:"valid"`
	Issues []modulecatalog.Issue `json:"issues"`
}

func HovelRegistry(runtime Runtime) Registry {
	return MustRegistry(withCommonOptions(
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
			Path:    []string{"chain", "add"},
			Summary: "Add a module to the active chain.",
			Positionals: []Positional{
				{Name: "module", Help: "Module ID", Required: true},
			},
			Handler: chainAddHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "validate"},
			Summary: "Validate active chain configuration.",
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainValidateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "set"},
			Summary: "Set active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: chainConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "unset"},
			Summary: "Unset active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: chainConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "list"},
			Summary: "List active chain configuration.",
			Handler: chainConfigListHandler(runtime),
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
			Path:    []string{"targets", "config", "set"},
			Summary: "Set target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: targetsConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"targets", "config", "unset"},
			Summary: "Unset target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: targetsConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"targets", "config", "list"},
			Summary: "List target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsConfigListHandler(runtime),
		},
		Definition{
			Path:    []string{"modules", "list"},
			Summary: "List modules in the module database.",
			Options: []Option{
				stringOption("type", "t", "Module type filter"),
			},
			Handler: modulesListHandler(runtime),
		},
		Definition{
			Path:    []string{"modules", "inspect"},
			Summary: "Inspect a module in the module database.",
			Positionals: []Positional{
				{Name: "module", Help: "Module reference", Required: true},
			},
			Handler: modulesInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"modules", "search"},
			Summary: "Search modules in the module database.",
			Positionals: []Positional{
				{Name: "query", Help: "Search query", Required: true},
			},
			Handler: modulesSearchHandler(runtime),
		},
		Definition{
			Path:           []string{"throw"},
			Summary:        "Throw the selected chain at configured targets.",
			RequiresDaemon: true,
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwHandler(runtime),
		},
	)...)
}

func stringOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionString}
}

func boolOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionBool}
}

func withCommonOptions(definitions ...Definition) []Definition {
	common := []Option{
		boolOption("no-color", "", "Disable styled terminal output"),
		boolOption("verbose", "v", "Emit verbose output"),
		boolOption("debug", "", "Emit debug output"),
	}
	out := make([]Definition, 0, len(definitions))
	for _, definition := range definitions {
		for _, option := range common {
			if !definitionHasOption(definition, option.Name) {
				definition.Options = append(definition.Options, option)
			}
		}
		out = append(out, definition)
	}
	return out
}

func definitionHasOption(definition Definition, name string) bool {
	for _, option := range definition.Options {
		if option.Name == name {
			return true
		}
	}
	return false
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
			return Result{}, operatorSessionRequiredError("chain create")
		}
		if err := runtime.Session.CreateChain(chain); err != nil {
			return Result{}, err
		}
		if err := runtime.Session.UseChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain created and selected: %s", chain)}, nil
	}
}

func chainUseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain use")
		}
		if err := runtime.Session.UseChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
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
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain rename")
		}
		if err := runtime.Session.RenameChain(chain, name); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain renamed: %s -> %s", chain, name)}, nil
	}
}

func chainAddHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		moduleID := invocation.Positional("module")
		module, ok := moduleDB(runtime).Find(moduleID)
		if !ok {
			return Result{}, fmt.Errorf("module %s does not exist", moduleID)
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain add")
		}
		step, err := runtime.Session.AddModule(module.ID)
		if err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Module added: %s as %s", module.ID, step.ID)}, nil
	}
}

func chainValidateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		_ = runtime.Session.AppendLog(operatorlog.Info("validate", "validation started"))
		validation := moduleDB(runtime).Validate(validationView(state))
		payload := ValidationPayload{Valid: validation.Valid, Issues: validation.Issues}
		if validation.Valid {
			_ = runtime.Session.AppendLog(operatorlog.Success("validate", "validation completed"))
			return Result{
				Human: fmt.Sprintf("Chain %s valid", state.ActiveChain),
				JSON:  payload,
			}, nil
		}
		var lines []string
		lines = append(lines, fmt.Sprintf("Chain %s invalid", state.ActiveChain))
		logEntries := []operatorlog.Entry{operatorlog.Finding("validate", "validation failed")}
		for _, issue := range validation.Issues {
			lines = append(lines, "[!] "+issue.Message)
			logEntries = append(logEntries, operatorlog.Finding("validate", issue.Message,
				operatorlog.Field{Name: "scope", Value: string(issue.Scope)},
				operatorlog.Field{Name: "module", Value: issue.ModuleID},
				operatorlog.Field{Name: "target", Value: issue.Target},
				operatorlog.Field{Name: "key", Value: issue.Key},
			))
		}
		_ = runtime.Session.AppendLog(logEntries...)
		return Result{
			Human: strings.Join(lines, "\n"),
			JSON:  payload,
		}, nil
	}
}

func chainConfigSetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		key := invocation.Positional("key")
		value := invocation.Positional("value")
		if err := runtime.Session.SetChainConfig(key, value); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain config set: %s", key)}, nil
	}
}

func chainConfigUnsetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		key := invocation.Positional("key")
		if err := runtime.Session.UnsetChainConfig(key); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain config unset: %s", key)}, nil
	}
}

func chainConfigListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		if len(state.Config) == 0 {
			return Result{Human: "No chain config set\n\nNext: config interactive"}, nil
		}
		requirements := requirementsByKey(moduleDB(runtime), state, modulecatalog.ScopeChain)
		return Result{Human: "Chain config\n" + configLines(state.Config, requirements)}, nil
	}
}

func chainListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain list")
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
			lines = append(lines, fmt.Sprintf("%s %s steps=%d targets=%d topic=%s", prefix, chain.Name, len(chain.Steps), len(chain.Targets), chain.LogTopic))
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
			return Result{}, activeChainRequiredError()
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, activeChainRequiredError()
		}
		return Result{Human: chainInspect(state)}, nil
	}
}

func chainDeleteHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain delete")
		}
		if err := runtime.Session.DeleteChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
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
			return Result{}, activeChainRequiredError()
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, activeChainRequiredError()
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
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("targets add")
		}
		if err := runtime.Session.AddTarget(target); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target added: %s", target)}, nil
	}
}

func targetsClearHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("targets clear")
		}
		runtime.Session.ClearTargets()
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: "Targets cleared"}, nil
	}
}

func targetsConfigSetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		target := invocation.Positional("target")
		key := invocation.Positional("key")
		value := invocation.Positional("value")
		if err := runtime.Session.SetTargetConfig(target, key, value); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target config set: %s %s", target, key)}, nil
	}
}

func targetsConfigUnsetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		target := invocation.Positional("target")
		key := invocation.Positional("key")
		if err := runtime.Session.UnsetTargetConfig(target, key); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target config unset: %s %s", target, key)}, nil
	}
}

func targetsConfigListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		target := invocation.Positional("target")
		config, ok := state.TargetConfigs[target]
		if !ok || len(config) == 0 {
			return Result{Human: fmt.Sprintf("No target config for %s\n\nNext: targets config set %s <key> <value>", target, target)}, nil
		}
		requirements := requirementsByKey(moduleDB(runtime), state, modulecatalog.ScopeTarget)
		return Result{Human: fmt.Sprintf("Target config %s\n%s", target, configLines(config, requirements))}, nil
	}
}

func modulesListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		db := moduleDB(runtime)
		var modules []modulecatalog.Module
		if moduleType := invocation.Option("type"); moduleType != "" {
			modules = db.ByType(modulecatalog.ModuleType(moduleType))
		} else {
			modules = db.List()
		}
		if len(modules) == 0 {
			return Result{Human: "No modules"}, nil
		}
		return Result{Human: moduleLines(modules)}, nil
	}
}

func modulesInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		moduleID := invocation.Positional("module")
		module, ok := moduleDB(runtime).Find(moduleID)
		if !ok {
			return Result{}, fmt.Errorf("module %s does not exist", moduleID)
		}
		return Result{Human: moduleInspect(module)}, nil
	}
}

func modulesSearchHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		modules := moduleDB(runtime).Search(invocation.Positional("query"))
		if len(modules) == 0 {
			return Result{Human: "No modules"}, nil
		}
		return Result{Human: moduleLines(modules)}, nil
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
		throw, err := throwInputs(runtime, invocation)
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

		plan := newThrowPlan(status.WorkspacePath, throw.Chain, throw.Targets)
		if runtime.Plans != nil {
			if err := runtime.Plans.RecordThrowPlan(ctx, plan); err != nil {
				return Result{}, err
			}
		}

		client, err := runtime.Runs.DialRunClient(status.Identity.SocketPath)
		if err != nil {
			return Result{}, err
		}
		defer client.Close()

		throwStarted := time.Now()
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			_ = runtime.Session.AppendLogToChain(throw.Chain, throwHeader(throw.Chain))
		}
		var payload ThrowPayload
		payload.Plan = plan.Payload()
		payload.Chain = throw.Chain
		payload.Targets = append([]string(nil), throw.Targets...)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			_ = runtime.Session.AppendLogToChain(throw.Chain, throwPlanEntries(payload, throwStarted)...)
		}
		for _, target := range throw.Targets {
			for _, moduleID := range throw.Modules {
				runIndex := len(payload.Results) + 1
				if runtime.Session != nil && feedbackPublished(runtime.Session) {
					_ = runtime.Session.AppendLogToChain(throw.Chain, throwRunStartEntries(throw.Chain, target, moduleID, runIndex, len(throw.Targets)*len(throw.Modules), throwStarted)...)
				}
				result, err := client.RunMockExploit(ctx, RunMockExploitRequest{
					ModuleID:     moduleID,
					Target:       target,
					ChainConfig:  throw.ChainConfig,
					TargetConfig: throw.TargetConfigs[target],
					ThrowStarted: throwStarted.Format(time.RFC3339Nano),
				})
				if err != nil {
					return Result{}, err
				}
				payload.Results = append(payload.Results, runPayload(result))
				if runtime.Session != nil && feedbackPublished(runtime.Session) {
					_ = runtime.Session.AppendLogToChain(throw.Chain, throwRunResultEntries(payload, payload.Results[len(payload.Results)-1], runIndex, len(throw.Targets)*len(throw.Modules), throwStarted)...)
				}
			}
		}
		log := throwLog(payload, throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			_ = runtime.Session.AppendLogToChain(payload.Chain, throwCompleteEntries(payload, throwStarted)...)
			return Result{JSON: payload}, nil
		}
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

func newThrowPlan(workspacePath, chain string, targets []string) ThrowPlanRecord {
	id := "plan-" + stablePlanComponent(chain, targets)
	return ThrowPlanRecord{
		ID:         id,
		ApprovalID: "approval-" + stablePlanComponent(chain, targets),
		Workspace:  workspacePath,
		Chain:      chain,
		Targets:    append([]string(nil), targets...),
		Decision:   "operator-reviewed",
		Intent:     fmt.Sprintf("throw chain %s against %d target(s)", chain, len(targets)),
	}
}

func stablePlanComponent(chain string, targets []string) string {
	var b strings.Builder
	b.WriteString(chain)
	for _, target := range targets {
		b.WriteString("-")
		b.WriteString(target)
	}
	out := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			return r
		default:
			return '-'
		}
	}, b.String())
	out = strings.Trim(out, "-")
	if out == "" {
		return "throw"
	}
	return out
}

type throwExecution struct {
	Chain         string
	Targets       []string
	Modules       []string
	ChainConfig   map[string]string
	TargetConfigs map[string]map[string]string
}

func throwInputs(runtime Runtime, invocation Invocation) (throwExecution, error) {
	chain := invocation.Option("chain")
	var targets []string
	if target := invocation.Option("target"); target != "" {
		targets = append(targets, target)
	}
	chainConfig := map[string]string{}
	targetConfigs := map[string]map[string]string{}
	var modules []string
	if runtime.Session != nil {
		state := runtime.Session.Snapshot()
		if chain == "" {
			chain = state.Chain
		}
		selected, ok := selectedChainState(state, chain)
		if !ok {
			return throwExecution{}, fmt.Errorf("chain %s does not exist", chain)
		}
		for _, step := range selected.Steps {
			modules = append(modules, step.ModuleID)
		}
		chainConfig = cloneStringMap(selected.Config)
		targetConfigs = cloneTargetConfigs(selected.TargetConfigs)
		if len(targets) == 0 {
			targets = append(targets, targetsForChain(state, chain)...)
		}
	}
	if strings.TrimSpace(chain) == "" {
		return throwExecution{}, fmt.Errorf("chain is required; set one with chain use <chain> or pass --chain")
	}
	if len(targets) == 0 {
		return throwExecution{}, fmt.Errorf("target is required; add one with targets add <target> or pass --target")
	}
	if len(modules) == 0 {
		if runtime.Session != nil {
			return throwExecution{}, fmt.Errorf("chain %s has no modules; add one with chain add <module>", chain)
		}
		moduleRef := chain
		if module, ok := moduleDB(runtime).Find(chain); ok {
			moduleRef = module.ID
		}
		modules = append(modules, moduleRef)
	}
	return throwExecution{
		Chain:         chain,
		Targets:       targets,
		Modules:       modules,
		ChainConfig:   chainConfig,
		TargetConfigs: targetConfigs,
	}, nil
}

func selectedChainState(state operatorsession.State, chain string) (operatorsession.Chain, bool) {
	if chain == "" || chain == state.ActiveChain {
		return operatorsession.Chain{
			Name:          state.Chain,
			Targets:       append([]string(nil), state.Targets...),
			Steps:         append([]operatorsession.Step(nil), state.Steps...),
			Config:        cloneStringMap(state.Config),
			TargetConfigs: cloneTargetConfigs(state.TargetConfigs),
			LogTopic:      state.LogTopic,
		}, true
	}
	for _, candidate := range state.Chains {
		if candidate.Name == chain {
			return candidate, true
		}
	}
	return operatorsession.Chain{}, false
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

func activeState(runtime Runtime) (operatorsession.State, error) {
	if runtime.Session == nil {
		return operatorsession.State{}, activeChainRequiredError()
	}
	state := runtime.Session.Snapshot()
	if state.ActiveChain == "" {
		return operatorsession.State{}, activeChainRequiredError()
	}
	return state, nil
}

func feedbackPublished(session OperatorSession) bool {
	publisher, ok := session.(publishedFeedbackSession)
	return ok && publisher.RemoteFeedback()
}

func activeChainRequiredError() error {
	return fmt.Errorf("active chain is required\n\nStart with:\n  chain create <name>\n  chain use <name>")
}

func operatorSessionRequiredError(command string) error {
	return fmt.Errorf("%s needs an operator session\n\nUse the interactive shell:\n  hovel shell\n\nOr keep using one-shot commands that do not depend on selected chain state, such as:\n  hovel modules list\n  hovel throw --chain <chain> --target <target>", command)
}

func withActiveChainHelp(err error) error {
	if err != nil && strings.Contains(err.Error(), "active chain is required") {
		return activeChainRequiredError()
	}
	return err
}

func moduleDB(runtime Runtime) ModuleDatabase {
	if runtime.Modules != nil {
		return runtime.Modules
	}
	return modulecatalog.BuiltIns()
}

func validationView(state operatorsession.State) modulecatalog.ConfigView {
	steps := make([]modulecatalog.StepRef, 0, len(state.Steps))
	for _, step := range state.Steps {
		steps = append(steps, modulecatalog.StepRef{ID: step.ID, ModuleID: step.ModuleID})
	}
	return modulecatalog.ConfigView{
		Steps:         steps,
		Targets:       append([]string(nil), state.Targets...),
		ChainConfig:   cloneStringMap(state.Config),
		TargetConfigs: cloneTargetConfigs(state.TargetConfigs),
	}
}

func requirementsByKey(db ModuleDatabase, state operatorsession.State, scope modulecatalog.Scope) map[string]modulecatalog.Requirement {
	requirements := map[string]modulecatalog.Requirement{}
	for _, step := range state.Steps {
		module, ok := db.Find(step.ModuleID)
		if !ok {
			continue
		}
		var scoped []modulecatalog.Requirement
		if scope == modulecatalog.ScopeTarget {
			scoped = module.TargetConfig
		} else {
			scoped = module.ChainConfig
		}
		for _, requirement := range scoped {
			requirements[requirement.Key] = requirement
		}
	}
	return requirements
}

func configLines(config map[string]string, requirements map[string]modulecatalog.Requirement) string {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		requirement := requirements[key]
		value := modulecatalog.DisplayValue(requirement, config[key])
		typeName := string(requirement.Type)
		if typeName == "" {
			typeName = "string"
		}
		lines = append(lines, fmt.Sprintf("  %-28s %-18s %s", key, typeName, value))
	}
	return strings.Join(lines, "\n")
}

func moduleLines(modules []modulecatalog.Module) string {
	lines := []string{
		"ID                         TYPE              SUMMARY",
		"--                         ----              -------",
	}
	for _, module := range modules {
		lines = append(lines, fmt.Sprintf("%-26s %-17s %s", module.ID, module.Type, module.Summary))
	}
	return strings.Join(lines, "\n")
}

func moduleInspect(module modulecatalog.Module) string {
	lines := []string{
		fmt.Sprintf("%s %s", module.ID, module.Type),
		"",
		module.Summary,
	}
	if module.Description != "" {
		lines = append(lines, module.Description)
	}
	lines = append(lines,
		"",
		fmt.Sprintf("version      %s", module.Version),
		fmt.Sprintf("runtime      %s", module.RuntimeKind),
		fmt.Sprintf("author       %s", module.Author),
		fmt.Sprintf("enabled      %t", module.Enabled),
	)
	if len(module.Tags) > 0 {
		lines = append(lines, "tags         "+strings.Join(module.Tags, ", "))
	}
	if len(module.ChainConfig) > 0 {
		lines = append(lines, "", "chain config")
		for _, requirement := range module.ChainConfig {
			lines = append(lines, requirementLine(requirement))
		}
	}
	if len(module.TargetConfig) > 0 {
		lines = append(lines, "", "target config")
		for _, requirement := range module.TargetConfig {
			lines = append(lines, requirementLine(requirement))
		}
	}
	lines = append(lines, "", "Next: chain add "+module.ID)
	return strings.Join(lines, "\n")
}

func requirementLine(requirement modulecatalog.Requirement) string {
	required := "optional"
	if requirement.Required {
		required = "required"
	}
	typeName := string(requirement.Type)
	if typeName == "" {
		typeName = "string"
	}
	line := fmt.Sprintf("  %-28s %-18s %s", requirement.Key, typeName, required)
	if len(requirement.Allowed) > 0 {
		line += " [" + strings.Join(requirement.Allowed, ", ") + "]"
	}
	if requirement.Description != "" {
		line += "  " + requirement.Description
	}
	return line
}

func chainInspect(state operatorsession.State) string {
	lines := []string{
		fmt.Sprintf("Chain %s steps=%d targets=%d config=%d topic=%s", state.ActiveChain, len(state.Steps), len(state.Targets), len(state.Config), state.LogTopic),
		"",
		"steps",
	}
	if len(state.Steps) == 0 {
		lines = append(lines, "  none")
	} else {
		for _, step := range state.Steps {
			lines = append(lines, fmt.Sprintf("  %-10s %s", step.ID, step.ModuleID))
		}
	}
	lines = append(lines, "", "targets")
	if len(state.Targets) == 0 {
		lines = append(lines, "  none")
	} else {
		for _, target := range state.Targets {
			lines = append(lines, "  "+target)
		}
	}
	lines = append(lines, "", "Next: add <module>, targets add <target>, config interactive, validate, throw")
	return strings.Join(lines, "\n")
}

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		out[target] = cloneStringMap(config)
	}
	return out
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
		Logs:      result.Logs,
	}
}

func throwHeader(chain string) operatorlog.Entry {
	return operatorlog.Entry{
		Kind:      operatorlog.KindHeader,
		Level:     operatorlog.LevelInfo,
		Message:   "HOVEL//THROW",
		ChainName: chain,
	}
}

func throwPlanEntries(payload ThrowPayload, started time.Time) []operatorlog.Entry {
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("0/5 review plan",
			operatorlog.Field{Name: "plan", Value: payload.Plan.ID},
			operatorlog.Field{Name: "approval", Value: payload.Plan.ApprovalID},
			operatorlog.Field{Name: "decision", Value: payload.Plan.Decision},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Stage("1/5 prepare chain",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
	}
}

func throwRunStartEntries(chain, target, moduleID string, runIndex, runCount int, started time.Time) []operatorlog.Entry {
	at := time.Now()
	targetStep := fmt.Sprintf("%d/%d", runIndex, runCount)
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("2/5 engage target",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "address", Value: target},
		).WithTarget(target), at, started, chain),
		elapsedAt(operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: "pending"},
			operatorlog.Field{Name: "target", Value: target},
		).WithTarget(target), at, started, chain),
		elapsedAt(operatorlog.Stage("3/5 execute module",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "module", Value: moduleID},
		).WithTarget(target).WithModule(moduleID), at, started, chain),
	}
}

func throwRunResultEntries(payload ThrowPayload, result RunPayload, runIndex, runCount int, started time.Time) []operatorlog.Entry {
	at := lastLogTime(result.Logs, time.Now())
	targetStep := fmt.Sprintf("%d/%d", runIndex, runCount)
	entries := []operatorlog.Entry{
		elapsedAt(operatorlog.Info("module", result.Summary).
			WithTarget(result.Target).
			WithRun(result.RunID).
			WithModule(result.ModuleID), at, started, payload.Chain),
		elapsedAt(operatorlog.Stage("4/5 record result",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "run", Value: result.RunID},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain),
	}
	for _, finding := range result.Findings {
		entries = append(entries, elapsedAt(operatorlog.Finding("finding", finding.Title,
			operatorlog.Field{Name: "severity", Value: finding.Severity},
			operatorlog.Field{Name: "detail", Value: finding.Detail},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain))
	}
	for _, artifact := range result.Artifacts {
		entries = append(entries, elapsedAt(operatorlog.Artifact("artifact", artifact.Name,
			operatorlog.Field{Name: "kind", Value: artifact.Kind},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain))
	}
	return entries
}

func throwCompleteEntries(payload ThrowPayload, started time.Time) []operatorlog.Entry {
	at := time.Now()
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("5/5 complete throw",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), at, started, payload.Chain),
		elapsedAt(operatorlog.Success("throw", "completed",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), at, started, payload.Chain),
	}
}

func throwLog(payload ThrowPayload, started time.Time) operatorlog.Log {
	elapsed := func(entry operatorlog.Entry) operatorlog.Entry {
		return elapsedAt(entry, time.Now(), started, payload.Chain)
	}
	elapsedAtLogTime := func(entry operatorlog.Entry, log LogEntry) operatorlog.Entry {
		at, err := time.Parse(time.RFC3339Nano, log.Time)
		if err != nil || at.IsZero() {
			at = time.Now()
		}
		return elapsedAt(entry, at, started, payload.Chain)
	}
	entries := []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("0/5 review plan",
			operatorlog.Field{Name: "plan", Value: payload.Plan.ID},
			operatorlog.Field{Name: "approval", Value: payload.Plan.ApprovalID},
			operatorlog.Field{Name: "decision", Value: payload.Plan.Decision},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Stage("1/5 prepare chain",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
	}
	for index, result := range payload.Results {
		targetStep := fmt.Sprintf("%d/%d", index+1, len(payload.Results))
		resultStarted := firstLogTime(result.Logs, started)
		resultFinished := lastLogTime(result.Logs, time.Now())
		entries = append(entries, elapsedAt(operatorlog.Stage("2/5 engage target",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "address", Value: result.Target},
		).WithTarget(result.Target).WithRun(result.RunID), resultStarted, started, payload.Chain))
		entries = append(entries, elapsedAt(operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: result.RunID},
			operatorlog.Field{Name: "target", Value: result.Target},
		).WithTarget(result.Target).WithRun(result.RunID), resultStarted, started, payload.Chain))
		entries = append(entries, elapsedAt(operatorlog.Stage("3/5 execute module",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "module", Value: result.ModuleID},
		).WithTarget(result.Target).WithRun(result.RunID).WithModule(result.ModuleID), resultStarted, started, payload.Chain))
		for _, log := range result.Logs {
			entries = append(entries, elapsedAtLogTime(operatorlog.Info("module", log.Message, logFields(log)...).
				WithTarget(result.Target).
				WithRun(result.RunID).
				WithModule(result.ModuleID), log))
		}
		if result.Summary != "" {
			entries = append(entries, elapsedAt(operatorlog.Info("module", result.Summary).
				WithTarget(result.Target).
				WithRun(result.RunID).
				WithModule(result.ModuleID), resultFinished, started, payload.Chain))
		}
		entries = append(entries, elapsedAt(operatorlog.Stage("4/5 record result",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "run", Value: result.RunID},
		).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		for _, finding := range result.Findings {
			entries = append(entries, elapsedAt(operatorlog.Finding("finding", finding.Title,
				operatorlog.Field{Name: "severity", Value: finding.Severity},
				operatorlog.Field{Name: "detail", Value: finding.Detail},
			).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		}
		for _, artifact := range result.Artifacts {
			entries = append(entries, elapsedAt(operatorlog.Artifact("artifact", artifact.Name,
				operatorlog.Field{Name: "kind", Value: artifact.Kind},
			).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		}
	}
	entries = append(entries, elapsed(operatorlog.Stage("5/5 complete throw",
		operatorlog.Field{Name: "chain", Value: payload.Chain},
		operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
	)))
	entries = append(entries, elapsed(operatorlog.Success("throw", "completed",
		operatorlog.Field{Name: "chain", Value: payload.Chain},
		operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
	)))

	return operatorlog.New(
		"HOVEL//THROW",
		payload.Chain,
		entries,
	)
}

func elapsedAt(entry operatorlog.Entry, at, started time.Time, chain string) operatorlog.Entry {
	if at.Before(started) {
		at = started
	}
	return entry.
		WithElapsed(at.Sub(started).Seconds()).
		WithChain(chain).
		WithTopic("chain/" + chain + "/logs")
}

func firstLogTime(logs []LogEntry, fallback time.Time) time.Time {
	for _, log := range logs {
		if at, err := time.Parse(time.RFC3339Nano, log.Time); err == nil && !at.IsZero() {
			return at
		}
	}
	return fallback
}

func lastLogTime(logs []LogEntry, fallback time.Time) time.Time {
	for i := len(logs) - 1; i >= 0; i-- {
		if at, err := time.Parse(time.RFC3339Nano, logs[i].Time); err == nil && !at.IsZero() {
			return at
		}
	}
	return fallback
}

func logFields(log LogEntry) []operatorlog.Field {
	fields := make([]operatorlog.Field, 0, len(log.Fields)+2)
	if log.Level != "" {
		fields = append(fields, operatorlog.Field{Name: "level", Value: log.Level})
	}
	if log.Logger != "" {
		fields = append(fields, operatorlog.Field{Name: "logger", Value: log.Logger})
	}
	keys := make([]string, 0, len(log.Fields))
	for key := range log.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fields = append(fields, operatorlog.Field{Name: key, Value: log.Fields[key]})
	}
	return fields
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
