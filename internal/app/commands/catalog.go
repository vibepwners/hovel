package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
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
	ListSessions(context.Context) ([]SessionRef, error)
	CloseSession(context.Context, string) error
}

type ThrowPlanRecorder interface {
	RecordThrowPlan(context.Context, ThrowPlanRecord) error
}

type ThrowRecorder interface {
	RecordThrow(context.Context, ThrowRecord) error
}

type ThrowConfirmationRecorder interface {
	RecordThrowConfirmation(context.Context, ThrowConfirmationRecord) error
}

type ArtifactRecorder interface {
	MaterializeArtifact(context.Context, ArtifactMaterialization) (ArtifactRecord, error)
}

type ArtifactRepository interface {
	ListArtifacts(context.Context, string) ([]ArtifactRecord, error)
	GetArtifact(context.Context, string, string) (ArtifactRecord, error)
}

type EventRecorder interface {
	RecordEvent(context.Context, string, event.Event) error
}

type EventRepository interface {
	ListEvents(context.Context, string, event.Filter) ([]event.Event, error)
}

type ThrowConfirmationRepository interface {
	GetThrowConfirmation(context.Context, string, string) (ThrowConfirmationRecord, bool, error)
}

type ThrowPlanRepository interface {
	ListThrowPlans(context.Context, string) ([]ThrowPlanRecord, error)
	GetThrowPlan(context.Context, string, string) (ThrowPlanRecord, error)
}

type ChainFileStore interface {
	WriteChainFile(context.Context, string, ChainFile) error
	ReadChainFile(context.Context, string) (ChainFile, error)
}

type OperatorSession interface {
	CreateOperation(string) error
	UseOperation(string) error
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
	Workspaces         WorkspaceInitializer
	Daemons            DaemonStatusProvider
	Runs               RunClientFactory
	Plans              ThrowPlanRecorder
	Throws             ThrowRecorder
	Confirmations      ThrowConfirmationRecorder
	Artifacts          ArtifactRecorder
	ArtifactRecords    ArtifactRepository
	Events             EventRecorder
	EventRecords       EventRepository
	ThrowConfirmations ThrowConfirmationRepository
	ThrowPlans         ThrowPlanRepository
	ChainFiles         ChainFileStore
	Session            OperatorSession
	Modules            ModuleDatabase
}

type ModuleDatabase interface {
	List() []modulecatalog.Module
	ByType(modulecatalog.ModuleType) []modulecatalog.Module
	Search(string) []modulecatalog.Module
	Find(string) (modulecatalog.Module, bool)
	Validate(modulecatalog.ConfigView) modulecatalog.Validation
}

type RunMockExploitRequest struct {
	Operation    string
	Chain        string
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
	Data string `json:"data,omitempty"`
	Path string `json:"path,omitempty"`
}

type ArtifactRecord struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	ThrowID   string `json:"throwId"`
	RunID     string `json:"runId"`
	ModuleID  string `json:"moduleId"`
	Target    string `json:"target"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	CreatedAt string `json:"createdAt"`
}

type ArtifactMaterialization struct {
	Workspace string
	ThrowID   string
	RunID     string
	ModuleID  string
	Target    string
	Artifact  Artifact
	CreatedAt time.Time
}

type SessionRef struct {
	ID           string   `json:"id"`
	RunID        string   `json:"runId"`
	ModuleID     string   `json:"moduleId"`
	Target       string   `json:"target"`
	Name         string   `json:"name,omitempty"`
	Kind         string   `json:"kind"`
	State        string   `json:"state"`
	Transport    string   `json:"transport"`
	Capabilities []string `json:"capabilities"`
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
	Sessions  []SessionRef
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
	RunID     string       `json:"runId"`
	ModuleID  string       `json:"moduleId"`
	Target    string       `json:"target"`
	State     string       `json:"state"`
	Summary   string       `json:"summary"`
	Findings  []Finding    `json:"findings"`
	Artifacts []Artifact   `json:"artifacts"`
	Logs      []LogEntry   `json:"logs"`
	Sessions  []SessionRef `json:"sessions"`
}

type ThrowPayload struct {
	Plan    ThrowPlanPayload `json:"plan"`
	ThrowID string           `json:"throwId,omitempty"`
	Chain   string           `json:"chain"`
	Targets []string         `json:"targets"`
	Results []RunPayload     `json:"results"`
}

type ThrowInspectPayload struct {
	Plan   ThrowPlanRecord `json:"plan"`
	Events []event.Event   `json:"events,omitempty"`
}

type ThrowPlanPayload struct {
	ID             string   `json:"id"`
	ConfirmationID string   `json:"confirmationId"`
	PlanHash       string   `json:"planHash"`
	Chain          string   `json:"chain"`
	Targets        []string `json:"targets"`
	Review         string   `json:"review"`
}

type ThrowPlanRecord struct {
	ID             string                       `json:"id"`
	ConfirmationID string                       `json:"confirmationId"`
	PlanHash       string                       `json:"planHash"`
	Workspace      string                       `json:"workspace"`
	Operation      string                       `json:"operation,omitempty"`
	Chain          string                       `json:"chain"`
	Targets        []string                     `json:"targets"`
	Modules        []string                     `json:"modules,omitempty"`
	ChainConfig    map[string]string            `json:"chainConfig,omitempty"`
	TargetConfigs  map[string]map[string]string `json:"targetConfigs,omitempty"`
	Review         string                       `json:"review"`
	Intent         string                       `json:"intent"`
}

type ThrowRecord struct {
	ID          string       `json:"id"`
	Workspace   string       `json:"workspace"`
	PlanID      string       `json:"planId"`
	PlanHash    string       `json:"planHash"`
	Chain       string       `json:"chain"`
	Targets     []string     `json:"targets"`
	State       string       `json:"state"`
	StartedAt   string       `json:"startedAt"`
	CompletedAt string       `json:"completedAt"`
	Runs        []RunSummary `json:"runs"`
}

type RunSummary struct {
	RunID     string `json:"runId"`
	ModuleID  string `json:"moduleId"`
	Target    string `json:"target"`
	State     string `json:"state"`
	Summary   string `json:"summary"`
	Artifacts int    `json:"artifacts"`
	Findings  int    `json:"findings"`
}

type ThrowConfirmationRecord struct {
	ID          string `json:"id"`
	Workspace   string `json:"workspace"`
	PlanID      string `json:"planId"`
	PlanHash    string `json:"planHash"`
	ClientID    string `json:"clientId"`
	Method      string `json:"method"`
	ConfirmedAt string `json:"confirmedAt"`
}

func (r ThrowPlanRecord) Payload() ThrowPlanPayload {
	return ThrowPlanPayload{
		ID:             r.ID,
		ConfirmationID: r.ConfirmationID,
		PlanHash:       r.PlanHash,
		Chain:          r.Chain,
		Targets:        append([]string(nil), r.Targets...),
		Review:         r.Review,
	}
}

type ValidationPayload struct {
	Valid  bool                  `json:"valid"`
	Issues []modulecatalog.Issue `json:"issues"`
}

type ChainFile struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ChainFileMetadata `json:"metadata"`
	Spec       ChainFileSpec     `json:"spec"`
}

type ChainFileMetadata struct {
	Name string `json:"name"`
}

type ChainFileSpec struct {
	Mode          string                       `json:"mode"`
	Steps         []ChainFileStep              `json:"steps"`
	Config        map[string]string            `json:"config,omitempty"`
	Targets       []ChainFileTarget            `json:"targets,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
}

type ChainFileStep struct {
	ID   string `json:"id"`
	Uses string `json:"uses"`
}

type ChainFileTarget struct {
	ID     string            `json:"id"`
	Config map[string]string `json:"config,omitempty"`
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
				boolOption("events", "", "Include structured events"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: daemonStatusHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "create"},
			Aliases: [][]string{{"operation", "create"}},
			Summary: "Create and select an operation.",
			Positionals: []Positional{
				{Name: "operation", Help: "Operation name", Required: true},
			},
			Handler: operationCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "use"},
			Aliases: [][]string{{"operation", "use"}},
			Summary: "Select the active operation.",
			Positionals: []Positional{
				{Name: "operation", Help: "Operation name", Required: true},
			},
			Handler: operationUseHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "list"},
			Aliases: [][]string{{"operation", "list"}},
			Summary: "List operations in the operator session.",
			Handler: operationListHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "inspect"},
			Aliases: [][]string{{"operation", "inspect"}},
			Summary: "Inspect the active operation.",
			Handler: operationInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "create"},
			Aliases: [][]string{{"chains", "create"}},
			Summary: "Create a chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "use"},
			Aliases: [][]string{{"chains", "use"}},
			Summary: "Select the active chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain or module identifier", Required: true},
			},
			Handler: chainUseHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "rename"},
			Aliases: [][]string{{"chains", "rename"}},
			Summary: "Rename a chain and keep its targets and logs.",
			Positionals: []Positional{
				{Name: "chain", Help: "Current chain name", Required: true},
				{Name: "name", Help: "New chain name", Required: true},
			},
			Handler: chainRenameHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "add"},
			Aliases: [][]string{{"chains", "add"}},
			Summary: "Add a module to the active chain.",
			Positionals: []Positional{
				{Name: "module", Help: "Module ID", Required: true},
			},
			Handler: chainAddHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "validate"},
			Aliases: [][]string{{"chains", "validate"}},
			Summary: "Validate active chain configuration.",
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainValidateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "save"},
			Aliases: [][]string{{"chains", "save"}},
			Summary: "Save the active chain to a YAML file.",
			Positionals: []Positional{
				{Name: "file", Help: "Chain YAML file path", Required: true},
			},
			Options: []Option{
				boolOption("template", "", "Save a targetless reusable chain template"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainSaveHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "load"},
			Aliases: [][]string{{"chains", "load"}},
			Summary: "Load a chain from a YAML file.",
			Positionals: []Positional{
				{Name: "file", Help: "Chain YAML file path", Required: true},
			},
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainLoadHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "set"},
			Aliases: [][]string{{"chains", "config", "set"}},
			Summary: "Set active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: chainConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "unset"},
			Aliases: [][]string{{"chains", "config", "unset"}},
			Summary: "Unset active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: chainConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "list"},
			Aliases: [][]string{{"chains", "config", "list"}},
			Summary: "List active chain configuration.",
			Handler: chainConfigListHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "list"},
			Aliases: [][]string{{"chains", "list"}},
			Summary: "List chains in the operator session.",
			Handler: chainListHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "inspect"},
			Aliases: [][]string{{"chains", "inspect"}},
			Summary: "Inspect the active chain.",
			Handler: chainInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "delete"},
			Aliases: [][]string{{"chains", "delete"}},
			Summary: "Delete a chain from the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainDeleteHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "logs"},
			Aliases: [][]string{{"chains", "logs"}},
			Summary: "Show logs for the active chain.",
			Handler: chainLogsHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "add"},
			Aliases: [][]string{{"targets", "add"}},
			Summary: "Add a target to the operator session.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsAddHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "clear"},
			Aliases: [][]string{{"targets", "clear"}},
			Summary: "Clear targets from the operator session.",
			Handler: targetsClearHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "set"},
			Aliases: [][]string{{"targets", "config", "set"}},
			Summary: "Set target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: targetsConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "unset"},
			Aliases: [][]string{{"targets", "config", "unset"}},
			Summary: "Unset target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: targetsConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "list"},
			Aliases: [][]string{{"targets", "config", "list"}},
			Summary: "List target configuration on the active chain.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsConfigListHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "list"},
			Aliases: [][]string{{"modules", "list"}},
			Summary: "List modules in the module database.",
			Options: []Option{
				stringOption("type", "t", "Module type filter"),
			},
			Handler: modulesListHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "inspect"},
			Aliases: [][]string{{"modules", "inspect"}},
			Summary: "Inspect a module in the module database.",
			Positionals: []Positional{
				{Name: "module", Help: "Module reference", Required: true},
			},
			Handler: modulesInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "search"},
			Aliases: [][]string{{"modules", "search"}},
			Summary: "Search modules in the module database.",
			Positionals: []Positional{
				{Name: "query", Help: "Search query", Required: true},
			},
			Handler: modulesSearchHandler(runtime),
		},
		Definition{
			Path:    []string{"artifact", "list"},
			Aliases: [][]string{{"artifacts", "list"}},
			Summary: "List materialized artifacts.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: artifactsListHandler(runtime),
		},
		Definition{
			Path:    []string{"artifact", "inspect"},
			Aliases: [][]string{{"artifacts", "inspect"}},
			Summary: "Inspect a materialized artifact.",
			Positionals: []Positional{
				{Name: "artifact", Help: "Artifact ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: artifactsInspectHandler(runtime),
		},
		Definition{
			Path:           []string{"throw"},
			Summary:        "Throw the selected chain or a configured chain file.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				boolOption("now", "", "Bypass typed confirmation prompt"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwHandler(runtime),
		},
		Definition{
			Path:    []string{"confirm"},
			Summary: "Pre-confirm the selected throw plan or chain file without executing it.",
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: confirmHandler(runtime),
		},
		Definition{
			Path:    []string{"review"},
			Summary: "Review and confirm the selected throw plan or chain file without executing it.",
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: reviewHandler(runtime),
		},
		Definition{
			Path:    []string{"throw", "list"},
			Aliases: [][]string{{"throws", "list"}},
			Summary: "List recorded throw plans.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwsListHandler(runtime),
		},
		Definition{
			Path:    []string{"throw", "inspect"},
			Aliases: [][]string{{"throws", "inspect"}},
			Summary: "Inspect a recorded throw plan.",
			Positionals: []Positional{
				{Name: "throw", Help: "Throw plan ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwsInspectHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "list"},
			Aliases:        [][]string{{"sessions"}},
			Summary:        "List active post-exploitation sessions.",
			RequiresDaemon: true,
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionsListHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "connect"},
			Aliases:        [][]string{{"sessions", "connect"}},
			Summary:        "Connect interactively to an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
			},
			Handler: sessionConnectHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "close"},
			Aliases:        [][]string{{"sessions", "close"}},
			Summary:        "Close an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionCloseHandler(runtime),
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

func operationCreateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		operation := invocation.Positional("operation")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op create")
		}
		if err := runtime.Session.CreateOperation(operation); err != nil {
			return Result{}, err
		}
		if err := runtime.Session.UseOperation(operation); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Operation selected: %s", operation)}, nil
	}
}

func operationUseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		operation := invocation.Positional("operation")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op use")
		}
		if err := runtime.Session.UseOperation(operation); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Operation selected: %s", operation)}, nil
	}
}

func operationListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op list")
		}
		state := runtime.Session.Snapshot()
		if len(state.Operations) == 0 {
			return Result{Human: "No operations"}, nil
		}
		var lines []string
		for _, operation := range state.Operations {
			prefix := " "
			if operation.Name == state.ActiveOperation {
				prefix = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s chains=%d", prefix, operation.Name, len(operation.Chains)))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func operationInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op inspect")
		}
		state := runtime.Session.Snapshot()
		lines := []string{
			fmt.Sprintf("Operation %s chains=%d active_chain=%s", state.ActiveOperation, len(state.Chains), displayValue(state.ActiveChain, "none")),
		}
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

func chainSaveHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.ChainFiles == nil {
			return Result{}, fmt.Errorf("chain file store is not configured")
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		chainFile := chainFileFromState(state, invocation.Flag("template"))
		path := invocation.Positional("file")
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("chain file path is required")
		}
		if err := runtime.ChainFiles.WriteChainFile(ctx, path, chainFile); err != nil {
			return Result{}, err
		}
		mode := chainFile.Spec.Mode
		return Result{
			Human: fmt.Sprintf("Chain %s saved as %s to %s", chainFile.Metadata.Name, mode, path),
			JSON:  chainFile,
		}, nil
	}
}

func chainLoadHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.ChainFiles == nil {
			return Result{}, fmt.Errorf("chain file store is not configured")
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain load")
		}
		path := invocation.Positional("file")
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("chain file path is required")
		}
		chainFile, err := runtime.ChainFiles.ReadChainFile(ctx, path)
		if err != nil {
			return Result{}, err
		}
		if err := loadChainFile(runtime.Session, chainFile); err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Chain loaded: %s", chainFile.Metadata.Name),
			JSON:  chainFile,
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
			return Result{}, operatorSessionRequiredError("target add")
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
			return Result{}, operatorSessionRequiredError("target clear")
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
			return Result{Human: fmt.Sprintf("No target config for %s\n\nNext: target config set %s <key> <value>", target, target)}, nil
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

func artifactsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ArtifactRecords == nil {
			return Result{}, fmt.Errorf("artifact repository is not configured")
		}
		workspacePath := invocation.Option("workspace")
		if workspacePath == "" {
			workspacePath = ".hovel"
		}
		artifacts, err := runtime.ArtifactRecords.ListArtifacts(ctx, workspacePath)
		if err != nil {
			return Result{}, err
		}
		if len(artifacts) == 0 {
			return Result{Human: "No artifacts", JSON: artifacts}, nil
		}
		lines := []string{"ID                                                                 THROW                     NAME                      KIND       SIZE PATH"}
		for _, artifact := range artifacts {
			lines = append(lines, fmt.Sprintf("%-66s %-25s %-25s %-10s %-4d %s", artifact.ID, artifact.ThrowID, artifact.Name, artifact.Kind, artifact.Size, artifact.Path))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: artifacts}, nil
	}
}

func artifactsInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ArtifactRecords == nil {
			return Result{}, fmt.Errorf("artifact repository is not configured")
		}
		workspacePath := invocation.Option("workspace")
		if workspacePath == "" {
			workspacePath = ".hovel"
		}
		artifact, err := runtime.ArtifactRecords.GetArtifact(ctx, workspacePath, invocation.Positional("artifact"))
		if err != nil {
			return Result{}, err
		}
		lines := []string{
			fmt.Sprintf("Artifact %s", artifact.ID),
			fmt.Sprintf("name       %s", artifact.Name),
			fmt.Sprintf("kind       %s", artifact.Kind),
			fmt.Sprintf("throw      %s", artifact.ThrowID),
			fmt.Sprintf("run        %s", artifact.RunID),
			fmt.Sprintf("module     %s", artifact.ModuleID),
			fmt.Sprintf("target     %s", artifact.Target),
			fmt.Sprintf("size       %d", artifact.Size),
			fmt.Sprintf("sha256     %s", artifact.SHA256),
			fmt.Sprintf("path       %s", artifact.Path),
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: artifact}, nil
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
		throw, err := throwInputs(ctx, runtime, invocation)
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

		plan := newThrowPlanForExecution(status.WorkspacePath, throw)
		if runtime.Plans != nil {
			if err := runtime.Plans.RecordThrowPlan(ctx, plan); err != nil {
				return Result{}, err
			}
		}
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.planned", "throw planned", plan, "", "", event.LevelInfo, map[string]string{
			"planHash": plan.PlanHash,
			"review":   plan.Review,
		}); err != nil {
			return Result{}, err
		}
		if runtime.Confirmations != nil {
			method := "typed_yes"
			if invocation.Flag("now") {
				method = "now_bypass"
			}
			confirmed := false
			if method != "now_bypass" && runtime.ThrowConfirmations != nil {
				_, ok, err := runtime.ThrowConfirmations.GetThrowConfirmation(ctx, status.WorkspacePath, plan.PlanHash)
				if err != nil {
					return Result{}, err
				}
				confirmed = ok
			}
			if !confirmed {
				if method != "now_bypass" {
					if invocation.NonInteractive {
						return Result{}, fmt.Errorf("throw requires --now or a matching preconfirmation in non-interactive mode")
					}
					if invocation.Input == nil {
						return Result{}, fmt.Errorf("throw requires confirmation; run confirm first, type yes at the prompt, or pass --now")
					}
					prompt := throwConfirmationPrompt(plan, "throw")
					answer, err := invocation.Input.Confirm(ctx, prompt)
					if err != nil {
						return Result{}, err
					}
					if !answer.Confirmed(prompt) {
						return Result{}, fmt.Errorf("throw cancelled")
					}
				}
				confirmation := newThrowConfirmation(plan, confirmationClientID(runtime), method, time.Now().UTC())
				if err := runtime.Confirmations.RecordThrowConfirmation(ctx, confirmation); err != nil {
					return Result{}, err
				}
				if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.confirmed", "throw confirmed", plan, "", "", event.LevelInfo, map[string]string{
					"confirmationId": confirmation.ID,
					"method":         method,
				}); err != nil {
					return Result{}, err
				}
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
		payload.ThrowID = throwRecordID(plan)
		payload.Chain = throw.Chain
		payload.Targets = append([]string(nil), throw.Targets...)
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.started", "throw started", plan, payload.ThrowID, "", event.LevelInfo, nil); err != nil {
			return Result{}, err
		}
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
					Operation:    planOperation(plan),
					Chain:        throw.Chain,
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
				if runtime.Artifacts != nil {
					resultIndex := len(payload.Results) - 1
					for artifactIndex, artifact := range payload.Results[resultIndex].Artifacts {
						record, err := runtime.Artifacts.MaterializeArtifact(ctx, ArtifactMaterialization{
							Workspace: status.WorkspacePath,
							ThrowID:   payload.ThrowID,
							RunID:     result.RunID,
							ModuleID:  moduleID,
							Target:    target,
							Artifact:  artifact,
							CreatedAt: time.Now().UTC(),
						})
						if err != nil {
							return Result{}, err
						}
						if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.artifact.recorded", "artifact recorded", plan, payload.ThrowID, result.RunID, event.LevelInfo, map[string]string{
							"artifactId": record.ID,
							"name":       record.Name,
							"kind":       record.Kind,
							"path":       record.Path,
							"sha256":     record.SHA256,
						}); err != nil {
							return Result{}, err
						}
						payload.Results[resultIndex].Artifacts[artifactIndex].Data = ""
						payload.Results[resultIndex].Artifacts[artifactIndex].Name = record.Name
					}
				}
				if runtime.Session != nil && feedbackPublished(runtime.Session) {
					_ = runtime.Session.AppendLogToChain(throw.Chain, throwRunResultEntries(payload, payload.Results[len(payload.Results)-1], runIndex, len(throw.Targets)*len(throw.Modules), throwStarted)...)
				}
			}
		}
		log := throwLog(payload, throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			_ = runtime.Session.AppendLogToChain(payload.Chain, throwCompleteEntries(payload, throwStarted)...)
			if runtime.Throws != nil {
				if err := runtime.Throws.RecordThrow(ctx, newThrowRecord(status.WorkspacePath, plan, payload, throwStarted, time.Now().UTC())); err != nil {
					return Result{}, err
				}
			}
			if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.completed", "throw completed", plan, payload.ThrowID, "", event.LevelInfo, map[string]string{
				"runs": fmt.Sprint(len(payload.Results)),
			}); err != nil {
				return Result{}, err
			}
			return Result{JSON: payload}, nil
		}
		if runtime.Session != nil {
			_ = runtime.Session.AppendLogToChain(payload.Chain, log.Entries()...)
		}
		if runtime.Throws != nil {
			if err := runtime.Throws.RecordThrow(ctx, newThrowRecord(status.WorkspacePath, plan, payload, throwStarted, time.Now().UTC())); err != nil {
				return Result{}, err
			}
		}
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.completed", "throw completed", plan, payload.ThrowID, "", event.LevelInfo, map[string]string{
			"runs": fmt.Sprint(len(payload.Results)),
		}); err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Throw completed chain %s against %d target(s)", payload.Chain, len(payload.Targets)),
			JSON:  payload,
			Log:   log,
		}, nil
	}
}

func confirmHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		plan, err := recordThrowPlan(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		confirmation, err := recordThrowConfirmation(ctx, runtime, plan, "preconfirmed")
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Confirmed throw plan %s for chain %s against %d target(s)", plan.ID, plan.Chain, len(plan.Targets)),
			JSON:  confirmation,
		}, nil
	}
}

func reviewHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		plan, err := recordThrowPlan(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		if invocation.NonInteractive {
			return Result{}, fmt.Errorf("review requires an interactive typed yes confirmation")
		}
		if invocation.Input == nil {
			return Result{}, fmt.Errorf("review requires confirmation; type yes at the prompt")
		}
		prompt := throwConfirmationPrompt(plan, "confirm review")
		answer, err := invocation.Input.Confirm(ctx, prompt)
		if err != nil {
			return Result{}, err
		}
		if !answer.Confirmed(prompt) {
			return Result{}, fmt.Errorf("review cancelled")
		}
		confirmation, err := recordThrowConfirmation(ctx, runtime, plan, "reviewed_yes")
		if err != nil {
			return Result{}, err
		}
		return Result{
			JSON: confirmation,
			Log: operatorlog.New("HOVEL//REVIEW", plan.Chain, []operatorlog.Entry{
				operatorlog.Success("review", "confirmed",
					operatorlog.Field{Name: "plan", Value: plan.ID},
					operatorlog.Field{Name: "targets", Value: fmt.Sprint(len(plan.Targets))},
					operatorlog.Field{Name: "planHash", Value: plan.PlanHash},
				),
			}),
		}, nil
	}
}

func throwConfirmationPrompt(plan ThrowPlanRecord, action string) ConfirmationPrompt {
	return ConfirmationPrompt{
		Title:           "THROW REVIEW",
		Action:          action,
		RequiredLiteral: "yes",
		Plan:            plan,
		Fields: []ConfirmationField{
			{Label: "chain", Value: plan.Chain},
			{Label: "targets", Value: strings.Join(plan.Targets, ", ")},
			{Label: "modules", Value: formatReviewList(plan.Modules)},
			{Label: "chain config", Value: formatReviewConfig(plan.ChainConfig)},
			{Label: "target config", Value: formatReviewTargetConfigs(plan.Targets, plan.TargetConfigs)},
			{Label: "plan hash", Value: shortPlanHash(plan.PlanHash), Muted: true},
		},
	}
}

func shortPlanHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 10 {
		return hash
	}
	return hash[:10]
}

func formatReviewList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func formatReviewConfig(config map[string]string) string {
	if len(config) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, config[key]))
	}
	return strings.Join(lines, "\n")
}

func formatReviewTargetConfigs(targets []string, configs map[string]map[string]string) string {
	if len(configs) == 0 {
		return "(none)"
	}
	orderedTargets := append([]string(nil), targets...)
	seen := make(map[string]bool, len(orderedTargets))
	for _, target := range orderedTargets {
		seen[target] = true
	}
	for target := range configs {
		if !seen[target] {
			orderedTargets = append(orderedTargets, target)
		}
	}
	lines := make([]string, 0)
	for _, target := range orderedTargets {
		config := configs[target]
		if len(config) == 0 {
			continue
		}
		lines = append(lines, target)
		for _, line := range strings.Split(formatReviewConfig(config), "\n") {
			lines = append(lines, "  "+line)
		}
	}
	if len(lines) == 0 {
		return "(none)"
	}
	return strings.Join(lines, "\n")
}

func recordThrowPlan(ctx context.Context, runtime Runtime, invocation Invocation) (ThrowPlanRecord, error) {
	if runtime.Plans == nil {
		return ThrowPlanRecord{}, fmt.Errorf("throw plan recorder is not configured")
	}
	throw, err := throwInputs(ctx, runtime, invocation)
	if err != nil {
		return ThrowPlanRecord{}, err
	}
	workspacePath := invocation.Option("workspace")
	if workspacePath == "" {
		workspacePath = ".hovel"
	}
	plan := newThrowPlanForExecution(workspacePath, throw)
	if err := runtime.Plans.RecordThrowPlan(ctx, plan); err != nil {
		return ThrowPlanRecord{}, err
	}
	return plan, nil
}

func recordThrowConfirmation(ctx context.Context, runtime Runtime, plan ThrowPlanRecord, method string) (ThrowConfirmationRecord, error) {
	if runtime.Confirmations == nil {
		return ThrowConfirmationRecord{}, fmt.Errorf("throw confirmation recorder is not configured")
	}
	confirmation := newThrowConfirmation(plan, confirmationClientID(runtime), method, time.Now().UTC())
	if err := runtime.Confirmations.RecordThrowConfirmation(ctx, confirmation); err != nil {
		return ThrowConfirmationRecord{}, err
	}
	return confirmation, nil
}

func throwsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ThrowPlans == nil {
			return Result{}, fmt.Errorf("throw plan repository is not configured")
		}
		workspacePath := invocation.Option("workspace")
		if workspacePath == "" {
			workspacePath = ".hovel"
		}
		plans, err := runtime.ThrowPlans.ListThrowPlans(ctx, workspacePath)
		if err != nil {
			return Result{}, err
		}
		if len(plans) == 0 {
			return Result{Human: "No throws", JSON: plans}, nil
		}
		lines := []string{"ID                         CHAIN                     TARGETS REVIEW"}
		for _, plan := range plans {
			lines = append(lines, fmt.Sprintf("%-26s %-25s %-7d %s", plan.ID, plan.Chain, len(plan.Targets), plan.Review))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: plans}, nil
	}
}

func throwsInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ThrowPlans == nil {
			return Result{}, fmt.Errorf("throw plan repository is not configured")
		}
		workspacePath := invocation.Option("workspace")
		if workspacePath == "" {
			workspacePath = ".hovel"
		}
		plan, err := runtime.ThrowPlans.GetThrowPlan(ctx, workspacePath, invocation.Positional("throw"))
		if err != nil {
			return Result{}, err
		}
		lines := []string{
			fmt.Sprintf("Throw %s", plan.ID),
			fmt.Sprintf("chain          %s", plan.Chain),
			fmt.Sprintf("targets        %s", strings.Join(plan.Targets, ", ")),
			fmt.Sprintf("confirmation   %s", plan.ConfirmationID),
			fmt.Sprintf("review         %s", plan.Review),
			fmt.Sprintf("intent         %s", plan.Intent),
		}
		payload := ThrowInspectPayload{Plan: plan}
		if invocation.Flag("events") {
			if runtime.EventRecords == nil {
				return Result{}, fmt.Errorf("event repository is not configured")
			}
			events, err := runtime.EventRecords.ListEvents(ctx, workspacePath, event.Filter{ThrowID: throwRecordID(plan)})
			if err != nil {
				return Result{}, err
			}
			payload.Events = events
			lines = append(lines, "")
			lines = append(lines, eventLines(events)...)
		}
		if invocation.Flag("events") {
			return Result{Human: strings.Join(lines, "\n"), JSON: payload}, nil
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: plan}, nil
	}
}

func eventLines(events []event.Event) []string {
	if len(events) == 0 {
		return []string{"No events"}
	}
	lines := []string{"EVENTS", "TIME                           LEVEL TYPE                         MESSAGE"}
	for _, evt := range events {
		lines = append(lines, fmt.Sprintf("%-30s %-5s %-28s %s", evt.Timestamp.Format(time.RFC3339Nano), evt.Level, evt.Type, evt.Message))
	}
	return lines
}

func recordStructuredEvent(ctx context.Context, runtime Runtime, workspacePath, typ, message string, plan ThrowPlanRecord, throwID, runID string, level event.Level, fields map[string]string) error {
	if runtime.Events == nil {
		return nil
	}
	id, err := event.NewID(eventID(typ))
	if err != nil {
		return err
	}
	eventType, err := event.NewType(typ)
	if err != nil {
		return err
	}
	if fields == nil {
		fields = map[string]string{}
	}
	if plan.PlanHash != "" {
		fields["planHash"] = plan.PlanHash
	}
	topic := ""
	if plan.Chain != "" {
		topic = "operation/" + planOperation(plan) + "/chain/" + plan.Chain + "/logs"
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Level:     level,
		Message:   message,
		Timestamp: time.Now().UTC(),
		Topic:     topic,
		Refs: event.Refs{
			WorkspaceID: workspacePath,
			Operation:   planOperation(plan),
			Chain:       plan.Chain,
			ThrowID:     throwID,
			RunID:       runID,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return runtime.Events.RecordEvent(ctx, workspacePath, evt)
}

func eventID(typ string) string {
	safeType := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			return r
		default:
			return '-'
		}
	}, typ)
	safeType = strings.Trim(safeType, "-")
	if safeType == "" {
		safeType = "event"
	}
	return fmt.Sprintf("event-%s-%d", safeType, time.Now().UnixNano())
}

func sessionsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessions, err := client.ListSessions(ctx)
		if err != nil {
			return Result{}, err
		}
		if len(sessions) == 0 {
			return Result{Human: "No active sessions", JSON: sessions}, nil
		}
		lines := []string{"ID                         KIND      STATE    TARGET        NAME"}
		for _, session := range sessions {
			lines = append(lines, fmt.Sprintf("%-26s %-9s %-8s %-13s %s", session.ID, session.Kind, session.State, session.Target, session.Name))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: sessions}, nil
	}
}

func sessionConnectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("session connect is available in the interactive CLI; run hovel cli and use session connect %s", invocation.Positional("session"))
	}
}

func sessionCloseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessionID := invocation.Positional("session")
		if err := client.CloseSession(ctx, sessionID); err != nil {
			return Result{}, err
		}
		payload := map[string]string{"sessionId": sessionID, "status": "closed"}
		return Result{Human: fmt.Sprintf("Session closed: %s", sessionID), JSON: payload}, nil
	}
}

func dialDaemonRunClient(ctx context.Context, runtime Runtime, workspacePath string) (RunClient, func(), error) {
	if runtime.Daemons == nil {
		return nil, nil, fmt.Errorf("daemon service is not configured")
	}
	if runtime.Runs == nil {
		return nil, nil, fmt.Errorf("run client factory is not configured")
	}
	status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacePath})
	if err != nil {
		return nil, nil, err
	}
	if status.State != daemon.StateRunning {
		return nil, nil, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
	}
	client, err := runtime.Runs.DialRunClient(status.Identity.SocketPath)
	if err != nil {
		return nil, nil, err
	}
	return client, func() { _ = client.Close() }, nil
}

func newThrowPlan(workspacePath, chain string, targets []string) ThrowPlanRecord {
	return newThrowPlanForExecution(workspacePath, throwExecution{Chain: chain, Targets: targets})
}

func newThrowPlanForExecution(workspacePath string, throw throwExecution) ThrowPlanRecord {
	id := "plan-" + stablePlanComponent(throw.Chain, throw.Targets)
	hash := planHashForExecution(throw)
	return ThrowPlanRecord{
		ID:             id,
		ConfirmationID: "confirmation-" + stablePlanComponent(throw.Chain, throw.Targets),
		PlanHash:       hash,
		Workspace:      workspacePath,
		Operation:      throw.Operation,
		Chain:          throw.Chain,
		Targets:        append([]string(nil), throw.Targets...),
		Modules:        append([]string(nil), throw.Modules...),
		ChainConfig:    cloneStringMap(throw.ChainConfig),
		TargetConfigs:  cloneTargetConfigs(throw.TargetConfigs),
		Review:         "operator-confirmed",
		Intent:         fmt.Sprintf("throw chain %s against %d target(s)", throw.Chain, len(throw.Targets)),
	}
}

func newThrowConfirmation(plan ThrowPlanRecord, clientID, method string, confirmedAt time.Time) ThrowConfirmationRecord {
	if clientID == "" {
		clientID = "command"
	}
	if method == "" {
		method = "typed_yes"
	}
	return ThrowConfirmationRecord{
		ID:          plan.ConfirmationID,
		Workspace:   plan.Workspace,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		ClientID:    clientID,
		Method:      method,
		ConfirmedAt: confirmedAt.UTC().Format(time.RFC3339Nano),
	}
}

func throwRecordID(plan ThrowPlanRecord) string {
	return "throw-" + strings.TrimPrefix(plan.ID, "plan-")
}

func newThrowRecord(workspacePath string, plan ThrowPlanRecord, payload ThrowPayload, startedAt, completedAt time.Time) ThrowRecord {
	record := ThrowRecord{
		ID:          payload.ThrowID,
		Workspace:   workspacePath,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		Chain:       payload.Chain,
		Targets:     append([]string(nil), payload.Targets...),
		State:       "succeeded",
		StartedAt:   startedAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: completedAt.UTC().Format(time.RFC3339Nano),
	}
	for _, result := range payload.Results {
		if result.State != "succeeded" {
			record.State = result.State
		}
		record.Runs = append(record.Runs, RunSummary{
			RunID:     result.RunID,
			ModuleID:  result.ModuleID,
			Target:    result.Target,
			State:     result.State,
			Summary:   result.Summary,
			Artifacts: len(result.Artifacts),
			Findings:  len(result.Findings),
		})
	}
	return record
}

func planOperation(plan ThrowPlanRecord) string {
	if plan.Operation != "" {
		return plan.Operation
	}
	return operatorsession.DefaultOperation
}

func confirmationClientID(runtime Runtime) string {
	if runtime.Session != nil && feedbackPublished(runtime.Session) {
		return "cli"
	}
	return "command"
}

func planHash(chain string, targets []string) string {
	return planHashForExecution(throwExecution{Chain: chain, Targets: targets})
}

func planHashForExecution(throw throwExecution) string {
	review := struct {
		Chain         string                       `json:"chain"`
		Targets       []string                     `json:"targets"`
		Modules       []string                     `json:"modules"`
		ChainConfig   map[string]string            `json:"chainConfig,omitempty"`
		TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	}{
		Chain:         throw.Chain,
		Targets:       append([]string(nil), throw.Targets...),
		Modules:       append([]string(nil), throw.Modules...),
		ChainConfig:   cloneStringMap(throw.ChainConfig),
		TargetConfigs: cloneTargetConfigs(throw.TargetConfigs),
	}
	data, err := json.Marshal(review)
	if err != nil {
		return planHashLegacy(throw.Chain, throw.Targets)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func planHashLegacy(chain string, targets []string) string {
	var b strings.Builder
	b.WriteString("chain:")
	b.WriteString(chain)
	b.WriteString("\ntargets:")
	for _, target := range targets {
		b.WriteString("\n")
		b.WriteString(target)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
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
	Operation     string
	Chain         string
	Targets       []string
	Modules       []string
	ChainConfig   map[string]string
	TargetConfigs map[string]map[string]string
}

func throwInputs(ctx context.Context, runtime Runtime, invocation Invocation) (throwExecution, error) {
	if file := invocation.Positional("file"); strings.TrimSpace(file) != "" {
		return throwInputsFromChainFile(ctx, runtime, invocation, file)
	}
	operation := operatorsession.DefaultOperation
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
		if state.ActiveOperation != "" {
			operation = state.ActiveOperation
		}
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
		return throwExecution{}, fmt.Errorf("target is required; add one with target add <target> or pass --target")
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
		Operation:     operation,
		Chain:         chain,
		Targets:       targets,
		Modules:       modules,
		ChainConfig:   chainConfig,
		TargetConfigs: targetConfigs,
	}, nil
}

func throwInputsFromChainFile(ctx context.Context, runtime Runtime, invocation Invocation, path string) (throwExecution, error) {
	if runtime.ChainFiles == nil {
		return throwExecution{}, fmt.Errorf("chain file store is not configured")
	}
	file, err := runtime.ChainFiles.ReadChainFile(ctx, path)
	if err != nil {
		return throwExecution{}, err
	}
	if err := validateChainFileForThrow(file); err != nil {
		return throwExecution{}, err
	}
	targets := make([]string, 0, len(file.Spec.Targets))
	targetConfigs := cloneTargetConfigs(file.Spec.TargetConfigs)
	for _, target := range file.Spec.Targets {
		targets = append(targets, target.ID)
		if len(target.Config) != 0 {
			if targetConfigs == nil {
				targetConfigs = map[string]map[string]string{}
			}
			targetConfigs[target.ID] = cloneStringMap(target.Config)
		}
	}
	if target := invocation.Option("target"); target != "" {
		targets = []string{target}
	}
	modules := make([]string, 0, len(file.Spec.Steps))
	for _, step := range file.Spec.Steps {
		if !strings.HasPrefix(strings.TrimSpace(step.Uses), "module:") {
			return throwExecution{}, fmt.Errorf("chain file step %s uses unsupported runtime %q", step.ID, step.Uses)
		}
		moduleID := strings.TrimPrefix(strings.TrimSpace(step.Uses), "module:")
		if moduleID == "" {
			return throwExecution{}, fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		modules = append(modules, moduleID)
	}
	if len(targets) == 0 {
		return throwExecution{}, fmt.Errorf("target is required; configured chain files must include targets or pass --target")
	}
	return throwExecution{
		Operation:     operatorsession.DefaultOperation,
		Chain:         file.Metadata.Name,
		Targets:       targets,
		Modules:       modules,
		ChainConfig:   cloneStringMap(file.Spec.Config),
		TargetConfigs: targetConfigs,
	}, nil
}

func validateChainFileForThrow(file ChainFile) error {
	if err := validateChainFileShape(file); err != nil {
		return err
	}
	if file.Spec.Mode != "configured" {
		return fmt.Errorf("chain file mode must be configured for throw")
	}
	if len(file.Spec.Targets) == 0 {
		return fmt.Errorf("chain file must include targets for throw")
	}
	return nil
}

func validateChainFileShape(file ChainFile) error {
	if strings.TrimSpace(file.APIVersion) == "" {
		return fmt.Errorf("chain file apiVersion is required")
	}
	if file.Kind != "Chain" {
		return fmt.Errorf("chain file kind must be Chain")
	}
	if strings.TrimSpace(file.Metadata.Name) == "" {
		return fmt.Errorf("chain file metadata.name is required")
	}
	if file.Spec.Mode != "" && file.Spec.Mode != "template" && file.Spec.Mode != "configured" {
		return fmt.Errorf("chain file mode must be template or configured")
	}
	if len(file.Spec.Steps) == 0 {
		return fmt.Errorf("chain file must include at least one step")
	}
	for _, step := range file.Spec.Steps {
		if strings.TrimSpace(step.ID) == "" {
			return fmt.Errorf("chain file step id is required")
		}
		if strings.TrimSpace(step.Uses) == "" {
			return fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		if !strings.HasPrefix(step.Uses, "module:") && !strings.HasPrefix(step.Uses, "service:") && !strings.HasPrefix(step.Uses, "provider:") {
			return fmt.Errorf("chain file step %s uses must start with module:, service:, or provider:", step.ID)
		}
	}
	return nil
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

func chainFileFromState(state operatorsession.State, template bool) ChainFile {
	mode := "configured"
	if template {
		mode = "template"
	}
	file := ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   ChainFileMetadata{Name: state.ActiveChain},
		Spec: ChainFileSpec{
			Mode:  mode,
			Steps: chainFileSteps(state.Steps),
		},
	}
	if !template {
		file.Spec.Config = cloneStringMap(state.Config)
		for _, target := range state.Targets {
			file.Spec.Targets = append(file.Spec.Targets, ChainFileTarget{
				ID:     target,
				Config: cloneStringMap(state.TargetConfigs[target]),
			})
		}
		file.Spec.TargetConfigs = cloneTargetConfigs(state.TargetConfigs)
	}
	return file
}

func chainFileSteps(steps []operatorsession.Step) []ChainFileStep {
	out := make([]ChainFileStep, 0, len(steps))
	for _, step := range steps {
		out = append(out, ChainFileStep{
			ID:   step.ID,
			Uses: "module:" + step.ModuleID,
		})
	}
	return out
}

func loadChainFile(session OperatorSession, file ChainFile) error {
	if err := validateChainFileShape(file); err != nil {
		return err
	}
	name := strings.TrimSpace(file.Metadata.Name)
	if err := session.DeleteChain(name); err != nil && !strings.Contains(err.Error(), "does not exist") {
		return err
	}
	if err := session.CreateChain(name); err != nil {
		return err
	}
	if err := session.UseChain(name); err != nil {
		return err
	}
	for _, step := range file.Spec.Steps {
		moduleID := strings.TrimPrefix(strings.TrimSpace(step.Uses), "module:")
		if moduleID == "" {
			return fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		if _, err := session.AddModule(moduleID); err != nil {
			return err
		}
	}
	for key, value := range file.Spec.Config {
		if err := session.SetChainConfig(key, value); err != nil {
			return err
		}
	}
	for _, target := range file.Spec.Targets {
		if strings.TrimSpace(target.ID) == "" {
			return fmt.Errorf("chain file target id is required")
		}
		if err := session.AddTarget(target.ID); err != nil {
			return err
		}
		targetConfig := target.Config
		if len(targetConfig) == 0 {
			targetConfig = file.Spec.TargetConfigs[target.ID]
		}
		for key, value := range targetConfig {
			if err := session.SetTargetConfig(target.ID, key, value); err != nil {
				return err
			}
		}
	}
	return nil
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
	return fmt.Errorf("%s needs an operator session\n\nUse the interactive shell:\n  hovel shell\n\nOr keep using one-shot commands that do not depend on selected chain state, such as:\n  hovel module list\n  hovel throw --chain <chain> --target <target>", command)
}

func withActiveChainHelp(err error) error {
	if err != nil && strings.Contains(err.Error(), "active chain is required") {
		return activeChainRequiredError()
	}
	return err
}

func displayValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
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
	lines = append(lines, "", "Next: add <module>, target add <target>, config interactive, validate, throw")
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
		Sessions:  result.Sessions,
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
			operatorlog.Field{Name: "confirmation", Value: payload.Plan.ConfirmationID},
			operatorlog.Field{Name: "review", Value: payload.Plan.Review},
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
	for _, session := range result.Sessions {
		entries = append(entries, elapsedAt(operatorlog.Info("session", "session opened",
			operatorlog.Field{Name: "session", Value: session.ID},
			operatorlog.Field{Name: "kind", Value: session.Kind},
			operatorlog.Field{Name: "state", Value: session.State},
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
			operatorlog.Field{Name: "confirmation", Value: payload.Plan.ConfirmationID},
			operatorlog.Field{Name: "review", Value: payload.Plan.Review},
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
		for _, session := range result.Sessions {
			entries = append(entries, elapsedAt(operatorlog.Info("session", "session opened",
				operatorlog.Field{Name: "session", Value: session.ID},
				operatorlog.Field{Name: "kind", Value: session.Kind},
				operatorlog.Field{Name: "state", Value: session.State},
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
		WithTopic("operation/" + operatorsession.DefaultOperation + "/chain/" + chain + "/logs")
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
