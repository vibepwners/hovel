package mcpadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	"github.com/Vibe-Pwners/hovel/internal/moduleruntime/pythonrpc"
	"github.com/Vibe-Pwners/hovel/internal/version"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Version = version.Version

	ToolOperatorIdentity     = "hovel_operator_identity"
	ToolOperatorListEntities = "hovel_operator_list_entities"
	ToolOperationList        = "hovel_operation_list"
	ToolWorkspaceSnapshot    = "hovel_workspace_snapshot"
	ToolCatalogSnapshot      = "hovel_catalog_snapshot"
	ToolModuleSearch         = "hovel_module_search"
	ToolModuleInspect        = "hovel_module_inspect"
	ToolChainSuggest         = "hovel_chain_suggest"
	ToolLaunchKeyPolicy      = "hovel_launch_key_policy"
	ToolChainApply           = "hovel_chain_apply"
	ToolCommandRun           = "hovel_command_run"
	ToolThrowPlan            = "hovel_throw_plan"
	ToolThrowConfirm         = "hovel_throw_confirm"
	ToolThrowStart           = "hovel_throw_start"
	ToolInstalledPayloadList = "hovel_installed_payload_list"
	ToolSessionCapabilities  = "hovel_session_capabilities"
	ToolSessionCall          = "hovel_session_call"
	ToolPayloadCapabilities  = "hovel_payload_capabilities"
	ToolPayloadCall          = "hovel_payload_call"
	ToolPayloadCmd           = "hovel_payload_cmd"
	ToolPayloadCommandList   = "hovel_payload_command_list"
	ToolPayloadCommandCall   = "hovel_payload_command_call"

	DefaultWorkspace         = workspace.DefaultPath
	DefaultDisplayName       = "Hovel MCP"
	DefaultHeartbeatInterval = 15 * time.Second
	DefaultTransportMode     = "stdio"
	DefaultHTTPAddr          = "127.0.0.1:0"
)

type Daemon interface {
	AttachEntity(context.Context, daemonrpc.AttachEntityRequest) (daemonrpc.EntityResponse, error)
	HeartbeatEntity(context.Context, daemonrpc.HeartbeatEntityRequest) (daemonrpc.EntityResponse, error)
	DetachEntity(context.Context, daemonrpc.DetachEntityRequest) error
	ListEntities(context.Context, daemonrpc.ListEntitiesRequest) (daemonrpc.ListEntitiesResponse, error)
	Snapshot(context.Context, daemonrpc.SnapshotRequest) (daemonrpc.SnapshotResponse, error)
	GetLaunchKeyPolicy(context.Context, daemonrpc.LaunchKeyPolicyRequest) (daemonrpc.LaunchKeyPolicyResponse, error)
	CreatePendingThrow(context.Context, daemonrpc.CreatePendingThrowRequest) (daemonrpc.PendingThrowResponse, error)
	ConfirmPendingThrow(context.Context, daemonrpc.ConfirmPendingThrowRequest) (daemonrpc.PendingThrowResponse, error)
	ListPayloadCommands(context.Context, daemonrpc.PayloadCommandListRequest) (daemonrpc.PayloadCommandListResponse, error)
	RunPayloadCommand(context.Context, daemonrpc.PayloadCommandRunRequest) (daemonrpc.PayloadCommandRunResponse, error)
	ListSessionCommands(context.Context, daemonrpc.SessionCommandListRequest) (daemonrpc.SessionCommandListResponse, error)
	RunSessionCommand(context.Context, daemonrpc.SessionCommandRunRequest) (daemonrpc.SessionCommandRunResponse, error)
	Close() error
}

type DialFunc func(context.Context, string) (Daemon, error)
type ThrowStarter func(context.Context, throwStartInput) (throwStartOutput, error)
type CommandRunner func(context.Context, commandRunInput) (commandRunOutput, error)

type Config struct {
	Workspace         string
	Operation         string
	Chain             string
	EntityID          string
	DisplayName       string
	Capabilities      []string
	PolicyTags        []string
	Input             io.Reader
	Output            io.Writer
	Status            io.Writer
	TransportMode     string
	HTTPAddr          string
	Transport         mcpsdk.Transport
	HeartbeatInterval time.Duration
	Manager           *daemonmanager.Manager
	Dial              DialFunc
	CatalogPath       string
	HovelConfig       string
	ThrowStarter      ThrowStarter
	CommandRunner     CommandRunner
}

type Server struct {
	mu            sync.Mutex
	daemon        Daemon
	entity        daemonrpc.OperatorEntity
	operation     string
	activeChain   string
	workspace     string
	catalogPath   string
	hovelConfig   string
	throwStarter  ThrowStarter
	commandRunner CommandRunner
}

type OperatorOptions struct {
	EntityID      string
	DisplayName   string
	Operation     string
	ActiveChain   string
	Capabilities  []string
	PolicyTags    []string
	Workspace     string
	CatalogPath   string
	HovelConfig   string
	ThrowStarter  ThrowStarter
	CommandRunner CommandRunner
}

func Run(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	workspacePath := workspaceOrDefault(cfg.Workspace)
	manager := daemonmanager.New()
	if cfg.Manager != nil {
		manager = *cfg.Manager
	}
	session, err := manager.EnsureWithConfig(ctx, workspacePath, cfg.CatalogPath, cfg.HovelConfig)
	if err != nil {
		return err
	}
	defer func() { logMCPError("close daemon manager session", session.Close()) }()

	dial := cfg.Dial
	if dial == nil {
		dial = func(ctx context.Context, socketPath string) (Daemon, error) {
			return daemonrpc.Dial(socketPath)
		}
	}
	client, err := dial(ctx, session.Status().Identity.SocketPath)
	if err != nil {
		return err
	}
	defer func() { logMCPError("close daemon client", client.Close()) }()
	throwStarter := cfg.ThrowStarter
	commandRunner := cfg.CommandRunner
	if throwStarter == nil {
		if rpcClient, ok := client.(*daemonrpc.Client); ok {
			throwStarter = commandModeThrowStarter(workspacePath, rpcClient, cfg.CatalogPath, cfg.HovelConfig)
		}
	}
	if commandRunner == nil {
		if rpcClient, ok := client.(*daemonrpc.Client); ok {
			commandRunner = commandModeCommandRunner(workspacePath, rpcClient, cfg.CatalogPath, cfg.HovelConfig)
		}
	}

	operator, err := Attach(ctx, client, OperatorOptions{
		EntityID:      cfg.EntityID,
		DisplayName:   cfg.DisplayName,
		Operation:     cfg.Operation,
		ActiveChain:   cfg.Chain,
		Capabilities:  cfg.Capabilities,
		PolicyTags:    cfg.PolicyTags,
		Workspace:     workspacePath,
		CatalogPath:   cfg.CatalogPath,
		HovelConfig:   cfg.HovelConfig,
		ThrowStarter:  throwStarter,
		CommandRunner: commandRunner,
	})
	if err != nil {
		return err
	}
	defer func() { logMCPError("detach operator", operator.Detach(context.Background())) }()

	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go operator.heartbeatLoop(heartbeatCtx, heartbeatIntervalOrDefault(cfg.HeartbeatInterval))

	if cfg.Transport != nil {
		if err := operator.MCPServer().Run(ctx, cfg.Transport); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}

	switch transportModeOrDefault(cfg.TransportMode) {
	case "stdio":
		if err := operator.MCPServer().Run(ctx, ioTransport(cfg.Input, cfg.Output)); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	case "http":
		if err := runHTTPTransport(ctx, operator, cfg.HTTPAddr, cfg.Status); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported MCP transport %q", cfg.TransportMode)
	}
	return nil
}

func Attach(ctx context.Context, daemon Daemon, opts OperatorOptions) (*Server, error) {
	if daemon == nil {
		return nil, errors.New("daemon client is required")
	}
	entityID, err := entityIDOrDefault(opts.EntityID)
	if err != nil {
		return nil, err
	}
	displayName := strings.TrimSpace(opts.DisplayName)
	if displayName == "" {
		displayName = DefaultDisplayName
	}
	capabilities := append(defaultCapabilities(), opts.Capabilities...)
	resp, err := daemon.AttachEntity(ctx, daemonrpc.AttachEntityRequest{
		ID:           entityID,
		Kind:         string(operatordomain.KindMCP),
		DisplayName:  displayName,
		Agent:        true,
		Operation:    strings.TrimSpace(opts.Operation),
		ActiveChain:  strings.TrimSpace(opts.ActiveChain),
		Capabilities: uniqueStrings(capabilities),
		PolicyTags:   uniqueStrings(opts.PolicyTags),
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		daemon:        daemon,
		entity:        resp.Entity,
		operation:     resp.Entity.Operation,
		activeChain:   resp.Entity.ActiveChain,
		workspace:     workspaceOrDefault(opts.Workspace),
		catalogPath:   strings.TrimSpace(opts.CatalogPath),
		hovelConfig:   strings.TrimSpace(opts.HovelConfig),
		throwStarter:  opts.ThrowStarter,
		commandRunner: opts.CommandRunner,
	}, nil
}

func (s *Server) Detach(ctx context.Context) error {
	if s == nil || s.daemon == nil {
		return nil
	}
	entity := s.currentEntity()
	if strings.TrimSpace(entity.ID) == "" {
		return nil
	}
	return s.daemon.DetachEntity(ctx, daemonrpc.DetachEntityRequest{ID: entity.ID})
}

func (s *Server) MCPServer() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "hovel",
		Title:   "Hovel MCP",
		Version: Version,
	}, &mcpsdk.ServerOptions{
		Capabilities: &mcpsdk.ServerCapabilities{},
		Instructions: "Use typed tools first. Start with hovel_catalog_snapshot or hovel_chain_suggest for catalog discovery, then hovel_workspace_snapshot for current state. Use hovel_module_inspect for full module-authored metadata, and hovel_chain_apply to idempotently create/select an operation and chain, add modules, targets, set config, and validate. Use hovel_throw_plan to review preflight details before hovel_throw_confirm and hovel_throw_start. Use hovel_throw_start only after explicit caller authorization for the throw and dangerous modules. After a throw, follow executable nextActions such as hovel_installed_payload_list and hovel_payload_cmd. Use hovel_command_run only as an escape hatch for commands without typed tools.",
	})
	s.RegisterTools(server)
	return server
}

func (s *Server) RegisterTools(server *mcpsdk.Server) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolOperatorIdentity,
		Title:       "Operator Identity",
		Description: "Return this MCP server's logged-in Hovel operator entity.",
		Annotations: readOnlyTool("Operator Identity"),
	}, s.operatorIdentity)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolOperatorListEntities,
		Title:       "List Operator Entities",
		Description: "List live operator entities attached to hoveld, optionally filtered by operation.",
		Annotations: readOnlyTool("List Operator Entities"),
	}, s.operatorListEntities)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolOperationList,
		Title:       "List Operations",
		Description: "List operation names, chains, and targets visible in the daemon-backed workspace.",
		Annotations: readOnlyTool("List Operations"),
	}, s.operationList)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolWorkspaceSnapshot,
		Title:       "Workspace Snapshot",
		Description: "Return a structured workspace snapshot for an operation and optional chain.",
		Annotations: readOnlyTool("Workspace Snapshot"),
	}, s.workspaceSnapshot)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolCatalogSnapshot,
		Title:       "Catalog Snapshot",
		Description: "Return loaded module catalog details, including config path, module IDs, provider modules, and load errors.",
		Annotations: readOnlyTool("Catalog Snapshot"),
	}, s.catalogSnapshot)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolModuleSearch,
		Title:       "Search Modules",
		Description: "Search the effective module catalog by ID, summary, tags, and optional module-authored context.",
		Annotations: readOnlyTool("Search Modules"),
	}, s.moduleSearch)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolModuleInspect,
		Title:       "Inspect Module",
		Description: "Return full structured context for one module, including config requirements and step contracts.",
		Annotations: readOnlyTool("Inspect Module"),
	}, s.moduleInspect)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolChainSuggest,
		Title:       "Suggest Chain",
		Description: "Return read-only chain candidates and hovel_chain_apply drafts from catalog context.",
		Annotations: readOnlyTool("Suggest Chain"),
	}, s.chainSuggest)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolLaunchKeyPolicy,
		Title:       "Launch-Key Policy",
		Description: "Return the effective launch-key policy for an operation. MCP cannot change this policy.",
		Annotations: readOnlyTool("Launch-Key Policy"),
	}, s.launchKeyPolicy)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolChainApply,
		Title:       "Apply Chain State",
		Description: "Idempotently create/select an operation and chain, add missing modules and targets, set config, and validate.",
		Annotations: destructiveTool("Apply Chain State"),
	}, s.chainApply)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:         ToolCommandRun,
		Title:        "Run Hovel Command",
		Description:  "Run one Hovel command-mode command through the daemon-backed MCP operator session. Use this for setup and inspection commands such as op use, chain create, chain add, target add, target config set, chain config set, validate, payloads list for provider-buildable payloads, payloads installed for installed payload records, artifacts list, and chain logs. Pass args without a leading hovel or run.",
		Annotations:  destructiveTool("Run Hovel Command"),
		OutputSchema: commandRunOutputSchema(),
	}, s.commandRun)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolThrowPlan,
		Title:       "Plan Throw",
		Description: "Create or refresh a persisted throw plan and launch-key pending approval record without executing.",
		Annotations: destructiveTool("Plan Throw"),
	}, s.throwPlan)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolThrowConfirm,
		Title:       "Confirm Throw",
		Description: "Approve a pending throw for this MCP entity with an explicit nuclear key string and exact plan hash.",
		Annotations: destructiveTool("Confirm Throw"),
	}, s.throwConfirm)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolThrowStart,
		Title:       "Start Throw",
		Description: "Start a throw for the selected operation and chain after explicit MCP caller confirmation.",
		Annotations: destructiveTool("Start Throw"),
	}, s.throwStart)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolInstalledPayloadList,
		Title:       "List Installed Payloads",
		Description: "List installed payload handles and provider readiness for the workspace.",
		Annotations: readOnlyTool("List Installed Payloads"),
	}, s.installedPayloadList)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolSessionCapabilities,
		Title:       "List Session Capabilities",
		Description: "List typed capabilities exposed by an active session. This uses the session task channel, not the interactive byte stream.",
		Annotations: readOnlyTool("List Session Capabilities"),
	}, s.sessionCapabilities)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolSessionCall,
		Title:       "Call Session Capability",
		Description: "Call a typed capability exposed by an active session without writing to or reading from the interactive PTY stream.",
		Annotations: destructiveTool("Call Session Capability"),
	}, s.sessionCall)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCmd,
		Title:       "Run Payload Cmd",
		Description: "Legacy compatibility shim for calling the provider-owned cmd command. Prefer hovel_payload_capabilities and hovel_payload_call for provider-neutral payload actions.",
		Annotations: destructiveTool("Run Payload Cmd"),
	}, s.payloadCmd)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCapabilities,
		Title:       "List Payload Capabilities",
		Description: "List provider-owned payload actions and their advertised capabilities for an installed payload handle.",
		Annotations: readOnlyTool("List Payload Capabilities"),
	}, s.payloadCapabilities)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCall,
		Title:       "Call Payload Capability",
		Description: "Call a provider-owned payload action against an installed payload handle. Hovel brokers the call; the provider owns command semantics and payload transport.",
		Annotations: destructiveTool("Call Payload Capability"),
	}, s.payloadCall)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCommandList,
		Title:       "List Payload Commands",
		Description: "Compatibility alias for hovel_payload_capabilities.",
		Annotations: readOnlyTool("List Payload Commands"),
	}, s.payloadCommandList)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCommandCall,
		Title:       "Call Payload Command",
		Description: "Compatibility alias for hovel_payload_call.",
		Annotations: destructiveTool("Call Payload Command"),
	}, s.payloadCommandCall)
}

type emptyInput struct{}

type operationContextInput struct {
	Operation string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to this MCP operator's current operation, then the daemon default."`
	Chain     string `json:"chain,omitempty" jsonschema:"Optional chain name within the selected operation. Defaults to this MCP operator's active chain."`
}

type workspaceSnapshotInput struct {
	Operation      string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to this MCP operator's current operation, then the daemon default."`
	Chain          string `json:"chain,omitempty" jsonschema:"Optional chain name within the selected operation. Defaults to this MCP operator's active chain."`
	IncludeCatalog bool   `json:"includeCatalog,omitempty" jsonschema:"Include the full module catalog snapshot. Defaults to false to keep MCP context concise."`
}

type listEntitiesInput struct {
	Operation string `json:"operation,omitempty" jsonschema:"Optional operation name to filter entities."`
}

type throwStartInput struct {
	Operation      string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to this MCP operator's current operation, then the daemon default."`
	Chain          string `json:"chain,omitempty" jsonschema:"Optional chain name. Defaults to this MCP operator's active chain."`
	NowBypass      bool   `json:"nowBypass" jsonschema:"Must be true to bypass the typed local confirmation prompt; Hovel still records an auditable confirmation for the bypass."`
	AllowDangerous bool   `json:"allowDangerous,omitempty" jsonschema:"Set true only when the caller explicitly authorized modules tagged dangerous."`
}

type throwPlanInput struct {
	Operation      string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to current operation."`
	Chain          string `json:"chain,omitempty" jsonschema:"Chain name. Defaults to current chain."`
	AllowDangerous bool   `json:"allowDangerous,omitempty" jsonschema:"Whether dangerous modules are explicitly authorized for this plan."`
	NowBypass      bool   `json:"nowBypass,omitempty" jsonschema:"Whether the later start is expected to use an auditable now bypass."`
}

type throwConfirmInput struct {
	PendingID      string `json:"pendingId" jsonschema:"Pending throw ID returned by hovel_throw_plan."`
	PlanHash       string `json:"planHash" jsonschema:"Exact plan hash returned by hovel_throw_plan."`
	NuclearKey     string `json:"nuclearKey" jsonschema:"Explicit caller-provided approval phrase; must be non-empty."`
	AllowDangerous bool   `json:"allowDangerous,omitempty" jsonschema:"Must match the planned dangerous-module flag."`
	NowBypass      bool   `json:"nowBypass,omitempty" jsonschema:"Must match the planned now-bypass flag."`
}

type payloadCommandListInput struct {
	Payload string `json:"payload" jsonschema:"Installed payload handle or record ID."`
}

type sessionCommandListInput struct {
	Session string `json:"session" jsonschema:"Session ID. Use hovel_command_run with [\"session\",\"list\"] to discover active sessions."`
}

type sessionCommandCallInput struct {
	Session       string   `json:"session" jsonschema:"Session ID. Use hovel_session_capabilities first to discover supported actions."`
	Capability    string   `json:"capability,omitempty" jsonschema:"Session-owned capability or action name. Used by hovel_session_call when command is omitted."`
	Command       string   `json:"command,omitempty" jsonschema:"Session-owned command name. Compatibility name for capability/action."`
	Args          []string `json:"args,omitempty" jsonschema:"Command arguments."`
	InputData     string   `json:"inputData,omitempty" jsonschema:"Optional UTF-8 input data for upload-style commands."`
	InputEncoding string   `json:"inputEncoding,omitempty" jsonschema:"Encoding for inputData; defaults to utf-8."`
}

type payloadCommandCallInput struct {
	Payload       string   `json:"payload" jsonschema:"Installed payload handle or record ID."`
	Capability    string   `json:"capability,omitempty" jsonschema:"Provider-owned payload capability or action name. Used by hovel_payload_call when command is omitted."`
	Command       string   `json:"command,omitempty" jsonschema:"Provider-owned payload command name. Compatibility name for capability/action."`
	Args          []string `json:"args,omitempty" jsonschema:"Command arguments."`
	InputData     string   `json:"inputData,omitempty" jsonschema:"Optional UTF-8 input data for upload-style commands."`
	InputEncoding string   `json:"inputEncoding,omitempty" jsonschema:"Encoding for inputData; defaults to utf-8."`
}

type commandRunInput struct {
	Args      []string `json:"args" jsonschema:"Command arguments without leading hovel or run. Examples: [\"op\",\"use\",\"lab\"], [\"chain\",\"create\",\"ms17-010-squatter\"], [\"target\",\"add\",\"192.168.122.142\"]."`
	Operation string   `json:"operation,omitempty" jsonschema:"Optional operation context to select before running the command. Defaults to this MCP operator's current operation."`
	Chain     string   `json:"chain,omitempty" jsonschema:"Optional chain context to select before running the command. Defaults to this MCP operator's active chain."`
}

type moduleSearchInput struct {
	Query string `json:"query,omitempty" jsonschema:"Search text from the caller's intent, target, platform, CVE, or desired capability."`
	Type  string `json:"type,omitempty" jsonschema:"Optional module type filter: survey, exploit, or payload_provider."`
}

type moduleInspectInput struct {
	Module string `json:"module" jsonschema:"Module ID or latest-version alias."`
}

type chainSuggestInput struct {
	Intent  string   `json:"intent,omitempty" jsonschema:"Caller intent for the chain."`
	Targets []string `json:"targets,omitempty" jsonschema:"Known target identifiers or hosts."`
	Query   string   `json:"query,omitempty" jsonschema:"Optional additional catalog search query."`
}

type chainApplyInput struct {
	Operation             string                       `json:"operation,omitempty" jsonschema:"Operation to create/select. Defaults to current operation, then default."`
	Chain                 string                       `json:"chain" jsonschema:"Chain to create/select."`
	Modules               []string                     `json:"modules,omitempty" jsonschema:"Module IDs to ensure in the chain, in order."`
	Targets               []string                     `json:"targets,omitempty" jsonschema:"Targets to ensure in the operation."`
	ChainConfig           map[string]string            `json:"chainConfig,omitempty" jsonschema:"Chain config values to set."`
	TargetConfigs         map[string]map[string]string `json:"targetConfigs,omitempty" jsonschema:"Per-target config values to set."`
	AllowDuplicateModules bool                         `json:"allowDuplicateModules,omitempty" jsonschema:"If false, modules already present in the chain are not added again."`
	SkipValidate          bool                         `json:"skipValidate,omitempty" jsonschema:"If true, do not run chain validate after applying state."`
	IncludeCatalog        bool                         `json:"includeCatalog,omitempty" jsonschema:"Include the full module catalog in the returned snapshot. Defaults to false."`
}

type installedPayloadListInput struct {
	Operation      string `json:"operation,omitempty" jsonschema:"Optional operation filter. Defaults to current operation."`
	Chain          string `json:"chain,omitempty" jsonschema:"Optional chain filter. Defaults to current chain."`
	State          string `json:"state,omitempty" jsonschema:"Optional installed payload state filter."`
	IncludeRemoved bool   `json:"includeRemoved,omitempty" jsonschema:"Include removed payload records."`
	IncludeCatalog bool   `json:"includeCatalog,omitempty" jsonschema:"Include provider catalog details. Defaults to false to keep MCP context concise."`
}

type payloadCmdInput struct {
	Payload string `json:"payload" jsonschema:"Installed payload handle or record ID."`
	Command string `json:"command" jsonschema:"cmd.exe command line to run, for example systeminfo."`
}

type operatorIdentityOutput struct {
	Entity daemonrpc.OperatorEntity `json:"entity"`
}

type operatorListEntitiesOutput struct {
	Operation string                     `json:"operation,omitempty"`
	Entities  []daemonrpc.OperatorEntity `json:"entities"`
}

type operationListOutput struct {
	ActiveOperation string            `json:"activeOperation,omitempty"`
	ActiveChain     string            `json:"activeChain,omitempty"`
	Operations      []operationOutput `json:"operations"`
}

type workspaceSnapshotOutput struct {
	Entity          daemonrpc.OperatorEntity `json:"entity"`
	ActiveOperation string                   `json:"activeOperation,omitempty"`
	ActiveChain     string                   `json:"activeChain,omitempty"`
	Operations      []operationOutput        `json:"operations"`
	Catalog         *catalogSnapshotOutput   `json:"catalog,omitempty"`
	Installed       []installedPayloadStatus `json:"installedPayloads,omitempty"`
}

type catalogSnapshotOutput struct {
	ConfigPath       string         `json:"configPath,omitempty"`
	LoadError        string         `json:"loadError,omitempty"`
	Modules          []moduleOutput `json:"modules"`
	PayloadProviders []moduleOutput `json:"payloadProviders"`
}

type moduleOutput struct {
	ID           string                       `json:"id"`
	Name         string                       `json:"name,omitempty"`
	Type         string                       `json:"type"`
	Version      string                       `json:"version,omitempty"`
	Summary      string                       `json:"summary,omitempty"`
	Description  string                       `json:"description,omitempty"`
	Tags         []string                     `json:"tags,omitempty"`
	Enabled      bool                         `json:"enabled"`
	Dangerous    bool                         `json:"dangerous,omitempty"`
	ChainConfig  []modulecatalog.Requirement  `json:"chainConfig,omitempty"`
	TargetConfig []modulecatalog.Requirement  `json:"targetConfig,omitempty"`
	Discovery    *modulecatalog.Context       `json:"discoveryContext,omitempty"`
	Planning     *modulecatalog.Context       `json:"planningContext,omitempty"`
	Steps        []commands.ModuleStepPayload `json:"steps,omitempty"`
}

type moduleSearchOutput struct {
	Query   string         `json:"query,omitempty"`
	Modules []moduleOutput `json:"modules"`
}

type moduleInspectOutput struct {
	Module moduleOutput `json:"module"`
}

type chainSuggestOutput struct {
	Intent         string                    `json:"intent,omitempty"`
	Query          string                    `json:"query,omitempty"`
	Matches        chainSuggestMatchesOutput `json:"matches"`
	RequiredConfig []configRequirementOutput `json:"requiredConfig,omitempty"`
	Candidates     []chainSuggestionOutput   `json:"candidates,omitempty"`
	NextActions    []toolCallHint            `json:"nextActions,omitempty"`
}

type chainSuggestMatchesOutput struct {
	SurveyModules    []moduleMatchOutput `json:"surveyModules,omitempty"`
	ExploitModules   []moduleMatchOutput `json:"exploitModules,omitempty"`
	PayloadProviders []moduleMatchOutput `json:"payloadProviders,omitempty"`
	OtherModules     []moduleMatchOutput `json:"otherModules,omitempty"`
}

type moduleMatchOutput struct {
	ID           string                         `json:"id"`
	Name         string                         `json:"name,omitempty"`
	Type         string                         `json:"type"`
	Version      string                         `json:"version,omitempty"`
	Summary      string                         `json:"summary,omitempty"`
	Tags         []string                       `json:"tags,omitempty"`
	Dangerous    bool                           `json:"dangerous,omitempty"`
	ChainConfig  []modulecatalog.Requirement    `json:"chainConfig,omitempty"`
	TargetConfig []modulecatalog.Requirement    `json:"targetConfig,omitempty"`
	MatchReasons []string                       `json:"matchReasons,omitempty"`
	Examples     []modulecatalog.ContextExample `json:"examples,omitempty"`
}

type chainSuggestionOutput struct {
	Summary    string                     `json:"summary,omitempty"`
	Modules    []string                   `json:"modules"`
	Targets    []string                   `json:"targets,omitempty"`
	ChainApply chainApplyInput            `json:"chainApply"`
	Risk       *modulecatalog.RiskContext `json:"risk,omitempty"`
}

type operationOutput struct {
	Name          string                       `json:"name"`
	Targets       []string                     `json:"targets,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	TargetSets    []operatorsession.TargetSet  `json:"targetSets,omitempty"`
	Chains        []chainOutput                `json:"chains"`
}

type chainOutput struct {
	Name          string                       `json:"name"`
	Targets       []string                     `json:"targets,omitempty"`
	Steps         []operatorsession.Step       `json:"steps,omitempty"`
	Config        map[string]string            `json:"config,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	LogTopic      string                       `json:"logTopic,omitempty"`
}

type throwStartOutput struct {
	Operation         string                    `json:"operation,omitempty"`
	Summary           throwSummaryOutput        `json:"summary"`
	Plan              commands.ThrowPlanPayload `json:"plan"`
	ThrowID           string                    `json:"throwId,omitempty"`
	Chain             string                    `json:"chain"`
	Targets           []string                  `json:"targets"`
	Results           []commands.RunPayload     `json:"results"`
	InstalledPayloads []installedPayloadStatus  `json:"installedPayloads,omitempty"`
	Next              []string                  `json:"next,omitempty"`
	NextActions       []toolCallHint            `json:"nextActions,omitempty"`
}

type throwPlanOutput struct {
	Operation string                            `json:"operation,omitempty"`
	Chain     string                            `json:"chain"`
	Plan      commands.ThrowPlanPayload         `json:"plan"`
	Pending   daemonrpc.PendingThrowResponse    `json:"pending"`
	Policy    daemonrpc.LaunchKeyPolicyResponse `json:"policy"`
	Preflight throwPreflightOutput              `json:"preflight"`
}

type throwConfirmOutput struct {
	Pending            daemonrpc.PendingThrowResponse `json:"pending"`
	NuclearKeyAccepted bool                           `json:"nuclearKeyAccepted"`
}

type sessionCommandListOutput struct {
	Session  string               `json:"session"`
	Commands []run.PayloadCommand `json:"commands"`
}

type sessionCommandCallOutput struct {
	Session    string                   `json:"session"`
	Invocation payloadCommandInvocation `json:"invocation"`
	Result     run.PayloadCommandResult `json:"result"`
}

type payloadCommandListOutput struct {
	Payload  commands.InstalledPayloadRecord `json:"payload"`
	Commands []run.PayloadCommand            `json:"commands"`
}

type payloadCommandCallOutput struct {
	Payload    commands.InstalledPayloadRecord `json:"payload"`
	Invocation payloadCommandInvocation        `json:"invocation"`
	Result     run.PayloadCommandResult        `json:"result"`
}

type commandRunOutput struct {
	Args      []string `json:"args"`
	Operation string   `json:"operation,omitempty"`
	Chain     string   `json:"chain,omitempty"`
	ExitCode  int      `json:"exitCode"`
	OK        bool     `json:"ok"`
	Stdout    string   `json:"stdout,omitempty"`
	Stderr    string   `json:"stderr,omitempty"`
	JSON      any      `json:"json,omitempty"`
}

func commandRunOutputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"args": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
			"operation": map[string]any{"type": "string"},
			"chain":     map[string]any{"type": "string"},
			"exitCode":  map[string]any{"type": "integer"},
			"ok":        map[string]any{"type": "boolean"},
			"stdout":    map[string]any{"type": "string"},
			"stderr":    map[string]any{"type": "string"},
			"json":      anyJSONValueSchema("Decoded JSON from stdout when the command emits valid JSON."),
		},
		"required":             []string{"args", "exitCode", "ok"},
		"additionalProperties": false,
	}
}

func anyJSONValueSchema(description string) map[string]any {
	return map[string]any{
		"description": description,
		"anyOf": []any{
			map[string]any{"type": "object"},
			map[string]any{"type": "array"},
			map[string]any{"type": "string"},
			map[string]any{"type": "number"},
			map[string]any{"type": "boolean"},
			map[string]any{"type": "null"},
		},
	}
}

type chainApplyOutput struct {
	Operation      string                  `json:"operation"`
	Chain          string                  `json:"chain"`
	AddedSteps     []operatorsession.Step  `json:"addedSteps,omitempty"`
	SkippedModules []string                `json:"skippedModules,omitempty"`
	Targets        []string                `json:"targets,omitempty"`
	Validation     *chainValidationOutput  `json:"validation,omitempty"`
	Snapshot       workspaceSnapshotOutput `json:"snapshot"`
	NextActions    []toolCallHint          `json:"nextActions,omitempty"`
}

type installedPayloadListOutput struct {
	Operation string                   `json:"operation,omitempty"`
	Chain     string                   `json:"chain,omitempty"`
	Records   []installedPayloadStatus `json:"records"`
	Catalog   *catalogSnapshotOutput   `json:"catalog,omitempty"`
}

type installedPayloadStatus struct {
	Record             commands.InstalledPayloadRecord `json:"record"`
	ProviderConfigured bool                            `json:"providerConfigured"`
	ProviderError      string                          `json:"providerError,omitempty"`
	Next               []string                        `json:"next,omitempty"`
	NextActions        []toolCallHint                  `json:"nextActions,omitempty"`
}

type payloadCmdOutput struct {
	Payload    commands.InstalledPayloadRecord `json:"payload"`
	Command    string                          `json:"command"`
	Invocation payloadCommandInvocation        `json:"invocation"`
	Result     run.PayloadCommandResult        `json:"result"`
}

type chainValidationOutput struct {
	Valid   bool                  `json:"valid"`
	Issues  []modulecatalog.Issue `json:"issues,omitempty"`
	Human   string                `json:"human,omitempty"`
	Command *commandRunOutput     `json:"command,omitempty"`
}

type throwPreflightOutput struct {
	Targets                []string                   `json:"targets,omitempty"`
	Steps                  []chainStepPreflightOutput `json:"steps,omitempty"`
	DangerousModules       []string                   `json:"dangerousModules,omitempty"`
	RequiresAllowDangerous bool                       `json:"requiresAllowDangerous,omitempty"`
	AllowDangerous         bool                       `json:"allowDangerous"`
	NowBypass              bool                       `json:"nowBypass"`
	RequiredConfirmations  []string                   `json:"requiredConfirmations,omitempty"`
	RequiredApproverIDs    []string                   `json:"requiredApproverIds,omitempty"`
	MissingApproverIDs     []string                   `json:"missingApproverIds,omitempty"`
	RequiredConfig         []configRequirementOutput  `json:"requiredConfig,omitempty"`
	EffectiveConfig        []effectiveConfigOutput    `json:"effectiveConfig,omitempty"`
	PayloadConfig          []effectiveConfigOutput    `json:"payloadConfig,omitempty"`
	ExpectedOutputs        []expectedOutputOutput     `json:"expectedOutputs,omitempty"`
	Warnings               []string                   `json:"warnings,omitempty"`
}

type chainStepPreflightOutput struct {
	ID        string `json:"id,omitempty"`
	ModuleID  string `json:"moduleId"`
	StepID    string `json:"stepId,omitempty"`
	Type      string `json:"type,omitempty"`
	Summary   string `json:"summary,omitempty"`
	Dangerous bool   `json:"dangerous,omitempty"`
}

type configRequirementOutput struct {
	Module      string                  `json:"module"`
	Scope       string                  `json:"scope"`
	Key         string                  `json:"key"`
	Type        modulecatalog.ValueType `json:"type,omitempty"`
	Required    bool                    `json:"required,omitempty"`
	Default     string                  `json:"default,omitempty"`
	Description string                  `json:"description,omitempty"`
	Allowed     []string                `json:"allowed,omitempty"`
	Secret      bool                    `json:"secret,omitempty"`
}

type effectiveConfigOutput struct {
	Module   string                  `json:"module"`
	Scope    string                  `json:"scope"`
	Target   string                  `json:"target,omitempty"`
	Key      string                  `json:"key"`
	Value    string                  `json:"value,omitempty"`
	Source   string                  `json:"source,omitempty"`
	Type     modulecatalog.ValueType `json:"type,omitempty"`
	Required bool                    `json:"required,omitempty"`
	Default  string                  `json:"default,omitempty"`
	Missing  bool                    `json:"missing,omitempty"`
}

type expectedOutputOutput struct {
	Module        string                       `json:"module"`
	StepID        string                       `json:"stepId,omitempty"`
	Type          modulecatalog.CapabilityType `json:"type"`
	SchemaVersion string                       `json:"schemaVersion,omitempty"`
	States        []string                     `json:"states,omitempty"`
	Attributes    map[string]any               `json:"attributes,omitempty"`
}

type throwSummaryOutput struct {
	Targets  []throwTargetSummary   `json:"targets,omitempty"`
	Payloads []payloadSummaryOutput `json:"payloads,omitempty"`
}

type throwTargetSummary struct {
	Target  string `json:"target"`
	State   string `json:"state,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type payloadSummaryOutput struct {
	Handle            string `json:"handle,omitempty"`
	ID                string `json:"id,omitempty"`
	Provider          string `json:"provider,omitempty"`
	Target            string `json:"target,omitempty"`
	State             string `json:"state,omitempty"`
	Transport         string `json:"transport,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	SupportsReconnect bool   `json:"supportsReconnect,omitempty"`
}

type payloadCommandInvocation struct {
	ProviderCommand string   `json:"providerCommand"`
	Args            []string `json:"args,omitempty"`
	Semantics       string   `json:"semantics"`
}

type toolCallHint struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Reason    string         `json:"reason,omitempty"`
}

func (s *Server) operatorIdentity(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, operatorIdentityOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, operatorIdentityOutput{}, err
	}
	return nil, operatorIdentityOutput{Entity: s.currentEntity()}, nil
}

func (s *Server) operatorListEntities(ctx context.Context, _ *mcpsdk.CallToolRequest, input listEntitiesInput) (*mcpsdk.CallToolResult, operatorListEntitiesOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, operatorListEntitiesOutput{}, err
	}
	operation := strings.TrimSpace(input.Operation)
	resp, err := s.daemon.ListEntities(ctx, daemonrpc.ListEntitiesRequest{Operation: operation})
	if err != nil {
		return nil, operatorListEntitiesOutput{}, err
	}
	return nil, operatorListEntitiesOutput{Operation: operation, Entities: resp.Entities}, nil
}

func (s *Server) operationList(ctx context.Context, _ *mcpsdk.CallToolRequest, input operationContextInput) (*mcpsdk.CallToolResult, operationListOutput, error) {
	snapshot, err := s.snapshot(ctx, input)
	if err != nil {
		return nil, operationListOutput{}, err
	}
	return nil, operationListOutput{
		ActiveOperation: snapshot.ActiveOperation,
		ActiveChain:     snapshot.ActiveChain,
		Operations:      operationOutputs(snapshot.Operations),
	}, nil
}

func (s *Server) workspaceSnapshot(ctx context.Context, _ *mcpsdk.CallToolRequest, input workspaceSnapshotInput) (*mcpsdk.CallToolResult, workspaceSnapshotOutput, error) {
	snapshot, err := s.snapshot(ctx, operationContextInput{Operation: input.Operation, Chain: input.Chain})
	if err != nil {
		return nil, workspaceSnapshotOutput{}, err
	}
	operation := contextOperation(input.Operation, snapshot.ActiveOperation)
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = snapshot.ActiveChain
	}
	installed, _, err := s.installedPayloadStatuses(ctx, operation, chain, "", false)
	logMCPError("read installed payload statuses", err)
	out := workspaceSnapshotOutput{
		Entity:          s.currentEntity(),
		ActiveOperation: snapshot.ActiveOperation,
		ActiveChain:     snapshot.ActiveChain,
		Operations:      operationOutputs(snapshot.Operations),
		Installed:       installed,
	}
	if input.IncludeCatalog {
		catalog := s.catalogSnapshotValue(ctx)
		out.Catalog = &catalog
	}
	return nil, out, nil
}

func (s *Server) catalogSnapshot(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, catalogSnapshotOutput, error) {
	return nil, s.catalogSnapshotValue(ctx), nil
}

func (s *Server) moduleSearch(ctx context.Context, _ *mcpsdk.CallToolRequest, input moduleSearchInput) (*mcpsdk.CallToolResult, moduleSearchOutput, error) {
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "list"})
	if err != nil {
		return nil, moduleSearchOutput{}, err
	}
	modules := catalog.Search(input.Query)
	if strings.TrimSpace(input.Type) != "" {
		filtered := modules[:0]
		for _, module := range modules {
			if string(module.Type) == strings.TrimSpace(input.Type) {
				filtered = append(filtered, module)
			}
		}
		modules = filtered
	}
	return nil, moduleSearchOutput{
		Query:   strings.TrimSpace(input.Query),
		Modules: moduleOutputs(modules),
	}, nil
}

func (s *Server) moduleInspect(ctx context.Context, _ *mcpsdk.CallToolRequest, input moduleInspectInput) (*mcpsdk.CallToolResult, moduleInspectOutput, error) {
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "inspect"})
	if err != nil {
		return nil, moduleInspectOutput{}, err
	}
	module, ok := catalog.Find(input.Module)
	if !ok {
		return nil, moduleInspectOutput{}, fmt.Errorf("module %s does not exist", input.Module)
	}
	return nil, moduleInspectOutput{Module: moduleOutputFromModuleWithSteps(module, catalog)}, nil
}

func (s *Server) chainSuggest(ctx context.Context, _ *mcpsdk.CallToolRequest, input chainSuggestInput) (*mcpsdk.CallToolResult, chainSuggestOutput, error) {
	query := strings.TrimSpace(strings.Join([]string{input.Intent, input.Query, strings.Join(input.Targets, " ")}, " "))
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "list"})
	if err != nil {
		return nil, chainSuggestOutput{}, err
	}
	matches := catalogMatchesForQuery(catalog, query)
	candidates := chainSuggestionCandidatesFromExamples(catalog, query, input)
	required := requiredConfigForMatches(matches)
	next := []toolCallHint{{
		Tool: ToolModuleSearch,
		Arguments: map[string]any{
			"query": query,
		},
		Reason: "Search matching module metadata directly.",
	}}
	for _, module := range firstMatchedModules(matches, 3) {
		next = append(next, toolCallHint{
			Tool:      ToolModuleInspect,
			Arguments: map[string]any{"module": module.ID},
			Reason:    "Inspect full module-authored context and contracts.",
		})
	}
	return nil, chainSuggestOutput{
		Intent:         strings.TrimSpace(input.Intent),
		Query:          query,
		Matches:        matches,
		RequiredConfig: required,
		Candidates:     candidates,
		NextActions:    next,
	}, nil
}

func (s *Server) launchKeyPolicy(ctx context.Context, _ *mcpsdk.CallToolRequest, input operationContextInput) (*mcpsdk.CallToolResult, daemonrpc.LaunchKeyPolicyResponse, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, daemonrpc.LaunchKeyPolicyResponse{}, err
	}
	operation := contextOperation(input.Operation, s.currentOperation())
	out, err := s.daemon.GetLaunchKeyPolicy(ctx, daemonrpc.LaunchKeyPolicyRequest{Operation: operation})
	if err != nil {
		return nil, daemonrpc.LaunchKeyPolicyResponse{}, err
	}
	return nil, out, nil
}

func (s *Server) chainApply(ctx context.Context, _ *mcpsdk.CallToolRequest, input chainApplyInput) (*mcpsdk.CallToolResult, chainApplyOutput, error) {
	operation := contextOperation(input.Operation, s.currentOperation())
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		return nil, chainApplyOutput{}, errors.New("chain is required")
	}
	if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Args: []string{"op", "use", operation}}); err != nil {
		return nil, chainApplyOutput{}, err
	}
	if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Args: []string{"chain", "use", chain}}); err != nil {
		return nil, chainApplyOutput{}, err
	}

	added, skipped, err := s.applyModules(ctx, operation, chain, input.Modules, input.AllowDuplicateModules)
	if err != nil {
		return nil, chainApplyOutput{}, err
	}
	for _, target := range input.Targets {
		if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"target", "add", target}}); err != nil {
			return nil, chainApplyOutput{}, err
		}
	}
	if err := s.applyChainConfig(ctx, operation, chain, input.ChainConfig); err != nil {
		return nil, chainApplyOutput{}, err
	}
	if err := s.applyTargetConfigs(ctx, operation, chain, input.TargetConfigs); err != nil {
		return nil, chainApplyOutput{}, err
	}
	if err := s.applyTargetHostDefaults(ctx, operation, chain); err != nil {
		return nil, chainApplyOutput{}, err
	}
	if err := s.applySchemaDefaults(ctx, operation, chain); err != nil {
		return nil, chainApplyOutput{}, err
	}

	var validation *chainValidationOutput
	if !input.SkipValidate {
		out, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"chain", "validate", "--json"}})
		if err != nil {
			return nil, chainApplyOutput{}, err
		}
		validation = chainValidationFromCommand(out)
	}
	_, snapshot, err := s.workspaceSnapshot(ctx, nil, workspaceSnapshotInput{Operation: operation, Chain: chain, IncludeCatalog: input.IncludeCatalog})
	if err != nil {
		return nil, chainApplyOutput{}, err
	}
	return nil, chainApplyOutput{
		Operation:      operation,
		Chain:          chain,
		AddedSteps:     added,
		SkippedModules: skipped,
		Targets:        append([]string(nil), input.Targets...),
		Validation:     validation,
		Snapshot:       snapshot,
		NextActions: []toolCallHint{
			{
				Tool: ToolThrowPlan,
				Arguments: map[string]any{
					"operation": operation,
					"chain":     chain,
					"nowBypass": true,
				},
				Reason: "Review throw preflight and create a launch-key pending approval record.",
			},
			{
				Tool: ToolWorkspaceSnapshot,
				Arguments: map[string]any{
					"operation": operation,
					"chain":     chain,
				},
				Reason: "Inspect the persisted operation and chain state.",
			},
		},
	}, nil
}

func (s *Server) commandRun(ctx context.Context, _ *mcpsdk.CallToolRequest, input commandRunInput) (*mcpsdk.CallToolResult, commandRunOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, commandRunOutput{}, err
	}
	if s.commandRunner == nil {
		return nil, commandRunOutput{}, errors.New("command execution is not configured for this MCP server")
	}
	args := normalizeMCPCommandArgs(input.Args)
	if len(args) == 0 {
		return nil, commandRunOutput{}, errors.New("args are required")
	}
	if mcpCommandMutatesHumanOnlyPolicy(args) {
		return nil, commandRunOutput{}, errors.New("launch-key policy changes are human-only; use the CLI, not MCP")
	}
	input.Args = args
	if strings.TrimSpace(input.Operation) == "" {
		input.Operation = strings.TrimSpace(s.currentOperation())
	}
	if strings.TrimSpace(input.Chain) == "" {
		input.Chain = strings.TrimSpace(s.currentActiveChain())
	}
	out, err := s.commandRunner(ctx, input)
	if err != nil {
		return nil, commandRunOutput{}, err
	}
	if len(out.Args) == 0 {
		out.Args = append([]string(nil), input.Args...)
	}
	out.OK = out.ExitCode == 0
	if out.ExitCode == 0 {
		out.Operation, out.Chain = commandContextAfter(input.Operation, input.Chain, out.Args)
		if err := s.setContext(ctx, out.Operation, out.Chain); err != nil {
			return nil, commandRunOutput{}, err
		}
	} else {
		out.Operation = strings.TrimSpace(input.Operation)
		out.Chain = strings.TrimSpace(input.Chain)
	}
	return nil, out, nil
}

func mcpCommandMutatesHumanOnlyPolicy(args []string) bool {
	if len(args) < 3 {
		return false
	}
	return strings.TrimSpace(args[0]) == "launch-key" &&
		strings.TrimSpace(args[1]) == "policy" &&
		strings.TrimSpace(args[2]) == "set"
}

func (s *Server) requireCommandOK(ctx context.Context, input commandRunInput) (commandRunOutput, error) {
	_, out, err := s.commandRun(ctx, nil, input)
	if err != nil {
		return commandRunOutput{}, err
	}
	if !out.OK {
		return commandRunOutput{}, commandFailureError(out)
	}
	return out, nil
}

func commandFailureError(out commandRunOutput) error {
	message := strings.TrimSpace(out.Stderr)
	if message == "" {
		message = strings.TrimSpace(out.Stdout)
	}
	if message == "" {
		message = fmt.Sprintf("command exited with status %d", out.ExitCode)
	}
	return errors.New(message)
}

func chainValidationFromCommand(out commandRunOutput) *chainValidationOutput {
	if out.JSON != nil {
		var payload commands.ValidationPayload
		if data, err := json.Marshal(out.JSON); err == nil {
			if err := json.Unmarshal(data, &payload); err == nil {
				return &chainValidationOutput{
					Valid:  payload.Valid,
					Issues: append([]modulecatalog.Issue(nil), payload.Issues...),
				}
			}
		}
	}
	command := out
	return &chainValidationOutput{
		Valid:   out.OK,
		Human:   strings.TrimSpace(out.Stdout),
		Command: &command,
	}
}

func (s *Server) throwPreflight(ctx context.Context, operation, chain string, input throwPlanInput, pending daemonrpc.PendingThrowResponse) throwPreflightOutput {
	details := s.chainPreflightDetails(ctx, operation, chain)
	out := throwPreflightOutput{
		AllowDangerous:      input.AllowDangerous,
		NowBypass:           input.NowBypass,
		RequiredApproverIDs: append([]string(nil), pending.RequiredApproverIDs...),
		MissingApproverIDs:  append([]string(nil), pending.MissingApproverIDs...),
		Targets:             details.Targets,
		Steps:               details.Steps,
		DangerousModules:    details.DangerousModules,
		RequiredConfig:      details.RequiredConfig,
		EffectiveConfig:     details.EffectiveConfig,
		PayloadConfig:       details.PayloadConfig,
		ExpectedOutputs:     details.ExpectedOutputs,
	}
	out.Warnings = append(out.Warnings, details.Warnings...)
	if len(details.DangerousModules) > 0 {
		out.RequiresAllowDangerous = true
		out.RequiredConfirmations = append(out.RequiredConfirmations, "allowDangerous")
		if !input.AllowDangerous {
			out.Warnings = append(out.Warnings, "dangerous modules are present; confirm and start with allowDangerous=true only after human authorization")
		}
	}
	out.RequiredConfirmations = append(out.RequiredConfirmations, "nowBypass")
	if !input.NowBypass {
		out.Warnings = append(out.Warnings, "MCP throw start requires nowBypass=true; hovel_throw_confirm flags must match the planned throw")
	}
	if len(pending.MissingApproverIDs) > 0 {
		out.Warnings = append(out.Warnings, "launch-key approvals are still missing: "+strings.Join(pending.MissingApproverIDs, ", "))
	}
	return out
}

type chainPreflightDetails struct {
	Targets          []string
	Steps            []chainStepPreflightOutput
	DangerousModules []string
	RequiredConfig   []configRequirementOutput
	EffectiveConfig  []effectiveConfigOutput
	PayloadConfig    []effectiveConfigOutput
	ExpectedOutputs  []expectedOutputOutput
	Warnings         []string
}

func (s *Server) chainPreflightDetails(ctx context.Context, operation, chain string) chainPreflightDetails {
	var out chainPreflightDetails
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "list"})
	if err != nil {
		out.Warnings = append(out.Warnings, "could not inspect module catalog: "+err.Error())
		return out
	}
	snapshot, err := s.snapshot(ctx, operationContextInput{Operation: operation, Chain: chain})
	if err != nil {
		out.Warnings = append(out.Warnings, "could not inspect workspace state: "+err.Error())
		return out
	}
	operationState := activeOperation(snapshot, operation)
	chainState := activeChain(snapshot, operation, chain)
	out.Targets = chainPreflightTargets(operationState, chainState)
	dangerous := map[string]bool{}

	for _, step := range chainState.Steps {
		module, ok := catalog.Find(step.ModuleID)
		stepOut := chainStepPreflightOutput{
			ID:       step.ID,
			ModuleID: step.ModuleID,
			StepID:   step.StepID,
		}
		if ok {
			stepOut.ModuleID = module.ID
			stepOut.Type = string(module.Type)
			stepOut.Summary = module.Summary
			stepOut.Dangerous = module.Dangerous()
			if module.Dangerous() {
				dangerous[module.ID] = true
			}
			out.RequiredConfig = append(out.RequiredConfig, requiredConfigForModule(module)...)
			out.EffectiveConfig = append(out.EffectiveConfig, effectiveConfigForModule(module, out.Targets, chainState.Config, operationState.TargetConfigs)...)
			out.ExpectedOutputs = append(out.ExpectedOutputs, expectedOutputsForModule(module)...)
		} else {
			out.Warnings = append(out.Warnings, "module "+step.ModuleID+" is present in the chain but not loaded in the active catalog")
		}
		out.Steps = append(out.Steps, stepOut)
	}

	for moduleID := range dangerous {
		out.DangerousModules = append(out.DangerousModules, moduleID)
	}
	sort.Strings(out.DangerousModules)
	out.RequiredConfig = uniqueConfigRequirements(out.RequiredConfig)
	out.EffectiveConfig = uniqueEffectiveConfig(out.EffectiveConfig)
	out.PayloadConfig = payloadConfigValues(out.EffectiveConfig)
	out.ExpectedOutputs = uniqueExpectedOutputs(out.ExpectedOutputs)
	return out
}

func chainPreflightTargets(operation operatorsession.PersistedOperation, chain operatorsession.PersistedChain) []string {
	targets := append([]string(nil), chain.Targets...)
	if len(targets) == 0 {
		targets = append(targets, operation.Targets...)
	}
	sort.Strings(targets)
	return targets
}

func requiredConfigForModule(module modulecatalog.Module) []configRequirementOutput {
	var out []configRequirementOutput
	for _, req := range module.ChainConfig {
		if req.Required {
			out = append(out, configRequirementFromRequirement(module.ID, modulecatalog.ScopeChain, req))
		}
	}
	for _, req := range module.TargetConfig {
		if req.Required {
			out = append(out, configRequirementFromRequirement(module.ID, modulecatalog.ScopeTarget, req))
		}
	}
	return out
}

func effectiveConfigForModule(module modulecatalog.Module, targets []string, chainConfig map[string]string, targetConfigs map[string]map[string]string) []effectiveConfigOutput {
	var out []effectiveConfigOutput
	for _, req := range module.ChainConfig {
		value, source, missing := effectiveConfigValue(req, chainConfig, "chainConfig")
		out = append(out, effectiveConfigOutput{
			Module:   module.ID,
			Scope:    string(modulecatalog.ScopeChain),
			Key:      req.Key,
			Value:    value,
			Source:   source,
			Type:     req.Type,
			Required: req.Required,
			Default:  req.Default,
			Missing:  missing,
		})
	}
	for _, target := range targets {
		values := targetConfigs[target]
		for _, req := range module.TargetConfig {
			value, source, missing := effectiveTargetConfigValue(req, target, values)
			out = append(out, effectiveConfigOutput{
				Module:   module.ID,
				Scope:    string(modulecatalog.ScopeTarget),
				Target:   target,
				Key:      req.Key,
				Value:    value,
				Source:   source,
				Type:     req.Type,
				Required: req.Required,
				Default:  req.Default,
				Missing:  missing,
			})
		}
	}
	return out
}

func effectiveTargetConfigValue(req modulecatalog.Requirement, target string, values map[string]string) (string, string, bool) {
	if value, ok := values[req.Key]; ok {
		return value, "targetConfig", false
	}
	if req.Key == "target.host" && strings.TrimSpace(target) != "" {
		return target, "target", false
	}
	return effectiveConfigValue(req, values, "targetConfig")
}

func effectiveConfigValue(req modulecatalog.Requirement, values map[string]string, source string) (string, string, bool) {
	if value, ok := values[req.Key]; ok {
		return value, source, false
	}
	if req.Default != "" {
		return req.Default, "moduleDefault", false
	}
	return "", "", req.Required
}

func expectedOutputsForModule(module modulecatalog.Module) []expectedOutputOutput {
	var out []expectedOutputOutput
	for _, step := range module.StepContracts.Steps {
		for _, produced := range step.Produces {
			switch produced.Type {
			case modulecatalog.CapabilityPayloadArtifact, modulecatalog.CapabilityPayloadInstance, modulecatalog.CapabilitySessionRef, modulecatalog.CapabilityTransport:
				out = append(out, expectedOutputOutput{
					Module:        module.ID,
					StepID:        step.ID,
					Type:          produced.Type,
					SchemaVersion: produced.SchemaVersion,
					States:        append([]string(nil), produced.States...),
					Attributes:    cloneAnyMap(produced.Attributes),
				})
			}
		}
	}
	return out
}

func uniqueConfigRequirements(values []configRequirementOutput) []configRequirementOutput {
	seen := map[string]bool{}
	out := make([]configRequirementOutput, 0, len(values))
	for _, value := range values {
		key := value.Module + "\x00" + value.Scope + "\x00" + value.Key
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func uniqueEffectiveConfig(values []effectiveConfigOutput) []effectiveConfigOutput {
	seen := map[string]bool{}
	out := make([]effectiveConfigOutput, 0, len(values))
	for _, value := range values {
		key := strings.Join([]string{value.Module, value.Scope, value.Target, value.Key}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].Module, out[i].Scope, out[i].Target, out[i].Key}, "\x00")
		right := strings.Join([]string{out[j].Module, out[j].Scope, out[j].Target, out[j].Key}, "\x00")
		return left < right
	})
	return out
}

func payloadConfigValues(values []effectiveConfigOutput) []effectiveConfigOutput {
	var out []effectiveConfigOutput
	for _, value := range values {
		if strings.HasPrefix(value.Key, "payload.") {
			out = append(out, value)
		}
	}
	return out
}

func uniqueExpectedOutputs(values []expectedOutputOutput) []expectedOutputOutput {
	seen := map[string]bool{}
	out := make([]expectedOutputOutput, 0, len(values))
	for _, value := range values {
		key := strings.Join([]string{value.Module, value.StepID, string(value.Type), value.SchemaVersion}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].Module, out[i].StepID, string(out[i].Type), out[i].SchemaVersion}, "\x00")
		right := strings.Join([]string{out[j].Module, out[j].StepID, string(out[j].Type), out[j].SchemaVersion}, "\x00")
		return left < right
	})
	return out
}

func throwSummary(results []commands.RunPayload, statuses []installedPayloadStatus) throwSummaryOutput {
	out := throwSummaryOutput{
		Targets:  make([]throwTargetSummary, 0, len(results)),
		Payloads: make([]payloadSummaryOutput, 0, len(statuses)),
	}
	for _, result := range results {
		out.Targets = append(out.Targets, throwTargetSummary{
			Target:  result.Target,
			State:   result.State,
			Summary: result.Summary,
		})
	}
	for _, status := range statuses {
		record := status.Record
		out.Payloads = append(out.Payloads, payloadSummaryOutput{
			Handle:            record.Handle,
			ID:                record.ID,
			Provider:          record.Provider,
			Target:            record.Target,
			State:             record.State,
			Transport:         record.Transport,
			Endpoint:          record.Endpoint,
			SupportsReconnect: record.SupportsReconnect,
		})
	}
	return out
}

func payloadCommandInvocationFor(command string, args []string) payloadCommandInvocation {
	return payloadCommandInvocation{
		ProviderCommand: strings.TrimSpace(command),
		Args:            append([]string(nil), args...),
		Semantics:       "Hovel calls the provider-owned payload command with these arguments; the payload provider defines exact shell, process, and environment-expansion behavior.",
	}
}

func payloadCommandName(input payloadCommandCallInput) string {
	command := strings.TrimSpace(input.Command)
	if command != "" {
		return command
	}
	return strings.TrimSpace(input.Capability)
}

func sessionCommandName(input sessionCommandCallInput) string {
	command := strings.TrimSpace(input.Command)
	if command != "" {
		return command
	}
	return strings.TrimSpace(input.Capability)
}

func catalogMatchesForQuery(catalog modulecatalog.Catalog, query string) chainSuggestMatchesOutput {
	terms := queryTerms(query)
	type scoredModule struct {
		module  modulecatalog.Module
		score   int
		reasons []string
	}
	var scored []scoredModule
	for _, module := range catalog.List() {
		score, reasons := moduleMatchScore(module, terms)
		if len(terms) == 0 || score > 0 {
			scored = append(scored, scoredModule{module: module, score: score, reasons: reasons})
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].module.ID < scored[j].module.ID
	})

	var out chainSuggestMatchesOutput
	for _, item := range scored {
		match := moduleMatchFromModule(item.module, item.reasons)
		switch item.module.Type {
		case modulecatalog.TypeSurvey:
			out.SurveyModules = appendLimited(out.SurveyModules, match, 5)
		case modulecatalog.TypeExploit:
			out.ExploitModules = appendLimited(out.ExploitModules, match, 5)
		case modulecatalog.TypePayloadProvider:
			out.PayloadProviders = appendLimited(out.PayloadProviders, match, 5)
		default:
			out.OtherModules = appendLimited(out.OtherModules, match, 5)
		}
	}
	return out
}

func appendLimited[T any](values []T, value T, limit int) []T {
	if len(values) >= limit {
		return values
	}
	return append(values, value)
}

func moduleMatchFromModule(module modulecatalog.Module, reasons []string) moduleMatchOutput {
	return moduleMatchOutput{
		ID:           module.ID,
		Name:         module.Name,
		Type:         string(module.Type),
		Version:      module.Version,
		Summary:      module.Summary,
		Tags:         append([]string(nil), module.Tags...),
		Dangerous:    module.Dangerous(),
		ChainConfig:  append([]modulecatalog.Requirement(nil), module.ChainConfig...),
		TargetConfig: append([]modulecatalog.Requirement(nil), module.TargetConfig...),
		MatchReasons: uniqueStrings(reasons),
		Examples:     moduleExamples(module),
	}
}

func moduleMatchScore(module modulecatalog.Module, terms []string) (int, []string) {
	if len(terms) == 0 {
		return 1, nil
	}
	fields := []struct {
		name   string
		weight int
		text   string
	}{
		{name: "id", weight: 6, text: module.ID + " " + modulecatalog.ReferenceName(module.ID) + " " + module.Name},
		{name: "tags", weight: 4, text: strings.Join(module.Tags, " ")},
		{name: "summary", weight: 3, text: module.Summary},
		{name: "description", weight: 2, text: module.Description},
		{name: "discoveryContext", weight: 3, text: contextText(module.Discovery)},
		{name: "planningContext", weight: 3, text: contextText(module.Planning)},
		{name: "config", weight: 2, text: requirementText(module.ChainConfig) + " " + requirementText(module.TargetConfig)},
	}
	score := 0
	var reasons []string
	for _, field := range fields {
		text := strings.ToLower(field.text)
		matched := 0
		for _, term := range terms {
			if strings.Contains(text, term) {
				score += field.weight
				matched++
			}
		}
		if matched > 0 {
			reasons = append(reasons, field.name)
		}
	}
	return score, reasons
}

func queryTerms(query string) []string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, term := range strings.FieldsFunc(query, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= '0' && r <= '9':
			return false
		default:
			return true
		}
	}) {
		term = strings.TrimSpace(term)
		if len(term) < 2 || seen[term] {
			continue
		}
		seen[term] = true
		out = append(out, term)
	}
	sort.Strings(out)
	return out
}

func contextText(context modulecatalog.Context) string {
	parts := []string{
		context.Summary,
		strings.Join(context.Keywords, " "),
		strings.Join(context.Platforms, " "),
		strings.Join(context.Targets, " "),
		strings.Join(context.Capabilities, " "),
		strings.Join(context.Preconditions, " "),
		strings.Join(context.SideEffects, " "),
		context.Cleanup,
		context.Risk.Level,
		strings.Join(context.Risk.Reasons, " "),
	}
	for _, example := range context.Examples {
		parts = append(parts, example.Name, example.Description, strings.Join(example.Modules, " "))
	}
	for _, hint := range context.AgentHints {
		parts = append(parts, hint.Schema, hint.Phase, hint.Audience, hint.Risk, hint.Text)
	}
	return strings.Join(parts, " ")
}

func requirementText(requirements []modulecatalog.Requirement) string {
	parts := make([]string, 0, len(requirements)*3)
	for _, req := range requirements {
		parts = append(parts, req.Key, string(req.Type), req.Description, strings.Join(req.Allowed, " "))
	}
	return strings.Join(parts, " ")
}

func moduleExamples(module modulecatalog.Module) []modulecatalog.ContextExample {
	examples := append([]modulecatalog.ContextExample(nil), module.Discovery.Examples...)
	examples = append(examples, module.Planning.Examples...)
	return examples
}

func chainSuggestionCandidatesFromExamples(catalog modulecatalog.Catalog, query string, input chainSuggestInput) []chainSuggestionOutput {
	terms := queryTerms(query)
	var out []chainSuggestionOutput
	seen := map[string]bool{}
	for _, module := range catalog.List() {
		for _, example := range moduleExamples(module) {
			modules := validExampleModules(catalog, example.Modules)
			if len(modules) == 0 || !exampleMatches(example, terms) {
				continue
			}
			key := strings.Join(modules, "\x00") + "\x00" + example.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			summary := strings.TrimSpace(example.Description)
			if summary == "" {
				summary = strings.TrimSpace(example.Name)
			}
			apply := chainApplyInput{
				Chain:       suggestedChainName(firstNonEmpty(example.Name, input.Intent), modules[0]),
				Modules:     modules,
				Targets:     append([]string(nil), input.Targets...),
				ChainConfig: cloneStringMap(example.ChainConfig),
			}
			candidate := chainSuggestionOutput{
				Summary:    summary,
				Modules:    modules,
				Targets:    append([]string(nil), input.Targets...),
				ChainApply: apply,
			}
			if module.Planning.Risk.Level != "" {
				risk := module.Planning.Risk
				candidate.Risk = &risk
			}
			out = append(out, candidate)
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func exampleMatches(example modulecatalog.ContextExample, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	text := strings.ToLower(strings.Join([]string{
		example.Name,
		example.Description,
		strings.Join(example.Modules, " "),
	}, " "))
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func validExampleModules(catalog modulecatalog.Catalog, modules []string) []string {
	out := make([]string, 0, len(modules))
	for _, moduleID := range modules {
		module, ok := catalog.Find(moduleID)
		if !ok {
			return nil
		}
		out = append(out, module.ID)
	}
	return out
}

func requiredConfigForMatches(matches chainSuggestMatchesOutput) []configRequirementOutput {
	seen := map[string]bool{}
	var out []configRequirementOutput
	for _, module := range allMatchedModules(matches) {
		for _, req := range module.ChainConfig {
			if req.Required {
				item := configRequirementFromRequirement(module.ID, modulecatalog.ScopeChain, req)
				key := item.Module + "\x00" + item.Scope + "\x00" + item.Key
				if !seen[key] {
					seen[key] = true
					out = append(out, item)
				}
			}
		}
		for _, req := range module.TargetConfig {
			if req.Required {
				item := configRequirementFromRequirement(module.ID, modulecatalog.ScopeTarget, req)
				key := item.Module + "\x00" + item.Scope + "\x00" + item.Key
				if !seen[key] {
					seen[key] = true
					out = append(out, item)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func allMatchedModules(matches chainSuggestMatchesOutput) []moduleMatchOutput {
	var out []moduleMatchOutput
	out = append(out, matches.SurveyModules...)
	out = append(out, matches.ExploitModules...)
	out = append(out, matches.PayloadProviders...)
	out = append(out, matches.OtherModules...)
	return out
}

func firstMatchedModules(matches chainSuggestMatchesOutput, limit int) []moduleMatchOutput {
	modules := allMatchedModules(matches)
	if len(modules) > limit {
		return modules[:limit]
	}
	return modules
}

func configRequirementFromRequirement(module string, scope modulecatalog.Scope, req modulecatalog.Requirement) configRequirementOutput {
	return configRequirementOutput{
		Module:      module,
		Scope:       string(scope),
		Key:         req.Key,
		Type:        req.Type,
		Required:    req.Required,
		Default:     req.Default,
		Description: req.Description,
		Allowed:     append([]string(nil), req.Allowed...),
		Secret:      req.Secret,
	}
}

func (s *Server) applyModules(ctx context.Context, operation, chain string, modules []string, allowDuplicates bool) ([]operatorsession.Step, []string, error) {
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "list"})
	if err != nil {
		return nil, nil, err
	}
	existing := map[string]bool{}
	snapshot, err := s.snapshot(ctx, operationContextInput{Operation: operation, Chain: chain})
	if err == nil {
		for _, step := range activeChain(snapshot, operation, chain).Steps {
			existing[modulecatalog.ReferenceName(step.ModuleID)] = true
			existing[step.ModuleID] = true
		}
	}
	var added []operatorsession.Step
	var skipped []string
	for _, moduleID := range modules {
		moduleID = strings.TrimSpace(moduleID)
		if moduleID == "" {
			continue
		}
		module, ok := catalog.Find(moduleID)
		if !ok {
			return nil, nil, fmt.Errorf("module %s does not exist in active catalog; loaded modules: %s", moduleID, strings.Join(moduleIDs(catalog.List()), ", "))
		}
		if !allowDuplicates && (existing[module.ID] || existing[modulecatalog.ReferenceName(module.ID)]) {
			skipped = append(skipped, module.ID)
			continue
		}
		out, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"chain", "add", module.ID}})
		if err != nil {
			return nil, nil, err
		}
		added = append(added, operatorsession.Step{ID: stepIDFromOutput(out.Stdout), ModuleID: module.ID})
		existing[module.ID] = true
		existing[modulecatalog.ReferenceName(module.ID)] = true
	}
	return added, skipped, nil
}

func (s *Server) applyChainConfig(ctx context.Context, operation, chain string, config map[string]string) error {
	for _, key := range sortedStringKeys(config) {
		if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"chain", "config", "set", key, config[key]}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) applyTargetConfigs(ctx context.Context, operation, chain string, configs map[string]map[string]string) error {
	for _, target := range sortedTargetKeys(configs) {
		for _, key := range sortedStringKeys(configs[target]) {
			if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"target", "config", "set", target, key, configs[target][key]}}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) applyTargetHostDefaults(ctx context.Context, operation, chain string) error {
	snapshot, err := s.snapshot(ctx, operationContextInput{Operation: operation, Chain: chain})
	if err != nil {
		return err
	}
	operationState := activeOperation(snapshot, operation)
	targetConfigs := cloneTargetConfigs(operationState.TargetConfigs)
	for _, target := range operationState.Targets {
		if targetConfigs[target] == nil {
			targetConfigs[target] = map[string]string{}
		}
		if targetConfigs[target]["target.host"] != "" {
			continue
		}
		if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"target", "config", "set", target, "target.host", target}}); err != nil {
			return err
		}
		targetConfigs[target]["target.host"] = target
	}
	return nil
}

func (s *Server) applySchemaDefaults(ctx context.Context, operation, chain string) error {
	catalog, err := s.mcpCommandCatalog(ctx, []string{"module", "list"})
	if err != nil {
		return err
	}
	snapshot, err := s.snapshot(ctx, operationContextInput{Operation: operation, Chain: chain})
	if err != nil {
		return err
	}
	operationState := activeOperation(snapshot, operation)
	chainState := activeChain(snapshot, operation, chain)
	chainConfig := cloneStringMap(chainState.Config)
	if chainConfig == nil {
		chainConfig = map[string]string{}
	}
	targetConfigs := cloneTargetConfigs(operationState.TargetConfigs)
	if targetConfigs == nil {
		targetConfigs = map[string]map[string]string{}
	}
	for _, step := range chainState.Steps {
		module, ok := catalog.Find(step.ModuleID)
		if !ok {
			continue
		}
		for _, req := range module.ChainConfig {
			if req.Required && req.Default != "" && chainConfig[req.Key] == "" {
				if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"chain", "config", "set", req.Key, req.Default}}); err != nil {
					return err
				}
				chainConfig[req.Key] = req.Default
			}
		}
		for _, target := range operationState.Targets {
			if targetConfigs[target] == nil {
				targetConfigs[target] = map[string]string{}
			}
			for _, req := range module.TargetConfig {
				if req.Required && req.Default != "" && targetConfigs[target][req.Key] == "" {
					if _, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"target", "config", "set", target, req.Key, req.Default}}); err != nil {
						return err
					}
					targetConfigs[target][req.Key] = req.Default
				}
			}
		}
	}
	return nil
}

func (s *Server) throwPlan(ctx context.Context, _ *mcpsdk.CallToolRequest, input throwPlanInput) (*mcpsdk.CallToolResult, throwPlanOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, throwPlanOutput{}, err
	}
	operation := contextOperation(input.Operation, s.currentOperation())
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = s.currentActiveChain()
	}
	if chain == "" {
		return nil, throwPlanOutput{}, errors.New("chain is required; provide chain or attach hovel mcp with --chain")
	}
	out, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"throw", "plan", "--chain", chain, "--json"}})
	if err != nil {
		return nil, throwPlanOutput{}, err
	}
	var plan commands.ThrowPlanPayload
	data, err := json.Marshal(out.JSON)
	if err != nil {
		return nil, throwPlanOutput{}, err
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, throwPlanOutput{}, err
	}
	if plan.ID == "" || plan.PlanHash == "" {
		return nil, throwPlanOutput{}, errors.New("throw plan command did not return a plan payload")
	}
	pendingID := launchKeyPendingThrowID(plan.PlanHash, input.AllowDangerous, input.NowBypass)
	pending, err := s.daemon.CreatePendingThrow(ctx, daemonrpc.CreatePendingThrowRequest{
		ID:             pendingID,
		Operation:      operation,
		Chain:          chain,
		PlanHash:       plan.PlanHash,
		AllowDangerous: input.AllowDangerous,
		NowBypass:      input.NowBypass,
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return nil, throwPlanOutput{}, err
	}
	if err != nil {
		pending = daemonrpc.PendingThrowResponse{ID: pendingID, Operation: operation, Chain: chain, PlanHash: plan.PlanHash}
	}
	policy, err := s.daemon.GetLaunchKeyPolicy(ctx, daemonrpc.LaunchKeyPolicyRequest{Operation: operation})
	if err != nil {
		return nil, throwPlanOutput{}, err
	}
	preflight := s.throwPreflight(ctx, operation, chain, input, pending)
	return nil, throwPlanOutput{Operation: operation, Chain: chain, Plan: plan, Pending: pending, Policy: policy, Preflight: preflight}, nil
}

func (s *Server) throwConfirm(ctx context.Context, _ *mcpsdk.CallToolRequest, input throwConfirmInput) (*mcpsdk.CallToolResult, throwConfirmOutput, error) {
	if strings.TrimSpace(input.PendingID) == "" {
		return nil, throwConfirmOutput{}, errors.New("pendingId is required")
	}
	if strings.TrimSpace(input.PlanHash) == "" {
		return nil, throwConfirmOutput{}, errors.New("planHash is required")
	}
	key := strings.TrimSpace(input.NuclearKey)
	if key == "" {
		return nil, throwConfirmOutput{}, errors.New("nuclearKey is required")
	}
	if err := s.refresh(ctx); err != nil {
		return nil, throwConfirmOutput{}, err
	}
	pending, err := s.daemon.ConfirmPendingThrow(ctx, daemonrpc.ConfirmPendingThrowRequest{
		ID:             input.PendingID,
		EntityID:       s.currentEntity().ID,
		PlanHash:       input.PlanHash,
		AllowDangerous: input.AllowDangerous,
		NowBypass:      input.NowBypass,
	})
	if err != nil {
		return nil, throwConfirmOutput{}, err
	}
	return nil, throwConfirmOutput{Pending: pending, NuclearKeyAccepted: true}, nil
}

func (s *Server) throwStart(ctx context.Context, _ *mcpsdk.CallToolRequest, input throwStartInput) (*mcpsdk.CallToolResult, throwStartOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, throwStartOutput{}, err
	}
	if s.throwStarter == nil {
		return nil, throwStartOutput{}, errors.New("throw execution is not configured for this MCP server")
	}
	if !input.NowBypass {
		return nil, throwStartOutput{}, errors.New("hovel_throw_start requires nowBypass=true so confirmation bypass is explicit and auditable")
	}
	operation := contextOperation(input.Operation, s.currentOperation())
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = s.currentActiveChain()
	}
	if chain == "" {
		return nil, throwStartOutput{}, errors.New("chain is required; provide chain or attach hovel mcp with --chain")
	}
	input.Operation = operation
	input.Chain = chain
	out, err := s.throwStarter(ctx, input)
	if err != nil {
		return nil, throwStartOutput{}, err
	}
	if out.Operation == "" {
		out.Operation = operation
	}
	if out.Chain == "" {
		out.Chain = chain
	}
	statuses, _, err := s.installedPayloadStatuses(ctx, out.Operation, out.Chain, "", false)
	logMCPError("read installed payload statuses after throw start", err)
	out.InstalledPayloads = statuses
	out.Summary = throwSummary(out.Results, statuses)
	out.NextActions = append(out.NextActions, toolCallHint{
		Tool: ToolInstalledPayloadList,
		Arguments: map[string]any{
			"operation": out.Operation,
			"chain":     out.Chain,
		},
		Reason: "List installed payload handles for this throw.",
	})
	if len(statuses) > 0 {
		out.Next = []string{ToolInstalledPayloadList}
		for _, status := range statuses {
			if status.ProviderConfigured {
				out.Next = append(out.Next, ToolPayloadCapabilities, ToolPayloadCall)
				out.NextActions = append(out.NextActions, toolCallHint{
					Tool: ToolPayloadCapabilities,
					Arguments: map[string]any{
						"payload": status.Record.Handle,
					},
					Reason: "List provider-owned payload capabilities for this installed payload.",
				}, toolCallHint{
					Tool: ToolPayloadCall,
					Arguments: map[string]any{
						"payload":    status.Record.Handle,
						"capability": "wininfo",
					},
					Reason: "Collect native Windows host facts without relying on shell output parsing.",
				})
				break
			}
		}
	}
	return nil, out, nil
}

func (s *Server) installedPayloadList(ctx context.Context, _ *mcpsdk.CallToolRequest, input installedPayloadListInput) (*mcpsdk.CallToolResult, installedPayloadListOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, installedPayloadListOutput{}, err
	}
	operation := strings.TrimSpace(input.Operation)
	if operation == "" {
		operation = s.currentOperation()
	}
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = s.currentActiveChain()
	}
	records, catalog, err := s.installedPayloadStatuses(ctx, operation, chain, input.State, input.IncludeRemoved)
	if err != nil {
		return nil, installedPayloadListOutput{}, err
	}
	out := installedPayloadListOutput{Operation: operation, Chain: chain, Records: records}
	if input.IncludeCatalog {
		out.Catalog = &catalog
	}
	return nil, out, nil
}

func (s *Server) payloadCmd(ctx context.Context, _ *mcpsdk.CallToolRequest, input payloadCmdInput) (*mcpsdk.CallToolResult, payloadCmdOutput, error) {
	command := strings.TrimSpace(input.Command)
	if command == "" {
		return nil, payloadCmdOutput{}, errors.New("command is required")
	}
	_, out, err := s.payloadCommandCall(ctx, nil, payloadCommandCallInput{
		Payload: strings.TrimSpace(input.Payload),
		Command: "cmd",
		Args:    []string{command},
	})
	if err != nil {
		return nil, payloadCmdOutput{}, s.enrichPayloadProviderError(ctx, input.Payload, err)
	}
	return nil, payloadCmdOutput{Payload: out.Payload, Command: command, Invocation: out.Invocation, Result: out.Result}, nil
}

func (s *Server) sessionCapabilities(ctx context.Context, _ *mcpsdk.CallToolRequest, input sessionCommandListInput) (*mcpsdk.CallToolResult, sessionCommandListOutput, error) {
	sessionID := strings.TrimSpace(input.Session)
	if sessionID == "" {
		return nil, sessionCommandListOutput{}, errors.New("session is required")
	}
	if err := s.refresh(ctx); err != nil {
		return nil, sessionCommandListOutput{}, err
	}
	resp, err := s.daemon.ListSessionCommands(ctx, daemonrpc.SessionCommandListRequest{SessionID: sessionID})
	if err != nil {
		return nil, sessionCommandListOutput{}, err
	}
	return nil, sessionCommandListOutput{Session: sessionID, Commands: resp.Commands}, nil
}

func (s *Server) sessionCall(ctx context.Context, _ *mcpsdk.CallToolRequest, input sessionCommandCallInput) (*mcpsdk.CallToolResult, sessionCommandCallOutput, error) {
	sessionID := strings.TrimSpace(input.Session)
	if sessionID == "" {
		return nil, sessionCommandCallOutput{}, errors.New("session is required")
	}
	command := sessionCommandName(input)
	if command == "" {
		return nil, sessionCommandCallOutput{}, errors.New("command or capability is required")
	}
	if err := s.refresh(ctx); err != nil {
		return nil, sessionCommandCallOutput{}, err
	}
	req := run.PayloadCommandRequest{
		Command:       command,
		Args:          append([]string(nil), input.Args...),
		InputData:     input.InputData,
		InputEncoding: strings.TrimSpace(input.InputEncoding),
	}
	if req.InputData != "" && req.InputEncoding == "" {
		req.InputEncoding = "utf-8"
	}
	resp, err := s.daemon.RunSessionCommand(ctx, daemonrpc.SessionCommandRunRequest{
		SessionID: sessionID,
		Request:   req,
	})
	if err != nil {
		return nil, sessionCommandCallOutput{}, err
	}
	return nil, sessionCommandCallOutput{
		Session:    sessionID,
		Invocation: payloadCommandInvocationFor(command, input.Args),
		Result:     resp,
	}, nil
}

func (s *Server) payloadCapabilities(ctx context.Context, req *mcpsdk.CallToolRequest, input payloadCommandListInput) (*mcpsdk.CallToolResult, payloadCommandListOutput, error) {
	return s.payloadCommandList(ctx, req, input)
}

func (s *Server) payloadCall(ctx context.Context, req *mcpsdk.CallToolRequest, input payloadCommandCallInput) (*mcpsdk.CallToolResult, payloadCommandCallOutput, error) {
	return s.payloadCommandCall(ctx, req, input)
}

func (s *Server) payloadCommandList(ctx context.Context, _ *mcpsdk.CallToolRequest, input payloadCommandListInput) (*mcpsdk.CallToolResult, payloadCommandListOutput, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, payloadCommandListOutput{}, err
	}
	record, err := filesystem.NewWorkspaceStore().GetInstalledPayload(ctx, s.workspace, input.Payload)
	if err != nil {
		return nil, payloadCommandListOutput{}, err
	}
	if err := providerConfiguredError(record, s.catalogSnapshotValue(ctx)); err != nil {
		return nil, payloadCommandListOutput{}, err
	}
	resp, err := s.daemon.ListPayloadCommands(ctx, daemonrpc.PayloadCommandListRequest{
		ModuleID: record.Provider,
		Request:  payloadCommandListRequest(record),
	})
	if err != nil {
		return nil, payloadCommandListOutput{}, s.enrichPayloadProviderError(ctx, input.Payload, err)
	}
	return nil, payloadCommandListOutput{Payload: record, Commands: resp.Commands}, nil
}

func (s *Server) payloadCommandCall(ctx context.Context, _ *mcpsdk.CallToolRequest, input payloadCommandCallInput) (*mcpsdk.CallToolResult, payloadCommandCallOutput, error) {
	command := payloadCommandName(input)
	if command == "" {
		return nil, payloadCommandCallOutput{}, errors.New("command or capability is required")
	}
	if err := s.refresh(ctx); err != nil {
		return nil, payloadCommandCallOutput{}, err
	}
	record, err := filesystem.NewWorkspaceStore().GetInstalledPayload(ctx, s.workspace, input.Payload)
	if err != nil {
		return nil, payloadCommandCallOutput{}, err
	}
	if err := providerConfiguredError(record, s.catalogSnapshotValue(ctx)); err != nil {
		return nil, payloadCommandCallOutput{}, err
	}
	req := payloadCommandRunRequest(record, input)
	resp, err := s.daemon.RunPayloadCommand(ctx, daemonrpc.PayloadCommandRunRequest{
		Operation: record.Operation,
		Chain:     record.Chain,
		ModuleID:  record.Provider,
		Request:   req,
	})
	if err != nil {
		return nil, payloadCommandCallOutput{}, s.enrichPayloadProviderError(ctx, input.Payload, err)
	}
	if len(resp.Artifacts) > 0 {
		resp, err = materializeMCPPayloadArtifacts(ctx, s.workspace, record, resp)
		if err != nil {
			return nil, payloadCommandCallOutput{}, err
		}
	}
	return nil, payloadCommandCallOutput{Payload: record, Invocation: payloadCommandInvocationFor(command, input.Args), Result: resp}, nil
}

func (s *Server) snapshot(ctx context.Context, input operationContextInput) (operatorsession.PersistedState, error) {
	if err := s.refresh(ctx); err != nil {
		return operatorsession.PersistedState{}, err
	}
	operation := contextOperation(input.Operation, s.currentOperation())
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = s.currentActiveChain()
	}
	resp, err := s.daemon.Snapshot(ctx, daemonrpc.SnapshotRequest{Operation: operation, Chain: chain})
	if err != nil {
		return operatorsession.PersistedState{}, err
	}
	return resp.State, nil
}

func (s *Server) refresh(ctx context.Context) error {
	if s == nil || s.daemon == nil {
		return errors.New("mcp server is not attached to a daemon")
	}
	_, operation, activeChain := s.currentState()
	return s.setContext(ctx, operation, activeChain)
}

func (s *Server) setContext(ctx context.Context, operation, activeChain string) error {
	if s == nil || s.daemon == nil {
		return errors.New("mcp server is not attached to a daemon")
	}
	entity := s.currentEntity()
	operation = strings.TrimSpace(operation)
	activeChain = strings.TrimSpace(activeChain)
	resp, err := s.daemon.HeartbeatEntity(ctx, daemonrpc.HeartbeatEntityRequest{
		ID:          entity.ID,
		Operation:   &operation,
		ActiveChain: &activeChain,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entity = resp.Entity
	s.operation = resp.Entity.Operation
	s.activeChain = resp.Entity.ActiveChain
	return nil
}

func (s *Server) currentEntity() daemonrpc.OperatorEntity {
	entity, _, _ := s.currentState()
	return entity
}

func (s *Server) currentOperation() string {
	_, operation, _ := s.currentState()
	return operation
}

func (s *Server) currentActiveChain() string {
	_, _, activeChain := s.currentState()
	return activeChain
}

func (s *Server) currentState() (daemonrpc.OperatorEntity, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entity, s.operation, s.activeChain
}

func (s *Server) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logMCPError("refresh MCP state", s.refresh(ctx))
		}
	}
}

func commandModeThrowStarter(workspacePath string, client *daemonrpc.Client, catalogPath, hovelConfig string) ThrowStarter {
	return func(ctx context.Context, input throwStartInput) (throwStartOutput, error) {
		if !input.NowBypass {
			return throwStartOutput{}, errors.New("nowBypass=true is required")
		}
		chain := strings.TrimSpace(input.Chain)
		if chain == "" {
			return throwStartOutput{}, errors.New("chain is required")
		}

		session := daemonrpc.NewSessionClient(ctx, client)
		if operation := strings.TrimSpace(input.Operation); operation != "" {
			if err := session.UseOperation(operation); err != nil {
				return throwStartOutput{}, err
			}
		}
		if err := session.UseChain(chain); err != nil {
			return throwStartOutput{}, err
		}

		args := []string{"throw", "--workspace", workspacePath, "--chain", chain, "--now", "--json"}
		args = injectConfigForMCPCommand(args, hovelConfig)
		if input.AllowDangerous {
			args = append(args, "--allow-dangerous")
		}
		var stdout, stderr bytes.Buffer
		catalog, err := mcpCommandCatalog(ctx, []string{"throw"}, catalogPath, hovelConfig, workspacePath)
		if err != nil {
			return throwStartOutput{}, err
		}
		code := commandmode.NewAppWithSessionModulesAndWorkspace(session, catalog, workspacePath).Run(ctx, args, &stdout, &stderr)
		if code != 0 {
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				message = strings.TrimSpace(stdout.String())
			}
			if message == "" {
				message = fmt.Sprintf("throw command exited with status %d", code)
			}
			return throwStartOutput{}, errors.New(message)
		}

		var payload commands.ThrowPayload
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			return throwStartOutput{}, fmt.Errorf("decode throw output: %w", err)
		}
		return throwStartOutput{
			Operation: strings.TrimSpace(input.Operation),
			Plan:      payload.Plan,
			ThrowID:   payload.ThrowID,
			Chain:     payload.Chain,
			Targets:   append([]string(nil), payload.Targets...),
			Results:   append([]commands.RunPayload(nil), payload.Results...),
		}, nil
	}
}

func commandModeCommandRunner(workspacePath string, client *daemonrpc.Client, catalogPath, hovelConfig string) CommandRunner {
	return func(ctx context.Context, input commandRunInput) (commandRunOutput, error) {
		session := daemonrpc.NewSessionClient(ctx, client)
		operation := strings.TrimSpace(input.Operation)
		if operation != "" {
			if err := session.UseOperation(operation); err != nil {
				return commandRunOutput{}, err
			}
		}
		chain := strings.TrimSpace(input.Chain)
		if chain != "" {
			if err := session.UseChain(chain); err != nil {
				return commandRunOutput{}, err
			}
		}

		args := injectWorkspaceForMCPCommand(normalizeMCPCommandArgs(input.Args), workspacePath)
		args = injectConfigForMCPCommand(args, hovelConfig)
		catalog, err := mcpCommandCatalog(ctx, args, catalogPath, hovelConfig, workspacePath)
		if err != nil {
			return commandRunOutput{}, err
		}
		var stdout, stderr bytes.Buffer
		code := commandmode.NewAppWithSessionModulesAndWorkspace(session, catalog, workspacePath).Run(ctx, args, &stdout, &stderr)
		out := commandRunOutput{
			Args:      append([]string(nil), args...),
			Operation: operation,
			Chain:     chain,
			ExitCode:  code,
			OK:        code == 0,
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
		}
		if decoded, ok := decodeCommandJSON(stdout.Bytes()); ok {
			out.JSON = decoded
		}
		return out, nil
	}
}

func normalizeMCPCommandArgs(args []string) []string {
	out := append([]string(nil), args...)
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	if len(out) > 0 && strings.TrimSpace(out[0]) == "hovel" {
		out = out[1:]
	}
	if len(out) > 0 {
		switch strings.TrimSpace(out[0]) {
		case "run", "command":
			out = out[1:]
		}
	}
	if len(out) > 0 && strings.TrimSpace(out[0]) == "--" {
		out = out[1:]
	}
	if len(out) == 0 {
		return nil
	}
	switch strings.TrimSpace(out[0]) {
	case "add", "config", "inspect", "logs", "validate":
		normalized := make([]string, 0, len(out)+1)
		normalized = append(normalized, "chain")
		normalized = append(normalized, out...)
		return normalized
	default:
		return out
	}
}

func injectWorkspaceForMCPCommand(args []string, workspacePath string) []string {
	if hasWorkspaceArg(args) || !mcpCommandUsesWorkspace(args) {
		return append([]string(nil), args...)
	}
	out := append([]string(nil), args...)
	return append(out, "--workspace", workspace.ResolvePath(workspacePath))
}

func injectConfigForMCPCommand(args []string, configPath string) []string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" || hasConfigArg(args) {
		return append([]string(nil), args...)
	}
	out := append([]string(nil), args...)
	return append(out, "--config", configPath)
}

func (s *Server) mcpCommandCatalog(ctx context.Context, args []string) (modulecatalog.Catalog, error) {
	return mcpCommandCatalog(ctx, args, s.catalogPath, s.hovelConfig, s.workspace)
}

func mcpCommandCatalog(ctx context.Context, args []string, catalogPath, hovelConfig, workspacePath string) (modulecatalog.Catalog, error) {
	needsModules := mcpCommandNeedsModules(args)
	catalog, err := (pythonrpc.Runner{ConfigPath: catalogPath, HovelConfig: hovelConfig, WorkspacePath: workspacePath}).Catalog(ctx)
	if err != nil {
		if needsModules {
			return modulecatalog.Catalog{}, fmt.Errorf("load module catalog: %w", err)
		}
		return modulecatalog.New(), nil
	}
	if len(catalog.List()) == 0 && needsModules {
		return modulecatalog.Catalog{}, errors.New("module catalog is empty; set HOVEL_MODULE_CONFIG, pass hovel mcp --module-config, or launch Hovel MCP from the repository root")
	}
	return catalog, nil
}

func mcpCommandNeedsModules(args []string) bool {
	if len(args) == 0 {
		return false
	}
	root := strings.TrimSpace(args[0])
	switch root {
	case "module", "modules":
		return true
	case "throw", "throws":
		return true
	case "chain", "chains":
		if len(args) < 2 {
			return false
		}
		switch strings.TrimSpace(args[1]) {
		case "add", "inspect", "validate":
			return true
		default:
			return false
		}
	case "payload", "payloads":
		if len(args) < 2 {
			return true
		}
		switch strings.TrimSpace(args[1]) {
		case "available", "list":
			return true
		default:
			return false
		}
	default:
		return false
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

func hasConfigArg(args []string) bool {
	for i, arg := range args {
		if arg == "--config" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(arg, "--config=") {
			return true
		}
	}
	return false
}

func mcpCommandUsesWorkspace(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch strings.TrimSpace(args[0]) {
	case "throw", "throws", "confirm", "review", "artifact", "artifacts", "session", "sessions":
		return true
	case "payload", "payloads":
		if len(args) < 2 {
			return false
		}
		switch strings.TrimSpace(args[1]) {
		case "installed", "inspect", "connect", "cleanup", "mark-removed", "refresh", "commands", "getfile", "putfile", "cmd", "register-squatter":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func commandContextAfter(operation, chain string, args []string) (string, string) {
	operation = strings.TrimSpace(operation)
	chain = strings.TrimSpace(chain)
	if len(args) < 2 {
		return operation, chain
	}
	root := strings.TrimSpace(args[0])
	action := strings.TrimSpace(args[1])
	switch root {
	case "op", "ops", "operation", "operations":
		switch action {
		case "create", "use":
			if len(args) >= 3 {
				return strings.TrimSpace(args[2]), ""
			}
		case "delete", "remove", "rm":
			if len(args) >= 3 && strings.TrimSpace(args[2]) == operation {
				return "", ""
			}
		}
	case "chain", "chains":
		switch action {
		case "create", "use":
			if len(args) >= 3 {
				return operation, strings.TrimSpace(args[2])
			}
		case "delete", "remove", "rm":
			if len(args) >= 3 && strings.TrimSpace(args[2]) == chain {
				return operation, ""
			}
		}
	}
	return operation, chain
}

func decodeCommandJSON(data []byte) (any, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

func payloadCommandListRequest(record commands.InstalledPayloadRecord) run.PayloadCommandListRequest {
	return run.PayloadCommandListRequest{
		InstalledPayloadID: record.Handle,
		Target:             record.Target,
		PayloadID:          record.PayloadID,
		Config:             installedPayloadConfig(record),
		Reconnect:          payloadProviderRecordToRun(record.Reconnect),
	}
}

func payloadCommandRunRequest(record commands.InstalledPayloadRecord, input payloadCommandCallInput) run.PayloadCommandRequest {
	encoding := strings.TrimSpace(input.InputEncoding)
	if encoding == "" && input.InputData != "" {
		encoding = "utf-8"
	}
	return run.PayloadCommandRequest{
		InstalledPayloadID: record.Handle,
		Target:             record.Target,
		PayloadID:          record.PayloadID,
		Command:            payloadCommandName(input),
		Args:               append([]string(nil), input.Args...),
		InputData:          input.InputData,
		InputEncoding:      encoding,
		Config:             installedPayloadConfig(record),
		Reconnect:          payloadProviderRecordToRun(record.Reconnect),
	}
}

func installedPayloadConfig(record commands.InstalledPayloadRecord) map[string]string {
	config := map[string]string{}
	if record.Reconnect != nil {
		for key, value := range record.Reconnect.Descriptor {
			text := fmt.Sprint(value)
			if text != "" {
				config[key] = text
			}
		}
	}
	if record.Transport != "" {
		config["payload.transport"] = record.Transport
	}
	if record.Target != "" {
		config["target.host"] = record.Target
	}
	return config
}

func payloadProviderRecordToRun(record *commands.PayloadProviderRecord) *run.PayloadProviderRecord {
	if record == nil {
		return nil
	}
	return &run.PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    cloneAnyMap(record.Descriptor),
	}
}

func materializeMCPPayloadArtifacts(ctx context.Context, workspacePath string, record commands.InstalledPayloadRecord, result run.PayloadCommandResult) (run.PayloadCommandResult, error) {
	store := filesystem.NewWorkspaceStore()
	if result.Fields == nil {
		result.Fields = map[string]string{}
	}
	for index, artifact := range result.Artifacts {
		materialized, err := store.MaterializeArtifact(ctx, commands.ArtifactMaterialization{
			Workspace: workspacePath,
			ThrowID:   "payload-command",
			RunID:     "payload-" + record.Handle + "-" + result.Command,
			ModuleID:  "payload/" + record.Provider,
			Target:    record.Target,
			Artifact: commands.Artifact{
				Name: artifact.Name,
				Kind: artifact.Kind,
				Data: artifact.Data,
				Path: artifact.Path,
			},
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return run.PayloadCommandResult{}, err
		}
		result.Artifacts[index].Data = ""
		result.Artifacts[index].Path = materialized.Path
		result.Fields["artifactId"] = materialized.ID
		result.Fields["artifactPath"] = materialized.Path
	}
	return result, nil
}

func (s *Server) catalogSnapshotValue(ctx context.Context) catalogSnapshotOutput {
	return catalogSnapshotValue(ctx, s.catalogPath)
}

func catalogSnapshotValue(ctx context.Context, catalogPath string) catalogSnapshotOutput {
	info, err := pythonrpc.CatalogInfoForConfig(ctx, catalogPath)
	out := catalogSnapshotOutput{ConfigPath: info.ConfigPath}
	if err != nil {
		out.LoadError = err.Error()
		return out
	}
	out.Modules = moduleOutputs(info.Modules)
	for _, module := range info.Modules {
		if module.Type == modulecatalog.TypePayloadProvider {
			out.PayloadProviders = append(out.PayloadProviders, moduleOutputFromModule(module))
		}
	}
	return out
}

func moduleOutputs(modules []modulecatalog.Module) []moduleOutput {
	out := make([]moduleOutput, 0, len(modules))
	for _, module := range modules {
		out = append(out, moduleOutputFromModule(module))
	}
	return out
}

func moduleOutputFromModule(module modulecatalog.Module) moduleOutput {
	out := moduleOutput{
		ID:           module.ID,
		Name:         module.Name,
		Type:         string(module.Type),
		Version:      module.Version,
		Summary:      module.Summary,
		Description:  module.Description,
		Tags:         append([]string(nil), module.Tags...),
		Enabled:      module.Enabled,
		Dangerous:    module.Dangerous(),
		ChainConfig:  append([]modulecatalog.Requirement(nil), module.ChainConfig...),
		TargetConfig: append([]modulecatalog.Requirement(nil), module.TargetConfig...),
	}
	if commandContextPresent(module.Discovery) {
		discovery := module.Discovery
		out.Discovery = &discovery
	}
	if commandContextPresent(module.Planning) {
		planning := module.Planning
		out.Planning = &planning
	}
	return out
}

func moduleOutputFromModuleWithSteps(module modulecatalog.Module, catalog modulecatalog.Catalog) moduleOutput {
	out := moduleOutputFromModule(module)
	out.Steps = commands.ModuleStepPayloadsForMCP(module.ID, catalog.ResolveStepAvailability(nil))
	return out
}

func commandContextPresent(context modulecatalog.Context) bool {
	return context.Summary != "" ||
		len(context.Keywords) > 0 ||
		len(context.Platforms) > 0 ||
		len(context.Targets) > 0 ||
		len(context.Capabilities) > 0 ||
		len(context.Preconditions) > 0 ||
		len(context.SideEffects) > 0 ||
		context.Cleanup != "" ||
		context.Risk.Level != "" ||
		len(context.Risk.Reasons) > 0 ||
		len(context.Examples) > 0 ||
		len(context.AgentHints) > 0
}

func suggestedChainName(intent, moduleID string) string {
	base := modulecatalog.ReferenceName(moduleID)
	if text := strings.ToLower(strings.TrimSpace(intent)); text != "" {
		text = strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				return r
			case r == '-' || r == '_':
				return '-'
			default:
				return '-'
			}
		}, text)
		text = strings.Trim(text, "-")
		if text != "" {
			base = text
		}
	}
	if base == "" {
		return "suggested-chain"
	}
	return base
}

func launchKeyPendingThrowID(planHash string, allowDangerous, nowBypass bool) string {
	fingerprint := struct {
		PlanHash       string `json:"planHash"`
		AllowDangerous bool   `json:"allowDangerous"`
		NowBypass      bool   `json:"nowBypass"`
	}{
		PlanHash:       planHash,
		AllowDangerous: allowDangerous,
		NowBypass:      nowBypass,
	}
	data, err := json.Marshal(fingerprint)
	if err != nil {
		return "pending-" + strings.TrimSpace(planHash)
	}
	sum := sha256.Sum256(data)
	return "pending-" + hex.EncodeToString(sum[:16])
}

func (s *Server) installedPayloadRecords(ctx context.Context, operation, chain, state string, includeRemoved bool) ([]commands.InstalledPayloadRecord, error) {
	records, err := filesystem.NewWorkspaceStore().ListInstalledPayloads(ctx, s.workspace, commands.InstalledPayloadFilter{
		IncludeRemoved: includeRemoved,
		State:          strings.TrimSpace(state),
	})
	if err != nil {
		return nil, err
	}
	operation = strings.TrimSpace(operation)
	chain = strings.TrimSpace(chain)
	out := make([]commands.InstalledPayloadRecord, 0, len(records))
	for _, record := range records {
		if operation != "" && record.Operation != operation {
			continue
		}
		if chain != "" && record.Chain != chain {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *Server) installedPayloadStatuses(ctx context.Context, operation, chain, state string, includeRemoved bool) ([]installedPayloadStatus, catalogSnapshotOutput, error) {
	catalog := s.catalogSnapshotValue(ctx)
	records, err := s.installedPayloadRecords(ctx, operation, chain, state, includeRemoved)
	if err != nil {
		return nil, catalog, err
	}
	out := make([]installedPayloadStatus, 0, len(records))
	for _, record := range records {
		status := installedPayloadStatus{Record: record}
		if providerConfigured(record.Provider, catalog) {
			status.ProviderConfigured = true
			status.Next = []string{ToolPayloadCapabilities, ToolPayloadCall}
			status.NextActions = []toolCallHint{
				{
					Tool:      ToolPayloadCapabilities,
					Arguments: map[string]any{"payload": record.Handle},
					Reason:    "List provider-owned capabilities and actions available for this payload.",
				},
				{
					Tool: ToolPayloadCall,
					Arguments: map[string]any{
						"payload":    record.Handle,
						"capability": "payload.status",
					},
					Reason: "Collect typed payload lifecycle/status facts.",
				},
			}
		} else {
			status.ProviderError = providerMissingMessage(record, catalog)
		}
		out = append(out, status)
	}
	return out, catalog, nil
}

func providerConfiguredError(record commands.InstalledPayloadRecord, catalog catalogSnapshotOutput) error {
	if providerConfigured(record.Provider, catalog) {
		return nil
	}
	return errors.New(providerMissingMessage(record, catalog))
}

func providerConfigured(provider string, catalog catalogSnapshotOutput) bool {
	provider = strings.TrimSpace(provider)
	if provider == "" || catalog.LoadError != "" {
		return false
	}
	for _, module := range catalog.PayloadProviders {
		if module.ID == provider || module.Name == provider || modulecatalog.ReferenceName(module.ID) == provider {
			return true
		}
	}
	return false
}

func providerMissingMessage(record commands.InstalledPayloadRecord, catalog catalogSnapshotOutput) string {
	if catalog.LoadError != "" {
		return fmt.Sprintf("installed payload %s uses provider %s, but the active module catalog failed to load from %s: %s", record.Handle, record.Provider, displayValue(catalog.ConfigPath, "(none)"), catalog.LoadError)
	}
	providers := make([]string, 0, len(catalog.PayloadProviders))
	for _, provider := range catalog.PayloadProviders {
		providers = append(providers, provider.ID)
	}
	if len(providers) == 0 {
		providers = append(providers, "(none)")
	}
	return fmt.Sprintf("installed payload %s uses provider %s, but the active module catalog at %s has no matching payload_provider. Loaded providers: %s", record.Handle, record.Provider, displayValue(catalog.ConfigPath, "(none)"), strings.Join(providers, ", "))
}

func (s *Server) enrichPayloadProviderError(ctx context.Context, payload string, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if !strings.Contains(message, "unknown module") && !strings.Contains(message, "not configured") {
		return err
	}
	record, recordErr := filesystem.NewWorkspaceStore().GetInstalledPayload(ctx, s.workspace, strings.TrimSpace(payload))
	if recordErr != nil {
		return err
	}
	return fmt.Errorf("%w; %s", err, providerMissingMessage(record, s.catalogSnapshotValue(ctx)))
}

func operationOutputs(operations []operatorsession.PersistedOperation) []operationOutput {
	out := make([]operationOutput, 0, len(operations))
	for _, operation := range operations {
		out = append(out, operationOutput{
			Name:          operation.Name,
			Targets:       append([]string(nil), operation.Targets...),
			TargetConfigs: cloneTargetConfigs(operation.TargetConfigs),
			TargetSets:    cloneTargetSets(operation.TargetSets),
			Chains:        chainOutputs(operation.Chains),
		})
	}
	return out
}

func activeOperation(snapshot operatorsession.PersistedState, operation string) operatorsession.PersistedOperation {
	operation = contextOperation(operation, snapshot.ActiveOperation)
	for _, candidate := range snapshot.Operations {
		if candidate.Name == operation {
			return candidate
		}
	}
	return operatorsession.PersistedOperation{Name: operation}
}

func activeChain(snapshot operatorsession.PersistedState, operation, chain string) operatorsession.PersistedChain {
	operationState := activeOperation(snapshot, operation)
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = snapshot.ActiveChain
	}
	for _, candidate := range operationState.Chains {
		if candidate.Name == chain {
			return candidate
		}
	}
	return operatorsession.PersistedChain{Name: chain}
}

func moduleIDs(modules []modulecatalog.Module) []string {
	out := make([]string, 0, len(modules))
	for _, module := range modules {
		out = append(out, module.ID)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sortedTargetKeys(values map[string]map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func stepIDFromOutput(stdout string) string {
	fields := strings.Fields(stdout)
	for i, field := range fields {
		if field == "as" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func displayValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func chainOutputs(chains []operatorsession.PersistedChain) []chainOutput {
	out := make([]chainOutput, 0, len(chains))
	for _, chain := range chains {
		out = append(out, chainOutput{
			Name:          chain.Name,
			Targets:       append([]string(nil), chain.Targets...),
			Steps:         append([]operatorsession.Step(nil), chain.Steps...),
			Config:        cloneStringMap(chain.Config),
			TargetConfigs: cloneTargetConfigs(chain.TargetConfigs),
			LogTopic:      chain.LogTopic,
		})
	}
	return out
}

func defaultCapabilities() []string {
	return []string{
		ToolOperatorIdentity,
		ToolOperatorListEntities,
		ToolOperationList,
		ToolWorkspaceSnapshot,
		ToolCatalogSnapshot,
		ToolModuleSearch,
		ToolModuleInspect,
		ToolChainSuggest,
		ToolLaunchKeyPolicy,
		ToolChainApply,
		ToolCommandRun,
		ToolThrowPlan,
		ToolThrowConfirm,
		ToolThrowStart,
		ToolInstalledPayloadList,
		ToolPayloadCapabilities,
		ToolPayloadCall,
		ToolPayloadCmd,
		ToolPayloadCommandList,
		ToolPayloadCommandCall,
	}
}

func readOnlyTool(title string) *mcpsdk.ToolAnnotations {
	closedWorld := false
	nonDestructive := false
	return &mcpsdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
		DestructiveHint: &nonDestructive,
	}
}

func destructiveTool(title string) *mcpsdk.ToolAnnotations {
	openWorld := false
	destructive := true
	return &mcpsdk.ToolAnnotations{
		Title:           title,
		OpenWorldHint:   &openWorld,
		DestructiveHint: &destructive,
	}
}

func entityIDOrDefault(entityID string) (string, error) {
	entityID = strings.TrimSpace(entityID)
	if entityID != "" {
		return entityID, nil
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate mcp operator id: %w", err)
	}
	return "mcp-" + hex.EncodeToString(raw[:]), nil
}

func contextOperation(requested, fallback string) string {
	requested = strings.TrimSpace(requested)
	if requested != "" {
		return requested
	}
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		return fallback
	}
	return operatorsession.DefaultOperation
}

func workspaceOrDefault(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultWorkspace
	}
	return workspace.ResolvePath(path)
}

func heartbeatIntervalOrDefault(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultHeartbeatInterval
	}
	return interval
}

func transportModeOrDefault(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return DefaultTransportMode
	}
	return mode
}

func httpAddrOrDefault(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return DefaultHTTPAddr
	}
	return addr
}

func runHTTPTransport(ctx context.Context, operator *Server, addr string, status io.Writer) error {
	listener, err := net.Listen("tcp", httpAddrOrDefault(addr))
	if err != nil {
		return err
	}
	return serveHTTPTransport(ctx, operator, listener, status)
}

func serveHTTPTransport(ctx context.Context, operator *Server, listener net.Listener, status io.Writer) error {
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return operator.MCPServer()
	}, nil)

	server := &http.Server{Handler: handler}
	shutdownCtx, stopShutdown := context.WithCancel(ctx)
	defer stopShutdown()
	go func() {
		<-shutdownCtx.Done()
		if ctx.Err() == nil {
			return
		}
		graceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		logMCPError("shut down MCP HTTP server", server.Shutdown(graceCtx))
	}()

	if status != nil {
		if _, err := fmt.Fprintf(status, "Hovel MCP HTTP listening on http://%s\n", listener.Addr().String()); err != nil {
			logMCPError("write MCP HTTP status", err)
		}
	}
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func ioTransport(input io.Reader, output io.Writer) mcpsdk.Transport {
	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stdout
	}
	return &mcpsdk.IOTransport{Reader: io.NopCloser(input), Writer: nopWriteCloser{Writer: output}}
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		if len(config) == 0 {
			out[target] = map[string]string{}
			continue
		}
		out[target] = cloneStringMap(config)
	}
	return out
}

func cloneTargetSets(values []operatorsession.TargetSet) []operatorsession.TargetSet {
	if len(values) == 0 {
		return nil
	}
	out := make([]operatorsession.TargetSet, len(values))
	for i, value := range values {
		out[i] = operatorsession.TargetSet{
			Name:    value.Name,
			Targets: append([]string(nil), value.Targets...),
		}
	}
	return out
}
