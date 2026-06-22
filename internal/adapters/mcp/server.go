package mcpadapter

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Version = "0.1.0"

	ToolOperatorIdentity     = "hovel_operator_identity"
	ToolOperatorListEntities = "hovel_operator_list_entities"
	ToolOperationList        = "hovel_operation_list"
	ToolWorkspaceSnapshot    = "hovel_workspace_snapshot"
	ToolCatalogSnapshot      = "hovel_catalog_snapshot"
	ToolChainApply           = "hovel_chain_apply"
	ToolCommandRun           = "hovel_command_run"
	ToolThrowStart           = "hovel_throw_start"
	ToolInstalledPayloadList = "hovel_installed_payload_list"
	ToolPayloadCmd           = "hovel_payload_cmd"
	ToolPayloadCommandList   = "hovel_payload_command_list"
	ToolPayloadCommandCall   = "hovel_payload_command_call"

	DefaultWorkspace         = ".hovel"
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
	ListPayloadCommands(context.Context, daemonrpc.PayloadCommandListRequest) (daemonrpc.PayloadCommandListResponse, error)
	RunPayloadCommand(context.Context, daemonrpc.PayloadCommandRunRequest) (daemonrpc.PayloadCommandRunResponse, error)
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
	defer session.Close()

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
	defer client.Close()
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
	defer operator.Detach(context.Background())

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
		Instructions: "Use typed tools first. Start with hovel_catalog_snapshot and hovel_workspace_snapshot. Use hovel_chain_apply to idempotently create/select an operation and chain, add modules, targets, and config, and validate. For Etro-to-Squatter TCP bind, add etro-survey@v0.1.0, etro-exploit@v1.0.0, and squatter@v0.1.0, then set operator.confirmed_lab and optional squatter.bind_port as chain config. Use hovel_throw_start only after explicit caller authorization for the throw and dangerous modules. After a throw, use hovel_installed_payload_list to get payload handles and hovel_payload_cmd to run cmd.exe commands such as systeminfo. Use hovel_command_run only as an escape hatch for commands without typed tools.",
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
		Name:        ToolChainApply,
		Title:       "Apply Chain State",
		Description: "Idempotently create/select an operation and chain, add missing modules and targets, set config, and validate.",
		Annotations: destructiveTool("Apply Chain State"),
	}, s.chainApply)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolCommandRun,
		Title:       "Run Hovel Command",
		Description: "Run one Hovel command-mode command through the daemon-backed MCP operator session. Use this for setup and inspection commands such as op use, chain create, chain add, target add, target config set, chain config set, validate, payloads list for provider-buildable payloads, payloads installed for installed payload records, artifacts list, and chain logs. Pass args without a leading hovel or run.",
		Annotations: destructiveTool("Run Hovel Command"),
	}, s.commandRun)
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
		Name:        ToolPayloadCmd,
		Title:       "Run Payload Cmd",
		Description: "Run one cmd.exe command line through an installed payload handle.",
		Annotations: destructiveTool("Run Payload Cmd"),
	}, s.payloadCmd)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCommandList,
		Title:       "List Payload Commands",
		Description: "List provider-owned commands available for an installed payload.",
		Annotations: readOnlyTool("List Payload Commands"),
	}, s.payloadCommandList)
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolPayloadCommandCall,
		Title:       "Call Payload Command",
		Description: "Call a provider-owned command against an installed payload without attaching to a raw session.",
		Annotations: destructiveTool("Call Payload Command"),
	}, s.payloadCommandCall)
}

type emptyInput struct{}

type operationContextInput struct {
	Operation string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to this MCP operator's current operation, then the daemon default."`
	Chain     string `json:"chain,omitempty" jsonschema:"Optional chain name within the selected operation. Defaults to this MCP operator's active chain."`
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

type payloadCommandListInput struct {
	Payload string `json:"payload" jsonschema:"Installed payload handle or record ID."`
}

type payloadCommandCallInput struct {
	Payload       string   `json:"payload" jsonschema:"Installed payload handle or record ID."`
	Command       string   `json:"command" jsonschema:"Provider-owned payload command name."`
	Args          []string `json:"args,omitempty" jsonschema:"Command arguments."`
	InputData     string   `json:"inputData,omitempty" jsonschema:"Optional UTF-8 input data for upload-style commands."`
	InputEncoding string   `json:"inputEncoding,omitempty" jsonschema:"Encoding for inputData; defaults to utf-8."`
}

type commandRunInput struct {
	Args      []string `json:"args" jsonschema:"Command arguments without leading hovel or run. Examples: [\"op\",\"use\",\"lab\"], [\"chain\",\"create\",\"etro-squatter\"], [\"target\",\"add\",\"192.168.122.142\"]."`
	Operation string   `json:"operation,omitempty" jsonschema:"Optional operation context to select before running the command. Defaults to this MCP operator's current operation."`
	Chain     string   `json:"chain,omitempty" jsonschema:"Optional chain context to select before running the command. Defaults to this MCP operator's active chain."`
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
}

type installedPayloadListInput struct {
	Operation      string `json:"operation,omitempty" jsonschema:"Optional operation filter. Defaults to current operation."`
	Chain          string `json:"chain,omitempty" jsonschema:"Optional chain filter. Defaults to current chain."`
	State          string `json:"state,omitempty" jsonschema:"Optional installed payload state filter."`
	IncludeRemoved bool   `json:"includeRemoved,omitempty" jsonschema:"Include removed payload records."`
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
	Catalog         catalogSnapshotOutput    `json:"catalog"`
	Installed       []installedPayloadStatus `json:"installedPayloads,omitempty"`
}

type catalogSnapshotOutput struct {
	ConfigPath       string         `json:"configPath,omitempty"`
	LoadError        string         `json:"loadError,omitempty"`
	Modules          []moduleOutput `json:"modules"`
	PayloadProviders []moduleOutput `json:"payloadProviders"`
}

type moduleOutput struct {
	ID           string                      `json:"id"`
	Name         string                      `json:"name,omitempty"`
	Type         string                      `json:"type"`
	Version      string                      `json:"version,omitempty"`
	Summary      string                      `json:"summary,omitempty"`
	Tags         []string                    `json:"tags,omitempty"`
	Enabled      bool                        `json:"enabled"`
	Dangerous    bool                        `json:"dangerous,omitempty"`
	ChainConfig  []modulecatalog.Requirement `json:"chainConfig,omitempty"`
	TargetConfig []modulecatalog.Requirement `json:"targetConfig,omitempty"`
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
	Plan              commands.ThrowPlanPayload `json:"plan"`
	ThrowID           string                    `json:"throwId,omitempty"`
	Chain             string                    `json:"chain"`
	Targets           []string                  `json:"targets"`
	Results           []commands.RunPayload     `json:"results"`
	InstalledPayloads []installedPayloadStatus  `json:"installedPayloads,omitempty"`
	Next              []string                  `json:"next,omitempty"`
}

type payloadCommandListOutput struct {
	Payload  commands.InstalledPayloadRecord `json:"payload"`
	Commands []run.PayloadCommand            `json:"commands"`
}

type payloadCommandCallOutput struct {
	Payload commands.InstalledPayloadRecord `json:"payload"`
	Result  run.PayloadCommandResult        `json:"result"`
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

type chainApplyOutput struct {
	Operation      string                  `json:"operation"`
	Chain          string                  `json:"chain"`
	AddedSteps     []operatorsession.Step  `json:"addedSteps,omitempty"`
	SkippedModules []string                `json:"skippedModules,omitempty"`
	Targets        []string                `json:"targets,omitempty"`
	Validation     commandRunOutput        `json:"validation,omitempty"`
	Snapshot       workspaceSnapshotOutput `json:"snapshot"`
}

type installedPayloadListOutput struct {
	Operation string                   `json:"operation,omitempty"`
	Chain     string                   `json:"chain,omitempty"`
	Records   []installedPayloadStatus `json:"records"`
	Catalog   catalogSnapshotOutput    `json:"catalog"`
}

type installedPayloadStatus struct {
	Record             commands.InstalledPayloadRecord `json:"record"`
	ProviderConfigured bool                            `json:"providerConfigured"`
	ProviderError      string                          `json:"providerError,omitempty"`
	Next               []string                        `json:"next,omitempty"`
}

type payloadCmdOutput struct {
	Payload commands.InstalledPayloadRecord `json:"payload"`
	Command string                          `json:"command"`
	Result  run.PayloadCommandResult        `json:"result"`
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

func (s *Server) workspaceSnapshot(ctx context.Context, _ *mcpsdk.CallToolRequest, input operationContextInput) (*mcpsdk.CallToolResult, workspaceSnapshotOutput, error) {
	snapshot, err := s.snapshot(ctx, input)
	if err != nil {
		return nil, workspaceSnapshotOutput{}, err
	}
	operation := contextOperation(input.Operation, snapshot.ActiveOperation)
	chain := strings.TrimSpace(input.Chain)
	if chain == "" {
		chain = snapshot.ActiveChain
	}
	installed, _, _ := s.installedPayloadStatuses(ctx, operation, chain, "", false)
	return nil, workspaceSnapshotOutput{
		Entity:          s.currentEntity(),
		ActiveOperation: snapshot.ActiveOperation,
		ActiveChain:     snapshot.ActiveChain,
		Operations:      operationOutputs(snapshot.Operations),
		Catalog:         s.catalogSnapshotValue(ctx),
		Installed:       installed,
	}, nil
}

func (s *Server) catalogSnapshot(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, catalogSnapshotOutput, error) {
	return nil, s.catalogSnapshotValue(ctx), nil
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

	var validation commandRunOutput
	if !input.SkipValidate {
		out, err := s.requireCommandOK(ctx, commandRunInput{Operation: operation, Chain: chain, Args: []string{"chain", "validate"}})
		if err != nil {
			return nil, chainApplyOutput{}, err
		}
		validation = out
	}
	_, snapshot, err := s.workspaceSnapshot(ctx, nil, operationContextInput{Operation: operation, Chain: chain})
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
	statuses, _, _ := s.installedPayloadStatuses(ctx, out.Operation, out.Chain, "", false)
	out.InstalledPayloads = statuses
	if len(statuses) > 0 {
		out.Next = []string{ToolInstalledPayloadList}
		for _, status := range statuses {
			if status.ProviderConfigured {
				out.Next = append(out.Next, ToolPayloadCmd)
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
	return nil, installedPayloadListOutput{Operation: operation, Chain: chain, Records: records, Catalog: catalog}, nil
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
	return nil, payloadCmdOutput{Payload: out.Payload, Command: command, Result: out.Result}, nil
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
	return nil, payloadCommandCallOutput{Payload: record, Result: resp}, nil
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
			_ = s.refresh(ctx)
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
		code := commandmode.NewAppWithSessionAndModules(session, catalog).Run(ctx, args, &stdout, &stderr)
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
		code := commandmode.NewAppWithSessionAndModules(session, catalog).Run(ctx, args, &stdout, &stderr)
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
	if workspacePath == "" || hasWorkspaceArg(args) || !mcpCommandUsesWorkspace(args) {
		return append([]string(nil), args...)
	}
	out := append([]string(nil), args...)
	return append(out, "--workspace", workspacePath)
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
		Command:            strings.TrimSpace(input.Command),
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
	return moduleOutput{
		ID:           module.ID,
		Name:         module.Name,
		Type:         string(module.Type),
		Version:      module.Version,
		Summary:      module.Summary,
		Tags:         append([]string(nil), module.Tags...),
		Enabled:      module.Enabled,
		Dangerous:    module.Dangerous(),
		ChainConfig:  append([]modulecatalog.Requirement(nil), module.ChainConfig...),
		TargetConfig: append([]modulecatalog.Requirement(nil), module.TargetConfig...),
	}
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
			status.Next = []string{"hovel_payload_command_list", "hovel_payload_cmd"}
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
		ToolChainApply,
		ToolCommandRun,
		ToolThrowStart,
		ToolInstalledPayloadList,
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
		_ = server.Shutdown(graceCtx)
	}()

	if status != nil {
		fmt.Fprintf(status, "Hovel MCP HTTP listening on http://%s\n", listener.Addr().String())
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
