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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Version = "0.1.0"

	ToolOperatorIdentity     = "hovel_operator_identity"
	ToolOperatorListEntities = "hovel_operator_list_entities"
	ToolOperationList        = "hovel_operation_list"
	ToolWorkspaceSnapshot    = "hovel_workspace_snapshot"
	ToolThrowStart           = "hovel_throw_start"

	DefaultWorkspace         = ".hovel"
	DefaultDisplayName       = "Hovel MCP"
	DefaultHeartbeatInterval = 15 * time.Second
)

type Daemon interface {
	AttachEntity(context.Context, daemonrpc.AttachEntityRequest) (daemonrpc.EntityResponse, error)
	HeartbeatEntity(context.Context, daemonrpc.HeartbeatEntityRequest) (daemonrpc.EntityResponse, error)
	DetachEntity(context.Context, daemonrpc.DetachEntityRequest) error
	ListEntities(context.Context, daemonrpc.ListEntitiesRequest) (daemonrpc.ListEntitiesResponse, error)
	Snapshot(context.Context, daemonrpc.SnapshotRequest) (daemonrpc.SnapshotResponse, error)
	Close() error
}

type DialFunc func(context.Context, string) (Daemon, error)
type ThrowStarter func(context.Context, throwStartInput) (throwStartOutput, error)

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
	Transport         mcpsdk.Transport
	HeartbeatInterval time.Duration
	Manager           *daemonmanager.Manager
	Dial              DialFunc
	ThrowStarter      ThrowStarter
}

type Server struct {
	mu           sync.Mutex
	daemon       Daemon
	entity       daemonrpc.OperatorEntity
	operation    string
	activeChain  string
	workspace    string
	throwStarter ThrowStarter
}

type OperatorOptions struct {
	EntityID     string
	DisplayName  string
	Operation    string
	ActiveChain  string
	Capabilities []string
	PolicyTags   []string
	Workspace    string
	ThrowStarter ThrowStarter
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
	session, err := manager.Ensure(ctx, workspacePath)
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
	if throwStarter == nil {
		if rpcClient, ok := client.(*daemonrpc.Client); ok {
			throwStarter = commandModeThrowStarter(workspacePath, rpcClient)
		}
	}

	operator, err := Attach(ctx, client, OperatorOptions{
		EntityID:     cfg.EntityID,
		DisplayName:  cfg.DisplayName,
		Operation:    cfg.Operation,
		ActiveChain:  cfg.Chain,
		Capabilities: cfg.Capabilities,
		PolicyTags:   cfg.PolicyTags,
		Workspace:    workspacePath,
		ThrowStarter: throwStarter,
	})
	if err != nil {
		return err
	}
	defer operator.Detach(context.Background())

	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go operator.heartbeatLoop(heartbeatCtx, heartbeatIntervalOrDefault(cfg.HeartbeatInterval))

	transport := cfg.Transport
	if transport == nil {
		transport = ioTransport(cfg.Input, cfg.Output)
	}
	if err := operator.MCPServer().Run(ctx, transport); err != nil && !errors.Is(err, context.Canceled) {
		return err
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
		daemon:       daemon,
		entity:       resp.Entity,
		operation:    resp.Entity.Operation,
		activeChain:  resp.Entity.ActiveChain,
		workspace:    workspaceOrDefault(opts.Workspace),
		throwStarter: opts.ThrowStarter,
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
		Instructions: "Drive Hovel through structured tools. Read state before mutating it, preserve operation and chain context, and treat throw actions as safety-sensitive.",
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
		Name:        ToolThrowStart,
		Title:       "Start Throw",
		Description: "Start a throw for the selected operation and chain after explicit MCP caller confirmation.",
		Annotations: destructiveTool("Start Throw"),
	}, s.throwStart)
}

type emptyInput struct{}

type operationContextInput struct {
	Operation string `json:"operation,omitempty" jsonschema:"Optional operation name. Defaults to this MCP operator's current operation, then the daemon default."`
	Chain     string `json:"chain,omitempty" jsonschema:"Optional chain name within the selected operation."`
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
	Operation string                    `json:"operation,omitempty"`
	Plan      commands.ThrowPlanPayload `json:"plan"`
	ThrowID   string                    `json:"throwId,omitempty"`
	Chain     string                    `json:"chain"`
	Targets   []string                  `json:"targets"`
	Results   []commands.RunPayload     `json:"results"`
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
	return nil, workspaceSnapshotOutput{
		Entity:          s.currentEntity(),
		ActiveOperation: snapshot.ActiveOperation,
		ActiveChain:     snapshot.ActiveChain,
		Operations:      operationOutputs(snapshot.Operations),
	}, nil
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
	return nil, out, nil
}

func (s *Server) snapshot(ctx context.Context, input operationContextInput) (operatorsession.PersistedState, error) {
	if err := s.refresh(ctx); err != nil {
		return operatorsession.PersistedState{}, err
	}
	operation := contextOperation(input.Operation, s.currentOperation())
	chain := strings.TrimSpace(input.Chain)
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
	entity, operation, activeChain := s.currentState()
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

func commandModeThrowStarter(workspacePath string, client *daemonrpc.Client) ThrowStarter {
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
		if input.AllowDangerous {
			args = append(args, "--allow-dangerous")
		}
		var stdout, stderr bytes.Buffer
		code := commandmode.NewAppWithSession(session).Run(ctx, args, &stdout, &stderr)
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
		ToolThrowStart,
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

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
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
