package daemonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/launchkey"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/mesh"
	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const (
	serviceURLPrefix = "/hovel.daemon.v1.DaemonService/"

	rpcMethodDescribeMesh       = "DescribeMesh"
	rpcMethodMeshTopology       = "MeshTopology"
	rpcMethodListMeshBeacons    = "ListMeshBeacons"
	rpcMethodRunMeshTask        = "RunMeshTask"
	rpcMethodOpenMeshStream     = "OpenMeshStream"
	rpcMethodOpenMeshBridge     = "OpenMeshBridge"
	rpcMethodCloseMeshBridge    = "CloseMeshBridge"
	rpcMethodListMeshOperations = "ListMeshOperations"
)

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

type ExecuteModuleRequest = RunMockExploitRequest

type Finding struct {
	Title    string
	Severity string
	Detail   string
}

type Artifact struct {
	Name string
	Kind string
	Data string
	Path string
}

type SessionRef struct {
	ID                 string
	RunID              string
	ModuleID           string
	Target             string
	Name               string
	Kind               string
	State              string
	Transport          string
	InstalledPayloadID string
	Capabilities       []string
}

type SessionChunk struct {
	SessionID string
	Data      []byte
	Closed    bool
}

type LogEntry struct {
	ID             string
	Time           string
	Topic          string
	Kind           string
	Level          string
	Source         string
	Message        string
	Logger         string
	ChainID        string
	ChainName      string
	RunID          string
	Target         string
	ModuleID       string
	ElapsedSeconds *float64
	Fields         map[string]string
	Attributes     map[string]string
}

type OperatorLogEntry struct {
	ID             string
	Time           string
	Topic          string
	Kind           string
	Level          string
	Source         string
	Message        string
	ChainID        string
	ChainName      string
	RunID          string
	Target         string
	ModuleID       string
	ElapsedSeconds *float64
	Fields         map[string]string
	Attributes     map[string]string
}

type PublishedLog struct {
	Seq       uint64
	Operation string
	Chain     string
	Entry     OperatorLogEntry
}

type PollLogsRequest struct {
	Since     uint64
	Operation string
	Chain     string
}

type PollLogsResponse struct {
	Last uint64
	Logs []PublishedLog
}

type RunMockExploitResponse struct {
	RunID             string
	ModuleID          string
	Target            string
	State             string
	Summary           string
	Findings          []Finding
	Artifacts         []Artifact
	Logs              []LogEntry
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
}

type ExecuteModuleResponse = RunMockExploitResponse

type PayloadProviderRecord = run.PayloadProviderRecord
type InstalledPayloadDescriptor = run.InstalledPayloadDescriptor

type OperatorEntity struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"displayName"`
	Agent        bool     `json:"agent"`
	Operation    string   `json:"operation,omitempty"`
	ActiveChain  string   `json:"activeChain,omitempty"`
	ConnectedAt  string   `json:"connectedAt"`
	LastSeenAt   string   `json:"lastSeenAt"`
	Capabilities []string `json:"capabilities,omitempty"`
	PolicyTags   []string `json:"policyTags,omitempty"`
}

type AttachEntityRequest struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"displayName,omitempty"`
	Agent        bool     `json:"agent,omitempty"`
	Operation    string   `json:"operation,omitempty"`
	ActiveChain  string   `json:"activeChain,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	PolicyTags   []string `json:"policyTags,omitempty"`
}

type HeartbeatEntityRequest struct {
	ID          string  `json:"id"`
	Operation   *string `json:"operation,omitempty"`
	ActiveChain *string `json:"activeChain,omitempty"`
}

type DetachEntityRequest struct {
	ID string `json:"id"`
}

type ListEntitiesRequest struct {
	Operation string `json:"operation,omitempty"`
}

type EntityResponse struct {
	Entity OperatorEntity `json:"entity"`
}

type ListEntitiesResponse struct {
	Entities []OperatorEntity `json:"entities"`
}

type CreatePendingThrowRequest struct {
	ID             string `json:"id"`
	Operation      string `json:"operation"`
	Chain          string `json:"chain"`
	PlanHash       string `json:"planHash"`
	AllowDangerous bool   `json:"allowDangerous,omitempty"`
	NowBypass      bool   `json:"nowBypass,omitempty"`
}

type ConfirmPendingThrowRequest struct {
	ID             string `json:"id"`
	EntityID       string `json:"entityId"`
	PlanHash       string `json:"planHash"`
	AllowDangerous bool   `json:"allowDangerous,omitempty"`
	NowBypass      bool   `json:"nowBypass,omitempty"`
}

type PendingThrowRequest struct {
	ID string `json:"id"`
}

type PendingThrowResponse struct {
	ID                  string   `json:"id"`
	Operation           string   `json:"operation"`
	Chain               string   `json:"chain"`
	PlanHash            string   `json:"planHash"`
	AllowDangerous      bool     `json:"allowDangerous,omitempty"`
	NowBypass           bool     `json:"nowBypass,omitempty"`
	CreatedAt           string   `json:"createdAt"`
	Ready               bool     `json:"ready"`
	RequiredApproverIDs []string `json:"requiredApproverIds"`
	MissingApproverIDs  []string `json:"missingApproverIds"`
}

type LaunchKeyPolicyRequest struct {
	Operation string `json:"operation,omitempty"`
}

type SetLaunchKeyPolicyRequest struct {
	Operation        string `json:"operation,omitempty"`
	Mode             string `json:"mode"`
	Quorum           int    `json:"quorum,omitempty"`
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

type LaunchKeyPolicyResponse struct {
	Operation string                `json:"operation"`
	Policy    LaunchKeyPolicyOutput `json:"policy"`
}

type LaunchKeyPolicyOutput struct {
	Mode             string `json:"mode"`
	Quorum           int    `json:"quorum,omitempty"`
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

type PayloadCommand = run.PayloadCommand
type PayloadGenerateRequest struct {
	ModuleID string                     `json:"moduleId"`
	Request  run.GeneratePayloadRequest `json:"request"`
}

type PayloadGenerateResponse = run.PayloadArtifactSet

type PayloadCommandListRequest struct {
	ModuleID string                        `json:"moduleId"`
	Request  run.PayloadCommandListRequest `json:"request"`
}

type PayloadCommandListResponse struct {
	Commands []run.PayloadCommand `json:"commands"`
}

type PayloadCommandRunRequest struct {
	Operation string                    `json:"operation,omitempty"`
	Chain     string                    `json:"chain,omitempty"`
	ModuleID  string                    `json:"moduleId"`
	Request   run.PayloadCommandRequest `json:"request"`
}

type PayloadCommandRunResponse = run.PayloadCommandResult

type MeshDescribeRequest struct {
	ModuleID string               `json:"moduleId"`
	Request  mesh.DescribeRequest `json:"request"`
}

type MeshDescribeResponse = mesh.Descriptor

type MeshTopologyRequest struct {
	ModuleID string               `json:"moduleId"`
	Request  mesh.TopologyRequest `json:"request"`
}

type MeshTopologyResponse = mesh.Topology

type MeshBeaconListRequest struct {
	ModuleID string             `json:"moduleId"`
	Request  mesh.BeaconRequest `json:"request"`
}

type MeshBeaconListResponse struct {
	Beacons []mesh.Beacon `json:"beacons"`
}

type MeshTaskRunRequest struct {
	ModuleID string           `json:"moduleId"`
	Request  mesh.TaskRequest `json:"request"`
}

type MeshTaskRunResponse = mesh.TaskResult

type MeshStreamOpenRequest struct {
	ModuleID string             `json:"moduleId"`
	Request  mesh.StreamRequest `json:"request"`
}

type MeshStreamOpenResponse = run.SessionRef

type MeshBridgeOpenRequest struct {
	ModuleID  string             `json:"moduleId"`
	Request   mesh.StreamRequest `json:"request"`
	LocalHost string             `json:"localHost,omitempty"`
	LocalPort int                `json:"localPort,omitempty"`
}

type MeshBridgeOpenResponse struct {
	OperationID  string `json:"operationId"`
	SessionID    string `json:"sessionId"`
	LocalHost    string `json:"localHost"`
	LocalPort    int    `json:"localPort"`
	LocalAddress string `json:"localAddress"`
}

type MeshBridgeCloseRequest struct {
	OperationID string `json:"operationId,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
}

type MeshBridgeCloseResponse struct {
	OperationID string             `json:"operationId,omitempty"`
	SessionID   string             `json:"sessionId,omitempty"`
	State       MeshOperationState `json:"state"`
}

type operatorClock interface {
	Now() time.Time
}

type systemOperatorClock struct{}

func (systemOperatorClock) Now() time.Time {
	return time.Now().UTC()
}

type Server struct {
	runs            services.RunService
	moduleSessions  services.SessionBroker
	meshOps         *MeshBook
	meshBridges     *MeshBridgeManager
	session         *operatorsession.Session
	logs            *LogBroker
	entities        map[string]operatordomain.Entity
	launchKeys      *launchkey.Coordinator
	launchKeyPolicy operatordomain.LaunchKeyPolicy
	launchKeyByOp   map[string]operatordomain.LaunchKeyPolicy
	clock           operatorClock
	persistSession  func(operatorsession.PersistedState) error
	mu              sync.Mutex
}

func Register(mux *http.ServeMux, runs services.RunService, options ...ServerOption) error {
	if mux == nil {
		return errors.New("daemon rpc mux is required")
	}
	rpcServer := &Server{
		runs:        runs,
		meshOps:     NewMeshBook(),
		meshBridges: NewMeshBridgeManager(),
		session:     operatorsession.New(),
		logs:        NewLogBroker(),
		entities:    map[string]operatordomain.Entity{},
		launchKeys:  launchkey.NewCoordinator(),
		clock:       systemOperatorClock{},
	}
	for _, option := range options {
		option(rpcServer)
	}
	registerUnary[ExecuteModuleRequest, ExecuteModuleResponse](mux, "ExecuteModule", rpcServer.executeModuleRPC)
	registerUnary[EmptyRequest, ListSessionsResponse](mux, "ListSessions", rpcServer.listSessionsRPC)
	registerUnary[SessionReadRequest, SessionChunk](mux, "ReadSession", rpcServer.readSessionRPC)
	registerUnary[SessionTailRequest, SessionChunk](mux, "TailSession", rpcServer.tailSessionRPC)
	registerUnary[SessionWriteRequest, EmptyResponse](mux, "WriteSession", rpcServer.writeSessionRPC)
	registerUnary[SessionCloseRequest, EmptyResponse](mux, "CloseSession", rpcServer.closeSessionRPC)
	registerUnary[SessionCommandListRequest, SessionCommandListResponse](mux, "ListSessionCommands", rpcServer.listSessionCommandsRPC)
	registerUnary[SessionCommandRunRequest, SessionCommandRunResponse](mux, "RunSessionCommand", rpcServer.runSessionCommandRPC)
	registerUnary[OperationRequest, EmptyResponse](mux, "CreateOperation", rpcServer.createOperationRPC)
	registerUnary[OperationRequest, EmptyResponse](mux, "UseOperation", rpcServer.useOperationRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "CreateChain", rpcServer.createChainRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "UseChain", rpcServer.useChainRPC)
	registerUnary[RenameChainRequest, EmptyResponse](mux, "RenameChain", rpcServer.renameChainRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "DeleteChain", rpcServer.deleteChainRPC)
	registerUnary[TargetRequest, EmptyResponse](mux, "AddTarget", rpcServer.addTargetRPC)
	registerUnary[TargetRequest, EmptyResponse](mux, "BindTarget", rpcServer.bindTargetRPC)
	registerUnary[TargetRequest, EmptyResponse](mux, "UnbindTarget", rpcServer.unbindTargetRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "ClearTargets", rpcServer.clearTargetsRPC)
	registerUnary[TargetSetRequest, EmptyResponse](mux, "CreateTargetSet", rpcServer.createTargetSetRPC)
	registerUnary[TargetSetRequest, EmptyResponse](mux, "AddTargetToSet", rpcServer.addTargetToSetRPC)
	registerUnary[TargetSetRequest, EmptyResponse](mux, "RemoveTargetFromSet", rpcServer.removeTargetFromSetRPC)
	registerUnary[ModuleRequest, StepResponse](mux, "AddModule", rpcServer.addModuleRPC)
	registerUnary[ConfigRequest, EmptyResponse](mux, "SetChainConfig", rpcServer.setChainConfigRPC)
	registerUnary[ConfigRequest, EmptyResponse](mux, "UnsetChainConfig", rpcServer.unsetChainConfigRPC)
	registerUnary[TargetConfigRequest, EmptyResponse](mux, "SetTargetConfig", rpcServer.setTargetConfigRPC)
	registerUnary[TargetConfigRequest, EmptyResponse](mux, "UnsetTargetConfig", rpcServer.unsetTargetConfigRPC)
	registerUnary[SnapshotRequest, SnapshotResponse](mux, "Snapshot", rpcServer.snapshotRPC)
	registerUnary[ActiveLogsRequest, []OperatorLogEntry](mux, "ActiveLogs", rpcServer.activeLogsRPC)
	registerUnary[AppendLogRequest, EmptyResponse](mux, "AppendLog", rpcServer.appendLogRPC)
	registerUnary[PollLogsRequest, PollLogsResponse](mux, "PollLogs", rpcServer.pollLogsRPC)
	registerUnary[AttachEntityRequest, EntityResponse](mux, "AttachEntity", rpcServer.attachEntityRPC)
	registerUnary[HeartbeatEntityRequest, EntityResponse](mux, "HeartbeatEntity", rpcServer.heartbeatEntityRPC)
	registerUnary[DetachEntityRequest, EmptyResponse](mux, "DetachEntity", rpcServer.detachEntityRPC)
	registerUnary[ListEntitiesRequest, ListEntitiesResponse](mux, "ListEntities", rpcServer.listEntitiesRPC)
	registerUnary[CreatePendingThrowRequest, PendingThrowResponse](mux, "CreatePendingThrow", rpcServer.createPendingThrowRPC)
	registerUnary[ConfirmPendingThrowRequest, PendingThrowResponse](mux, "ConfirmPendingThrow", rpcServer.confirmPendingThrowRPC)
	registerUnary[PendingThrowRequest, PendingThrowResponse](mux, "RequirePendingThrowReady", rpcServer.requirePendingThrowReadyRPC)
	registerUnary[PendingThrowRequest, EmptyResponse](mux, "CancelPendingThrow", rpcServer.cancelPendingThrowRPC)
	registerUnary[LaunchKeyPolicyRequest, LaunchKeyPolicyResponse](mux, "GetLaunchKeyPolicy", rpcServer.getLaunchKeyPolicyRPC)
	registerUnary[SetLaunchKeyPolicyRequest, LaunchKeyPolicyResponse](mux, "SetLaunchKeyPolicy", rpcServer.setLaunchKeyPolicyRPC)
	registerUnary[PayloadGenerateRequest, PayloadGenerateResponse](mux, "GeneratePayload", rpcServer.generatePayloadRPC)
	registerUnary[PayloadCommandListRequest, PayloadCommandListResponse](mux, "ListPayloadCommands", rpcServer.listPayloadCommandsRPC)
	registerUnary[PayloadCommandRunRequest, PayloadCommandRunResponse](mux, "RunPayloadCommand", rpcServer.runPayloadCommandRPC)
	registerUnary[MeshDescribeRequest, MeshDescribeResponse](mux, rpcMethodDescribeMesh, rpcServer.describeMeshRPC)
	registerUnary[MeshTopologyRequest, MeshTopologyResponse](mux, rpcMethodMeshTopology, rpcServer.meshTopologyRPC)
	registerUnary[MeshBeaconListRequest, MeshBeaconListResponse](mux, rpcMethodListMeshBeacons, rpcServer.listMeshBeaconsRPC)
	registerUnary[MeshTaskRunRequest, MeshTaskRunResponse](mux, rpcMethodRunMeshTask, rpcServer.runMeshTaskRPC)
	registerUnary[MeshStreamOpenRequest, MeshStreamOpenResponse](mux, rpcMethodOpenMeshStream, rpcServer.openMeshStreamRPC)
	registerUnary[MeshBridgeOpenRequest, MeshBridgeOpenResponse](mux, rpcMethodOpenMeshBridge, rpcServer.openMeshBridgeRPC)
	registerUnary[MeshBridgeCloseRequest, MeshBridgeCloseResponse](mux, rpcMethodCloseMeshBridge, rpcServer.closeMeshBridgeRPC)
	registerUnary[MeshOperationListRequest, MeshOperationListResponse](mux, rpcMethodListMeshOperations, rpcServer.listMeshOperationsRPC)
	return nil
}

func NewHandler(runs services.RunService, options ...ServerOption) (http.Handler, error) {
	mux := http.NewServeMux()
	if err := Register(mux, runs, options...); err != nil {
		return nil, err
	}
	return mux, nil
}

func registerUnary[Req, Res any](mux *http.ServeMux, method string, fn func(context.Context, Req) (Res, error)) {
	path := serviceURLPrefix + method
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer func() { logDaemonRPCError("close request body", r.Body.Close()) }()
		var req Req
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON request: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := fn(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

type ServerOption func(*Server)

func WithSession(session *operatorsession.Session) ServerOption {
	return func(server *Server) {
		if session != nil {
			server.session = session
		}
	}
}

func WithLogBroker(logs *LogBroker) ServerOption {
	return func(server *Server) {
		if logs != nil {
			server.logs = logs
		}
	}
}

func WithSessionPersistence(persist func(operatorsession.PersistedState) error) ServerOption {
	return func(server *Server) {
		server.persistSession = persist
	}
}

func WithModuleSessions(sessions services.SessionBroker) ServerOption {
	return func(server *Server) {
		server.moduleSessions = sessions
	}
}

func WithMeshBook(book *MeshBook) ServerOption {
	return func(server *Server) {
		if book != nil {
			server.meshOps = book
		}
	}
}

func WithMeshBridgeManager(manager *MeshBridgeManager) ServerOption {
	return func(server *Server) {
		if manager != nil {
			server.meshBridges = manager
		}
	}
}

func WithOperatorClock(clock operatorClock) ServerOption {
	return func(server *Server) {
		if clock != nil {
			server.clock = clock
		}
	}
}

func WithLaunchKeyPolicy(policy operatordomain.LaunchKeyPolicy) ServerOption {
	return func(server *Server) {
		server.launchKeyPolicy = operatordomain.NormalizeLaunchKeyPolicy(policy)
	}
}

func (s *Server) meshBook() *MeshBook {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meshOps == nil {
		s.meshOps = NewMeshBook()
	}
	return s.meshOps
}

func (s *Server) meshBridgeManager() *MeshBridgeManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meshBridges == nil {
		s.meshBridges = NewMeshBridgeManager()
	}
	return s.meshBridges
}

func (s *Server) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

func (s *Server) RunMockExploit(req RunMockExploitRequest, resp *RunMockExploitResponse) error {
	return s.ExecuteModule(ExecuteModuleRequest(req), (*ExecuteModuleResponse)(resp))
}

func (s *Server) executeModuleRPC(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	var resp ExecuteModuleResponse
	err := s.executeModule(ctx, req, &resp)
	return resp, err
}

func (s *Server) ExecuteModule(req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	return s.executeModule(context.Background(), req, resp)
}

func (s *Server) executeModule(ctx context.Context, req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	var throwStarted time.Time
	if req.ThrowStarted != "" {
		var err error
		throwStarted, err = time.Parse(time.RFC3339Nano, req.ThrowStarted)
		if err != nil {
			return fmt.Errorf("parse throw started timestamp: %w", err)
		}
	}
	result, err := s.runs.ExecuteModule(ctx, services.ExecuteModuleRequest{
		Operation:    req.Operation,
		Chain:        req.Chain,
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
		ThrowStarted: throwStarted,
	})
	if err != nil {
		return err
	}
	*resp = responseFromResult(result)
	return nil
}

func (s *Server) generatePayloadRPC(ctx context.Context, req PayloadGenerateRequest) (PayloadGenerateResponse, error) {
	return s.runs.GeneratePayload(ctx, services.GeneratePayloadRequest{
		ModuleID: req.ModuleID,
		Request:  req.Request,
	})
}

func (s *Server) listPayloadCommandsRPC(ctx context.Context, req PayloadCommandListRequest) (PayloadCommandListResponse, error) {
	commands, err := s.runs.ListPayloadCommands(ctx, services.PayloadCommandListRequest{
		ModuleID: req.ModuleID,
		Request:  req.Request,
	})
	if err != nil {
		return PayloadCommandListResponse{}, err
	}
	return PayloadCommandListResponse{Commands: commands}, nil
}

func (s *Server) runPayloadCommandRPC(ctx context.Context, req PayloadCommandRunRequest) (PayloadCommandRunResponse, error) {
	return s.runs.RunPayloadCommand(ctx, services.PayloadCommandRunRequest{
		Operation: req.Operation,
		Chain:     req.Chain,
		ModuleID:  req.ModuleID,
		Request:   req.Request,
	})
}

func (s *Server) describeMeshRPC(ctx context.Context, req MeshDescribeRequest) (MeshDescribeResponse, error) {
	return s.runs.DescribeMesh(ctx, req.ModuleID, req.Request)
}

func (s *Server) meshTopologyRPC(ctx context.Context, req MeshTopologyRequest) (MeshTopologyResponse, error) {
	return s.runs.MeshTopology(ctx, req.ModuleID, req.Request)
}

func (s *Server) listMeshBeaconsRPC(
	ctx context.Context,
	req MeshBeaconListRequest,
) (MeshBeaconListResponse, error) {
	beacons, err := s.runs.ListMeshBeacons(ctx, req.ModuleID, req.Request)
	if err != nil {
		return MeshBeaconListResponse{}, err
	}
	return MeshBeaconListResponse{Beacons: beacons}, nil
}

func (s *Server) runMeshTaskRPC(ctx context.Context, req MeshTaskRunRequest) (MeshTaskRunResponse, error) {
	operation := s.meshBook().StartTask(req.ModuleID, req.Request, s.now())
	result, err := s.runs.RunMeshTask(ctx, req.ModuleID, req.Request)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshTaskRunResponse{}, err
	}
	s.meshBook().CompleteTask(operation.ID, result, s.now())
	return result, nil
}

func (s *Server) openMeshStreamRPC(
	ctx context.Context,
	req MeshStreamOpenRequest,
) (MeshStreamOpenResponse, error) {
	operation := s.meshBook().StartStream(req.ModuleID, req.Request, s.now())
	session, err := s.runs.OpenMeshStream(ctx, req.ModuleID, req.Request)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return run.SessionRef{}, err
	}
	s.meshBook().ActivateStream(operation.ID, session, s.now())
	return session, nil
}

func (s *Server) openMeshBridgeRPC(
	ctx context.Context,
	req MeshBridgeOpenRequest,
) (MeshBridgeOpenResponse, error) {
	if s.moduleSessions == nil {
		return MeshBridgeOpenResponse{}, errors.New("session broker is not configured")
	}
	return OpenMeshBridge(
		ctx,
		MeshBridgeOpenArgs{
			ModuleID: req.ModuleID,
			Request:  req.Request,
			Host:     req.LocalHost,
			Port:     req.LocalPort,
			Runs:     s.runs,
			Sessions: s.moduleSessions,
			Book:     s.meshBook(),
			Bridges:  s.meshBridgeManager(),
			Now:      s.now,
		},
	)
}

func (s *Server) closeMeshBridgeRPC(
	ctx context.Context,
	req MeshBridgeCloseRequest,
) (MeshBridgeCloseResponse, error) {
	operationID := strings.TrimSpace(req.OperationID)
	sessionID := strings.TrimSpace(req.SessionID)
	if (operationID == "") == (sessionID == "") {
		return MeshBridgeCloseResponse{}, errors.New("exactly one mesh bridge operation id or session id is required")
	}
	bridge, ok := s.meshBridgeManager().Find(operationID, sessionID)
	if !ok {
		return MeshBridgeCloseResponse{}, errors.New("mesh bridge does not exist")
	}
	if err := bridge.Close(ctx); err != nil {
		return MeshBridgeCloseResponse{}, err
	}
	return MeshBridgeCloseResponse{
		OperationID: bridge.OperationID(),
		SessionID:   bridge.SessionID(),
		State:       MeshOperationStateClosed,
	}, nil
}

func (s *Server) listMeshOperationsRPC(
	_ context.Context,
	req MeshOperationListRequest,
) (MeshOperationListResponse, error) {
	return MeshOperationListResponse{Operations: s.meshBook().List(req)}, nil
}

type SessionReadRequest struct {
	SessionID string
	TimeoutMs int
}

type SessionTailRequest struct {
	SessionID string
	MaxBytes  int
	MaxLines  int
	Consume   bool
}

type SessionWriteRequest struct {
	SessionID string
	Data      []byte
}

type SessionCloseRequest struct {
	SessionID string
}

type SessionCommandListRequest struct {
	SessionID string                        `json:"sessionId"`
	Request   run.PayloadCommandListRequest `json:"request"`
}

type SessionCommandListResponse struct {
	Commands []run.PayloadCommand `json:"commands"`
}

type SessionCommandRunRequest struct {
	SessionID string                    `json:"sessionId"`
	Request   run.PayloadCommandRequest `json:"request"`
}

type SessionCommandRunResponse = run.PayloadCommandResult

type ListSessionsResponse struct {
	Sessions []SessionRef
}

func (s *Server) ListSessions(_ EmptyRequest, resp *ListSessionsResponse) error {
	if s.moduleSessions == nil {
		resp.Sessions = nil
		return nil
	}
	sessions, err := s.moduleSessions.ListSessions(context.Background())
	if err != nil {
		return err
	}
	resp.Sessions = sessionRefsFromRun(sessions)
	return nil
}

func (s *Server) listSessionsRPC(ctx context.Context, _ EmptyRequest) (ListSessionsResponse, error) {
	var resp ListSessionsResponse
	if s.moduleSessions == nil {
		return resp, nil
	}
	sessions, err := s.moduleSessions.ListSessions(ctx)
	if err != nil {
		return resp, err
	}
	resp.Sessions = sessionRefsFromRun(sessions)
	return resp, nil
}

func (s *Server) ReadSession(req SessionReadRequest, resp *SessionChunk) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	chunk, err := s.moduleSessions.ReadSession(context.Background(), req.SessionID, timeout)
	if err != nil {
		return err
	}
	*resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return nil
}

func (s *Server) readSessionRPC(ctx context.Context, req SessionReadRequest) (SessionChunk, error) {
	var resp SessionChunk
	if s.moduleSessions == nil {
		return resp, errors.New("session broker is not configured")
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	chunk, err := s.moduleSessions.ReadSession(ctx, req.SessionID, timeout)
	if err != nil {
		return resp, err
	}
	resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return resp, nil
}

func (s *Server) TailSession(req SessionTailRequest, resp *SessionChunk) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	chunk, err := s.moduleSessions.TailSession(context.Background(), req.SessionID, run.SessionTailOptions{
		MaxBytes: req.MaxBytes,
		MaxLines: req.MaxLines,
		Consume:  req.Consume,
	})
	if err != nil {
		return err
	}
	*resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return nil
}

func (s *Server) tailSessionRPC(ctx context.Context, req SessionTailRequest) (SessionChunk, error) {
	var resp SessionChunk
	if s.moduleSessions == nil {
		return resp, errors.New("session broker is not configured")
	}
	chunk, err := s.moduleSessions.TailSession(ctx, req.SessionID, run.SessionTailOptions{
		MaxBytes: req.MaxBytes,
		MaxLines: req.MaxLines,
		Consume:  req.Consume,
	})
	if err != nil {
		return resp, err
	}
	resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return resp, nil
}

func (s *Server) WriteSession(req SessionWriteRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	return s.moduleSessions.WriteSession(context.Background(), req.SessionID, req.Data)
}

func (s *Server) writeSessionRPC(ctx context.Context, req SessionWriteRequest) (EmptyResponse, error) {
	if s.moduleSessions == nil {
		return EmptyResponse{}, errors.New("session broker is not configured")
	}
	return EmptyResponse{}, s.moduleSessions.WriteSession(ctx, req.SessionID, req.Data)
}

func (s *Server) CloseSession(req SessionCloseRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	if err := s.moduleSessions.CloseSession(context.Background(), req.SessionID); err != nil {
		return err
	}
	s.meshBook().CloseSession(req.SessionID, s.now())
	return nil
}

func (s *Server) closeSessionRPC(ctx context.Context, req SessionCloseRequest) (EmptyResponse, error) {
	if s.moduleSessions == nil {
		return EmptyResponse{}, errors.New("session broker is not configured")
	}
	if err := s.moduleSessions.CloseSession(ctx, req.SessionID); err != nil {
		return EmptyResponse{}, err
	}
	s.meshBook().CloseSession(req.SessionID, s.now())
	return EmptyResponse{}, nil
}

func (s *Server) ListSessionCommands(req SessionCommandListRequest, resp *SessionCommandListResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	commands, err := s.moduleSessions.ListSessionCommands(context.Background(), req.SessionID, req.Request)
	if err != nil {
		return err
	}
	resp.Commands = commands
	return nil
}

func (s *Server) listSessionCommandsRPC(ctx context.Context, req SessionCommandListRequest) (SessionCommandListResponse, error) {
	if s.moduleSessions == nil {
		return SessionCommandListResponse{}, errors.New("session broker is not configured")
	}
	commands, err := s.moduleSessions.ListSessionCommands(ctx, req.SessionID, req.Request)
	if err != nil {
		return SessionCommandListResponse{}, err
	}
	return SessionCommandListResponse{Commands: commands}, nil
}

func (s *Server) RunSessionCommand(req SessionCommandRunRequest, resp *SessionCommandRunResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	result, err := s.moduleSessions.RunSessionCommand(context.Background(), req.SessionID, req.Request)
	if err != nil {
		return err
	}
	*resp = result
	return nil
}

func (s *Server) runSessionCommandRPC(ctx context.Context, req SessionCommandRunRequest) (SessionCommandRunResponse, error) {
	if s.moduleSessions == nil {
		return SessionCommandRunResponse{}, errors.New("session broker is not configured")
	}
	return s.moduleSessions.RunSessionCommand(ctx, req.SessionID, req.Request)
}

type ChainRequest struct {
	Operation string
	Chain     string
}

type RenameChainRequest struct {
	Operation string
	Chain     string
	Name      string
}

type TargetRequest struct {
	Operation string
	Target    string
	Chain     string
}

type TargetSetRequest struct {
	Operation string
	Name      string
	Target    string
	Chain     string
}

type ModuleRequest struct {
	Operation string
	ModuleID  string
	StepID    string
	Chain     string
}

type StepResponse struct {
	ID       string
	ModuleID string
	StepID   string
}

type ConfigRequest struct {
	Operation string
	Key       string
	Value     string
	Chain     string
}

type TargetConfigRequest struct {
	Operation string
	Target    string
	Key       string
	Value     string
	Chain     string
}

type SnapshotRequest struct {
	Operation string
	Chain     string
}

type SnapshotResponse struct {
	State operatorsession.PersistedState
}

type AppendLogRequest struct {
	Operation string
	Chain     string
	Entries   []OperatorLogEntry
}

type EmptyResponse struct{}

type EmptyRequest struct{}

type ActiveLogsRequest struct {
	Operation string
	Chain     string
}

type OperationRequest struct {
	Operation string
}

func (s *Server) AttachEntity(req AttachEntityRequest, resp *EntityResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entity, err := operatordomain.NewEntity(operatordomain.EntityArgs{
		ID:           req.ID,
		Kind:         operatordomain.EntityKind(req.Kind),
		DisplayName:  req.DisplayName,
		Agent:        req.Agent,
		Operation:    req.Operation,
		ActiveChain:  req.ActiveChain,
		ConnectedAt:  now,
		LastSeenAt:   now,
		Capabilities: req.Capabilities,
		PolicyTags:   req.PolicyTags,
	})
	if err != nil {
		return err
	}
	s.ensureEntitiesLocked()
	s.entities[entity.ID] = entity
	resp.Entity = operatorEntityFromDomain(entity)
	return nil
}

func (s *Server) HeartbeatEntity(req HeartbeatEntityRequest, resp *EntityResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return errors.New("operator entity id is required")
	}
	s.ensureEntitiesLocked()
	entity, ok := s.entities[req.ID]
	if !ok {
		return fmt.Errorf("operator entity %s is not attached", req.ID)
	}
	operation := entity.Operation
	if req.Operation != nil {
		operation = *req.Operation
	}
	activeChain := entity.ActiveChain
	if req.ActiveChain != nil {
		activeChain = *req.ActiveChain
	}
	next, err := operatordomain.NewEntity(operatordomain.EntityArgs{
		ID:           entity.ID,
		Kind:         entity.Kind,
		DisplayName:  entity.DisplayName,
		Agent:        entity.Agent,
		Operation:    operation,
		ActiveChain:  activeChain,
		ConnectedAt:  entity.ConnectedAt,
		LastSeenAt:   s.now(),
		Capabilities: entity.Capabilities,
		PolicyTags:   entity.PolicyTags,
	})
	if err != nil {
		return err
	}
	s.entities[next.ID] = next
	resp.Entity = operatorEntityFromDomain(next)
	return nil
}

func (s *Server) DetachEntity(req DetachEntityRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return errors.New("operator entity id is required")
	}
	s.ensureEntitiesLocked()
	delete(s.entities, req.ID)
	return nil
}

func (s *Server) ListEntities(req ListEntitiesRequest, resp *ListEntitiesResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureEntitiesLocked()
	operation := strings.TrimSpace(req.Operation)
	entities := make([]operatordomain.Entity, 0, len(s.entities))
	for _, entity := range s.entities {
		if operation != "" && entity.Operation != operation {
			continue
		}
		entities = append(entities, entity)
	}
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].ID < entities[j].ID
	})
	resp.Entities = make([]OperatorEntity, 0, len(entities))
	for _, entity := range entities {
		resp.Entities = append(resp.Entities, operatorEntityFromDomain(entity))
	}
	return nil
}

func (s *Server) CreatePendingThrow(req CreatePendingThrowRequest, resp *PendingThrowResponse) error {
	operation := operationOrDefault(req.Operation)
	entities, policy, now := s.launchKeyInputs(operation)
	snapshot, err := s.launchKeyCoordinator().CreatePending(launchkey.CreatePendingRequest{
		ID:        req.ID,
		Operation: operation,
		Chain:     strings.TrimSpace(req.Chain),
		PlanHash:  req.PlanHash,
		Flags:     approvalFlags(req.AllowDangerous, req.NowBypass),
		Entities:  entities,
		Policy:    policy,
		Now:       now,
	})
	if err != nil {
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) GetLaunchKeyPolicy(req LaunchKeyPolicyRequest, resp *LaunchKeyPolicyResponse) error {
	operation := operationOrDefault(req.Operation)
	policy := s.launchKeyPolicyForOperation(operation)
	*resp = launchKeyPolicyResponse(operation, policy)
	return nil
}

func (s *Server) SetLaunchKeyPolicy(req SetLaunchKeyPolicyRequest, resp *LaunchKeyPolicyResponse) error {
	operation := operationOrDefault(req.Operation)
	policy, err := launchKeyPolicyFromRequest(req)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.launchKeyByOp == nil {
		s.launchKeyByOp = map[string]operatordomain.LaunchKeyPolicy{}
	}
	s.launchKeyByOp[operation] = policy
	s.mu.Unlock()
	*resp = launchKeyPolicyResponse(operation, policy)
	return nil
}

func (s *Server) ConfirmPendingThrow(req ConfirmPendingThrowRequest, resp *PendingThrowResponse) error {
	snapshot, err := s.launchKeyCoordinator().Confirm(launchkey.ConfirmRequest{
		PendingID:   req.ID,
		EntityID:    req.EntityID,
		PlanHash:    req.PlanHash,
		Flags:       approvalFlags(req.AllowDangerous, req.NowBypass),
		ConfirmedAt: s.now(),
	})
	if err != nil {
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) RequirePendingThrowReady(req PendingThrowRequest, resp *PendingThrowResponse) error {
	snapshot, err := s.launchKeyCoordinator().RequireReady(req.ID)
	if err != nil {
		*resp = pendingThrowResponse(snapshot)
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) CancelPendingThrow(req PendingThrowRequest, resp *EmptyResponse) error {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		return errors.New("pending throw id is required")
	}
	if !s.launchKeyCoordinator().Cancel(id) {
		return fmt.Errorf("pending throw %s does not exist", id)
	}
	return nil
}

func (s *Server) CreateOperation(req OperationRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.session.CreateOperation(req.Operation); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Server) UseOperation(req OperationRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.session.CreateOperation(req.Operation); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Server) CreateChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, "")
	if err := session.CreateChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain created", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) UseChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, "")
	if err := session.UseChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain selected", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) RenameChain(req RenameChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.RenameChain(req.Chain, req.Name); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Name, operatorlog.Info("chain", "chain renamed",
		operatorlog.Field{Name: "from", Value: req.Chain},
		operatorlog.Field{Name: "to", Value: req.Name},
	))
	return s.persistLocked()
}

func (s *Server) DeleteChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.DeleteChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain deleted", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) AddTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.AddTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target added", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) BindTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.BindTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target bound", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) UnbindTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.UnbindTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target unbound", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) ClearTargets(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	session.ClearTargets()
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "targets cleared"))
	}
	return s.persistLocked()
}

func (s *Server) CreateTargetSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.CreateTargetSet(req.Name); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target set created", operatorlog.Field{Name: "targetSet", Value: req.Name}))
	}
	return s.persistLocked()
}

func (s *Server) AddTargetToSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.AddTargetToSet(req.Name, req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target added to set",
			operatorlog.Field{Name: "targetSet", Value: req.Name},
			operatorlog.Field{Name: "target", Value: req.Target},
		))
	}
	return s.persistLocked()
}

func (s *Server) RemoveTargetFromSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.RemoveTargetFromSet(req.Name, req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target removed from set",
			operatorlog.Field{Name: "targetSet", Value: req.Name},
			operatorlog.Field{Name: "target", Value: req.Target},
		))
	}
	return s.persistLocked()
}

func (s *Server) AddModule(req ModuleRequest, resp *StepResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		step, err := session.AddStep(req.ModuleID, req.StepID)
		if err != nil {
			return err
		}
		*resp = StepResponse{ID: step.ID, ModuleID: step.ModuleID, StepID: step.StepID}
		fields := []operatorlog.Field{
			operatorlog.Field{Name: "step", Value: step.ID},
			operatorlog.Field{Name: "module", Value: req.ModuleID},
		}
		if step.StepID != "" {
			fields = append(fields, operatorlog.Field{Name: "providerStep", Value: step.StepID})
		}
		s.publish(operation, chain, operatorlog.Info("chain", "module added", fields...))
		return nil
	})
}

func (s *Server) SetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.SetChainConfig(req.Key, req.Value); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "chain config set", operatorlog.Field{Name: "key", Value: req.Key}))
		return nil
	})
}

func (s *Server) UnsetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.UnsetChainConfig(req.Key); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "chain config unset", operatorlog.Field{Name: "key", Value: req.Key}))
		return nil
	})
}

func (s *Server) SetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.SetTargetConfig(req.Target, req.Key, req.Value); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("config", "target config set",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
	}
	return s.persistLocked()
}

func (s *Server) UnsetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.UnsetTargetConfig(req.Target, req.Key); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("config", "target config unset",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
	}
	return s.persistLocked()
}

func (s *Server) Snapshot(req SnapshotRequest, resp *SnapshotResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp.State = s.attachment(req.Operation, req.Chain).Export()
	return nil
}

func (s *Server) ActiveLogs(req ActiveLogsRequest, resp *[]OperatorLogEntry) error {
	return s.withChainRead(req.Operation, req.Chain, func(session *operatorsession.Session, _, _ string) error {
		for _, entry := range session.ActiveLogs() {
			*resp = append(*resp, operatorLogEntry(entry))
		}
		return nil
	})
}

func (s *Server) AppendLog(req AppendLogRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]operatorlog.Entry, 0, len(req.Entries))
	for _, entry := range req.Entries {
		entries = append(entries, operatorLogFromRPC(entry))
	}
	session := s.attachment(req.Operation, req.Chain)
	if req.Chain == "" {
		if err := session.AppendLog(entries...); err != nil {
			return err
		}
		req.Chain = session.Snapshot().ActiveChain
	} else {
		if err := session.AppendLogToChain(req.Chain, entries...); err != nil {
			return err
		}
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, entries...)
	return s.persistLocked()
}

func (s *Server) PollLogs(req PollLogsRequest, resp *PollLogsResponse) error {
	if req.Chain != "" {
		resp.Last, resp.Logs = s.logs.SinceChain(operationOrDefault(req.Operation), req.Chain, req.Since)
		return nil
	}
	resp.Last, resp.Logs = s.logs.Since(req.Since)
	return nil
}

func (s *Server) createOperationRPC(_ context.Context, req OperationRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateOperation(req, &resp)
	return resp, err
}

func (s *Server) useOperationRPC(_ context.Context, req OperationRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UseOperation(req, &resp)
	return resp, err
}

func (s *Server) createChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateChain(req, &resp)
	return resp, err
}

func (s *Server) useChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UseChain(req, &resp)
	return resp, err
}

func (s *Server) renameChainRPC(_ context.Context, req RenameChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.RenameChain(req, &resp)
	return resp, err
}

func (s *Server) deleteChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.DeleteChain(req, &resp)
	return resp, err
}

func (s *Server) addTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AddTarget(req, &resp)
	return resp, err
}

func (s *Server) bindTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.BindTarget(req, &resp)
	return resp, err
}

func (s *Server) unbindTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnbindTarget(req, &resp)
	return resp, err
}

func (s *Server) clearTargetsRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.ClearTargets(req, &resp)
	return resp, err
}

func (s *Server) createTargetSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateTargetSet(req, &resp)
	return resp, err
}

func (s *Server) addTargetToSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AddTargetToSet(req, &resp)
	return resp, err
}

func (s *Server) removeTargetFromSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.RemoveTargetFromSet(req, &resp)
	return resp, err
}

func (s *Server) addModuleRPC(_ context.Context, req ModuleRequest) (StepResponse, error) {
	var resp StepResponse
	err := s.AddModule(req, &resp)
	return resp, err
}

func (s *Server) setChainConfigRPC(_ context.Context, req ConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.SetChainConfig(req, &resp)
	return resp, err
}

func (s *Server) unsetChainConfigRPC(_ context.Context, req ConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnsetChainConfig(req, &resp)
	return resp, err
}

func (s *Server) setTargetConfigRPC(_ context.Context, req TargetConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.SetTargetConfig(req, &resp)
	return resp, err
}

func (s *Server) unsetTargetConfigRPC(_ context.Context, req TargetConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnsetTargetConfig(req, &resp)
	return resp, err
}

func (s *Server) snapshotRPC(_ context.Context, req SnapshotRequest) (SnapshotResponse, error) {
	var resp SnapshotResponse
	err := s.Snapshot(req, &resp)
	return resp, err
}

func (s *Server) activeLogsRPC(_ context.Context, req ActiveLogsRequest) ([]OperatorLogEntry, error) {
	var resp []OperatorLogEntry
	err := s.ActiveLogs(req, &resp)
	return resp, err
}

func (s *Server) appendLogRPC(_ context.Context, req AppendLogRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AppendLog(req, &resp)
	return resp, err
}

func (s *Server) pollLogsRPC(_ context.Context, req PollLogsRequest) (PollLogsResponse, error) {
	var resp PollLogsResponse
	err := s.PollLogs(req, &resp)
	return resp, err
}

func (s *Server) attachEntityRPC(_ context.Context, req AttachEntityRequest) (EntityResponse, error) {
	var resp EntityResponse
	err := s.AttachEntity(req, &resp)
	return resp, err
}

func (s *Server) heartbeatEntityRPC(_ context.Context, req HeartbeatEntityRequest) (EntityResponse, error) {
	var resp EntityResponse
	err := s.HeartbeatEntity(req, &resp)
	return resp, err
}

func (s *Server) detachEntityRPC(_ context.Context, req DetachEntityRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.DetachEntity(req, &resp)
	return resp, err
}

func (s *Server) listEntitiesRPC(_ context.Context, req ListEntitiesRequest) (ListEntitiesResponse, error) {
	var resp ListEntitiesResponse
	err := s.ListEntities(req, &resp)
	return resp, err
}

func (s *Server) createPendingThrowRPC(_ context.Context, req CreatePendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.CreatePendingThrow(req, &resp)
	return resp, err
}

func (s *Server) confirmPendingThrowRPC(_ context.Context, req ConfirmPendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.ConfirmPendingThrow(req, &resp)
	return resp, err
}

func (s *Server) requirePendingThrowReadyRPC(_ context.Context, req PendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.RequirePendingThrowReady(req, &resp)
	return resp, err
}

func (s *Server) cancelPendingThrowRPC(_ context.Context, req PendingThrowRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CancelPendingThrow(req, &resp)
	return resp, err
}

func (s *Server) getLaunchKeyPolicyRPC(_ context.Context, req LaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	var resp LaunchKeyPolicyResponse
	err := s.GetLaunchKeyPolicy(req, &resp)
	return resp, err
}

func (s *Server) setLaunchKeyPolicyRPC(_ context.Context, req SetLaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	var resp LaunchKeyPolicyResponse
	err := s.SetLaunchKeyPolicy(req, &resp)
	return resp, err
}

func (s *Server) publish(operation, chain string, entries ...operatorlog.Entry) {
	s.logs.Publish(operation, chain, entries...)
}

func (s *Server) withChain(operation, chain string, fn func(*operatorsession.Session, string, string) error) error {
	return s.withChainAccess(operation, chain, true, fn)
}

func (s *Server) withChainRead(operation, chain string, fn func(*operatorsession.Session, string, string) error) error {
	return s.withChainAccess(operation, chain, false, fn)
}

func (s *Server) withChainAccess(operation, chain string, persist bool, fn func(*operatorsession.Session, string, string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(operation, chain)
	if chain == "" {
		chain = session.Snapshot().ActiveChain
	}
	if chain == "" {
		return errors.New("active chain is required")
	}
	if err := fn(session, session.Snapshot().ActiveOperation, chain); err != nil {
		return err
	}
	if !persist {
		return nil
	}
	return s.persistLocked()
}

func (s *Server) attachment(operation, chain string) *operatorsession.Session {
	operation = operationOrDefault(operation)
	return s.session.Attachment(operation, chain)
}

func (s *Server) persistLocked() error {
	if s.persistSession == nil {
		return nil
	}
	return s.persistSession(s.session.Export())
}

func operationOrDefault(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return operatorsession.DefaultOperation
	}
	return operation
}

func (s *Server) ensureEntitiesLocked() {
	if s.entities == nil {
		s.entities = map[string]operatordomain.Entity{}
	}
}

func (s *Server) launchKeyInputs(operation string) ([]operatordomain.Entity, operatordomain.LaunchKeyPolicy, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureEntitiesLocked()
	entities := make([]operatordomain.Entity, 0, len(s.entities))
	for _, entity := range s.entities {
		entities = append(entities, entity)
	}
	return entities, s.launchKeyPolicyForOperationLocked(operation), s.now()
}

func (s *Server) launchKeyCoordinator() *launchkey.Coordinator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.launchKeys == nil {
		s.launchKeys = launchkey.NewCoordinator()
	}
	return s.launchKeys
}

func approvalFlags(allowDangerous, nowBypass bool) operatordomain.ApprovalFlags {
	return operatordomain.ApprovalFlags{
		AllowDangerous: allowDangerous,
		NowBypass:      nowBypass,
	}
}

func pendingThrowResponse(snapshot launchkey.PendingSnapshot) PendingThrowResponse {
	createdAt := ""
	if !snapshot.CreatedAt.IsZero() {
		createdAt = snapshot.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return PendingThrowResponse{
		ID:                  snapshot.ID,
		Operation:           snapshot.Operation,
		Chain:               snapshot.Chain,
		PlanHash:            snapshot.PlanHash,
		AllowDangerous:      snapshot.Flags.AllowDangerous,
		NowBypass:           snapshot.Flags.NowBypass,
		CreatedAt:           createdAt,
		Ready:               snapshot.Ready,
		RequiredApproverIDs: append([]string(nil), snapshot.RequiredApproverIDs...),
		MissingApproverIDs:  append([]string(nil), snapshot.MissingApproverIDs...),
	}
}

func (s *Server) launchKeyPolicyForOperation(operation string) operatordomain.LaunchKeyPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.launchKeyPolicyForOperationLocked(operation)
}

func (s *Server) launchKeyPolicyForOperationLocked(operation string) operatordomain.LaunchKeyPolicy {
	operation = operationOrDefault(operation)
	if s.launchKeyByOp != nil {
		if policy, ok := s.launchKeyByOp[operation]; ok {
			return operatordomain.NormalizeLaunchKeyPolicy(policy)
		}
	}
	return operatordomain.NormalizeLaunchKeyPolicy(s.launchKeyPolicy)
}

func launchKeyPolicyFromRequest(req SetLaunchKeyPolicyRequest) (operatordomain.LaunchKeyPolicy, error) {
	policy := operatordomain.LaunchKeyPolicy{
		Mode:   operatordomain.LaunchKeyMode(strings.TrimSpace(req.Mode)),
		Quorum: req.Quorum,
	}
	switch policy.Mode {
	case operatordomain.LaunchKeyAnyone, operatordomain.LaunchKeyAllConnected:
	case operatordomain.LaunchKeyQuorum:
		if policy.Quorum < 1 {
			return operatordomain.LaunchKeyPolicy{}, errors.New("launch-key quorum must be at least 1")
		}
	default:
		return operatordomain.LaunchKeyPolicy{}, fmt.Errorf("unsupported launch-key mode %q", req.Mode)
	}
	if timeout := strings.TrimSpace(req.HeartbeatTimeout); timeout != "" {
		parsed, err := time.ParseDuration(timeout)
		if err != nil {
			return operatordomain.LaunchKeyPolicy{}, fmt.Errorf("invalid launch-key heartbeat timeout: %w", err)
		}
		policy.HeartbeatTimeout = parsed
	}
	return operatordomain.NormalizeLaunchKeyPolicy(policy), nil
}

func launchKeyPolicyResponse(operation string, policy operatordomain.LaunchKeyPolicy) LaunchKeyPolicyResponse {
	policy = operatordomain.NormalizeLaunchKeyPolicy(policy)
	timeout := ""
	if policy.HeartbeatTimeout != 0 {
		timeout = policy.HeartbeatTimeout.String()
	}
	return LaunchKeyPolicyResponse{
		Operation: operationOrDefault(operation),
		Policy: LaunchKeyPolicyOutput{
			Mode:             string(policy.Mode),
			Quorum:           policy.Quorum,
			HeartbeatTimeout: timeout,
		},
	}
}

func operatorEntityFromDomain(entity operatordomain.Entity) OperatorEntity {
	return OperatorEntity{
		ID:           entity.ID,
		Kind:         string(entity.Kind),
		DisplayName:  entity.DisplayName,
		Agent:        entity.Agent,
		Operation:    entity.Operation,
		ActiveChain:  entity.ActiveChain,
		ConnectedAt:  entity.ConnectedAt.UTC().Format(time.RFC3339Nano),
		LastSeenAt:   entity.LastSeenAt.UTC().Format(time.RFC3339Nano),
		Capabilities: append([]string(nil), entity.Capabilities...),
		PolicyTags:   append([]string(nil), entity.PolicyTags...),
	}
}

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func Dial(socketPath string) (*Client, error) {
	endpoint, err := ParseEndpoint(socketPath)
	if err != nil {
		return nil, err
	}
	client := NewClient(endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := client.PollLogs(ctx, 0); err != nil {
		logDaemonRPCError("close daemon client after failed dial", client.Close())
		return nil, err
	}
	return client, nil
}

func NewClient(endpoint Endpoint) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	baseURL := endpoint.BaseURL()
	if endpoint.Network == "unix" {
		address := endpoint.Address
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", address)
		}
	}
	return &Client{
		httpClient: &http.Client{Transport: transport},
		baseURL:    baseURL,
	}
}

func (c *Client) Close() error {
	if c == nil || c.httpClient == nil {
		return nil
	}
	c.httpClient.CloseIdleConnections()
	return nil
}

func (c *Client) RunMockExploit(ctx context.Context, req RunMockExploitRequest) (RunMockExploitResponse, error) {
	return c.ExecuteModule(ctx, ExecuteModuleRequest(req))
}

func (c *Client) ExecuteModule(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	return invoke[ExecuteModuleRequest, ExecuteModuleResponse](c, ctx, "ExecuteModule", req)
}

func (c *Client) GeneratePayload(ctx context.Context, req PayloadGenerateRequest) (PayloadGenerateResponse, error) {
	return invoke[PayloadGenerateRequest, PayloadGenerateResponse](c, ctx, "GeneratePayload", req)
}

func (c *Client) ListPayloadCommands(ctx context.Context, req PayloadCommandListRequest) (PayloadCommandListResponse, error) {
	return invoke[PayloadCommandListRequest, PayloadCommandListResponse](c, ctx, "ListPayloadCommands", req)
}

func (c *Client) RunPayloadCommand(ctx context.Context, req PayloadCommandRunRequest) (PayloadCommandRunResponse, error) {
	return invoke[PayloadCommandRunRequest, PayloadCommandRunResponse](c, ctx, "RunPayloadCommand", req)
}

func (c *Client) DescribeMesh(
	ctx context.Context,
	req MeshDescribeRequest,
) (MeshDescribeResponse, error) {
	return invoke[MeshDescribeRequest, MeshDescribeResponse](c, ctx, rpcMethodDescribeMesh, req)
}

func (c *Client) MeshTopology(
	ctx context.Context,
	req MeshTopologyRequest,
) (MeshTopologyResponse, error) {
	return invoke[MeshTopologyRequest, MeshTopologyResponse](c, ctx, rpcMethodMeshTopology, req)
}

func (c *Client) ListMeshBeacons(
	ctx context.Context,
	req MeshBeaconListRequest,
) (MeshBeaconListResponse, error) {
	return invoke[MeshBeaconListRequest, MeshBeaconListResponse](c, ctx, rpcMethodListMeshBeacons, req)
}

func (c *Client) RunMeshTask(
	ctx context.Context,
	req MeshTaskRunRequest,
) (MeshTaskRunResponse, error) {
	return invoke[MeshTaskRunRequest, MeshTaskRunResponse](c, ctx, rpcMethodRunMeshTask, req)
}

func (c *Client) OpenMeshStream(
	ctx context.Context,
	req MeshStreamOpenRequest,
) (MeshStreamOpenResponse, error) {
	return invoke[MeshStreamOpenRequest, MeshStreamOpenResponse](c, ctx, rpcMethodOpenMeshStream, req)
}

func (c *Client) OpenMeshBridge(
	ctx context.Context,
	req MeshBridgeOpenRequest,
) (MeshBridgeOpenResponse, error) {
	return invoke[MeshBridgeOpenRequest, MeshBridgeOpenResponse](c, ctx, rpcMethodOpenMeshBridge, req)
}

func (c *Client) CloseMeshBridge(
	ctx context.Context,
	req MeshBridgeCloseRequest,
) (MeshBridgeCloseResponse, error) {
	return invoke[MeshBridgeCloseRequest, MeshBridgeCloseResponse](c, ctx, rpcMethodCloseMeshBridge, req)
}

func (c *Client) ListMeshOperations(
	ctx context.Context,
	req MeshOperationListRequest,
) (MeshOperationListResponse, error) {
	return invoke[MeshOperationListRequest, MeshOperationListResponse](c, ctx, rpcMethodListMeshOperations, req)
}

func (c *Client) ListSessions(ctx context.Context) ([]SessionRef, error) {
	resp, err := invoke[EmptyRequest, ListSessionsResponse](c, ctx, "ListSessions", EmptyRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func (c *Client) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (SessionChunk, error) {
	return invoke[SessionReadRequest, SessionChunk](c, ctx, "ReadSession", SessionReadRequest{
		SessionID: sessionID,
		TimeoutMs: int(timeout / time.Millisecond),
	})
}

func (c *Client) TailSession(ctx context.Context, sessionID string, options run.SessionTailOptions) (SessionChunk, error) {
	return invoke[SessionTailRequest, SessionChunk](c, ctx, "TailSession", SessionTailRequest{
		SessionID: sessionID,
		MaxBytes:  options.MaxBytes,
		MaxLines:  options.MaxLines,
		Consume:   options.Consume,
	})
}

func (c *Client) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	_, err := invoke[SessionWriteRequest, EmptyResponse](c, ctx, "WriteSession", SessionWriteRequest{
		SessionID: sessionID,
		Data:      append([]byte(nil), data...),
	})
	return err
}

func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	_, err := invoke[SessionCloseRequest, EmptyResponse](c, ctx, "CloseSession", SessionCloseRequest{SessionID: sessionID})
	return err
}

func (c *Client) ListSessionCommands(ctx context.Context, req SessionCommandListRequest) (SessionCommandListResponse, error) {
	return invoke[SessionCommandListRequest, SessionCommandListResponse](c, ctx, "ListSessionCommands", req)
}

func (c *Client) RunSessionCommand(ctx context.Context, req SessionCommandRunRequest) (SessionCommandRunResponse, error) {
	return invoke[SessionCommandRunRequest, SessionCommandRunResponse](c, ctx, "RunSessionCommand", req)
}

func (c *Client) PollLogs(ctx context.Context, since uint64) (PollLogsResponse, error) {
	return c.pollLogs(ctx, "", "", since)
}

func (c *Client) PollChainLogs(ctx context.Context, chain string, since uint64) (PollLogsResponse, error) {
	return c.PollOperationChainLogs(ctx, operatorsession.DefaultOperation, chain, since)
}

func (c *Client) PollOperationChainLogs(ctx context.Context, operation, chain string, since uint64) (PollLogsResponse, error) {
	return c.pollLogs(ctx, operation, chain, since)
}

func (c *Client) pollLogs(ctx context.Context, operation, chain string, since uint64) (PollLogsResponse, error) {
	return invoke[PollLogsRequest, PollLogsResponse](c, ctx, "PollLogs", PollLogsRequest{Since: since, Operation: operation, Chain: chain})
}

func (c *Client) AttachEntity(ctx context.Context, req AttachEntityRequest) (EntityResponse, error) {
	return invoke[AttachEntityRequest, EntityResponse](c, ctx, "AttachEntity", req)
}

func (c *Client) HeartbeatEntity(ctx context.Context, req HeartbeatEntityRequest) (EntityResponse, error) {
	return invoke[HeartbeatEntityRequest, EntityResponse](c, ctx, "HeartbeatEntity", req)
}

func (c *Client) DetachEntity(ctx context.Context, req DetachEntityRequest) error {
	_, err := invoke[DetachEntityRequest, EmptyResponse](c, ctx, "DetachEntity", req)
	return err
}

func (c *Client) ListEntities(ctx context.Context, req ListEntitiesRequest) (ListEntitiesResponse, error) {
	return invoke[ListEntitiesRequest, ListEntitiesResponse](c, ctx, "ListEntities", req)
}

func (c *Client) Snapshot(ctx context.Context, req SnapshotRequest) (SnapshotResponse, error) {
	return invoke[SnapshotRequest, SnapshotResponse](c, ctx, "Snapshot", req)
}

func (c *Client) CreatePendingThrow(ctx context.Context, req CreatePendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[CreatePendingThrowRequest, PendingThrowResponse](c, ctx, "CreatePendingThrow", req)
}

func (c *Client) ConfirmPendingThrow(ctx context.Context, req ConfirmPendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[ConfirmPendingThrowRequest, PendingThrowResponse](c, ctx, "ConfirmPendingThrow", req)
}

func (c *Client) RequirePendingThrowReady(ctx context.Context, req PendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[PendingThrowRequest, PendingThrowResponse](c, ctx, "RequirePendingThrowReady", req)
}

func (c *Client) CancelPendingThrow(ctx context.Context, req PendingThrowRequest) error {
	_, err := invoke[PendingThrowRequest, EmptyResponse](c, ctx, "CancelPendingThrow", req)
	return err
}

func (c *Client) GetLaunchKeyPolicy(ctx context.Context, req LaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	return invoke[LaunchKeyPolicyRequest, LaunchKeyPolicyResponse](c, ctx, "GetLaunchKeyPolicy", req)
}

func (c *Client) SetLaunchKeyPolicy(ctx context.Context, req SetLaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	return invoke[SetLaunchKeyPolicyRequest, LaunchKeyPolicyResponse](c, ctx, "SetLaunchKeyPolicy", req)
}

type SessionClient struct {
	client          *Client
	ctx             context.Context
	mu              sync.Mutex
	activeOperation string
	activeChains    map[string]string
}

func NewSessionClient(ctx context.Context, client *Client) *SessionClient {
	return &SessionClient{
		client:       client,
		ctx:          ctx,
		activeChains: map[string]string{},
	}
}

func (s *SessionClient) RemoteFeedback() bool {
	return true
}

func (s *SessionClient) CreateOperation(operation string) error {
	_, err := invoke[OperationRequest, EmptyResponse](s.client, s.ctx, "CreateOperation", OperationRequest{Operation: operation})
	return err
}

func (s *SessionClient) UseOperation(operation string) error {
	if _, err := invoke[OperationRequest, EmptyResponse](s.client, s.ctx, "UseOperation", OperationRequest{Operation: operation}); err != nil {
		return err
	}
	s.setActiveOperation(operation)
	return nil
}

func (s *SessionClient) CreateChain(chain string) error {
	_, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "CreateChain", ChainRequest{Operation: s.operation(), Chain: chain})
	return err
}

func (s *SessionClient) UseChain(chain string) error {
	if _, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "UseChain", ChainRequest{Operation: s.operation(), Chain: chain}); err != nil {
		return err
	}
	s.setActiveChain(chain)
	return nil
}

func (s *SessionClient) RenameChain(chain, name string) error {
	if _, err := invoke[RenameChainRequest, EmptyResponse](s.client, s.ctx, "RenameChain", RenameChainRequest{Operation: s.operation(), Chain: chain, Name: name}); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain(name)
	}
	return nil
}

func (s *SessionClient) DeleteChain(chain string) error {
	if _, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "DeleteChain", ChainRequest{Operation: s.operation(), Chain: chain}); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain("")
	}
	return nil
}

func (s *SessionClient) AddTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "AddTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) BindTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "BindTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) UnbindTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "UnbindTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) ClearTargets() {
	_, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "ClearTargets", ChainRequest{Operation: s.operation(), Chain: s.active()})
	logDaemonRPCError("clear session targets", err)
}

func (s *SessionClient) CreateTargetSet(name string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "CreateTargetSet", TargetSetRequest{Operation: s.operation(), Name: name, Chain: s.active()})
	return err
}

func (s *SessionClient) AddTargetToSet(name, target string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "AddTargetToSet", TargetSetRequest{Operation: s.operation(), Name: name, Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) RemoveTargetFromSet(name, target string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "RemoveTargetFromSet", TargetSetRequest{Operation: s.operation(), Name: name, Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) AddModule(moduleID string) (operatorsession.Step, error) {
	return s.AddStep(moduleID, "")
}

func (s *SessionClient) AddStep(moduleID, stepID string) (operatorsession.Step, error) {
	resp, err := invoke[ModuleRequest, StepResponse](s.client, s.ctx, "AddModule", ModuleRequest{Operation: s.operation(), ModuleID: moduleID, StepID: stepID, Chain: s.active()})
	return operatorsession.Step{ID: resp.ID, ModuleID: resp.ModuleID, StepID: resp.StepID}, err
}

func (s *SessionClient) SetChainConfig(key, value string) error {
	_, err := invoke[ConfigRequest, EmptyResponse](s.client, s.ctx, "SetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Value: value, Chain: s.active()})
	return err
}

func (s *SessionClient) UnsetChainConfig(key string) error {
	_, err := invoke[ConfigRequest, EmptyResponse](s.client, s.ctx, "UnsetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Chain: s.active()})
	return err
}

func (s *SessionClient) SetTargetConfig(target, key, value string) error {
	_, err := invoke[TargetConfigRequest, EmptyResponse](s.client, s.ctx, "SetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Value: value, Chain: s.active()})
	return err
}

func (s *SessionClient) UnsetTargetConfig(target, key string) error {
	_, err := invoke[TargetConfigRequest, EmptyResponse](s.client, s.ctx, "UnsetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Chain: s.active()})
	return err
}

func (s *SessionClient) AppendLog(entries ...operatorlog.Entry) error {
	_, err := invoke[AppendLogRequest, EmptyResponse](s.client, s.ctx, "AppendLog", AppendLogRequest{Operation: s.operation(), Chain: s.active(), Entries: operatorLogEntries(entries)})
	return err
}

func (s *SessionClient) AppendLogToChain(chain string, entries ...operatorlog.Entry) error {
	_, err := invoke[AppendLogRequest, EmptyResponse](s.client, s.ctx, "AppendLog", AppendLogRequest{Operation: s.operation(), Chain: chain, Entries: operatorLogEntries(entries)})
	return err
}

func (s *SessionClient) ActiveLogs() []operatorlog.Entry {
	resp, err := invoke[ActiveLogsRequest, []OperatorLogEntry](s.client, s.ctx, "ActiveLogs", ActiveLogsRequest{Operation: s.operation(), Chain: s.active()})
	if err != nil {
		return nil
	}
	out := make([]operatorlog.Entry, 0, len(resp))
	for _, entry := range resp {
		out = append(out, operatorLogFromRPC(entry))
	}
	return out
}

func (s *SessionClient) Snapshot() operatorsession.State {
	resp, err := invoke[SnapshotRequest, SnapshotResponse](s.client, s.ctx, "Snapshot", SnapshotRequest{Operation: s.operation(), Chain: s.active()})
	if err != nil {
		return operatorsession.State{}
	}
	session := operatorsession.New()
	session.Import(resp.State)
	return session.Snapshot()
}

func (s *SessionClient) ActiveOperationSelected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.activeOperation) != ""
}

func (s *SessionClient) active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeChains[s.operationLocked()]
}

func (s *SessionClient) setActiveChain(chain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	s.activeChains[s.operationLocked()] = chain
}

func (s *SessionClient) operation() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.operationLocked()
}

func (s *SessionClient) operationLocked() string {
	operation := strings.TrimSpace(s.activeOperation)
	if operation == "" {
		return operatorsession.DefaultOperation
	}
	return operation
}

func (s *SessionClient) setActiveOperation(operation string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = operatorsession.DefaultOperation
	}
	s.activeOperation = operation
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
}

func invoke[Req, Res any](c *Client, ctx context.Context, method string, req Req) (Res, error) {
	var zero Res
	if c == nil || c.httpClient == nil || c.baseURL == "" {
		return zero, errors.New("daemon rpc client is not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+serviceURLPrefix+method, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	defer func() { logDaemonRPCError("close response body", resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return zero, fmt.Errorf("%s: %s; additionally failed to read error response: %v", method, resp.Status, readErr)
		}
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = resp.Status
		}
		return zero, fmt.Errorf("%s: %s", method, message)
	}
	if err := json.NewDecoder(resp.Body).Decode(&zero); err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	return zero, nil
}

type Endpoint struct {
	Network string
	Address string
}

func ParseEndpoint(value string) (Endpoint, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Endpoint{}, errors.New("daemon rpc endpoint is required")
	}
	switch {
	case strings.HasPrefix(value, "unix://"):
		path := strings.TrimPrefix(value, "unix://")
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return unixEndpoint(path)
	case strings.HasPrefix(value, "unix:"):
		return unixEndpoint(strings.TrimPrefix(value, "unix:"))
	case strings.HasPrefix(value, "tcp://"):
		return tcpEndpoint(strings.TrimPrefix(value, "tcp://"))
	case strings.HasPrefix(value, "http://"):
		return tcpEndpoint(strings.TrimPrefix(value, "http://"))
	case strings.HasPrefix(value, "https://"):
		return Endpoint{}, errors.New("daemon rpc tcp endpoint must use http, not https")
	case strings.Contains(value, "/"):
		return unixEndpoint(value)
	default:
		if _, _, err := net.SplitHostPort(value); err == nil {
			return tcpEndpoint(value)
		}
		return unixEndpoint(value)
	}
}

func unixEndpoint(path string) (Endpoint, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Endpoint{}, errors.New("daemon unix socket path is required")
	}
	return Endpoint{Network: "unix", Address: path}, nil
}

func tcpEndpoint(address string) (Endpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return Endpoint{}, errors.New("daemon tcp address is required")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Network: "tcp", Address: address}, nil
}

func (e Endpoint) BaseURL() string {
	if e.Network == "unix" {
		return "http://hoveld"
	}
	return "http://" + e.Address
}

func (e Endpoint) String() string {
	if e.Network == "tcp" {
		return "tcp://" + e.Address
	}
	if strings.HasPrefix(e.Address, "unix:") {
		return e.Address
	}
	return e.Address
}

type LogBroker struct {
	mu    sync.Mutex
	next  uint64
	logs  []PublishedLog
	limit int
	start int
	count int
}

const defaultLogBrokerLimit = 4096

func NewLogBroker() *LogBroker {
	return NewLogBrokerWithLimit(defaultLogBrokerLimit)
}

func NewLogBrokerWithLimit(limit int) *LogBroker {
	if limit <= 0 {
		limit = defaultLogBrokerLimit
	}
	return &LogBroker{limit: limit}
}

func (b *LogBroker) Publish(operation, chain string, entries ...operatorlog.Entry) {
	if b == nil {
		return
	}
	operation = operationOrDefault(operation)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, entry := range entries {
		b.next++
		log := PublishedLog{
			Seq:       b.next,
			Operation: operation,
			Chain:     chain,
			Entry:     operatorLogEntry(entry),
		}
		if b.count < b.limit {
			b.logs = append(b.logs, log)
			b.count++
			continue
		}
		b.logs[b.start] = log
		b.start = (b.start + 1) % b.limit
	}
}

func (b *LogBroker) Since(since uint64) (uint64, []PublishedLog) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var logs []PublishedLog
	for i := 0; i < b.count; i++ {
		log := b.logs[(b.start+i)%len(b.logs)]
		if log.Seq > since {
			logs = append(logs, log)
		}
	}
	return b.next, logs
}

func (b *LogBroker) SinceChain(operation, chain string, since uint64) (uint64, []PublishedLog) {
	if b == nil {
		return 0, nil
	}
	operation = operationOrDefault(operation)
	b.mu.Lock()
	defer b.mu.Unlock()
	var logs []PublishedLog
	for i := 0; i < b.count; i++ {
		log := b.logs[(b.start+i)%len(b.logs)]
		if log.Seq > since && log.Operation == operation && log.Chain == chain {
			logs = append(logs, log)
		}
	}
	return b.next, logs
}

func responseFromResult(result run.Result) RunMockExploitResponse {
	resp := RunMockExploitResponse{
		RunID:    result.ID,
		ModuleID: result.ModuleID,
		Target:   result.Target,
		State:    string(result.State),
		Summary:  result.Summary,
	}
	for _, finding := range result.Findings {
		resp.Findings = append(resp.Findings, Finding{
			Title:    finding.Title,
			Severity: string(finding.Severity),
			Detail:   finding.Detail,
		})
	}
	for _, artifact := range result.Artifacts {
		resp.Artifacts = append(resp.Artifacts, Artifact{
			Name: artifact.Name,
			Kind: artifact.Kind,
			Data: artifact.Data,
			Path: artifact.Path,
		})
	}
	resp.Sessions = sessionRefsFromRun(result.Sessions)
	resp.InstalledPayloads = run.CloneInstalledPayloads(result.InstalledPayloads)
	for _, log := range result.Logs {
		resp.Logs = append(resp.Logs, LogEntry{
			ID:             log.ID,
			Time:           log.Time,
			Topic:          log.Topic,
			Kind:           log.Kind,
			Level:          log.Level,
			Source:         sourceOrDefault(log.Source, "module"),
			Message:        log.Message,
			Logger:         log.Logger,
			ChainID:        log.ChainID,
			ChainName:      log.ChainName,
			RunID:          log.RunID,
			Target:         log.Target,
			ModuleID:       log.ModuleID,
			ElapsedSeconds: cloneFloat64(log.ElapsedSeconds),
			Fields:         cloneStringMap(log.Fields),
			Attributes:     cloneStringMap(log.Attributes),
		})
	}
	return resp
}

func sessionRefsFromRun(sessions []run.SessionRef) []SessionRef {
	out := make([]SessionRef, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, SessionRef{
			ID:                 session.ID,
			RunID:              session.RunID,
			ModuleID:           session.ModuleID,
			Target:             session.Target,
			Name:               session.Name,
			Kind:               session.Kind,
			State:              session.State,
			Transport:          session.Transport,
			InstalledPayloadID: session.InstalledPayloadID,
			Capabilities:       append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func sourceOrDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func operatorLogEntry(entry operatorlog.Entry) OperatorLogEntry {
	return OperatorLogEntry{
		ID:             entry.ID,
		Time:           entry.Time.Format(time.RFC3339Nano),
		Topic:          entry.Topic,
		Kind:           string(entry.Kind),
		Level:          string(entry.Level),
		Source:         entry.Source,
		Message:        entry.Message,
		ChainID:        entry.ChainID,
		ChainName:      entry.ChainName,
		RunID:          entry.RunID,
		Target:         entry.Target,
		ModuleID:       entry.ModuleID,
		ElapsedSeconds: cloneFloat64(entry.ElapsedSeconds),
		Fields:         fieldsToMap(entry.Fields),
		Attributes:     cloneStringMap(entry.Attributes),
	}
}

func operatorLogEntries(entries []operatorlog.Entry) []OperatorLogEntry {
	out := make([]OperatorLogEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, operatorLogEntry(entry))
	}
	return out
}

func operatorLogFromRPC(entry OperatorLogEntry) operatorlog.Entry {
	fields := make([]operatorlog.Field, 0, len(entry.Fields))
	for name, value := range entry.Fields {
		fields = append(fields, operatorlog.Field{Name: name, Value: value})
	}
	timestamp, err := time.Parse(time.RFC3339Nano, entry.Time)
	logDaemonRPCError("parse operator log timestamp", err)
	return operatorlog.Entry{
		ID:             entry.ID,
		Time:           timestamp,
		Topic:          entry.Topic,
		Kind:           operatorlog.Kind(entry.Kind),
		Level:          operatorlog.Level(entry.Level),
		Source:         entry.Source,
		Message:        entry.Message,
		ChainID:        entry.ChainID,
		ChainName:      entry.ChainName,
		RunID:          entry.RunID,
		Target:         entry.Target,
		ModuleID:       entry.ModuleID,
		ElapsedSeconds: cloneFloat64(entry.ElapsedSeconds),
		Fields:         fields,
		Attributes:     cloneStringMap(entry.Attributes),
	}
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func fieldsToMap(fields []operatorlog.Field) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for _, field := range fields {
		out[field.Name] = field.Value
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

func logDaemonRPCError(action string, err error) {
	if err != nil {
		log.Printf("hovel daemon rpc: %s: %v", action, err)
	}
}
