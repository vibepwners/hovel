package daemonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const (
	serviceName      = "Daemon"
	serviceURLPrefix = "/hovel.daemon.v1.DaemonService/"
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
	ID           string
	RunID        string
	ModuleID     string
	Target       string
	Name         string
	Kind         string
	State        string
	Transport    string
	Capabilities []string
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

type ExecuteModuleResponse = RunMockExploitResponse

type Server struct {
	runs           services.RunService
	moduleSessions services.SessionBroker
	session        *operatorsession.Session
	logs           *LogBroker
	persistSession func(operatorsession.PersistedState) error
	mu             sync.Mutex
}

func Register(mux *http.ServeMux, runs services.RunService, options ...ServerOption) error {
	if mux == nil {
		return errors.New("daemon rpc mux is required")
	}
	rpcServer := &Server{
		runs:    runs,
		session: operatorsession.New(),
		logs:    NewLogBroker(),
	}
	for _, option := range options {
		option(rpcServer)
	}
	registerUnary[ExecuteModuleRequest, ExecuteModuleResponse](mux, "ExecuteModule", rpcServer.executeModuleRPC)
	registerUnary[EmptyRequest, ListSessionsResponse](mux, "ListSessions", rpcServer.listSessionsRPC)
	registerUnary[SessionReadRequest, SessionChunk](mux, "ReadSession", rpcServer.readSessionRPC)
	registerUnary[SessionWriteRequest, EmptyResponse](mux, "WriteSession", rpcServer.writeSessionRPC)
	registerUnary[SessionCloseRequest, EmptyResponse](mux, "CloseSession", rpcServer.closeSessionRPC)
	registerUnary[OperationRequest, EmptyResponse](mux, "CreateOperation", rpcServer.createOperationRPC)
	registerUnary[OperationRequest, EmptyResponse](mux, "UseOperation", rpcServer.useOperationRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "CreateChain", rpcServer.createChainRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "UseChain", rpcServer.useChainRPC)
	registerUnary[RenameChainRequest, EmptyResponse](mux, "RenameChain", rpcServer.renameChainRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "DeleteChain", rpcServer.deleteChainRPC)
	registerUnary[TargetRequest, EmptyResponse](mux, "AddTarget", rpcServer.addTargetRPC)
	registerUnary[ChainRequest, EmptyResponse](mux, "ClearTargets", rpcServer.clearTargetsRPC)
	registerUnary[ModuleRequest, StepResponse](mux, "AddModule", rpcServer.addModuleRPC)
	registerUnary[ConfigRequest, EmptyResponse](mux, "SetChainConfig", rpcServer.setChainConfigRPC)
	registerUnary[ConfigRequest, EmptyResponse](mux, "UnsetChainConfig", rpcServer.unsetChainConfigRPC)
	registerUnary[TargetConfigRequest, EmptyResponse](mux, "SetTargetConfig", rpcServer.setTargetConfigRPC)
	registerUnary[TargetConfigRequest, EmptyResponse](mux, "UnsetTargetConfig", rpcServer.unsetTargetConfigRPC)
	registerUnary[SnapshotRequest, SnapshotResponse](mux, "Snapshot", rpcServer.snapshotRPC)
	registerUnary[ActiveLogsRequest, []OperatorLogEntry](mux, "ActiveLogs", rpcServer.activeLogsRPC)
	registerUnary[AppendLogRequest, EmptyResponse](mux, "AppendLog", rpcServer.appendLogRPC)
	registerUnary[PollLogsRequest, PollLogsResponse](mux, "PollLogs", rpcServer.pollLogsRPC)
	return nil
}

func NewHandler(runs services.RunService, options ...ServerOption) (http.Handler, error) {
	mux := http.NewServeMux()
	if err := Register(mux, runs, options...); err != nil {
		return nil, err
	}
	return mux, nil
}

type jsonCodec struct{}

func (jsonCodec) Name() string {
	return "json"
}

func (jsonCodec) Marshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func (jsonCodec) Unmarshal(data []byte, value any) error {
	return json.Unmarshal(data, value)
}

func registerUnary[Req, Res any](mux *http.ServeMux, method string, fn func(context.Context, Req) (Res, error)) {
	path := serviceURLPrefix + method
	mux.Handle(path, connect.NewUnaryHandler[Req, Res](
		path,
		func(ctx context.Context, req *connect.Request[Req]) (*connect.Response[Res], error) {
			resp, err := fn(ctx, *req.Msg)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnknown, err)
			}
			return connect.NewResponse(&resp), nil
		},
		connect.WithCodec(jsonCodec{}),
	))
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

func (s Server) RunMockExploit(req RunMockExploitRequest, resp *RunMockExploitResponse) error {
	return s.ExecuteModule(ExecuteModuleRequest(req), (*ExecuteModuleResponse)(resp))
}

func (s *Server) executeModuleRPC(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	var resp ExecuteModuleResponse
	err := s.executeModule(ctx, req, &resp)
	return resp, err
}

func (s Server) ExecuteModule(req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	return s.executeModule(context.Background(), req, resp)
}

func (s Server) executeModule(ctx context.Context, req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	var throwStarted time.Time
	if req.ThrowStarted != "" {
		throwStarted, _ = time.Parse(time.RFC3339Nano, req.ThrowStarted)
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

type SessionReadRequest struct {
	SessionID string
	TimeoutMs int
}

type SessionWriteRequest struct {
	SessionID string
	Data      []byte
}

type SessionCloseRequest struct {
	SessionID string
}

type ListSessionsResponse struct {
	Sessions []SessionRef
}

func (s Server) ListSessions(_ EmptyRequest, resp *ListSessionsResponse) error {
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

func (s Server) ReadSession(req SessionReadRequest, resp *SessionChunk) error {
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
	return resp, nil
}

func (s Server) WriteSession(req SessionWriteRequest, resp *EmptyResponse) error {
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

func (s Server) CloseSession(req SessionCloseRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	return s.moduleSessions.CloseSession(context.Background(), req.SessionID)
}

func (s *Server) closeSessionRPC(ctx context.Context, req SessionCloseRequest) (EmptyResponse, error) {
	if s.moduleSessions == nil {
		return EmptyResponse{}, errors.New("session broker is not configured")
	}
	return EmptyResponse{}, s.moduleSessions.CloseSession(ctx, req.SessionID)
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

type ModuleRequest struct {
	Operation string
	ModuleID  string
	Chain     string
}

type StepResponse struct {
	ID       string
	ModuleID string
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
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.AddTarget(req.Target); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("target", "target added", operatorlog.Field{Name: "target", Value: req.Target}))
		return nil
	})
}

func (s *Server) ClearTargets(req ChainRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		session.ClearTargets()
		s.publish(operation, chain, operatorlog.Info("target", "targets cleared"))
		return nil
	})
}

func (s *Server) AddModule(req ModuleRequest, resp *StepResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		step, err := session.AddModule(req.ModuleID)
		if err != nil {
			return err
		}
		*resp = StepResponse{ID: step.ID, ModuleID: step.ModuleID}
		s.publish(operation, chain, operatorlog.Info("chain", "module added",
			operatorlog.Field{Name: "step", Value: step.ID},
			operatorlog.Field{Name: "module", Value: req.ModuleID},
		))
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
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.SetTargetConfig(req.Target, req.Key, req.Value); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "target config set",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
		return nil
	})
}

func (s *Server) UnsetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.UnsetTargetConfig(req.Target, req.Key); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "target config unset",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
		return nil
	})
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

func (s Server) PollLogs(req PollLogsRequest, resp *PollLogsResponse) error {
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

func (s *Server) clearTargetsRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.ClearTargets(req, &resp)
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
		_ = client.Close()
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

func (s *SessionClient) ClearTargets() {
	_, _ = invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "ClearTargets", ChainRequest{Operation: s.operation(), Chain: s.active()})
}

func (s *SessionClient) AddModule(moduleID string) (operatorsession.Step, error) {
	resp, err := invoke[ModuleRequest, StepResponse](s.client, s.ctx, "AddModule", ModuleRequest{Operation: s.operation(), ModuleID: moduleID, Chain: s.active()})
	return operatorsession.Step{ID: resp.ID, ModuleID: resp.ModuleID}, err
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
	client := connect.NewClient[Req, Res](
		c.httpClient,
		c.baseURL+serviceURLPrefix+method,
		connect.WithCodec(jsonCodec{}),
	)
	resp, err := client.CallUnary(ctx, connect.NewRequest(&req))
	if err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	return *resp.Msg, nil
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
			ID:           session.ID,
			RunID:        session.RunID,
			ModuleID:     session.ModuleID,
			Target:       session.Target,
			Name:         session.Name,
			Kind:         session.Kind,
			State:        session.State,
			Transport:    session.Transport,
			Capabilities: append([]string(nil), session.Capabilities...),
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
	timestamp, _ := time.Parse(time.RFC3339Nano, entry.Time)
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
