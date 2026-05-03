package daemonrpc

import (
	"context"
	"errors"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const serviceName = "Daemon"

type RunMockExploitRequest struct {
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

func Register(server *rpc.Server, runs services.RunService, options ...ServerOption) error {
	rpcServer := Server{
		runs:    runs,
		session: operatorsession.New(),
		logs:    NewLogBroker(),
	}
	for _, option := range options {
		option(&rpcServer)
	}
	return server.RegisterName(serviceName, &rpcServer)
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

func (s Server) ExecuteModule(req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	var throwStarted time.Time
	if req.ThrowStarted != "" {
		throwStarted, _ = time.Parse(time.RFC3339Nano, req.ThrowStarted)
	}
	result, err := s.runs.ExecuteModule(context.Background(), services.ExecuteModuleRequest{
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

func (s Server) WriteSession(req SessionWriteRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	return s.moduleSessions.WriteSession(context.Background(), req.SessionID, req.Data)
}

func (s Server) CloseSession(req SessionCloseRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	return s.moduleSessions.CloseSession(context.Background(), req.SessionID)
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
	rpc *rpc.Client
}

func Dial(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

func NewClient(conn net.Conn) *Client {
	return &Client{rpc: jsonrpc.NewClient(conn)}
}

func (c *Client) Close() error {
	return c.rpc.Close()
}

func (c *Client) RunMockExploit(ctx context.Context, req RunMockExploitRequest) (RunMockExploitResponse, error) {
	return c.ExecuteModule(ctx, ExecuteModuleRequest(req))
}

func (c *Client) ExecuteModule(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	var resp ExecuteModuleResponse
	done := make(chan error, 1)
	go func() {
		done <- c.rpc.Call(serviceName+".ExecuteModule", req, &resp)
	}()

	select {
	case <-ctx.Done():
		_ = c.Close()
		return ExecuteModuleResponse{}, ctx.Err()
	case err := <-done:
		return resp, err
	}
}

func (c *Client) ListSessions(ctx context.Context) ([]SessionRef, error) {
	var resp ListSessionsResponse
	if err := c.call(ctx, serviceName+".ListSessions", EmptyRequest{}, &resp); err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func (c *Client) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (SessionChunk, error) {
	var resp SessionChunk
	err := c.call(ctx, serviceName+".ReadSession", SessionReadRequest{
		SessionID: sessionID,
		TimeoutMs: int(timeout / time.Millisecond),
	}, &resp)
	return resp, err
}

func (c *Client) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	return c.call(ctx, serviceName+".WriteSession", SessionWriteRequest{
		SessionID: sessionID,
		Data:      append([]byte(nil), data...),
	}, &EmptyResponse{})
}

func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	return c.call(ctx, serviceName+".CloseSession", SessionCloseRequest{SessionID: sessionID}, &EmptyResponse{})
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
	var resp PollLogsResponse
	err := c.call(ctx, serviceName+".PollLogs", PollLogsRequest{Since: since, Operation: operation, Chain: chain}, &resp)
	return resp, err
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
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".CreateOperation", OperationRequest{Operation: operation}, &resp)
}

func (s *SessionClient) UseOperation(operation string) error {
	var resp EmptyResponse
	if err := s.client.call(s.ctx, serviceName+".UseOperation", OperationRequest{Operation: operation}, &resp); err != nil {
		return err
	}
	s.setActiveOperation(operation)
	return nil
}

func (s *SessionClient) CreateChain(chain string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".CreateChain", ChainRequest{Operation: s.operation(), Chain: chain}, &resp)
}

func (s *SessionClient) UseChain(chain string) error {
	var resp EmptyResponse
	if err := s.client.call(s.ctx, serviceName+".UseChain", ChainRequest{Operation: s.operation(), Chain: chain}, &resp); err != nil {
		return err
	}
	s.setActiveChain(chain)
	return nil
}

func (s *SessionClient) RenameChain(chain, name string) error {
	var resp EmptyResponse
	if err := s.client.call(s.ctx, serviceName+".RenameChain", RenameChainRequest{Operation: s.operation(), Chain: chain, Name: name}, &resp); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain(name)
	}
	return nil
}

func (s *SessionClient) DeleteChain(chain string) error {
	var resp EmptyResponse
	if err := s.client.call(s.ctx, serviceName+".DeleteChain", ChainRequest{Operation: s.operation(), Chain: chain}, &resp); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain("")
	}
	return nil
}

func (s *SessionClient) AddTarget(target string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AddTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()}, &resp)
}

func (s *SessionClient) ClearTargets() {
	var resp EmptyResponse
	_ = s.client.call(s.ctx, serviceName+".ClearTargets", ChainRequest{Operation: s.operation(), Chain: s.active()}, &resp)
}

func (s *SessionClient) AddModule(moduleID string) (operatorsession.Step, error) {
	var resp StepResponse
	err := s.client.call(s.ctx, serviceName+".AddModule", ModuleRequest{Operation: s.operation(), ModuleID: moduleID, Chain: s.active()}, &resp)
	return operatorsession.Step{ID: resp.ID, ModuleID: resp.ModuleID}, err
}

func (s *SessionClient) SetChainConfig(key, value string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".SetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Value: value, Chain: s.active()}, &resp)
}

func (s *SessionClient) UnsetChainConfig(key string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".UnsetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Chain: s.active()}, &resp)
}

func (s *SessionClient) SetTargetConfig(target, key, value string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".SetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Value: value, Chain: s.active()}, &resp)
}

func (s *SessionClient) UnsetTargetConfig(target, key string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".UnsetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Chain: s.active()}, &resp)
}

func (s *SessionClient) AppendLog(entries ...operatorlog.Entry) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AppendLog", AppendLogRequest{Operation: s.operation(), Chain: s.active(), Entries: operatorLogEntries(entries)}, &resp)
}

func (s *SessionClient) AppendLogToChain(chain string, entries ...operatorlog.Entry) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AppendLog", AppendLogRequest{Operation: s.operation(), Chain: chain, Entries: operatorLogEntries(entries)}, &resp)
}

func (s *SessionClient) ActiveLogs() []operatorlog.Entry {
	var resp []OperatorLogEntry
	if err := s.client.call(s.ctx, serviceName+".ActiveLogs", ActiveLogsRequest{Operation: s.operation(), Chain: s.active()}, &resp); err != nil {
		return nil
	}
	out := make([]operatorlog.Entry, 0, len(resp))
	for _, entry := range resp {
		out = append(out, operatorLogFromRPC(entry))
	}
	return out
}

func (s *SessionClient) Snapshot() operatorsession.State {
	var resp SnapshotResponse
	if err := s.client.call(s.ctx, serviceName+".Snapshot", SnapshotRequest{Operation: s.operation(), Chain: s.active()}, &resp); err != nil {
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

func (c *Client) call(ctx context.Context, method string, req any, resp any) error {
	done := make(chan error, 1)
	go func() {
		done <- c.rpc.Call(method, req, resp)
	}()

	select {
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	case err := <-done:
		return err
	}
}

type LogBroker struct {
	mu   sync.Mutex
	next uint64
	logs []PublishedLog
}

func NewLogBroker() *LogBroker {
	return &LogBroker{}
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
		b.logs = append(b.logs, PublishedLog{
			Seq:       b.next,
			Operation: operation,
			Chain:     chain,
			Entry:     operatorLogEntry(entry),
		})
	}
}

func (b *LogBroker) Since(since uint64) (uint64, []PublishedLog) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var logs []PublishedLog
	for _, log := range b.logs {
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
	for _, log := range b.logs {
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
