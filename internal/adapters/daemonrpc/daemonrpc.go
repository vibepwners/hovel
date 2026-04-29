package daemonrpc

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"sync"

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
}

type LogEntry struct {
	Level   string
	Source  string
	Message string
	Logger  string
	Fields  map[string]string
}

type OperatorLogEntry struct {
	Level   string
	Source  string
	Message string
	Fields  map[string]string
}

type PublishedLog struct {
	Seq   uint64
	Chain string
	Entry OperatorLogEntry
}

type PollLogsRequest struct {
	Since uint64
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
}

type ExecuteModuleResponse = RunMockExploitResponse

type Server struct {
	runs    services.RunService
	session *operatorsession.Session
	logs    *LogBroker
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
	return server.RegisterName(serviceName, rpcServer)
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

func (s Server) RunMockExploit(req RunMockExploitRequest, resp *RunMockExploitResponse) error {
	return s.ExecuteModule(ExecuteModuleRequest(req), (*ExecuteModuleResponse)(resp))
}

func (s Server) ExecuteModule(req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	result, err := s.runs.ExecuteModule(context.Background(), services.ExecuteModuleRequest{
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
	})
	if err != nil {
		return err
	}
	*resp = responseFromResult(result)
	return nil
}

type ChainRequest struct {
	Chain string
}

type RenameChainRequest struct {
	Chain string
	Name  string
}

type TargetRequest struct {
	Target string
}

type ModuleRequest struct {
	ModuleID string
}

type StepResponse struct {
	ID       string
	ModuleID string
}

type ConfigRequest struct {
	Key   string
	Value string
}

type TargetConfigRequest struct {
	Target string
	Key    string
	Value  string
}

type SnapshotRequest struct{}

type SnapshotResponse struct {
	State operatorsession.PersistedState
}

type AppendLogRequest struct {
	Chain   string
	Entries []OperatorLogEntry
}

type EmptyResponse struct{}

type EmptyRequest struct{}

func (s Server) CreateChain(req ChainRequest, resp *EmptyResponse) error {
	if err := s.session.CreateChain(req.Chain); err != nil {
		return err
	}
	s.publish(req.Chain, operatorlog.Info("chain", "chain created", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return nil
}

func (s Server) UseChain(req ChainRequest, resp *EmptyResponse) error {
	if err := s.session.UseChain(req.Chain); err != nil {
		return err
	}
	s.publish(req.Chain, operatorlog.Info("chain", "chain selected", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return nil
}

func (s Server) RenameChain(req RenameChainRequest, resp *EmptyResponse) error {
	if err := s.session.RenameChain(req.Chain, req.Name); err != nil {
		return err
	}
	s.publish(req.Name, operatorlog.Info("chain", "chain renamed",
		operatorlog.Field{Name: "from", Value: req.Chain},
		operatorlog.Field{Name: "to", Value: req.Name},
	))
	return nil
}

func (s Server) DeleteChain(req ChainRequest, resp *EmptyResponse) error {
	if err := s.session.DeleteChain(req.Chain); err != nil {
		return err
	}
	s.publish(req.Chain, operatorlog.Info("chain", "chain deleted", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return nil
}

func (s Server) AddTarget(req TargetRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	if err := s.session.AddTarget(req.Target); err != nil {
		return err
	}
	s.publish(chain, operatorlog.Info("target", "target added", operatorlog.Field{Name: "target", Value: req.Target}))
	return nil
}

func (s Server) ClearTargets(_ EmptyRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	s.session.ClearTargets()
	s.publish(chain, operatorlog.Info("target", "targets cleared"))
	return nil
}

func (s Server) AddModule(req ModuleRequest, resp *StepResponse) error {
	chain := s.session.Snapshot().ActiveChain
	step, err := s.session.AddModule(req.ModuleID)
	if err != nil {
		return err
	}
	*resp = StepResponse{ID: step.ID, ModuleID: step.ModuleID}
	s.publish(chain, operatorlog.Info("chain", "module added",
		operatorlog.Field{Name: "step", Value: step.ID},
		operatorlog.Field{Name: "module", Value: req.ModuleID},
	))
	return nil
}

func (s Server) SetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	if err := s.session.SetChainConfig(req.Key, req.Value); err != nil {
		return err
	}
	s.publish(chain, operatorlog.Info("config", "chain config set", operatorlog.Field{Name: "key", Value: req.Key}))
	return nil
}

func (s Server) UnsetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	if err := s.session.UnsetChainConfig(req.Key); err != nil {
		return err
	}
	s.publish(chain, operatorlog.Info("config", "chain config unset", operatorlog.Field{Name: "key", Value: req.Key}))
	return nil
}

func (s Server) SetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	if err := s.session.SetTargetConfig(req.Target, req.Key, req.Value); err != nil {
		return err
	}
	s.publish(chain, operatorlog.Info("config", "target config set",
		operatorlog.Field{Name: "target", Value: req.Target},
		operatorlog.Field{Name: "key", Value: req.Key},
	))
	return nil
}

func (s Server) UnsetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	chain := s.session.Snapshot().ActiveChain
	if err := s.session.UnsetTargetConfig(req.Target, req.Key); err != nil {
		return err
	}
	s.publish(chain, operatorlog.Info("config", "target config unset",
		operatorlog.Field{Name: "target", Value: req.Target},
		operatorlog.Field{Name: "key", Value: req.Key},
	))
	return nil
}

func (s Server) Snapshot(_ SnapshotRequest, resp *SnapshotResponse) error {
	resp.State = s.session.Export()
	return nil
}

func (s Server) ActiveLogs(_ EmptyRequest, resp *[]OperatorLogEntry) error {
	for _, entry := range s.session.ActiveLogs() {
		*resp = append(*resp, operatorLogEntry(entry))
	}
	return nil
}

func (s Server) AppendLog(req AppendLogRequest, resp *EmptyResponse) error {
	entries := make([]operatorlog.Entry, 0, len(req.Entries))
	for _, entry := range req.Entries {
		entries = append(entries, operatorLogFromRPC(entry))
	}
	if req.Chain == "" {
		if err := s.session.AppendLog(entries...); err != nil {
			return err
		}
		req.Chain = s.session.Snapshot().ActiveChain
	} else if err := s.session.AppendLogToChain(req.Chain, entries...); err != nil {
		return err
	}
	s.publish(req.Chain, entries...)
	return nil
}

func (s Server) PollLogs(req PollLogsRequest, resp *PollLogsResponse) error {
	resp.Last, resp.Logs = s.logs.Since(req.Since)
	return nil
}

func (s Server) publish(chain string, entries ...operatorlog.Entry) {
	s.logs.Publish(chain, entries...)
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

func (c *Client) PollLogs(ctx context.Context, since uint64) (PollLogsResponse, error) {
	var resp PollLogsResponse
	err := c.call(ctx, serviceName+".PollLogs", PollLogsRequest{Since: since}, &resp)
	return resp, err
}

type SessionClient struct {
	client *Client
	ctx    context.Context
}

func NewSessionClient(ctx context.Context, client *Client) *SessionClient {
	return &SessionClient{client: client, ctx: ctx}
}

func (s *SessionClient) RemoteFeedback() bool {
	return true
}

func (s *SessionClient) CreateChain(chain string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".CreateChain", ChainRequest{Chain: chain}, &resp)
}

func (s *SessionClient) UseChain(chain string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".UseChain", ChainRequest{Chain: chain}, &resp)
}

func (s *SessionClient) RenameChain(chain, name string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".RenameChain", RenameChainRequest{Chain: chain, Name: name}, &resp)
}

func (s *SessionClient) DeleteChain(chain string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".DeleteChain", ChainRequest{Chain: chain}, &resp)
}

func (s *SessionClient) AddTarget(target string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AddTarget", TargetRequest{Target: target}, &resp)
}

func (s *SessionClient) ClearTargets() {
	var resp EmptyResponse
	_ = s.client.call(s.ctx, serviceName+".ClearTargets", EmptyRequest{}, &resp)
}

func (s *SessionClient) AddModule(moduleID string) (operatorsession.Step, error) {
	var resp StepResponse
	err := s.client.call(s.ctx, serviceName+".AddModule", ModuleRequest{ModuleID: moduleID}, &resp)
	return operatorsession.Step{ID: resp.ID, ModuleID: resp.ModuleID}, err
}

func (s *SessionClient) SetChainConfig(key, value string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".SetChainConfig", ConfigRequest{Key: key, Value: value}, &resp)
}

func (s *SessionClient) UnsetChainConfig(key string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".UnsetChainConfig", ConfigRequest{Key: key}, &resp)
}

func (s *SessionClient) SetTargetConfig(target, key, value string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".SetTargetConfig", TargetConfigRequest{Target: target, Key: key, Value: value}, &resp)
}

func (s *SessionClient) UnsetTargetConfig(target, key string) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".UnsetTargetConfig", TargetConfigRequest{Target: target, Key: key}, &resp)
}

func (s *SessionClient) AppendLog(entries ...operatorlog.Entry) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AppendLog", AppendLogRequest{Entries: operatorLogEntries(entries)}, &resp)
}

func (s *SessionClient) AppendLogToChain(chain string, entries ...operatorlog.Entry) error {
	var resp EmptyResponse
	return s.client.call(s.ctx, serviceName+".AppendLog", AppendLogRequest{Chain: chain, Entries: operatorLogEntries(entries)}, &resp)
}

func (s *SessionClient) ActiveLogs() []operatorlog.Entry {
	var resp []OperatorLogEntry
	if err := s.client.call(s.ctx, serviceName+".ActiveLogs", EmptyRequest{}, &resp); err != nil {
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
	if err := s.client.call(s.ctx, serviceName+".Snapshot", SnapshotRequest{}, &resp); err != nil {
		return operatorsession.State{}
	}
	session := operatorsession.New()
	session.Import(resp.State)
	return session.Snapshot()
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

func (b *LogBroker) Publish(chain string, entries ...operatorlog.Entry) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, entry := range entries {
		b.next++
		b.logs = append(b.logs, PublishedLog{
			Seq:   b.next,
			Chain: chain,
			Entry: operatorLogEntry(entry),
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
		})
	}
	for _, log := range result.Logs {
		resp.Logs = append(resp.Logs, LogEntry{
			Level:   log.Level,
			Source:  "module",
			Message: log.Message,
			Logger:  log.Logger,
			Fields:  cloneStringMap(log.Fields),
		})
	}
	return resp
}

func operatorLogEntry(entry operatorlog.Entry) OperatorLogEntry {
	return OperatorLogEntry{
		Level:   string(entry.Level),
		Source:  entry.Source,
		Message: entry.Message,
		Fields:  fieldsToMap(entry.Fields),
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
	return operatorlog.Entry{
		Level:   operatorlog.Level(entry.Level),
		Source:  entry.Source,
		Message: entry.Message,
		Fields:  fields,
	}
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
