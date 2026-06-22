package hovel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// logRecord is the wire shape of a "module/log" notification.
type logRecord struct {
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Logger    string         `json:"logger"`
	Fields    map[string]any `json:"fields,omitempty"`
	Exception string         `json:"exception,omitempty"`
}

// server runs the JSON-RPC dispatch loop for a single module.
type server struct {
	module   Module
	reader   *frameReader
	writer   *frameWriter
	sessions *sessionManager
}

// Serve runs module over stdin/stdout until the daemon sends "shutdown" or the
// stream closes. It is the entry point for every Go module's main function:
//
//	func main() { hovel.Serve(&MyModule{}) }
func Serve(module Module) {
	if err := ServeIO(module, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "hovel sdk error: %v\n", err)
		os.Exit(2)
	}
}

// ServeIO runs module over explicit streams. It is useful for contract tests
// and embedded harnesses; production modules should normally call Serve.
func ServeIO(module Module, in io.Reader, out io.Writer) error {
	s := &server{
		module: module,
		reader: newFrameReader(in),
		writer: newFrameWriter(out),
	}
	s.sessions = newSessionManager(s.emitSession)
	var requests sync.WaitGroup
	for {
		message, err := s.reader.read()
		if err == io.EOF {
			requests.Wait()
			return nil
		}
		if err != nil {
			return err
		}
		method := stringField(message, "method")
		if method == "" {
			continue
		}
		idRaw, hasID := message["id"]
		if !hasID {
			// Notification (e.g. "cancel"): no response expected.
			continue
		}
		params := append(json.RawMessage(nil), message["params"]...)
		id := append(json.RawMessage(nil), idRaw...)
		requests.Add(1)
		go func() {
			defer requests.Done()
			result, derr := s.dispatch(method, params)
			if derr != nil {
				_ = s.writer.write(errorResponse(id, derr))
			} else {
				_ = s.writer.write(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
			}
		}()
		if method == "shutdown" {
			requests.Wait()
			return nil
		}
	}
}

func (s *server) dispatch(method string, params json.RawMessage) (any, error) {
	switch method {
	case "handshake":
		return s.handshake(), nil
	case "schema":
		return s.schema(), nil
	case "list_payloads":
		return s.listPayloads(params)
	case "resolve_payload":
		return s.resolvePayload(params)
	case "prepare_listener":
		return s.prepareListener(params)
	case "generate_payload":
		return s.generatePayload(params)
	case "connect_session":
		return s.connectSession(params)
	case "cleanup_payload":
		return s.cleanupPayload(params)
	case "read_payload_chunk":
		return s.readPayloadChunk(params)
	case "payload.command.list":
		return s.listPayloadCommands(params)
	case "payload.command.run":
		return s.runPayloadCommand(params)
	case "step.describe":
		return s.describeSteps()
	case "step.prepare":
		return s.prepareStep(params)
	case "step.execute":
		return s.executeStep(params)
	case "step.cleanup":
		return s.cleanupStep(params)
	case "execute":
		return s.execute(params)
	case "session/write":
		return s.sessionWrite(params)
	case "session/read":
		return s.sessionRead(params)
	case "session/close":
		return s.sessionClose(params)
	case "shutdown":
		s.sessions.closeAll("shutdown")
		return map[string]any{"status": "ok"}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func (s *server) handshake() map[string]any {
	info := s.module.Info()
	tags := info.Tags
	if tags == nil {
		tags = []string{}
	}
	return map[string]any{
		"name":        info.Name,
		"version":     info.Version,
		"moduleType":  string(info.Type),
		"summary":     info.Summary,
		"description": info.Description,
		"tags":        tags,
	}
}

func (s *server) schema() map[string]any {
	schema := s.module.Schema()
	outputs := schema.Outputs
	if outputs == nil {
		outputs = map[string]any{}
	}
	return map[string]any{
		"chainConfig":  requirementsToRPC(schema.ChainConfig),
		"targetConfig": requirementsToRPC(schema.TargetConfig),
		"outputs":      outputs,
	}
}

func (s *server) payloadProvider() (PayloadProvider, error) {
	provider, ok := s.module.(PayloadProvider)
	if !ok {
		return nil, fmt.Errorf("module %q is not a payload provider", s.module.Info().Name)
	}
	return provider, nil
}

func (s *server) stepProvider() (StepProvider, error) {
	provider, ok := s.module.(StepProvider)
	if !ok {
		return nil, fmt.Errorf("module %q is not a step provider", s.module.Info().Name)
	}
	return provider, nil
}

func (s *server) payloadCommandProvider() (PayloadCommandProvider, error) {
	provider, ok := s.module.(PayloadCommandProvider)
	if !ok {
		return nil, fmt.Errorf("module %q is not a payload command provider", s.module.Info().Name)
	}
	return provider, nil
}

func decodeParams[T any](params json.RawMessage) (T, error) {
	var p T
	if len(params) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return p, err
	}
	return p, nil
}

func (s *server) describeSteps() (any, error) {
	provider, err := s.stepProvider()
	if err != nil {
		return nil, err
	}
	return provider.DescribeSteps()
}

func (s *server) prepareStep(params json.RawMessage) (any, error) {
	provider, err := s.stepProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[StepPrepareRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.PrepareStep(req)
}

func (s *server) executeStep(params json.RawMessage) (any, error) {
	provider, err := s.stepProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[StepExecuteRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.ExecuteStep(req)
}

func (s *server) cleanupStep(params json.RawMessage) (any, error) {
	provider, err := s.stepProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[StepCleanupRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.CleanupStep(req)
}

func (s *server) listPayloads(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	query, err := decodeParams[PayloadQuery](params)
	if err != nil {
		return nil, err
	}
	return provider.ListPayloads(query)
}

func (s *server) resolvePayload(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	query, err := decodeParams[PayloadQuery](params)
	if err != nil {
		return nil, err
	}
	return provider.ResolvePayload(query)
}

func (s *server) prepareListener(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[PrepareListenerRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.PrepareListener(req)
}

func (s *server) generatePayload(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[GeneratePayloadRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.GeneratePayload(req)
}

func (s *server) connectSession(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[ConnectSessionRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.ConnectSession(req)
}

func (s *server) cleanupPayload(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[CleanupPayloadRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.CleanupPayload(req)
}

func (s *server) readPayloadChunk(params json.RawMessage) (any, error) {
	provider, err := s.payloadProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[ReadPayloadChunkRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.ReadPayloadChunk(req)
}

func (s *server) listPayloadCommands(params json.RawMessage) (any, error) {
	provider, err := s.payloadCommandProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[PayloadCommandListRequest](params)
	if err != nil {
		return nil, err
	}
	commands, err := provider.ListPayloadCommands(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"commands": commands}, nil
}

func (s *server) runPayloadCommand(params json.RawMessage) (any, error) {
	provider, err := s.payloadCommandProvider()
	if err != nil {
		return nil, err
	}
	req, err := decodeParams[PayloadCommandRequest](params)
	if err != nil {
		return nil, err
	}
	return provider.RunPayloadCommand(req)
}

func requirementsToRPC(requirements []Requirement) []map[string]any {
	out := make([]map[string]any, 0, len(requirements))
	for _, req := range requirements {
		allowed := req.Allowed
		if allowed == nil {
			allowed = []string{}
		}
		valueType := req.Type
		if valueType == "" {
			valueType = "string"
		}
		out = append(out, map[string]any{
			"key":         req.Key,
			"type":        valueType,
			"required":    req.Required,
			"default":     req.Default,
			"description": req.Description,
			"allowed":     allowed,
			"secret":      req.Secret,
		})
	}
	return out
}

func (s *server) execute(params json.RawMessage) (any, error) {
	var p struct {
		RunID        string         `json:"runId"`
		ModuleID     string         `json:"moduleId"`
		Target       string         `json:"target"`
		Inputs       map[string]any `json:"inputs"`
		ChainConfig  map[string]any `json:"chainConfig"`
		TargetConfig map[string]any `json:"targetConfig"`
		Agent        *AgentContext  `json:"agentContext"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
	}
	registry := s.sessions.forRun(sessionScope{runID: p.RunID, moduleID: p.ModuleID, target: p.Target})
	ctx := &Context{
		RunID:        p.RunID,
		ModuleID:     p.ModuleID,
		Target:       p.Target,
		Inputs:       orEmpty(p.Inputs),
		ChainConfig:  orEmpty(p.ChainConfig),
		TargetConfig: orEmpty(p.TargetConfig),
		Agent:        p.Agent,
		Log:          &Logger{name: s.module.Info().Name, emit: s.emitLog},
		sessions:     registry,
	}
	result, err := s.module.Run(ctx)
	if err != nil {
		return nil, err
	}
	return result.toRPC(registry.refs()), nil
}

func (s *server) sessionWrite(params json.RawMessage) (any, error) {
	var p struct {
		SessionID string `json:"sessionId"`
		Data      string `json:"data"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.write(p.SessionID, data); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok"}, nil
}

func (s *server) sessionRead(params json.RawMessage) (any, error) {
	var p struct {
		SessionID string  `json:"sessionId"`
		TimeoutMS float64 `json:"timeoutMs"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	wait := time.Duration(-1)
	if p.TimeoutMS >= 0 {
		wait = time.Duration(p.TimeoutMS) * time.Millisecond
	}
	chunk, closed, err := s.sessions.read(p.SessionID, wait)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sessionId": p.SessionID,
		"data":      base64.StdEncoding.EncodeToString(chunk),
		"closed":    closed,
	}, nil
}

func (s *server) sessionClose(params json.RawMessage) (any, error) {
	var p struct {
		SessionID string `json:"sessionId"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	reason := p.Reason
	if reason == "" {
		reason = "closed"
	}
	if err := s.sessions.close(p.SessionID, reason); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok"}, nil
}

func (s *server) emitLog(record logRecord) {
	_ = s.writer.write(map[string]any{"jsonrpc": "2.0", "method": "module/log", "params": record})
}

func (s *server) emitSession(event sessionEvent) {
	params := map[string]any{"event": event.event, "session": event.ref.toRPC()}
	if event.fields != nil {
		params["fields"] = event.fields
	}
	_ = s.writer.write(map[string]any{"jsonrpc": "2.0", "method": "module/session", "params": params})
}

func errorResponse(idRaw json.RawMessage, err error) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(idRaw),
		"error":   map[string]any{"code": -32000, "message": err.Error()},
	}
}

func stringField(message map[string]json.RawMessage, key string) string {
	raw, ok := message[key]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
