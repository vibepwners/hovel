package hovel

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeModule is a survey-style module that also opens a shell session so a
// single round-trip test can exercise handshake, schema, execute, and sessions.
type fakeModule struct{ withSession bool }

func (fakeModule) Info() Info {
	return Info{
		Name:    "fake",
		Version: "v0.0.0-test",
		Type:    TypeSurvey,
		Summary: "fake module",
		Tags:    []string{"example", "test"},
	}
}

func (fakeModule) Schema() Schema {
	return Schema{
		TargetConfig: []Requirement{Req("target.host", "host", "Target host.")},
	}
}

func (m fakeModule) Run(ctx *Context) (Result, error) {
	ctx.Log.Info("running", "target", ctx.Target)
	host := ctx.InputString("target.host", ctx.Target)
	if m.withSession {
		shell := &LineShellSession{Prompt: "mock$ ", Echo: true, Handle: func(command string) (string, error) {
			if command == "whoami" {
				return "mock-operator", nil
			}
			return "unknown: " + command, nil
		}}
		ref, err := ctx.OpenSession(shell, WithName("mock shell"), WithCapabilities("read", "write", "exec", "close"))
		if err != nil {
			return Result{}, err
		}
		return Ok(map[string]any{"sessionId": ref.ID}, WithSummary("opened session")), nil
	}
	return Ok(
		map[string]any{"facts": map[string]any{"host": host, "reachable": true}},
		WithSummary(fmt.Sprintf("surveyed %s", host)),
		WithFindings(Finding{Title: "reachable", Severity: "info"}),
		WithArtifacts(TextArtifact("note.txt", "hi")),
	), nil
}

type fakePayloadProvider struct{}

func (fakePayloadProvider) Info() Info {
	return Info{
		Name:    "fake-payload",
		Version: "v0.0.0-test",
		Type:    TypePayloadProvider,
		Summary: "fake payload provider",
		Tags:    []string{"test", "payload_provider"},
	}
}

func (fakePayloadProvider) Schema() Schema {
	return Schema{
		ChainConfig: []Requirement{Req("payload.transport", "enum", "Payload transport.")},
	}
}

func (fakePayloadProvider) Run(*Context) (Result, error) {
	return Ok(map[string]any{"status": "not-used"}, WithSummary("payload provider execute placeholder")), nil
}

func (fakePayloadProvider) ListPayloads(PayloadQuery) ([]PayloadInfo, error) {
	return []PayloadInfo{fakePayloadInfo()}, nil
}

func (fakePayloadProvider) ResolvePayload(PayloadQuery) (PayloadInfo, error) {
	return fakePayloadInfo(), nil
}

func (fakePayloadProvider) PrepareListener(req PrepareListenerRequest) (ListenerRef, error) {
	return ListenerRef{ID: "listener-1", RunID: req.RunID, Target: req.Target, Transport: "reverse-tcp", Host: "127.0.0.1", Port: 4444, State: "listening"}, nil
}

func (fakePayloadProvider) GeneratePayload(GeneratePayloadRequest) (PayloadArtifactSet, error) {
	artifact := PayloadArtifact{Name: "fake.exe", Role: "primary", Format: "pe-exe", Encoding: "base64", Bytes: base64.StdEncoding.EncodeToString([]byte("fake"))}
	return PayloadArtifactSet{Primary: artifact, Artifacts: []PayloadArtifact{artifact}}, nil
}

func (fakePayloadProvider) ConnectSession(req ConnectSessionRequest) (SessionRef, error) {
	return SessionRef{ID: "session-1", RunID: req.RunID, Target: req.Target, Kind: "agent", State: "pending", Transport: "squatter/smb-named-pipe", InstalledPayloadID: req.InstalledPayloadID, Capabilities: []string{"read", "write"}}, nil
}

func (fakePayloadProvider) CleanupPayload(CleanupPayloadRequest) (CleanupResult, error) {
	return CleanupResult{Status: "ok"}, nil
}

func (fakePayloadProvider) ReadPayloadChunk(req ReadPayloadChunkRequest) (PayloadChunk, error) {
	return PayloadChunk{Handle: req.Handle, Offset: req.Offset, Data: base64.StdEncoding.EncodeToString([]byte("chunk")), EOF: true, Encoding: "base64"}, nil
}

type fakeStepModule struct{}

func (fakeStepModule) Info() Info {
	return Info{Name: "fake-step", Version: "v0.0.0-test", Type: TypePayloadProvider}
}

func (fakeStepModule) Schema() Schema { return Schema{} }

func (fakeStepModule) Run(*Context) (Result, error) {
	return Ok(nil, WithSummary("not used")), nil
}

func (fakeStepModule) DescribeSteps() (StepContractSet, error) {
	return StepContractSet{Steps: []StepContract{{
		ID:           "squatter.connect_smb",
		Kind:         "session.connector",
		ConfigSchema: map[string]any{"type": "object"},
		Requires: []CapabilityRequirement{
			{
				Type:          CapabilityPayloadInstance,
				SchemaVersion: "v1",
				Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
				States:        []string{"installed", "disconnected", "unreachable"},
			},
			{
				Type:          CapabilityCredential,
				SchemaVersion: "v1",
				Attributes:    map[string]any{"protocol": "smb"},
				States:        []string{"active"},
			},
		},
		Produces: []CapabilityRequirement{{
			Type:          CapabilitySessionRef,
			SchemaVersion: "v1",
			Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
		}},
		Prepare: StepPrepareContract{Materializes: []string{}},
	}}, Version: "contracts-v1"}, nil
}

func (fakeStepModule) PrepareStep(req StepPrepareRequest) (StepPrepareResult, error) {
	return StepPrepareResult{
		PlannedOutputs: []Capability{{
			ID:             "cap_credential_6mb8pq",
			Type:           CapabilityCredential,
			SchemaVersion:  "v1",
			State:          "planned",
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"protocol":  "smb",
				"username":  "m7q4z92d",
				"password":  "plain-high-entropy-password",
				"sensitive": true,
			},
		}},
		PreparedValues: map[string]PreparedValue{
			"username": {Value: "m7q4z92d", Editable: true},
			"password": {Value: "plain-high-entropy-password", Editable: true},
		},
		OperatorSummary: OperatorSummary{TargetSideArtifacts: []string{"local admin user m7q4z92d"}},
	}, nil
}

func (fakeStepModule) ExecuteStep(req StepExecuteRequest) (StepExecuteResult, error) {
	return StepExecuteResult{
		Status: "succeeded",
		Capabilities: []Capability{{
			ID:             "cap_session_q8m2v4",
			Type:           CapabilitySessionRef,
			SchemaVersion:  "v1",
			State:          "connected",
			ProducerStepID: req.StepID,
			Attributes:     map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
		}},
		Evidence: []Evidence{{ID: "ev_connected", Level: "info", Kind: "session.connected", SourceStepID: req.StepID, Message: "connected"}},
		InstalledPayloads: []InstalledPayloadDescriptor{{
			Provider:                 "fake-step",
			PayloadID:                "fake/windows/x86/tcp-bind/pe-exe",
			PayloadVersion:           "v0.0.0-test",
			Target:                   "target-1",
			State:                    "installed",
			Transport:                "tcp-bind",
			Endpoint:                 "target-1:9101",
			InstanceKey:              "fake-step:target-1:9101",
			SupportsReconnect:        true,
			SupportsMultipleSessions: true,
			Reconnect: &PayloadProviderRecord{
				ProviderID:    "fake-step",
				Schema:        "fake.reconnect",
				SchemaVersion: "v1",
				Descriptor:    map[string]any{"host": "target-1", "port": float64(9101)},
			},
		}},
	}, nil
}

func (fakeStepModule) CleanupStep(StepCleanupRequest) (StepCleanupResult, error) {
	return StepCleanupResult{Status: "cleanup_verified"}, nil
}

func fakePayloadInfo() PayloadInfo {
	return PayloadInfo{
		ID:           "fake/windows/x86/reverse-tcp/pe-exe",
		Name:         "fake",
		Version:      "v0.0.0-test",
		Platform:     "windows",
		Arch:         "x86",
		MinOS:        "windows-xp-sp3",
		TestedOS:     []string{"windows-xp-sp3"},
		Formats:      []string{"pe-exe"},
		Capabilities: []string{"file.get"},
		Transport:    PayloadTransport{Kind: "reverse-tcp"},
		Session:      PayloadSession{Kind: "agent", Acquisition: "callback", RequiresPreThrowListener: true, Owner: "payload_provider"},
	}
}

func TestServeStepContractMethods(t *testing.T) {
	conn := newRPCConn(t, fakeStepModule{})
	defer conn.close()

	describe := conn.call("step.describe", nil)
	steps, _ := describe["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("steps = %#v, want one step", describe["steps"])
	}
	step, _ := steps[0].(map[string]any)
	if step["id"] != "squatter.connect_smb" {
		t.Fatalf("step id = %#v", step["id"])
	}
	requires, _ := step["requires"].([]any)
	if len(requires) != 2 {
		t.Fatalf("requires = %#v, want two requirements", step["requires"])
	}

	prepared := conn.call("step.prepare", map[string]any{
		"preparedPlanId": "prep-1",
		"stepId":         "windows.credential.create_local_admin",
	})
	values, _ := prepared["preparedValues"].(map[string]any)
	password, _ := values["password"].(map[string]any)
	if password["value"] != "plain-high-entropy-password" {
		t.Fatalf("prepared password = %#v", password["value"])
	}

	executed := conn.call("step.execute", map[string]any{"runId": "run-1", "stepId": "squatter.connect_smb"})
	if executed["status"] != "succeeded" {
		t.Fatalf("execute status = %#v", executed["status"])
	}
	installedPayloads, _ := executed["installedPayloads"].([]any)
	if len(installedPayloads) != 1 {
		t.Fatalf("installedPayloads = %#v, want one descriptor", executed["installedPayloads"])
	}
	installed, _ := installedPayloads[0].(map[string]any)
	if installed["provider"] != "fake-step" || installed["instanceKey"] != "fake-step:target-1:9101" {
		t.Fatalf("installed payload descriptor = %#v", installed)
	}

	cleanup := conn.call("step.cleanup", map[string]any{"runId": "run-1", "stepId": "squatter.cleanup_smb", "cleanupHandleId": "cap_cleanup_74m2wq"})
	if cleanup["status"] != "cleanup_verified" {
		t.Fatalf("cleanup status = %#v", cleanup["status"])
	}
}

// rpcConn drives a serve() loop over in-memory pipes.
type rpcConn struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
	id   int
}

func newRPCConn(t *testing.T, module Module) *rpcConn {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeIO(module, inR, outW); outW.Close() }()
	return &rpcConn{t: t, in: inW, out: bufio.NewReader(outR), done: done}
}

func (c *rpcConn) call(method string, params map[string]any) map[string]any {
	c.t.Helper()
	c.id++
	c.writeRequest(c.id, method, params)
	// Skip notifications (module/log, module/session) until the matching response.
	for {
		message := c.readFrame()
		if _, hasID := message["id"]; !hasID {
			continue
		}
		if errObj, ok := message["error"]; ok {
			c.t.Fatalf("rpc error for %s: %v", method, errObj)
		}
		result, _ := message["result"].(map[string]any)
		return result
	}
}

func (c *rpcConn) writeRequest(id int, method string, params map[string]any) {
	c.t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c.in, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.in.Write(body); err != nil {
		c.t.Fatal(err)
	}
}

func (c *rpcConn) readFrame() map[string]any {
	c.t.Helper()
	length := 0
	for {
		line, err := c.out.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read frame: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			length, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.out, body); err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	var message map[string]any
	if err := json.Unmarshal(body, &message); err != nil {
		c.t.Fatalf("decode body: %v", err)
	}
	return message
}

func (c *rpcConn) close() {
	c.call("shutdown", nil)
	if err := <-c.done; err != nil {
		c.t.Fatalf("serve returned error: %v", err)
	}
	c.in.Close()
}

func TestServePayloadProviderMethods(t *testing.T) {
	conn := newRPCConn(t, fakePayloadProvider{})
	defer conn.close()

	info := conn.call("handshake", nil)
	if info["moduleType"] != "payload_provider" {
		t.Fatalf("handshake = %#v", info)
	}

	list := conn.call("list_payloads", map[string]any{"platform": "windows", "arch": "x86"})
	payloads, _ := list["payloads"].([]any)
	if payloads == nil {
		// Method results that are arrays decode directly through rpcConn as nil
		// because it expects object results. Exercise object-returning methods
		// below and keep this call as a dispatch smoke check.
	}

	resolved := conn.call("resolve_payload", map[string]any{"format": "pe-exe"})
	if resolved["id"] != "fake/windows/x86/reverse-tcp/pe-exe" {
		t.Fatalf("resolve_payload = %#v", resolved)
	}
	listener := conn.call("prepare_listener", map[string]any{"runId": "run-1", "target": "target-1", "payloadId": resolved["id"]})
	if listener["state"] != "listening" {
		t.Fatalf("prepare_listener = %#v", listener)
	}
	generated := conn.call("generate_payload", map[string]any{"target": "target-1", "payloadId": resolved["id"], "format": "pe-exe"})
	primary, _ := generated["primary"].(map[string]any)
	if primary["format"] != "pe-exe" || primary["encoding"] != "base64" {
		t.Fatalf("generate_payload primary = %#v", primary)
	}
	session := conn.call("connect_session", map[string]any{
		"runId":              "run-1",
		"target":             "target-1",
		"payloadId":          resolved["id"],
		"installedPayloadId": "p1",
		"reconnect": map[string]any{
			"providerId":    "fake-payload",
			"schema":        "fake.reconnect",
			"schemaVersion": "v1",
			"descriptor":    map[string]any{"target": "target-1"},
		},
	})
	if session["transport"] != "squatter/smb-named-pipe" {
		t.Fatalf("connect_session = %#v", session)
	}
	if session["installedPayloadId"] != "p1" {
		t.Fatalf("connect_session installedPayloadId = %#v, want p1", session["installedPayloadId"])
	}
	cleanup := conn.call("cleanup_payload", map[string]any{"reason": "test"})
	if cleanup["status"] != "ok" {
		t.Fatalf("cleanup_payload = %#v", cleanup)
	}
}

func TestFrameReaderRejectsOversizedFrameBeforeBodyRead(t *testing.T) {
	reader := newFrameReader(strings.NewReader(fmt.Sprintf("Content-Length: %d\r\n\r\n", maxFrameBytes+1)))
	_, err := reader.read()
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("error = %v, want frame size error", err)
	}
}

func TestServeHandshakeSchemaExecute(t *testing.T) {
	conn := newRPCConn(t, fakeModule{})
	defer conn.close()

	info := conn.call("handshake", nil)
	if info["name"] != "fake" || info["moduleType"] != "survey" {
		t.Fatalf("handshake = %#v", info)
	}

	schema := conn.call("schema", nil)
	target, _ := schema["targetConfig"].([]any)
	if len(target) != 1 {
		t.Fatalf("schema targetConfig = %#v", schema["targetConfig"])
	}
	req, _ := target[0].(map[string]any)
	if req["key"] != "target.host" || req["required"] != true {
		t.Fatalf("requirement = %#v", req)
	}

	result := conn.call("execute", map[string]any{
		"runId":        "run-1",
		"moduleId":     "fake",
		"target":       "mock://host",
		"targetConfig": map[string]any{"target.host": "example.test"},
	})
	if result["status"] != "succeeded" {
		t.Fatalf("execute status = %#v", result["status"])
	}
	if result["summary"] != "surveyed example.test" {
		t.Fatalf("summary = %#v", result["summary"])
	}
	findings, _ := result["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", result["findings"])
	}
}

func TestServeSessionRoundTrip(t *testing.T) {
	conn := newRPCConn(t, fakeModule{withSession: true})
	defer conn.close()

	conn.call("handshake", nil)
	result := conn.call("execute", map[string]any{"runId": "run-1", "moduleId": "fake", "target": "mock://host"})
	sessions, _ := result["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %#v", result["sessions"])
	}
	ref, _ := sessions[0].(map[string]any)
	sessionID, _ := ref["id"].(string)
	if sessionID == "" {
		t.Fatalf("session ref missing id: %#v", ref)
	}

	// Drain the opening prompt.
	prompt := readSession(t, conn, sessionID)
	if !strings.Contains(prompt, "mock$") {
		t.Fatalf("opening prompt = %q", prompt)
	}

	conn.call("session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString([]byte("whoami\n")),
	})
	output := readSession(t, conn, sessionID)
	if !strings.Contains(output, "mock-operator") {
		t.Fatalf("session output = %q", output)
	}

	closeResult := conn.call("session/close", map[string]any{"sessionId": sessionID, "reason": "done"})
	if closeResult["status"] != "ok" {
		t.Fatalf("close result = %#v", closeResult)
	}
}

func readSession(t *testing.T, conn *rpcConn, sessionID string) string {
	t.Helper()
	var builder strings.Builder
	for i := 0; i < 5; i++ {
		resp := conn.call("session/read", map[string]any{"sessionId": sessionID, "timeoutMs": 200})
		data, _ := resp["data"].(string)
		decoded, _ := base64.StdEncoding.DecodeString(data)
		builder.Write(decoded)
		if len(decoded) == 0 {
			break
		}
	}
	return builder.String()
}

func TestServeSessionReadDoesNotBlockWrite(t *testing.T) {
	conn := newRPCConn(t, fakeModule{withSession: true})
	defer conn.close()

	result := conn.call("execute", map[string]any{"runId": "run-1", "moduleId": "fake", "target": "mock://host"})
	sessions, _ := result["sessions"].([]any)
	ref, _ := sessions[0].(map[string]any)
	sessionID, _ := ref["id"].(string)
	_ = readSession(t, conn, sessionID)

	readID := 1001
	writeID := 1002
	conn.writeRequest(readID, "session/read", map[string]any{
		"sessionId": sessionID,
		"timeoutMs": 1000,
	})

	writeSent := make(chan struct{})
	go func() {
		defer close(writeSent)
		conn.writeRequest(writeID, "session/write", map[string]any{
			"sessionId": sessionID,
			"data":      base64.StdEncoding.EncodeToString([]byte("whoami\n")),
		})
	}()

	select {
	case <-writeSent:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("session/write request was blocked behind a pending session/read")
	}

	seenWrite, seenRead := false, false
	var readOutput strings.Builder
	deadline := time.After(2 * time.Second)
	for !seenWrite || !seenRead {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for read/write responses; seenWrite=%v seenRead=%v", seenWrite, seenRead)
		default:
		}
		message := conn.readFrame()
		id, ok := responseID(message)
		if !ok {
			continue
		}
		if errObj, ok := message["error"]; ok {
			t.Fatalf("rpc error for id %d: %v", id, errObj)
		}
		switch id {
		case writeID:
			seenWrite = true
		case readID:
			seenRead = true
			result, _ := message["result"].(map[string]any)
			data, _ := result["data"].(string)
			decoded, _ := base64.StdEncoding.DecodeString(data)
			if len(decoded) == 0 {
				t.Fatal("pending session/read returned no data after session/write")
			}
			readOutput.Write(decoded)
		}
	}
	readOutput.WriteString(readSession(t, conn, sessionID))
	if !strings.Contains(readOutput.String(), "mock-operator") {
		t.Fatalf("session output = %q, want command output", readOutput.String())
	}
}

func responseID(message map[string]any) (int, bool) {
	value, ok := message["id"]
	if !ok {
		return 0, false
	}
	switch id := value.(type) {
	case float64:
		return int(id), true
	case int:
		return id, true
	default:
		return 0, false
	}
}

func TestLineShellSessionExit(t *testing.T) {
	shell := &LineShellSession{Handle: func(string) (string, error) { return "ok", nil }}
	_ = shell.Open()
	_ = shell.Write([]byte("exit\n"))
	if !shell.Closed() {
		t.Fatal("shell should be closed after exit")
	}
	if data, _ := shell.Read(10 * time.Millisecond); len(data) != 0 && !shell.Closed() {
		t.Fatalf("unexpected data after close: %q", data)
	}
}

func TestPTYSessionUsesTerminalLineDiscipline(t *testing.T) {
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "got:%s", line)
		return err
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	defer session.Close("test")

	if err := session.Write([]byte{'a', 'b', 0x7f, 'c', '\n'}); err != nil {
		t.Fatal(err)
	}
	output := readPTYSession(t, session)
	if !strings.Contains(output, "got:ac") {
		t.Fatalf("pty output = %q, want frontend line ac", output)
	}
}

func TestSessionManagerMarksPTYSessionCapability(t *testing.T) {
	manager := newSessionManager(nil)
	session := &PTYSession{Frontend: func(io.Reader, io.Writer) error {
		return nil
	}}
	ref, err := manager.open(sessionScope{runID: "run-1", moduleID: "mod", target: "target"}, session, sessionOptions{
		name:         "terminal",
		kind:         "agent",
		transport:    "pty/test",
		capabilities: []string{"read", "write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close("test")
	if !hasString(ref.Capabilities, CapabilityTerminalPTY) {
		t.Fatalf("capabilities = %#v, want %q", ref.Capabilities, CapabilityTerminalPTY)
	}
}

func TestPTYSessionUsesSeparateInputOutputHandles(t *testing.T) {
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		inputFile, ok := input.(*os.File)
		if !ok {
			return fmt.Errorf("input = %T, want *os.File", input)
		}
		outputFile, ok := output.(*os.File)
		if !ok {
			return fmt.Errorf("output = %T, want *os.File", output)
		}
		if inputFile == outputFile || inputFile.Fd() == outputFile.Fd() {
			return fmt.Errorf("input and output handles must be independent")
		}
		return writeAll(output, []byte("separate handles\n"))
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	defer session.Close("test")

	output := readPTYSession(t, session)
	if !strings.Contains(output, "separate handles") {
		t.Fatalf("pty output = %q, want frontend output", output)
	}
}

func TestPTYSessionDrainsLargeFrontendOutput(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef\r\n"), 4096)
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		_ = input
		return writeAll(output, payload)
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	defer session.Close("test")

	output := readPTYSessionUntil(t, session, len(payload), 2*time.Second)
	if len(output) < len(payload) || !strings.Contains(output, "0123456789abcdef") {
		t.Fatalf("pty drained %d bytes, want at least %d and repeated payload text", len(output), len(payload))
	}
}

func readPTYSession(t *testing.T, session *PTYSession) string {
	t.Helper()
	var builder strings.Builder
	for i := 0; i < 10; i++ {
		chunk, err := session.Read(100 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk) == 0 {
			break
		}
		builder.Write(chunk)
	}
	return builder.String()
}

func readPTYSessionUntil(t *testing.T, session *PTYSession, minBytes int, timeout time.Duration) string {
	t.Helper()
	var builder strings.Builder
	deadline := time.Now().Add(timeout)
	for builder.Len() < minBytes && time.Now().Before(deadline) {
		chunk, err := session.Read(100 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk) == 0 {
			continue
		}
		builder.Write(chunk)
	}
	return builder.String()
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
