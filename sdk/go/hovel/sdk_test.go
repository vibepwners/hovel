package hovel

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	go func() { done <- serve(module, inR, outW); outW.Close() }()
	return &rpcConn{t: t, in: inW, out: bufio.NewReader(outR), done: done}
}

func (c *rpcConn) call(method string, params map[string]any) map[string]any {
	c.t.Helper()
	c.id++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c.in, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.in.Write(body); err != nil {
		c.t.Fatal(err)
	}
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
