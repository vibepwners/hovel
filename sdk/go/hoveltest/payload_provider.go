package hoveltest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

// RPCConn drives a Hovel module through the real Content-Length framed JSON-RPC
// server used by the daemon.
type RPCConn struct {
	t    testing.TB
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
	id   int
}

func NewRPCConn(t testing.TB, module hovel.Module) *RPCConn {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- hovel.ServeIO(module, inR, outW)
		if err := outW.Close(); err != nil {
			log.Printf("hoveltest: close RPC output pipe: %v", err)
		}
	}()
	return &RPCConn{t: t, in: inW, out: bufio.NewReader(outR), done: done}
}

func (c *RPCConn) Call(method string, params any, result any) {
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
	for {
		message := c.readFrame()
		if _, hasID := message["id"]; !hasID {
			continue
		}
		if raw := message["error"]; raw != nil {
			c.t.Fatalf("rpc error for %s: %s", method, string(raw))
		}
		if result == nil {
			return
		}
		if err := json.Unmarshal(message["result"], result); err != nil {
			c.t.Fatalf("decode result for %s: %v", method, err)
		}
		return
	}
}

func (c *RPCConn) Close() {
	c.t.Helper()
	var result map[string]string
	c.Call("shutdown", map[string]any{}, &result)
	if err := <-c.done; err != nil {
		c.t.Fatalf("serve returned error: %v", err)
	}
	if err := c.in.Close(); err != nil {
		c.t.Logf("close RPC input pipe: %v", err)
	}
}

func (c *RPCConn) readFrame() map[string]json.RawMessage {
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
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			var err error
			length, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				c.t.Fatalf("parse content-length %q: %v", value, err)
			}
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.out, body); err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil {
		c.t.Fatalf("decode body: %v", err)
	}
	return message
}

// PayloadProviderContract describes the minimum lifecycle a payload-provider
// module must satisfy over JSON-RPC.
type PayloadProviderContract struct {
	Query                  hovel.PayloadQuery
	Target                 string
	RunID                  string
	Config                 map[string]string
	WantKind               string
	WantFormat             string
	WantTransport          string
	WantTags               []string
	WantCapabilities       []string
	WantInstalledPayloadID string
}

func AssertPayloadProviderContract(t testing.TB, module hovel.PayloadProvider, contract PayloadProviderContract) {
	t.Helper()
	conn := NewRPCConn(t, module)
	defer conn.Close()

	var info struct {
		Name       string   `json:"name"`
		ModuleType string   `json:"moduleType"`
		Tags       []string `json:"tags"`
	}
	conn.Call("handshake", nil, &info)
	if info.ModuleType != string(hovel.TypePayloadProvider) {
		t.Fatalf("moduleType = %q, want payload_provider", info.ModuleType)
	}

	var payloads []hovel.PayloadInfo
	conn.Call("list_payloads", contract.Query, &payloads)
	if len(payloads) == 0 {
		t.Fatal("list_payloads returned no payloads")
	}

	var resolved hovel.PayloadInfo
	conn.Call("resolve_payload", contract.Query, &resolved)
	if resolved.ID == "" {
		t.Fatalf("resolve_payload returned missing id: %#v", resolved)
	}
	if contract.WantKind != "" && resolved.Kind != contract.WantKind {
		t.Fatalf("resolved kind = %q, want %q", resolved.Kind, contract.WantKind)
	}
	if contract.WantFormat != "" && !contains(resolved.Formats, contract.WantFormat) {
		t.Fatalf("resolved formats = %#v, want %q", resolved.Formats, contract.WantFormat)
	}
	if contract.WantTransport != "" && resolved.Transport.Kind != contract.WantTransport {
		t.Fatalf("resolved transport = %q, want %q", resolved.Transport.Kind, contract.WantTransport)
	}
	for _, tag := range contract.WantTags {
		if !contains(resolved.Tags, tag) {
			t.Fatalf("resolved tags = %#v, missing %q", resolved.Tags, tag)
		}
	}
	for _, capability := range contract.WantCapabilities {
		if !contains(resolved.Capabilities, capability) {
			t.Fatalf("resolved capabilities = %#v, missing %q", resolved.Capabilities, capability)
		}
	}

	var listener hovel.ListenerRef
	conn.Call("prepare_listener", hovel.PrepareListenerRequest{
		RunID:     contract.RunID,
		Target:    contract.Target,
		PayloadID: resolved.ID,
		Config:    contract.Config,
	}, &listener)

	var generated hovel.PayloadArtifactSet
	conn.Call("generate_payload", hovel.GeneratePayloadRequest{
		RunID:     contract.RunID,
		Target:    contract.Target,
		PayloadID: resolved.ID,
		Format:    contract.WantFormat,
		Config:    contract.Config,
		Listener:  &listener,
	}, &generated)
	if generated.Primary.Role != "primary" {
		t.Fatalf("primary artifact role = %q", generated.Primary.Role)
	}
	if generated.Primary.Format == "" {
		t.Fatalf("primary artifact missing format: %#v", generated.Primary)
	}
	if contract.WantKind != "" && generated.Primary.Kind != contract.WantKind {
		t.Fatalf("primary artifact kind = %q, want %q", generated.Primary.Kind, contract.WantKind)
	}
	if generated.Primary.Encoding != "base64" && generated.Primary.Encoding != "chunked" {
		t.Fatalf("primary artifact encoding = %q", generated.Primary.Encoding)
	}
	if len(generated.Artifacts) == 0 {
		t.Fatal("generate_payload returned no artifacts")
	}

	var session hovel.SessionRef
	installedPayloadID := contract.WantInstalledPayloadID
	if installedPayloadID == "" {
		installedPayloadID = "p-contract"
	}
	conn.Call("connect_session", hovel.ConnectSessionRequest{
		RunID:              contract.RunID,
		Target:             contract.Target,
		PayloadID:          resolved.ID,
		InstalledPayloadID: installedPayloadID,
		Config:             contract.Config,
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    info.Name,
			Schema:        "hoveltest.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"target": contract.Target},
		},
	}, &session)
	if session.ID == "" {
		t.Fatalf("connect_session returned missing session id: %#v", session)
	}
	if session.InstalledPayloadID != installedPayloadID {
		t.Fatalf("connect_session installed payload id = %q, want %q", session.InstalledPayloadID, installedPayloadID)
	}

	var cleanup hovel.CleanupResult
	conn.Call("cleanup_payload", hovel.CleanupPayloadRequest{
		RunID:              contract.RunID,
		Target:             contract.Target,
		PayloadID:          resolved.ID,
		InstalledPayloadID: installedPayloadID,
		Reason:             "contract test",
		Cleanup: &hovel.PayloadProviderRecord{
			ProviderID:    info.Name,
			Schema:        "hoveltest.cleanup",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"target": contract.Target},
		},
	}, &cleanup)
	if cleanup.Status != "ok" {
		t.Fatalf("cleanup status = %q", cleanup.Status)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
