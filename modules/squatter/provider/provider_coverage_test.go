package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
	"github.com/vibepwners/hovel/sdk/go/hovel"
)

func TestProviderMetadataPreparationAndUnknownSteps(t *testing.T) {
	p := newProvider()
	info := p.Info()
	if info.Name != payloadName || info.Type != hovel.TypePayloadProvider || len(info.Tags) == 0 {
		t.Fatalf("Info = %#v", info)
	}
	schema := p.Schema()
	if len(schema.ChainConfig) == 0 || len(schema.Outputs) == 0 {
		t.Fatalf("Schema = %#v", schema)
	}
	if req := enumReq("key", "description", "a", "b"); len(req.Allowed) != 2 {
		t.Fatalf("enum requirement = %#v", req)
	}
	contracts, err := p.DescribeSteps()
	if err != nil || len(contracts.Steps) < 5 {
		t.Fatalf("DescribeSteps = %#v, %v", contracts, err)
	}

	existing := map[string]hovel.PreparedValue{
		"staged_path":  {Value: `C:\Windows\Temp\x.exe`, Editable: true},
		"service_name": {Value: "svc", Editable: true},
		"bind_port":    {Value: "19100", Editable: true},
	}
	for _, req := range []hovel.StepPrepareRequest{
		{StepID: "squatter.install_tcp_bind", ExistingPreparedValues: existing},
		{StepID: "squatter.install_tcp_callback", ExistingPreparedValues: existing},
		{StepID: "squatter.listen_tcp_callback", Config: map[string]any{"payload.lhost": "127.0.0.1", "payload.lport": "4444"}},
		{StepID: "unknown"},
	} {
		result, err := p.PrepareStep(req)
		if err != nil {
			t.Fatalf("PrepareStep(%q): %v", req.StepID, err)
		}
		if req.StepID == "unknown" && len(result.Evidence) == 0 {
			t.Fatal("unknown prepare step returned no evidence")
		}
	}

	result, err := p.ExecuteStep(hovel.StepExecuteRequest{StepID: "unknown"})
	if err != nil || result.Status != "failed" || len(result.Evidence) == 0 {
		t.Fatalf("unknown ExecuteStep = %#v, %v", result, err)
	}
	cleanup, err := p.CleanupStep(hovel.StepCleanupRequest{StepID: "cleanup"})
	if err != nil || cleanup.Status == "" || len(cleanup.Evidence) == 0 {
		t.Fatalf("CleanupStep = %#v, %v", cleanup, err)
	}
}

func TestProviderExecuteFailureAndCallbackPaths(t *testing.T) {
	p := newProvider()
	if _, err := p.ExecuteStep(hovel.StepExecuteRequest{StepID: "squatter.install_smb"}); err == nil {
		t.Fatal("SMB install accepted missing prepared values")
	}

	listen, err := p.ExecuteStep(hovel.StepExecuteRequest{
		StepID: "squatter.listen_tcp_callback",
		RunMetadata: map[string]any{"config": map[string]any{
			"target.host": "callback-target", "payload.lhost": "invalid::host", "payload.lport": "1",
		}},
	})
	if err != nil || listen.Status != "listener_failed" {
		t.Fatalf("invalid listener = %#v, %v", listen, err)
	}

	connected, err := p.ExecuteStep(hovel.StepExecuteRequest{
		RunID:  "run",
		StepID: "squatter.connect_tcp_callback",
		RunMetadata: map[string]any{"config": map[string]any{
			"target.host": "callback-target",
		}},
	})
	if err != nil || connected.Status != "succeeded" || len(connected.Sessions) != 1 {
		t.Fatalf("callback connect = %#v, %v", connected, err)
	}

	unreachable, err := p.ExecuteStep(hovel.StepExecuteRequest{
		StepID: "squatter.connect_tcp_bind",
		RunMetadata: map[string]any{"config": map[string]any{
			"target.host": "127.0.0.1", "payload.bind_port": "1", "session.connect_ms": "1",
		}},
	})
	if err != nil || unreachable.Status != "unreachable" {
		t.Fatalf("TCP unreachable = %#v, %v", unreachable, err)
	}

	smb, err := p.ExecuteStep(hovel.StepExecuteRequest{
		StepID:      "squatter.connect_smb",
		RunMetadata: map[string]any{"config": map[string]any{"target.host": "server"}},
	})
	if err != nil || smb.Status != "unreachable" {
		t.Fatalf("SMB unreachable = %#v, %v", smb, err)
	}
}

func TestProviderPayloadConfigValidationAndMetadataFilters(t *testing.T) {
	valid := testPayloadConfigBody()
	for _, req := range []hovel.GeneratePayloadRequest{
		{PayloadID: "/tcp-bind/", Config: map[string]string{"payload.bind_port": "bad"}},
		{PayloadID: "/tcp-callback/", Config: map[string]string{"payload.lhost": "hostname", "payload.lport": "4444"}},
		{PayloadID: "/tcp-callback/", Config: map[string]string{"payload.lhost": "127.0.0.1", "payload.lport": "bad"}},
		{PayloadID: "/smb-named-pipe/", Config: map[string]string{"payload.pipe": strings.Repeat("x", payloadConfigPipeCharacters)}},
		{Config: map[string]string{"payload.transport": "unknown"}},
	} {
		body := append([]byte(nil), valid...)
		if err := patchPayloadConfig(body, req); err == nil {
			t.Fatalf("patchPayloadConfig(%#v) returned nil error", req)
		}
	}
	if err := patchPayloadConfig(nil, hovel.GeneratePayloadRequest{}); err == nil {
		t.Fatal("patchPayloadConfig accepted missing marker")
	}
	if looksLikePayloadConfig([]byte(payloadConfigMagic), 0) {
		t.Fatal("short config looked valid")
	}
	badKind := append([]byte(nil), valid...)
	binaryOffset := payloadConfigKindOffset
	badKind[binaryOffset] = 99
	if looksLikePayloadConfig(badKind, 0) {
		t.Fatal("unknown config kind looked valid")
	}
	if utf16HasPrefix(nil, "x") {
		t.Fatal("short UTF-16 prefix matched")
	}

	for _, pipe := range []string{"", `\\.\pipe\ready`, `\\host\pipe\remote`, `\plain`} {
		if got := normalizeNamedPipe(pipe); !strings.HasPrefix(got, `\\.\pipe\`) {
			t.Fatalf("normalizeNamedPipe(%q) = %q", pipe, got)
		}
	}

	queries := []hovel.PayloadQuery{
		{Kind: "wrong"}, {OS: "linux"}, {Platform: "linux"}, {Arch: "x64"}, {Format: "elf"}, {Tags: []string{"missing"}},
	}
	for _, query := range queries {
		if _, ok := matchingPayloadInfo(query, tcpBind); ok {
			t.Fatalf("matchingPayloadInfo(%#v) matched", query)
		}
	}
	for _, transport := range []string{tcpBind, tcpCallback, smbNamedPipe, reverseTCP} {
		if info := payloadInfo(transport); info.ID == "" || info.Session.Acquisition == "" {
			t.Fatalf("payloadInfo(%q) = %#v", transport, info)
		}
	}
	if _, err := (Provider{}).ResolvePayload(hovel.PayloadQuery{}); err == nil {
		t.Fatal("ResolvePayload accepted missing transport")
	}
	if _, err := (Provider{}).ResolvePayload(hovel.PayloadQuery{Transport: tcpBind, OS: "linux"}); err == nil {
		t.Fatal("ResolvePayload accepted mismatched query")
	}
	if payloads, err := (Provider{}).ListPayloads(hovel.PayloadQuery{Transport: tcpBind, OS: "linux"}); err != nil || len(payloads) != 0 {
		t.Fatalf("ListPayloads mismatch = %#v, %v", payloads, err)
	}
}

func TestProviderSmallHelpersAndCommandMetadata(t *testing.T) {
	if got, ok := stringConfig(map[string]any{"x": "y"}, "x"); !ok || got != "y" {
		t.Fatalf("stringConfig = %q, %v", got, ok)
	}
	if _, ok := stringConfig(map[string]any{"x": 1}, "x"); ok {
		t.Fatal("stringConfig accepted integer")
	}
	if sanitizeCapabilitySuffix(`a:b.c/d\e[f]`) != "a_b_c_d_e_f_" {
		t.Fatal("sanitizeCapabilitySuffix did not replace separators")
	}
	generated, err := preparedString(map[string]hovel.PreparedValue{"x": {Value: 1}}, "x", func() (string, error) { return "generated", nil })
	if err != nil || generated != "generated" {
		t.Fatalf("preparedString = %q, %v", generated, err)
	}
	if token, err := randomToken(4); err != nil || len(token) != 8 {
		t.Fatalf("randomToken = %q, %v", token, err)
	}

	for _, command := range []string{"wininfo", "process.list", "process.kill", "process.run_as_user", "payload.status", "payload.cleanup", "file.stat", "registry.query", "eventlog.query", "drive.list", "share.list", "acl.stat", "other"} {
		if payloadCommandSummary(command) == "" {
			t.Fatalf("empty summary for %q", command)
		}
	}
	if got := payloadCommandTimeout(hovel.PayloadCommandRequest{Command: "process.run", Args: []string{"cmd", "100"}}); got != 5100*time.Millisecond {
		t.Fatalf("payload timeout = %s", got)
	}
	if got := payloadCommandTimeout(hovel.PayloadCommandRequest{Command: "process.run", Args: []string{"cmd", "bad"}}); got != 30*time.Second {
		t.Fatalf("default payload timeout = %s", got)
	}
	if recordDescriptorStringMap(nil) != nil {
		t.Fatal("nil record produced descriptor")
	}
	record := recordDescriptorStringMap(&hovel.PayloadProviderRecord{Descriptor: map[string]any{"port": 445, "empty": ""}})
	if record["port"] != "445" {
		t.Fatalf("record descriptor = %#v", record)
	}
	if canonicalTransport(reverseTCP) != tcpCallback || canonicalTransport(tcpBind) != tcpBind || len(capabilities()) < 10 {
		t.Fatal("transport/capability helpers failed")
	}
}

func TestListeningPostReconnectOptionsCleanupAndErrors(t *testing.T) {
	p := Provider{}
	if p.listeningPost() == nil {
		t.Fatal("nil provider did not create listening post")
	}
	lp := newPlaceholderLP()
	if _, err := lp.PrepareListener(hovel.PrepareListenerRequest{}); err == nil {
		t.Fatal("listener accepted missing target")
	}
	if _, err := lp.PrepareListener(hovel.PrepareListenerRequest{Target: "x", Config: map[string]string{"payload.lport": "bad"}}); err == nil {
		t.Fatal("listener accepted invalid port")
	}
	if _, err := lp.PrepareListener(hovel.PrepareListenerRequest{Target: "x", Config: map[string]string{"payload.lhost": "invalid::host"}}); err == nil {
		t.Fatal("listener accepted invalid host")
	}
	if _, err := lp.ConnectSession(hovel.ConnectSessionRequest{}); err == nil {
		t.Fatal("session accepted missing target")
	}

	req := requestWithReconnectRecord(hovel.ConnectSessionRequest{Reconnect: &hovel.PayloadProviderRecord{Descriptor: map[string]any{
		"transport": tcpCallback, "target": "node", "smb.port": 445, "other": 1.5,
	}}})
	if req.Target != "node" || req.Config["payload.transport"] != tcpCallback || req.Config["smb.port"] != "445" {
		t.Fatalf("reconnect request = %#v", req)
	}
	for input, want := range map[any]string{nil: "", "x": "x", 3: "3", int64(4): "4", float64(5): "5", float64(1.5): "1.5", true: "true"} {
		if got := descriptorString(input); got != want {
			t.Fatalf("descriptorString(%#v) = %q, want %q", input, got, want)
		}
	}

	for _, req := range []hovel.ConnectSessionRequest{
		{Target: "host", Config: map[string]string{"smb.port": "bad", "smb.username": "u", "smb.password": "p"}},
		{Target: "host", Config: map[string]string{"session.connect_ms": "bad", "smb.username": "u", "smb.password": "p"}},
		{Target: "host", Config: map[string]string{"smb.password": "p"}},
		{Target: "host", Config: map[string]string{"smb.username": "u"}},
	} {
		if _, err := smbOptionsFromRequest(req); err == nil {
			t.Fatalf("smbOptionsFromRequest(%#v) returned nil", req)
		}
	}
	for _, req := range []hovel.ConnectSessionRequest{
		{},
		{Target: "host", Config: map[string]string{"payload.bind_port": "bad"}},
		{Target: "host", Config: map[string]string{"session.connect_ms": "0"}},
	} {
		if _, err := tcpBindOptionsFromRequest(req); err == nil {
			t.Fatalf("tcpBindOptionsFromRequest(%#v) returned nil", req)
		}
	}
	if firstNonEmpty("", "value", "later") != "value" || firstNonEmpty("", "") != "" {
		t.Fatal("firstNonEmpty cases failed")
	}
	if _, ok := lp.takeReverseCallback("missing"); ok {
		t.Fatal("missing callback found")
	}
	if _, ok := lp.listener("missing"); ok {
		t.Fatal("missing listener found")
	}
	if _, ok := lp.session("missing"); ok {
		t.Fatal("missing session found")
	}
	if _, ok := lp.tcpBindConn("missing"); ok {
		t.Fatal("missing bind connection found")
	}
	if _, ok := lp.smbConn("missing"); ok {
		t.Fatal("missing SMB connection found")
	}
	lp.smbConns["x"] = noopReadWriteCloser{}
	client, server := net.Pipe()
	lp.bindConns["x"] = client
	lp.sessions["x"] = hovel.SessionRef{ID: "x"}
	if result, err := lp.Cleanup(hovel.CleanupPayloadRequest{}); err != nil || result.Status != "ok" {
		t.Fatalf("cleanup all = %#v, %v", result, err)
	}
	_ = server.Close()
}

func TestMeshErrorsAddressConversionAndSessionLifecycle(t *testing.T) {
	p := newProvider()
	if descriptor, err := p.DescribeCredentialDelivery(); err != nil || len(descriptor.Slots) != 1 {
		t.Fatalf("credential delivery = %#v, %v", descriptor, err)
	}
	if meshLinkState("ready") != "up" || meshLinkState("offline") != "down" {
		t.Fatal("mesh link states failed")
	}
	unsupported, err := p.RunMeshTask(nil, hovel.MeshTaskRequest{TaskID: "t", Kind: "other"})
	if err != nil || unsupported.Status != hovel.MeshTaskStatusFailed {
		t.Fatalf("unsupported task = %#v, %v", unsupported, err)
	}
	offline, err := p.RunMeshTask(nil, hovel.MeshTaskRequest{
		TaskID: "survey", Kind: hovel.MeshTaskSurvey, DestinationHost: "127.0.0.1", DestinationPort: 1,
		Config: map[string]any{"session.connect_ms": "1"},
	})
	if err != nil || offline.Status != hovel.MeshTaskStatusFailed || offline.Route == nil {
		t.Fatalf("offline survey = %#v, %v", offline, err)
	}
	if _, err := p.RunMeshTask(nil, hovel.MeshTaskRequest{Kind: hovel.MeshTaskSurvey, ListenerID: "listener"}); err == nil {
		t.Fatal("listener-scoped survey accepted")
	}
	if _, _, err := p.resolveSquatterMeshAddress("missing", "", nil, "", 0, "", nil); err == nil {
		t.Fatal("unknown node accepted")
	}
	if node, err := validateSquatterMeshRoute(hovel.MeshRoute{Nodes: []string{meshRootNodeID}}); err != nil || node != meshRootNodeID {
		t.Fatalf("root route = %q, %v", node, err)
	}
	if _, err := validateSquatterMeshRoute(hovel.MeshRoute{Nodes: []string{"bad"}}); err == nil {
		t.Fatal("bad route accepted")
	}
	if _, err := p.meshTLSServerConfig(); err == nil {
		t.Fatal("TLS config succeeded without bundle")
	}
	opts, err := meshTCPBindOptions("", 0, "host", map[string]any{"payload.bind_port": float64(9100), "session.connect_ms": 2})
	if err != nil || opts.Port != 9100 || opts.Timeout != 2*time.Millisecond {
		t.Fatalf("mesh options = %#v, %v", opts, err)
	}

	client, server := net.Pipe()
	closedExtra := false
	session := newMeshConnSession(client, func() { closedExtra = true })
	if err := session.Open(); err != nil || session.Closed() {
		t.Fatalf("session initial = %v, closed %v", err, session.Closed())
	}
	if data, err := session.Read(time.Millisecond); err != nil || data != nil {
		t.Fatalf("timed read = %x, %v", data, err)
	}
	read := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 3)
		_, _ = io.ReadFull(server, buf)
		read <- buf
	}()
	if err := session.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := <-read; string(got) != "abc" {
		t.Fatalf("peer read = %q", got)
	}
	go func() { _, _ = server.Write([]byte("reply")) }()
	if got, err := session.Read(-1); err != nil || string(got) != "reply" {
		t.Fatalf("session read = %q, %v", got, err)
	}
	if err := session.Close("done"); err != nil || !session.Closed() || !closedExtra {
		t.Fatalf("session close = %v, closed %v extra %v", err, session.Closed(), closedExtra)
	}
	if err := session.Close("again"); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
}

func TestMeshRoutingTLSAndConnectionFailures(t *testing.T) {
	p := newProvider()
	if _, err := p.MeshTopology(hovel.MeshTopologyRequest{ListenerID: "listener"}); err == nil {
		t.Fatal("listener-scoped topology returned nil error")
	}
	endpoint := p.rememberMeshEndpoint(tcpBindOptions{Host: "127.0.0.1", Port: 19091}, "ready")
	route := meshRoute(endpoint)
	if _, _, err := p.resolveSquatterMeshAddress("other", "", &route, "", 0, "", nil); err == nil {
		t.Fatal("route and node mismatch returned nil error")
	}
	if _, _, err := p.resolveSquatterMeshAddress(endpoint.NodeID, "", nil, "192.0.2.1", 0, "", nil); err == nil {
		t.Fatal("node host conflict returned nil error")
	}
	if _, _, err := p.resolveSquatterMeshAddress(endpoint.NodeID, "", nil, "", 19092, "", nil); err == nil {
		t.Fatal("node port conflict returned nil error")
	}
	if _, err := p.OpenMeshStream(nil, hovel.MeshStreamRequest{ListenerID: "listener"}); err == nil {
		t.Fatal("listener-scoped stream returned nil error")
	}
	if _, err := p.OpenMeshStream(nil, hovel.MeshStreamRequest{
		DestinationHost: "127.0.0.1", DestinationPort: 1, Protocol: "unsupported",
	}); err == nil {
		t.Fatal("unsupported mesh protocol returned nil error")
	}
	if _, err := p.OpenMeshStream(nil, hovel.MeshStreamRequest{
		DestinationHost: "127.0.0.1", DestinationPort: 1, Protocol: meshProtocolRaw,
		Config: map[string]any{"session.connect_ms": 1},
	}); err == nil {
		t.Fatal("unreachable mesh stream returned nil error")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	if _, err := p.OpenMeshStream(nil, hovel.MeshStreamRequest{
		DestinationHost: "127.0.0.1", DestinationPort: listener.Addr().(*net.TCPAddr).Port,
		Protocol: meshProtocolTLS, Config: map[string]any{"session.connect_ms": 1000},
	}); err == nil {
		t.Fatal("TLS stream without runtime credential returned nil error")
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("mesh TLS test connection was not accepted")
	}

	expired, _ := testSquatterTLSBundle(t, time.Now().UTC().Add(-2*time.Hour))
	p.lp.mu.Lock()
	p.lp.tlsBundle = expired
	p.lp.mu.Unlock()
	if _, err := p.meshTLSServerConfig(); err == nil {
		t.Fatal("expired runtime TLS bundle returned nil error")
	}

	writeFailure := newMeshConnSession(&providerFaultConn{writeErr: errors.New("write failed")}, nil)
	if err := writeFailure.Write([]byte("x")); err == nil || !writeFailure.Closed() {
		t.Fatalf("mesh write failure = %v closed=%v", err, writeFailure.Closed())
	}
	zeroWrite := newMeshConnSession(&providerFaultConn{zeroWrite: true}, nil)
	if err := zeroWrite.Write([]byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("mesh zero write = %v", err)
	}
	for name, conn := range map[string]*providerFaultConn{
		"clear_deadline": {deadlineErr: errors.New("clear deadline failed")},
		"set_deadline":   {deadlineErr: errors.New("set deadline failed")},
	} {
		t.Run(name, func(t *testing.T) {
			session := newMeshConnSession(conn, nil)
			wait := time.Millisecond
			if name == "clear_deadline" {
				wait = -1
			}
			if _, err := session.Read(wait); err == nil {
				t.Fatal("deadline failure returned nil error")
			}
		})
	}
	for name, readErr := range map[string]error{"eof": io.EOF, "closed": net.ErrClosed, "failure": errors.New("read failed")} {
		t.Run("read_"+name, func(t *testing.T) {
			session := newMeshConnSession(&providerFaultConn{readErr: readErr}, nil)
			data, err := session.Read(time.Millisecond)
			if name == "failure" {
				if err == nil || !session.Closed() {
					t.Fatalf("read failure = %x, %v closed=%v", data, err, session.Closed())
				}
			} else if err != nil || data != nil || !session.Closed() {
				t.Fatalf("terminal read = %x, %v closed=%v", data, err, session.Closed())
			}
		})
	}
	closeFailure := newMeshConnSession(&providerFaultConn{closeErr: errors.New("close failed")}, nil)
	if err := closeFailure.Close("done"); err == nil {
		t.Fatal("mesh close failure returned nil error")
	}

	rawClient, rawServer := net.Pipe()
	defer rawServer.Close()
	tlsSession := newTLSMeshGatewaySession(rawClient, &tls.Config{})
	if err := tlsSession.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !tlsSession.Closed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !tlsSession.Closed() {
		t.Fatal("invalid TLS handshake did not close the mesh session")
	}
}

func TestPayloadCommandDispatchInputsAndStreamErrors(t *testing.T) {
	emptyReader := bufio.NewReader(bytes.NewReader(nil))
	for _, req := range []hovel.PayloadCommandRequest{
		{Command: "unsupported"},
		{Command: "getfile"},
		{Command: "putfile"},
		{Command: "cmd"},
		{Command: "process.run"},
		{Command: "process.run_as_user"},
	} {
		if _, err := runPayloadCommandOnTransport(io.Discard, emptyReader, 1, req); err == nil {
			t.Fatalf("command %#v returned nil error", req)
		}
	}

	file := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(file, []byte("file-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, req := range []hovel.PayloadCommandRequest{
		{InputPath: file},
		{InputData: "text", InputEncoding: "text"},
		{InputData: base64.StdEncoding.EncodeToString([]byte("base64")), InputEncoding: "base64"},
	} {
		input, closeInput, err := payloadCommandInput(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(input)
		closeInput()
		if err != nil || len(data) == 0 {
			t.Fatalf("payloadCommandInput = %q, %v", data, err)
		}
	}
	for _, req := range []hovel.PayloadCommandRequest{
		{InputPath: filepath.Join(t.TempDir(), "missing")},
		{InputData: "%%%", InputEncoding: "base64"},
		{InputData: "x", InputEncoding: "binary"},
	} {
		if _, _, err := payloadCommandInput(req); err == nil {
			t.Fatalf("payloadCommandInput(%#v) returned nil error", req)
		}
	}

	if _, err := runGetfileCommand(io.Discard, bufio.NewReader(bytes.NewReader([]byte("short"))), 1, hovel.PayloadCommandRequest{Args: []string{"remote"}}); err == nil {
		t.Fatal("getfile truncated response returned nil error")
	}
	putResponses := providerFrames(t,
		providerFrame{wire.KindData, []byte("SOK")},
		providerFrame{wire.KindData, []byte("SOK 4")},
		providerFrame{wire.KindClose, nil},
	)
	result, err := runPutfileCommand(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(putResponses)), 2, hovel.PayloadCommandRequest{
		Command: "putfile", Args: []string{"remote"}, InputData: "data",
	})
	if err != nil || result.Command != "putfile" || result.Fields["bytes"] != "4" {
		t.Fatalf("putfile result = %#v, %v", result, err)
	}
	if _, err := runPutfileCommand(io.Discard, bufio.NewReader(bytes.NewReader([]byte("short"))), 1, hovel.PayloadCommandRequest{Args: []string{"remote"}, InputData: "x"}); err == nil {
		t.Fatal("putfile truncated response returned nil error")
	}
}

func TestPayloadCommandFrameProcessingBranches(t *testing.T) {
	cmdResponses := providerFrames(t,
		providerFrame{wire.KindControl, nil},
		providerFrame{wire.KindData, []byte("hello")},
		providerFrame{wire.KindClose, nil},
	)
	var requests bytes.Buffer
	result, err := runCmdCommand(&requests, bufio.NewReader(bytes.NewReader(cmdResponses)), 3, hovel.PayloadCommandRequest{Command: "cmd", Args: []string{"whoami"}})
	if err != nil || result.Stdout != "hello" || result.Fields["command"] != "whoami" {
		t.Fatalf("cmd result = %#v, %v", result, err)
	}
	if _, err := runCmdCommand(io.Discard, bufio.NewReader(bytes.NewReader([]byte("short"))), 1, hovel.PayloadCommandRequest{Args: []string{"whoami"}}); err == nil {
		t.Fatal("cmd truncated response returned nil error")
	}

	jsonResponses := providerFrames(t,
		providerFrame{wire.KindControl, []byte{0x80}},
		providerFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventExited, Code: 7})},
		providerFrame{wire.KindData, []byte(`{"ok":true}`)},
		providerFrame{wire.KindClose, nil},
	)
	result, err = runJSONPayloadCommand(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(jsonResponses)), 4, hovel.PayloadCommandRequest{Command: "wininfo"}, "wininfo", nil)
	if err != nil || result.Fields["exitCode"] != "7" || result.Stdout == "" {
		t.Fatalf("JSON result = %#v, %v", result, err)
	}

	errorResponses := providerFrames(t,
		providerFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventError, Code: 5})},
		providerFrame{wire.KindClose, nil},
	)
	if _, err := runJSONPayloadCommand(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(errorResponses)), 5, hovel.PayloadCommandRequest{Command: "wininfo"}, "wininfo", nil); err == nil || !strings.Contains(err.Error(), "code 5") {
		t.Fatalf("JSON stream error = %v", err)
	}
	if _, err := runJSONPayloadCommand(io.Discard, bufio.NewReader(bytes.NewReader([]byte("short"))), 1, hovel.PayloadCommandRequest{}, "wininfo", nil); err == nil {
		t.Fatal("JSON truncated response returned nil error")
	}

	rawProcess := providerFrames(t, providerFrame{wire.KindData, []byte("not-json")}, providerFrame{wire.KindClose, nil})
	result, err = runProcessRunCommand(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(rawProcess)), 6, hovel.PayloadCommandRequest{Command: "process.run", Args: []string{"whoami"}})
	if err != nil || !strings.Contains(result.Summary, "raw JSON") {
		t.Fatalf("raw process result = %#v, %v", result, err)
	}
	rawUser := providerFrames(t, providerFrame{wire.KindData, []byte("not-json")}, providerFrame{wire.KindClose, nil})
	result, err = runProcessRunAsUserCommand(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(rawUser)), 7, hovel.PayloadCommandRequest{Command: "process.run_as_user", Args: []string{"notepad"}})
	if err != nil || !strings.Contains(result.Summary, "raw JSON") {
		t.Fatalf("raw user result = %#v, %v", result, err)
	}

	chunk, err := (Provider{}).ReadPayloadChunk(hovel.ReadPayloadChunkRequest{Handle: "h", Offset: 9})
	if err != nil || !chunk.EOF || chunk.Offset != 9 || chunk.Encoding != "base64" {
		t.Fatalf("payload chunk = %#v, %v", chunk, err)
	}
}

func testPayloadConfigBody() []byte {
	body := make([]byte, payloadConfigPipeOffset+payloadConfigPipeCharacters*2)
	copy(body, []byte(payloadConfigMagic))
	body[payloadConfigKindOffset] = payloadConfigKindSMBPipe
	writeUTF16At(body, payloadConfigPipeOffset, `\\.\pipe\squatter`)
	return body
}

type providerFrame struct {
	kind    uint16
	payload []byte
}

type providerFaultConn struct {
	writeErr    error
	readErr     error
	deadlineErr error
	closeErr    error
	zeroWrite   bool
}

func (c *providerFaultConn) Read([]byte) (int, error) { return 0, c.readErr }
func (c *providerFaultConn) Write(data []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.zeroWrite {
		return 0, nil
	}
	return len(data), nil
}
func (c *providerFaultConn) Close() error                    { return c.closeErr }
func (*providerFaultConn) LocalAddr() net.Addr               { return testNetAddr("local") }
func (*providerFaultConn) RemoteAddr() net.Addr              { return testNetAddr("remote") }
func (*providerFaultConn) SetDeadline(time.Time) error       { return nil }
func (c *providerFaultConn) SetReadDeadline(time.Time) error { return c.deadlineErr }
func (*providerFaultConn) SetWriteDeadline(time.Time) error  { return nil }

func providerFrames(t *testing.T, frames ...providerFrame) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, frame := range frames {
		if err := wire.WriteFrame(&out, frame.kind, 1, frame.payload); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}
