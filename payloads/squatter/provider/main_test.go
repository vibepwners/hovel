package main

import (
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
		if payload.Platform != "windows" || payload.Arch != "x86" || payload.MinOS != "windows-xp-sp3" {
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

func TestProviderGeneratesPlaceholderArtifactSet(t *testing.T) {
	generated, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-xp-sp3/reverse-tcp/pe-exe",
		Format:    "pe-exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Primary.Role != "primary" || generated.Primary.Encoding != "base64" {
		t.Fatalf("primary artifact = %#v", generated.Primary)
	}
	if len(generated.Artifacts) != 1 {
		t.Fatalf("artifact count = %d", len(generated.Artifacts))
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
		Config:        map[string]string{"payload.transport": reverseTCP, "payload.lhost": "127.0.0.1", "payload.lport": "4444"},
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
		PayloadID: "squatter/windows/x86/windows-xp-sp3/reverse-tcp/pe-exe",
		Config:    map[string]string{"payload.lhost": "127.0.0.1", "payload.lport": "4444"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if listener.Transport != "squatter/reverse-tcp" || listener.Host != "127.0.0.1" || listener.Port != 4444 {
		t.Fatalf("listener = %#v", listener)
	}
	if _, ok := lp.listener("target-1"); !ok {
		t.Fatal("listener was not recorded in placeholder LP")
	}
}

func TestPlaceholderLPSMBConnectsProviderOwnedSession(t *testing.T) {
	lp := newPlaceholderLP()
	provider := Provider{lp: lp}
	session, err := provider.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     "run-1",
		Target:    "target-1",
		PayloadID: "squatter/windows/x86/windows-xp-sp3/smb-named-pipe/pe-exe",
		Config:    map[string]string{"payload.transport": smbNamedPipe, "payload.pipe": "hovel-squatter-target-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Transport != "squatter/smb-named-pipe" || session.Kind != "agent" || session.State != "placeholder" {
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
