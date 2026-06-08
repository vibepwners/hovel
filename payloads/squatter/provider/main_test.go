package main

import (
	"testing"

	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

func TestProviderReportsSquatterPayloads(t *testing.T) {
	provider := Provider{}
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
	generated, err := (Provider{}).GeneratePayload(hovel.GeneratePayloadRequest{
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
