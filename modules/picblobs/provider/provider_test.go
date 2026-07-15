package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibepwners/hovel/sdk/go/hovel"
	"github.com/vibepwners/hovel/sdk/go/hoveltest"
)

func TestPayloadProviderContract(t *testing.T) {
	root := t.TempDir()
	blobDir := filepath.Join(root, "python", "picblobs", "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "hello.linux.x86_64.bin"), []byte("hello-picblob"), 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := map[string]any{
		"type":          "hello",
		"os":            "linux",
		"arch":          "x86_64",
		"config_offset": 0,
		"entry_offset":  0,
		"sha256":        "test-sidecar-hash-not-used-by-provider",
	}
	sidecarBody, err := json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "hello.linux.x86_64.json"), sidecarBody, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"catalog": map[string]any{
			"hello": map[string]any{
				"platforms": map[string][]string{"linux": []string{"x86_64"}},
			},
		},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "python", "picblobs", "manifest.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	hoveltest.AssertPayloadProviderContract(t, &Provider{Root: root}, hoveltest.PayloadProviderContract{
		Query: hovel.PayloadQuery{
			Target:   "hello",
			Kind:     string(hovel.PayloadKindPIC),
			Platform: "linux",
			OS:       "linux",
			Arch:     "x86_64",
			Format:   hovel.PayloadFormatPIC,
			Tags:     []string{"pic"},
		},
		Target:           "lab-target",
		RunID:            "run-1",
		WantKind:         string(hovel.PayloadKindPIC),
		WantFormat:       hovel.PayloadFormatPIC,
		WantTransport:    "stdio",
		WantTags:         []string{"pic", "linux"},
		WantCapabilities: []string{"payload.pic"},
	})
}

func TestGeneratePayloadCanWrapLinuxX86PICAsELF(t *testing.T) {
	root := t.TempDir()
	blobDir := filepath.Join(root, "python", "picblobs", "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0xcc, 0xcc, 0xcc}
	if err := os.WriteFile(filepath.Join(blobDir, "hello.linux.x86_64.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := map[string]any{
		"type":          "hello",
		"os":            "linux",
		"arch":          "x86_64",
		"config_offset": 0,
		"entry_offset":  1,
	}
	sidecarBody, err := json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "hello.linux.x86_64.json"), sidecarBody, 0o644); err != nil {
		t.Fatal(err)
	}

	generated, err := (&Provider{Root: root}).GeneratePayload(hovel.GeneratePayloadRequest{
		PayloadID: "hello:linux:x86_64",
		Format:    hovel.PayloadFormatELF,
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Primary.Kind != string(hovel.PayloadKindPIC) || generated.Primary.Format != hovel.PayloadFormatELF {
		t.Fatalf("primary = %#v", generated.Primary)
	}
	body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(body[:4]) != "\x7fELF" {
		t.Fatalf("ELF magic = % x", body[:4])
	}
	if got := body[0x1000:]; string(got) != string(payload) {
		t.Fatalf("wrapped payload = %x, want %x", got, payload)
	}
}

func TestGeneratePayloadCanWrapLinuxPICAsELFForSupportedArchitectures(t *testing.T) {
	tests := []struct {
		name        string
		arch        string
		format      byte
		machine     uint16
		flags       uint32
		entry       uint64
		little      bool
		entryOffset int64
	}{
		{name: "i686", arch: "i686", format: 1, machine: 3, entry: 0x08048000, little: true},
		{name: "armv7_thumb", arch: "armv7_thumb", format: 1, machine: 40, flags: 0x05000400, entry: 0x10001, little: true},
		{name: "mipsbe32", arch: "mipsbe32", format: 1, machine: 8, flags: 0x50001007, entry: 0x00400000, little: false},
		{name: "aarch64", arch: "aarch64", format: 2, machine: 183, entry: 0x400002, little: true, entryOffset: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeBlobFixture(t, root, "hello", "linux", tt.arch, []byte{0x90, 0x90, 0x90, 0x90}, tt.entryOffset)

			generated, err := (&Provider{Root: root}).GeneratePayload(hovel.GeneratePayloadRequest{
				PayloadID: "hello:linux:" + tt.arch,
				Format:    hovel.PayloadFormatELF,
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := base64.StdEncoding.DecodeString(generated.Primary.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			var order binary.ByteOrder = binary.BigEndian
			if tt.little {
				order = binary.LittleEndian
			}
			if body[4] != tt.format {
				t.Fatalf("ELF class = %d, want %d", body[4], tt.format)
			}
			if body[5] != map[bool]byte{true: 1, false: 2}[tt.little] {
				t.Fatalf("ELF data = %d", body[5])
			}
			if got := order.Uint16(body[18:]); got != tt.machine {
				t.Fatalf("machine = %d, want %d", got, tt.machine)
			}
			if tt.format == 1 {
				if got := uint64(order.Uint32(body[24:])); got != tt.entry {
					t.Fatalf("entry = %#x, want %#x", got, tt.entry)
				}
				if got := order.Uint32(body[36:]); got != tt.flags {
					t.Fatalf("flags = %#x, want %#x", got, tt.flags)
				}
			} else {
				if got := order.Uint64(body[24:]); got != tt.entry {
					t.Fatalf("entry = %#x, want %#x", got, tt.entry)
				}
				if got := order.Uint32(body[48:]); got != tt.flags {
					t.Fatalf("flags = %#x, want %#x", got, tt.flags)
				}
			}
		})
	}
}

func TestListPayloadsAdvertisesELFForSupportedLinuxArchitectures(t *testing.T) {
	root := t.TempDir()
	writeBlobFixture(t, root, "hello", "linux", "aarch64", []byte{0x90}, 0)
	writeBlobFixture(t, root, "hello", "linux", "sparcv8", []byte{0x90}, 0)
	writeBlobFixture(t, root, "hello_windows", "windows", "x86_64", []byte{0x90}, 0)
	writeManifest(t, root, map[string]map[string][]string{
		"hello":         {"linux": {"aarch64", "sparcv8"}},
		"hello_windows": {"windows": {"x86_64"}},
	})

	payloads, err := (&Provider{Root: root}).ListPayloads(hovel.PayloadQuery{Format: hovel.PayloadFormatELF})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("ELF payloads = %#v", payloads)
	}
	for _, payload := range payloads {
		if payload.OS != "linux" || !contains(payload.Formats, hovel.PayloadFormatELF) {
			t.Fatalf("unexpected ELF payload = %#v", payload)
		}
	}
}

func writeBlobFixture(t *testing.T, root, name, platform, arch string, payload []byte, entryOffset int64) {
	t.Helper()
	blobDir := filepath.Join(root, "python", "picblobs", "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stem := name + "." + platform + "." + arch
	if err := os.WriteFile(filepath.Join(blobDir, stem+".bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := map[string]any{
		"type":          name,
		"os":            platform,
		"arch":          arch,
		"config_offset": 0,
		"entry_offset":  entryOffset,
	}
	sidecarBody, err := json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, stem+".json"), sidecarBody, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeManifest(t *testing.T, root string, catalog map[string]map[string][]string) {
	t.Helper()
	manifestCatalog := map[string]any{}
	for name, platforms := range catalog {
		manifestCatalog[name] = map[string]any{"platforms": platforms}
	}
	body, err := json.Marshal(map[string]any{"catalog": manifestCatalog})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "python", "picblobs", "manifest.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}
