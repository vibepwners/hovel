package hoveltest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

type fakeProvider struct{}

func (fakeProvider) Info() hovel.Info {
	return hovel.Info{Name: "fake-provider", Version: "v0.0.0", Type: hovel.TypePayloadProvider}
}

func (fakeProvider) Schema() hovel.Schema {
	return hovel.Schema{}
}

func (fakeProvider) Run(*hovel.Context) (hovel.Result, error) {
	return hovel.Ok(map[string]any{}), nil
}

func (fakeProvider) ListPayloads(hovel.PayloadQuery) ([]hovel.PayloadInfo, error) {
	return []hovel.PayloadInfo{fakeInfo()}, nil
}

func (fakeProvider) ResolvePayload(hovel.PayloadQuery) (hovel.PayloadInfo, error) {
	return fakeInfo(), nil
}

func (fakeProvider) PrepareListener(req hovel.PrepareListenerRequest) (hovel.ListenerRef, error) {
	return hovel.ListenerRef{ID: "listener-1", RunID: req.RunID, Target: req.Target, Transport: "fake/reverse-tcp", State: "listening"}, nil
}

func (fakeProvider) GeneratePayload(hovel.GeneratePayloadRequest) (hovel.PayloadArtifactSet, error) {
	body := []byte("fake payload")
	sum := sha256.Sum256(body)
	artifact := hovel.PayloadArtifact{
		Name:     "fake.exe",
		Role:     "primary",
		Kind:     string(hovel.PayloadKindPE),
		Format:   hovel.PayloadFormatPEEXE,
		OS:       "windows",
		Arch:     "x86",
		Tags:     []string{"native", "test"},
		Encoding: "base64",
		Bytes:    base64.StdEncoding.EncodeToString(body),
		Size:     int64(len(body)),
		SHA256:   hex.EncodeToString(sum[:]),
	}
	return hovel.PayloadArtifactSet{Primary: artifact, Artifacts: []hovel.PayloadArtifact{artifact}}, nil
}

func (fakeProvider) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	return hovel.SessionRef{ID: "session-1", RunID: req.RunID, Target: req.Target, Kind: "agent", State: "placeholder", Transport: "fake/reverse-tcp", InstalledPayloadID: req.InstalledPayloadID}, nil
}

func (fakeProvider) CleanupPayload(hovel.CleanupPayloadRequest) (hovel.CleanupResult, error) {
	return hovel.CleanupResult{Status: "ok"}, nil
}

func (fakeProvider) ReadPayloadChunk(hovel.ReadPayloadChunkRequest) (hovel.PayloadChunk, error) {
	return hovel.PayloadChunk{Encoding: "base64", EOF: true}, nil
}

func fakeInfo() hovel.PayloadInfo {
	return hovel.PayloadInfo{
		ID:           "fake/windows/x86/reverse-tcp/pe-exe",
		Name:         "fake",
		Version:      "v0.0.0",
		Kind:         string(hovel.PayloadKindPE),
		Platform:     "windows",
		OS:           "windows",
		Arch:         "x86",
		Formats:      []string{hovel.PayloadFormatPEEXE, hovel.PayloadFormatPE},
		Tags:         []string{"native", "test"},
		Capabilities: []string{"file.get"},
		Transport:    hovel.PayloadTransport{Kind: "reverse-tcp"},
		Session:      hovel.PayloadSession{Kind: "agent", Acquisition: "callback", RequiresPreThrowListener: true, Owner: "payload_provider"},
	}
}

func TestAssertPayloadProviderContract(t *testing.T) {
	AssertPayloadProviderContract(t, fakeProvider{}, PayloadProviderContract{
		Query:            hovel.PayloadQuery{Transport: "reverse-tcp", Format: "pe-exe"},
		Target:           "target-1",
		RunID:            "run-1",
		WantKind:         string(hovel.PayloadKindPE),
		WantFormat:       "pe-exe",
		WantTransport:    "reverse-tcp",
		WantTags:         []string{"native", "test"},
		WantCapabilities: []string{"file.get"},
	})
}
