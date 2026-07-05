package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

const providerVersion = "0.1.6"

type Provider struct {
	Root string
}

type payloadDef struct {
	ID           string
	Name         string
	Platform     string
	Arch         string
	Formats      []string
	Capabilities []string
	Transport    hovel.PayloadTransport
	Session      hovel.PayloadSession
}

var payloads = []payloadDef{
	{
		ID:           "hello:linux:x86_64",
		Name:         "hello",
		Platform:     "linux",
		Arch:         "x86_64",
		Formats:      []string{"bin"},
		Capabilities: []string{"payload.pic", "payload.smoke"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
	{
		ID:           "ul_exec:linux:x86_64",
		Name:         "ul_exec",
		Platform:     "linux",
		Arch:         "x86_64",
		Formats:      []string{"bin"},
		Capabilities: []string{"payload.pic", "payload.exec"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
	{
		ID:           "hello_windows:windows:x86_64",
		Name:         "hello_windows",
		Platform:     "windows",
		Arch:         "x86_64",
		Formats:      []string{"bin"},
		Capabilities: []string{"payload.pic", "payload.windows", "payload.smoke"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
}

type releaseManifest struct {
	Catalog map[string]struct {
		Platforms map[string][]string `json:"platforms"`
	} `json:"catalog"`
}

func main() {
	hovel.Serve(&Provider{Root: discoverRoot()})
}

func discoverRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "python", "picblobs")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "modules", "picblobs", "python", "picblobs")); err == nil {
			return filepath.Join(dir, "modules", "picblobs")
		}
		next := filepath.Dir(dir)
		if next == dir {
			return cwd
		}
	}
}

func (p *Provider) Info() hovel.Info {
	return hovel.Info{
		Name:        "picblobs",
		Version:     providerVersion,
		Type:        hovel.TypePayloadProvider,
		Summary:     "Position-independent payload blob provider",
		Description: "Provides staged picblobs payload artifacts for Hovel exploit modules.",
		Tags:        []string{"payload_provider", "pic", "cross-platform"},
		DiscoveryContext: hovel.ModuleContext{
			Summary:      "Generates flat PIC blob artifacts from the staged picblobs release tree.",
			Keywords:     []string{"picblobs", "position-independent code", "payloads"},
			Platforms:    []string{"linux/x86_64", "windows/x86_64"},
			Capabilities: []string{"payload.pic", "payload.smoke", "payload.exec"},
			Risk:         hovel.RiskContext{Level: "medium", Reasons: []string{"Generated payload bytes are intended for authorized lab and red-team use."}},
		},
	}
}

func (p *Provider) Schema() hovel.Schema {
	return hovel.Schema{
		TargetConfig: []hovel.Requirement{
			{Key: "payload.platform", Type: "string", Required: false, Description: "Target operating system such as linux or windows."},
			{Key: "payload.arch", Type: "string", Required: false, Description: "Target CPU architecture such as x86_64."},
			{Key: "payload.format", Type: "string", Required: false, Default: "bin", Description: "Artifact format to generate."},
		},
		Outputs: map[string]any{
			"artifacts": []map[string]string{
				{"name": "payload", "kind": "application/octet-stream", "mode": "inline"},
			},
		},
	}
}

func (p *Provider) Run(ctx *hovel.Context) (hovel.Result, error) {
	_ = ctx
	return hovel.Ok(map[string]any{"status": "ready"}, hovel.WithSummary("picblobs payload provider is ready")), nil
}

func (p *Provider) ListPayloads(query hovel.PayloadQuery) ([]hovel.PayloadInfo, error) {
	var out []hovel.PayloadInfo
	for _, payload := range p.catalog() {
		if matches(payload, query) {
			out = append(out, payload.info())
		}
	}
	return out, nil
}

func (p *Provider) ResolvePayload(query hovel.PayloadQuery) (hovel.PayloadInfo, error) {
	for _, payload := range p.catalog() {
		if matches(payload, query) {
			return payload.info(), nil
		}
	}
	return hovel.PayloadInfo{}, fmt.Errorf("no picblobs payload matches query")
}

func (p *Provider) PrepareListener(req hovel.PrepareListenerRequest) (hovel.ListenerRef, error) {
	return hovel.ListenerRef{
		ID:        refID("listener", req.RunID, req.PayloadID),
		RunID:     req.RunID,
		Target:    req.Target,
		Transport: "none",
		State:     "not_required",
		Fields:    map[string]string{"provider": "picblobs"},
	}, nil
}

func (p *Provider) GeneratePayload(req hovel.GeneratePayloadRequest) (hovel.PayloadArtifactSet, error) {
	payload, err := p.resolveByID(req.PayloadID)
	if err != nil {
		return hovel.PayloadArtifactSet{}, err
	}
	if req.Format != "" && !contains(payload.Formats, req.Format) {
		return hovel.PayloadArtifactSet{}, fmt.Errorf("payload %s does not support format %q", payload.ID, req.Format)
	}
	data, path, err := p.readArtifact(payload)
	if err != nil {
		return hovel.PayloadArtifactSet{}, err
	}
	sum := sha256.Sum256(data)
	artifact := hovel.PayloadArtifact{
		Name:     filepath.Base(path),
		Role:     "primary",
		Format:   "bin",
		Encoding: "base64",
		Bytes:    base64.StdEncoding.EncodeToString(data),
		Size:     int64(len(data)),
		SHA256:   fmt.Sprintf("%x", sum[:]),
	}
	return hovel.PayloadArtifactSet{Primary: artifact, Artifacts: []hovel.PayloadArtifact{artifact}}, nil
}

func (p *Provider) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	return hovel.SessionRef{
		ID:                 refID("session", req.RunID, req.PayloadID),
		RunID:              req.RunID,
		ModuleID:           "picblobs",
		Target:             req.Target,
		Name:               "picblobs payload",
		Kind:               "none",
		State:              "not_connected",
		Transport:          "none",
		InstalledPayloadID: req.InstalledPayloadID,
		Capabilities:       []string{},
	}, nil
}

func (p *Provider) CleanupPayload(req hovel.CleanupPayloadRequest) (hovel.CleanupResult, error) {
	_ = req
	return hovel.CleanupResult{Status: "ok"}, nil
}

func (p *Provider) ReadPayloadChunk(req hovel.ReadPayloadChunkRequest) (hovel.PayloadChunk, error) {
	return hovel.PayloadChunk{}, fmt.Errorf("chunked payload reads are not implemented for handle %q", req.Handle)
}

func (p *Provider) readArtifact(payload payloadDef) ([]byte, string, error) {
	root := p.Root
	if root == "" {
		root = discoverRoot()
	}
	name := fmt.Sprintf("%s.%s.%s.bin", payload.Name, payload.Platform, payload.Arch)
	path := filepath.Join(root, "python", "picblobs", "blobs", name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, fmt.Errorf("picblobs artifact %s is not staged; run task picblobs:stage: %w", name, err)
	}
	return data, path, nil
}

func (p *Provider) catalog() []payloadDef {
	if fromManifest, err := p.catalogFromManifest(); err == nil && len(fromManifest) > 0 {
		return fromManifest
	}
	if fromBlobs, err := p.catalogFromBlobDir(); err == nil && len(fromBlobs) > 0 {
		return fromBlobs
	}
	return append([]payloadDef{}, payloads...)
}

func (p *Provider) catalogFromManifest() ([]payloadDef, error) {
	path := filepath.Join(p.root(), "python", "picblobs", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest releaseManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	var out []payloadDef
	for name, entry := range manifest.Catalog {
		for platform, arches := range entry.Platforms {
			for _, arch := range arches {
				out = append(out, newPayload(name, platform, arch))
			}
		}
	}
	sortPayloads(out)
	return out, nil
}

func (p *Provider) catalogFromBlobDir() ([]payloadDef, error) {
	pattern := filepath.Join(p.root(), "python", "picblobs", "blobs", "*.bin")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var out []payloadDef
	seen := map[string]bool{}
	for _, path := range paths {
		stem := strings.TrimSuffix(filepath.Base(path), ".bin")
		parts := strings.Split(stem, ".")
		if len(parts) < 3 {
			continue
		}
		name := strings.Join(parts[:len(parts)-2], ".")
		platform := parts[len(parts)-2]
		arch := parts[len(parts)-1]
		key := name + ":" + platform + ":" + arch
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, newPayload(name, platform, arch))
	}
	sortPayloads(out)
	return out, nil
}

func (p *Provider) resolveByID(id string) (payloadDef, error) {
	for _, payload := range p.catalog() {
		if payload.ID == id || payload.Name == id {
			return payload, nil
		}
	}
	return payloadDef{}, fmt.Errorf("unknown picblobs payload %q", id)
}

func (p *Provider) root() string {
	if p.Root != "" {
		return p.Root
	}
	return discoverRoot()
}

func matches(payload payloadDef, query hovel.PayloadQuery) bool {
	if query.Target != "" && query.Target != payload.ID && query.Target != payload.Name {
		return false
	}
	if query.Platform != "" && query.Platform != payload.Platform {
		return false
	}
	if query.Arch != "" && query.Arch != payload.Arch {
		return false
	}
	if query.Format != "" && !contains(payload.Formats, query.Format) {
		return false
	}
	return true
}

func (p payloadDef) info() hovel.PayloadInfo {
	return hovel.PayloadInfo{
		ID:           p.ID,
		Name:         p.Name,
		Version:      providerVersion,
		Platform:     p.Platform,
		Arch:         p.Arch,
		Formats:      append([]string{}, p.Formats...),
		Capabilities: append([]string{}, p.Capabilities...),
		Transport:    p.Transport,
		Session:      p.Session,
	}
}

func newPayload(name, platform, arch string) payloadDef {
	capabilities := []string{"payload.pic"}
	if strings.Contains(name, "hello") {
		capabilities = append(capabilities, "payload.smoke")
	}
	if strings.Contains(name, "exec") {
		capabilities = append(capabilities, "payload.exec")
	}
	if platform == "windows" {
		capabilities = append(capabilities, "payload.windows")
	}
	return payloadDef{
		ID:           fmt.Sprintf("%s:%s:%s", name, platform, arch),
		Name:         name,
		Platform:     platform,
		Arch:         arch,
		Formats:      []string{"bin"},
		Capabilities: capabilities,
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	}
}

func sortPayloads(values []payloadDef) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].ID < values[j].ID
	})
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func refID(prefix, runID, payloadID string) string {
	parts := []string{prefix}
	if runID != "" {
		parts = append(parts, runID)
	}
	if payloadID != "" {
		parts = append(parts, strings.ReplaceAll(payloadID, ":", "-"))
	}
	return strings.Join(parts, "-")
}
