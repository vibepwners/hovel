package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

const providerVersion = "0.1.7"
const legacyFormatBin = "bin"

type Provider struct {
	Root string
}

type payloadDef struct {
	ID           string
	Name         string
	Kind         string
	Platform     string
	Arch         string
	Formats      []string
	Tags         []string
	Capabilities []string
	Transport    hovel.PayloadTransport
	Session      hovel.PayloadSession
}

var payloads = []payloadDef{
	{
		ID:           "hello:linux:x86_64",
		Name:         "hello",
		Kind:         string(hovel.PayloadKindPIC),
		Platform:     "linux",
		Arch:         "x86_64",
		Formats:      []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, hovel.PayloadFormatELF, legacyFormatBin},
		Tags:         []string{"pic", "flat", "linux", "smoke"},
		Capabilities: []string{"payload.pic", "payload.smoke"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
	{
		ID:           "ul_exec:linux:x86_64",
		Name:         "ul_exec",
		Kind:         string(hovel.PayloadKindPIC),
		Platform:     "linux",
		Arch:         "x86_64",
		Formats:      []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, hovel.PayloadFormatELF, legacyFormatBin},
		Tags:         []string{"pic", "flat", "linux", "exec"},
		Capabilities: []string{"payload.pic", "payload.exec"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
	{
		ID:           "hello_windows:windows:x86_64",
		Name:         "hello_windows",
		Kind:         string(hovel.PayloadKindPIC),
		Platform:     "windows",
		Arch:         "x86_64",
		Formats:      []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, legacyFormatBin},
		Tags:         []string{"pic", "flat", "windows", "smoke"},
		Capabilities: []string{"payload.pic", "payload.windows", "payload.smoke"},
		Transport:    hovel.PayloadTransport{Kind: "stdio", Encrypted: false},
		Session:      hovel.PayloadSession{Kind: "none", Acquisition: "none", Owner: "payload_provider"},
	},
}

type blobMetadata struct {
	EntryOffset int64 `json:"entry_offset"`
}

type elfArch struct {
	Class        byte
	Data         byte
	Machine      uint16
	Flags        uint32
	BaseVaddr    uint64
	ThumbEntry   bool
	LittleEndian bool
}

type releaseManifest struct {
	Catalog map[string]struct {
		Platforms map[string][]string `json:"platforms"`
	} `json:"catalog"`
}

var linuxELFArches = map[string]elfArch{
	"x86_64":      {Class: 2, Data: 1, Machine: 62, BaseVaddr: 0x400000, LittleEndian: true},
	"i686":        {Class: 1, Data: 1, Machine: 3, BaseVaddr: 0x08048000, LittleEndian: true},
	"aarch64":     {Class: 2, Data: 1, Machine: 183, BaseVaddr: 0x400000, LittleEndian: true},
	"armv5_arm":   {Class: 1, Data: 1, Machine: 40, Flags: 0x05000200, BaseVaddr: 0x00010000, LittleEndian: true},
	"armv5_thumb": {Class: 1, Data: 1, Machine: 40, Flags: 0x05000200, BaseVaddr: 0x00010000, LittleEndian: true},
	"armv7_thumb": {Class: 1, Data: 1, Machine: 40, Flags: 0x05000400, BaseVaddr: 0x00010000, ThumbEntry: true, LittleEndian: true},
	"mipsel32":    {Class: 1, Data: 1, Machine: 8, Flags: 0x50001007, BaseVaddr: 0x00400000, LittleEndian: true},
	"mipsbe32":    {Class: 1, Data: 2, Machine: 8, Flags: 0x50001007, BaseVaddr: 0x00400000},
	"s390x":       {Class: 2, Data: 2, Machine: 22, BaseVaddr: 0x00400000},
	"sparcv8":     {Class: 1, Data: 2, Machine: 2, BaseVaddr: 0x00010000},
	"powerpc":     {Class: 1, Data: 2, Machine: 20, Flags: 0x00008000, BaseVaddr: 0x01000000},
	"ppc64le":     {Class: 2, Data: 1, Machine: 21, Flags: 0x00000002, BaseVaddr: 0x10000000, LittleEndian: true},
	"riscv64":     {Class: 2, Data: 1, Machine: 243, Flags: 0x00000004, BaseVaddr: 0x00010000, LittleEndian: true},
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
			AgentHints: []hovel.AgentHint{{
				Schema: "hovel.payload.formats",
				Phase:  "planning",
				Text:   "picblobs emits native flat PIC payloads and can wrap supported Linux PIC blobs as ELF artifacts.",
			}},
			Risk: hovel.RiskContext{Level: "medium", Reasons: []string{"Generated payload bytes are intended for authorized lab and red-team use."}},
		},
	}
}

func (p *Provider) Schema() hovel.Schema {
	return hovel.Schema{
		TargetConfig: []hovel.Requirement{
			{Key: "payload.platform", Type: "string", Required: false, Description: "Target operating system such as linux or windows."},
			{Key: "payload.arch", Type: "string", Required: false, Description: "Target CPU architecture such as x86_64."},
			{Key: "payload.kind", Type: "enum", Required: false, Default: string(hovel.PayloadKindPIC), Allowed: []string{string(hovel.PayloadKindPIC), string(hovel.PayloadKindPOC)}, Description: "Semantic payload representation."},
			{Key: "payload.format", Type: "enum", Required: false, Default: hovel.PayloadFormatPIC, Allowed: []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, hovel.PayloadFormatELF, legacyFormatBin}, Description: "Artifact container to generate."},
		},
		Outputs: map[string]any{
			"artifacts": []map[string]string{
				{"name": "payload", "kind": "application/octet-stream", "mode": "inline"},
			},
			"payloads": []map[string]any{
				{
					"name":    "picblobs",
					"kind":    string(hovel.PayloadKindPIC),
					"formats": []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, hovel.PayloadFormatELF},
					"os":      "linux",
					"arch":    "multi",
					"tags":    []string{"pic", "typed", "hovel-native"},
				},
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
	format := canonicalFormat(req.Format)
	if format == "" {
		format = hovel.PayloadFormatPIC
	}
	if !contains(payload.Formats, format) {
		return hovel.PayloadArtifactSet{}, fmt.Errorf("payload %s does not support format %q", payload.ID, format)
	}
	data, path, meta, err := p.readArtifact(payload)
	if err != nil {
		return hovel.PayloadArtifactSet{}, err
	}
	name := filepath.Base(path)
	if format == hovel.PayloadFormatELF {
		data, err = wrapLinuxELF(data, payload.Platform, payload.Arch, uint64(meta.EntryOffset))
		if err != nil {
			return hovel.PayloadArtifactSet{}, err
		}
		name = fmt.Sprintf("%s.%s.%s.elf", payload.Name, payload.Platform, payload.Arch)
	}
	sum := sha256.Sum256(data)
	artifact := hovel.PayloadArtifact{
		Name:     name,
		Role:     "primary",
		Kind:     payload.Kind,
		Format:   format,
		OS:       payload.Platform,
		Arch:     payload.Arch,
		Tags:     append([]string{}, payload.Tags...),
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

func (p *Provider) readArtifact(payload payloadDef) ([]byte, string, blobMetadata, error) {
	root := p.Root
	if root == "" {
		root = discoverRoot()
	}
	name := fmt.Sprintf("%s.%s.%s.bin", payload.Name, payload.Platform, payload.Arch)
	path := filepath.Join(root, "python", "picblobs", "blobs", name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, blobMetadata{}, fmt.Errorf("picblobs artifact %s is not staged; run task picblobs:stage: %w", name, err)
	}
	meta := blobMetadata{}
	metaPath := strings.TrimSuffix(path, ".bin") + ".json"
	if metaData, err := os.ReadFile(metaPath); err == nil {
		if err := json.Unmarshal(metaData, &meta); err != nil {
			return nil, path, blobMetadata{}, fmt.Errorf("picblobs sidecar %s is invalid: %w", metaPath, err)
		}
	}
	return data, path, meta, nil
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
	if query.Kind != "" && query.Kind != payload.Kind {
		return false
	}
	if query.Platform != "" && query.Platform != payload.Platform {
		return false
	}
	if query.OS != "" && query.OS != payload.Platform {
		return false
	}
	if query.Arch != "" && query.Arch != payload.Arch {
		return false
	}
	if query.Format != "" && !contains(payload.Formats, canonicalFormat(query.Format)) {
		return false
	}
	for _, tag := range query.Tags {
		if !contains(payload.Tags, tag) {
			return false
		}
	}
	return true
}

func (p payloadDef) info() hovel.PayloadInfo {
	return hovel.PayloadInfo{
		ID:           p.ID,
		Name:         p.Name,
		Version:      providerVersion,
		Kind:         p.Kind,
		Platform:     p.Platform,
		OS:           p.Platform,
		Arch:         p.Arch,
		Formats:      append([]string{}, p.Formats...),
		Tags:         append([]string{}, p.Tags...),
		Capabilities: append([]string{}, p.Capabilities...),
		Transport:    p.Transport,
		Session:      p.Session,
	}
}

func newPayload(name, platform, arch string) payloadDef {
	capabilities := []string{"payload.pic"}
	tags := []string{"pic", "flat", platform, arch}
	if strings.Contains(name, "hello") {
		capabilities = append(capabilities, "payload.smoke")
		tags = append(tags, "smoke")
	}
	if strings.Contains(name, "exec") {
		capabilities = append(capabilities, "payload.exec")
		tags = append(tags, "exec")
	}
	if platform == "windows" {
		capabilities = append(capabilities, "payload.windows")
	}
	formats := []string{hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC, legacyFormatBin}
	if supportsLinuxELF(platform, arch) {
		formats = append(formats, hovel.PayloadFormatELF)
	}
	return payloadDef{
		ID:           fmt.Sprintf("%s:%s:%s", name, platform, arch),
		Name:         name,
		Kind:         string(hovel.PayloadKindPIC),
		Platform:     platform,
		Arch:         arch,
		Formats:      formats,
		Tags:         tags,
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

func canonicalFormat(format string) string {
	switch format {
	case "", legacyFormatBin, hovel.PayloadFormatPIC, hovel.PayloadFormatFlatPIC:
		if format == legacyFormatBin {
			return hovel.PayloadFormatPIC
		}
		return format
	default:
		return format
	}
}

func supportsLinuxELF(platform, arch string) bool {
	if platform != "linux" {
		return false
	}
	_, ok := linuxELFArches[arch]
	return ok
}

func wrapLinuxELF(payload []byte, platform, archName string, entryOffset uint64) ([]byte, error) {
	const (
		elfClass32    = 1
		elfClass64    = 2
		segmentOffset = 0x1000
		pageSize      = 0x1000
	)
	if platform != "linux" {
		return nil, fmt.Errorf("ELF wrapping supports linux payloads only, got %s", platform)
	}
	arch, ok := linuxELFArches[archName]
	if !ok {
		return nil, fmt.Errorf("ELF wrapping does not support arch %s", archName)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("payload must be non-empty")
	}
	if entryOffset >= uint64(len(payload)) {
		return nil, fmt.Errorf("entry offset %d exceeds payload size %d", entryOffset, len(payload))
	}
	var order binary.ByteOrder = binary.BigEndian
	if arch.LittleEndian {
		order = binary.LittleEndian
	}
	entry := arch.BaseVaddr + entryOffset
	if arch.ThumbEntry {
		entry |= 1
	}

	var elfHeaderSize int
	var programHeaderSize int
	switch arch.Class {
	case elfClass32:
		elfHeaderSize = 52
		programHeaderSize = 32
	case elfClass64:
		elfHeaderSize = 64
		programHeaderSize = 56
	default:
		return nil, fmt.Errorf("unsupported ELF class %d for arch %s", arch.Class, archName)
	}
	out := make([]byte, segmentOffset+len(payload))
	copy(out[segmentOffset:], payload)
	copy(out[0:4], []byte{0x7f, 'E', 'L', 'F'})
	out[4] = arch.Class
	out[5] = arch.Data
	out[6] = 1 // EV_CURRENT
	putELFHeader(out, order, arch, entry, uint64(elfHeaderSize), uint16(programHeaderSize), 1)
	putProgramHeader(out[elfHeaderSize:elfHeaderSize+programHeaderSize], order, arch, segmentOffset, pageSize, uint64(len(payload)))
	return out, nil
}

func putELFHeader(out []byte, order binary.ByteOrder, arch elfArch, entry, phoff uint64, phentsize, phnum uint16) {
	order.PutUint16(out[16:], 2) // ET_EXEC
	order.PutUint16(out[18:], arch.Machine)
	order.PutUint32(out[20:], 1) // EV_CURRENT
	if arch.Class == 1 {
		order.PutUint32(out[24:], uint32(entry))
		order.PutUint32(out[28:], uint32(phoff))
		order.PutUint32(out[32:], 0) // e_shoff: omitted
		order.PutUint32(out[36:], arch.Flags)
		order.PutUint16(out[40:], 52)
		order.PutUint16(out[42:], phentsize)
		order.PutUint16(out[44:], phnum)
		return
	}
	order.PutUint64(out[24:], entry)
	order.PutUint64(out[32:], phoff)
	order.PutUint64(out[40:], 0) // e_shoff: omitted
	order.PutUint32(out[48:], arch.Flags)
	order.PutUint16(out[52:], 64)
	order.PutUint16(out[54:], phentsize)
	order.PutUint16(out[56:], phnum)
}

func putProgramHeader(out []byte, order binary.ByteOrder, arch elfArch, segmentOffset, pageSize uint64, payloadSize uint64) {
	const (
		ptLoad = 1
		flags  = 0x7
	)
	if arch.Class == 1 {
		order.PutUint32(out[0:], ptLoad)
		order.PutUint32(out[4:], uint32(segmentOffset))
		order.PutUint32(out[8:], uint32(arch.BaseVaddr))
		order.PutUint32(out[12:], uint32(arch.BaseVaddr))
		order.PutUint32(out[16:], uint32(payloadSize))
		order.PutUint32(out[20:], uint32(payloadSize))
		order.PutUint32(out[24:], flags)
		order.PutUint32(out[28:], uint32(pageSize))
		return
	}
	order.PutUint32(out[0:], ptLoad)
	order.PutUint32(out[4:], flags)
	order.PutUint64(out[8:], segmentOffset)
	order.PutUint64(out[16:], arch.BaseVaddr)
	order.PutUint64(out[24:], arch.BaseVaddr)
	order.PutUint64(out[32:], payloadSize)
	order.PutUint64(out[40:], payloadSize)
	order.PutUint64(out[48:], pageSize)
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
