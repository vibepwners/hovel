// Command squatter-provider is the Hovel payload_provider module for Squatter.
//
// This scaffold exposes the provider RPC shape and placeholder metadata without
// implementing a real listener, SMB named-pipe transport, or Windows agent.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

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
	body := []byte("squatter placeholder payload: nonfunctional scaffold\n")
	sum := sha256.Sum256(body)
	artifact := hovel.PayloadArtifact{
		Name:     "squatter-placeholder.exe",
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
