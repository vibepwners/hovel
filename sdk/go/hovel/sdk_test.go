package hovel

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	shutdownBarrierObservationWindow = 50 * time.Millisecond
	testRPCResponseTimeout           = time.Second
)

func TestAdvancedCredentialStampContractUsesCanonicalWireTypes(t *testing.T) {
	request := CredentialStampRequest{
		AssignmentID: "assignment-1",
		Capability:   CredentialDeliveryStampAdvanced,
		SlotName:     "tls-server",
		Target: CredentialStampTarget{
			Kind: CredentialStampTargetBytePattern,
			BytePattern: &CredentialBytePatternTarget{
				Pattern:         []byte{0xaa, 0xbb},
				Mask:            []byte{0xff, 0x0f},
				Occurrence:      1,
				MaximumLength:   CredentialCanonicalUint64("18446744073709551615"),
				RemainderPolicy: CredentialStampRemainderZeroFill,
				Precondition: CredentialStampPrecondition{
					Kind:   CredentialStampPreconditionSHA256,
					SHA256: strings.Repeat("0", 64),
					Length: "2",
				},
			},
		},
		Material: CredentialStampMaterial{
			Projection: CredentialProjectionBundle,
			Credential: &CredentialMaterialReference{
				Projection: CredentialProjectionBundle,
				Form:       CredentialMaterialPrivateBytes,
				BundleID:   "bundle-1",
			},
		},
		EncodedBytes: 4096,
		Credential: ResolvedCredentialMetadata{
			BundleVersion:         "hovel.pki.bundle/v1",
			Purpose:               CredentialPurposeTLSServer,
			ConsumerType:          CredentialConsumerMeshProvider,
			ProfileID:             "tls-server",
			CompatibilityTargetID: "mbedtls-3",
		},
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	target := wire["target"].(map[string]any)
	pattern := target["bytePattern"].(map[string]any)
	if pattern["maximumLength"] != "18446744073709551615" ||
		pattern["pattern"] != base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb}) {
		t.Fatalf("advanced stamp target = %#v", pattern)
	}
	material := wire["material"].(map[string]any)
	credential := material["credential"].(map[string]any)
	if credential["bundleId"] != "bundle-1" {
		t.Fatalf("stamp material = %#v", material)
	}
}

// fakeModule is a survey-style module that also opens a shell session so a
// single round-trip test can exercise handshake, schema, execute, and sessions.
type fakeModule struct{ withSession bool }

func (fakeModule) Info() Info {
	return Info{
		Name:    "fake",
		Version: "v0.0.0-test",
		Type:    TypeSurvey,
		Summary: "fake module",
		Tags:    []string{"example", "test"},
	}
}

func (fakeModule) Schema() Schema {
	return Schema{
		TargetConfig: []Requirement{Req("target.host", "host", "Target host.")},
	}
}

func (m fakeModule) Run(ctx *Context) (Result, error) {
	ctx.Log.Info("running", "target", ctx.Target)
	host := ctx.InputString("target.host", ctx.Target)
	if m.withSession {
		shell := &fakeCommandSession{LineShellSession: &LineShellSession{Prompt: "mock$ ", Echo: true, Handle: func(command string) (string, error) {
			if command == "whoami" {
				return "mock-operator", nil
			}
			return "unknown: " + command, nil
		}}}
		ref, err := ctx.OpenSession(shell, WithName("mock shell"), WithCapabilities("read", "write", "exec", "close"))
		if err != nil {
			return Result{}, err
		}
		return Ok(map[string]any{"sessionId": ref.ID}, WithSummary("opened session")), nil
	}
	return Ok(
		map[string]any{"facts": map[string]any{"host": host, "reachable": true}},
		WithSummary(fmt.Sprintf("surveyed %s", host)),
		WithFindings(Finding{Title: "reachable", Severity: "info"}),
		WithArtifacts(TextArtifact("note.txt", "hi")),
	), nil
}

type missingVersionModule struct{}

func (missingVersionModule) Info() Info {
	return Info{Name: "missing-version", Type: TypeSurvey}
}

func (missingVersionModule) Schema() Schema { return Schema{} }

func (missingVersionModule) Run(*Context) (Result, error) { return Ok(nil), nil }

type fakeCommandSession struct {
	*LineShellSession
}

type failingOpenSession struct {
	closeCalls int
}

func (*failingOpenSession) Open() error { return errors.New("open failed") }

func (*failingOpenSession) Write([]byte) error { return nil }

func (*failingOpenSession) Read(time.Duration) ([]byte, error) { return nil, nil }

func (s *failingOpenSession) Close(string) error {
	s.closeCalls++
	return nil
}

func (*failingOpenSession) Closed() bool { return false }

func (s *fakeCommandSession) ListPayloadCommands(PayloadCommandListRequest) ([]PayloadCommand, error) {
	return []PayloadCommand{{Name: "session.info", Summary: "return mock session facts", ReadOnly: true}}, nil
}

func (s *fakeCommandSession) RunPayloadCommand(req PayloadCommandRequest) (PayloadCommandResult, error) {
	return PayloadCommandResult{
		Command: req.Command,
		Summary: "session command completed",
		Stdout:  "mock session info",
		Fields:  map[string]string{"args": strings.Join(req.Args, ",")},
	}, nil
}

type fakePayloadProvider struct{}

func (fakePayloadProvider) Info() Info {
	return Info{
		Name:    "fake-payload",
		Version: "v0.0.0-test",
		Type:    TypePayloadProvider,
		Summary: "fake payload provider",
		Tags:    []string{"test", "payload_provider"},
	}
}

func (fakePayloadProvider) Schema() Schema {
	return Schema{
		ChainConfig: []Requirement{Req("payload.transport", "enum", "Payload transport.")},
	}
}

func (fakePayloadProvider) Run(*Context) (Result, error) {
	return Ok(map[string]any{"status": "not-used"}, WithSummary("payload provider execute placeholder")), nil
}

type fakeContextModule struct{}

func (fakeContextModule) Info() Info {
	return Info{
		Name:    "fake-context",
		Version: "v0.0.0-test",
		Type:    TypeSurvey,
		DiscoveryContext: ModuleContext{
			Summary:  "Find SMB exposure",
			Keywords: []string{"ms17-010"},
		},
	}
}

func (fakeContextModule) Schema() Schema {
	return Schema{
		PlanningContext: ModuleContext{Risk: RiskContext{Level: "low"}},
	}
}

func (fakeContextModule) Run(*Context) (Result, error) { return Ok(nil), nil }

func (fakePayloadProvider) ListPayloads(PayloadQuery) ([]PayloadInfo, error) {
	return []PayloadInfo{fakePayloadInfo()}, nil
}

func (fakePayloadProvider) ResolvePayload(PayloadQuery) (PayloadInfo, error) {
	return fakePayloadInfo(), nil
}

func (fakePayloadProvider) PrepareListener(req PrepareListenerRequest) (ListenerRef, error) {
	return ListenerRef{ID: "listener-1", RunID: req.RunID, Target: req.Target, Transport: "reverse-tcp", Host: "127.0.0.1", Port: 4444, State: "listening"}, nil
}

func (fakePayloadProvider) GeneratePayload(GeneratePayloadRequest) (PayloadArtifactSet, error) {
	artifact := PayloadArtifact{Name: "fake.exe", Role: "primary", Kind: string(PayloadKindPE), Format: PayloadFormatPEEXE, OS: "windows", Arch: "x86", Tags: []string{"native", "test"}, Encoding: "base64", Bytes: base64.StdEncoding.EncodeToString([]byte("fake"))}
	return PayloadArtifactSet{Primary: artifact, Artifacts: []PayloadArtifact{artifact}}, nil
}

func (fakePayloadProvider) ConnectSession(req ConnectSessionRequest) (SessionRef, error) {
	return SessionRef{ID: "session-1", RunID: req.RunID, Target: req.Target, Kind: "agent", State: "pending", Transport: "squatter/smb-named-pipe", InstalledPayloadID: req.InstalledPayloadID, Capabilities: []string{"read", "write"}}, nil
}

func (fakePayloadProvider) CleanupPayload(CleanupPayloadRequest) (CleanupResult, error) {
	return CleanupResult{Status: "ok"}, nil
}

func (fakePayloadProvider) ReadPayloadChunk(req ReadPayloadChunkRequest) (PayloadChunk, error) {
	return PayloadChunk{Handle: req.Handle, Offset: req.Offset, Data: base64.StdEncoding.EncodeToString([]byte("chunk")), EOF: true, Encoding: "base64"}, nil
}

type fakeStepModule struct{}

func (fakeStepModule) Info() Info {
	return Info{Name: "fake-step", Version: "v0.0.0-test", Type: TypePayloadProvider}
}

func (fakeStepModule) Schema() Schema { return Schema{} }

func (fakeStepModule) Run(*Context) (Result, error) {
	return Ok(nil, WithSummary("not used")), nil
}

func (fakeStepModule) DescribeSteps() (StepContractSet, error) {
	return StepContractSet{Steps: []StepContract{{
		ID:           "squatter.connect_smb",
		Kind:         "session.connector",
		ConfigSchema: map[string]any{"type": "object"},
		Requires: []CapabilityRequirement{
			{
				Type:          CapabilityPayloadInstance,
				SchemaVersion: "v1",
				Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
				States:        []string{"installed", "disconnected", "unreachable"},
			},
			{
				Type:          CapabilityCredential,
				SchemaVersion: "v1",
				Attributes:    map[string]any{"protocol": "smb"},
				States:        []string{"active"},
			},
		},
		Produces: []CapabilityRequirement{{
			Type:          CapabilitySessionRef,
			SchemaVersion: "v1",
			Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
		}},
		Prepare: StepPrepareContract{Materializes: []string{}},
	}}, Version: "contracts-v1"}, nil
}

func (fakeStepModule) PrepareStep(req StepPrepareRequest) (StepPrepareResult, error) {
	return StepPrepareResult{
		PlannedOutputs: []Capability{{
			ID:             "cap_credential_6mb8pq",
			Type:           CapabilityCredential,
			SchemaVersion:  "v1",
			State:          "planned",
			ProducerStepID: req.StepID,
			Attributes: map[string]any{
				"protocol":  "smb",
				"username":  "m7q4z92d",
				"password":  "plain-high-entropy-password",
				"sensitive": true,
			},
		}},
		PreparedValues: map[string]PreparedValue{
			"username": {Value: "m7q4z92d", Editable: true},
			"password": {Value: "plain-high-entropy-password", Editable: true},
		},
		OperatorSummary: OperatorSummary{TargetSideArtifacts: []string{"local admin user m7q4z92d"}},
	}, nil
}

func (fakeStepModule) ExecuteStep(req StepExecuteRequest) (StepExecuteResult, error) {
	return StepExecuteResult{
		Status: "succeeded",
		Capabilities: []Capability{{
			ID:             "cap_session_q8m2v4",
			Type:           CapabilitySessionRef,
			SchemaVersion:  "v1",
			State:          "connected",
			ProducerStepID: req.StepID,
			Attributes:     map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
		}},
		Evidence: []Evidence{{ID: "ev_connected", Level: "info", Kind: "session.connected", SourceStepID: req.StepID, Message: "connected"}},
		InstalledPayloads: []InstalledPayloadDescriptor{{
			Provider:                 "fake-step",
			PayloadID:                "fake/windows/x86/tcp-bind/pe-exe",
			PayloadVersion:           "v0.0.0-test",
			Target:                   "target-1",
			State:                    "installed",
			Transport:                "tcp-bind",
			Endpoint:                 "target-1:9101",
			InstanceKey:              "fake-step:target-1:9101",
			SupportsReconnect:        true,
			SupportsMultipleSessions: true,
			Reconnect: &PayloadProviderRecord{
				ProviderID:    "fake-step",
				Schema:        "fake.reconnect",
				SchemaVersion: "v1",
				Descriptor:    map[string]any{"host": "target-1", "port": float64(9101)},
			},
		}},
	}, nil
}

func (fakeStepModule) CleanupStep(StepCleanupRequest) (StepCleanupResult, error) {
	return StepCleanupResult{Status: "cleanup_verified"}, nil
}

type agentAwareModule struct{}

func (agentAwareModule) Info() Info {
	return Info{Name: "agent-aware", Version: "v0.0.0-test", Type: TypeSurvey, Summary: "agent aware"}
}

func (agentAwareModule) Schema() Schema { return Schema{} }

func (agentAwareModule) Run(ctx *Context) (Result, error) {
	if ctx.Agent == nil {
		return Ok(map[string]any{"agentPresent": false}, WithSummary("agent absent")), nil
	}
	return Ok(
		map[string]any{
			"agentPresent": true,
			"entityID":     ctx.Agent.Entity.ID,
			"entityKind":   ctx.Agent.Entity.Kind,
			"phase":        ctx.Agent.Phase,
		},
		WithSummary("agent present"),
		WithAgentHints(AgentHint{
			Schema:   "hovel.agent_hint.v1",
			Phase:    "execute",
			Audience: "assistant",
			Risk:     "low",
			Text:     "Prefer read-only inspection before changing state.",
			Provenance: map[string]string{
				"moduleId": "agent-aware@v0.0.0-test",
			},
		}),
	), nil
}

type fakeMeshModule struct{}

func (fakeMeshModule) Info() Info {
	return Info{
		Name:    "fake-mesh",
		Version: "v0.0.0-test",
		Type:    TypePayloadProvider,
		Summary: "fake node mesh",
		Tags:    []string{"test", "mesh"},
	}
}

func (fakeMeshModule) Schema() Schema {
	return Schema{}
}

func (fakeMeshModule) Run(*Context) (Result, error) {
	return Ok(nil, WithSummary("mesh provider execute placeholder")), nil
}

func fakeCredentialDeliveryDescriptor() CredentialDeliveryDescriptor {
	return CredentialDeliveryDescriptor{
		SchemaVersion: CredentialDeliverySchemaV1,
		Capabilities: []CredentialDeliveryCapability{
			CredentialDeliveryRuntime,
			CredentialDeliveryStampStandard,
		},
		Slots: []CredentialSlot{{
			Name:                         "control-plane-mtls",
			Purpose:                      CredentialPurposeMTLSServer,
			EndpointRole:                 CredentialEndpointServer,
			ConsumerType:                 CredentialConsumerMeshListener,
			AcceptedBundleVersions:       []string{"hovel.pki.bundle/v1"},
			AcceptedProfiles:             []string{"mtls-server"},
			AcceptedCompatibilityTargets: []string{"portable-x509"},
			AcceptedProjections:          []CredentialProjection{CredentialProjectionBundle},
			AcceptedMaterialForms:        []CredentialMaterialForm{CredentialMaterialPrivateBytes},
			MaximumEncodedBytes:          16 * 1024,
			RemainderPolicy:              CredentialStampRemainderPreserve,
			PrivateMaterial:              CredentialPrivateMaterialAllowed,
		}},
		StampTargetKinds: []CredentialStampTargetKind{CredentialStampTargetNamedSlot},
	}
}

func (fakeMeshModule) DescribeCredentialDelivery() (CredentialDeliveryDescriptor, error) {
	return fakeCredentialDeliveryDescriptor(), nil
}

func (fakeMeshModule) DescribeMesh(MeshDescribeRequest) (MeshDescriptor, error) {
	topology := fakeMeshTopology(true)
	credentialDelivery := fakeCredentialDeliveryDescriptor()
	return MeshDescriptor{
		Name:    "fake-mesh",
		Version: "v0.0.0-test",
		Summary: "tree-routed test mesh",
		Capabilities: []string{
			"topology.tree",
			"task.survey",
			"task.command",
			"stream.tcp",
		},
		Topology:           &topology,
		CredentialDelivery: &credentialDelivery,
		Tasks: []MeshTaskSpec{
			{
				Kind:         MeshTaskSurvey,
				Summary:      "survey a mesh node",
				ReadOnly:     true,
				TargetScopes: []MeshTargetScope{MeshTargetNode},
			},
			{
				Kind:         MeshTaskCommand,
				Summary:      "run a node command or routed destination command",
				TargetScopes: []MeshTargetScope{MeshTargetNode, MeshTargetDestination},
			},
			{
				Kind:         MeshTaskUploadExecute,
				Summary:      "upload and execute a file",
				Destructive:  true,
				TargetScopes: []MeshTargetScope{MeshTargetNode, MeshTargetDestination},
			},
		},
		ListenerTypes: []MeshListenerSpec{{
			Kind:            "https",
			Summary:         "HTTPS rendezvous listener",
			Deployments:     []MeshListenerDeployment{MeshListenerDeploymentEmbedded, MeshListenerDeploymentSeparate},
			ManagementModes: []MeshListenerManagement{MeshListenerManagementProvider, MeshListenerManagementExternal},
			Protocols:       []string{"https"},
			ConfigSchema:    map[string]any{"type": "object"},
		}},
		Triggers: []MeshTrigger{{
			ID:         "trig-beacon-command",
			Kind:       "beacon",
			NodeID:     "node-2",
			ListenerID: "listener-primary",
			State:      "armed",
			ActionKind: MeshTaskCommand,
		}},
	}, nil
}

func (fakeMeshModule) MeshTopology(req MeshTopologyRequest) (MeshTopology, error) {
	return fakeMeshTopology(req.IncludeRoutes), nil
}

func (fakeMeshModule) ListMeshBeacons(req MeshBeaconRequest) ([]MeshBeacon, error) {
	nodeID := req.NodeID
	if nodeID == "" {
		nodeID = "node-2"
	}
	return []MeshBeacon{{
		ID:              "beacon-1",
		NodeID:          nodeID,
		ListenerID:      "listener-primary",
		Time:            "2026-07-09T00:00:00Z",
		State:           "alive",
		Transport:       "relay",
		RemoteAddr:      "10.0.0.2:4444",
		IntervalSeconds: 30,
		Fields:          map[string]any{"route": "root>node-1>node-2"},
	}}, nil
}

func (fakeMeshModule) ListMeshListeners(req MeshListenerListRequest) ([]MeshListener, error) {
	listenerID := req.ListenerID
	if listenerID == "" {
		listenerID = "listener-primary"
	}
	return []MeshListener{{
		ID:         listenerID,
		Name:       "primary HTTPS listener",
		Kind:       "https",
		State:      MeshListenerStateActive,
		Deployment: MeshListenerDeploymentSeparate,
		Management: MeshListenerManagementProvider,
		Addresses:  []string{"https://127.0.0.1:8443"},
		Protocols:  []string{"https"},
	}}, nil
}

type emptyMeshListenerModule struct {
	fakeMeshModule
}

func (emptyMeshListenerModule) ListMeshListeners(MeshListenerListRequest) ([]MeshListener, error) {
	return nil, nil
}

func (fakeMeshModule) StartMeshListener(req MeshListenerStartRequest) (MeshListener, error) {
	return MeshListener{
		ID:         req.ListenerID,
		Name:       req.Name,
		Kind:       req.Kind,
		State:      MeshListenerStateActive,
		Deployment: req.Deployment,
		Management: req.Management,
		Addresses:  []string{"https://127.0.0.1:8443"},
		Protocols:  []string{"https"},
	}, nil
}

func (fakeMeshModule) StopMeshListener(req MeshListenerStopRequest) (MeshListener, error) {
	return MeshListener{
		ID:         req.ListenerID,
		State:      MeshListenerStateStopped,
		Deployment: MeshListenerDeploymentSeparate,
		Management: MeshListenerManagementProvider,
	}, nil
}

func (fakeMeshModule) LoadRuntimeCredential(
	req CredentialRuntimeRequest,
) (CredentialDeliveryReceipt, error) {
	return CredentialDeliveryReceipt{
		RequestID:         req.RequestID,
		ProviderReference: "runtime-loaded",
	}, nil
}

func (fakeMeshModule) LoadCredentialFiles(
	req CredentialFilesRequest,
) (CredentialDeliveryReceipt, error) {
	return CredentialDeliveryReceipt{
		RequestID:         req.RequestID,
		ProviderReference: "files-loaded",
	}, nil
}

func (fakeMeshModule) EncodeCredentialMaterial(
	req CredentialEncodingRequest,
) (CredentialEncodingResult, error) {
	return CredentialEncodingResult{
		RequestID: req.RequestID,
		Form:      req.OutputForm,
		Encoding:  "provider-test",
		SHA256:    strings.Repeat("1", 64),
		Data:      CredentialBytes("encoded"),
	}, nil
}

func (fakeMeshModule) StampCredential(
	req CredentialStampExecutionRequest,
) (CredentialStampExecutionResult, error) {
	content, err := NewCredentialArtifactData([]byte("stamped"))
	if err != nil {
		return CredentialStampExecutionResult{}, err
	}
	output, err := NewCredentialStampArtifactOutput(CredentialArtifactOutput{
		Name: "stamped.bin", Encoding: "raw", Content: content,
	})
	if err != nil {
		return CredentialStampExecutionResult{}, err
	}
	return CredentialStampExecutionResult{
		StampID:          req.StampID,
		Output:           output,
		TargetResolution: CredentialStampTargetUnchanged,
		ResolvedTarget:   req.Request.Target,
		BytesWritten:     CredentialCanonicalUint64(strconv.FormatUint(req.Request.EncodedBytes, 10)),
		MaterialDigests:  append([]CredentialStampedMaterialDigest(nil), req.ExpectedDigests...),
	}, nil
}

func (fakeMeshModule) RunMeshTask(ctx *MeshContext, req MeshTaskRequest) (MeshTaskResult, error) {
	ctx.Log.Info("mesh task", "kind", req.Kind, "node", req.NodeID)
	switch req.Kind {
	case MeshTaskSurvey:
		return MeshTaskResult{
			TaskID:     req.TaskID,
			Status:     MeshTaskStatusSucceeded,
			Summary:    "surveyed " + req.NodeID,
			NodeID:     req.NodeID,
			ListenerID: req.ListenerID,
			Outputs: map[string]any{
				"os":              "linux",
				"reachable":       true,
				"contextRunId":    ctx.RunID,
				"contextModuleId": ctx.ModuleID,
				"contextTarget":   ctx.Target,
			},
			Findings: []Finding{{Title: "node reachable", Severity: "info", Detail: req.NodeID}},
		}, nil
	case MeshTaskCommand:
		return MeshTaskResult{
			TaskID:          req.TaskID,
			Status:          MeshTaskStatusSucceeded,
			Summary:         "command completed",
			NodeID:          req.NodeID,
			ListenerID:      req.ListenerID,
			DestinationHost: req.DestinationHost,
			DestinationPort: req.DestinationPort,
			Protocol:        req.Protocol,
			Outputs:         map[string]any{"stdout": strings.Join(req.Args, " ")},
		}, nil
	default:
		return MeshTaskResult{
			TaskID:  req.TaskID,
			Status:  MeshTaskStatusFailed,
			Summary: "unsupported mesh task",
			NodeID:  req.NodeID,
		}, nil
	}
}

func (fakeMeshModule) OpenMeshStream(ctx *MeshContext, req MeshStreamRequest) (SessionRef, error) {
	shell := &LineShellSession{
		Prompt: "mesh$ ",
		Echo:   true,
		Handle: func(command string) (string, error) {
			return "routed " + command + " to " + req.DestinationHost, nil
		},
	}
	return ctx.OpenSession(
		shell,
		WithName("mesh stream to "+req.DestinationHost),
		WithKind("stream"),
		WithTransport("mesh-route"),
		WithCapabilities("read", "write", "close", "stream.tcp"),
	)
}

type emptyStatusMeshModule struct {
	fakeMeshModule
}

func (emptyStatusMeshModule) RunMeshTask(_ *MeshContext, req MeshTaskRequest) (MeshTaskResult, error) {
	return MeshTaskResult{
		TaskID:  req.TaskID,
		Status:  "   ",
		Summary: "completed without an explicit status",
	}, nil
}

type streamOnlyMeshModule struct{}

func (streamOnlyMeshModule) Info() Info {
	return Info{
		Name:    "stream-only-mesh",
		Version: "v0.0.0-test",
		Type:    TypePayloadProvider,
		Summary: "minimal stream mesh",
		Tags:    []string{"mesh"},
	}
}

func (streamOnlyMeshModule) Schema() Schema {
	return Schema{}
}

func (streamOnlyMeshModule) Run(*Context) (Result, error) {
	return Ok(nil, WithSummary("not used")), nil
}

func (streamOnlyMeshModule) DescribeMesh(MeshDescribeRequest) (MeshDescriptor, error) {
	return MeshDescriptor{
		Name:         "stream-only-mesh",
		Version:      "v0.0.0-test",
		Summary:      "one stream operation, no task or beacon surface",
		Capabilities: []string{"stream.tcp"},
		Tasks: []MeshTaskSpec{{
			Kind:         MeshTaskStream,
			Summary:      "open one routed TCP stream",
			OpensStream:  true,
			TargetScopes: []MeshTargetScope{MeshTargetDestination},
		}},
	}, nil
}

func (streamOnlyMeshModule) OpenMeshStream(ctx *MeshContext, req MeshStreamRequest) (SessionRef, error) {
	return ctx.OpenSession(
		&LineShellSession{Prompt: "stream$ ", Echo: true},
		WithName("minimal stream to "+req.DestinationHost),
		WithKind("stream"),
		WithTransport("mesh-stream"),
		WithCapabilities("read", "write", "close"),
	)
}

type shutdownBarrierMeshModule struct {
	fakeMeshModule
	started chan struct{}
	release chan struct{}
	session *shutdownTrackingSession
}

func (m shutdownBarrierMeshModule) RunMeshTask(ctx *MeshContext, _ MeshTaskRequest) (MeshTaskResult, error) {
	close(m.started)
	<-m.release
	ref, err := ctx.OpenSession(m.session)
	if err != nil {
		return MeshTaskResult{}, err
	}
	return MeshTaskResult{Status: MeshTaskStatusSucceeded, Sessions: []SessionRef{ref}}, nil
}

type shutdownTrackingSession struct {
	closed chan struct{}
}

func (*shutdownTrackingSession) Open() error { return nil }

func (*shutdownTrackingSession) Write([]byte) error { return nil }

func (*shutdownTrackingSession) Read(time.Duration) ([]byte, error) { return nil, nil }

func (s *shutdownTrackingSession) Close(string) error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func (s *shutdownTrackingSession) Closed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func fakeMeshTopology(includeRoutes bool) MeshTopology {
	topology := MeshTopology{
		Root: "root",
		Nodes: []MeshNode{
			{ID: "root", Name: "controller", Kind: "controller", State: "online"},
			{ID: "node-1", ParentID: "root", Name: "relay", Kind: "relay", State: "online"},
			{ID: "node-2", ParentID: "node-1", Name: "leaf", Kind: "agent", State: "online"},
		},
		Links: []MeshLink{
			{
				ID:     "link-root-node-1",
				Source: "root",
				Target: "node-1",
				Kind:   "relay",
				State:  "up",
			},
			{
				ID:     "link-node-1-node-2",
				Source: "node-1",
				Target: "node-2",
				Kind:   "relay",
				State:  "up",
			},
		},
	}
	if includeRoutes {
		topology.Routes = []MeshRoute{{
			ID:    "route-node-2",
			Nodes: []string{"root", "node-1", "node-2"},
			Links: []string{"link-root-node-1", "link-node-1-node-2"},
		}}
	}
	return topology
}

func fakePayloadInfo() PayloadInfo {
	return PayloadInfo{
		ID:           "fake/windows/x86/reverse-tcp/pe-exe",
		Name:         "fake",
		Version:      "v0.0.0-test",
		Kind:         string(PayloadKindPE),
		Platform:     "windows",
		OS:           "windows",
		Arch:         "x86",
		MinOS:        "windows-xp-sp3",
		TestedOS:     []string{"windows-xp-sp3"},
		Formats:      []string{PayloadFormatPEEXE, PayloadFormatPE},
		Tags:         []string{"native", "test"},
		Capabilities: []string{"file.get"},
		Transport:    PayloadTransport{Kind: "reverse-tcp"},
		Session:      PayloadSession{Kind: "agent", Acquisition: "callback", RequiresPreThrowListener: true, Owner: "payload_provider"},
	}
}

func TestServeMeshProviderMethods(t *testing.T) {
	conn := newRPCConn(t, fakeMeshModule{})
	defer conn.close()

	describe := conn.call("mesh.describe", nil)
	if describe["name"] != "fake-mesh" {
		t.Fatalf("mesh.describe = %#v", describe)
	}
	tasks, _ := describe["tasks"].([]any)
	if len(tasks) != 3 {
		t.Fatalf("mesh tasks = %#v, want three common task specs", describe["tasks"])
	}
	uploadExecute, _ := tasks[2].(map[string]any)
	targetScopes, _ := uploadExecute["targetScopes"].([]any)
	if len(targetScopes) != 2 || targetScopes[1] != string(MeshTargetDestination) {
		t.Fatalf("mesh upload_execute target scopes = %#v", targetScopes)
	}
	triggers, _ := describe["triggers"].([]any)
	if len(triggers) != 1 {
		t.Fatalf("mesh triggers = %#v, want one trigger", describe["triggers"])
	}
	listenerTypes, _ := describe["listenerTypes"].([]any)
	if len(listenerTypes) != 1 {
		t.Fatalf("mesh listener types = %#v, want one", describe["listenerTypes"])
	}
	credentialDelivery, _ := describe["credentialDelivery"].(map[string]any)
	if credentialDelivery["schemaVersion"] != CredentialDeliverySchemaV1 {
		t.Fatalf("mesh credential delivery descriptor = %#v", credentialDelivery)
	}
	deliveryCapabilities, _ := credentialDelivery["deliveryCapabilities"].([]any)
	if len(deliveryCapabilities) != 2 || deliveryCapabilities[1] != string(CredentialDeliveryStampStandard) {
		t.Fatalf("mesh credential delivery capabilities = %#v", deliveryCapabilities)
	}

	topology := conn.call("mesh.topology", map[string]any{"includeRoutes": true})
	nodes, _ := topology["nodes"].([]any)
	links, _ := topology["links"].([]any)
	routes, _ := topology["routes"].([]any)
	if len(nodes) != 3 || len(links) != 2 || len(routes) != 1 {
		t.Fatalf("mesh topology = %#v", topology)
	}

	beacons := conn.call("mesh.beacons", map[string]any{"nodeId": "node-2"})
	items, _ := beacons["beacons"].([]any)
	if len(items) != 1 {
		t.Fatalf("mesh beacons = %#v, want one", beacons["beacons"])
	}
	beacon, _ := items[0].(map[string]any)
	if beacon["nodeId"] != "node-2" || beacon["listenerId"] != "listener-primary" || beacon["state"] != "alive" {
		t.Fatalf("mesh beacon = %#v", beacon)
	}

	listeners := conn.call("mesh.listeners", map[string]any{
		"listenerId": "  listener-primary  ",
		"state":      "  active  ",
	})
	listenerItems, _ := listeners["listeners"].([]any)
	if len(listenerItems) != 1 {
		t.Fatalf("mesh listeners = %#v, want one", listeners["listeners"])
	}
	listener, _ := listenerItems[0].(map[string]any)
	if listener["id"] != "listener-primary" || listener["state"] != "active" ||
		listener["deployment"] != "separate" || listener["management"] != "provider" {
		t.Fatalf("mesh listener = %#v", listener)
	}

	startedListener := conn.call("mesh.listener.start", map[string]any{
		"listenerId": "listener-web",
		"name":       "web-controlled listener",
		"kind":       "https",
		"deployment": "  separate  ",
		"management": "  provider  ",
		"config":     map[string]any{"token": "write-only-secret"},
	})
	if startedListener["id"] != "listener-web" || startedListener["state"] != "active" ||
		startedListener["deployment"] != "separate" || startedListener["management"] != "provider" {
		t.Fatalf("started mesh listener = %#v", startedListener)
	}
	if _, exposesConfig := startedListener["config"]; exposesConfig {
		t.Fatalf("started mesh listener exposed write-only config: %#v", startedListener)
	}

	stoppedListener := conn.call("mesh.listener.stop", map[string]any{"listenerId": "listener-web"})
	if stoppedListener["id"] != "listener-web" || stoppedListener["state"] != "stopped" {
		t.Fatalf("stopped mesh listener = %#v", stoppedListener)
	}

	task := conn.call("mesh.task", map[string]any{
		"runId":      "run-mesh-1",
		"taskId":     "task-survey-1",
		"kind":       string(MeshTaskSurvey),
		"nodeId":     "node-2",
		"listenerId": "listener-primary",
	})
	if task["status"] != "succeeded" || task["summary"] != "surveyed node-2" {
		t.Fatalf("mesh task = %#v", task)
	}
	if task["listenerId"] != "listener-primary" {
		t.Fatalf("mesh task listener = %#v", task["listenerId"])
	}
	outputs, _ := task["outputs"].(map[string]any)
	if outputs["os"] != "linux" || outputs["reachable"] != true {
		t.Fatalf("mesh task outputs = %#v", outputs)
	}

	defaulted := conn.call("mesh.task", map[string]any{
		"runId":           " ",
		"moduleId":        " ",
		"target":          " ",
		"destinationHost": "10.10.0.99",
		"kind":            string(MeshTaskSurvey),
	})
	defaultedOutputs, _ := defaulted["outputs"].(map[string]any)
	if defaultedOutputs["contextRunId"] != "mesh" ||
		defaultedOutputs["contextModuleId"] != "fake-mesh@v0.0.0-test" ||
		defaultedOutputs["contextTarget"] != "10.10.0.99" {
		t.Fatalf("defaulted mesh context = %#v", defaultedOutputs)
	}
}

func TestServeCredentialProviderMethods(t *testing.T) {
	conn := newRPCConn(t, fakeMeshModule{})
	defer conn.close()

	descriptor := conn.call(credentialRPCDescribeMethod, map[string]any{})
	if descriptor["schemaVersion"] != CredentialDeliverySchemaV1 {
		t.Fatalf("credential.describe = %#v", descriptor)
	}

	credential := map[string]any{
		"bundleVersion":         "hovel.pki.bundle/v1",
		"purpose":               "mtls-server",
		"consumerType":          "mesh-listener",
		"profileId":             "mtls-server",
		"compatibilityTargetId": "portable-x509",
	}
	material := map[string]any{
		"projection": "bundle",
		"form":       "private-bytes",
		"encoding":   "hovel-bundle-json",
		"sha256":     strings.Repeat("0", 64),
		"data":       base64.StdEncoding.EncodeToString([]byte("private-bundle")),
	}
	provider := map[string]any{
		"moduleId":         "fake-mesh",
		"providerId":       "fake-mesh",
		"providerVersion":  "v1.0.0",
		"descriptorSha256": strings.Repeat("4", 64),
	}
	runtime := conn.call(credentialRPCRuntimeMethod, map[string]any{
		"schemaVersion": CredentialProviderExecutionSchemaV1,
		"provider":      provider,
		"requestId":     "delivery-runtime-1",
		"assignmentId":  "assignment-1",
		"slotName":      "control-plane-mtls",
		"credential":    credential,
		"material":      material,
		"scope":         map[string]any{"listenerId": "listener-primary"},
	})
	if runtime["requestId"] != "delivery-runtime-1" || runtime["providerReference"] != "runtime-loaded" {
		t.Fatalf("credential.runtime = %#v", runtime)
	}
	if _, leaksMaterial := runtime["material"]; leaksMaterial {
		t.Fatalf("credential.runtime echoed material: %#v", runtime)
	}

	files := conn.call(credentialRPCFilesMethod, map[string]any{
		"schemaVersion": CredentialProviderExecutionSchemaV1,
		"provider":      provider,
		"requestId":     "delivery-files-1",
		"assignmentId":  "assignment-1",
		"slotName":      "control-plane-mtls",
		"credential":    credential,
		"files": []any{map[string]any{
			"projection": "certificate-der",
			"form":       "public",
			"mediaType":  "application/pkix-cert",
			"path":       "/provider-input/certificate.der",
			"sha256":     strings.Repeat("1", 64),
			"size":       512,
		}},
		"scope": map[string]any{},
	})
	if files["requestId"] != "delivery-files-1" || files["providerReference"] != "files-loaded" {
		t.Fatalf("credential.files = %#v", files)
	}

	encoded := conn.call(credentialRPCEncodeMethod, map[string]any{
		"schemaVersion":       CredentialProviderExecutionSchemaV1,
		"provider":            provider,
		"requestId":           "encoding-1",
		"providerId":          "fake-mesh",
		"providerSchema":      "v1",
		"outputForm":          "private-bytes",
		"maximumEncodedBytes": 4096,
		"source":              material,
		"scope":               map[string]any{},
	})
	if encoded["requestId"] != "encoding-1" || encoded["data"] != base64.StdEncoding.EncodeToString([]byte("encoded")) {
		t.Fatalf("credential.encode = %#v", encoded)
	}

	stampRequest := map[string]any{
		"assignmentId": "assignment-1",
		"capability":   "stamp-standard",
		"slotName":     "control-plane-mtls",
		"target": map[string]any{
			"kind":      "named-slot",
			"namedSlot": map[string]any{"name": "control-plane-mtls"},
		},
		"material": map[string]any{
			"projection": "bundle",
			"credential": map[string]any{
				"projection": "bundle",
				"form":       "private-bytes",
				"bundleId":   "bundle-1",
			},
		},
		"encodedBytes": 14,
		"credential":   credential,
	}
	stamped := conn.call(credentialRPCStampMethod, map[string]any{
		"schemaVersion": CredentialProviderExecutionSchemaV1,
		"provider":      provider,
		"stampId":       "credential-stamp-1",
		"request":       stampRequest,
		"input": map[string]any{
			"id":       "artifact-1",
			"sha256":   strings.Repeat("3", 64),
			"encoding": "raw",
			"data":     base64.StdEncoding.EncodeToString([]byte("input")),
		},
		"resolvedMaterial": material,
		"expectedDigests": []map[string]any{{
			"projection": "bundle",
			"reference":  "bundle-1",
			"sha256":     strings.Repeat("2", 64),
		}},
		"scope": map[string]any{"runId": "run-1"},
	})
	if stamped["stampId"] != "credential-stamp-1" || stamped["targetResolution"] != "unchanged" ||
		stamped["bytesWritten"] != "14" {
		t.Fatalf("credential.stamp = %#v", stamped)
	}
	output := stamped["output"].(map[string]any)
	artifact := output["artifact"].(map[string]any)
	if artifact["data"] != base64.StdEncoding.EncodeToString([]byte("stamped")) {
		t.Fatalf("credential.stamp output = %#v", output)
	}
}

func TestCredentialProviderSecretsAreRedactedInDiagnostics(t *testing.T) {
	t.Parallel()

	value, err := NewCredentialMaterialReference(CredentialScopedReference{
		ProviderID: "hsm", Reference: CredentialSecretReference("capability-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewResolvedCredentialMaterial(
		CredentialProjectionSignerReference,
		CredentialMaterialPrivateReference,
		"provider-reference",
		strings.Repeat("a", 64),
		value,
	)
	if err != nil {
		t.Fatal(err)
	}
	file := CredentialFile{Path: CredentialProtectedPath("/secret/private-key.der")}
	for _, formatted := range []string{
		fmt.Sprintf("%#v", material),
		fmt.Sprintf("%#v", file),
		fmt.Sprintf("%#v", CredentialBytes("private-bytes")),
	} {
		for _, secret := range []string{"capability-secret", "/secret/private-key.der", "private-bytes"} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("credential diagnostic leaked %q: %s", secret, formatted)
			}
		}
	}
}

func TestResolvedCredentialMaterialRejectsInvalidUnionStates(t *testing.T) {
	t.Parallel()

	encoded := base64.StdEncoding.EncodeToString([]byte("material"))
	reference := map[string]any{"providerId": "hsm", "reference": "secret-reference"}
	tests := []struct {
		name    string
		form    string
		variant map[string]any
	}{
		{name: "neither variant", form: "private-bytes", variant: map[string]any{}},
		{
			name: "both variants", form: "private-bytes",
			variant: map[string]any{"data": encoded, "reference": reference},
		},
		{name: "reference form with bytes", form: "private-reference", variant: map[string]any{"data": encoded}},
		{name: "bytes form with reference", form: "private-bytes", variant: map[string]any{"reference": reference}},
		{name: "unknown form", form: "unknown", variant: map[string]any{"data": encoded}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := map[string]any{
				"projection": "bundle",
				"form":       test.form,
				"encoding":   "raw",
				"sha256":     strings.Repeat("0", 64),
			}
			for key, value := range test.variant {
				wire[key] = value
			}
			data, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var material ResolvedCredentialMaterial
			err = json.Unmarshal(data, &material)
			if !errors.Is(err, ErrCredentialMaterialVariant) {
				t.Fatalf("json.Unmarshal() error = %v, want %v", err, ErrCredentialMaterialVariant)
			}
		})
	}
	bytesValue, err := NewCredentialMaterialBytes([]byte("material"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolvedCredentialMaterial(
		CredentialProjectionBundle,
		CredentialMaterialPrivateReference,
		"raw",
		strings.Repeat("0", 64),
		bytesValue,
	); !errors.Is(err, ErrCredentialMaterialVariant) {
		t.Fatalf("NewResolvedCredentialMaterial() error = %v", err)
	}
}

func TestCredentialBytesRejectNoncanonicalBase64(t *testing.T) {
	t.Parallel()

	for _, encoded := range []string{"Zg", "Zg=", "Zh==", "Zg==\n", " Zg=="} {
		t.Run(fmt.Sprintf("%q", encoded), func(t *testing.T) {
			data, err := json.Marshal(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var decoded CredentialBytes
			if err := json.Unmarshal(data, &decoded); err == nil {
				t.Fatalf("json.Unmarshal() accepted noncanonical base64 %q", encoded)
			}
		})
	}
}

func TestCredentialArtifactRejectsInvalidUnionStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		variant map[string]any
	}{
		{name: "neither variant", variant: map[string]any{}},
		{
			name: "both variants",
			variant: map[string]any{
				"data": base64.StdEncoding.EncodeToString([]byte("artifact")),
				"path": "/protected/artifact.bin",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := map[string]any{
				"id":       "artifact-1",
				"sha256":   strings.Repeat("0", 64),
				"encoding": "raw",
			}
			for key, value := range test.variant {
				wire[key] = value
			}
			data, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var artifact CredentialArtifactInput
			err = json.Unmarshal(data, &artifact)
			if !errors.Is(err, ErrCredentialArtifactVariant) {
				t.Fatalf("json.Unmarshal() error = %v, want %v", err, ErrCredentialArtifactVariant)
			}
		})
	}
}

func TestCredentialArtifactOutputSerializesExactlyOneVariant(t *testing.T) {
	t.Parallel()

	dataContent, err := NewCredentialArtifactData([]byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	pathContent, err := NewCredentialArtifactPath("/protected/artifact.bin")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		content CredentialArtifactContent
		present string
		absent  string
	}{
		{name: "data", content: dataContent, present: "data", absent: "path"},
		{name: "path", content: pathContent, present: "path", absent: "data"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(CredentialArtifactOutput{
				Name: "artifact.bin", Encoding: "raw", Content: test.content,
			})
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			if _, ok := wire[test.present]; !ok {
				t.Fatalf("output %s missing %q: %#v", data, test.present, wire)
			}
			if _, ok := wire[test.absent]; ok {
				t.Fatalf("output %s unexpectedly contains %q: %#v", data, test.absent, wire)
			}
		})
	}
}

func TestCredentialStampOutputRejectsUnsetVariant(t *testing.T) {
	t.Parallel()

	_, err := json.Marshal(CredentialStampOutput{})
	if !errors.Is(err, ErrCredentialStampOutputVariant) {
		t.Fatalf("json.Marshal() error = %v, want %v", err, ErrCredentialStampOutputVariant)
	}
}

func TestCredentialStampOutputValidatesAndClonesNestedPayloads(t *testing.T) {
	t.Parallel()

	content, err := NewCredentialArtifactData([]byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCredentialStampArtifactOutput(CredentialArtifactOutput{
		Encoding: "raw", Content: content,
	}); !errors.Is(err, ErrCredentialStampOutputVariant) {
		t.Fatalf("NewCredentialStampArtifactOutput() error = %v", err)
	}
	if _, err := NewCredentialStampDeploymentOutput(CredentialDeploymentOutput{
		Reference: "deployment-1",
	}); !errors.Is(err, ErrCredentialStampOutputVariant) {
		t.Fatalf("NewCredentialStampDeploymentOutput() error = %v", err)
	}

	receipt := CredentialBytes("provider-receipt")
	output, err := NewCredentialStampDeploymentOutput(CredentialDeploymentOutput{
		Reference: "deployment-1", Receipt: receipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt[0] = 'X'
	deployment, ok := output.Deployment()
	if !ok || string(deployment.Receipt) != "provider-receipt" {
		t.Fatalf("deployment output = %#v, %v", deployment, ok)
	}
	deployment.Receipt[0] = 'X'
	cloned, ok := output.Deployment()
	if !ok || string(cloned.Receipt) != "provider-receipt" {
		t.Fatalf("deployment accessor retained receipt alias: %#v, %v", cloned, ok)
	}
}

func TestListMeshListenersEncodesEmptyListAsArray(t *testing.T) {
	server := server{module: emptyMeshListenerModule{}}

	result, err := server.listMeshListeners(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("listener response type = %T, want map[string]any", result)
	}
	listeners, ok := response["listeners"].([]MeshListener)
	if !ok || listeners == nil || len(listeners) != 0 {
		t.Fatalf("listeners = %#v, want non-nil empty array", response["listeners"])
	}
}

func TestServeMeshOpenStreamCreatesSession(t *testing.T) {
	conn := newRPCConn(t, fakeMeshModule{})
	defer conn.close()

	session := conn.call("mesh.open_stream", map[string]any{
		"runId":           "run-mesh-2",
		"moduleId":        "fake-mesh@v0.0.0-test",
		"target":          "mock://mesh",
		"nodeId":          "node-2",
		"destinationHost": "10.10.10.10",
		"destinationPort": 443,
		"protocol":        "tcp",
	})
	sessionID, _ := session["id"].(string)
	if sessionID == "" {
		t.Fatalf("mesh stream session = %#v", session)
	}
	if session["kind"] != "stream" || session["transport"] != "mesh-route" {
		t.Fatalf("mesh stream session metadata = %#v", session)
	}

	prompt := readSession(t, conn, sessionID)
	if !strings.Contains(prompt, "mesh$") {
		t.Fatalf("mesh stream prompt = %q", prompt)
	}

	conn.call("session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.0\n")),
	})
	output := readSession(t, conn, sessionID)
	if !strings.Contains(output, "routed GET / HTTP/1.0 to 10.10.10.10") {
		t.Fatalf("mesh stream output = %q", output)
	}
}

func TestServeMeshTaskDefaultsEmptyStatus(t *testing.T) {
	conn := newRPCConn(t, emptyStatusMeshModule{})
	defer conn.close()

	task := conn.call("mesh.task", map[string]any{
		"taskId": "task-default-status",
		"kind":   string(MeshTaskSurvey),
	})
	if task["status"] != string(MeshTaskStatusSucceeded) {
		t.Fatalf("mesh task status = %#v, want %q", task["status"], MeshTaskStatusSucceeded)
	}
}

func TestServeMeshProviderCanImplementOnlySupportedSurfaces(t *testing.T) {
	conn := newRPCConn(t, streamOnlyMeshModule{})
	defer conn.close()

	describe := conn.call("mesh.describe", nil)
	if describe["name"] != "stream-only-mesh" {
		t.Fatalf("mesh.describe = %#v", describe)
	}
	tasks, _ := describe["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("mesh tasks = %#v, want one stream task", describe["tasks"])
	}

	session := conn.call("mesh.open_stream", map[string]any{
		"runId":           "run-stream-only",
		"destinationHost": "10.10.10.10",
		"destinationPort": 443,
		"protocol":        "tcp",
	})
	if session["transport"] != "mesh-stream" {
		t.Fatalf("stream-only session = %#v", session)
	}

	errText := conn.callError("mesh.task", map[string]any{"kind": string(MeshTaskCommand)})
	if !strings.Contains(errText, "does not implement mesh.task") {
		t.Fatalf("mesh.task error = %q, want unsupported surface", errText)
	}

	errText = conn.callError("mesh.listeners", nil)
	if !strings.Contains(errText, "does not implement mesh.listeners") {
		t.Fatalf("mesh.listeners error = %q, want unsupported surface", errText)
	}
}

func TestServeShutdownWaitsForInFlightMeshTask(t *testing.T) {
	module := shutdownBarrierMeshModule{
		started: make(chan struct{}),
		release: make(chan struct{}),
		session: &shutdownTrackingSession{closed: make(chan struct{})},
	}
	conn := newRPCConn(t, module)
	conn.writeRequest(1, meshRPCTaskMethod, map[string]any{"runId": "run-1", "kind": MeshTaskCommand})
	select {
	case <-module.started:
	case <-time.After(testRPCResponseTimeout):
		t.Fatal("mesh task did not start")
	}
	conn.writeRequest(2, "shutdown", nil)

	responses := make(chan map[string]any, 2)
	go func() {
		for {
			message := conn.readFrame()
			id, ok := responseID(message)
			if !ok {
				continue
			}
			responses <- message
			if id == 2 {
				return
			}
		}
	}()
	select {
	case message := <-responses:
		t.Fatalf("shutdown responded before the in-flight mesh task completed: %#v", message)
	case <-time.After(shutdownBarrierObservationWindow):
	}

	close(module.release)
	seenShutdown := false
	for !seenShutdown {
		var message map[string]any
		select {
		case message = <-responses:
		case <-time.After(testRPCResponseTimeout):
			t.Fatal("timed out waiting for mesh task and shutdown responses")
		}
		id, ok := responseID(message)
		if ok && id == 2 {
			seenShutdown = true
		}
	}
	select {
	case <-module.session.closed:
	case <-time.After(testRPCResponseTimeout):
		t.Fatal("shutdown did not close the session opened by the in-flight mesh task")
	}
	if err := <-conn.done; err != nil {
		t.Fatalf("serve returned error: %v", err)
	}
	if err := conn.in.Close(); err != nil {
		t.Logf("close rpc input pipe: %v", err)
	}
}

func TestServeStepContractMethods(t *testing.T) {
	conn := newRPCConn(t, fakeStepModule{})
	defer conn.close()

	describe := conn.call("step.describe", nil)
	steps, _ := describe["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("steps = %#v, want one step", describe["steps"])
	}
	step, _ := steps[0].(map[string]any)
	if step["id"] != "squatter.connect_smb" {
		t.Fatalf("step id = %#v", step["id"])
	}
	requires, _ := step["requires"].([]any)
	if len(requires) != 2 {
		t.Fatalf("requires = %#v, want two requirements", step["requires"])
	}

	prepared := conn.call("step.prepare", map[string]any{
		"preparedPlanId": "prep-1",
		"stepId":         "windows.credential.create_local_admin",
	})
	values, _ := prepared["preparedValues"].(map[string]any)
	password, _ := values["password"].(map[string]any)
	if password["value"] != "plain-high-entropy-password" {
		t.Fatalf("prepared password = %#v", password["value"])
	}

	executed := conn.call("step.execute", map[string]any{"runId": "run-1", "stepId": "squatter.connect_smb"})
	if executed["status"] != "succeeded" {
		t.Fatalf("execute status = %#v", executed["status"])
	}
	installedPayloads, _ := executed["installedPayloads"].([]any)
	if len(installedPayloads) != 1 {
		t.Fatalf("installedPayloads = %#v, want one descriptor", executed["installedPayloads"])
	}
	installed, _ := installedPayloads[0].(map[string]any)
	if installed["provider"] != "fake-step" || installed["instanceKey"] != "fake-step:target-1:9101" {
		t.Fatalf("installed payload descriptor = %#v", installed)
	}

	cleanup := conn.call("step.cleanup", map[string]any{"runId": "run-1", "stepId": "squatter.cleanup_smb", "cleanupHandleId": "cap_cleanup_74m2wq"})
	if cleanup["status"] != "cleanup_verified" {
		t.Fatalf("cleanup status = %#v", cleanup["status"])
	}
}

// rpcConn drives a serve() loop over in-memory pipes.
type rpcConn struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
	id   int
}

func newRPCConn(t *testing.T, module Module) *rpcConn {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- ServeIO(module, inR, outW)
		if err := outW.Close(); err != nil {
			t.Logf("close rpc output pipe: %v", err)
		}
	}()
	return &rpcConn{t: t, in: inW, out: bufio.NewReader(outR), done: done}
}

func (c *rpcConn) call(method string, params map[string]any) map[string]any {
	c.t.Helper()
	c.id++
	c.writeRequest(c.id, method, params)
	// Skip notifications (module/log, module/session) until the matching response.
	for {
		message := c.readFrame()
		if _, hasID := message["id"]; !hasID {
			continue
		}
		if errObj, ok := message["error"]; ok {
			c.t.Fatalf("rpc error for %s: %v", method, errObj)
		}
		result, _ := message["result"].(map[string]any)
		return result
	}
}

func (c *rpcConn) callError(method string, params map[string]any) string {
	c.t.Helper()
	c.id++
	c.writeRequest(c.id, method, params)
	for {
		message := c.readFrame()
		if _, hasID := message["id"]; !hasID {
			continue
		}
		errObj, ok := message["error"].(map[string]any)
		if !ok {
			c.t.Fatalf("rpc %s returned success, want error: %#v", method, message)
		}
		messageText, _ := errObj["message"].(string)
		return messageText
	}
}

func (c *rpcConn) writeRequest(id int, method string, params map[string]any) {
	c.t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c.in, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.in.Write(body); err != nil {
		c.t.Fatal(err)
	}
}

func (c *rpcConn) readFrame() map[string]any {
	c.t.Helper()
	length := 0
	for {
		line, err := c.out.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read frame: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			var err error
			length, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				c.t.Fatalf("parse content-length %q: %v", value, err)
			}
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.out, body); err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	var message map[string]any
	if err := json.Unmarshal(body, &message); err != nil {
		c.t.Fatalf("decode body: %v", err)
	}
	return message
}

func (c *rpcConn) close() {
	c.call("shutdown", nil)
	if err := <-c.done; err != nil {
		c.t.Fatalf("serve returned error: %v", err)
	}
	if err := c.in.Close(); err != nil {
		c.t.Logf("close rpc input pipe: %v", err)
	}
}

func TestServePayloadProviderMethods(t *testing.T) {
	conn := newRPCConn(t, fakePayloadProvider{})
	defer conn.close()

	info := conn.call("handshake", nil)
	if info["moduleType"] != "payload_provider" {
		t.Fatalf("handshake = %#v", info)
	}

	list := conn.call("list_payloads", map[string]any{"platform": "windows", "arch": "x86"})
	payloads, _ := list["payloads"].([]any)
	if payloads == nil {
		// Method results that are arrays decode directly through rpcConn as nil
		// because it expects object results. Exercise object-returning methods
		// below and keep this call as a dispatch smoke check.
		t.Log("list_payloads returned a non-object result")
	}

	resolved := conn.call("resolve_payload", map[string]any{"format": "pe-exe"})
	if resolved["id"] != "fake/windows/x86/reverse-tcp/pe-exe" {
		t.Fatalf("resolve_payload = %#v", resolved)
	}
	listener := conn.call("prepare_listener", map[string]any{"runId": "run-1", "target": "target-1", "payloadId": resolved["id"]})
	if listener["state"] != "listening" {
		t.Fatalf("prepare_listener = %#v", listener)
	}
	if resolved["kind"] != "pe" || resolved["os"] != "windows" {
		t.Fatalf("resolve_payload typed payload fields = %#v", resolved)
	}
	tags, _ := resolved["tags"].([]any)
	if len(tags) != 2 || tags[0] != "native" {
		t.Fatalf("resolve_payload tags = %#v", resolved["tags"])
	}
	generated := conn.call("generate_payload", map[string]any{"target": "target-1", "payloadId": resolved["id"], "format": "pe-exe"})
	primary, _ := generated["primary"].(map[string]any)
	if primary["format"] != "pe-exe" || primary["encoding"] != "base64" {
		t.Fatalf("generate_payload primary = %#v", primary)
	}
	if primary["kind"] != "pe" || primary["os"] != "windows" || primary["arch"] != "x86" {
		t.Fatalf("generate_payload primary typed fields = %#v", primary)
	}
	session := conn.call("connect_session", map[string]any{
		"runId":              "run-1",
		"target":             "target-1",
		"payloadId":          resolved["id"],
		"installedPayloadId": "p1",
		"reconnect": map[string]any{
			"providerId":    "fake-payload",
			"schema":        "fake.reconnect",
			"schemaVersion": "v1",
			"descriptor":    map[string]any{"target": "target-1"},
		},
	})
	if session["transport"] != "squatter/smb-named-pipe" {
		t.Fatalf("connect_session = %#v", session)
	}
	if session["installedPayloadId"] != "p1" {
		t.Fatalf("connect_session installedPayloadId = %#v, want p1", session["installedPayloadId"])
	}
	cleanup := conn.call("cleanup_payload", map[string]any{"reason": "test"})
	if cleanup["status"] != "ok" {
		t.Fatalf("cleanup_payload = %#v", cleanup)
	}
}

func TestFrameReaderRejectsOversizedFrameBeforeBodyRead(t *testing.T) {
	reader := newFrameReader(strings.NewReader(fmt.Sprintf("Content-Length: %d\r\n\r\n", maxFrameBytes+1)))
	_, err := reader.read()
	if err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("error = %v, want frame size error", err)
	}
}

func TestFrameReaderIgnoresOptionalHeaders(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1}`
	reader := newFrameReader(strings.NewReader(fmt.Sprintf(
		"Content-Length: %d\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n%s",
		len(body),
		body,
	)))
	message, err := reader.read()
	if err != nil {
		t.Fatalf("read() error = %v", err)
	}
	if string(message["id"]) != "1" {
		t.Fatalf("id = %s, want 1", message["id"])
	}
}

func TestServeHandshakeSchemaExecute(t *testing.T) {
	conn := newRPCConn(t, fakeModule{})
	defer conn.close()

	info := conn.call("handshake", nil)
	if info["name"] != "fake" || info["moduleType"] != "survey" {
		t.Fatalf("handshake = %#v", info)
	}

	schema := conn.call("schema", nil)
	target, _ := schema["targetConfig"].([]any)
	if len(target) != 1 {
		t.Fatalf("schema targetConfig = %#v", schema["targetConfig"])
	}
	req, _ := target[0].(map[string]any)
	if req["key"] != "target.host" || req["required"] != true {
		t.Fatalf("requirement = %#v", req)
	}

	result := conn.call("execute", map[string]any{
		"runId":        "run-1",
		"moduleId":     "fake",
		"target":       "mock://host",
		"targetConfig": map[string]any{"target.host": "example.test"},
	})
	if result["status"] != "succeeded" {
		t.Fatalf("execute status = %#v", result["status"])
	}
	if result["summary"] != "surveyed example.test" {
		t.Fatalf("summary = %#v", result["summary"])
	}
	findings, _ := result["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", result["findings"])
	}
}

func TestServeHandshakeRequiresIdentityAndType(t *testing.T) {
	conn := newRPCConn(t, missingVersionModule{})
	defer conn.close()

	if got := conn.callError("handshake", nil); got != "module handshake version is required" {
		t.Fatalf("handshake error = %q", got)
	}
}

func TestServeOptionalContextFields(t *testing.T) {
	conn := newRPCConn(t, fakeContextModule{})
	defer conn.close()

	info := conn.call("handshake", nil)
	discovery, _ := info["discoveryContext"].(map[string]any)
	if discovery["summary"] != "Find SMB exposure" {
		t.Fatalf("discovery context = %#v", discovery)
	}
	if _, ok := discovery["risk"]; ok {
		t.Fatalf("discovery context included absent risk: %#v", discovery)
	}
	schema := conn.call("schema", nil)
	planning, _ := schema["planningContext"].(map[string]any)
	risk, _ := planning["risk"].(map[string]any)
	if risk["level"] != "low" {
		t.Fatalf("planning context = %#v", planning)
	}

	plain := newRPCConn(t, fakeModule{})
	defer plain.close()
	plainInfo := plain.call("handshake", nil)
	if _, ok := plainInfo["discoveryContext"]; ok {
		t.Fatalf("plain handshake has discoveryContext: %#v", plainInfo)
	}
}

func TestServeExecuteExposesOptionalAgentContext(t *testing.T) {
	conn := newRPCConn(t, agentAwareModule{})
	defer conn.close()

	withoutAgent := conn.call("execute", map[string]any{
		"runId":    "run-1",
		"moduleId": "agent-aware",
		"target":   "mock://host",
	})
	outputs, _ := withoutAgent["outputs"].(map[string]any)
	if outputs["agentPresent"] != false {
		t.Fatalf("without agent outputs = %#v", outputs)
	}
	if _, ok := withoutAgent["agentHints"]; ok {
		t.Fatalf("agentHints should be omitted without opt-in: %#v", withoutAgent["agentHints"])
	}

	withAgent := conn.call("execute", map[string]any{
		"runId":    "run-2",
		"moduleId": "agent-aware",
		"target":   "mock://host",
		"agentContext": map[string]any{
			"schema": "hovel.agent_context.v1",
			"entity": map[string]any{
				"id":          "entity-mcp",
				"kind":        "mcp",
				"displayName": "Codex",
				"agent":       true,
			},
			"operation":     "redteam-lab",
			"chain":         "alpha",
			"planId":        "plan-1",
			"planHash":      "hash-1",
			"approvalState": "pending",
			"phase":         "execute",
			"resources":     []any{"hovel://throw-plan/plan-1"},
		},
	})
	outputs, _ = withAgent["outputs"].(map[string]any)
	if outputs["entityID"] != "entity-mcp" || outputs["entityKind"] != "mcp" || outputs["phase"] != "execute" {
		t.Fatalf("with agent outputs = %#v", outputs)
	}
	hints, _ := withAgent["agentHints"].([]any)
	if len(hints) != 1 {
		t.Fatalf("agentHints = %#v, want one", withAgent["agentHints"])
	}
	hint, _ := hints[0].(map[string]any)
	if hint["schema"] != "hovel.agent_hint.v1" || hint["text"] == "" {
		t.Fatalf("agent hint = %#v", hint)
	}
}

func TestServeSessionRoundTrip(t *testing.T) {
	conn := newRPCConn(t, fakeModule{withSession: true})
	defer conn.close()

	conn.call("handshake", nil)
	result := conn.call("execute", map[string]any{"runId": "run-1", "moduleId": "fake", "target": "mock://host"})
	sessions, _ := result["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %#v", result["sessions"])
	}
	ref, _ := sessions[0].(map[string]any)
	sessionID, _ := ref["id"].(string)
	if sessionID == "" {
		t.Fatalf("session ref missing id: %#v", ref)
	}

	// Drain the opening prompt.
	prompt := readSession(t, conn, sessionID)
	if !strings.Contains(prompt, "mock$") {
		t.Fatalf("opening prompt = %q", prompt)
	}

	conn.call("session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString([]byte("whoami\n")),
	})
	output := readSession(t, conn, sessionID)
	if !strings.Contains(output, "mock-operator") {
		t.Fatalf("session output = %q", output)
	}

	closeResult := conn.call("session/close", map[string]any{"sessionId": sessionID, "reason": "done"})
	if closeResult["status"] != "ok" {
		t.Fatalf("close result = %#v", closeResult)
	}
}

func TestServeSessionCommandRoundTrip(t *testing.T) {
	conn := newRPCConn(t, fakeModule{withSession: true})
	defer conn.close()

	result := conn.call("execute", map[string]any{"runId": "run-1", "moduleId": "fake", "target": "mock://host"})
	sessions, _ := result["sessions"].([]any)
	ref, _ := sessions[0].(map[string]any)
	sessionID, _ := ref["id"].(string)
	if sessionID == "" {
		t.Fatalf("session ref missing id: %#v", ref)
	}

	list := conn.call("session.command.list", map[string]any{"sessionId": sessionID})
	commands, _ := list["commands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("commands = %#v, want one", list["commands"])
	}
	command, _ := commands[0].(map[string]any)
	if command["name"] != "session.info" {
		t.Fatalf("command = %#v, want session.info", command)
	}

	run := conn.call("session.command.run", map[string]any{
		"sessionId": sessionID,
		"request": map[string]any{
			"command": "session.info",
			"args":    []string{"one", "two"},
		},
	})
	if run["command"] != "session.info" || run["stdout"] != "mock session info" {
		t.Fatalf("session command result = %#v", run)
	}
	fields, _ := run["fields"].(map[string]any)
	if fields["args"] != "one,two" {
		t.Fatalf("session command fields = %#v", fields)
	}
}

func readSession(t *testing.T, conn *rpcConn, sessionID string) string {
	t.Helper()
	var builder strings.Builder
	for i := 0; i < 5; i++ {
		resp := conn.call("session/read", map[string]any{"sessionId": sessionID, "timeoutMs": 200})
		data, _ := resp["data"].(string)
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			t.Fatalf("decode session data: %v", err)
		}
		builder.Write(decoded)
		if len(decoded) == 0 {
			break
		}
	}
	return builder.String()
}

func TestServeSessionReadDoesNotBlockWrite(t *testing.T) {
	conn := newRPCConn(t, fakeModule{withSession: true})
	defer conn.close()

	result := conn.call("execute", map[string]any{"runId": "run-1", "moduleId": "fake", "target": "mock://host"})
	sessions, _ := result["sessions"].([]any)
	ref, _ := sessions[0].(map[string]any)
	sessionID, _ := ref["id"].(string)
	_ = readSession(t, conn, sessionID)

	readID := 1001
	writeID := 1002
	conn.writeRequest(readID, "session/read", map[string]any{
		"sessionId": sessionID,
		"timeoutMs": 1000,
	})

	writeSent := make(chan struct{})
	go func() {
		defer close(writeSent)
		conn.writeRequest(writeID, "session/write", map[string]any{
			"sessionId": sessionID,
			"data":      base64.StdEncoding.EncodeToString([]byte("whoami\n")),
		})
	}()

	select {
	case <-writeSent:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("session/write request was blocked behind a pending session/read")
	}

	seenWrite, seenRead := false, false
	var readOutput strings.Builder
	deadline := time.After(2 * time.Second)
	for !seenWrite || !seenRead {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for read/write responses; seenWrite=%v seenRead=%v", seenWrite, seenRead)
		default:
		}
		message := conn.readFrame()
		id, ok := responseID(message)
		if !ok {
			continue
		}
		if errObj, ok := message["error"]; ok {
			t.Fatalf("rpc error for id %d: %v", id, errObj)
		}
		switch id {
		case writeID:
			seenWrite = true
		case readID:
			seenRead = true
			result, _ := message["result"].(map[string]any)
			data, _ := result["data"].(string)
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				t.Fatalf("decode pending session data: %v", err)
			}
			if len(decoded) == 0 {
				t.Fatal("pending session/read returned no data after session/write")
			}
			readOutput.Write(decoded)
		}
	}
	readOutput.WriteString(readSession(t, conn, sessionID))
	if !strings.Contains(readOutput.String(), "mock-operator") {
		t.Fatalf("session output = %q, want command output", readOutput.String())
	}
}

func responseID(message map[string]any) (int, bool) {
	value, ok := message["id"]
	if !ok {
		return 0, false
	}
	switch id := value.(type) {
	case float64:
		return int(id), true
	case int:
		return id, true
	default:
		return 0, false
	}
}

func TestLineShellSessionExit(t *testing.T) {
	shell := &LineShellSession{Handle: func(string) (string, error) { return "ok", nil }}
	if err := shell.Open(); err != nil {
		t.Fatalf("open shell: %v", err)
	}
	if err := shell.Write([]byte("exit\n")); err != nil {
		t.Fatalf("write shell: %v", err)
	}
	if !shell.Closed() {
		t.Fatal("shell should be closed after exit")
	}
	data, err := shell.Read(10 * time.Millisecond)
	if err != nil {
		t.Fatalf("read shell: %v", err)
	}
	if len(data) != 0 && !shell.Closed() {
		t.Fatalf("unexpected data after close: %q", data)
	}
}

func TestPTYSessionUsesTerminalLineDiscipline(t *testing.T) {
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "got:%s", line)
		return err
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := session.Close("test"); err != nil {
			t.Logf("close pty session: %v", err)
		}
	})

	if err := session.Write([]byte{'a', 'b', 0x7f, 'c', '\n'}); err != nil {
		t.Fatal(err)
	}
	output := readPTYSession(t, session)
	if !strings.Contains(output, "got:ac") {
		t.Fatalf("pty output = %q, want frontend line ac", output)
	}
}

func TestSessionManagerMarksPTYSessionCapability(t *testing.T) {
	manager := newSessionManager(nil)
	session := &PTYSession{Frontend: func(io.Reader, io.Writer) error {
		return nil
	}}
	ref, err := manager.open(sessionScope{runID: "run-1", moduleID: "mod", target: "target"}, session, sessionOptions{
		name:         "terminal",
		kind:         "agent",
		transport:    "pty/test",
		capabilities: []string{"read", "write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestSession(t, session)
	if !hasString(ref.Capabilities, CapabilityTerminalPTY) {
		t.Fatalf("capabilities = %#v, want %q", ref.Capabilities, CapabilityTerminalPTY)
	}
}

func TestSessionManagerDoesNotTrackFailedOpen(t *testing.T) {
	manager := newSessionManager(nil)
	session := &failingOpenSession{}
	_, err := manager.open(
		sessionScope{runID: "run-1", moduleID: "mod", target: "target"},
		session,
	)
	if err == nil {
		t.Fatal("open session succeeded, want error")
	}
	if refs := manager.refsForRun("run-1"); len(refs) != 0 {
		t.Fatalf("refs = %#v, want no tracked sessions", refs)
	}
	manager.closeAll("test")
	if session.closeCalls != 0 {
		t.Fatalf("close calls = %d, want 0", session.closeCalls)
	}
}

func TestPTYSessionUsesSeparateInputOutputHandles(t *testing.T) {
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		inputFile, ok := input.(*os.File)
		if !ok {
			return fmt.Errorf("input = %T, want *os.File", input)
		}
		outputFile, ok := output.(*os.File)
		if !ok {
			return fmt.Errorf("output = %T, want *os.File", output)
		}
		if inputFile == outputFile || inputFile.Fd() == outputFile.Fd() {
			return fmt.Errorf("input and output handles must be independent")
		}
		return writeAll(output, []byte("separate handles\n"))
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	defer closeTestSession(t, session)

	output := readPTYSession(t, session)
	if !strings.Contains(output, "separate handles") {
		t.Fatalf("pty output = %q, want frontend output", output)
	}
}

func TestPTYSessionDrainsLargeFrontendOutput(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef\r\n"), 4096)
	session := &PTYSession{Frontend: func(input io.Reader, output io.Writer) error {
		_ = input
		return writeAll(output, payload)
	}}
	if err := session.Open(); err != nil {
		t.Fatal(err)
	}
	defer closeTestSession(t, session)

	output := readPTYSessionUntil(t, session, len(payload), 2*time.Second)
	if len(output) < len(payload) || !strings.Contains(output, "0123456789abcdef") {
		t.Fatalf("pty drained %d bytes, want at least %d and repeated payload text", len(output), len(payload))
	}
}

func readPTYSession(t *testing.T, session *PTYSession) string {
	t.Helper()
	var builder strings.Builder
	for i := 0; i < 10; i++ {
		chunk, err := session.Read(100 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk) == 0 {
			break
		}
		builder.Write(chunk)
	}
	return builder.String()
}

func readPTYSessionUntil(t *testing.T, session *PTYSession, minBytes int, timeout time.Duration) string {
	t.Helper()
	var builder strings.Builder
	deadline := time.Now().Add(timeout)
	for builder.Len() < minBytes && time.Now().Before(deadline) {
		chunk, err := session.Read(100 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk) == 0 {
			continue
		}
		builder.Write(chunk)
	}
	return builder.String()
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func closeTestSession(t *testing.T, session *PTYSession) {
	t.Helper()
	if err := session.Close("test"); err != nil {
		t.Logf("close pty session: %v", err)
	}
}
