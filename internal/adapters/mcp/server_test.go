package mcpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAttachRegistersMCPAgentEntity(t *testing.T) {
	daemon := newFakeDaemon()

	server, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-test",
		DisplayName: "Claude reviewer",
		Operation:   "redteam-lab",
		ActiveChain: "alpha",
		PolicyTags:  []string{"review-required", "review-required"},
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}

	attach := daemon.attachRequests[0]
	if attach.ID != "mcp-test" || attach.Kind != "mcp" || !attach.Agent {
		t.Fatalf("attach request identity = %#v", attach)
	}
	if attach.DisplayName != "Claude reviewer" || attach.Operation != "redteam-lab" || attach.ActiveChain != "alpha" {
		t.Fatalf("attach request context = %#v", attach)
	}
	if got, want := attach.Capabilities, defaultCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
	if got, want := attach.PolicyTags, []string{"review-required"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy tags = %#v, want %#v", got, want)
	}

	if err := server.Detach(context.Background()); err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if got, want := daemon.detachedIDs, []string{"mcp-test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("detached IDs = %#v, want %#v", got, want)
	}
}

func TestHTTPTransportServesMCPTools(t *testing.T) {
	daemon := newFakeDaemon()
	attached, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-http-test",
		DisplayName: "MCP HTTP test",
		Operation:   "redteam-lab",
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var status bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serveHTTPTransport(ctx, attached, listener, &status)
	}()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-http-client", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: "http://" + listener.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("client connect returned error: %v", err)
	}
	if !strings.Contains(status.String(), "Hovel MCP HTTP listening") {
		t.Fatalf("status = %q, want listening message", status.String())
	}

	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: ToolOperatorIdentity})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolOperatorIdentity, err)
	}
	identity := decodeStructured[operatorIdentityOutput](t, result)
	if identity.Entity.ID != "mcp-http-test" || identity.Entity.Kind != "mcp" {
		t.Fatalf("identity = %#v", identity.Entity)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("session close returned error: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HTTP transport returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP transport did not stop")
	}
}

func TestMCPServerExposesTypedReadOnlyTools(t *testing.T) {
	daemon := newFakeDaemon()
	var throwRequest throwStartInput
	daemon.snapshot = daemonrpc.SnapshotResponse{State: operatorsession.PersistedState{
		ActiveOperation: "redteam-lab",
		ActiveChain:     "alpha",
		Operations: []operatorsession.PersistedOperation{{
			Name:          "redteam-lab",
			Targets:       []string{"mock://router-01"},
			TargetConfigs: map[string]map[string]string{"mock://router-01": nil},
			Chains: []operatorsession.PersistedChain{{
				Name:    "alpha",
				Targets: []string{"mock://router-01"},
				Steps: []operatorsession.Step{{
					ID:       "step-1",
					ModuleID: "mock-exploit@v0.0.0-example",
				}},
				Config:   map[string]string{"operator.confirmed_lab": "true"},
				LogTopic: "chain.redteam-lab.alpha",
			}},
		}},
	}}

	attached, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-test",
		DisplayName: "MCP test",
		Operation:   "redteam-lab",
		ActiveChain: "alpha",
		ThrowStarter: func(_ context.Context, input throwStartInput) (throwStartOutput, error) {
			throwRequest = input
			return throwStartOutput{
				Operation: input.Operation,
				Plan: commands.ThrowPlanPayload{
					ID:       "plan-1",
					PlanHash: "hash-1",
					Chain:    input.Chain,
					Targets:  []string{"mock://router-01"},
				},
				ThrowID: "throw-1",
				Chain:   input.Chain,
				Targets: []string{"mock://router-01"},
				Results: []commands.RunPayload{{
					RunID:    "run-1",
					ModuleID: "mock-exploit@v0.0.0-example",
					Target:   "mock://router-01",
					State:    "succeeded",
					Summary:  "mock exploit opened an interactive shell session",
				}},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sdkServer := attached.MCPServer()
	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- sdkServer.Run(ctx, serverTransport)
	}()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect returned error: %v", err)
	}
	defer func() {
		_ = session.Close()
		cancel()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("server run returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
	}()

	tools, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}
	names := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Name == ToolChainApply || tool.Name == ToolCommandRun || tool.Name == ToolThrowStart || tool.Name == ToolPayloadCmd || tool.Name == ToolPayloadCommandCall {
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
				t.Fatalf("tool %s is missing destructive annotations", tool.Name)
			}
			continue
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool %s is missing read-only annotations", tool.Name)
		}
	}
	sort.Strings(names)
	wantNames := []string{ToolCatalogSnapshot, ToolChainApply, ToolCommandRun, ToolInstalledPayloadList, ToolOperationList, ToolOperatorIdentity, ToolOperatorListEntities, ToolPayloadCmd, ToolPayloadCommandCall, ToolPayloadCommandList, ToolThrowStart, ToolWorkspaceSnapshot}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tool names = %#v, want %#v", names, wantNames)
	}

	identityResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: ToolOperatorIdentity})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolOperatorIdentity, err)
	}
	identity := decodeStructured[operatorIdentityOutput](t, identityResult)
	if identity.Entity.ID != "mcp-test" || identity.Entity.Kind != "mcp" || !identity.Entity.Agent {
		t.Fatalf("identity = %#v", identity.Entity)
	}

	listResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      ToolOperatorListEntities,
		Arguments: map[string]any{"operation": "redteam-lab"},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolOperatorListEntities, err)
	}
	entities := decodeStructured[operatorListEntitiesOutput](t, listResult)
	if entities.Operation != "redteam-lab" || len(entities.Entities) != 1 || entities.Entities[0].ID != "mcp-test" {
		t.Fatalf("entities = %#v", entities)
	}

	snapshotResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      ToolWorkspaceSnapshot,
		Arguments: map[string]any{"operation": "redteam-lab", "chain": "alpha"},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolWorkspaceSnapshot, err)
	}
	snapshot := decodeStructured[workspaceSnapshotOutput](t, snapshotResult)
	if snapshot.ActiveOperation != "redteam-lab" || snapshot.ActiveChain != "alpha" {
		t.Fatalf("snapshot context = %s/%s", snapshot.ActiveOperation, snapshot.ActiveChain)
	}
	if len(snapshot.Operations) != 1 || snapshot.Operations[0].Name != "redteam-lab" {
		t.Fatalf("operations = %#v", snapshot.Operations)
	}
	if got := snapshot.Operations[0].TargetConfigs["mock://router-01"]; got == nil {
		t.Fatalf("target config for unconfigured target encoded as nil: %#v", snapshot.Operations[0].TargetConfigs)
	}
	chain := snapshot.Operations[0].Chains[0]
	if chain.Name != "alpha" || len(chain.Steps) != 1 || chain.Steps[0].ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("chain = %#v", chain)
	}
	if got := chain.Config["operator.confirmed_lab"]; got != "true" {
		t.Fatalf("operator.confirmed_lab = %q, want true", got)
	}

	throwResult, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: ToolThrowStart,
		Arguments: map[string]any{
			"operation": "redteam-lab",
			"chain":     "alpha",
			"nowBypass": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool(%s) returned error: %v", ToolThrowStart, err)
	}
	throwOut := decodeStructured[throwStartOutput](t, throwResult)
	if throwOut.ThrowID != "throw-1" || throwOut.Chain != "alpha" || len(throwOut.Results) != 1 {
		t.Fatalf("throw output = %#v", throwOut)
	}
	if throwRequest.Operation != "redteam-lab" || throwRequest.Chain != "alpha" || !throwRequest.NowBypass {
		t.Fatalf("throw request = %#v", throwRequest)
	}

	if got := daemon.snapshotRequests[0]; got.Operation != "redteam-lab" || got.Chain != "alpha" {
		t.Fatalf("snapshot request = %#v", got)
	}
	if len(daemon.heartbeatRequests) == 0 {
		t.Fatal("expected tool calls to heartbeat the MCP operator entity")
	}
}

func TestMCPCommandRunCarriesOperationAndChainContext(t *testing.T) {
	daemon := newFakeDaemon()
	var requests []commandRunInput
	attached, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-command-test",
		DisplayName: "MCP command test",
		CommandRunner: func(_ context.Context, input commandRunInput) (commandRunOutput, error) {
			requests = append(requests, commandRunInput{
				Args:      append([]string(nil), input.Args...),
				Operation: input.Operation,
				Chain:     input.Chain,
			})
			return commandRunOutput{
				Args:     append([]string(nil), input.Args...),
				ExitCode: 0,
				Stdout:   "ok\n",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	call := func(args ...string) commandRunOutput {
		t.Helper()
		_, out, err := attached.commandRun(context.Background(), nil, commandRunInput{Args: args})
		if err != nil {
			t.Fatalf("commandRun(%q) returned error: %v", strings.Join(args, " "), err)
		}
		return out
	}

	if out := call("hovel", "run", "--", "op", "use", "redteam-lab"); !out.OK || out.Operation != "redteam-lab" || out.Chain != "" {
		t.Fatalf("op use output = %#v", out)
	}
	if out := call("chain", "create", "etro-squatter"); !out.OK || out.Operation != "redteam-lab" || out.Chain != "etro-squatter" {
		t.Fatalf("chain create output = %#v", out)
	}
	if out := call("target", "add", "192.168.122.142"); !out.OK || out.Operation != "redteam-lab" || out.Chain != "etro-squatter" {
		t.Fatalf("target add output = %#v", out)
	}

	if len(requests) != 3 {
		t.Fatalf("command requests = %#v", requests)
	}
	if got, want := requests[0].Args, []string{"op", "use", "redteam-lab"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first args = %#v, want %#v", got, want)
	}
	if requests[1].Operation != "redteam-lab" || requests[1].Chain != "" {
		t.Fatalf("second request context = %#v", requests[1])
	}
	if requests[2].Operation != "redteam-lab" || requests[2].Chain != "etro-squatter" {
		t.Fatalf("third request context = %#v", requests[2])
	}
	entity := attached.currentEntity()
	if entity.Operation != "redteam-lab" || entity.ActiveChain != "etro-squatter" {
		t.Fatalf("entity context = %#v", entity)
	}
}

func TestMCPCommandRunExecutesThroughDaemonSession(t *testing.T) {
	testsupport.UseExampleModuleConfig(t)
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{})
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	attached, err := Attach(context.Background(), client, OperatorOptions{
		EntityID:      "mcp-command-daemon-test",
		DisplayName:   "MCP command daemon test",
		Workspace:     fixture.WorkspacePath,
		CommandRunner: commandModeCommandRunner(fixture.WorkspacePath, client, "", ""),
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	run := func(args ...string) commandRunOutput {
		t.Helper()
		_, out, err := attached.commandRun(context.Background(), nil, commandRunInput{Args: args})
		if err != nil {
			t.Fatalf("commandRun(%q) returned error: %v", strings.Join(args, " "), err)
		}
		if !out.OK {
			t.Fatalf("commandRun(%q) exit code = %d, stdout = %s, stderr = %s", strings.Join(args, " "), out.ExitCode, out.Stdout, out.Stderr)
		}
		return out
	}

	run("op", "use", "mcp-e2e")
	run("chain", "create", "etro")
	modules := run("modules", "list")
	if !strings.Contains(modules.Stdout, "etro-exploit@v1.0.0") {
		t.Fatalf("modules list missing configured catalog:\n%s", modules.Stdout)
	}
	run("target", "add", "192.168.122.142")
	run("target", "config", "set", "192.168.122.142", "target.host", "192.168.122.142")
	run("chain", "config", "set", "operator.confirmed_lab", "true")

	_, snapshot, err := attached.workspaceSnapshot(context.Background(), nil, operationContextInput{})
	if err != nil {
		t.Fatalf("workspaceSnapshot returned error: %v", err)
	}
	if snapshot.ActiveOperation != "mcp-e2e" || snapshot.ActiveChain != "etro" {
		t.Fatalf("snapshot context = %s/%s", snapshot.ActiveOperation, snapshot.ActiveChain)
	}
	if len(snapshot.Operations) != 1 {
		t.Fatalf("operations = %#v", snapshot.Operations)
	}
	operation := snapshot.Operations[0]
	if !containsString(operation.Targets, "192.168.122.142") {
		t.Fatalf("operation targets = %#v", operation.Targets)
	}
	if got := operation.TargetConfigs["192.168.122.142"]["target.host"]; got != "192.168.122.142" {
		t.Fatalf("target.host = %q", got)
	}
	if len(operation.Chains) != 1 || operation.Chains[0].Name != "etro" {
		t.Fatalf("chains = %#v", operation.Chains)
	}
	if got := operation.Chains[0].Config["operator.confirmed_lab"]; got != "true" {
		t.Fatalf("operator.confirmed_lab = %q", got)
	}
}

func TestMCPChainApplyBuildsEtroSquatterWithoutCLIProbing(t *testing.T) {
	configPath := testsupport.WritePythonModuleFixtures(t,
		testsupport.PythonModuleFixture{
			ID:   "etro-survey",
			Body: schemaModuleFixtureBody("etro-survey", "v0.1.0", "survey", `[]`, `[]`),
		},
		testsupport.PythonModuleFixture{
			ID: "etro-exploit",
			Body: schemaModuleFixtureBody("etro-exploit", "v1.0.0", "exploit", `[
		{"key": "operator.confirmed_lab", "type": "bool", "required": True}
	]`, `[
		{"key": "target.host", "type": "host", "required": True},
		{"key": "target.port", "type": "port", "required": True, "default": "445"},
		{"key": "pipe", "type": "enum", "required": True, "default": "spoolss", "allowed": ["spoolss"]}
	]`),
		},
		testsupport.PythonModuleFixture{
			ID:   "squatter",
			Body: schemaModuleFixtureBody("squatter", "v0.1.0", "payload_provider", `[]`, `[]`),
		},
	)
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{})
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	attached, err := Attach(context.Background(), client, OperatorOptions{
		EntityID:      "mcp-chain-apply-test",
		DisplayName:   "MCP chain apply test",
		Workspace:     fixture.WorkspacePath,
		CatalogPath:   configPath,
		CommandRunner: commandModeCommandRunner(fixture.WorkspacePath, client, configPath, ""),
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	_, out, err := attached.chainApply(context.Background(), nil, chainApplyInput{
		Operation: "o1",
		Chain:     "xp",
		Modules:   []string{"etro-survey@v0.1.0", "etro-exploit@v1.0.0", "squatter@v0.1.0"},
		Targets:   []string{"192.168.122.142"},
		ChainConfig: map[string]string{
			"operator.confirmed_lab": "true",
			"squatter.bind_port":     "9100",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Validation.OK || !strings.Contains(out.Validation.Stdout, "Chain xp valid") {
		t.Fatalf("validation = %#v", out.Validation)
	}
	operation := out.Snapshot.Operations[0]
	if len(operation.Chains) != 1 || len(operation.Chains[0].Steps) != 3 {
		t.Fatalf("snapshot chain = %#v", operation.Chains)
	}
	chainConfig := operation.Chains[0].Config
	if chainConfig["squatter.type"] != "tcp-bind" || chainConfig["squatter.bind_port"] != "9100" {
		t.Fatalf("chain config = %#v", chainConfig)
	}
	targetConfig := operation.TargetConfigs["192.168.122.142"]
	if targetConfig["target.host"] != "192.168.122.142" || targetConfig["target.port"] != "445" || targetConfig["pipe"] != "spoolss" {
		t.Fatalf("target config = %#v", targetConfig)
	}
}

func TestMCPInstalledPayloadListReportsProviderReadiness(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOVEL_MODULE_CONFIG", configPath)
	workspace := t.TempDir()
	recordInstalledPayload(t, workspace, "squatter")

	attached, err := Attach(context.Background(), newFakeDaemon(), OperatorOptions{
		EntityID:    "mcp-payload-list-test",
		DisplayName: "MCP payload list test",
		Operation:   "o1",
		ActiveChain: "xp",
		Workspace:   workspace,
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	_, out, err := attached.installedPayloadList(context.Background(), nil, installedPayloadListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 1 {
		t.Fatalf("records = %#v", out.Records)
	}
	payload := out.Records[0]
	if payload.Record.Handle != "p1" || payload.ProviderConfigured {
		t.Fatalf("payload status = %#v", payload)
	}
	if !strings.Contains(payload.ProviderError, "active module catalog") || !strings.Contains(payload.ProviderError, "squatter") {
		t.Fatalf("provider error = %q", payload.ProviderError)
	}
}

func TestMCPPayloadCmdRunsCmdThroughInstalledPayload(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixture(t, "squatter", payloadProviderFixtureBody()))
	workspace := t.TempDir()
	recordInstalledPayload(t, workspace, "squatter")
	daemon := newFakeDaemon()
	daemon.payloadCommandResponse = run.PayloadCommandResult{Command: "cmd", Stdout: "host\n"}
	attached, err := Attach(context.Background(), daemon, OperatorOptions{
		EntityID:    "mcp-payload-cmd-test",
		DisplayName: "MCP payload cmd test",
		Operation:   "o1",
		ActiveChain: "xp",
		Workspace:   workspace,
	})
	if err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	defer attached.Detach(context.Background())

	_, out, err := attached.payloadCmd(context.Background(), nil, payloadCmdInput{Payload: "p1", Command: "systeminfo"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Command != "systeminfo" || out.Result.Stdout != "host\n" {
		t.Fatalf("payload cmd output = %#v", out)
	}
	if len(daemon.payloadCommandRequests) != 1 {
		t.Fatalf("payload command requests = %#v", daemon.payloadCommandRequests)
	}
	req := daemon.payloadCommandRequests[0]
	if req.ModuleID != "squatter" || req.Request.Command != "cmd" || !reflect.DeepEqual(req.Request.Args, []string{"systeminfo"}) {
		t.Fatalf("payload command request = %#v", req)
	}
}

func TestMCPWorkspaceInjectionSkipsPayloadsAvailable(t *testing.T) {
	if got, want := injectWorkspaceForMCPCommand([]string{"payloads", "available"}, "/tmp/hovel"), []string{"payloads", "available"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payloads available args = %#v, want %#v", got, want)
	}
	if got, want := injectWorkspaceForMCPCommand([]string{"payloads", "list"}, "/tmp/hovel"), []string{"payloads", "list"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payloads list args = %#v, want %#v", got, want)
	}
	if got, want := injectWorkspaceForMCPCommand([]string{"payloads", "installed"}, "/tmp/hovel"), []string{"payloads", "installed", "--workspace", "/tmp/hovel"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payloads installed args = %#v, want %#v", got, want)
	}
	workdir := t.TempDir()
	t.Setenv("BUILD_WORKING_DIRECTORY", workdir)
	if got, want := injectWorkspaceForMCPCommand([]string{"payloads", "installed"}, ""), []string{"payloads", "installed", "--workspace", filepath.Join(workdir, ".hovel")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payloads installed default args = %#v, want %#v", got, want)
	}
}

func recordInstalledPayload(t *testing.T, workspace, provider string) commands.InstalledPayloadRecord {
	t.Helper()
	record, err := filesystem.NewWorkspaceStore().RecordInstalledPayload(context.Background(), commands.InstalledPayloadRecord{
		Workspace:         workspace,
		Provider:          provider,
		PayloadID:         "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Target:            "192.168.122.142",
		State:             commands.PayloadStateInstalled,
		Transport:         "tcp-bind",
		Endpoint:          "192.168.122.142:9100",
		Operation:         "o1",
		Chain:             "xp",
		SupportsReconnect: true,
		Reconnect: &commands.PayloadProviderRecord{
			ProviderID: provider,
			Descriptor: map[string]any{"payload.transport": "tcp-bind", "payload.bind_port": "9100"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func payloadProviderFixtureBody() string {
	return `
while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "squatter", "version": "v0.1.0", "moduleType": "payload_provider"}
    elif method == "schema":
        response["result"] = {}
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`
}

func schemaModuleFixtureBody(name, version, moduleType, chainConfig, targetConfig string) string {
	return `
while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "` + name + `", "version": "` + version + `", "moduleType": "` + moduleType + `"}
    elif method == "schema":
        response["result"] = {"chainConfig": ` + chainConfig + `, "targetConfig": ` + targetConfig + `, "outputs": {}}
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`
}

func TestMCPCommandCatalogRejectsEmptyCatalogForModuleCommands(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(configPath, []byte(`{"modules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOVEL_MODULE_CONFIG", configPath)

	if _, err := mcpCommandCatalog(context.Background(), []string{"module", "list"}, "", "", ""); err == nil || !strings.Contains(err.Error(), "module catalog is empty") {
		t.Fatalf("module command catalog error = %v, want empty catalog error", err)
	}
	catalog, err := mcpCommandCatalog(context.Background(), []string{"op", "use", "lab"}, "", "", "")
	if err != nil {
		t.Fatalf("non-module command catalog returned error: %v", err)
	}
	if len(catalog.List()) != 0 {
		t.Fatalf("catalog = %#v, want empty catalog for non-module command", catalog.List())
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func decodeStructured[T any](t *testing.T, result *mcpsdk.CallToolResult) T {
	t.Helper()
	if result == nil {
		t.Fatal("tool result is nil")
	}
	if result.IsError {
		t.Fatalf("tool returned error content: %#v", result.Content)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode structured content %s: %v", data, err)
	}
	return out
}

type fakeDaemon struct {
	mu                     sync.Mutex
	now                    time.Time
	attachRequests         []daemonrpc.AttachEntityRequest
	heartbeatRequests      []daemonrpc.HeartbeatEntityRequest
	listRequests           []daemonrpc.ListEntitiesRequest
	snapshotRequests       []daemonrpc.SnapshotRequest
	detachedIDs            []string
	entities               map[string]daemonrpc.OperatorEntity
	snapshot               daemonrpc.SnapshotResponse
	payloadCommandRequests []daemonrpc.PayloadCommandRunRequest
	payloadCommandResponse daemonrpc.PayloadCommandRunResponse
	payloadCommandError    error
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{
		now:      time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		entities: map[string]daemonrpc.OperatorEntity{},
	}
}

func (f *fakeDaemon) AttachEntity(_ context.Context, req daemonrpc.AttachEntityRequest) (daemonrpc.EntityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attachRequests = append(f.attachRequests, req)
	entity := daemonrpc.OperatorEntity{
		ID:           req.ID,
		Kind:         req.Kind,
		DisplayName:  req.DisplayName,
		Agent:        req.Agent,
		Operation:    req.Operation,
		ActiveChain:  req.ActiveChain,
		ConnectedAt:  f.now.Format(time.RFC3339Nano),
		LastSeenAt:   f.now.Format(time.RFC3339Nano),
		Capabilities: append([]string(nil), req.Capabilities...),
		PolicyTags:   append([]string(nil), req.PolicyTags...),
	}
	f.entities[entity.ID] = entity
	return daemonrpc.EntityResponse{Entity: entity}, nil
}

func (f *fakeDaemon) HeartbeatEntity(_ context.Context, req daemonrpc.HeartbeatEntityRequest) (daemonrpc.EntityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatRequests = append(f.heartbeatRequests, req)
	entity, ok := f.entities[req.ID]
	if !ok {
		return daemonrpc.EntityResponse{}, errors.New("entity is not attached")
	}
	if req.Operation != nil {
		entity.Operation = *req.Operation
	}
	if req.ActiveChain != nil {
		entity.ActiveChain = *req.ActiveChain
	}
	f.now = f.now.Add(time.Second)
	entity.LastSeenAt = f.now.Format(time.RFC3339Nano)
	f.entities[entity.ID] = entity
	return daemonrpc.EntityResponse{Entity: entity}, nil
}

func (f *fakeDaemon) DetachEntity(_ context.Context, req daemonrpc.DetachEntityRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachedIDs = append(f.detachedIDs, req.ID)
	delete(f.entities, req.ID)
	return nil
}

func (f *fakeDaemon) ListEntities(_ context.Context, req daemonrpc.ListEntitiesRequest) (daemonrpc.ListEntitiesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listRequests = append(f.listRequests, req)
	out := make([]daemonrpc.OperatorEntity, 0, len(f.entities))
	for _, entity := range f.entities {
		if req.Operation != "" && entity.Operation != req.Operation {
			continue
		}
		out = append(out, entity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return daemonrpc.ListEntitiesResponse{Entities: out}, nil
}

func (f *fakeDaemon) Snapshot(_ context.Context, req daemonrpc.SnapshotRequest) (daemonrpc.SnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshotRequests = append(f.snapshotRequests, req)
	return f.snapshot, nil
}

func (f *fakeDaemon) ListPayloadCommands(context.Context, daemonrpc.PayloadCommandListRequest) (daemonrpc.PayloadCommandListResponse, error) {
	return daemonrpc.PayloadCommandListResponse{}, nil
}

func (f *fakeDaemon) RunPayloadCommand(_ context.Context, req daemonrpc.PayloadCommandRunRequest) (daemonrpc.PayloadCommandRunResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payloadCommandRequests = append(f.payloadCommandRequests, req)
	if f.payloadCommandError != nil {
		return daemonrpc.PayloadCommandRunResponse{}, f.payloadCommandError
	}
	return f.payloadCommandResponse, nil
}

func (f *fakeDaemon) Close() error { return nil }
