package commands

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

func TestHovelRegistryContainsCommandModeSurface(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})

	for _, path := range [][]string{
		{"control", "init"},
		{"control", "daemon", "status"},
		{"chain", "create"},
		{"chain", "delete"},
		{"chain", "add"},
		{"chain", "config", "list"},
		{"chain", "config", "set"},
		{"chain", "config", "unset"},
		{"chain", "inspect"},
		{"chain", "list"},
		{"chain", "logs"},
		{"chain", "rename"},
		{"chain", "validate"},
		{"modules", "inspect"},
		{"modules", "list"},
		{"modules", "search"},
		{"chain", "use"},
		{"targets", "add"},
		{"targets", "clear"},
		{"targets", "config", "list"},
		{"targets", "config", "set"},
		{"targets", "config", "unset"},
		{"throw"},
	} {
		if _, ok := registry.Find(path...); !ok {
			t.Fatalf("missing command path %q", strings.Join(path, " "))
		}
	}
}

func TestThrowDefinitionRequiresDaemonAndCentralOptions(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})
	definition, ok := registry.Find("throw")
	if !ok {
		t.Fatal("throw definition not found")
	}
	if !definition.RequiresDaemon {
		t.Fatal("throw should require a daemon")
	}
	if len(definition.Positionals) != 0 {
		t.Fatalf("positionals = %#v, want none", definition.Positionals)
	}
	for _, name := range []string{"workspace", "chain", "target", "json"} {
		if !hasOption(definition, name) {
			t.Fatalf("throw definition missing %q option", name)
		}
	}
}

func TestInitHandlerUsesWorkspaceService(t *testing.T) {
	service := fakeWorkspaceService{}
	registry := HovelRegistry(Runtime{
		Workspaces: service,
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})
	definition, _ := registry.Find("control", "init")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"name":      "ops",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "Initialized workspace ops") {
		t.Fatalf("human result = %q", result.Human)
	}
	payload, ok := result.JSON.(InitPayload)
	if !ok {
		t.Fatalf("json payload type = %T, want InitPayload", result.JSON)
	}
	if payload.Workspace.Name != "ops" {
		t.Fatalf("workspace name = %q, want ops", payload.Workspace.Name)
	}
}

func TestThrowHandlerRejectsMissingDaemon(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.NotRunning(".hovel")},
		Runs:       fakeRunClientFactory{},
	})
	definition, _ := registry.Find("throw")

	_, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "daemon is not running") {
		t.Fatalf("error = %v, want daemon not running", err)
	}
}

func TestThrowHandlerUsesDaemonSocket(t *testing.T) {
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           12345,
		SocketPath:    "/tmp/hovel.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	runs := fakeRunClientFactory{}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.Running(identity)},
		Runs:       runs,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "Throw completed chain mock-exploit") {
		t.Fatalf("human result = %q", result.Human)
	}
	payload, ok := result.JSON.(ThrowPayload)
	if !ok {
		t.Fatalf("json payload type = %T, want ThrowPayload", result.JSON)
	}
	if payload.Chain != "mock-exploit" {
		t.Fatalf("chain = %q", payload.Chain)
	}
	if len(payload.Results) != 1 || payload.Results[0].Target != "mock://target" {
		t.Fatalf("results = %#v", payload.Results)
	}
	if result.Log.Empty() {
		t.Fatal("throw log is empty")
	}
	if result.Log.Title != "HOVEL//THROW" {
		t.Fatalf("log title = %q, want HOVEL//THROW", result.Log.Title)
	}
	if len(result.Log.Entries()) < 4 {
		t.Fatalf("log entry count = %d, want at least 4", len(result.Log.Entries()))
	}
}

func TestChainCRUDAndTargetHandlersUpdateSession(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Session:    session,
	})
	createDefinition, _ := registry.Find("chain", "create")
	useDefinition, _ := registry.Find("chain", "use")
	targetDefinition, _ := registry.Find("targets", "add")
	listDefinition, _ := registry.Find("chain", "list")
	inspectDefinition, _ := registry.Find("chain", "inspect")
	renameDefinition, _ := registry.Find("chain", "rename")
	deleteDefinition, _ := registry.Find("chain", "delete")

	if _, err := createDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if session.Snapshot().ActiveChain != "alpha" {
		t.Fatalf("active chain = %q, want alpha after create", session.Snapshot().ActiveChain)
	}
	if _, err := useDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := useDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "beta"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://beta"},
	}); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if state.ActiveChain != "beta" {
		t.Fatalf("active chain = %q, want beta", state.ActiveChain)
	}
	if len(state.Targets) != 1 || state.Targets[0] != "mock://beta" {
		t.Fatalf("beta targets = %#v", state.Targets)
	}

	listResult, err := listDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  alpha steps=0 targets=1 topic=chain/alpha/logs",
		"* beta steps=0 targets=1 topic=chain/beta/logs",
	} {
		if !strings.Contains(listResult.Human, want) {
			t.Fatalf("chain list missing %q:\n%s", want, listResult.Human)
		}
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectResult.Human, "Chain beta steps=0 targets=1 config=0 topic=chain/beta/logs") {
		t.Fatalf("inspect result = %q", inspectResult.Human)
	}

	if _, err := renameDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "beta", "name": "renamed"},
	}); err != nil {
		t.Fatal(err)
	}
	state = session.Snapshot()
	if state.ActiveChain != "renamed" {
		t.Fatalf("active chain = %q, want renamed", state.ActiveChain)
	}
	if len(state.Targets) != 1 || state.Targets[0] != "mock://beta" {
		t.Fatalf("renamed targets = %#v", state.Targets)
	}
	if state.LogTopic != "chain/renamed/logs" {
		t.Fatalf("renamed log topic = %q", state.LogTopic)
	}

	if _, err := deleteDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "renamed"},
	}); err != nil {
		t.Fatal(err)
	}
	if session.Snapshot().ActiveChain != "" {
		t.Fatal("deleting active chain should clear active chain")
	}
}

func TestModuleCommandsListInspectAndSearchBuiltIns(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})
	listDefinition, _ := registry.Find("modules", "list")
	inspectDefinition, _ := registry.Find("modules", "inspect")
	searchDefinition, _ := registry.Find("modules", "search")

	listResult, err := listDefinition.Execute(context.Background(), Invocation{
		Options: map[string]string{"type": "payload_provider"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listResult.Human, "mock-payload-provider payload_provider") {
		t.Fatalf("module list = %q", listResult.Human)
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "mock-simple-exploit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mock-simple-exploit exploit", "operator.confirmed_lab bool required", "target.port port required"} {
		if !strings.Contains(inspectResult.Human, want) {
			t.Fatalf("inspect missing %q:\n%s", want, inspectResult.Human)
		}
	}

	searchResult, err := searchDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"query": "kitchen"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(searchResult.Human, "mock-config-kitchen-sink") {
		t.Fatalf("search result = %q", searchResult.Human)
	}
}

func TestChainAddConfigAndValidateHandlers(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Session:    session,
	})
	useDefinition, _ := registry.Find("chain", "use")
	addDefinition, _ := registry.Find("chain", "add")
	chainConfigSetDefinition, _ := registry.Find("chain", "config", "set")
	chainConfigListDefinition, _ := registry.Find("chain", "config", "list")
	targetDefinition, _ := registry.Find("targets", "add")
	targetConfigSetDefinition, _ := registry.Find("targets", "config", "set")
	targetConfigListDefinition, _ := registry.Find("targets", "config", "list")
	validateDefinition, _ := registry.Find("chain", "validate")

	if _, err := useDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := addDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "mock-simple-exploit"},
	}); err != nil {
		t.Fatal(err)
	}
	invalidResult, err := validateDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(invalidResult.Human, "Chain alpha invalid") || !strings.Contains(invalidResult.Human, "missing chain config operator.confirmed_lab") {
		t.Fatalf("invalid validation = %q", invalidResult.Human)
	}

	if _, err := chainConfigSetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"key": "operator.confirmed_lab", "value": "true"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetConfigSetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target", "key": "target.host", "value": "router-01"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetConfigSetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target", "key": "target.port", "value": "22"},
	}); err != nil {
		t.Fatal(err)
	}

	chainConfigResult, err := chainConfigListDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(chainConfigResult.Human, "operator.confirmed_lab=true") {
		t.Fatalf("chain config = %q", chainConfigResult.Human)
	}
	targetConfigResult, err := targetConfigListDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(targetConfigResult.Human, "target.port=22") {
		t.Fatalf("target config = %q", targetConfigResult.Human)
	}

	validResult, err := validateDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if validResult.Human != "Chain alpha valid" {
		t.Fatalf("valid result = %q", validResult.Human)
	}
	payload, ok := validResult.JSON.(ValidationPayload)
	if !ok || !payload.Valid {
		t.Fatalf("validation payload = %#v", validResult.JSON)
	}
}

func TestSecretConfigListRedactsValues(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Session:    session,
	})
	useDefinition, _ := registry.Find("chain", "use")
	addDefinition, _ := registry.Find("chain", "add")
	targetDefinition, _ := registry.Find("targets", "add")
	targetConfigSetDefinition, _ := registry.Find("targets", "config", "set")
	targetConfigListDefinition, _ := registry.Find("targets", "config", "list")

	if _, err := useDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"chain": "alpha"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := addDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"module": "mock-auth-survey"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"target": "mock://target"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetConfigSetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target", "key": "auth.password", "value": "hunter2"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := targetConfigListDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Human, "hunter2") || !strings.Contains(result.Human, "auth.password=<secret:set>") {
		t.Fatalf("target config was not redacted: %q", result.Human)
	}
}

func TestTargetHandlerRequiresActiveChain(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Session:    session,
	})
	targetDefinition, _ := registry.Find("targets", "add")

	_, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	})
	if err == nil || !strings.Contains(err.Error(), "active chain is required") {
		t.Fatalf("error = %v, want active chain required", err)
	}
}

func TestThrowHandlerStoresLogsOnPayloadChain(t *testing.T) {
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           12345,
		SocketPath:    "/tmp/hovel.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := operatorsession.New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.Running(identity)},
		Runs:       fakeRunClientFactory{},
		Session:    session,
	})
	throwDefinition, _ := registry.Find("throw")

	result, err := throwDefinition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "alpha",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := result.JSON.(ThrowPayload)
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://alpha" {
		t.Fatalf("throw targets = %#v, want alpha chain targets", payload.Targets)
	}
	if session.Snapshot().ActiveChain != "beta" {
		t.Fatalf("active chain = %q, want beta", session.Snapshot().ActiveChain)
	}
	if logs := session.ActiveLogs(); len(logs) != 0 {
		t.Fatalf("beta logs = %#v, want none", logs)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if logs := session.ActiveLogs(); !hasLogMessage(logs, "chain staged") {
		t.Fatalf("alpha logs = %#v", logs)
	}
}

func hasLogMessage(logs []operatorlog.Entry, message string) bool {
	for _, entry := range logs {
		if entry.Message == message {
			return true
		}
	}
	return false
}

func hasOption(definition Definition, name string) bool {
	for _, option := range definition.Options {
		if option.Name == name {
			return true
		}
	}
	return false
}

type fakeWorkspaceService struct{}

func (fakeWorkspaceService) InitWorkspace(context.Context, services.InitWorkspaceRequest) (services.InitWorkspaceResult, error) {
	id, _ := workspace.NewID("workspace-1")
	name, _ := workspace.NewName("ops")
	ws, _ := workspace.New(id, name, ".hovel")
	return services.InitWorkspaceResult{Workspace: ws, Created: true}, nil
}

type fakeDaemonService struct {
	status daemon.Status
}

func (s fakeDaemonService) Status(context.Context, services.DaemonStatusRequest) (daemon.Status, error) {
	if s.status.State == "" {
		return daemon.NotRunning(".hovel"), nil
	}
	return s.status, nil
}

type fakeRunClientFactory struct{}

func (fakeRunClientFactory) DialRunClient(string) (RunClient, error) {
	return fakeRunClient{}, nil
}

type fakeRunClient struct{}

func (fakeRunClient) Close() error {
	return nil
}

func (fakeRunClient) RunMockExploit(context.Context, RunMockExploitRequest) (RunMockExploitResponse, error) {
	return RunMockExploitResponse{
		RunID:    "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
		State:    "succeeded",
		Summary:  "mock exploit completed",
		Findings: []Finding{{Title: "finding", Severity: "info", Detail: "detail"}},
		Artifacts: []Artifact{{
			Name: "artifact",
			Kind: "text",
			Data: "data",
		}},
	}, nil
}
