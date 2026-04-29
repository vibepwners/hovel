package commands

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
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
	for _, name := range []string{"workspace", "chain", "target", "json", "no-color", "verbose", "debug"} {
		if !hasOption(definition, name) {
			t.Fatalf("throw definition missing %q option", name)
		}
	}
}

func TestRegistryHasRootUsesDefinitions(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})

	for _, root := range []string{"chain", "control", "modules", "targets", "throw"} {
		if !registry.HasRoot(root) {
			t.Fatalf("HasRoot(%q) = false, want true", root)
		}
	}
	if registry.HasRoot("shell") {
		t.Fatal(`HasRoot("shell") = true, want false`)
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
	recorder := &fakeRunRecorder{}
	runs := fakeRunClientFactory{recorder: recorder}
	plans := &fakePlanRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.Running(identity)},
		Runs:       runs,
		Plans:      plans,
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
	if recorder.socketPath != "/tmp/hovel.sock" {
		t.Fatalf("socket path = %q, want /tmp/hovel.sock", recorder.socketPath)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("run requests = %#v, want one request", recorder.requests)
	}
	if recorder.requests[0] != (RunMockExploitRequest{ModuleID: "mock-exploit", Target: "mock://target"}) {
		t.Fatalf("run request = %#v", recorder.requests[0])
	}
	wantPlan := ThrowPlanRecord{
		ID:         "plan-mock-exploit-mock---target",
		ApprovalID: "approval-mock-exploit-mock---target",
		Workspace:  ".hovel",
		Chain:      "mock-exploit",
		Targets:    []string{"mock://target"},
		Decision:   "operator-reviewed",
		Intent:     "throw chain mock-exploit against 1 target(s)",
	}
	if !reflect.DeepEqual(plans.records, []ThrowPlanRecord{wantPlan}) {
		t.Fatalf("plans = %#v, want %#v", plans.records, []ThrowPlanRecord{wantPlan})
	}
	payload, ok := result.JSON.(ThrowPayload)
	if !ok {
		t.Fatalf("json payload type = %T, want ThrowPayload", result.JSON)
	}
	wantPayload := ThrowPayload{
		Plan:    wantPlan.Payload(),
		Chain:   "mock-exploit",
		Targets: []string{"mock://target"},
		Results: []RunPayload{{
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
		}},
	}
	if !equalThrowPayload(payload, wantPayload) {
		t.Fatalf("payload = %#v, want %#v", payload, wantPayload)
	}
	if result.Log.Empty() {
		t.Fatal("throw log is empty")
	}
	if result.Log.Title != "HOVEL//THROW" {
		t.Fatalf("log title = %q, want HOVEL//THROW", result.Log.Title)
	}
	entries := result.Log.Entries()
	wantEntries := []operatorlog.Entry{
		operatorlog.Stage("0/5 review plan",
			operatorlog.Field{Name: "plan", Value: "plan-mock-exploit-mock---target"},
			operatorlog.Field{Name: "approval", Value: "approval-mock-exploit-mock---target"},
			operatorlog.Field{Name: "decision", Value: "operator-reviewed"},
		),
		operatorlog.Stage("1/5 prepare chain",
			operatorlog.Field{Name: "chain", Value: "mock-exploit"},
			operatorlog.Field{Name: "targets", Value: "1"},
		),
		operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: "mock-exploit"},
			operatorlog.Field{Name: "targets", Value: "1"},
		),
		operatorlog.Stage("2/5 engage target",
			operatorlog.Field{Name: "target", Value: "1/1"},
			operatorlog.Field{Name: "address", Value: "mock://target"},
		),
		operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: "run-1"},
			operatorlog.Field{Name: "target", Value: "mock://target"},
		),
		operatorlog.Stage("3/5 execute module",
			operatorlog.Field{Name: "target", Value: "1/1"},
			operatorlog.Field{Name: "module", Value: "mock-exploit"},
		),
		operatorlog.Info("module", "mock exploit completed"),
		operatorlog.Stage("4/5 record result",
			operatorlog.Field{Name: "target", Value: "1/1"},
			operatorlog.Field{Name: "run", Value: "run-1"},
		),
		operatorlog.Finding("finding", "finding",
			operatorlog.Field{Name: "severity", Value: "info"},
			operatorlog.Field{Name: "detail", Value: "detail"},
		),
		operatorlog.Artifact("artifact", "artifact",
			operatorlog.Field{Name: "kind", Value: "text"},
		),
		operatorlog.Stage("5/5 complete throw",
			operatorlog.Field{Name: "chain", Value: "mock-exploit"},
			operatorlog.Field{Name: "targets", Value: "1"},
		),
		operatorlog.Success("throw", "completed",
			operatorlog.Field{Name: "chain", Value: "mock-exploit"},
			operatorlog.Field{Name: "targets", Value: "1"},
		),
	}
	if !equalEntries(entries, wantEntries) {
		t.Fatalf("log entries = %#v, want %#v", entries, wantEntries)
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
	if !strings.Contains(listResult.Human, "mock-payload-provider") || !strings.Contains(listResult.Human, "payload_provider") {
		t.Fatalf("module list = %q", listResult.Human)
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "mock-simple-exploit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mock-simple-exploit exploit", "version", "runtime", "operator.confirmed_lab", "bool", "target.port", "port", "Next: chain add mock-simple-exploit"} {
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

func TestSessionCommandsRejectOneShotMode(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
	})
	definition, _ := registry.Find("targets", "add")

	_, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	})
	if err == nil || !strings.Contains(err.Error(), "hovel shell") {
		t.Fatalf("error = %v, want shell guidance", err)
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
	invalidPayload, ok := invalidResult.JSON.(ValidationPayload)
	if !ok {
		t.Fatalf("validation payload type = %T, want ValidationPayload", invalidResult.JSON)
	}
	wantIssues := []modulecatalog.Issue{
		{
			Scope:    modulecatalog.ScopeChain,
			StepID:   "step-1",
			ModuleID: "mock-simple-exploit",
			Key:      "operator.confirmed_lab",
			Message:  "missing chain config operator.confirmed_lab",
		},
		{
			Scope:   modulecatalog.ScopeTarget,
			Message: "chain has no targets",
		},
	}
	if invalidPayload.Valid || !reflect.DeepEqual(invalidPayload.Issues, wantIssues) {
		t.Fatalf("validation payload = %#v, want issues %#v", invalidPayload, wantIssues)
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
	if !strings.Contains(chainConfigResult.Human, "Chain config") || !strings.Contains(chainConfigResult.Human, "operator.confirmed_lab") || !strings.Contains(chainConfigResult.Human, "true") {
		t.Fatalf("chain config = %q", chainConfigResult.Human)
	}
	targetConfigResult, err := targetConfigListDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(targetConfigResult.Human, "Target config mock://target") || !strings.Contains(targetConfigResult.Human, "target.port") || !strings.Contains(targetConfigResult.Human, "22") {
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
	if strings.Contains(result.Human, "hunter2") || !strings.Contains(result.Human, "auth.password") || !strings.Contains(result.Human, "<secret:set>") {
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

func equalThrowPayload(got, want ThrowPayload) bool {
	return reflect.DeepEqual(got, want)
}

func equalEntries(got, want []operatorlog.Entry) bool {
	return reflect.DeepEqual(got, want)
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

type fakeRunRecorder struct {
	socketPath string
	requests   []RunMockExploitRequest
}

type fakePlanRecorder struct {
	records []ThrowPlanRecord
}

func (r *fakePlanRecorder) RecordThrowPlan(_ context.Context, plan ThrowPlanRecord) error {
	r.records = append(r.records, plan)
	return nil
}

type fakeRunClientFactory struct {
	recorder *fakeRunRecorder
}

func (f fakeRunClientFactory) DialRunClient(socketPath string) (RunClient, error) {
	if f.recorder != nil {
		f.recorder.socketPath = socketPath
	}
	return fakeRunClient{recorder: f.recorder}, nil
}

type fakeRunClient struct {
	recorder *fakeRunRecorder
}

func (fakeRunClient) Close() error {
	return nil
}

func (c fakeRunClient) RunMockExploit(_ context.Context, req RunMockExploitRequest) (RunMockExploitResponse, error) {
	if c.recorder != nil {
		c.recorder.requests = append(c.recorder.requests, req)
	}
	return RunMockExploitResponse{
		RunID:    "run-1",
		ModuleID: req.ModuleID,
		Target:   req.Target,
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
