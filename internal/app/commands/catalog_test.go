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
		Modules:    exampleCatalog(),
	})

	for _, path := range [][]string{
		{"control", "init"},
		{"control", "daemon", "status"},
		{"op", "create"},
		{"op", "inspect"},
		{"op", "list"},
		{"op", "use"},
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
		{"module", "inspect"},
		{"module", "list"},
		{"module", "search"},
		{"chain", "use"},
		{"target", "add"},
		{"target", "clear"},
		{"target", "config", "list"},
		{"target", "config", "set"},
		{"target", "config", "unset"},
		{"throw"},
		{"throw", "inspect"},
		{"throw", "list"},
	} {
		if _, ok := registry.Find(path...); !ok {
			t.Fatalf("missing command path %q", strings.Join(path, " "))
		}
	}
	for _, alias := range [][]string{
		{"chains", "create"},
		{"modules", "list"},
		{"targets", "add"},
		{"throws", "list"},
	} {
		if _, ok := registry.Find(alias...); !ok {
			t.Fatalf("legacy alias %q missing", strings.Join(alias, " "))
		}
	}
}

func TestThrowDefinitionRequiresDaemonAndCentralOptions(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
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
		Modules:    exampleCatalog(),
	})

	for _, root := range []string{"op", "chain", "chains", "control", "module", "modules", "target", "targets", "throw", "throws"} {
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
		Modules:    exampleCatalog(),
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
		Modules:    exampleCatalog(),
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
		Modules:    exampleCatalog(),
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
	if recorder.requests[0].ThrowStarted == "" {
		t.Fatal("throw start timestamp was not propagated to run request")
	}
	recorder.requests[0].ThrowStarted = ""
	if !reflect.DeepEqual(recorder.requests[0], RunMockExploitRequest{ModuleID: "mock-exploit@v0.0.0-example", Target: "mock://target", ChainConfig: map[string]string{}}) {
		t.Fatalf("run request = %#v", recorder.requests[0])
	}
	wantPlan := ThrowPlanRecord{
		ID:             "plan-mock-exploit-mock---target",
		ConfirmationID: "confirmation-mock-exploit-mock---target",
		Workspace:      ".hovel",
		Chain:          "mock-exploit",
		Targets:        []string{"mock://target"},
		Review:         "operator-confirmed",
		Intent:         "throw chain mock-exploit against 1 target(s)",
	}
	if !reflect.DeepEqual(plans.records, []ThrowPlanRecord{wantPlan}) {
		t.Fatalf("plans = %#v, want %#v", plans.records, []ThrowPlanRecord{wantPlan})
	}
	payload, ok := result.JSON.(ThrowPayload)
	if !ok {
		t.Fatalf("json payload type = %T, want ThrowPayload", result.JSON)
	}
	if payload.Chain != "mock-exploit" || len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("payload route = %#v", payload)
	}
	if !reflect.DeepEqual(payload.Plan, wantPlan.Payload()) {
		t.Fatalf("payload plan = %#v, want %#v", payload.Plan, wantPlan.Payload())
	}
	if len(payload.Results) != 1 {
		t.Fatalf("payload results = %#v, want one result", payload.Results)
	}
	run := payload.Results[0]
	if run.RunID != "run-1" || run.ModuleID != "mock-exploit@v0.0.0-example" || run.Target != "mock://target" || run.State != "succeeded" {
		t.Fatalf("payload run = %#v", run)
	}
	if len(run.Findings) != 1 || len(run.Artifacts) != 1 || len(run.Logs) != 1 {
		t.Fatalf("payload run details = %#v", run)
	}
	if result.Log.Empty() {
		t.Fatal("throw log is empty")
	}
	if result.Log.Title != "HOVEL//THROW" {
		t.Fatalf("log title = %q, want HOVEL//THROW", result.Log.Title)
	}
	entries := result.Log.Entries()
	for _, want := range []string{"0/5 review plan", "chain staged", "target engaged", "mock exploit started", "completed"} {
		if !hasLogMessage(entries, want) {
			t.Fatalf("log entries missing %q: %#v", want, entries)
		}
	}
}

func TestChainCRUDAndTargetHandlersUpdateSession(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
	})
	createDefinition, _ := registry.Find("chain", "create")
	useDefinition, _ := registry.Find("chain", "use")
	targetDefinition, _ := registry.Find("target", "add")
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
		t.Fatalf("beta target = %#v", state.Targets)
	}

	listResult, err := listDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  alpha steps=0 targets=1 topic=operation/default/chain/alpha/logs",
		"* beta steps=0 targets=1 topic=operation/default/chain/beta/logs",
	} {
		if !strings.Contains(listResult.Human, want) {
			t.Fatalf("chain list missing %q:\n%s", want, listResult.Human)
		}
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectResult.Human, "Chain beta steps=0 targets=1 config=0 topic=operation/default/chain/beta/logs") {
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
		t.Fatalf("renamed target = %#v", state.Targets)
	}
	if state.LogTopic != "operation/default/chain/renamed/logs" {
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

func TestOperationHandlersSegmentChainState(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
	})
	opUseDefinition, _ := registry.Find("op", "use")
	opListDefinition, _ := registry.Find("op", "list")
	opInspectDefinition, _ := registry.Find("op", "inspect")
	chainUseDefinition, _ := registry.Find("chain", "use")
	targetDefinition, _ := registry.Find("target", "add")

	if _, err := opUseDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"operation": "redteam-lab"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := chainUseDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"chain": "alpha"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"target": "mock://alpha"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := opUseDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"operation": "afterparty"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := chainUseDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"chain": "beta"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{Positionals: map[string]string{"target": "mock://beta"}}); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if state.ActiveOperation != "afterparty" || state.ActiveChain != "beta" {
		t.Fatalf("active attachment = %s/%s, want afterparty/beta", state.ActiveOperation, state.ActiveChain)
	}
	if len(state.Targets) != 1 || state.Targets[0] != "mock://beta" {
		t.Fatalf("afterparty beta target = %#v", state.Targets)
	}
	listResult, err := opListDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  redteam-lab chains=1", "* afterparty chains=1"} {
		if !strings.Contains(listResult.Human, want) {
			t.Fatalf("op list missing %q:\n%s", want, listResult.Human)
		}
	}
	inspectResult, err := opInspectDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectResult.Human, "Operation afterparty chains=1 active_chain=beta") {
		t.Fatalf("op inspect = %q", inspectResult.Human)
	}
}

func TestModuleCommandsListInspectAndSearchBuiltIns(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
	})
	listDefinition, _ := registry.Find("module", "list")
	inspectDefinition, _ := registry.Find("module", "inspect")
	searchDefinition, _ := registry.Find("module", "search")

	listResult, err := listDefinition.Execute(context.Background(), Invocation{
		Options: map[string]string{"type": "survey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listResult.Human, "mock-survey") || !strings.Contains(listResult.Human, "survey") {
		t.Fatalf("module list = %q", listResult.Human)
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "mock-exploit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mock-exploit@v0.0.0-example exploit", "version", "runtime", "operator.confirmed_lab", "bool", "target.port", "port", "Next: chain add mock-exploit@v0.0.0-example"} {
		if !strings.Contains(inspectResult.Human, want) {
			t.Fatalf("inspect missing %q:\n%s", want, inspectResult.Human)
		}
	}

	searchResult, err := searchDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"query": "survey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(searchResult.Human, "mock-survey") {
		t.Fatalf("search result = %q", searchResult.Human)
	}
}

func TestSessionCommandsRejectOneShotMode(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
	})
	definition, _ := registry.Find("target", "add")

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
		Modules:    exampleCatalog(),
		Session:    session,
	})
	useDefinition, _ := registry.Find("chain", "use")
	addDefinition, _ := registry.Find("chain", "add")
	chainConfigSetDefinition, _ := registry.Find("chain", "config", "set")
	chainConfigListDefinition, _ := registry.Find("chain", "config", "list")
	targetDefinition, _ := registry.Find("target", "add")
	targetConfigSetDefinition, _ := registry.Find("target", "config", "set")
	targetConfigListDefinition, _ := registry.Find("target", "config", "list")
	validateDefinition, _ := registry.Find("chain", "validate")

	if _, err := useDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := addDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "mock-exploit"},
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
			ModuleID: "mock-exploit@v0.0.0-example",
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

func TestTargetHandlerRequiresActiveChain(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
	})
	targetDefinition, _ := registry.Find("target", "add")

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
	if _, err := session.AddModule("mock-exploit"); err != nil {
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
		Modules:    exampleCatalog(),
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
		t.Fatalf("throw target = %#v, want alpha chain targets", payload.Targets)
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

func TestThrowActiveChainRejectsEmptyChain(t *testing.T) {
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           123,
		SocketPath:    "/tmp/hovel.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := operatorsession.New()
	if err := session.UseChain("empty"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target"); err != nil {
		t.Fatal(err)
	}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.Running(identity)},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
	})
	throwDefinition, _ := registry.Find("throw")

	_, err = throwDefinition.Execute(context.Background(), Invocation{Options: map[string]string{"workspace": ".hovel"}})
	if err == nil || !strings.Contains(err.Error(), "chain empty has no modules") {
		t.Fatalf("throw error = %v, want empty chain error", err)
	}
}

func TestThrowActiveChainExecutesConfiguredSteps(t *testing.T) {
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel",
		PID:           123,
		SocketPath:    "/tmp/hovel.sock",
		StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := operatorsession.New()
	if err := session.UseChain("test1"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("operator.confirmed_lab", "true"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://target", "target.host", "router-01"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://target", "target.port", "22"); err != nil {
		t.Fatal(err)
	}
	recorder := &fakeRunRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{status: daemon.Running(identity)},
		Runs:       fakeRunClientFactory{recorder: recorder},
		Modules:    exampleCatalog(),
		Session:    session,
	})
	throwDefinition, _ := registry.Find("throw")

	result, err := throwDefinition.Execute(context.Background(), Invocation{Options: map[string]string{"workspace": ".hovel"}})
	if err != nil {
		t.Fatal(err)
	}
	payload := result.JSON.(ThrowPayload)
	if payload.Chain != "test1" {
		t.Fatalf("payload chain = %q, want test1", payload.Chain)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("run requests = %#v, want one request", recorder.requests)
	}
	want := RunMockExploitRequest{
		ModuleID:    "mock-exploit",
		Target:      "mock://target",
		ChainConfig: map[string]string{"operator.confirmed_lab": "true"},
		TargetConfig: map[string]string{
			"target.host": "router-01",
			"target.port": "22",
		},
	}
	if recorder.requests[0].ThrowStarted == "" {
		t.Fatal("throw start timestamp was not propagated to run request")
	}
	recorder.requests[0].ThrowStarted = ""
	if !reflect.DeepEqual(recorder.requests[0], want) {
		t.Fatalf("run request = %#v, want %#v", recorder.requests[0], want)
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

func exampleCatalog() modulecatalog.Catalog {
	return modulecatalog.New(
		modulecatalog.Module{
			ID:          "mock-survey",
			Name:        "Mock Survey",
			Type:        modulecatalog.TypeSurvey,
			Version:     "v0.0.0-example",
			Summary:     "Collect example target facts.",
			Description: "Example Python survey module for the Hovel stdio JSON-RPC runtime.",
			Tags:        []string{"example", "survey", "python"},
			RuntimeKind: "jsonrpc-stdio",
			Author:      "hovel",
			Enabled:     true,
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
		modulecatalog.Module{
			ID:          "mock-exploit",
			Name:        "Mock Exploit",
			Type:        modulecatalog.TypeExploit,
			Version:     "v0.0.0-example",
			Summary:     "Run an example exploit flow.",
			Description: "Example Python exploit module for the Hovel stdio JSON-RPC runtime.",
			Tags:        []string{"example", "exploit", "python"},
			RuntimeKind: "jsonrpc-stdio",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "operator.confirmed_lab", Type: modulecatalog.ValueBool, Required: true, Description: "Operator confirmed this is an authorized lab."},
			},
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
	)
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
		Logs: []LogEntry{{
			Level:   "info",
			Logger:  req.ModuleID,
			Message: "mock exploit started",
			Fields:  map[string]string{"target": req.Target},
		}},
		Findings: []Finding{{Title: "finding", Severity: "info", Detail: "detail"}},
		Artifacts: []Artifact{{
			Name: "artifact",
			Kind: "text",
			Data: "data",
		}},
	}, nil
}
