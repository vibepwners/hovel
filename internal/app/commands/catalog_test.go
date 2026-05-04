package commands

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
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
		{"artifact", "inspect"},
		{"artifact", "list"},
		{"control", "init"},
		{"control", "daemon", "status"},
		{"review"},
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
		{"chain", "load"},
		{"chain", "logs"},
		{"chain", "rename"},
		{"chain", "save"},
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
		{"confirm"},
		{"throw"},
		{"throw", "inspect"},
		{"throw", "list"},
	} {
		if _, ok := registry.Find(path...); !ok {
			t.Fatalf("missing command path %q", strings.Join(path, " "))
		}
	}
	for _, alias := range [][]string{
		{"artifacts", "inspect"},
		{"artifacts", "list"},
		{"chains", "create"},
		{"chains", "load"},
		{"chains", "save"},
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
	if got, want := definition.Positionals, []Positional{{Name: "file", Help: "Configured chain YAML file", Required: false}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("positionals = %#v, want %#v", got, want)
	}
	for _, name := range []string{"workspace", "chain", "target", "now", "json", "no-color", "verbose", "debug"} {
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

	for _, root := range []string{"op", "chain", "chains", "confirm", "control", "module", "modules", "target", "targets", "throw", "throws"} {
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
	confirmations := &fakeConfirmationRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          runs,
		Modules:       exampleCatalog(),
		Plans:         plans,
		Confirmations: confirmations,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
		Input: &fakeInput{answer: "yes"},
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
	if !reflect.DeepEqual(recorder.requests[0], RunMockExploitRequest{Operation: operatorsession.DefaultOperation, Chain: "mock-exploit", ModuleID: "mock-exploit@v0.0.0-example", Target: "mock://target", ChainConfig: map[string]string{}}) {
		t.Fatalf("run request = %#v", recorder.requests[0])
	}
	wantPlan := newThrowPlanForExecution(".hovel", throwExecution{Operation: operatorsession.DefaultOperation, Chain: "mock-exploit", Targets: []string{"mock://target"}, Modules: []string{"mock-exploit@v0.0.0-example"}, ChainConfig: map[string]string{}, TargetConfigs: map[string]map[string]string{}})
	if !reflect.DeepEqual(plans.records, []ThrowPlanRecord{wantPlan}) {
		t.Fatalf("plans = %#v, want %#v", plans.records, []ThrowPlanRecord{wantPlan})
	}
	if len(confirmations.records) != 1 {
		t.Fatalf("confirmations = %#v, want one confirmation", confirmations.records)
	}
	confirmations.records[0].ConfirmedAt = ""
	wantConfirmation := ThrowConfirmationRecord{
		ID:        wantPlan.ConfirmationID,
		Workspace: ".hovel",
		PlanID:    wantPlan.ID,
		PlanHash:  wantPlan.PlanHash,
		ClientID:  "command",
		Method:    "typed_yes",
	}
	if !reflect.DeepEqual(confirmations.records[0], wantConfirmation) {
		t.Fatalf("confirmation = %#v, want %#v", confirmations.records[0], wantConfirmation)
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

func TestThrowRejectsUnconfirmedPlanWithoutPromptOrBypass(t *testing.T) {
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
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
	})
	definition, _ := registry.Find("throw")

	_, err = definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires confirmation") {
		t.Fatalf("error = %v, want confirmation required", err)
	}
	if len(recorder.requests) != 0 {
		t.Fatalf("run requests = %#v, want none", recorder.requests)
	}
}

func TestThrowCancelsWhenPromptDeclines(t *testing.T) {
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
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
	})
	definition, _ := registry.Find("throw")

	_, err = definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
		Input: &fakeInput{answer: "no"},
	})
	if err == nil || !strings.Contains(err.Error(), "throw cancelled") {
		t.Fatalf("error = %v, want throw cancelled", err)
	}
	if len(recorder.requests) != 0 {
		t.Fatalf("run requests = %#v, want none", recorder.requests)
	}
}

func TestThrowNowRecordsBypassConfirmation(t *testing.T) {
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
	confirmations := &fakeConfirmationRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: confirmations,
	})
	definition, _ := registry.Find("throw")

	_, err = definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
		Flags: map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmations.records) != 1 || confirmations.records[0].Method != "now_bypass" {
		t.Fatalf("confirmations = %#v, want now_bypass", confirmations.records)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("run requests = %#v, want one", recorder.requests)
	}
}

func TestConfirmHandlerRecordsPlanAndConfirmationWithoutRunning(t *testing.T) {
	plans := &fakePlanRecorder{}
	confirmations := &fakeConfirmationRecorder{}
	recorder := &fakeRunRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         plans,
		Confirmations: confirmations,
	})
	definition, _ := registry.Find("confirm")

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
	if len(recorder.requests) != 0 {
		t.Fatalf("run requests = %#v, want none", recorder.requests)
	}
	wantPlan := newThrowPlanForExecution(".hovel", throwExecution{Operation: operatorsession.DefaultOperation, Chain: "mock-exploit", Targets: []string{"mock://target"}, Modules: []string{"mock-exploit@v0.0.0-example"}, ChainConfig: map[string]string{}, TargetConfigs: map[string]map[string]string{}})
	if !reflect.DeepEqual(plans.records, []ThrowPlanRecord{wantPlan}) {
		t.Fatalf("plans = %#v, want %#v", plans.records, []ThrowPlanRecord{wantPlan})
	}
	if len(confirmations.records) != 1 {
		t.Fatalf("confirmations = %#v, want one", confirmations.records)
	}
	if confirmations.records[0].PlanHash != wantPlan.PlanHash || confirmations.records[0].Method != "preconfirmed" {
		t.Fatalf("confirmation = %#v, want preconfirmed for plan hash %s", confirmations.records[0], wantPlan.PlanHash)
	}
	if _, ok := result.JSON.(ThrowConfirmationRecord); !ok {
		t.Fatalf("json payload type = %T, want ThrowConfirmationRecord", result.JSON)
	}
}

func TestReviewHandlerRerunsTypedConfirmationWithoutRunning(t *testing.T) {
	plans := &fakePlanRecorder{}
	confirmations := &fakeConfirmationRecorder{}
	recorder := &fakeRunRecorder{}
	input := &fakeInput{answer: "yes"}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         plans,
		Confirmations: confirmations,
	})
	definition, _ := registry.Find("review")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
		Input: input,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.requests) != 0 {
		t.Fatalf("run requests = %#v, want none", recorder.requests)
	}
	if len(plans.records) != 1 {
		t.Fatalf("plans = %#v, want one", plans.records)
	}
	if len(confirmations.records) != 1 {
		t.Fatalf("confirmations = %#v, want one", confirmations.records)
	}
	if confirmations.records[0].PlanHash != plans.records[0].PlanHash || confirmations.records[0].Method != "reviewed_yes" {
		t.Fatalf("confirmation = %#v, want reviewed_yes for plan hash %s", confirmations.records[0], plans.records[0].PlanHash)
	}
	if input.prompt.Title != "THROW REVIEW" || input.prompt.Action != "confirm review" || input.prompt.RequiredLiteral != "yes" {
		t.Fatalf("prompt = %#v, want review confirmation prompt", input.prompt)
	}
	if !result.Log.Empty() {
		if result.Log.Title != "HOVEL//REVIEW" {
			t.Fatalf("review log title = %q, want HOVEL//REVIEW", result.Log.Title)
		}
	} else {
		t.Fatal("review result log is empty")
	}
	if result.Human != "" {
		t.Fatalf("human result = %q, want empty because review emits an operator log", result.Human)
	}
	if _, ok := result.JSON.(ThrowConfirmationRecord); !ok {
		t.Fatalf("json payload type = %T, want ThrowConfirmationRecord", result.JSON)
	}
}

func TestReviewHandlerCancelledDoesNotRecordConfirmation(t *testing.T) {
	plans := &fakePlanRecorder{}
	confirmations := &fakeConfirmationRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{},
		Runs:          fakeRunClientFactory{},
		Modules:       exampleCatalog(),
		Plans:         plans,
		Confirmations: confirmations,
	})
	definition, _ := registry.Find("review")

	_, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
		Input: &fakeInput{answer: "no"},
	})
	if err == nil || !strings.Contains(err.Error(), "review cancelled") {
		t.Fatalf("err = %v, want review cancelled", err)
	}
	if len(plans.records) != 1 {
		t.Fatalf("plans = %#v, want one reviewed plan", plans.records)
	}
	if len(confirmations.records) != 0 {
		t.Fatalf("confirmations = %#v, want none", confirmations.records)
	}
}

func TestThrowConfirmationPromptDisplaysReviewableConfiguration(t *testing.T) {
	plan := newThrowPlanForExecution(".hovel", throwExecution{
		Chain:   "alpha",
		Targets: []string{"mock://target"},
		Modules: []string{
			"mock-exploit@v0.0.0-example",
		},
		ChainConfig: map[string]string{
			"operator.confirmed_lab": "true",
			"payload.mode":           "survey",
		},
		TargetConfigs: map[string]map[string]string{
			"mock://target": {
				"target.host": "router-01",
				"target.port": "443",
			},
		},
	})

	prompt := throwConfirmationPrompt(plan, "throw")

	if got := promptFieldValue(prompt, "plan hash"); got != plan.PlanHash[:10] {
		t.Fatalf("plan hash field = %q, want short hash %q", got, plan.PlanHash[:10])
	}
	if got := promptFieldValue(prompt, "modules"); got != "mock-exploit@v0.0.0-example" {
		t.Fatalf("modules field = %q", got)
	}
	chainConfig := promptFieldValue(prompt, "chain config")
	for _, want := range []string{"operator.confirmed_lab=true", "payload.mode=survey"} {
		if !strings.Contains(chainConfig, want) {
			t.Fatalf("chain config = %q, missing %q", chainConfig, want)
		}
	}
	targetConfig := promptFieldValue(prompt, "target config")
	for _, want := range []string{"mock://target", "target.host=router-01", "target.port=443"} {
		if !strings.Contains(targetConfig, want) {
			t.Fatalf("target config = %q, missing %q", targetConfig, want)
		}
	}
}

func TestArtifactListAndInspectHandlersUseRepository(t *testing.T) {
	repository := &fakeArtifactRepository{records: []ArtifactRecord{{
		ID:        "artifact-abc",
		Workspace: ".hovel",
		ThrowID:   "throw-alpha",
		RunID:     "run-1",
		ModuleID:  "mock-exploit@v0.0.0-example",
		Target:    "mock://target",
		Name:      "transcript.txt",
		Kind:      "text/plain",
		Path:      "artifacts/throw-alpha/run-1/transcript.txt",
		SHA256:    "abc123",
		Size:      19,
		CreatedAt: "2026-05-03T12:00:00Z",
	}}}
	registry := HovelRegistry(Runtime{
		Workspaces:      fakeWorkspaceService{},
		Daemons:         fakeDaemonService{},
		Runs:            fakeRunClientFactory{},
		Modules:         exampleCatalog(),
		ArtifactRecords: repository,
	})
	listDefinition, _ := registry.Find("artifact", "list")
	inspectDefinition, _ := registry.Find("artifact", "inspect")

	listResult, err := listDefinition.Execute(context.Background(), Invocation{Options: map[string]string{"workspace": ".hovel"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listResult.Human, "artifact-abc") || !strings.Contains(listResult.Human, "transcript.txt") {
		t.Fatalf("artifact list = %q", listResult.Human)
	}
	if !reflect.DeepEqual(listResult.JSON, repository.records) {
		t.Fatalf("list json = %#v, want %#v", listResult.JSON, repository.records)
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"artifact": "artifact-abc"},
		Options:     map[string]string{"workspace": ".hovel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectResult.Human, "sha256     abc123") || !strings.Contains(inspectResult.Human, "path       artifacts/throw-alpha/run-1/transcript.txt") {
		t.Fatalf("artifact inspect = %q", inspectResult.Human)
	}
	if !reflect.DeepEqual(inspectResult.JSON, repository.records[0]) {
		t.Fatalf("inspect json = %#v, want %#v", inspectResult.JSON, repository.records[0])
	}
}

func TestThrowInspectCanIncludeStructuredEvents(t *testing.T) {
	plan := newThrowPlanForExecution(".hovel", throwExecution{Chain: "mock-exploit", Targets: []string{"mock://target"}, Modules: []string{"mock-exploit@v0.0.0-example"}, ChainConfig: map[string]string{}, TargetConfigs: map[string]map[string]string{}})
	evt := testEvent(t, "event-1", "hovel.throw.started", "throw started", event.Refs{WorkspaceID: ".hovel", Operation: "default", Chain: plan.Chain, ThrowID: throwRecordID(plan)})
	plans := &fakePlanRepository{records: []ThrowPlanRecord{plan}}
	events := &fakeEventRepository{events: []event.Event{evt}}
	registry := HovelRegistry(Runtime{
		Workspaces:   fakeWorkspaceService{},
		Daemons:      fakeDaemonService{},
		Runs:         fakeRunClientFactory{},
		Modules:      exampleCatalog(),
		ThrowPlans:   plans,
		EventRecords: events,
	})
	definition, _ := registry.Find("throw", "inspect")

	result, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"throw": plan.ID},
		Options:     map[string]string{"workspace": ".hovel"},
		Flags:       map[string]bool{"events": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "EVENTS") || !strings.Contains(result.Human, "hovel.throw.started") {
		t.Fatalf("inspect output = %q", result.Human)
	}
	payload, ok := result.JSON.(ThrowInspectPayload)
	if !ok {
		t.Fatalf("json payload = %T, want ThrowInspectPayload", result.JSON)
	}
	if len(payload.Events) != 1 {
		t.Fatalf("events = %#v, want one", payload.Events)
	}
	if got := events.filter.ThrowID; got != throwRecordID(plan) {
		t.Fatalf("event filter throw id = %q, want %q", got, throwRecordID(plan))
	}
}

func TestThrowUsesExistingConfirmationWithoutRecordingTypedYes(t *testing.T) {
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
	plan := newThrowPlanForExecution(".hovel", throwExecution{Chain: "mock-exploit", Targets: []string{"mock://target"}, Modules: []string{"mock-exploit@v0.0.0-example"}, ChainConfig: map[string]string{}, TargetConfigs: map[string]map[string]string{}})
	confirmations := &fakeConfirmationStore{
		records: []ThrowConfirmationRecord{
			newThrowConfirmation(plan, "command", "preconfirmed", time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)),
		},
	}
	recorder := &fakeRunRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:         fakeWorkspaceService{},
		Daemons:            fakeDaemonService{status: daemon.Running(identity)},
		Runs:               fakeRunClientFactory{recorder: recorder},
		Modules:            exampleCatalog(),
		Plans:              &fakePlanRecorder{},
		Confirmations:      confirmations,
		ThrowConfirmations: confirmations,
	})
	definition, _ := registry.Find("throw")

	_, err = definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "mock://target",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmations.records) != 1 {
		t.Fatalf("confirmations = %#v, want only existing preconfirmation", confirmations.records)
	}
	if confirmations.records[0].Method != "preconfirmed" {
		t.Fatalf("confirmation method = %q, want preconfirmed", confirmations.records[0].Method)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("run requests = %#v, want one", recorder.requests)
	}
}

func TestThrowChainFileUsesFileConfigWithoutSessionMutation(t *testing.T) {
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
	if err := session.UseChain("interactive"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	recorder := &fakeRunRecorder{}
	store := &fakeChainFileStore{reads: map[string]ChainFile{
		"alpha.chain.yaml": configuredChainFileFixture("alpha", "mock://target"),
	}}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
		Session:       session,
		ChainFiles:    store,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "alpha.chain.yaml"},
		Options:     map[string]string{"workspace": ".hovel"},
		Flags:       map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "Throw completed chain alpha") {
		t.Fatalf("human result = %q", result.Human)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("run requests = %#v, want one", recorder.requests)
	}
	wantRequest := RunMockExploitRequest{
		Operation:    operatorsession.DefaultOperation,
		Chain:        "alpha",
		ModuleID:     "mock-exploit@v0.0.0-example",
		Target:       "mock://target",
		ChainConfig:  map[string]string{"operator.confirmed_lab": "true"},
		TargetConfig: map[string]string{"target.host": "router-01", "target.port": "22"},
	}
	recorder.requests[0].ThrowStarted = ""
	if !reflect.DeepEqual(recorder.requests[0], wantRequest) {
		t.Fatalf("run request = %#v, want %#v", recorder.requests[0], wantRequest)
	}
	state := session.Snapshot()
	if state.ActiveChain != "interactive" || len(state.Targets) != 0 || state.Steps[0].ModuleID != "mock-survey@v0.0.0-example" {
		t.Fatalf("session mutated by file throw: %#v", state)
	}
}

func TestThrowRecordsThrowAndMaterializesArtifacts(t *testing.T) {
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
	throwRecorder := &fakeThrowRecorder{}
	artifactRecorder := &fakeArtifactRecorder{}
	eventRecorder := &fakeEventRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: &fakeRunRecorder{}},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Throws:        throwRecorder,
		Confirmations: &fakeConfirmationRecorder{},
		Artifacts:     artifactRecorder,
		Events:        eventRecorder,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{"workspace": ".hovel", "chain": "mock-exploit", "target": "mock://target"},
		Flags:   map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := result.JSON.(ThrowPayload)
	if len(throwRecorder.records) != 1 || throwRecorder.records[0].PlanHash != payload.Plan.PlanHash {
		t.Fatalf("throw records = %#v, want plan hash %s", throwRecorder.records, payload.Plan.PlanHash)
	}
	if len(artifactRecorder.materializations) != 1 {
		t.Fatalf("artifact materializations = %#v, want one", artifactRecorder.materializations)
	}
	if payload.Results[0].Artifacts[0].Data != "" {
		t.Fatalf("payload artifact data = %q, want scrubbed after materialization", payload.Results[0].Artifacts[0].Data)
	}
	for _, typ := range []string{"hovel.throw.planned", "hovel.throw.confirmed", "hovel.throw.started", "hovel.artifact.recorded", "hovel.throw.completed"} {
		if !hasStructuredEvent(eventRecorder.events, typ) {
			t.Fatalf("events = %#v, missing %s", eventRecorder.events, typ)
		}
	}
}

func TestThrowRegistersFileReferenceArtifacts(t *testing.T) {
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
	recorder := &fakeRunRecorder{artifacts: []Artifact{{Name: "loot.txt", Kind: "text/plain", Path: "/tmp/loot.txt"}}}
	artifactRecorder := &fakeArtifactRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
		Artifacts:     artifactRecorder,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{"workspace": ".hovel", "chain": "mock-exploit", "target": "mock://target"},
		Flags:   map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := result.JSON.(ThrowPayload)
	if len(artifactRecorder.materializations) != 1 || artifactRecorder.materializations[0].Artifact.Path != "/tmp/loot.txt" {
		t.Fatalf("artifact materializations = %#v, want file reference", artifactRecorder.materializations)
	}
	if payload.Results[0].Artifacts[0].Path != "/tmp/loot.txt" || payload.Results[0].Artifacts[0].Data != "" {
		t.Fatalf("payload artifact = %#v, want file reference without data", payload.Results[0].Artifacts[0])
	}
}

func TestThrowChainFileNonInteractiveRequiresNowOrPreconfirmation(t *testing.T) {
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
	store := &fakeChainFileStore{reads: map[string]ChainFile{
		"alpha.chain.yaml": configuredChainFileFixture("alpha", "mock://target"),
	}}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: &fakeRunRecorder{}},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
		ChainFiles:    store,
	})
	definition, _ := registry.Find("throw")

	_, err = definition.Execute(context.Background(), Invocation{
		Positionals:    map[string]string{"file": "alpha.chain.yaml"},
		Options:        map[string]string{"workspace": ".hovel"},
		NonInteractive: true,
	})
	if err == nil || !strings.Contains(err.Error(), "requires --now") {
		t.Fatalf("error = %v, want --now guidance", err)
	}
}

func TestThrowPlanHashIncludesReviewedConfigAndSteps(t *testing.T) {
	base := throwExecution{
		Chain:       "alpha",
		Targets:     []string{"mock://target"},
		Modules:     []string{"mock-exploit@v0.0.0-example"},
		ChainConfig: map[string]string{"operator.confirmed_lab": "true"},
		TargetConfigs: map[string]map[string]string{
			"mock://target": {"target.host": "router-01", "target.port": "22"},
		},
	}
	changedConfig := base
	changedConfig.ChainConfig = map[string]string{"operator.confirmed_lab": "false"}
	changedStep := base
	changedStep.Modules = []string{"mock-survey@v0.0.0-example"}

	baseHash := newThrowPlanForExecution(".hovel", base).PlanHash
	if baseHash == newThrowPlanForExecution(".hovel", changedConfig).PlanHash {
		t.Fatal("plan hash did not change when chain config changed")
	}
	if baseHash == newThrowPlanForExecution(".hovel", changedStep).PlanHash {
		t.Fatal("plan hash did not change when step modules changed")
	}
}

func TestConfirmChainFileRecordsSamePlanAsThrowChainFile(t *testing.T) {
	plans := &fakePlanRecorder{}
	confirmations := &fakeConfirmationStore{}
	store := &fakeChainFileStore{reads: map[string]ChainFile{
		"alpha.chain.yaml": configuredChainFileFixture("alpha", "mock://target"),
	}}
	registry := HovelRegistry(Runtime{
		Workspaces:         fakeWorkspaceService{},
		Daemons:            fakeDaemonService{},
		Runs:               fakeRunClientFactory{},
		Modules:            exampleCatalog(),
		Plans:              plans,
		Confirmations:      confirmations,
		ThrowConfirmations: confirmations,
		ChainFiles:         store,
	})
	confirmDefinition, _ := registry.Find("confirm")

	_, err := confirmDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "alpha.chain.yaml"},
		Options:     map[string]string{"workspace": ".hovel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPlan := newThrowPlanForExecution(".hovel", throwExecution{
		Operation:   operatorsession.DefaultOperation,
		Chain:       "alpha",
		Targets:     []string{"mock://target"},
		Modules:     []string{"mock-exploit@v0.0.0-example"},
		ChainConfig: map[string]string{"operator.confirmed_lab": "true"},
		TargetConfigs: map[string]map[string]string{
			"mock://target": {"target.host": "router-01", "target.port": "22"},
		},
	})
	if !reflect.DeepEqual(plans.records, []ThrowPlanRecord{wantPlan}) {
		t.Fatalf("plans = %#v, want %#v", plans.records, []ThrowPlanRecord{wantPlan})
	}
	if len(confirmations.records) != 1 || confirmations.records[0].PlanHash != wantPlan.PlanHash {
		t.Fatalf("confirmations = %#v, want plan hash %s", confirmations.records, wantPlan.PlanHash)
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

func TestChainSaveWritesConfiguredAndTemplateFiles(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("operator.confirmed_lab", "true"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://target", "target.host", "router-01"); err != nil {
		t.Fatal(err)
	}
	store := &fakeChainFileStore{writes: map[string]ChainFile{}}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
		ChainFiles: store,
	})
	saveDefinition, _ := registry.Find("chain", "save")

	result, err := saveDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "alpha.chain.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "Chain alpha saved as configured") {
		t.Fatalf("save result = %q", result.Human)
	}
	configured := store.writes["alpha.chain.yaml"]
	if configured.APIVersion != "hovel.dev/v1alpha1" || configured.Kind != "Chain" || configured.Metadata.Name != "alpha" {
		t.Fatalf("configured metadata = %#v", configured)
	}
	if configured.Spec.Mode != "configured" {
		t.Fatalf("mode = %q, want configured", configured.Spec.Mode)
	}
	if got, want := configured.Spec.Steps, []ChainFileStep{{ID: "step-1", Uses: "module:mock-exploit@v0.0.0-example"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("steps = %#v, want %#v", got, want)
	}
	if configured.Spec.Config["operator.confirmed_lab"] != "true" {
		t.Fatalf("chain config = %#v", configured.Spec.Config)
	}
	if got, want := configured.Spec.Targets, []ChainFileTarget{{ID: "mock://target", Config: map[string]string{"target.host": "router-01"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}

	if _, err := saveDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "alpha.template.yaml"},
		Flags:       map[string]bool{"template": true},
	}); err != nil {
		t.Fatal(err)
	}
	template := store.writes["alpha.template.yaml"]
	if template.Spec.Mode != "template" {
		t.Fatalf("template mode = %q, want template", template.Spec.Mode)
	}
	if len(template.Spec.Targets) != 0 || len(template.Spec.Config) != 0 || len(template.Spec.TargetConfigs) != 0 {
		t.Fatalf("template persisted configured data: %#v", template.Spec)
	}
}

func TestChainLoadRestoresConfiguredChainFile(t *testing.T) {
	session := operatorsession.New()
	store := &fakeChainFileStore{
		reads: map[string]ChainFile{
			"alpha.chain.yaml": {
				APIVersion: "hovel.dev/v1alpha1",
				Kind:       "Chain",
				Metadata:   ChainFileMetadata{Name: "alpha"},
				Spec: ChainFileSpec{
					Mode: "configured",
					Steps: []ChainFileStep{
						{ID: "ignored", Uses: "module:mock-exploit@v0.0.0-example"},
					},
					Config: map[string]string{"operator.confirmed_lab": "true"},
					Targets: []ChainFileTarget{
						{ID: "mock://target", Config: map[string]string{"target.host": "router-01"}},
					},
				},
			},
		},
	}
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    exampleCatalog(),
		Session:    session,
		ChainFiles: store,
	})
	loadDefinition, _ := registry.Find("chain", "load")

	result, err := loadDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "alpha.chain.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Human != "Chain loaded: alpha" {
		t.Fatalf("load result = %q", result.Human)
	}
	state := session.Snapshot()
	if state.ActiveChain != "alpha" {
		t.Fatalf("active chain = %q, want alpha", state.ActiveChain)
	}
	if got, want := state.Steps, []operatorsession.Step{{ID: "step-1", ModuleID: "mock-exploit@v0.0.0-example"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("steps = %#v, want %#v", got, want)
	}
	if got, want := state.Config, map[string]string{"operator.confirmed_lab": "true"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("config = %#v, want %#v", got, want)
	}
	if got, want := state.Targets, []string{"mock://target"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	if got, want := state.TargetConfigs, map[string]map[string]string{"mock://target": {"target.host": "router-01"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("target configs = %#v, want %#v", got, want)
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
		Operation:   operatorsession.DefaultOperation,
		Chain:       "test1",
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
	artifacts  []Artifact
}

type fakePlanRecorder struct {
	records []ThrowPlanRecord
}

func (r *fakePlanRecorder) RecordThrowPlan(_ context.Context, plan ThrowPlanRecord) error {
	r.records = append(r.records, plan)
	return nil
}

type fakePlanRepository struct {
	records []ThrowPlanRecord
}

func (r *fakePlanRepository) ListThrowPlans(_ context.Context, _ string) ([]ThrowPlanRecord, error) {
	return append([]ThrowPlanRecord(nil), r.records...), nil
}

func (r *fakePlanRepository) GetThrowPlan(_ context.Context, _ string, id string) (ThrowPlanRecord, error) {
	for _, record := range r.records {
		if record.ID == id {
			return record, nil
		}
	}
	return ThrowPlanRecord{}, fmt.Errorf("throw plan %s not found", id)
}

type fakeConfirmationRecorder struct {
	records []ThrowConfirmationRecord
}

func (r *fakeConfirmationRecorder) RecordThrowConfirmation(_ context.Context, confirmation ThrowConfirmationRecord) error {
	r.records = append(r.records, confirmation)
	return nil
}

type fakeConfirmationStore struct {
	records []ThrowConfirmationRecord
}

func (s *fakeConfirmationStore) RecordThrowConfirmation(_ context.Context, confirmation ThrowConfirmationRecord) error {
	s.records = append(s.records, confirmation)
	return nil
}

func (s *fakeConfirmationStore) GetThrowConfirmation(_ context.Context, workspacePath, planHash string) (ThrowConfirmationRecord, bool, error) {
	for i := len(s.records) - 1; i >= 0; i-- {
		record := s.records[i]
		if record.Workspace == workspacePath && record.PlanHash == planHash {
			return record, true, nil
		}
	}
	return ThrowConfirmationRecord{}, false, nil
}

type fakeThrowRecorder struct {
	records []ThrowRecord
}

func (r *fakeThrowRecorder) RecordThrow(_ context.Context, record ThrowRecord) error {
	r.records = append(r.records, record)
	return nil
}

type fakeArtifactRecorder struct {
	materializations []ArtifactMaterialization
}

func (r *fakeArtifactRecorder) MaterializeArtifact(_ context.Context, materialization ArtifactMaterialization) (ArtifactRecord, error) {
	r.materializations = append(r.materializations, materialization)
	return ArtifactRecord{
		ID:        "artifact-1",
		Workspace: materialization.Workspace,
		ThrowID:   materialization.ThrowID,
		RunID:     materialization.RunID,
		ModuleID:  materialization.ModuleID,
		Target:    materialization.Target,
		Name:      materialization.Artifact.Name,
		Kind:      materialization.Artifact.Kind,
		Path:      "artifacts/throw/run/artifact.txt",
		SHA256:    "hash",
		Size:      len(materialization.Artifact.Data),
		CreatedAt: "2026-05-03T12:00:00Z",
	}, nil
}

type fakeArtifactRepository struct {
	records []ArtifactRecord
}

func (r *fakeArtifactRepository) ListArtifacts(_ context.Context, _ string) ([]ArtifactRecord, error) {
	return append([]ArtifactRecord(nil), r.records...), nil
}

type fakeEventRecorder struct {
	events []event.Event
}

func (r *fakeEventRecorder) RecordEvent(_ context.Context, _ string, evt event.Event) error {
	r.events = append(r.events, evt)
	return nil
}

type fakeEventRepository struct {
	events []event.Event
	filter event.Filter
}

func (r *fakeEventRepository) ListEvents(_ context.Context, _ string, filter event.Filter) ([]event.Event, error) {
	r.filter = filter
	var out []event.Event
	for _, evt := range r.events {
		if filter.Match(evt) {
			out = append(out, evt)
		}
	}
	return out, nil
}

func testEvent(t *testing.T, idValue, typeValue, message string, refs event.Refs) event.Event {
	t.Helper()
	id, err := event.NewID(idValue)
	if err != nil {
		t.Fatal(err)
	}
	typ, err := event.NewType(typeValue)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      typ,
		Message:   message,
		Timestamp: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		Refs:      refs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evt
}

func hasStructuredEvent(events []event.Event, typ string) bool {
	for _, evt := range events {
		if evt.Type.String() == typ {
			return true
		}
	}
	return false
}

func promptFieldValue(prompt ConfirmationPrompt, label string) string {
	for _, field := range prompt.Fields {
		if field.Label == label {
			return field.Value
		}
	}
	return ""
}

func (r *fakeArtifactRepository) GetArtifact(_ context.Context, _ string, id string) (ArtifactRecord, error) {
	for _, record := range r.records {
		if record.ID == id {
			return record, nil
		}
	}
	return ArtifactRecord{}, fmt.Errorf("artifact %s not found", id)
}

type fakeChainFileStore struct {
	writes map[string]ChainFile
	reads  map[string]ChainFile
}

func (s *fakeChainFileStore) WriteChainFile(_ context.Context, path string, file ChainFile) error {
	if s.writes == nil {
		s.writes = map[string]ChainFile{}
	}
	s.writes[path] = file
	return nil
}

func (s *fakeChainFileStore) ReadChainFile(_ context.Context, path string) (ChainFile, error) {
	file, ok := s.reads[path]
	if !ok {
		return ChainFile{}, nil
	}
	return file, nil
}

func configuredChainFileFixture(name, target string) ChainFile {
	return ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   ChainFileMetadata{Name: name},
		Spec: ChainFileSpec{
			Mode: "configured",
			Steps: []ChainFileStep{
				{ID: "step-1", Uses: "module:mock-exploit@v0.0.0-example"},
			},
			Config: map[string]string{"operator.confirmed_lab": "true"},
			Targets: []ChainFileTarget{
				{ID: target, Config: map[string]string{"target.host": "router-01", "target.port": "22"}},
			},
		},
	}
}

type fakeInput struct {
	answer string
	prompt ConfirmationPrompt
}

func (i *fakeInput) Confirm(_ context.Context, prompt ConfirmationPrompt) (ConfirmationAnswer, error) {
	i.prompt = prompt
	return ConfirmationAnswer{Value: i.answer}, nil
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
	artifacts := []Artifact{{
		Name: "artifact",
		Kind: "text",
		Data: "data",
	}}
	if c.recorder != nil && c.recorder.artifacts != nil {
		artifacts = append([]Artifact(nil), c.recorder.artifacts...)
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
		Findings:  []Finding{{Title: "finding", Severity: "info", Detail: "detail"}},
		Artifacts: artifacts,
	}, nil
}

func (fakeRunClient) ListSessions(context.Context) ([]SessionRef, error) {
	return []SessionRef{{
		ID:           "session-1",
		RunID:        "run-1",
		ModuleID:     "mock-exploit-session",
		Target:       "mock://target",
		Name:         "mock shell on mock://target",
		Kind:         "shell",
		State:        "active",
		Transport:    "stdio",
		Capabilities: []string{"read", "write", "exec", "close"},
	}}, nil
}

func (fakeRunClient) CloseSession(context.Context, string) error {
	return nil
}
