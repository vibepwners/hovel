package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
		{"payloads", "available"},
		{"payloads", "cleanup"},
		{"payloads", "cmd"},
		{"payloads", "connect"},
		{"payloads", "commands"},
		{"payloads", "getfile"},
		{"payloads", "inspect"},
		{"payloads", "installed"},
		{"payloads", "mark-removed"},
		{"payloads", "putfile"},
		{"payloads", "refresh"},
		{"payloads", "register-squatter"},
		{"chain", "use"},
		{"target", "add"},
		{"target", "clear"},
		{"target", "config", "list"},
		{"target", "config", "set"},
		{"target", "config", "unset"},
		{"target", "set", "add"},
		{"target", "set", "create"},
		{"target", "set", "inspect"},
		{"target", "set", "list"},
		{"target", "set", "remove"},
		{"confirm"},
		{"run"},
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
		{"run"},
		{"targets", "add"},
		{"targets", "set", "create"},
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
	for _, name := range []string{"workspace", "chain", "target", "target-set", "now", "json", "no-color", "verbose", "debug"} {
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

	for _, root := range []string{"op", "chain", "chains", "confirm", "control", "module", "modules", "payload", "payloads", "run", "target", "targets", "throw", "throws"} {
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
	input := &fakeInput{answer: "yes"}
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
		Input: input,
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
	if input.prompt.Title != "THROW REVIEW" || input.prompt.Action != "confirm" {
		t.Fatalf("prompt = %#v, want confirm review prompt", input.prompt)
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

func TestPayloadsAvailableUsesProviderService(t *testing.T) {
	providers := &fakePayloadProviderService{available: []AvailablePayload{{
		Provider:     "squatter",
		PayloadID:    "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		Name:         "squatter",
		Version:      "v0.1.0",
		Platform:     "windows",
		Arch:         "x86",
		Formats:      []string{"pe-exe"},
		Capabilities: []string{"file.get", "exec"},
		Transport:    "tcp-bind",
	}}}
	registry := HovelRegistry(Runtime{
		Modules:          exampleCatalog(),
		PayloadProviders: providers,
	})
	definition, _ := registry.Find("payloads", "available")

	result, err := definition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "squatter") || !strings.Contains(result.Human, "tcp-bind") {
		t.Fatalf("available output = %q", result.Human)
	}
	if !reflect.DeepEqual(result.JSON, providers.available) {
		t.Fatalf("available json = %#v, want %#v", result.JSON, providers.available)
	}
}

func TestPayloadsInstalledInspectAndMarkRemovedUseRepository(t *testing.T) {
	repository := newFakePayloadRepository([]InstalledPayloadRecord{
		payloadRecordFixture("p1", PayloadStateInstalled),
		payloadRecordFixture("p2", PayloadStateRemoved),
	})
	registry := HovelRegistry(Runtime{
		Modules:  exampleCatalog(),
		Payloads: repository,
	})
	installedDefinition, _ := registry.Find("payloads", "installed")
	inspectDefinition, _ := registry.Find("payloads", "inspect")
	removeDefinition, _ := registry.Find("payloads", "mark-removed")

	installed, err := installedDefinition.Execute(context.Background(), Invocation{Options: map[string]string{"workspace": ".hovel"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(installed.Human, "p2") || !strings.Contains(installed.Human, "p1") {
		t.Fatalf("installed output = %q", installed.Human)
	}
	installedJSON, ok := installed.JSON.([]InstalledPayloadRecord)
	if !ok || len(installedJSON) != 1 || installedJSON[0].Handle != "p1" {
		t.Fatalf("installed json = %#v", installed.JSON)
	}

	inspected, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"payload": "p1"},
		Options:     map[string]string{"workspace": ".hovel"},
		Flags:       map[string]bool{"events": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspected.Human, "Payload p1") || !strings.Contains(inspected.Human, "endpoint   192.168.122.142:9101") {
		t.Fatalf("inspect output = %q", inspected.Human)
	}
	if payload, ok := inspected.JSON.(PayloadInspectPayload); !ok || payload.Record.Handle != "p1" || len(payload.Events) != 1 {
		t.Fatalf("inspect json = %#v", inspected.JSON)
	}

	removed, err := removeDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"payload": "p1"},
		Options:     map[string]string{"workspace": ".hovel", "reason": "operator verified cleanup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(removed.Human, "Payload marked removed: p1") {
		t.Fatalf("mark-removed output = %q", removed.Human)
	}
	if repository.records["p1"].State != PayloadStateRemoved {
		t.Fatalf("payload state = %q, want removed", repository.records["p1"].State)
	}
}

func TestPayloadsConnectCleanupAndRefreshUseProviderService(t *testing.T) {
	record := payloadRecordFixture("p1", PayloadStateInstalled)
	repository := newFakePayloadRepository([]InstalledPayloadRecord{record})
	providers := &fakePayloadProviderService{
		session: SessionRef{
			ID:                 "session-1",
			RunID:              "run-1",
			ModuleID:           "squatter@v0.1.0",
			Target:             record.Target,
			Kind:               "agent",
			State:              "open",
			Transport:          "squatter/tcp-bind",
			InstalledPayloadID: "p1",
		},
		refresh: func(record InstalledPayloadRecord) InstalledPayloadRecord {
			record.State = PayloadStateUnreachable
			record.UpdatedAt = "2026-05-03T12:02:00Z"
			return record
		},
	}
	registry := HovelRegistry(Runtime{
		Modules:          exampleCatalog(),
		Payloads:         repository,
		PayloadProviders: providers,
	})
	connectDefinition, _ := registry.Find("payloads", "connect")
	cleanupDefinition, _ := registry.Find("payloads", "cleanup")
	refreshDefinition, _ := registry.Find("payloads", "refresh")

	connected, err := connectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"payload": "p1"},
		Options:     map[string]string{"workspace": ".hovel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(connected.Human, "Session opened: session-1") {
		t.Fatalf("connect output = %q", connected.Human)
	}
	if repository.records["p1"].State != PayloadStateConnected {
		t.Fatalf("state after connect = %q", repository.records["p1"].State)
	}
	if providers.connected.Handle != "p1" {
		t.Fatalf("provider connected record = %#v", providers.connected)
	}

	refreshed, err := refreshDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"payload": "p1"},
		Options:     map[string]string{"workspace": ".hovel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(refreshed.Human, "Payload refreshed: p1 unreachable") {
		t.Fatalf("refresh output = %q", refreshed.Human)
	}
	if repository.records["p1"].State != PayloadStateUnreachable {
		t.Fatalf("state after refresh = %q", repository.records["p1"].State)
	}

	cleaned, err := cleanupDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"payload": "p1"},
		Options:     map[string]string{"workspace": ".hovel", "reason": "operator cleanup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cleaned.Human, "Payload cleaned up: p1") {
		t.Fatalf("cleanup output = %q", cleaned.Human)
	}
	if repository.records["p1"].State != PayloadStateRemoved || providers.cleaned.Handle != "p1" {
		t.Fatalf("cleanup state/provider = %#v %#v", repository.records["p1"], providers.cleaned)
	}
}

func TestThrowInspectCanIncludeStructuredEvents(t *testing.T) {
	plan := newThrowPlanForExecution(".hovel", throwExecution{Chain: "mock-exploit", Targets: []string{"mock://target"}, Modules: []string{"mock-exploit@v0.0.0-example"}, ChainConfig: map[string]string{}, TargetConfigs: map[string]map[string]string{}})
	evt := testEvent(t, "event-1", "hovel.throw.started", "throw started", event.Refs{WorkspaceID: ".hovel", Operation: "default", Chain: plan.Chain, ThrowID: "throw-1"})
	evt.Fields = map[string]string{"planHash": plan.PlanHash}
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
	if got := events.filter.PlanHash; got != plan.PlanHash {
		t.Fatalf("event filter plan hash = %q, want %q", got, plan.PlanHash)
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

func TestThrowRecordsInstalledPayloadsFromLegacyRun(t *testing.T) {
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
	payloads := newFakePayloadRepository(nil)
	events := &fakeEventRecorder{}
	recorder := &fakeRunRecorder{installedPayloads: []InstalledPayloadDescriptor{installedPayloadDescriptorFixture()}}
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: recorder},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
		Payloads:      payloads,
		Events:        events,
	})
	definition, _ := registry.Find("throw")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{
			"workspace": ".hovel",
			"chain":     "mock-exploit",
			"target":    "t1",
		},
		Flags: map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	record := payloads.records["p1"]
	if record.Provider != "squatter" || record.Target != "192.168.122.142" || record.Chain != "mock-exploit" {
		t.Fatalf("installed payload record = %#v", record)
	}
	if !hasStructuredEvent(events.events, "hovel.payload.installed") {
		t.Fatalf("events = %#v, want hovel.payload.installed", events.events)
	}
	throwPayload := result.JSON.(ThrowPayload)
	if len(throwPayload.Results) != 1 || len(throwPayload.Results[0].InstalledPayloads) != 1 {
		t.Fatalf("throw payload installed descriptors = %#v", throwPayload.Results)
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

func TestThrowChainFileCapabilityStepsUsesCapabilityRunner(t *testing.T) {
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
		"alpha.chain.yaml": capabilityChainFileFixture("alpha", "mock://target"),
	}}
	runner := &fakeCapabilityChainRunner{
		response: CapabilityChainResponse{
			RunID:   "cap-run-1",
			State:   "succeeded",
			Summary: "capability chain completed",
			Capabilities: []CapabilityPayload{{
				ID:             "session-1",
				Type:           string(modulecatalog.CapabilitySessionRef),
				SchemaVersion:  "v1",
				State:          "active",
				ProducerStepID: "squatter.connect_smb",
				Attributes:     map[string]any{"transport": "smb-named-pipe"},
			}},
			Evidence: []CapabilityEvidence{{
				ID:           "ev-1",
				Level:        "info",
				Kind:         "session",
				SourceStepID: "squatter.connect_smb",
				Message:      "smb session established",
			}},
			Sessions: []SessionRef{{
				ID:                 "session-1",
				RunID:              "cap-run-1",
				ModuleID:           "squatter@v1",
				Target:             "mock://target",
				Kind:               "shell",
				State:              "active",
				Transport:          "smb-named-pipe",
				InstalledPayloadID: "p1",
			}},
			InstalledPayloads: []InstalledPayloadDescriptor{installedPayloadDescriptorFixture()},
		},
	}
	payloads := newFakePayloadRepository(nil)
	events := &fakeEventRecorder{}
	registry := HovelRegistry(Runtime{
		Workspaces:       fakeWorkspaceService{},
		Daemons:          fakeDaemonService{status: daemon.Running(identity)},
		CapabilityChains: runner,
		Modules:          exampleCatalog(),
		Plans:            &fakePlanRecorder{},
		Confirmations:    &fakeConfirmationRecorder{},
		ChainFiles:       store,
		Payloads:         payloads,
		Events:           events,
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
	if len(runner.requests) != 1 {
		t.Fatalf("capability chain requests = %#v, want one", runner.requests)
	}
	wantRequest := CapabilityChainRequest{
		Operation:    operatorsession.DefaultOperation,
		Chain:        "alpha",
		Target:       "mock://target",
		ChainConfig:  map[string]string{"operator.confirmed_lab": "true"},
		TargetConfig: map[string]string{"target.host": "router-01", "target.port": "22"},
		Steps: []CapabilityChainStepRef{
			{ID: "exploit", ModuleID: "etro@v1", StepID: "etro.exploit"},
			{ID: "connect", ModuleID: "squatter@v1", StepID: "squatter.connect_smb"},
		},
	}
	runner.requests[0].ThrowStarted = ""
	runner.requests[0].ThrowID = ""
	runner.requests[0].RunID = ""
	if !reflect.DeepEqual(runner.requests[0], wantRequest) {
		t.Fatalf("capability chain request = %#v, want %#v", runner.requests[0], wantRequest)
	}
	payload := result.JSON.(ThrowPayload)
	if len(payload.Results) != 1 {
		t.Fatalf("results = %#v, want one aggregate result", payload.Results)
	}
	got := payload.Results[0]
	if got.RunID != "cap-run-1" || got.ModuleID != "capability-chain" || got.Target != "mock://target" || got.State != "succeeded" {
		t.Fatalf("aggregate run = %#v", got)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0].ID != "session-1" {
		t.Fatalf("capabilities = %#v, want session capability", got.Capabilities)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].SourceStepID != "squatter.connect_smb" {
		t.Fatalf("evidence = %#v, want squatter evidence", got.Evidence)
	}
	if len(got.Sessions) != 1 || got.Sessions[0].Transport != "smb-named-pipe" {
		t.Fatalf("sessions = %#v, want smb session", got.Sessions)
	}
	if len(got.InstalledPayloads) != 1 {
		t.Fatalf("installed payloads = %#v, want one descriptor", got.InstalledPayloads)
	}
	if record := payloads.records["p1"]; record.Provider != "squatter" || record.RunID != "cap-run-1" {
		t.Fatalf("persisted payload = %#v", record)
	}
	if !hasStructuredEvent(events.events, "hovel.payload.installed") {
		t.Fatalf("events = %#v, want hovel.payload.installed", events.events)
	}
	if !reflect.DeepEqual(payload.Plan.Steps, []CapabilityChainStepRef{
		{ID: "exploit", ModuleID: "etro@v1", StepID: "etro.exploit"},
		{ID: "connect", ModuleID: "squatter@v1", StepID: "squatter.connect_smb"},
	}) {
		t.Fatalf("plan steps = %#v", payload.Plan.Steps)
	}
}

func TestThrowActiveChainCapabilityStepsUseCapabilityRunnerWithPayloadConfig(t *testing.T) {
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
	if err := session.UseChain("payload-lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddStep("etro@v1", "etro.exploit"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddStep("squatter@v1", "squatter.connect_smb"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("payload.transport", "smb-named-pipe"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("payload.pipe", `\\.\pipe\hovel-test`); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("smb://target"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("smb://target", "target.host", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("smb://target", "target.port", "445"); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCapabilityChainRunner{
		response: CapabilityChainResponse{
			State:   "succeeded",
			Summary: "capability chain completed",
			Capabilities: []CapabilityPayload{{
				ID:             "session-1",
				Type:           string(modulecatalog.CapabilitySessionRef),
				State:          "active",
				ProducerStepID: "squatter.connect_smb",
				Attributes:     map[string]any{"transport": "smb-named-pipe"},
			}},
		},
	}
	registry := HovelRegistry(Runtime{
		Workspaces:       fakeWorkspaceService{},
		Daemons:          fakeDaemonService{status: daemon.Running(identity)},
		CapabilityChains: runner,
		Modules: modulecatalog.New(
			modulecatalog.Module{ID: "etro@v1", Type: modulecatalog.TypeExploit, Enabled: true},
			modulecatalog.Module{
				ID:      "squatter@v1",
				Type:    modulecatalog.TypePayloadProvider,
				Enabled: true,
				ChainConfig: []modulecatalog.Requirement{
					{Key: "payload.transport", Type: modulecatalog.ValueEnum, Required: true, Allowed: []string{"smb-named-pipe", "tcp-bind"}},
					{Key: "payload.pipe", Type: modulecatalog.ValueString, Required: true},
				},
				TargetConfig: []modulecatalog.Requirement{
					{Key: "target.host", Type: modulecatalog.ValueHost, Required: true},
					{Key: "target.port", Type: modulecatalog.ValuePort, Required: true},
				},
			},
		),
		Session:       session,
		Plans:         &fakePlanRecorder{},
		Confirmations: &fakeConfirmationRecorder{},
	})
	definition, _ := registry.Find("run")

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{"workspace": ".hovel"},
		Flags:   map[string]bool{"now": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.requests) != 1 {
		t.Fatalf("capability chain requests = %#v, want one", runner.requests)
	}
	request := runner.requests[0]
	request.ThrowID = ""
	request.RunID = ""
	request.ThrowStarted = ""
	want := CapabilityChainRequest{
		Operation:   operatorsession.DefaultOperation,
		Chain:       "payload-lab",
		Target:      "smb://target",
		ChainConfig: map[string]string{"payload.transport": "smb-named-pipe", "payload.pipe": `\\.\pipe\hovel-test`},
		TargetConfig: map[string]string{
			"target.host": "192.0.2.10",
			"target.port": "445",
		},
		Steps: []CapabilityChainStepRef{
			{ID: "step-1", ModuleID: "etro@v1", StepID: "etro.exploit"},
			{ID: "step-2", ModuleID: "squatter@v1", StepID: "squatter.connect_smb"},
		},
	}
	if !reflect.DeepEqual(request, want) {
		t.Fatalf("capability chain request = %#v, want %#v", request, want)
	}
	payload := result.JSON.(ThrowPayload)
	if len(payload.Results) != 1 || payload.Results[0].ModuleID != "capability-chain" {
		t.Fatalf("payload results = %#v, want one capability-chain result", payload.Results)
	}
	if !reflect.DeepEqual(payload.Plan.Steps, want.Steps) {
		t.Fatalf("plan steps = %#v, want %#v", payload.Plan.Steps, want.Steps)
	}
}

func TestThrowChainFileRejectsMixedCapabilityAndLegacySteps(t *testing.T) {
	store := &fakeChainFileStore{reads: map[string]ChainFile{
		"mixed.chain.yaml": {
			APIVersion: "hovel.dev/v1alpha1",
			Kind:       "Chain",
			Metadata:   ChainFileMetadata{Name: "mixed"},
			Spec: ChainFileSpec{
				Mode: "configured",
				Steps: []ChainFileStep{
					{ID: "exploit", Uses: "module:etro@v1", Step: "etro.exploit"},
					{ID: "connect", Uses: "module:squatter@v1"},
				},
				Targets: []ChainFileTarget{{ID: "mock://target"}},
			},
		},
	}}
	registry := HovelRegistry(Runtime{
		Workspaces:       fakeWorkspaceService{},
		Daemons:          fakeDaemonService{},
		CapabilityChains: &fakeCapabilityChainRunner{},
		Modules:          exampleCatalog(),
		Plans:            &fakePlanRecorder{},
		Confirmations:    &fakeConfirmationRecorder{},
		ChainFiles:       store,
	})
	definition, _ := registry.Find("throw")

	_, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"file": "mixed.chain.yaml"},
		Options:     map[string]string{"workspace": ".hovel"},
		Flags:       map[string]bool{"now": true},
	})
	if err == nil || !strings.Contains(err.Error(), "all steps must declare step") {
		t.Fatalf("err = %v, want mixed capability step error", err)
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
	if newThrowPlanForExecution(".hovel", base).ID == newThrowPlanForExecution(".hovel", changedConfig).ID {
		t.Fatal("plan id did not change when reviewed config changed")
	}
}

func TestThrowRecordsDistinctExecutionsForSamePlan(t *testing.T) {
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
	registry := HovelRegistry(Runtime{
		Workspaces:    fakeWorkspaceService{},
		Daemons:       fakeDaemonService{status: daemon.Running(identity)},
		Runs:          fakeRunClientFactory{recorder: &fakeRunRecorder{}},
		Modules:       exampleCatalog(),
		Plans:         &fakePlanRecorder{},
		Throws:        throwRecorder,
		Confirmations: &fakeConfirmationRecorder{},
	})
	definition, _ := registry.Find("throw")
	invocation := Invocation{
		Options: map[string]string{"workspace": ".hovel", "chain": "mock-exploit", "target": "mock://target"},
		Flags:   map[string]bool{"now": true},
	}

	first, err := definition.Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := definition.Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}

	firstPayload := first.JSON.(ThrowPayload)
	secondPayload := second.JSON.(ThrowPayload)
	if firstPayload.Plan.PlanHash != secondPayload.Plan.PlanHash {
		t.Fatalf("plan hashes differ = %q / %q", firstPayload.Plan.PlanHash, secondPayload.Plan.PlanHash)
	}
	if firstPayload.ThrowID == secondPayload.ThrowID {
		t.Fatalf("throw ids are equal: %q", firstPayload.ThrowID)
	}
	if len(throwRecorder.records) != 2 {
		t.Fatalf("throw records = %#v, want two executions", throwRecorder.records)
	}
}

func TestThrowTargetOverrideScopesTargetConfigs(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("op1"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"mock://one", "mock://two"} {
		if err := session.AddTarget(target); err != nil {
			t.Fatal(err)
		}
	}
	if err := session.SetTargetConfig("mock://one", "target.host", "one.local"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://one", "target.port", "22"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://two", "target.host", "two.local"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://two", "target.port", "22"); err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{Session: session, Modules: exampleCatalog()}

	throw, err := throwInputs(context.Background(), runtime, Invocation{Options: map[string]string{"target": "mock://one"}})
	if err != nil {
		t.Fatal(err)
	}

	wantConfigs := map[string]map[string]string{"mock://one": {"target.host": "one.local", "target.port": "22"}}
	if !reflect.DeepEqual(throw.TargetConfigs, wantConfigs) {
		t.Fatalf("target configs = %#v, want %#v", throw.TargetConfigs, wantConfigs)
	}
	baseHash := planHashForExecution(throw)
	changed := throw
	changed.TargetConfigs = map[string]map[string]string{
		"mock://one": {"target.host": "one.local", "target.port": "22"},
		"mock://two": {"target.host": "changed.local", "target.port": "22"},
	}
	if baseHash == planHashForExecution(changed) {
		t.Fatal("test setup invalid: unscoped target config should affect hash")
	}
}

func TestThrowInputsSquatterTypeDerivesEtroInstallConfig(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("op1"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("etro-exploit@v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("squatter@v0.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("operator.confirmed_lab", "true"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("squatter.type", "tcp-bind"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetChainConfig("squatter.bind_port", "9101"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("t1"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("t1", "target.host", "192.168.122.142"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("t1", "target.port", "1337"); err != nil {
		t.Fatal(err)
	}

	throw, err := throwInputs(context.Background(), Runtime{Session: session, Modules: exampleCatalog()}, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := throw.Modules, []string{"etro-exploit@v1.0.0", "squatter@v0.1.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %#v, want %#v", got, want)
	}
	if len(throw.Steps) != 0 {
		t.Fatalf("steps = %#v, want module-only execution", throw.Steps)
	}
	config := throw.TargetConfigs["t1"]
	if config["target.port"] != "445" {
		t.Fatalf("target.port = %q, want 445", config["target.port"])
	}
	if config["payload.bind_port"] != "9101" {
		t.Fatalf("payload.bind_port = %q, want 9101", config["payload.bind_port"])
	}
	if _, ok := config["payload.remote_path"]; ok {
		t.Fatalf("payload.remote_path = %q, want ETRO to auto-generate an unlocked path", config["payload.remote_path"])
	}
	if !strings.HasSuffix(config["payload.local_path"], filepath.Join("examples", "bin", "squatter.exe")) {
		t.Fatalf("payload.local_path = %q, want staged squatter.exe", config["payload.local_path"])
	}

	if err := session.SetChainConfig("squatter.remote_path", `C:\Windows\Temp\hovel-fixed.exe`); err != nil {
		t.Fatal(err)
	}
	throw, err = throwInputs(context.Background(), Runtime{Session: session, Modules: exampleCatalog()}, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	config = throw.TargetConfigs["t1"]
	if config["payload.remote_path"] != `C:\Windows\Temp\hovel-fixed.exe` {
		t.Fatalf("payload.remote_path = %q, want explicit Squatter remote path", config["payload.remote_path"])
	}
}

func TestSquatterPayloadPathPrefersModuleConfigStagedBinary(t *testing.T) {
	t.Setenv("SQUATTER_PAYLOAD_PATH", "")
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", "")

	root := t.TempDir()
	payloadPath := filepath.Join(root, "examples", "bin", "squatter.exe")
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, configPath := range []string{
		filepath.Join(root, "examples", "hovel-modules.json"),
		filepath.Join(root, "examples", "python", "hovel-modules.json"),
	} {
		t.Run(configPath, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOVEL_MODULE_CONFIG", configPath)
			if got := squatterPayloadPath(); got != payloadPath {
				t.Fatalf("squatterPayloadPath() = %q, want %q", got, payloadPath)
			}
		})
	}
}

func TestThrowInputsFromChainFileSquatterTypeDerivesInstallConfig(t *testing.T) {
	store := &fakeChainFileStore{
		reads: map[string]ChainFile{
			"etro-squatter.chain.yaml": {
				APIVersion: "hovel.dev/v1alpha1",
				Kind:       "Chain",
				Metadata:   ChainFileMetadata{Name: "etro-squatter"},
				Spec: ChainFileSpec{
					Mode: "configured",
					Steps: []ChainFileStep{
						{ID: "exploit", Uses: "module:etro-exploit@v1.0.0"},
						{ID: "squatter-bind", Uses: "module:squatter@v0.1.0"},
					},
					Config: map[string]string{"operator.confirmed_lab": "true", "squatter.type": "tcp-bind", "squatter.bind_port": "9101"},
					Targets: []ChainFileTarget{{
						ID: "t1",
						Config: map[string]string{
							"target.host": "192.168.122.142",
							"target.port": "1337",
						},
					}},
				},
			},
		},
	}

	throw, err := throwInputs(context.Background(), Runtime{ChainFiles: store}, Invocation{
		Positionals: map[string]string{"file": "etro-squatter.chain.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := throw.Modules, []string{"etro-exploit@v1.0.0", "squatter@v0.1.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %#v, want %#v", got, want)
	}
	config := throw.TargetConfigs["t1"]
	if config["target.port"] != "445" || config["payload.bind_port"] != "9101" || config["payload.local_path"] == "" {
		t.Fatalf("target config = %#v, want derived Squatter install config", config)
	}
}

func TestThrowInputsFromChainFileSquatterSMBTransportKeepsExplicitInstallConfig(t *testing.T) {
	store := &fakeChainFileStore{
		reads: map[string]ChainFile{
			"etro-squatter-smb.chain.yaml": {
				APIVersion: "hovel.dev/v1alpha1",
				Kind:       "Chain",
				Metadata:   ChainFileMetadata{Name: "etro-squatter-smb"},
				Spec: ChainFileSpec{
					Mode: "configured",
					Steps: []ChainFileStep{
						{ID: "exploit", Uses: "module:etro-exploit@v1.0.0"},
						{ID: "squatter-smb", Uses: "module:squatter@v0.1.0"},
					},
					Config: map[string]string{
						"operator.confirmed_lab": "true",
						"payload.transport":      "smb-named-pipe",
						"payload.pipe":           "squatter",
					},
					Targets: []ChainFileTarget{{
						ID: "t1",
						Config: map[string]string{
							"target.host":         "192.168.122.142",
							"target.port":         "445",
							"payload.local_path":  "/tmp/squatter-smb.exe",
							"payload.remote_path": `C:\Windows\Temp\hovelsmb.exe`,
							"payload.bind_port":   "",
						},
					}},
				},
			},
		},
	}

	throw, err := throwInputs(context.Background(), Runtime{ChainFiles: store}, Invocation{
		Positionals: map[string]string{"file": "etro-squatter-smb.chain.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := throw.TargetConfigs["t1"]
	if config["payload.local_path"] != "/tmp/squatter-smb.exe" {
		t.Fatalf("payload.local_path = %q, want explicit SMB payload", config["payload.local_path"])
	}
	if config["payload.remote_path"] != `C:\Windows\Temp\hovelsmb.exe` {
		t.Fatalf("payload.remote_path = %q, want explicit SMB remote path", config["payload.remote_path"])
	}
	if config["payload.bind_port"] != "" {
		t.Fatalf("payload.bind_port = %q, want no TCP bind arg for SMB payload", config["payload.bind_port"])
	}
}

func TestChainAddVersionedSquatterSetsTypeConfig(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("op1"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	result, err := chainAddHandler(Runtime{Session: session, Modules: squatterCatalog()})(context.Background(), Invocation{
		Positionals: map[string]string{"module": "squatter@v0.1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Human, "squatter.type=tcp-bind") {
		t.Fatalf("human = %q, want squatter.type=tcp-bind", result.Human)
	}
	state := session.Snapshot()
	if len(state.Steps) != 1 || state.Steps[0].ModuleID != "squatter@v0.1.0" || state.Steps[0].StepID != "" {
		t.Fatalf("steps = %#v, want Squatter provider module", state.Steps)
	}
	if got := state.Config["squatter.type"]; got != "tcp-bind" {
		t.Fatalf("squatter.type = %q, want tcp-bind", got)
	}
}

func TestExecuteLegacyThrowRunsSquatterProviderAfterEtroInstall(t *testing.T) {
	recorder := &fakeRunRecorder{}
	client := fakeRunClient{recorder: recorder}
	throw := throwExecution{
		Operation: "op1",
		Chain:     "alpha",
		Targets:   []string{"t1"},
		Modules:   []string{"etro-exploit@v1.0.0", "squatter.bind"},
		TargetConfigs: map[string]map[string]string{
			"t1": {
				"target.host":         "192.168.122.142",
				"target.port":         "445",
				"payload.local_path":  "/tmp/squatter.exe",
				"payload.remote_path": `C:\Windows\Temp\hovel-squatter.exe`,
				"payload.bind_port":   "9101",
			},
		},
	}
	payload := ThrowPayload{ThrowID: "throw-1", Chain: "alpha", Targets: []string{"t1"}}
	err := executeLegacyThrow(context.Background(), Runtime{Modules: squatterCatalog()}, client, "", ThrowPlanRecord{Operation: "op1", Chain: "alpha"}, throw, &payload, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.requests) != 2 {
		t.Fatalf("requests = %#v, want etro and squatter provider", recorder.requests)
	}
	if recorder.requests[0].ModuleID != "etro-exploit@v1.0.0" {
		t.Fatalf("first module = %q", recorder.requests[0].ModuleID)
	}
	if recorder.requests[1].ModuleID != "squatter@v0.1.0" {
		t.Fatalf("second module = %q, want squatter provider", recorder.requests[1].ModuleID)
	}
	if recorder.requests[1].TargetConfig["payload.bind_port"] != "9101" {
		t.Fatalf("squatter target config = %#v", recorder.requests[1].TargetConfig)
	}
}

func TestThrowTargetSetFiltersIncompatibleTargets(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("op1"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"mock://ready", "mock://missing-port"} {
		if err := session.AddTarget(target); err != nil {
			t.Fatal(err)
		}
	}
	if err := session.SetTargetConfig("mock://ready", "target.host", "ready.local"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://ready", "target.port", "22"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://missing-port", "target.host", "missing.local"); err != nil {
		t.Fatal(err)
	}
	if err := session.CreateTargetSet("mixed"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("mixed", "mock://ready"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("mixed", "mock://missing-port"); err != nil {
		t.Fatal(err)
	}

	throw, err := throwInputs(context.Background(), Runtime{Session: session, Modules: exampleCatalog()}, Invocation{
		Options: map[string]string{"target-set": "mixed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := throw.Targets, []string{"mock://ready"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	if _, ok := throw.TargetConfigs["mock://missing-port"]; ok {
		t.Fatalf("incompatible target config leaked into throw: %#v", throw.TargetConfigs)
	}
	if len(throw.SkippedTargets) != 1 || throw.SkippedTargets[0].Target != "mock://missing-port" {
		t.Fatalf("skipped targets = %#v", throw.SkippedTargets)
	}
	if !strings.Contains(throw.SkippedTargets[0].Reason, "target.port") {
		t.Fatalf("skip reason = %q, want missing target.port", throw.SkippedTargets[0].Reason)
	}
}

func TestThrowExplicitTargetFailsWhenIncompatible(t *testing.T) {
	session := operatorsession.New()
	if err := session.UseOperation("op1"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://missing-port"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://missing-port", "target.host", "missing.local"); err != nil {
		t.Fatal(err)
	}

	_, err := throwInputs(context.Background(), Runtime{Session: session, Modules: exampleCatalog()}, Invocation{
		Options: map[string]string{"target": "mock://missing-port"},
	})
	if err == nil || !strings.Contains(err.Error(), "target.port") {
		t.Fatalf("error = %v, want target.port validation failure", err)
	}
}

func TestConfirmChainFileRecordsSamePlanAsThrowChainFile(t *testing.T) {
	plans := &fakePlanRecorder{}
	confirmations := &fakeConfirmationStore{}
	input := &fakeInput{answer: "yes"}
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
		Input:       input,
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
	targetSetCreateDefinition, _ := registry.Find("target", "set", "create")
	targetSetAddDefinition, _ := registry.Find("target", "set", "add")
	targetSetInspectDefinition, _ := registry.Find("target", "set", "inspect")
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
	if got, want := state.Targets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	if _, err := targetSetCreateDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"name": "xp-lab"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetSetAddDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"name": "xp-lab", "target": "mock://alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetSetAddDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"name": "xp-lab", "target": "mock://beta"},
	}); err != nil {
		t.Fatal(err)
	}
	targetSetResult, err := targetSetInspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"name": "xp-lab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Target set xp-lab", "mock://alpha", "mock://beta"} {
		if !strings.Contains(targetSetResult.Human, want) {
			t.Fatalf("target set inspect missing %q:\n%s", want, targetSetResult.Human)
		}
	}

	listResult, err := listDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  alpha steps=0 topic=operation/default/chain/alpha/logs",
		"* beta steps=0 topic=operation/default/chain/beta/logs",
	} {
		if !strings.Contains(listResult.Human, want) {
			t.Fatalf("chain list missing %q:\n%s", want, listResult.Human)
		}
	}

	inspectResult, err := inspectDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectResult.Human, "Chain beta steps=0 config=0 topic=operation/default/chain/beta/logs") {
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
	if got, want := state.Targets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
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
	if !strings.Contains(inspectResult.Human, "Operation afterparty chains=1 targets=1 target_sets=0 active_chain=beta") {
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

func TestModuleInspectReportsStepAvailability(t *testing.T) {
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules: modulecatalog.New(modulecatalog.Module{
			ID:      "squatter-provider@v1",
			Name:    "Squatter Provider",
			Type:    modulecatalog.TypePayloadProvider,
			Version: "v1",
			Enabled: true,
			StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{
				{
					ID:   "squatter.connect_smb",
					Kind: "session.connector",
					Requires: []modulecatalog.CapabilityRequirement{{
						Type:       modulecatalog.CapabilityTransport,
						Attributes: map[string]any{"kind": "smb-pipe"},
						States:     []string{"active"},
					}},
					Produces: []modulecatalog.CapabilityRequirement{{
						Type: modulecatalog.CapabilitySessionRef,
					}},
				},
			}},
		}),
	})
	inspectDefinition, _ := registry.Find("module", "inspect")

	result, err := inspectDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "squatter-provider"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"steps", "squatter.connect_smb", "session.connector", "missing TransportEndpoint kind=smb-pipe state=active"} {
		if !strings.Contains(result.Human, want) {
			t.Fatalf("inspect missing %q:\n%s", want, result.Human)
		}
	}
	payload, ok := result.JSON.(ModuleInspectPayload)
	if !ok {
		t.Fatalf("json payload type = %T, want ModuleInspectPayload", result.JSON)
	}
	if payload.ID != "squatter-provider@v1" || len(payload.Steps) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
	step := payload.Steps[0]
	if step.ID != "squatter.connect_smb" || step.Ready || len(step.Missing) != 1 {
		t.Fatalf("step payload = %#v", step)
	}
	if step.Missing[0].Type != modulecatalog.CapabilityTransport {
		t.Fatalf("missing type = %q", step.Missing[0].Type)
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

func TestSessionReadDrainsBufferedOutput(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{reads: []SessionChunk{
		{SessionID: "session-1", Data: []byte("first")},
		{SessionID: "session-1", Data: []byte(" second")},
		{SessionID: "session-1"},
	}}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "read")

	result, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Raw != nil {
		t.Fatalf("raw output = %q, want structured human output", string(result.Raw))
	}
	for _, want := range []string{"first second", "Session session-1 read 12 bytes (open)"} {
		if !strings.Contains(result.Human, want) {
			t.Fatalf("human output missing %q:\n%s", want, result.Human)
		}
	}
}

func TestSessionTailPrintsRecentLinesByDefault(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{tail: SessionChunk{SessionID: "session-1", Data: []byte("line 2\nline 3\n")}}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "tail")

	result, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Raw); got != "line 2\nline 3\n" {
		t.Fatalf("raw output = %q, want tail output", got)
	}
	if got := recorder.tails[0].options; got.MaxLines != 20 || got.MaxBytes != 0 || got.Consume {
		t.Fatalf("tail options = %#v, want default 20 line non-consuming tail", got)
	}
}

func TestSessionTailAcceptsByteLimit(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{tail: SessionChunk{SessionID: "session-1", Data: []byte("tail")}}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "tail")

	_, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1"},
		Options:     map[string]string{"bytes": "128"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := recorder.tails[0].options; got.MaxBytes != 128 || got.MaxLines != 0 {
		t.Fatalf("tail options = %#v, want 128-byte tail", got)
	}
}

func TestSessionCommandsResolveLatestSession(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{
		reads: []SessionChunk{{SessionID: "session-1", Data: []byte("mock$ ")}},
		tail:  SessionChunk{Data: []byte("tail")},
	}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})

	readDefinition, _ := registry.Find("session", "read")
	readResult, err := readDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "latest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mock$ ", "Session session-1 read 6 bytes (open)"} {
		if !strings.Contains(readResult.Human, want) {
			t.Fatalf("read output missing %q:\n%s", want, readResult.Human)
		}
	}

	tailDefinition, _ := registry.Find("session", "tail")
	if _, err := tailDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "@latest"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := recorder.tails[0].sessionID; got != "session-1" {
		t.Fatalf("tail session = %q, want session-1", got)
	}

	sendDefinition, _ := registry.Find("session", "send")
	if _, err := sendDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "latest", "data": "whoami"},
		Options:     map[string]string{},
		Flags:       map[string]bool{},
	}); err != nil {
		t.Fatal(err)
	}
	if len(recorder.writes) != 1 || recorder.writes[0].sessionID != "session-1" {
		t.Fatalf("writes = %#v, want write to latest session", recorder.writes)
	}
}

func TestSessionLatestUsesLastActiveSessionInDaemonOrder(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{
		sessions: []SessionRef{
			{ID: "session-z", State: "active"},
			{ID: "session-a", State: "active"},
			{ID: "session-m", State: "closed"},
		},
	}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "send")

	if _, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "latest", "data": "whoami"},
		Options:     map[string]string{},
		Flags:       map[string]bool{},
	}); err != nil {
		t.Fatal(err)
	}
	if len(recorder.writes) != 1 || recorder.writes[0].sessionID != "session-a" {
		t.Fatalf("writes = %#v, want latest active session-a", recorder.writes)
	}
}

func TestSessionLatestRejectsClosedOnlySessions(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{
		sessions: []SessionRef{
			{ID: "session-1", State: "closed"},
			{ID: "session-2", State: "closed"},
		},
	}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "read")

	_, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "latest"},
	})
	if err == nil || !strings.Contains(err.Error(), "no active sessions available") {
		t.Fatalf("error = %v, want no active sessions", err)
	}
}

func TestSessionSendAppendsDefaultAndCustomTerminators(t *testing.T) {
	identity := daemon.Identity{SocketPath: "/tmp/hovel.sock", PID: 42}
	recorder := &fakeRunRecorder{}
	registry := HovelRegistry(Runtime{
		Daemons: fakeDaemonService{status: daemon.Running(identity)},
		Runs:    fakeRunClientFactory{recorder: recorder},
		Modules: exampleCatalog(),
	})
	definition, _ := registry.Find("session", "send")

	_, err := definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1", "data": "cmd /c whoami"},
		Options:     map[string]string{},
		Flags:       map[string]bool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1", "data": "raw"},
		Options:     map[string]string{"end": "\\r\\n"},
		Flags:       map[string]bool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = definition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"session": "session-1", "data": "none"},
		Options:     map[string]string{},
		Flags:       map[string]bool{"no-newline": true},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(recorder.writes), 3; got != want {
		t.Fatalf("writes = %d, want %d", got, want)
	}
	for i, want := range []string{"cmd /c whoami\n", "raw\r\n", "none"} {
		if got := string(recorder.writes[i].data); got != want {
			t.Fatalf("write[%d] = %q, want %q", i, got, want)
		}
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

func TestChainValidateSquatterBindUsesBridgeConfig(t *testing.T) {
	session := operatorsession.New()
	registry := HovelRegistry(Runtime{
		Workspaces: fakeWorkspaceService{},
		Daemons:    fakeDaemonService{},
		Runs:       fakeRunClientFactory{},
		Modules:    squatterCatalog(),
		Session:    session,
	})
	useDefinition, _ := registry.Find("chain", "use")
	addDefinition, _ := registry.Find("chain", "add")
	chainConfigSetDefinition, _ := registry.Find("chain", "config", "set")
	targetDefinition, _ := registry.Find("target", "add")
	validateDefinition, _ := registry.Find("chain", "validate")

	if _, err := useDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"chain": "squatter-lab"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := addDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"module": "squatter@v0.1.0"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := chainConfigSetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"key": "squatter.bind_port", "value": "9444"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "smb://192.0.2.10"},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := validateDefinition.Execute(context.Background(), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Human != "Chain squatter-lab valid" {
		t.Fatalf("validation result = %q", result.Human)
	}
	payload, ok := result.JSON.(ValidationPayload)
	if !ok || !payload.Valid {
		t.Fatalf("validation payload = %#v", result.JSON)
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

func TestThrowInputsFromChainFileKeepsCapabilityStepRefs(t *testing.T) {
	store := &fakeChainFileStore{
		reads: map[string]ChainFile{
			"etro-squatter.yaml": {
				APIVersion: "hovel.dev/v1alpha1",
				Kind:       "Chain",
				Metadata:   ChainFileMetadata{Name: "etro-squatter"},
				Spec: ChainFileSpec{
					Mode: "configured",
					Steps: []ChainFileStep{
						{ID: "exploit", Uses: "module:etro@v1", Step: "etro.exploit"},
						{ID: "connect", Uses: "module:squatter@v1", Step: "squatter.connect_smb"},
					},
					Targets: []ChainFileTarget{{ID: "smb://target"}},
				},
			},
		},
	}

	throw, err := throwInputsFromChainFile(context.Background(), Runtime{ChainFiles: store}, Invocation{}, "etro-squatter.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := []throwStepRef{
		{ID: "exploit", ModuleID: "etro@v1", StepID: "etro.exploit"},
		{ID: "connect", ModuleID: "squatter@v1", StepID: "squatter.connect_smb"},
	}
	if !reflect.DeepEqual(throw.Steps, want) {
		t.Fatalf("steps = %#v, want %#v", throw.Steps, want)
	}
}

func TestTargetHandlerRequiresActiveOperation(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), "active operation is required") {
		t.Fatalf("error = %v, want active operation required", err)
	}
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDefinition.Execute(context.Background(), Invocation{
		Positionals: map[string]string{"target": "mock://target"},
	}); err != nil {
		t.Fatalf("target add with active operation failed: %v", err)
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

func squatterCatalog() modulecatalog.Catalog {
	return modulecatalog.New(
		modulecatalog.Module{
			ID:          "squatter@v0.1.0",
			Name:        "squatter",
			Type:        modulecatalog.TypePayloadProvider,
			Version:     "v0.1.0",
			Summary:     "Build Squatter Windows payload artifacts.",
			RuntimeKind: "jsonrpc-stdio",
			Enabled:     true,
			Tags:        []string{"dangerous", "payload_provider"},
			ChainConfig: []modulecatalog.Requirement{
				{Key: "payload.transport", Type: modulecatalog.ValueEnum, Required: true, Allowed: []string{"tcp-bind"}},
				{Key: "payload.bind_port", Type: modulecatalog.ValuePort, Required: true},
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
	socketPath        string
	requests          []RunMockExploitRequest
	artifacts         []Artifact
	installedPayloads []InstalledPayloadDescriptor
	sessions          []SessionRef
	reads             []SessionChunk
	tail              SessionChunk
	tails             []fakeSessionTail
	writes            []fakeSessionWrite
}

type fakeSessionTail struct {
	sessionID string
	options   SessionTailOptions
}

type fakeSessionWrite struct {
	sessionID string
	data      []byte
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

type fakePayloadRepository struct {
	records map[string]InstalledPayloadRecord
	events  map[string][]InstalledPayloadEvent
}

func newFakePayloadRepository(records []InstalledPayloadRecord) *fakePayloadRepository {
	repo := &fakePayloadRepository{
		records: map[string]InstalledPayloadRecord{},
		events:  map[string][]InstalledPayloadEvent{},
	}
	for _, record := range records {
		repo.records[record.Handle] = record
		repo.events[record.Handle] = []InstalledPayloadEvent{{
			ID:        "payload-event-" + record.Handle,
			PayloadID: record.ID,
			Handle:    record.Handle,
			Workspace: record.Workspace,
			Type:      "installed",
			To:        record.State,
			CreatedAt: record.CreatedAt,
		}}
	}
	return repo
}

func (r *fakePayloadRepository) RecordInstalledPayload(_ context.Context, record InstalledPayloadRecord) (InstalledPayloadRecord, error) {
	if record.Handle == "" {
		record.Handle = fmt.Sprintf("p%d", len(r.records)+1)
	}
	if record.ID == "" {
		record.ID = "payload-" + record.Handle
	}
	if record.State == "" {
		record.State = PayloadStateInstalled
	}
	r.records[record.Handle] = record
	return record, nil
}

func (r *fakePayloadRepository) ListInstalledPayloads(_ context.Context, _ string, filter InstalledPayloadFilter) ([]InstalledPayloadRecord, error) {
	var records []InstalledPayloadRecord
	for _, record := range r.records {
		if !filter.IncludeRemoved && record.State == PayloadStateRemoved {
			continue
		}
		if filter.State != "" && record.State != filter.State {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Handle < records[j].Handle })
	return records, nil
}

func (r *fakePayloadRepository) GetInstalledPayload(_ context.Context, _ string, ref string) (InstalledPayloadRecord, error) {
	if record, ok := r.records[ref]; ok {
		return record, nil
	}
	for _, record := range r.records {
		if record.ID == ref {
			return record, nil
		}
	}
	return InstalledPayloadRecord{}, fmt.Errorf("payload %s not found", ref)
}

func (r *fakePayloadRepository) UpdateInstalledPayloadState(_ context.Context, _ string, ref, state, reason string) (InstalledPayloadRecord, error) {
	record, err := r.GetInstalledPayload(context.Background(), "", ref)
	if err != nil {
		return InstalledPayloadRecord{}, err
	}
	from := record.State
	record.State = state
	r.records[record.Handle] = record
	r.events[record.Handle] = append(r.events[record.Handle], InstalledPayloadEvent{
		ID:        fmt.Sprintf("payload-event-%s-%d", record.Handle, len(r.events[record.Handle])+1),
		PayloadID: record.ID,
		Handle:    record.Handle,
		Workspace: record.Workspace,
		Type:      "state_changed",
		From:      from,
		To:        state,
		Reason:    reason,
		CreatedAt: "2026-05-03T12:01:00Z",
	})
	return record, nil
}

func (r *fakePayloadRepository) ListInstalledPayloadEvents(_ context.Context, _ string, ref string) ([]InstalledPayloadEvent, error) {
	return append([]InstalledPayloadEvent(nil), r.events[ref]...), nil
}

type fakePayloadProviderService struct {
	available []AvailablePayload
	session   SessionRef
	connected InstalledPayloadRecord
	cleaned   InstalledPayloadRecord
	refresh   func(InstalledPayloadRecord) InstalledPayloadRecord
	commands  []PayloadCommand
	result    PayloadCommandResult
}

func (s *fakePayloadProviderService) ListAvailablePayloads(context.Context) ([]AvailablePayload, error) {
	return append([]AvailablePayload(nil), s.available...), nil
}

func (s *fakePayloadProviderService) ConnectInstalledPayload(_ context.Context, record InstalledPayloadRecord) (SessionRef, error) {
	s.connected = record
	session := s.session
	if session.ID == "" {
		session = SessionRef{ID: "session-1", Target: record.Target, Kind: "agent", State: "open", Transport: record.Transport, InstalledPayloadID: record.Handle}
	}
	return session, nil
}

func (s *fakePayloadProviderService) CleanupInstalledPayload(_ context.Context, record InstalledPayloadRecord, _ string) error {
	s.cleaned = record
	return nil
}

func (s *fakePayloadProviderService) RefreshInstalledPayload(_ context.Context, record InstalledPayloadRecord) (InstalledPayloadRecord, error) {
	if s.refresh != nil {
		return s.refresh(record), nil
	}
	return record, nil
}

func (s *fakePayloadProviderService) ListPayloadCommands(context.Context, InstalledPayloadRecord) ([]PayloadCommand, error) {
	if s.commands == nil {
		return []PayloadCommand{{Name: "cmd", Summary: "run one command through cmd.exe", Destructive: true}}, nil
	}
	return append([]PayloadCommand(nil), s.commands...), nil
}

func (s *fakePayloadProviderService) RunPayloadCommand(context.Context, InstalledPayloadRecord, PayloadCommandRequest) (PayloadCommandResult, error) {
	if s.result.Command != "" {
		return s.result, nil
	}
	return PayloadCommandResult{Command: "cmd", Summary: "command completed", Stdout: "ok\n"}, nil
}

func payloadRecordFixture(handle, state string) InstalledPayloadRecord {
	return InstalledPayloadRecord{
		ID:                       "payload-" + handle,
		Handle:                   handle,
		Workspace:                ".hovel",
		Provider:                 "squatter",
		PayloadID:                "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		PayloadVersion:           "v0.1.0",
		Target:                   "192.168.122.142",
		TargetID:                 "t1",
		State:                    state,
		Transport:                "tcp-bind",
		Endpoint:                 "192.168.122.142:9101",
		InstanceKey:              "squatter:192.168.122.142:9101",
		SupportsReconnect:        true,
		SupportsMultipleSessions: true,
		Reconnect: &PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"host": "192.168.122.142", "port": float64(9101)},
		},
		Cleanup: &PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.cleanup",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"remotePath": `C:\Windows\Temp\hovel.exe`},
		},
		Operation:  "default",
		Chain:      "c1",
		ThrowID:    "throw-1",
		RunID:      "run-1",
		CreatedAt:  "2026-05-03T12:00:00Z",
		UpdatedAt:  "2026-05-03T12:00:00Z",
		LastSeenAt: "2026-05-03T12:00:00Z",
	}
}

func installedPayloadDescriptorFixture() InstalledPayloadDescriptor {
	return InstalledPayloadDescriptor{
		Provider:                 "squatter",
		PayloadID:                "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
		PayloadVersion:           "v0.1.0",
		Target:                   "192.168.122.142",
		TargetID:                 "t1",
		State:                    PayloadStateInstalled,
		Transport:                "tcp-bind",
		Endpoint:                 "192.168.122.142:9101",
		InstanceKey:              "squatter:192.168.122.142:9101",
		StampID:                  "stamp-squatter-9101",
		SupportsReconnect:        true,
		SupportsMultipleSessions: true,
		Reconnect: &PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.tcp_bind.reconnect",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"host": "192.168.122.142", "port": float64(9101)},
		},
		Cleanup: &PayloadProviderRecord{
			ProviderID:    "squatter",
			Schema:        "squatter.cleanup",
			SchemaVersion: "v1",
			Descriptor:    map[string]any{"remotePath": `C:\Windows\Temp\hovel.exe`},
		},
		Metadata: map[string]string{"profile": "XP_SP2SP3_X86"},
	}
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

func capabilityChainFileFixture(name, target string) ChainFile {
	return ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   ChainFileMetadata{Name: name},
		Spec: ChainFileSpec{
			Mode: "configured",
			Steps: []ChainFileStep{
				{ID: "exploit", Uses: "module:etro@v1", Step: "etro.exploit"},
				{ID: "connect", Uses: "module:squatter@v1", Step: "squatter.connect_smb"},
			},
			Config: map[string]string{"operator.confirmed_lab": "true"},
			Targets: []ChainFileTarget{
				{ID: target, Config: map[string]string{"target.host": "router-01", "target.port": "22"}},
			},
		},
	}
}

type fakeCapabilityChainRunner struct {
	requests []CapabilityChainRequest
	response CapabilityChainResponse
}

func (r *fakeCapabilityChainRunner) ExecuteCapabilityChain(_ context.Context, req CapabilityChainRequest) (CapabilityChainResponse, error) {
	r.requests = append(r.requests, req)
	return r.response, nil
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
	var installedPayloads []InstalledPayloadDescriptor
	if c.recorder != nil {
		installedPayloads = cloneInstalledPayloadDescriptors(c.recorder.installedPayloads)
	}
	return RunMockExploitResponse{
		RunID:             "run-1",
		ModuleID:          req.ModuleID,
		Target:            req.Target,
		State:             "succeeded",
		Summary:           "mock exploit completed",
		InstalledPayloads: installedPayloads,
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

func (c fakeRunClient) ListSessions(context.Context) ([]SessionRef, error) {
	if c.recorder != nil && c.recorder.sessions != nil {
		return append([]SessionRef(nil), c.recorder.sessions...), nil
	}
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

func (c fakeRunClient) ReadSession(context.Context, string, time.Duration) (SessionChunk, error) {
	if c.recorder == nil || len(c.recorder.reads) == 0 {
		return SessionChunk{SessionID: "session-1"}, nil
	}
	chunk := c.recorder.reads[0]
	c.recorder.reads = c.recorder.reads[1:]
	chunk.Data = append([]byte(nil), chunk.Data...)
	return chunk, nil
}

func (c fakeRunClient) TailSession(_ context.Context, sessionID string, options SessionTailOptions) (SessionChunk, error) {
	if c.recorder == nil {
		return SessionChunk{SessionID: sessionID}, nil
	}
	c.recorder.tails = append(c.recorder.tails, fakeSessionTail{sessionID: sessionID, options: options})
	chunk := c.recorder.tail
	if chunk.SessionID == "" {
		chunk.SessionID = sessionID
	}
	chunk.Data = append([]byte(nil), chunk.Data...)
	return chunk, nil
}

func (c fakeRunClient) WriteSession(_ context.Context, sessionID string, data []byte) error {
	if c.recorder != nil {
		c.recorder.writes = append(c.recorder.writes, fakeSessionWrite{
			sessionID: sessionID,
			data:      append([]byte(nil), data...),
		})
	}
	return nil
}

func (fakeRunClient) CloseSession(context.Context, string) error {
	return nil
}

func (fakeRunClient) ListPayloadCommands(context.Context, string, RunPayloadCommandListRequest) ([]PayloadCommand, error) {
	return []PayloadCommand{{Name: "cmd", Summary: "run one command through cmd.exe", Destructive: true}}, nil
}

func (fakeRunClient) RunPayloadCommand(context.Context, RunPayloadCommandRunRequest) (PayloadCommandResult, error) {
	return PayloadCommandResult{Command: "cmd", Summary: "command completed", Stdout: "ok\n"}, nil
}

func TestGuardDangerousModules(t *testing.T) {
	runtime := Runtime{Modules: modulecatalog.New(
		modulecatalog.Module{ID: "safe-mod@1", Version: "1", Type: modulecatalog.ModuleType("survey")},
		modulecatalog.Module{ID: "risky-mod@1", Version: "1", Type: modulecatalog.ModuleType("exploit"), Tags: []string{"dangerous"}},
	)}

	if err := guardDangerousModules(runtime, []string{"safe-mod@1"}, false); err != nil {
		t.Fatalf("benign module blocked: %v", err)
	}
	if err := guardDangerousModules(runtime, []string{"unknown-mod@1"}, false); err != nil {
		t.Fatalf("unknown module should not be blocked here: %v", err)
	}
	err := guardDangerousModules(runtime, []string{"safe-mod@1", "risky-mod@1"}, false)
	if err == nil {
		t.Fatal("dangerous module not blocked without --allow-dangerous")
	}
	if !strings.Contains(err.Error(), "risky-mod@1") {
		t.Fatalf("error should name the dangerous module, got: %v", err)
	}
	if err := guardDangerousModules(runtime, []string{"risky-mod@1"}, true); err != nil {
		t.Fatalf("--allow-dangerous should permit dangerous module: %v", err)
	}
}
