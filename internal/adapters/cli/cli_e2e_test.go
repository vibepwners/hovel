package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestExecuteLineBuildsChainTargetsThenThrows(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(context.Background(), "op use test-op", &stdout, &stderr); code != 0 {
		t.Fatalf("op use exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "chain create lab", &stdout, &stderr); code != 0 {
		t.Fatalf("chain exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "chain add mock-exploit", &stdout, &stderr); code != 0 {
		t.Fatalf("chain add exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "target add mock://target", &stdout, &stderr); code != 0 {
		t.Fatalf("target exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}

	payload := decodeThrowJSON(t, stdout.Bytes())
	if payload.Chain != "lab" {
		t.Fatalf("chain = %q, want lab", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("target = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 || payload.Results[0].State != "succeeded" {
		t.Fatalf("results = %#v", payload.Results)
	}
	assertPersistedPlan(t, workspacePath, payload.Plan)
}

func TestDaemonLogSubscriptionOnlyShowsActiveChain(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alphaClient, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer alphaClient.Close()
	betaClient, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer betaClient.Close()

	alpha := newTestApp().withDaemonSession(ctx, alphaClient)
	beta := newTestApp().withDaemonSession(ctx, betaClient)
	if err := alpha.session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}

	var alphaOut, betaOut bytes.Buffer
	stopAlpha := alpha.SubscribeLogs(ctx, alphaClient, nil, &alphaOut)
	defer stopAlpha()
	stopBeta := beta.SubscribeLogs(ctx, betaClient, nil, &betaOut)
	defer stopBeta()

	if _, err := alpha.session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	testsupport.WaitFor(t, func() bool {
		return strings.Contains(alphaOut.String(), "mock-survey") && strings.Contains(betaOut.String(), "mock-exploit")
	}, func() string {
		return "alpha output:\n" + alphaOut.String() + "\nbeta output:\n" + betaOut.String()
	})
	if strings.Contains(alphaOut.String(), "mock-exploit") {
		t.Fatalf("alpha output leaked beta log:\n%s", alphaOut.String())
	}
	if strings.Contains(betaOut.String(), "mock-survey") {
		t.Fatalf("beta output leaked alpha log:\n%s", betaOut.String())
	}
}

func TestDaemonLogSubscriptionFollowsActiveOperation(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	app := newTestApp().withDaemonSession(ctx, client)
	if err := app.session.UseOperation("test"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.UseChain("new"); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	stop := app.SubscribeLogs(ctx, client, nil, &output)
	defer stop()

	if _, err := app.session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	testsupport.WaitFor(t, func() bool {
		return strings.Contains(output.String(), "mock-survey")
	}, func() string {
		return "output:\n" + output.String()
	})
}

func TestDaemonLogSubscriptionReceivesThrowRuntimeLogs(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	app := newTestApp().withDaemonSession(ctx, client)
	if err := app.session.UseOperation("test-op"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.UseChain("lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.session.AddModule("mock-exploit@v0.0.0-example"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.AddTarget("mock://router-01"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.SetChainConfig("operator.confirmed_lab", "true"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.SetTargetConfig("mock://router-01", "target.host", "router-01"); err != nil {
		t.Fatal(err)
	}
	if err := app.session.SetTargetConfig("mock://router-01", "target.port", "22"); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	stop := app.SubscribeLogs(ctx, client, nil, &logs)
	defer stop()

	var stdout, stderr bytes.Buffer
	if code := app.ExecuteLine(ctx, "throw --workspace "+workspacePath+" --now", &stdout, &stderr); code != 0 {
		t.Fatalf("throw exit code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}

	testsupport.WaitFor(t, func() bool {
		output := logs.String()
		return strings.Contains(output, "example exploit started") && strings.Contains(output, "run completed")
	}, func() string {
		return "logs:\n" + logs.String() + "\nstdout:\n" + stdout.String() + "\nstderr:\n" + stderr.String()
	})
}

func TestDaemonSessionKeepsInjectedModuleCatalog(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	modules := modulecatalog.New(modulecatalog.Module{
		ID:          "custom-module@v1",
		Name:        "Custom Module",
		Type:        modulecatalog.TypeExploit,
		Version:     "v1",
		Summary:     "Only available from the injected catalog.",
		RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
		Enabled:     true,
	})
	app := newAppWithSessionAndModules(operatorsession.New(), modules).withDaemonSession(context.Background(), client)
	var stdout, stderr bytes.Buffer

	if code := app.ExecuteLine(context.Background(), "op use test-op", &stdout, &stderr); code != 0 {
		t.Fatalf("op use exit code = %d, stderr = %s", code, stderr.String())
	}
	if code := app.ExecuteLine(context.Background(), "chain use catalog", &stdout, &stderr); code != 0 {
		t.Fatalf("chain use exit code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := app.ExecuteLine(context.Background(), "module list", &stdout, &stderr); code != 0 {
		t.Fatalf("module list exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "custom-module@v1") {
		t.Fatalf("module list output = %q, want injected custom module", stdout.String())
	}
	if strings.Contains(stdout.String(), "mock-exploit") {
		t.Fatalf("module list output leaked default catalog: %q", stdout.String())
	}
}

func TestDaemonCLIConfigListRedactsSecrets(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	modules := modulecatalog.New(modulecatalog.Module{
		ID:          "secret-exploit@v1",
		Name:        "Secret Exploit",
		Type:        modulecatalog.TypeExploit,
		Version:     "v1",
		Summary:     "Requires an API token.",
		RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
		Enabled:     true,
		ChainConfig: []modulecatalog.Requirement{
			{Key: "api.token", Type: modulecatalog.ValueSecret, Required: true, Secret: true, Description: "API token."},
		},
	})
	app := newAppWithSessionAndModules(operatorsession.New(), modules).withDaemonSession(context.Background(), client)
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use secret-op",
		"chain use secret-chain",
		"chain add secret-exploit",
		"chain config set api.token hunter2",
	)

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "chain config list", &stdout, &stderr); code != 0 {
		t.Fatalf("chain config list exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, "hunter2") {
		t.Fatalf("secret leaked through config list output:\n%s", output)
	}
	if !strings.Contains(output, "api.token") || !strings.Contains(output, "********") {
		t.Fatalf("redacted config output = %q, want api.token with redaction", output)
	}
}

func TestE2EExampleSurveyAuthChainUsesPythonModules(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use survey-example",
		"chain add mock-survey",
		"target add mock://router-01",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if payload.Chain != "survey-example" {
		t.Fatalf("chain = %q, want survey-example", payload.Chain)
	}
	if got, want := moduleIDs(payload.Results), []string{"mock-survey@v0.0.0-example"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("module order = %#v, want %#v", got, want)
	}
	for _, result := range payload.Results {
		if result.Target != "mock://router-01" || result.State != "succeeded" {
			t.Fatalf("result = %#v", result)
		}
	}
}

func TestE2EExamplePayloadExploitChainUsesPythonModules(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use survey-exploit",
		"chain add mock-survey",
		"chain add mock-exploit",
		"target add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if got, want := moduleIDs(payload.Results), []string{"mock-survey@v0.0.0-example", "mock-exploit@v0.0.0-example"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("module order = %#v, want %#v", got, want)
	}
	exploit := payload.Results[1]
	if exploit.State != "succeeded" {
		t.Fatalf("exploit state = %q, want succeeded", exploit.State)
	}
	if len(exploit.Findings) != 1 {
		t.Fatalf("findings = %#v, want one finding", exploit.Findings)
	}
	if len(exploit.Artifacts) != 1 || exploit.Artifacts[0].Name != "mock-exploit-transcript.txt" {
		t.Fatalf("artifacts = %#v, want mock transcript", exploit.Artifacts)
	}
	if !hasPayloadLog(exploit.Logs, "example exploit started") {
		t.Fatalf("logs = %#v, want example exploit started", exploit.Logs)
	}
	assertPersistedPlan(t, workspacePath, payload.Plan)
}

func TestE2EChainFileSaveLoadRoundTripThenThrows(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath
	chainFile := filepath.Join(t.TempDir(), "roundtrip.chain.yaml")

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use roundtrip",
		"chain add mock-exploit",
		"target add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
		"chain save "+chainFile,
	)
	if _, err := os.Stat(chainFile); err != nil {
		t.Fatalf("saved chain file %s: %v", chainFile, err)
	}

	stdout.Reset()
	stderr.Reset()
	executeLines(t, app, &stdout, &stderr,
		"chain delete roundtrip",
		"chain load "+chainFile,
	)

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "chain inspect", &stdout, &stderr); code != 0 {
		t.Fatalf("chain inspect exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"Chain roundtrip", "steps=1", "config=1", "mock://router-01"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("round-tripped chain inspect missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "target config list mock://router-01", &stdout, &stderr); code != 0 {
		t.Fatalf("target config list exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"target.host", "router-01", "target.port", "22"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("round-tripped target config missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if payload.Chain != "roundtrip" || len(payload.Results) != 1 || payload.Results[0].State != "succeeded" {
		t.Fatalf("round-tripped throw payload = %#v", payload)
	}
}

func TestE2ESessionConnectHandlesRawTerminalCarriageReturn(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use session-exploit",
		"chain add mock-exploit-session",
		"target add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if len(payload.Results) != 1 || len(payload.Results[0].Sessions) != 1 {
		t.Fatalf("results = %#v, want one session result", payload.Results)
	}
	sessionID := payload.Results[0].Sessions[0].ID

	stdout.Reset()
	stderr.Reset()
	code = app.ExecuteLine(context.Background(), "session list --workspace "+workspacePath, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("session list exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), sessionID) || !strings.Contains(stdout.String(), "mock shell on mock://router-01") {
		t.Fatalf("session list output = %q", stdout.String())
	}

	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	stdout.Reset()
	stderr.Reset()
	input := strings.NewReader("whoami\rpwd\r" + string([]byte{sessionDetachByte}))
	if err := ConnectSession(context.Background(), client, sessionID, input, &stdout); err != nil {
		t.Fatalf("session connect failed: %v", err)
	}
	for _, want := range []string{"Press Ctrl-] to detach", "mock$", "whoami", "mock-operator", "pwd", "/mock/session", "Detached from session"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("session connect output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestE2ESessionCloseRemovesSessionAndDaemonStillThrows(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use session-close",
		"chain add mock-exploit-session",
		"target add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("session throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if len(payload.Results) != 1 || len(payload.Results[0].Sessions) != 1 {
		t.Fatalf("results = %#v, want one session result", payload.Results)
	}
	sessionID := payload.Results[0].Sessions[0].ID

	stdout.Reset()
	stderr.Reset()
	code = app.ExecuteLine(context.Background(), "session close "+sessionID+" --workspace "+workspacePath+" --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("session close exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), sessionID) || !strings.Contains(stdout.String(), "closed") {
		t.Fatalf("session close output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = app.ExecuteLine(context.Background(), "session list --workspace "+workspacePath, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("session list exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No sessions") || strings.Contains(stdout.String(), sessionID) {
		t.Fatalf("session list after close = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	executeLines(t, app, &stdout, &stderr,
		"chain use post-close",
		"chain add mock-exploit",
		"target clear",
		"target add mock://target",
		"chain config set operator.confirmed_lab true",
		"target config set mock://target target.host target",
		"target config set mock://target target.port 443",
	)
	stdout.Reset()
	stderr.Reset()
	code = app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("post-close throw exit code = %d, stderr = %s", code, stderr.String())
	}
	recovered := decodeThrowJSON(t, stdout.Bytes())
	if len(recovered.Results) != 1 || recovered.Results[0].ModuleID != "mock-exploit@v0.0.0-example" || recovered.Results[0].State != "succeeded" {
		t.Fatalf("post-close throw results = %#v", recovered.Results)
	}
}

func TestE2EExampleFailingChainReportsFailedModule(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use test-op",
		"chain use failing-example",
		"chain add mock-exploit",
		"target add mock://target",
		"chain config set operator.confirmed_lab true",
		"chain config set failure_mode execution",
		"target config set mock://target target.host target",
		"target config set mock://target target.port 443",
		"chain validate",
	)
	stdout.Reset()
	stderr.Reset()

	code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if len(payload.Results) != 1 {
		t.Fatalf("results = %#v, want one result", payload.Results)
	}
	result := payload.Results[0]
	if result.ModuleID != "mock-exploit@v0.0.0-example" || result.State != "failed" {
		t.Fatalf("result = %#v, want failed mock-exploit@v0.0.0-example", result)
	}
	if !strings.Contains(result.Summary, "failed during execution") {
		t.Fatalf("summary = %q", result.Summary)
	}
}

func TestDaemonRestartRestoresRemoteChainAndCanThrow(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	cancel, errs := startCLITestDaemon(t, workspacePath, socketPath)

	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp().withDaemonSession(context.Background(), client)
	var stdout, stderr bytes.Buffer
	executeLines(t, app, &stdout, &stderr,
		"op use restart-op",
		"chain use persisted",
		"chain add mock-exploit",
		"target add mock://router-01",
		"chain config set operator.confirmed_lab true",
		"target config set mock://router-01 target.host router-01",
		"target config set mock://router-01 target.port 22",
	)
	client.Close()
	stopCLITestDaemon(t, cancel, errs)

	socketPath = workspacePath + "/hoveld-restarted.sock"
	cancel, errs = startCLITestDaemon(t, workspacePath, socketPath)
	defer stopCLITestDaemon(t, cancel, errs)

	client, err = daemonrpc.Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	app = newTestApp().withDaemonSession(context.Background(), client)
	stdout.Reset()
	stderr.Reset()
	executeLines(t, app, &stdout, &stderr,
		"op use restart-op",
		"chain use persisted",
	)

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "chain inspect", &stdout, &stderr); code != 0 {
		t.Fatalf("chain inspect exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"Chain persisted", "steps=1", "config=1", "mock://router-01"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("restored chain inspect missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "target config list mock://router-01", &stdout, &stderr); code != 0 {
		t.Fatalf("target config list exit code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"target.host", "router-01", "target.port", "22"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("restored target config missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.ExecuteLine(context.Background(), "throw --workspace "+workspacePath+" --now --json", &stdout, &stderr); code != 0 {
		t.Fatalf("restored throw exit code = %d, stderr = %s", code, stderr.String())
	}
	payload := decodeThrowJSON(t, stdout.Bytes())
	if payload.Chain != "persisted" || len(payload.Results) != 1 || payload.Results[0].State != "succeeded" {
		t.Fatalf("restored throw payload = %#v", payload)
	}
}

func TestWelcomeShowsOperatorAndDaemonState(t *testing.T) {
	app := newTestApp()
	workspacePath := testsupport.TempDir(t)
	session, err := app.EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	welcome := app.Welcome(session)
	for _, want := range []string{
		`.-"""-.`,
		"╭",
		"╰",
		"━",
		"┃",
		"███████",
		"modules: 3",
		"hoveld:",
		"hoveld.sock",
		"mode:",
		"managed",
		"health:",
		"healthy",
	} {
		if !strings.Contains(welcome, want) {
			t.Fatalf("welcome missing %q:\n%s", want, welcome)
		}
	}
	if lines := strings.Split(welcome, "\n"); len(lines) < 14 {
		t.Fatalf("welcome line count = %d, want ascii art block:\n%s", len(lines), welcome)
	}

	narrow := app.WelcomeForWidth(session, wideMastheadColumns-1)
	for _, want := range []string{
		"|   |,---..    ,,---.|",
		"`   '`---'  `'  `---'`---'",
		"modules:",
	} {
		if !strings.Contains(narrow, want) {
			t.Fatalf("narrow welcome missing %q:\n%s", want, narrow)
		}
	}
	for _, unwanted := range []string{"╭", "╰", "━", "┃", "███████"} {
		if strings.Contains(narrow, unwanted) {
			t.Fatalf("narrow welcome contains %q, want compact unbordered masthead:\n%s", unwanted, narrow)
		}
	}

	wide := app.WelcomeForWidth(session, wideMastheadColumns)
	if !strings.Contains(wide, "███████") || !strings.Contains(wide, "╭") {
		t.Fatalf("wide welcome should keep bordered masthead:\n%s", wide)
	}
}

func TestEnsureDaemonStartsManagedDaemonForCLI(t *testing.T) {
	workspacePath := testsupport.TempDir(t)
	session, err := newTestApp().EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if !session.Owned() {
		t.Fatal("session owned = false, want true")
	}
	status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != daemon.StateRunning {
		t.Fatalf("daemon state = %s, want running", status.State)
	}
}

func TestEnsureDaemonAttachesToWorkspaceDaemonForCLI(t *testing.T) {
	fixture := testsupport.StartDaemon(t, daemonruntimeArgs())
	workspacePath := fixture.WorkspacePath

	app := newTestApp()
	session, err := app.EnsureDaemon(context.Background(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if session.Owned() {
		t.Fatal("session owned = true, want false")
	}
	welcome := app.Welcome(session)
	for _, want := range []string{"mode:", "remote", "hoveld.sock"} {
		if !strings.Contains(welcome, want) {
			t.Fatalf("welcome missing %q:\n%s", want, welcome)
		}
	}
}

func executeLines(t *testing.T, app App, stdout, stderr *bytes.Buffer, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if code := app.ExecuteLine(context.Background(), line, stdout, stderr); code != 0 {
			t.Fatalf("%q exit code = %d, stderr = %s, stdout = %s", line, code, stderr.String(), stdout.String())
		}
	}
}

type e2eThrowPayload struct {
	Plan struct {
		ID             string   `json:"id"`
		ConfirmationID string   `json:"confirmationId"`
		Chain          string   `json:"chain"`
		Targets        []string `json:"targets"`
		Review         string   `json:"review"`
	} `json:"plan"`
	Chain   string   `json:"chain"`
	Targets []string `json:"targets"`
	Results []struct {
		RunID    string `json:"runId"`
		ModuleID string `json:"moduleId"`
		Target   string `json:"target"`
		State    string `json:"state"`
		Summary  string `json:"summary"`
		Findings []struct {
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Detail   string `json:"detail"`
		} `json:"findings"`
		Artifacts []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Data string `json:"data"`
		} `json:"artifacts"`
		Logs []struct {
			Level   string            `json:"level"`
			Message string            `json:"message"`
			Logger  string            `json:"logger"`
			Fields  map[string]string `json:"fields"`
		} `json:"logs"`
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	} `json:"results"`
}

func decodeThrowJSON(t *testing.T, data []byte) e2eThrowPayload {
	t.Helper()
	var payload e2eThrowPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", string(data), err)
	}
	return payload
}

func moduleIDs(results []struct {
	RunID    string `json:"runId"`
	ModuleID string `json:"moduleId"`
	Target   string `json:"target"`
	State    string `json:"state"`
	Summary  string `json:"summary"`
	Findings []struct {
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Detail   string `json:"detail"`
	} `json:"findings"`
	Artifacts []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Data string `json:"data"`
	} `json:"artifacts"`
	Logs []struct {
		Level   string            `json:"level"`
		Message string            `json:"message"`
		Logger  string            `json:"logger"`
		Fields  map[string]string `json:"fields"`
	} `json:"logs"`
	Sessions []struct {
		ID string `json:"id"`
	} `json:"sessions"`
}) []string {
	ids := make([]string, 0, len(results))
	for _, result := range results {
		ids = append(ids, result.ModuleID)
	}
	return ids
}

func hasPayloadLog(logs []struct {
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Logger  string            `json:"logger"`
	Fields  map[string]string `json:"fields"`
}, message string) bool {
	for _, log := range logs {
		if log.Message == message {
			return true
		}
	}
	return false
}

func assertPersistedPlan(t *testing.T, workspacePath string, plan struct {
	ID             string   `json:"id"`
	ConfirmationID string   `json:"confirmationId"`
	Chain          string   `json:"chain"`
	Targets        []string `json:"targets"`
	Review         string   `json:"review"`
}) {
	t.Helper()
	record, err := filesystem.NewWorkspaceStore().GetThrowPlan(context.Background(), workspacePath, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.ID != plan.ID || record.ConfirmationID != plan.ConfirmationID || record.Chain != plan.Chain || record.Review != plan.Review {
		t.Fatalf("persisted plan = %#v, payload plan = %#v", record, plan)
	}
	if strings.Join(record.Targets, ",") != strings.Join(plan.Targets, ",") {
		t.Fatalf("persisted plan target = %#v, payload target = %#v", record.Targets, plan.Targets)
	}
	if record.Workspace != workspacePath {
		t.Fatalf("persisted plan workspace = %q, want %q", record.Workspace, workspacePath)
	}
	if record.Intent == "" {
		t.Fatalf("persisted plan intent is empty: %#v", record)
	}
}

func daemonruntimeArgs() daemonruntime.Args {
	return daemonruntime.Args{}
}

func startCLITestDaemon(t *testing.T, workspacePath, socketPath string) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		})
	}()
	store := filesystem.NewWorkspaceStore()
	testsupport.WaitFor(t, func() bool {
		select {
		case err := <-errs:
			cancel()
			t.Fatalf("daemon exited before reporting running status: %v", err)
		default:
		}
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})
	return cancel, errs
}

func stopCLITestDaemon(t *testing.T, cancel context.CancelFunc, errs chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("daemon did not stop")
	}
}
