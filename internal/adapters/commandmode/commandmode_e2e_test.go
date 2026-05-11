package commandmode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestThrowMockExploitJSONCrossesDaemonRPC(t *testing.T) {
	var stdout, stderr bytes.Buffer
	workspacePath := testsupport.TempDir(t)
	socketPath := workspacePath + "/hoveld.sock"
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, daemonruntime.Args{
			WorkspacePath: workspacePath,
			SocketPath:    socketPath,
			PID:           12345,
			StartedAt:     time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
			IDs:           &sequenceIDs{values: []string{"run-1", "event-1", "event-2", "event-3", "event-4", "event-5"}},
			Clock:         fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		})
	}()
	defer func() {
		cancel()
		<-errs
	}()

	store := filesystem.NewWorkspaceStore()
	waitFor(t, func() bool {
		status, err := store.DaemonStatus(context.Background(), workspacePath)
		return err == nil && status.State == daemon.StateRunning
	})

	code := Run(context.Background(), []string{"throw", "--chain", "mock-exploit", "--target", "mock://target", "--workspace", workspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
		Chain   string   `json:"chain"`
		Targets []string `json:"targets"`
		Results []struct {
			RunID     string `json:"runId"`
			ModuleID  string `json:"moduleId"`
			Target    string `json:"target"`
			State     string `json:"state"`
			Summary   string `json:"summary"`
			Findings  []any  `json:"findings"`
			Artifacts []any  `json:"artifacts"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.Chain != "mock-exploit" {
		t.Fatalf("chain = %q, want mock-exploit", payload.Chain)
	}
	if len(payload.Targets) != 1 || payload.Targets[0] != "mock://target" {
		t.Fatalf("targets = %#v", payload.Targets)
	}
	if len(payload.Results) != 1 {
		t.Fatalf("result count = %d, want 1", len(payload.Results))
	}
	result := payload.Results[0]
	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.ModuleID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("module id = %q, want mock-exploit@v0.0.0-example", result.ModuleID)
	}
	if result.Target != "mock://target" {
		t.Fatalf("target = %q, want mock://target", result.Target)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
}

func TestThrowBrokenPythonModuleJSONRecordsFailedRun(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixture(
		t,
		"broken",
		`import sys; sys.stdout.write("not a frame\n"); sys.stdout.flush()`,
	))
	events := &eventRecorder{}
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Events:    events,
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "broken", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var payload struct {
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
			Logs     []struct {
				Level   string            `json:"level"`
				Source  string            `json:"source"`
				Message string            `json:"message"`
				Fields  map[string]string `json:"fields"`
			} `json:"logs"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if payload.Chain != "broken" {
		t.Fatalf("chain = %q, want broken", payload.Chain)
	}
	if len(payload.Results) != 1 {
		t.Fatalf("result count = %d, want 1", len(payload.Results))
	}
	result := payload.Results[0]
	if result.RunID != "run-1" || result.ModuleID != "broken" || result.Target != "mock://target" || result.State != "failed" {
		t.Fatalf("result = %#v", result)
	}
	if result.Summary != "module failed during startup" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Logs) != 1 || result.Logs[0].Level != "error" || result.Logs[0].Source != "host" {
		t.Fatalf("logs = %#v", result.Logs)
	}
	detail := result.Logs[0].Fields["error"]
	if !strings.Contains(detail, "module handshake failed") || !strings.Contains(detail, "malformed frame") {
		t.Fatalf("log detail = %q", detail)
	}
	plan, err := filesystem.NewWorkspaceStore().GetThrowPlan(context.Background(), fixture.WorkspacePath, payload.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ID != payload.Plan.ID || plan.ConfirmationID != payload.Plan.ConfirmationID || plan.Chain != "broken" || plan.Workspace != fixture.WorkspacePath {
		t.Fatalf("persisted plan = %#v, payload plan = %#v", plan, payload.Plan)
	}
	if !hasEvent(events.events, "hovel.run.failed") {
		t.Fatalf("events = %#v, want hovel.run.failed", events.events)
	}
}

func TestMalformedPythonModuleDoesNotPoisonDaemonForNextThrow(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixtures(t,
		testsupport.PythonModuleFixture{
			ID:   "broken",
			Body: `import sys; sys.stdout.write("not a frame\n"); sys.stdout.flush()`,
		},
		testsupport.PythonModuleFixture{
			ID: "healthy",
			Body: `
while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "healthy", "version": "v1", "moduleType": "exploit"}
    elif method == "schema":
        response["result"] = {}
    elif method == "execute":
        response["result"] = {"status": "succeeded", "summary": "healthy module recovered", "findings": [], "artifacts": []}
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`,
		},
	))
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"throw", "--chain", "broken", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("broken throw exit code = %d, stderr = %s", code, stderr.String())
	}
	var failed struct {
		Results []struct {
			State   string `json:"state"`
			Summary string `json:"summary"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &failed); err != nil {
		t.Fatalf("invalid broken JSON %q: %v", stdout.String(), err)
	}
	if len(failed.Results) != 1 || failed.Results[0].State != "failed" {
		t.Fatalf("broken results = %#v, want failed result", failed.Results)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"throw", "--chain", "healthy", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("healthy throw exit code = %d, stderr = %s", code, stderr.String())
	}
	var recovered struct {
		Results []struct {
			ModuleID string `json:"moduleId"`
			State    string `json:"state"`
			Summary  string `json:"summary"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &recovered); err != nil {
		t.Fatalf("invalid healthy JSON %q: %v", stdout.String(), err)
	}
	if len(recovered.Results) != 1 || recovered.Results[0].ModuleID != "healthy@v1" || recovered.Results[0].State != "succeeded" || recovered.Results[0].Summary != "healthy module recovered" {
		t.Fatalf("recovered results = %#v", recovered.Results)
	}
}

func TestTimedOutPythonModuleDoesNotPoisonDaemonForNextThrow(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixtures(t,
		testsupport.PythonModuleFixture{
			ID: "slow",
			Body: `
import time

while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "slow", "version": "v1", "moduleType": "exploit"}
    elif method == "schema":
        response["result"] = {}
    elif method == "execute":
        time.sleep(10)
        response["result"] = {"status": "succeeded", "summary": "too late", "findings": [], "artifacts": []}
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`,
		},
		testsupport.PythonModuleFixture{
			ID: "healthy",
			Body: `
while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "healthy", "version": "v1", "moduleType": "exploit"}
    elif method == "schema":
        response["result"] = {}
    elif method == "execute":
        response["result"] = {"status": "succeeded", "summary": "healthy after timeout", "findings": [], "artifacts": []}
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`,
		},
	))
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	client, err := daemonrpc.Dial(fixture.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = client.RunMockExploit(timeoutCtx, daemonrpc.RunMockExploitRequest{
		ModuleID: "slow",
		Target:   "mock://target",
	})
	cancel()
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("slow module error = %v, want context deadline exceeded", err)
	}

	result, err := client.RunMockExploit(context.Background(), daemonrpc.RunMockExploitRequest{
		ModuleID: "healthy",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatalf("healthy throw failed after slow timeout: %v", err)
	}
	if result.ModuleID != "healthy@v1" || result.State != "succeeded" || result.Summary != "healthy after timeout" {
		t.Fatalf("healthy result = %#v", result)
	}
}

func TestPythonFileArtifactMaterializesThroughDaemonThrow(t *testing.T) {
	t.Setenv("HOVEL_MODULE_CONFIG", testsupport.WritePythonModuleFixture(t, "file-artifact", `
import os
import tempfile

while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {"name": "file-artifact", "version": "v1", "moduleType": "exploit"}
    elif method == "schema":
        response["result"] = {}
    elif method == "execute":
        fd, path = tempfile.mkstemp(prefix="hovel-artifact-", suffix=".bin")
        with os.fdopen(fd, "wb") as handle:
            handle.write(b"large-artifact:" + b"x" * (1024 * 1024))
        response["result"] = {
            "status": "succeeded",
            "summary": "file artifact emitted",
            "findings": [],
            "artifacts": [{"name": "loot.bin", "kind": "application/octet-stream", "path": path}],
        }
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`))
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "file-artifact", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("throw exit code = %d, stderr = %s", code, stderr.String())
	}
	var payload struct {
		ThrowID string `json:"throwId"`
		Results []struct {
			RunID     string `json:"runId"`
			ModuleID  string `json:"moduleId"`
			State     string `json:"state"`
			Summary   string `json:"summary"`
			Artifacts []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
				Data string `json:"data"`
			} `json:"artifacts"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if len(payload.Results) != 1 || payload.Results[0].ModuleID != "file-artifact@v1" || payload.Results[0].State != "succeeded" {
		t.Fatalf("results = %#v", payload.Results)
	}
	if len(payload.Results[0].Artifacts) != 1 || payload.Results[0].Artifacts[0].Name != "loot.bin" || payload.Results[0].Artifacts[0].Data != "" {
		t.Fatalf("payload artifacts = %#v, want materialized file artifact without inline data", payload.Results[0].Artifacts)
	}

	records, err := filesystem.NewWorkspaceStore().ListArtifacts(context.Background(), fixture.WorkspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("artifact records = %#v, want one", records)
	}
	record := records[0]
	if record.ThrowID != payload.ThrowID || record.RunID != payload.Results[0].RunID || record.ModuleID != "file-artifact@v1" || record.Name != "loot.bin" {
		t.Fatalf("artifact record = %#v, payload = %#v", record, payload)
	}
	copied, err := os.ReadFile(filepath.Join(fixture.WorkspacePath, record.Path))
	if err != nil {
		t.Fatal(err)
	}
	wantSize := len("large-artifact:") + 1024*1024
	if record.Size != wantSize || len(copied) != wantSize {
		t.Fatalf("artifact size record=%d bytes=%d want %d", record.Size, len(copied), wantSize)
	}
	sum := sha256.Sum256(copied)
	if gotSHA := hex.EncodeToString(sum[:]); record.SHA256 != gotSHA {
		t.Fatalf("artifact sha = %s, want %s", record.SHA256, gotSHA)
	}
	if !bytes.HasPrefix(copied, []byte("large-artifact:")) {
		t.Fatalf("artifact bytes missing prefix")
	}
}

func TestThrowMissingModuleConfigReturnsCommandError(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "missing-modules.json")
	t.Setenv("HOVEL_MODULE_CONFIG", missingConfig)
	fixture := testsupport.StartDaemon(t, daemonruntime.Args{
		IDs:       &sequenceIDs{values: []string{"run-1", "event-1"}},
		Clock:     fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		StartedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"throw", "--chain", "missing", "--target", "mock://target", "--workspace", fixture.WorkspacePath, "--now", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no JSON payload", stdout.String())
	}
	if !strings.Contains(stderr.String(), missingConfig) {
		t.Fatalf("stderr = %q, want missing module config path", stderr.String())
	}
}
