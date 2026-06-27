package testsupport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

const ExampleModuleConfig = "examples/python/hovel-modules.json"

func UseExampleModuleConfig(t testing.TB) {
	t.Helper()
	t.Setenv("HOVEL_MODULE_CONFIG", ResolveRunfile(ExampleModuleConfig))
}

func ExampleModuleConfigPath() string {
	return ResolveRunfile(ExampleModuleConfig)
}

func ResolveRunfile(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if candidate, ok := runfileManifestLookup(path); ok {
		return candidate
	}
	for _, root := range runfileRoots() {
		candidate := filepath.Join(root, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}

func runfileRoots() []string {
	var roots []string
	if runfiles := os.Getenv("RUNFILES_DIR"); runfiles != "" {
		roots = append(roots,
			runfiles,
			filepath.Join(runfiles, "hovel"),
			filepath.Join(runfiles, "_main"),
		)
	}
	if testSrcDir := os.Getenv("TEST_SRCDIR"); testSrcDir != "" {
		roots = append(roots,
			testSrcDir,
			filepath.Join(testSrcDir, "hovel"),
			filepath.Join(testSrcDir, "_main"),
		)
		if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
			roots = append(roots, filepath.Join(testSrcDir, workspace))
		}
	}
	if exe, err := os.Executable(); err == nil {
		runfiles := exe + ".runfiles"
		roots = append(roots,
			runfiles,
			filepath.Join(runfiles, "hovel"),
			filepath.Join(runfiles, "_main"),
		)
	}
	return roots
}

func runfileManifestLookup(path string) (string, bool) {
	manifest := os.Getenv("RUNFILES_MANIFEST_FILE")
	if manifest == "" {
		return "", false
	}
	file, err := os.Open(manifest)
	if err != nil {
		return "", false
	}
	defer file.Close()
	keys := []string{
		filepath.ToSlash(path),
		filepath.ToSlash(filepath.Join("_main", path)),
		filepath.ToSlash(filepath.Join("hovel", path)),
	}
	if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
		keys = append(keys, filepath.ToSlash(filepath.Join(workspace, path)))
	}
	wanted := map[string]struct{}{}
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			continue
		}
		if _, ok := wanted[key]; ok {
			return value, true
		}
	}
	return "", false
}

func TempDir(t testing.TB) string {
	t.Helper()
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "hovel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func WaitFor(t testing.TB, condition func() bool, details ...func() string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	var extra []string
	for _, detail := range details {
		if text := strings.TrimSpace(detail()); text != "" {
			extra = append(extra, text)
		}
	}
	if len(extra) == 0 {
		t.Fatal("condition was not met before deadline")
	}
	t.Fatalf("condition was not met before deadline:\n%s", strings.Join(extra, "\n"))
}

type DaemonFixture struct {
	WorkspacePath string
	SocketPath    string
	cancel        context.CancelFunc
	errs          chan error
}

type ThrowAuditObservation struct {
	PlanID         string
	PlanHash       string
	ConfirmationID string
	ThrowID        string
	Chain          string
	Targets        []string
	ExpectedMethod string
}

func StartDaemon(t testing.TB, args daemonruntime.Args) DaemonFixture {
	t.Helper()
	if args.WorkspacePath == "" {
		args.WorkspacePath = TempDir(t)
	}
	if args.SocketPath == "" {
		args.SocketPath = filepath.Join(args.WorkspacePath, "hoveld.sock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- daemonruntime.Serve(ctx, args)
	}()
	fixture := DaemonFixture{
		WorkspacePath: args.WorkspacePath,
		SocketPath:    args.SocketPath,
		cancel:        cancel,
		errs:          errs,
	}
	var lastStatus string
	WaitFor(t, func() bool {
		select {
		case err := <-errs:
			cancel()
			t.Fatalf("daemon exited before reporting running status: %v", err)
		default:
		}
		status, err := filesystem.NewWorkspaceStore().DaemonStatus(context.Background(), args.WorkspacePath)
		lastStatus = fmt.Sprintf("workspace=%s socket=%s status=%#v err=%v", args.WorkspacePath, args.SocketPath, status, err)
		return err == nil && status.State == daemon.StateRunning
	}, func() string {
		return lastStatus
	})
	t.Cleanup(func() { fixture.Stop(t) })
	return fixture
}

func (f DaemonFixture) Stop(t testing.TB) {
	t.Helper()
	if f.cancel == nil || f.errs == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.errs:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("daemon did not stop within 2s for workspace %s", f.WorkspacePath)
	}
}

func AssertThrowAuditTrail(t testing.TB, workspacePath string, observation ThrowAuditObservation) {
	t.Helper()
	if observation.ExpectedMethod == "" {
		observation.ExpectedMethod = "now_bypass"
	}
	store := filesystem.NewWorkspaceStore()
	ctx := context.Background()
	plan, err := store.GetThrowPlan(ctx, workspacePath, observation.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	assertThrowPlan(t, workspacePath, plan, observation)
	confirmation, ok, err := store.GetThrowConfirmation(ctx, workspacePath, observation.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("throw confirmation for plan hash %s was not persisted", observation.PlanHash)
	}
	if confirmation.ID != observation.ConfirmationID || confirmation.PlanID != observation.PlanID || confirmation.PlanHash != observation.PlanHash || confirmation.Method != observation.ExpectedMethod {
		t.Fatalf("throw confirmation = %#v, observation = %#v", confirmation, observation)
	}
	if confirmation.Workspace != workspacePath {
		t.Fatalf("throw confirmation workspace = %q, want %q", confirmation.Workspace, workspacePath)
	}
	events, err := store.ListEvents(ctx, workspacePath, event.Filter{PlanHash: observation.PlanHash})
	if err != nil {
		t.Fatal(err)
	}
	assertEventTypes(t, events, []string{
		"hovel.throw.planned",
		"hovel.throw.confirmed",
		"hovel.throw.started",
		"hovel.throw.completed",
	})
	if observation.ThrowID != "" {
		if !hasEventWithThrowID(events, observation.ThrowID) {
			t.Fatalf("events for plan %s did not reference throw %s: %#v", observation.PlanHash, observation.ThrowID, events)
		}
	}
}

func assertThrowPlan(t testing.TB, workspacePath string, plan commands.ThrowPlanRecord, observation ThrowAuditObservation) {
	t.Helper()
	if plan.ID != observation.PlanID || plan.PlanHash != observation.PlanHash || plan.ConfirmationID != observation.ConfirmationID || plan.Chain != observation.Chain {
		t.Fatalf("throw plan = %#v, observation = %#v", plan, observation)
	}
	if plan.Workspace != workspacePath {
		t.Fatalf("throw plan workspace = %q, want %q", plan.Workspace, workspacePath)
	}
	if strings.Join(plan.Targets, ",") != strings.Join(observation.Targets, ",") {
		t.Fatalf("throw plan targets = %#v, want %#v", plan.Targets, observation.Targets)
	}
	if plan.Intent == "" || plan.Review == "" {
		t.Fatalf("throw plan missing reviewable audit fields: %#v", plan)
	}
}

func assertEventTypes(t testing.TB, events []event.Event, want []string) {
	t.Helper()
	for _, typ := range want {
		if !hasEventType(events, typ) {
			t.Fatalf("events missing %s: %#v", typ, events)
		}
	}
}

func hasEventType(events []event.Event, typ string) bool {
	for _, evt := range events {
		if evt.Type.String() == typ {
			return true
		}
	}
	return false
}

func hasEventWithThrowID(events []event.Event, throwID string) bool {
	for _, evt := range events {
		if evt.Refs.ThrowID == throwID {
			return true
		}
	}
	return false
}

type PythonModuleFixture struct {
	ID   string
	Body string
}

func WritePythonModuleFixture(t testing.TB, moduleID, body string) string {
	return WritePythonModuleFixtures(t, PythonModuleFixture{ID: moduleID, Body: body})
}

func WritePythonModuleFixtures(t testing.TB, modules ...PythonModuleFixture) string {
	t.Helper()
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	config := struct {
		Modules []struct {
			ID         string `json:"id"`
			Runtime    string `json:"runtime"`
			ProjectDir string `json:"project_dir"`
			Module     string `json:"module"`
		} `json:"modules"`
	}{}
	for _, module := range modules {
		if module.ID == "" {
			t.Fatal("python module fixture id is required")
		}
		packageName := pythonPackageName(module.ID)
		packageDir := filepath.Join(projectDir, packageName)
		if err := os.MkdirAll(packageDir, 0o755); err != nil {
			t.Fatal(err)
		}
		main := `import json
import sys

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    return sys.stdin.buffer.read(length)

def send(message):
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

` + module.Body + "\n"
		if err := os.WriteFile(filepath.Join(packageDir, "__main__.py"), []byte(main), 0o644); err != nil {
			t.Fatal(err)
		}
		config.Modules = append(config.Modules, struct {
			ID         string `json:"id"`
			Runtime    string `json:"runtime"`
			ProjectDir string `json:"project_dir"`
			Module     string `json:"module"`
		}{
			ID:         module.ID,
			Runtime:    "jsonrpc-stdio",
			ProjectDir: projectDir,
			Module:     packageName,
		})
	}
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "modules.json")
	if err := os.WriteFile(configPath, configBody, 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func pythonPackageName(moduleID string) string {
	var b strings.Builder
	for _, r := range moduleID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" || out[0] >= '0' && out[0] <= '9' {
		return "fixture_" + out
	}
	return out
}
