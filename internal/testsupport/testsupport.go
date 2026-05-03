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
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
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

func WritePythonModuleFixture(t testing.TB, moduleID, body string) string {
	t.Helper()
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	packageName := pythonPackageName(moduleID)
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

` + body + "\n"
	if err := os.WriteFile(filepath.Join(packageDir, "__main__.py"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	config := struct {
		Modules []struct {
			ID         string `json:"id"`
			Runtime    string `json:"runtime"`
			ProjectDir string `json:"project_dir"`
			Module     string `json:"module"`
		} `json:"modules"`
	}{}
	config.Modules = append(config.Modules, struct {
		ID         string `json:"id"`
		Runtime    string `json:"runtime"`
		ProjectDir string `json:"project_dir"`
		Module     string `json:"module"`
	}{
		ID:         moduleID,
		Runtime:    "jsonrpc-stdio",
		ProjectDir: projectDir,
		Module:     packageName,
	})
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
