package pythonrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

func TestRunnerExecutesPythonMockModule(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	result, err := Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1", "event-2", "event-3"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "example exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Data == "" {
		t.Fatalf("artifacts = %#v, want inline artifact data", result.Artifacts)
	}
	if len(events.events) == 0 || events.events[0].Type.String() != "hovel.module.log" {
		t.Fatalf("events = %#v, want hovel.module.log", events.events)
	}
}

func TestArtifactsFromRPCSupportsFileReferences(t *testing.T) {
	artifacts := artifactsFromRPC([]any{
		map[string]any{"name": "loot.txt", "kind": "text/plain", "path": "/tmp/loot.txt"},
	})
	if len(artifacts) != 1 {
		t.Fatalf("artifacts = %#v, want one", artifacts)
	}
	if artifacts[0].Path != "/tmp/loot.txt" || artifacts[0].Data != "" {
		t.Fatalf("artifact = %#v, want file reference without data", artifacts[0])
	}
}

func TestRunnerInspectsPythonModuleDeclaredSchema(t *testing.T) {
	module, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Inspect(context.Background(), "mock-exploit")
	if err != nil {
		t.Fatal(err)
	}
	if module.ID != "mock-exploit@v0.0.0-example" {
		t.Fatalf("id = %q, want mock-exploit@v0.0.0-example", module.ID)
	}
	if module.RuntimeKind != "jsonrpc-stdio" {
		t.Fatalf("runtime = %q, want jsonrpc-stdio", module.RuntimeKind)
	}
	if len(module.ChainConfig) != 1 || module.ChainConfig[0].Key != "operator.confirmed_lab" {
		t.Fatalf("chain config = %#v", module.ChainConfig)
	}
	if len(module.TargetConfig) != 2 || module.TargetConfig[0].Key != "target.host" {
		t.Fatalf("target config = %#v", module.TargetConfig)
	}
}

func TestRunnerLaunchesEveryBuiltInMockModule(t *testing.T) {
	for _, moduleID := range []string{"mock-survey", "mock-exploit", "mock-exploit-session"} {
		t.Run(moduleID, func(t *testing.T) {
			request, err := run.NewRequest(run.RequestArgs{
				ID:       "run-1",
				ModuleID: moduleID,
				Target:   "mock://target",
				ChainConfig: map[string]string{
					"delay":        "0s",
					"failure_mode": "execution",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Summary == "" {
				t.Fatal("summary is empty")
			}
		})
	}
}

func TestRunnerKeepsPythonSessionModuleAliveBehindBroker(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit-session",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := NewSessionBroker()
	result, err := Runner{
		ConfigPath: exampleModuleConfig,
		Timeout:    10 * time.Second,
		Sessions:   broker,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("sessions = %#v, want one session", result.Sessions)
	}
	sessionID := result.Sessions[0].ID
	sessions, err := broker.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != sessionID {
		t.Fatalf("broker sessions = %#v, want %s", sessions, sessionID)
	}
	prompt, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(prompt.Data) != "mock$ " {
		t.Fatalf("prompt = %q, want mock prompt", string(prompt.Data))
	}
	if err := broker.WriteSession(context.Background(), sessionID, []byte("whoami\n")); err != nil {
		t.Fatal(err)
	}
	echo, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(echo.Data) != "whoami\n" {
		t.Fatalf("echo = %q, want whoami", string(echo.Data))
	}
	output, err := broker.ReadSession(context.Background(), sessionID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(output.Data) != "mock-operator\n" {
		t.Fatalf("output = %q, want mock operator", string(output.Data))
	}
	if err := broker.CloseSession(context.Background(), sessionID); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerExecutesCanonicalModuleReference(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-exploit@v0.0.0-example",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateSucceeded {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
}

func TestRunnerMapsFailedPythonResult(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:          "run-1",
		ModuleID:    "mock-exploit",
		Target:      "mock://target",
		ChainConfig: map[string]string{"failure_mode": "execution"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Runner{ConfigPath: exampleModuleConfig, Timeout: 10 * time.Second}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != run.StateFailed {
		t.Fatalf("state = %q, want failed", result.State)
	}
}

func TestRunnerCapturesModuleLogs(t *testing.T) {
	request, err := run.NewRequest(run.RequestArgs{
		ID:       "run-1",
		ModuleID: "mock-survey",
		Target:   "mock://target",
		TargetConfig: map[string]string{
			"target.host": "target",
			"target.port": "443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &eventRecorder{}
	_, err = Runner{
		ConfigPath: exampleModuleConfig,
		Events:     events,
		IDs:        &sequenceIDs{values: []string{"event-1", "event-2", "event-3"}},
		Clock:      fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
		Timeout:    10 * time.Second,
	}.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(events.events) == 0 {
		t.Fatal("event count = 0, want module log events")
	}
}

func TestRunnerHasNoModulesWithoutConfig(t *testing.T) {
	catalog, err := Runner{}.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if modules := catalog.List(); len(modules) != 0 {
		t.Fatalf("modules = %#v, want none", modules)
	}
}

func TestRunnerReportsPythonProtocolFailures(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		inspect bool
		timeout time.Duration
		want    string
	}{
		{
			name:    "handshake error includes stderr",
			body:    `import sys; print("handshake stderr", file=sys.stderr); send({"jsonrpc":"2.0","id":1,"error":{"message":"no handshake"}})`,
			inspect: true,
			want:    "module handshake failed: no handshake: handshake stderr",
		},
		{
			name:    "malformed frame",
			body:    `import sys; sys.stdout.buffer.write(b"Content-Length: 1\r\n\r\n{"); sys.stdout.buffer.flush()`,
			inspect: true,
			want:    "module handshake failed",
		},
		{
			name: "execute error",
			body: `read(); send({"jsonrpc":"2.0","id":1,"result":{"moduleType":"exploit"}}); read(); send({"jsonrpc":"2.0","id":2,"result":{}}); read(); send({"jsonrpc":"2.0","id":3,"error":{"message":"execute denied"}})`,
			want: "module execute failed: execute denied",
		},
		{
			name:    "timeout",
			body:    `import time; time.sleep(2)`,
			inspect: true,
			timeout: 50 * time.Millisecond,
			want:    "context deadline exceeded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writePythonModuleFixture(t, tc.body)
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			runner := Runner{ConfigPath: configPath, Timeout: timeout}
			var err error
			if tc.inspect {
				_, err = runner.Inspect(context.Background(), "broken")
			} else {
				request, requestErr := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "broken", Target: "mock://target"})
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				_, err = runner.Run(context.Background(), request)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestRPCClientTimeoutDoesNotCorruptNextCall(t *testing.T) {
	moduleStdoutReader, moduleStdoutWriter := io.Pipe()
	moduleStdinReader, moduleStdinWriter := io.Pipe()
	defer moduleStdoutReader.Close()
	defer moduleStdoutWriter.Close()
	defer moduleStdinReader.Close()
	defer moduleStdinWriter.Close()

	client := newClient(moduleStdoutReader, moduleStdinWriter)
	done := make(chan error, 1)
	go func() {
		decoder := newFrameDecoder(moduleStdinReader)
		first, err := decoder.read()
		if err != nil {
			done <- err
			return
		}
		time.Sleep(50 * time.Millisecond)
		if err := writeFrame(moduleStdoutWriter, map[string]any{
			"jsonrpc": "2.0",
			"id":      first.ID,
			"result":  map[string]any{"call": "late-first"},
		}); err != nil {
			done <- err
			return
		}
		second, err := decoder.read()
		if err != nil {
			done <- err
			return
		}
		if err := writeFrame(moduleStdoutWriter, map[string]any{
			"jsonrpc": "2.0",
			"id":      second.ID,
			"result":  map[string]any{"call": "second"},
		}); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err := client.call(ctx, "first", nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("first call error = %v, want deadline", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	result, err := client.call(ctx, "second", nil)
	cancel()
	if err != nil {
		t.Fatalf("second call failed after first timeout: %v", err)
	}
	if result["call"] != "second" {
		t.Fatalf("second result = %#v, want second response", result)
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

const exampleModuleConfig = "examples/python/hovel-modules.json"

func writePythonModuleFixture(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	packageDir := filepath.Join(projectDir, "broken_module")
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
	config := ModuleConfig{Modules: []ModuleEntry{{
		ID:         "broken",
		Runtime:    "jsonrpc-stdio",
		ProjectDir: projectDir,
		Module:     "broken_module",
	}}}
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

type eventRecorder struct {
	events []event.Event
}

func (r *eventRecorder) Append(_ context.Context, evt event.Event) error {
	r.events = append(r.events, evt)
	return nil
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	if s.next >= len(s.values) {
		s.next++
		return fmt.Sprintf("event-%d", s.next)
	}
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}
