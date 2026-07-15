package commandmode

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	moduleConfigDir, err := os.MkdirTemp("", "hovel-commandmode-test-*")
	if err != nil {
		panic(err)
	}
	pythonSDKRoot, err := writeCommandModePythonSDKFixture(moduleConfigDir)
	if err != nil {
		panic(err)
	}
	moduleConfigPath, err := writeCommandModeModuleFixture(moduleConfigDir)
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("HOVEL_PYTHON_SDK_ROOT", pythonSDKRoot); err != nil {
		panic(err)
	}
	if err := os.Setenv("HOVEL_MODULE_CONFIG", moduleConfigPath); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := os.RemoveAll(moduleConfigDir); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func writeCommandModeModuleFixture(root string) (string, error) {
	packageDir := filepath.Join(root, "mock_exploit", "mock_exploit")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(packageDir, "__main__.py"), []byte(commandModeMockExploitModule), 0o644); err != nil {
		return "", err
	}
	configPath := filepath.Join(root, "hovel-modules.json")
	config := fmt.Sprintf(`{"modules":[{"id":"mock-exploit","runtime":"jsonrpc-stdio","project_dir":%q,"module":"mock_exploit"}]}`+"\n", filepath.Join(root, "mock_exploit"))
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		return "", err
	}
	return configPath, nil
}

func writeCommandModePythonSDKFixture(root string) (string, error) {
	sdkRoot := filepath.Join(root, "sdk", "python")
	packageDir := filepath.Join(sdkRoot, "hovel_sdk")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(packageDir, "__init__.py"), []byte(""), 0o644); err != nil {
		return "", err
	}
	return sdkRoot, nil
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

func waitFor(t *testing.T, condition func() bool) {
	testsupport.WaitFor(t, condition)
}

type eventRecorder struct {
	events []event.Event
}

func (r *eventRecorder) Append(_ context.Context, evt event.Event) error {
	r.events = append(r.events, evt)
	return nil
}

func hasEvent(events []event.Event, typ string) bool {
	for _, evt := range events {
		if evt.Type.String() == typ {
			return true
		}
	}
	return false
}

const commandModeMockExploitModule = `import json
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

while True:
    request = json.loads(read().decode())
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "handshake":
        response["result"] = {
            "name": "mock-exploit",
            "version": "v0.0.0-example",
            "moduleType": "exploit",
        }
    elif method == "schema":
        response["result"] = {}
    elif method == "execute":
        response["result"] = {
            "status": "succeeded",
            "summary": "example exploit completed without target interaction",
            "findings": [
                {
                    "title": "example exploit path verified",
                    "severity": "info",
                    "detail": "the example module exercised orchestration without touching a real target",
                }
            ],
            "artifacts": [
                {
                    "name": "mock-exploit-transcript.txt",
                    "kind": "text/plain",
                    "data": "example module invoked through daemon RPC",
                }
            ],
            "outputs": {},
            "sessions": [],
        }
    elif method == "shutdown":
        response["result"] = {}
        send(response)
        break
    else:
        response["error"] = {"message": "unknown method " + str(method)}
    send(response)
`
