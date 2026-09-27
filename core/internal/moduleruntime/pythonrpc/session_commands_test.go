package pythonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

const sessionCommandsFixtureArg = "--hovel-session-commands-fixture"

func init() {
	if len(os.Args) != 2 || os.Args[1] != sessionCommandsFixtureArg {
		return
	}
	if err := serveSessionCommandsFixture(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func serveSessionCommandsFixture() error {
	reader := framing.NewReader(os.Stdin, framing.DefaultMaxBytes)
	for {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Request run.PayloadCommandRequest `json:"request"`
			} `json:"params"`
		}
		if err := reader.ReadJSON(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var result any = map[string]any{}
		switch request.Method {
		case "handshake":
			result = map[string]any{"name": "session-commands", "version": "v0.0.0-test", "moduleType": "survey"}
		case "schema":
			result = map[string]any{"chainConfig": []any{}, "targetConfig": []any{}}
		case "execute":
			result = map[string]any{"status": "succeeded", "summary": "retained connection", "sessions": []any{map[string]any{
				"id": "session-1", "runId": "run-1", "moduleId": "session-commands@v0.0.0-test",
				"target": "mock://target", "name": "connection", "kind": "connection", "state": "open", "transport": "test",
			}}}
		case "session/read":
			result = map[string]any{"data": ""}
		case "session.command.list":
			result = map[string]any{"commands": []any{map[string]any{"name": "inspect", "readOnly": true}}}
		case "session.command.run":
			result = map[string]any{"command": request.Params.Request.Command, "stdout": strings.Join(request.Params.Request.Args, ","),
				"fields": map[string]string{"ownerPid": fmt.Sprint(os.Getpid())}}
		case "session/close", "shutdown":
			result = map[string]any{"status": "ok"}
		}
		if err := framing.WriteJSON(os.Stdout, map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}); err != nil {
			return err
		}
		if request.Method == "shutdown" {
			return nil
		}
	}
}

func TestRetainedNonPayloadSessionCommandsStayWithOwnerAndEndOnClose(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "modules.json")
	config, err := json.Marshal(ModuleConfig{Modules: []ModuleEntry{{
		ID: "session-commands", Runtime: "jsonrpc-stdio", Command: []string{executable, sessionCommandsFixtureArg},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	broker := NewSessionBroker()
	request, err := run.NewRequest(run.RequestArgs{ID: "run-1", ModuleID: "session-commands", Target: "mock://target"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Runner{ConfigPath: configPath, Sessions: broker}).Run(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].InstalledPayloadID != "" {
		t.Fatalf("sessions = %#v, want one ordinary non-payload session", result.Sessions)
	}
	commands, err := broker.ListSessionCommands(t.Context(), "session-1", run.PayloadCommandListRequest{})
	if err != nil || len(commands) != 1 || commands[0].Name != "inspect" {
		t.Fatalf("commands = %#v, error = %v", commands, err)
	}
	type outcome struct {
		label  string
		result run.PayloadCommandResult
		err    error
	}
	start := make(chan struct{})
	completed := make(chan outcome, 2)
	for _, label := range []string{"first", "second"} {
		go func() {
			<-start
			value, callErr := broker.RunSessionCommand(context.Background(), "session-1", run.PayloadCommandRequest{Command: "inspect", Args: []string{label}})
			completed <- outcome{label, value, callErr}
		}()
	}
	close(start)
	ownerPID := ""
	for range 2 {
		got := <-completed
		if got.err != nil || got.result.Command != "inspect" || got.result.Stdout != got.label || got.result.Fields["ownerPid"] == "" {
			t.Fatalf("correlated command %q = %#v, error = %v", got.label, got.result, got.err)
		}
		if ownerPID != "" && got.result.Fields["ownerPid"] != ownerPID {
			t.Fatalf("commands reached different owners: %q and %q", ownerPID, got.result.Fields["ownerPid"])
		}
		ownerPID = got.result.Fields["ownerPid"]
	}
	if err := broker.CloseSession(t.Context(), "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ListSessionCommands(t.Context(), "session-1", run.PayloadCommandListRequest{}); err == nil {
		t.Fatal("closed session still lists commands")
	}
	if _, err := broker.RunSessionCommand(t.Context(), "session-1", run.PayloadCommandRequest{Command: "inspect"}); err == nil {
		t.Fatal("closed session accepted a command or recreated an owner")
	}
}
