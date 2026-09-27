package pythonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

func TestFrameDecoderRejectsOversizedModuleNotification(t *testing.T) {
	var frame strings.Builder
	err := writeFrame(&frame, map[string]any{
		"jsonrpc": "2.0",
		"method":  "module/log",
		"params": map[string]any{
			"message": strings.Repeat("x", maxModuleNotificationBytes),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = newFrameDecoder(strings.NewReader(frame.String())).read()
	if err == nil || !strings.Contains(err.Error(), "module/log params size") {
		t.Fatalf("error = %v, want module notification size error", err)
	}
}

func TestCapturedStderrRetainsBoundedTail(t *testing.T) {
	stderr := newCapturedStderr()
	wantTail := strings.Repeat("z", maxCapturedStderrBytes)
	if _, err := stderr.Write([]byte("discarded" + wantTail)); err != nil {
		t.Fatal(err)
	}

	got := stderr.String()
	if len(got) != maxCapturedStderrBytes {
		t.Fatalf("captured stderr bytes = %d, want %d", len(got), maxCapturedStderrBytes)
	}
	if !strings.HasPrefix(got, stderrTruncationMarker) {
		t.Fatalf("captured stderr missing truncation marker: %q", got[:len(stderrTruncationMarker)])
	}
	if !strings.HasSuffix(got, strings.Repeat("z", maxCapturedStderrBytes-len(stderrTruncationMarker))) {
		t.Fatal("captured stderr did not retain the newest bytes")
	}
}

func TestRPCClientRetainsBoundedLogTail(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprintf("live=%t", live), func(t *testing.T) {
			client := &rpcClient{}
			var delivered []rpcLog
			if live {
				client.setOnLog(func(entry rpcLog) error {
					delivered = append(delivered, entry)
					return nil
				})
			}
			var want []rpcLog
			var firstSnapshot []rpcLog
			for index := range 4096 {
				entry := rpcLog{Message: fmt.Sprintf("log %d", index),
					Fields: map[string]any{"index": index}, ReceivedAt: time.Unix(int64(index), 0).UTC()}
				want = append(want, entry)
				if err := client.handleNotification(rpcMessage{Method: "module/log", Log: entry}); err != nil {
					t.Fatalf("handle module log %d: %v", index+1, err)
				}
				history := client.logsSnapshot()
				if len(history) > maxBufferedModuleLogs {
					t.Fatalf("buffered module logs = %d, exceeds %d", len(history), maxBufferedModuleLogs)
				}
				if index == maxBufferedModuleLogs-1 {
					firstSnapshot = history
				}
			}
			if !reflect.DeepEqual(client.logsSnapshot(), want[len(want)-maxBufferedModuleLogs:]) {
				t.Fatal("history did not retain the newest logs in order")
			}
			if !reflect.DeepEqual(firstSnapshot, want[:maxBufferedModuleLogs]) {
				t.Fatal("overflow changed an earlier snapshot")
			}
			if live && !reflect.DeepEqual(delivered, want) {
				t.Fatal("live delivery lost, duplicated, reordered or changed logs")
			}
		})
	}
}

func TestRPCClientPropagatesLogCallbackErrorAfterOverflow(t *testing.T) {
	var frames strings.Builder
	for range maxBufferedModuleLogs + 1 {
		if err := writeFrame(&frames, map[string]any{"method": "module/log"}); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("event storage unavailable")
	count := 0
	client := &rpcClient{decoder: newFrameDecoder(strings.NewReader(frames.String())), done: make(chan struct{})}
	client.setOnLog(func(rpcLog) error {
		count++
		if count > maxBufferedModuleLogs {
			return want
		}
		return nil
	})
	client.readLoop()
	var callback callbackError
	if err := client.readError(); !errors.Is(err, want) || !errors.As(err, &callback) {
		t.Fatalf("read error = %v, want callback storage error", err)
	}
}

func TestRunnerRetainsSessionControlAfterLogOverflow(t *testing.T) {
	for _, initial := range []int{3, 512} {
		t.Run(fmt.Sprintf("initial=%d", initial), func(t *testing.T) {
			t.Setenv("HOVEL_TEST_LOG_SESSION", "1")
			t.Setenv("HOVEL_TEST_INITIAL_LOGS", fmt.Sprint(initial))
			config, err := json.Marshal(ModuleConfig{Modules: []ModuleEntry{{
				ID: "log-session", Command: []string{os.Args[0], "-test.run=^TestLogSessionHelper$"},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "modules.json")
			if err := os.WriteFile(configPath, config, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			request, err := run.NewRequest(run.RequestArgs{
				ID: "log-run", ModuleID: "log-session", Target: "mock://target", Operation: "op", Chain: "chain",
			})
			if err != nil {
				t.Fatal(err)
			}
			broker := NewSessionBroker()
			events := &logSessionEvents{}
			started := time.Now().UTC()
			result, err := (Runner{ConfigPath: configPath, Sessions: broker, Events: events, IDs: events, Clock: events}).Run(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Sessions) != 1 {
				t.Fatalf("sessions = %#v, want one", result.Sessions)
			}
			sessionID := result.Sessions[0].ID
			session, err := broker.lookup(sessionID)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { session.closeLocal(); session.process.killAndWait() })
			if len(result.Logs) != min(initial, maxBufferedModuleLogs) {
				t.Fatalf("result logs = %d", len(result.Logs))
			}
			for index, entry := range result.Logs {
				want := fmt.Sprint(initial - len(result.Logs) + index)
				received, err := time.Parse(time.RFC3339Nano, entry.Time)
				if err != nil || received.Before(started) || received.After(time.Now().UTC()) ||
					entry.Message != "log "+want || entry.Fields["index"] != want || entry.Fields["exception"] != "fixture detail" ||
					entry.RunID != request.ID || entry.ModuleID != "log-session@v1" || entry.Target != request.Target ||
					entry.Logger != "fixture" || entry.Level != "info" {
					t.Fatalf("result log %d = %#v", index, entry)
				}
			}
			address := result.Sessions[0].Name
			connection, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatalf("retained listener: %v", err)
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			// The write triggers 4096 more logs only after Run has returned.
			if err := broker.WriteSession(ctx, sessionID, []byte("still controlled")); err != nil {
				t.Fatalf("write after Run: %v", err)
			}
			chunk, err := broker.ReadSession(ctx, sessionID, time.Second)
			if err != nil || chunk.Closed || string(chunk.Data) != "still controlled" {
				t.Fatalf("read after overflow = %#v, %v", chunk, err)
			}
			if len(session.process.client.logsSnapshot()) != maxBufferedModuleLogs {
				t.Fatal("retained owner history is not bounded")
			}
			if err := broker.CloseSession(ctx, sessionID); err != nil {
				t.Fatalf("explicit close not acknowledged: %v", err)
			}
			if connection, err := net.DialTimeout("tcp", address, time.Second); err == nil {
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				t.Fatal("fixture listener survived explicit close")
			}
			if sessions, err := broker.ListSessions(ctx); err != nil || len(sessions) != 0 {
				t.Fatalf("sessions after close = %#v, %v", sessions, err)
			}
			count := 0
			for _, entry := range events.Events {
				if entry.Type != "hovel.module.log" {
					continue
				}
				want := fmt.Sprint(count)
				if entry.Message != "log "+want || entry.Fields["index"] != want || entry.Fields["exception"] != "fixture detail" ||
					entry.Fields["logger"] != "fixture" || entry.Level != event.LevelInfo || !entry.Timestamp.Equal(events.Now()) ||
					entry.Refs != (event.Refs{Operation: "op", Chain: "chain", RunID: request.ID, ModuleID: "log-session@v1", TargetID: request.Target}) {
					t.Fatalf("live log %d = %#v", count, entry)
				}
				count++
			}
			if count != initial+4096 {
				t.Fatalf("live logs = %d, want %d", count, initial+4096)
			}
		})
	}
}

type logSessionEvents struct {
	event.Recorder
	nextID int
}

func (e *logSessionEvents) NewID() string {
	e.nextID++
	return fmt.Sprintf("event-%d", e.nextID)
}

func (*logSessionEvents) Now() time.Time { return time.Unix(1234567890, 0).UTC() }

// Reuse the test-binary subprocess pattern from process_lifecycle_test.go.
func TestLogSessionHelper(t *testing.T) {
	if os.Getenv("HOVEL_TEST_LOG_SESSION") != "1" {
		return
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	initial := 0
	if _, err := fmt.Sscan(os.Getenv("HOVEL_TEST_INITIAL_LOGS"), &initial); err != nil {
		t.Fatal(err)
	}
	count := 0
	emit := func(n int) {
		for range n {
			if err := writeFrame(os.Stdout, map[string]any{"method": "module/log", "params": rpcLog{
				Level: "info", Logger: "fixture", Message: fmt.Sprintf("log %d", count),
				Fields: map[string]any{"index": count}, Exception: "fixture detail",
			}}); err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	reader := framing.NewReader(os.Stdin, framing.DefaultMaxBytes)
	pending := ""
	closed := false
	for {
		var request struct {
			ID     int
			Method string
			Params struct{ Data string }
		}
		if err := reader.ReadJSON(&request); err != nil {
			t.Fatal(err)
		}
		result := map[string]any{}
		switch request.Method {
		case "handshake":
			result = map[string]any{"name": "log-session", "version": "v1", "moduleType": "exploit"}
		case "schema":
		case "execute":
			emit(initial)
			result["summary"] = "retained log fixture"
			result["sessions"] = []any{map[string]any{"id": "session-1", "name": listener.Addr().String()}}
		case "session/write":
			emit(4096)
			pending = request.Params.Data
		case "session/read":
			result["data"], pending = pending, ""
			// Avoid busy polling while still servicing writes and close promptly.
			time.Sleep(time.Millisecond)
		case "session/close":
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
		case "shutdown":
			if !closed {
				t.Fatal("shutdown without explicit session close")
			}
		default:
			t.Fatalf("unexpected method %q", request.Method)
		}
		if err := writeFrame(os.Stdout, map[string]any{"id": request.ID, "result": result}); err != nil {
			t.Fatal(err)
		}
		if request.Method == "shutdown" {
			os.Exit(0) // Keep testing's PASS text off the framed protocol stream.
		}
	}
}
