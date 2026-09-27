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
	"time"

	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

const lifetimeFixtureArg = "--hovel-execution-lifetime-fixture"

func init() {
	if len(os.Args) != 4 || os.Args[1] != lifetimeFixtureArg {
		return
	}
	if err := serveLifetimeFixture(os.Args[2], os.Args[3]); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
			os.Exit(2)
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func serveLifetimeFixture(delayText, startedPath string) error {
	delay, err := time.ParseDuration(delayText)
	if err != nil {
		return err
	}
	reader := framing.NewReader(os.Stdin, framing.DefaultMaxBytes)
	for {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := reader.ReadJSON(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		result := map[string]any{}
		switch request.Method {
		case "handshake":
			result = map[string]any{"name": "lifetime", "version": "v0.0.0-test", "moduleType": "exploit"}
		case "schema":
			result = map[string]any{"chainConfig": []any{}, "targetConfig": []any{}}
		case "execute", "step.execute":
			if err := os.WriteFile(startedPath, []byte("started"), 0o600); err != nil {
				return err
			}
			time.Sleep(delay)
			result = map[string]any{"status": "succeeded", "summary": "completed after delay"}
		}
		if err := framing.WriteJSON(os.Stdout, map[string]any{
			"jsonrpc": "2.0", "id": request.ID, "result": result,
		}); err != nil {
			return err
		}
		if request.Method == rpcShutdownMethod {
			return nil
		}
	}
}

func lifetimeRunner(t *testing.T, delay time.Duration) (Runner, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	config := ModuleConfig{Modules: []ModuleEntry{{
		ID: "lifetime", Runtime: "jsonrpc-stdio",
		Command: []string{executable, lifetimeFixtureArg, delay.String(), started},
	}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "modules.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Runner{ConfigPath: path, StepProcesses: NewStepProcessBroker()}, started
}

func executeLifetime(ctx context.Context, runner Runner, step bool) error {
	if step {
		result, err := runner.ExecuteStep(ctx, StepCallRequest{
			ModuleID: "lifetime", Params: map[string]any{"runId": "lifetime-run", "stepId": "execute"},
		})
		if err == nil && result["summary"] != "completed after delay" {
			return fmt.Errorf("unexpected step result: %v", result)
		}
		return err
	}
	request, err := run.NewRequest(run.RequestArgs{
		ID: "lifetime-run", ModuleID: "lifetime", Target: "mock://target",
	})
	if err != nil {
		return err
	}
	result, err := runner.Run(ctx, request)
	if err == nil && (result.State != run.StateSucceeded || result.Summary != "completed after delay") {
		return fmt.Errorf("unexpected run result: %v", result)
	}
	return err
}

func finishLifetime(t *testing.T, runner Runner) {
	t.Helper()
	var processes []*moduleProcess
	for _, process := range runner.StepProcesses.processes {
		processes = append(processes, process)
	}
	if err := (StepRuntimeRunner{Runner: runner}).FinishRun(t.Context(), "lifetime-run"); err != nil {
		t.Fatal(err)
	}
	if len(runner.StepProcesses.processes) != 0 {
		t.Fatal("finished run retained a module process")
	}
	for _, process := range processes {
		if process.cmd.ProcessState == nil {
			t.Fatal("finished run did not reap its module process")
		}
	}
}

func TestExecutionExceedsFormerGlobalLimit(t *testing.T) {
	for _, step := range []bool{false, true} {
		t.Run(fmt.Sprintf("step=%t", step), func(t *testing.T) {
			t.Parallel()
			// Deliberately cross the former real 60-second limit. The caller
			// deadline is only a test watchdog, never a runner setting.
			runner, _ := lifetimeRunner(t, 61*time.Second)
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			start := time.Now()
			if err := executeLifetime(ctx, runner, step); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) <= 60*time.Second {
				t.Fatal("fixture did not cross the former global deadline")
			}
			finishLifetime(t, runner)
		})
	}
}

func TestExecutionHonorsCallerCancellation(t *testing.T) {
	for _, step := range []bool{false, true} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("step=%t/deadline=%t", step, deadline), func(t *testing.T) {
				t.Parallel()
				runner, started := lifetimeRunner(t, 4*time.Second)
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- executeLifetime(ctx, runner, step) }()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					if _, err := os.Stat(started); err == nil {
						break
					}
					select {
					case err := <-done:
						t.Fatalf("execution ended before fixture started: %v", err)
					case <-ticker.C:
					}
				}
				want := context.DeadlineExceeded
				if !deadline {
					want = context.Canceled
					cancel()
				}
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), want.Error()) {
						t.Fatalf("execution error = %v, want %v", err, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("execution did not honor caller cancellation")
				}
				finishLifetime(t, runner)
			})
		}
	}
}
