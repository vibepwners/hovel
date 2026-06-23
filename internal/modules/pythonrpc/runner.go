package pythonrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/hovelconfig"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/protocol/framing"
)

const defaultTimeout = 60 * time.Second
const stderrSettleTimeout = 50 * time.Millisecond
const maxFrameBytes = framing.DefaultMaxBytes

const ModuleConfigEnv = "HOVEL_MODULE_CONFIG"

type ModuleConfig struct {
	Modules []ModuleEntry `json:"modules"`
}

type ModuleEntry struct {
	ID         string   `json:"id"`
	Runtime    string   `json:"runtime"`
	ProjectDir string   `json:"project_dir"`
	Module     string   `json:"module"`
	Command    []string `json:"command"`
}

type CatalogInfo struct {
	ConfigPath string
	Modules    []modulecatalog.Module
}

// usesCommand reports whether the entry launches an arbitrary executable
// (any language that speaks the stdio JSON-RPC protocol) rather than the
// built-in Python interpreter path.
func (e ModuleEntry) usesCommand() bool {
	return len(e.Command) > 0
}

type Runner struct {
	PythonPath    string
	SDKRoot       string
	ConfigPath    string
	HovelConfig   string
	WorkspacePath string
	Events        services.EventSink
	IDs           services.IDGenerator
	Clock         services.Clock
	Timeout       time.Duration
	Sessions      *SessionBroker
	StepProcesses *StepProcessBroker
}

type StepCallRequest struct {
	ModuleID string
	Params   map[string]any
}

func ConfiguredCatalog(ctx context.Context) (modulecatalog.Catalog, error) {
	return Runner{}.Catalog(ctx)
}

func ConfiguredCatalogInfo(ctx context.Context) (CatalogInfo, error) {
	return CatalogInfoForConfig(ctx, "")
}

func CatalogInfoForConfig(ctx context.Context, configPath string) (CatalogInfo, error) {
	runner := Runner{ConfigPath: configPath}
	path, pathErr := resolveConfigPath(runner.configPath())
	info := CatalogInfo{ConfigPath: path}
	if pathErr != nil {
		return info, pathErr
	}
	catalog, err := runner.Catalog(ctx)
	if err != nil {
		return info, err
	}
	info.Modules = catalog.List()
	return info, nil
}

func MustConfiguredCatalog() modulecatalog.Catalog {
	return MustConfiguredCatalogWithWarning(os.Stderr)
}

// MustConfiguredCatalogWithWarning loads the configured module catalog, falling
// back to an empty catalog if loading fails. Unlike a silent fallback, the
// underlying error is reported to warn so operators can tell "no modules
// configured" apart from "module configuration failed to load".
func MustConfiguredCatalogWithWarning(warn io.Writer) modulecatalog.Catalog {
	catalog, err := ConfiguredCatalog(context.Background())
	if err != nil {
		if warn != nil {
			fmt.Fprintf(warn, "hovel: failed to load module catalog: %v\n", err)
		}
		return modulecatalog.New()
	}
	return catalog
}

func (r Runner) Catalog(ctx context.Context) (modulecatalog.Catalog, error) {
	entries, err := r.moduleEntries()
	if err != nil {
		return modulecatalog.Catalog{}, err
	}
	modules := make([]modulecatalog.Module, 0, len(entries))
	for _, entry := range entries {
		module, err := r.Inspect(ctx, entry.ID)
		if err != nil {
			return modulecatalog.Catalog{}, err
		}
		modules = append(modules, module)
	}
	return modulecatalog.New(modules...), nil
}

func (r Runner) Inspect(ctx context.Context, moduleID string) (modulecatalog.Module, error) {
	return r.inspect(ctx, moduleID, func(ctx context.Context) (*moduleProcess, error) {
		return r.start(ctx, moduleID)
	})
}

func (r Runner) InspectEntry(ctx context.Context, entry ModuleEntry) (modulecatalog.Module, error) {
	entry.ID = strings.TrimSpace(entry.ID)
	if entry.ID == "" {
		return modulecatalog.Module{}, errors.New("module id is required")
	}
	return r.inspect(ctx, entry.ID, func(ctx context.Context) (*moduleProcess, error) {
		return r.startEntry(ctx, entry)
	})
}

func (r Runner) inspect(ctx context.Context, moduleID string, start func(context.Context) (*moduleProcess, error)) (modulecatalog.Module, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	process, err := start(ctx)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	defer process.killAndWait()

	info, err := process.client.call(ctx, "handshake", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderrString())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderrString())
	}
	stepContracts, err := process.client.call(ctx, "step.describe", nil)
	if err != nil {
		if isMissingStepProvider(err) {
			stepContracts = map[string]any{"steps": []any{}}
		} else {
			return modulecatalog.Module{}, moduleFailure("module failed while reporting step contracts", "module step describe failed", err, process.stderrString())
		}
	}
	_, _ = process.client.call(context.Background(), "shutdown", nil)
	if err := process.wait(); err != nil {
		return modulecatalog.Module{}, moduleFailure("module exited with error", "module exited with error", err, process.stderrString())
	}
	module, err := moduleFromRPC(moduleID, info, schema, stepContracts)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	if issues := modulecatalog.ValidateStepContracts(module); len(issues) > 0 {
		return modulecatalog.Module{}, fmt.Errorf("step contract invalid: %s", formatStepContractIssue(issues[0]))
	}
	return module, nil
}

func isMissingStepProvider(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "unknown method step.describe") ||
		strings.Contains(message, `unknown method "step.describe"`) ||
		strings.Contains(message, "not a step provider")
}

func (r Runner) PrepareStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.prepare", "module failed while preparing step", "module step prepare failed")
}

func (r Runner) ExecuteStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.execute", "module failed while executing step", "module step execute failed")
}

func (r Runner) CleanupStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.cleanup", "module failed while cleaning up step", "module step cleanup failed")
}

func (r Runner) ListPayloadCommands(ctx context.Context, moduleID string, request run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	result, err := r.callPayloadCommand(ctx, moduleID, "payload.command.list", request)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Commands []run.PayloadCommand `json:"commands"`
	}
	if err := decodeRPCMap(result, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid payload command list", err)
	}
	return decoded.Commands, nil
}

func (r Runner) RunPayloadCommand(ctx context.Context, moduleID string, request run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	result, err := r.callPayloadCommand(ctx, moduleID, "payload.command.run", request)
	if err != nil {
		return run.PayloadCommandResult{}, err
	}
	var decoded run.PayloadCommandResult
	if err := decodeRPCMap(result, &decoded); err != nil {
		return run.PayloadCommandResult{}, services.NewModuleExecutionFailure("module returned invalid payload command result", err)
	}
	return decoded, nil
}

func (r Runner) callPayloadCommand(ctx context.Context, moduleID, method string, params any) (map[string]any, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	process, err := r.start(ctx, moduleID)
	if err != nil {
		return nil, err
	}
	defer process.killAndWait()
	result, err := process.client.call(ctx, method, params)
	if err != nil {
		return nil, moduleFailure("module failed during payload command", "module payload command failed", err, process.stderrString())
	}
	_, _ = process.client.call(context.Background(), "shutdown", nil)
	if err := process.wait(); err != nil {
		return nil, moduleFailure("module exited with error", "module exited with error", err, process.stderrString())
	}
	return result, nil
}

func decodeRPCMap(value map[string]any, out any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (r Runner) callStep(ctx context.Context, request StepCallRequest, method, summary, prefix string) (map[string]any, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var process *moduleProcess
	var err error
	owned := true
	runID := stepCallRunID(request.Params)
	if r.StepProcesses != nil && runID != "" {
		process, err = r.StepProcesses.process(ctx, r, runID, request.ModuleID)
		owned = false
	} else {
		process, err = r.start(ctx, request.ModuleID)
	}
	if err != nil {
		return nil, err
	}
	if owned {
		defer process.killAndWait()
	}

	result, err := process.client.call(ctx, method, request.Params)
	if err != nil {
		return nil, moduleFailure(summary, prefix, err, process.stderrString())
	}
	if method == "step.execute" {
		sessions, err := sessionsFromStepRPC(request, result["sessions"])
		if err != nil {
			return nil, services.NewModuleExecutionFailure("module returned invalid step result", err)
		}
		if len(sessions) > 0 && r.Sessions != nil {
			r.Sessions.adopt(process, sessions)
			if r.StepProcesses != nil {
				r.StepProcesses.release(process)
			}
		}
	}
	if owned {
		_, _ = process.client.call(context.Background(), "shutdown", nil)
		if err := process.wait(); err != nil {
			return nil, moduleFailure("module exited with error", "module exited with error", err, process.stderrString())
		}
	}
	return result, nil
}

func stepCallRunID(params map[string]any) string {
	if params == nil {
		return ""
	}
	if text := stringValue(params["runId"]); text != "" {
		return text
	}
	return stringValue(params["preparedPlanId"])
}

func formatStepContractIssue(issue modulecatalog.StepContractIssue) string {
	if issue.StepID == "" {
		return issue.Message
	}
	return issue.StepID + ": " + issue.Message
}

func (r Runner) Run(ctx context.Context, request run.Request) (run.Result, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	entry, ok, err := r.moduleEntry(request.ModuleID)
	if err != nil {
		return run.Result{}, err
	}
	if ok {
		request.ModuleID = entry.ID
	}
	process, err := r.start(context.Background(), request.ModuleID)
	if err != nil {
		return run.Result{}, err
	}
	keepProcess := false
	defer func() {
		if !keepProcess {
			process.killAndWait()
		}
	}()
	process.client.setOnLog(func(log rpcLog) error {
		return r.appendLog(context.Background(), request, log)
	})

	info, err := process.client.call(ctx, "handshake", nil)
	if err != nil {
		return run.Result{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderrString())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return run.Result{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderrString())
	}
	module, err := moduleFromRPC(request.ModuleID, info, schema)
	if err != nil {
		return run.Result{}, moduleFailure("module failed while reporting metadata", "module metadata invalid", err, process.stderrString())
	}
	request.ModuleID = module.ID
	executeParams := map[string]any{
		"runId":        request.ID,
		"moduleId":     request.ModuleID,
		"target":       request.Target,
		"inputs":       request.Inputs,
		"chainConfig":  request.ChainConfig,
		"targetConfig": request.TargetConfig,
	}
	if request.Agent != nil {
		executeParams["agentContext"] = request.Agent
	}
	executeResult, err := process.client.call(ctx, "execute", executeParams)
	if err != nil {
		return run.Result{}, moduleFailure("module failed during execution", "module execute failed", err, process.stderrString())
	}
	result, err := resultFromRPC(request, executeResult, process.client.logsSnapshot())
	if err != nil {
		return run.Result{}, services.NewModuleExecutionFailure("module returned invalid result", err)
	}
	for _, session := range result.Sessions {
		if err := r.appendSessionCreated(context.Background(), request, session); err != nil {
			return run.Result{}, err
		}
	}
	if len(result.Sessions) > 0 && r.Sessions != nil {
		r.Sessions.adopt(process, result.Sessions)
		keepProcess = true
	} else {
		_, _ = process.client.call(context.Background(), "shutdown", nil)
		if err := process.wait(); err != nil {
			return run.Result{}, moduleFailure("module exited with error", "module exited with error", err, process.stderrString())
		}
	}
	return result, nil
}

type moduleProcess struct {
	cmd    *exec.Cmd
	client *rpcClient
	stderr *capturedStderr
	waited bool
}

func (r Runner) start(ctx context.Context, moduleID string) (*moduleProcess, error) {
	entrypoint, ok, err := r.moduleEntry(moduleID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown module %q", moduleID)
	}
	return r.startEntry(ctx, entrypoint)
}

func (r Runner) startEntry(ctx context.Context, entrypoint ModuleEntry) (*moduleProcess, error) {
	entrypoint.ID = strings.TrimSpace(entrypoint.ID)
	entrypoint.Runtime = strings.TrimSpace(entrypoint.Runtime)
	if entrypoint.ID == "" {
		return nil, errors.New("module id is required")
	}
	if entrypoint.Runtime == "" {
		entrypoint.Runtime = modulecatalog.RuntimeJSONRPCStdio
	}
	if entrypoint.Runtime != modulecatalog.RuntimeJSONRPCStdio {
		return nil, fmt.Errorf("module %q uses unsupported runtime %q", entrypoint.ID, entrypoint.Runtime)
	}
	if entrypoint.usesCommand() {
		entrypoint.Command[0] = strings.TrimSpace(entrypoint.Command[0])
		if entrypoint.Command[0] == "" {
			return nil, fmt.Errorf("module %q command[0] is required", entrypoint.ID)
		}
	} else if entrypoint.ProjectDir == "" || entrypoint.Module == "" {
		return nil, fmt.Errorf("module %q missing project_dir or module", entrypoint.ID)
	}
	cmd, err := r.command(ctx, entrypoint)
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := newCapturedStderr()
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &moduleProcess{cmd: cmd, client: newClient(stdout, stdin), stderr: stderr}, nil
}

// command builds the OS command that launches a module process. Entries with an
// explicit "command" run an arbitrary executable that speaks the stdio JSON-RPC
// protocol (Go, Rust, or any other language); entries without one use the
// built-in Python interpreter path (python -m <module>).
func (r Runner) command(ctx context.Context, entry ModuleEntry) (*exec.Cmd, error) {
	if entry.usesCommand() {
		cmd := exec.CommandContext(ctx, entry.Command[0], entry.Command[1:]...)
		cmd.Env = os.Environ()
		if entry.ProjectDir != "" {
			cmd.Dir = entry.ProjectDir
		}
		return cmd, nil
	}

	python, err := r.pythonPath()
	if err != nil {
		return nil, err
	}
	sdkRoot, err := r.sdkRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, python, "-m", entry.Module)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+strings.Join([]string{sdkRoot, entry.ProjectDir}, string(os.PathListSeparator)))
	cmd.Dir = entry.ProjectDir
	return cmd, nil
}

func (p *moduleProcess) wait() error {
	if p.waited {
		return nil
	}
	p.waited = true
	return p.cmd.Wait()
}

func (p *moduleProcess) killAndWait() {
	if p.waited {
		return
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.wait()
}

func (p *moduleProcess) stderrString() string {
	if p == nil || p.stderr == nil {
		return ""
	}
	return p.stderr.StringAfter(stderrSettleTimeout)
}

type capturedStderr struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	updated chan struct{}
}

func newCapturedStderr() *capturedStderr {
	return &capturedStderr{updated: make(chan struct{}, 1)}
}

func (s *capturedStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	if n > 0 {
		select {
		case s.updated <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (s *capturedStderr) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *capturedStderr) StringAfter(wait time.Duration) string {
	if text := s.String(); strings.TrimSpace(text) != "" || wait <= 0 {
		return text
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-s.updated:
	case <-timer.C:
	}
	return s.String()
}

type StepProcessBroker struct {
	mu        sync.Mutex
	processes map[stepProcessKey]*moduleProcess
}

type stepProcessKey struct {
	runID    string
	moduleID string
}

func NewStepProcessBroker() *StepProcessBroker {
	return &StepProcessBroker{processes: map[stepProcessKey]*moduleProcess{}}
}

func (b *StepProcessBroker) process(ctx context.Context, runner Runner, runID, moduleID string) (*moduleProcess, error) {
	if b == nil || runID == "" {
		return runner.start(ctx, moduleID)
	}
	key := stepProcessKey{runID: runID, moduleID: moduleID}
	b.mu.Lock()
	if process, ok := b.processes[key]; ok {
		b.mu.Unlock()
		return process, nil
	}
	b.mu.Unlock()

	process, err := runner.start(context.Background(), moduleID)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	if existing, ok := b.processes[key]; ok {
		b.mu.Unlock()
		process.killAndWait()
		return existing, nil
	}
	b.processes[key] = process
	b.mu.Unlock()
	return process, nil
}

func (b *StepProcessBroker) release(process *moduleProcess) {
	if b == nil || process == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, tracked := range b.processes {
		if tracked == process {
			delete(b.processes, key)
		}
	}
}

func (b *StepProcessBroker) FinishRun(ctx context.Context, runID string) error {
	if b == nil || runID == "" {
		return nil
	}
	var processes []*moduleProcess
	b.mu.Lock()
	for key, process := range b.processes {
		if key.runID == runID {
			processes = append(processes, process)
			delete(b.processes, key)
		}
	}
	b.mu.Unlock()

	var firstErr error
	for _, process := range processes {
		_, _ = process.client.call(ctx, "shutdown", nil)
		if err := process.wait(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r Runner) pythonPath() (string, error) {
	if r.PythonPath != "" {
		return r.PythonPath, nil
	}
	if path, err := exec.LookPath("python3"); err == nil {
		return path, nil
	}
	return exec.LookPath("python")
}

func (r Runner) sdkRoot() (string, error) {
	if r.SDKRoot != "" {
		return r.SDKRoot, nil
	}
	if env := os.Getenv("HOVEL_PYTHON_SDK_ROOT"); env != "" {
		return env, nil
	}
	for _, candidate := range sdkRootCandidates() {
		if hasPythonSDK(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("could not locate sdk/python; set HOVEL_PYTHON_SDK_ROOT")
}

func (r Runner) configPath() string {
	if r.ConfigPath != "" {
		return preferOperatorModuleConfig(r.ConfigPath)
	}
	if env := strings.TrimSpace(os.Getenv(ModuleConfigEnv)); env != "" {
		return preferOperatorModuleConfig(env)
	}
	for _, candidate := range defaultModuleConfigCandidates() {
		path, err := resolveConfigPath(candidate)
		if err != nil || path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			preferred := preferOperatorModuleConfig(path)
			resolved, err := resolveConfigPath(preferred)
			if err == nil && isFullExampleModuleConfig(resolved) && !operatorModuleConfigReady(resolved) {
				continue
			}
			return preferred
		}
	}
	return ""
}

func preferOperatorModuleConfig(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}
	resolved, err := resolveConfigPath(configPath)
	if err != nil || resolved == "" {
		return configPath
	}
	if filepath.Base(resolved) != "hovel-modules.json" {
		return configPath
	}
	pythonDir := filepath.Dir(resolved)
	if filepath.Base(pythonDir) != "python" {
		return configPath
	}
	examplesDir := filepath.Dir(pythonDir)
	if filepath.Base(examplesDir) != "examples" {
		return configPath
	}
	fullConfig := filepath.Join(examplesDir, "hovel-modules.json")
	if _, err := os.Stat(fullConfig); err != nil {
		return configPath
	}
	if !operatorModuleConfigReady(fullConfig) {
		return configPath
	}
	return fullConfig
}

func isFullExampleModuleConfig(configPath string) bool {
	configPath = filepath.Clean(strings.TrimSpace(configPath))
	if filepath.Base(configPath) != "hovel-modules.json" {
		return false
	}
	return filepath.Base(filepath.Dir(configPath)) == "examples"
}

func operatorModuleConfigReady(configPath string) bool {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var config ModuleConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return false
	}
	baseDir := filepath.Dir(configPath)
	for _, entry := range config.Modules {
		if len(entry.Command) == 0 {
			continue
		}
		command := strings.TrimSpace(entry.Command[0])
		if command == "" {
			return false
		}
		if !filepath.IsAbs(command) {
			command = filepath.Join(baseDir, command)
		}
		if _, err := os.Stat(command); err != nil {
			return false
		}
	}
	return true
}

func defaultModuleConfigCandidates() []string {
	var candidates []string
	add := func(path string) {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "." {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	for _, env := range []string{"HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY", "BUILD_WORKING_DIRECTORY"} {
		root := strings.TrimSpace(os.Getenv(env))
		if root == "" {
			continue
		}
		add(filepath.Join(root, "examples", "hovel-modules.json"))
		add(filepath.Join(root, "examples", "python", "hovel-modules.json"))
	}
	add(filepath.Join("examples", "hovel-modules.json"))
	add(filepath.Join("examples", "python", "hovel-modules.json"))
	return candidates
}

func (r Runner) moduleEntry(moduleID string) (ModuleEntry, bool, error) {
	entries, err := r.moduleEntries()
	if err != nil {
		return ModuleEntry{}, false, err
	}
	moduleName := modulecatalog.ReferenceName(moduleID)
	for _, entry := range entries {
		if entry.ID == moduleID || modulecatalog.ReferenceName(entry.ID) == moduleName {
			return entry, true, nil
		}
	}
	return ModuleEntry{}, false, nil
}

func (r Runner) moduleEntries() ([]ModuleEntry, error) {
	installed, err := r.installedModuleEntries()
	if err != nil {
		return nil, err
	}
	configured, err := r.configuredModuleEntries()
	if err != nil {
		return nil, err
	}
	path, err := resolveConfigPath(r.configPath())
	if err != nil {
		return nil, err
	}
	if path == "" {
		return append(installed, configured...), nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ModuleConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	entries := make([]ModuleEntry, 0, len(config.Modules))
	for index, entry := range config.Modules {
		entry.ID = strings.TrimSpace(entry.ID)
		entry.Runtime = strings.TrimSpace(entry.Runtime)
		entry.ProjectDir = strings.TrimSpace(entry.ProjectDir)
		entry.Module = strings.TrimSpace(entry.Module)
		if entry.ID == "" {
			return nil, fmt.Errorf("module entry %d missing id", index+1)
		}
		if entry.Runtime == "" {
			entry.Runtime = modulecatalog.RuntimeJSONRPCStdio
		}
		if entry.Runtime != modulecatalog.RuntimeJSONRPCStdio {
			return nil, fmt.Errorf("module %q uses unsupported runtime %q", entry.ID, entry.Runtime)
		}
		if entry.ProjectDir != "" && !filepath.IsAbs(entry.ProjectDir) {
			entry.ProjectDir = filepath.Join(baseDir, entry.ProjectDir)
		}
		if entry.usesCommand() {
			entry.Command[0] = strings.TrimSpace(entry.Command[0])
			if entry.Command[0] == "" {
				return nil, fmt.Errorf("module %q command[0] is required", entry.ID)
			}
			// command[0] may be a path relative to the config file; resolve it
			// so the runner can launch the binary regardless of working dir.
			if program := entry.Command[0]; program != "" && !filepath.IsAbs(program) && strings.ContainsRune(program, os.PathSeparator) {
				entry.Command[0] = filepath.Join(baseDir, program)
			}
			entries = append(entries, entry)
			continue
		}
		if entry.ProjectDir == "" || entry.Module == "" {
			return nil, fmt.Errorf("module %q missing project_dir or module", entry.ID)
		}
		entries = append(entries, entry)
	}
	out := append(installed, configured...)
	return append(out, entries...), nil
}

func (r Runner) installedModuleEntries() ([]ModuleEntry, error) {
	workspacePath := strings.TrimSpace(r.WorkspacePath)
	if workspacePath == "" {
		return nil, nil
	}
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	entries := make([]ModuleEntry, 0, len(lock.Modules))
	for _, record := range lock.Modules {
		pkg, err := modulepackage.LoadDir(record.Source)
		if err != nil {
			return nil, err
		}
		launch, err := pkg.LaunchEntry(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return nil, err
		}
		entries = append(entries, ModuleEntry{
			ID:      modulecatalog.CanonicalID(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version),
			Runtime: launch.Runtime,
			Command: append([]string(nil), launch.Command...),
		})
	}
	return entries, nil
}

func (r Runner) configuredModuleEntries() ([]ModuleEntry, error) {
	if strings.TrimSpace(r.WorkspacePath) == "" && strings.TrimSpace(r.HovelConfig) == "" {
		return nil, nil
	}
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    r.WorkspacePath,
		ExplicitPath: r.HovelConfig,
	})
	if err != nil {
		return nil, err
	}
	var entries []ModuleEntry
	for _, root := range config.Modules.SearchPaths {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, modulepackage.ManifestName)); err == nil {
			entry, err := moduleEntryFromPackageRoot(root)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
			continue
		}
		children, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			childRoot := filepath.Join(root, child.Name())
			if _, err := os.Stat(filepath.Join(childRoot, modulepackage.ManifestName)); err != nil {
				continue
			}
			entry, err := moduleEntryFromPackageRoot(childRoot)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func moduleEntryFromPackageRoot(root string) (ModuleEntry, error) {
	pkg, err := modulepackage.LoadDir(root)
	if err != nil {
		return ModuleEntry{}, err
	}
	launch, err := pkg.LaunchEntry(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return ModuleEntry{}, err
	}
	return ModuleEntry{
		ID:      modulecatalog.CanonicalID(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version),
		Runtime: launch.Runtime,
		Command: append([]string(nil), launch.Command...),
	}, nil
}

func resolveConfigPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if candidate, ok := runfileManifestLookup(path); ok {
		return candidate, nil
	}
	for _, root := range runfileRoots() {
		candidate := filepath.Join(root, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return path, nil
}

func runfileRoots() []string {
	var roots []string
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for i := 0; i < 8 && dir != "" && dir != string(filepath.Separator); i++ {
			roots = append(roots, dir)
			dir = filepath.Dir(dir)
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
	return roots
}

func sdkRootCandidates() []string {
	var candidates []string
	addClimbs := func(start string) {
		dir := start
		for i := 0; i < 8 && dir != "" && dir != string(filepath.Separator); i++ {
			candidates = append(candidates, filepath.Join(dir, "sdk", "python"))
			dir = filepath.Dir(dir)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		addClimbs(cwd)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		addClimbs(exeDir)
		runfiles := exe + ".runfiles"
		candidates = append(candidates,
			filepath.Join(runfiles, "hovel", "sdk", "python"),
			filepath.Join(runfiles, "_main", "sdk", "python"),
			filepath.Join(runfiles, "sdk", "python"),
			filepath.Join(exeDir, "sdk", "python"),
		)
	}
	if runfiles := os.Getenv("RUNFILES_DIR"); runfiles != "" {
		candidates = append(candidates,
			filepath.Join(runfiles, "hovel", "sdk", "python"),
			filepath.Join(runfiles, "_main", "sdk", "python"),
			filepath.Join(runfiles, "sdk", "python"),
		)
	}
	if testSrcDir := os.Getenv("TEST_SRCDIR"); testSrcDir != "" {
		candidates = append(candidates,
			filepath.Join(testSrcDir, "hovel", "sdk", "python"),
			filepath.Join(testSrcDir, "_main", "sdk", "python"),
			filepath.Join(testSrcDir, "sdk", "python"),
		)
		if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
			candidates = append(candidates, filepath.Join(testSrcDir, workspace, "sdk", "python"))
		}
	}
	if sdkInit, ok := runfileManifestLookup("sdk/python/hovel_sdk/__init__.py"); ok {
		candidates = append(candidates, filepath.Dir(filepath.Dir(sdkInit)))
	}
	return candidates
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
		line := scanner.Text()
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if _, ok := wanted[key]; ok {
			return value, true
		}
	}
	return "", false
}

func hasPythonSDK(path string) bool {
	info, err := os.Stat(filepath.Join(path, "hovel_sdk", "__init__.py"))
	return err == nil && !info.IsDir()
}

type rpcClient struct {
	decoder *frameDecoder
	writer  io.WriteCloser

	writeMu sync.Mutex

	mu      sync.Mutex
	nextID  int
	pending map[int]chan rpcMessage
	logs    []rpcLog
	onLog   func(rpcLog) error
	onEvent func(rpcSessionEvent) error
	readErr error
	done    chan struct{}
	once    sync.Once
}

func newClient(stdout io.Reader, stdin io.WriteCloser) *rpcClient {
	client := &rpcClient{
		decoder: newFrameDecoder(stdout),
		writer:  stdin,
		pending: map[int]chan rpcMessage{},
		done:    make(chan struct{}),
	}
	go client.readLoop()
	return client
}

func (c *rpcClient) call(ctx context.Context, method string, params any) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.nextID++
	id := c.nextID
	responses := make(chan rpcMessage, 1)
	c.pending[id] = responses
	c.mu.Unlock()
	defer c.removePending(id)

	c.writeMu.Lock()
	if err := writeFrame(c.writer, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		c.writeMu.Unlock()
		return nil, err
	}
	c.writeMu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.done:
			select {
			case message := <-responses:
				return rpcResult(message)
			default:
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, c.readError()
		case message := <-responses:
			return rpcResult(message)
		}
	}
}

func rpcResult(message rpcMessage) (map[string]any, error) {
	if message.Error != nil {
		return nil, errors.New(message.Error.Message)
	}
	if message.Result == nil {
		return map[string]any{}, nil
	}
	return message.Result, nil
}

func (c *rpcClient) readLoop() {
	for {
		message, err := c.decoder.read()
		if err != nil {
			c.finish(err)
			return
		}
		if message.Method == "module/log" || message.Method == "module/session" {
			if err := c.handleNotification(message); err != nil {
				c.finish(err)
				return
			}
			continue
		}
		c.mu.Lock()
		responses := c.pending[message.ID]
		c.mu.Unlock()
		if responses == nil {
			continue
		}
		select {
		case responses <- message:
		default:
		}
	}
}

func (c *rpcClient) handleNotification(message rpcMessage) error {
	switch message.Method {
	case "module/log":
		if message.Log.ReceivedAt.IsZero() {
			message.Log.ReceivedAt = time.Now().UTC()
		}
		c.mu.Lock()
		c.logs = append(c.logs, message.Log)
		onLog := c.onLog
		c.mu.Unlock()
		if onLog != nil {
			if err := onLog(message.Log); err != nil {
				return callbackError{err: err}
			}
		}
	case "module/session":
		c.mu.Lock()
		onEvent := c.onEvent
		c.mu.Unlock()
		if onEvent != nil {
			if err := onEvent(message.Session); err != nil {
				return callbackError{err: err}
			}
		}
	}
	return nil
}

func (c *rpcClient) removePending(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, id)
}

func (c *rpcClient) finish(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
		close(c.done)
	})
}

func (c *rpcClient) readError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	return io.EOF
}

func (c *rpcClient) setOnLog(fn func(rpcLog) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onLog = fn
}

func (c *rpcClient) logsSnapshot() []rpcLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]rpcLog(nil), c.logs...)
}

type rpcMessage struct {
	ID      int
	Method  string
	Result  map[string]any
	Log     rpcLog
	Session rpcSessionEvent
	Error   *rpcError
}

type rpcError struct {
	Message string `json:"message"`
}

type rpcLog struct {
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Logger     string         `json:"logger"`
	Fields     map[string]any `json:"fields"`
	Exception  string         `json:"exception"`
	ReceivedAt time.Time      `json:"-"`
}

type rpcSessionEvent struct {
	Event   string         `json:"event"`
	Session rpcSessionRef  `json:"session"`
	Fields  map[string]any `json:"fields"`
}

type rpcSessionRef struct {
	ID                 string `json:"id"`
	RunID              string `json:"runId"`
	ModuleID           string `json:"moduleId"`
	Target             string `json:"target"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	State              string `json:"state"`
	Transport          string `json:"transport"`
	InstalledPayloadID string `json:"installedPayloadId"`
	Capabilities       []any  `json:"capabilities"`
}

type frameDecoder struct {
	reader *framing.Reader
}

func newFrameDecoder(reader io.Reader) *frameDecoder {
	return &frameDecoder{reader: framing.NewReader(reader, maxFrameBytes)}
}

func (d *frameDecoder) read() (rpcMessage, error) {
	var raw struct {
		ID     *int            `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := d.reader.ReadJSON(&raw); err != nil {
		return rpcMessage{}, err
	}
	message := rpcMessage{Method: raw.Method, Error: raw.Error}
	if raw.ID != nil {
		message.ID = *raw.ID
	}
	if len(raw.Result) > 0 {
		if err := json.Unmarshal(raw.Result, &message.Result); err != nil {
			return rpcMessage{}, err
		}
	}
	if raw.Method == "module/log" && len(raw.Params) > 0 {
		if err := json.Unmarshal(raw.Params, &message.Log); err != nil {
			return rpcMessage{}, err
		}
	}
	if raw.Method == "module/session" && len(raw.Params) > 0 {
		if err := json.Unmarshal(raw.Params, &message.Session); err != nil {
			return rpcMessage{}, err
		}
	}
	return message, nil
}

func writeFrame(writer io.Writer, message map[string]any) error {
	return framing.WriteJSON(writer, message)
}

func resultFromRPC(request run.Request, values map[string]any, logs []rpcLog) (run.Result, error) {
	findings, err := findingsFromRPC(values["findings"])
	if err != nil {
		return run.Result{}, err
	}
	artifacts, err := artifactsFromRPC(values["artifacts"])
	if err != nil {
		return run.Result{}, err
	}
	sessions, err := sessionsFromRPC(request, values["sessions"])
	if err != nil {
		return run.Result{}, err
	}
	installedPayloads, err := installedPayloadsFromRPC(values["installedPayloads"])
	if err != nil {
		return run.Result{}, err
	}
	agentHints, err := agentHintsFromRPC(values["agentHints"])
	if err != nil {
		return run.Result{}, err
	}
	args := run.ResultArgs{
		Summary:           stringValue(values["summary"]),
		Findings:          findings,
		Artifacts:         artifacts,
		Logs:              logsFromRPC(request, logs),
		Sessions:          sessions,
		InstalledPayloads: installedPayloads,
		AgentHints:        agentHints,
	}
	if stringValue(values["status"]) == string(run.StateFailed) {
		return run.Failed(request, args)
	}
	return run.Succeeded(request, args)
}

func logsFromRPC(request run.Request, logs []rpcLog) []run.LogEntry {
	out := make([]run.LogEntry, 0, len(logs))
	for _, log := range logs {
		fields := make(map[string]string, len(log.Fields)+1)
		for key, value := range log.Fields {
			fields[key] = fmt.Sprint(value)
		}
		if log.Exception != "" {
			fields["exception"] = log.Exception
		}
		out = append(out, run.LogEntry{
			Kind:     "event",
			Time:     log.ReceivedAt.Format(time.RFC3339Nano),
			Level:    log.Level,
			Source:   "module",
			Message:  log.Message,
			Logger:   log.Logger,
			RunID:    request.ID,
			Target:   request.Target,
			ModuleID: request.ModuleID,
			Fields:   fields,
		})
	}
	return out
}

func moduleFromRPC(moduleID string, info, schema map[string]any, stepContractValues ...map[string]any) (modulecatalog.Module, error) {
	name := strings.TrimSpace(stringValue(info["name"]))
	configName, configVersion, configHasVersion := modulecatalog.SplitID(moduleID)
	if name == "" {
		name = configName
	}
	version := strings.TrimSpace(stringValue(info["version"]))
	if version == "" && configHasVersion {
		version = configVersion
	}
	if name == "" {
		return modulecatalog.Module{}, errors.New("module handshake missing name")
	}
	if version == "" {
		return modulecatalog.Module{}, errors.New("module handshake missing version")
	}
	moduleType, err := modulecatalog.NewModuleType(strings.TrimSpace(stringValue(info["moduleType"])))
	if err != nil {
		return modulecatalog.Module{}, err
	}
	chainConfig, err := requirementsFromRPC(schema["chainConfig"], "chainConfig")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	targetConfig, err := requirementsFromRPC(schema["targetConfig"], "targetConfig")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	tags, err := strictStringSlice(info["tags"], "handshake tags")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	display := strings.TrimSpace(stringValue(info["displayName"]))
	if display == "" {
		display = displayName(name)
	}
	module := modulecatalog.Module{
		ID:           modulecatalog.CanonicalID(name, version),
		Name:         display,
		Type:         moduleType,
		Version:      version,
		Summary:      stringValue(info["summary"]),
		Description:  stringValue(info["description"]),
		Tags:         tags,
		RuntimeKind:  modulecatalog.RuntimeJSONRPCStdio,
		Author:       "hovel",
		Enabled:      true,
		ChainConfig:  chainConfig,
		TargetConfig: targetConfig,
	}
	if len(stepContractValues) > 0 {
		stepContracts, err := stepContractsFromRPC(stepContractValues[0])
		if err != nil {
			return modulecatalog.Module{}, err
		}
		module.StepContracts = stepContracts
	}
	return module, nil
}

func stepContractsFromRPC(value map[string]any) (modulecatalog.StepContractSet, error) {
	set := modulecatalog.StepContractSet{
		Version: strings.TrimSpace(stringValue(value["version"])),
	}
	rawSteps, present := value["steps"]
	if !present || rawSteps == nil {
		return set, nil
	}
	items, ok := rawSteps.([]any)
	if !ok {
		return set, errors.New("step contracts steps must be an array")
	}
	set.Steps = make([]modulecatalog.StepContract, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return set, fmt.Errorf("step contract %d must be an object", index+1)
		}
		requires, err := capabilityRequirementsFromRPC(object["requires"], fmt.Sprintf("step contract %d requires", index+1))
		if err != nil {
			return set, err
		}
		produces, err := capabilityRequirementsFromRPC(object["produces"], fmt.Sprintf("step contract %d produces", index+1))
		if err != nil {
			return set, err
		}
		materializes, err := prepareMaterializesFromRPC(object["prepare"], fmt.Sprintf("step contract %d prepare", index+1))
		if err != nil {
			return set, err
		}
		cleanup, err := cleanupContractFromRPC(object["cleanup"], fmt.Sprintf("step contract %d cleanup", index+1))
		if err != nil {
			return set, err
		}
		set.Steps = append(set.Steps, modulecatalog.StepContract{
			ID:           strings.TrimSpace(stringValue(object["id"])),
			Kind:         strings.TrimSpace(stringValue(object["kind"])),
			ConfigSchema: anyMap(object["configSchema"]),
			Requires:     requires,
			Produces:     produces,
			Prepare: modulecatalog.StepPrepareContract{
				Materializes: materializes,
			},
			Cleanup: cleanup,
		})
	}
	return set, nil
}

func capabilityRequirementsFromRPC(value any, label string) ([]modulecatalog.CapabilityRequirement, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	requirements := make([]modulecatalog.CapabilityRequirement, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s item %d must be an object", label, index+1)
		}
		states, err := strictStringSlice(object["states"], fmt.Sprintf("%s item %d states", label, index+1))
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, modulecatalog.CapabilityRequirement{
			Type:          modulecatalog.CapabilityType(strings.TrimSpace(stringValue(object["type"]))),
			SchemaVersion: strings.TrimSpace(stringValue(object["schemaVersion"])),
			Attributes:    anyMap(object["attributes"]),
			States:        states,
		})
	}
	return requirements, nil
}

func prepareMaterializesFromRPC(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	materializes, present := object["materializes"]
	if !present || materializes == nil {
		return nil, nil
	}
	items, ok := materializes.([]any)
	if !ok {
		return nil, fmt.Errorf("%s materializes must be an array", label)
	}
	out := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s materializes item %d must be a string", label, index+1)
		}
		out = append(out, strings.TrimSpace(text))
	}
	return out, nil
}

func cleanupContractFromRPC(value any, label string) (*modulecatalog.StepCleanupContract, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return &modulecatalog.StepCleanupContract{StepID: strings.TrimSpace(stringValue(object["stepId"]))}, nil
}

func rpcArray(value any, label string) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	return items, nil
}

func rpcObjectItem(value any, label string, index int) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s item %d must be an object", label, index+1)
	}
	return object, nil
}

func strictStringSlice(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	out := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s item %d must be a string", label, index+1)
		}
		out = append(out, strings.TrimSpace(text))
	}
	return out, nil
}

func optionalAnyMap(value any, label string) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	out := make(map[string]any, len(object))
	for key, item := range object {
		out[key] = item
	}
	return out, nil
}

func anyMap(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(object))
	for key, item := range object {
		out[key] = item
	}
	return out
}

func requirementsFromRPC(value any, label string) ([]modulecatalog.Requirement, error) {
	items, err := rpcArray(value, label)
	if err != nil {
		return nil, err
	}
	requirements := make([]modulecatalog.Requirement, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, label, index)
		if err != nil {
			return nil, err
		}
		key, err := requiredStringValue(object["key"], fmt.Sprintf("%s item %d key", label, index+1))
		if err != nil {
			return nil, err
		}
		rawType, err := requiredStringValue(object["type"], fmt.Sprintf("%s item %d type", label, index+1))
		if err != nil {
			return nil, err
		}
		valueType := modulecatalog.ValueType(rawType)
		if !validRequirementType(valueType) {
			return nil, fmt.Errorf("%s item %d type %q is unsupported", label, index+1, rawType)
		}
		defaultValue, err := optionalStringValue(object["default"], fmt.Sprintf("%s item %d default", label, index+1))
		if err != nil {
			return nil, err
		}
		description, err := optionalStringValue(object["description"], fmt.Sprintf("%s item %d description", label, index+1))
		if err != nil {
			return nil, err
		}
		allowed, err := strictStringSlice(object["allowed"], fmt.Sprintf("%s item %d allowed", label, index+1))
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, modulecatalog.Requirement{
			Key:         key,
			Type:        valueType,
			Required:    boolValue(object["required"]),
			Default:     defaultValue,
			Description: description,
			Allowed:     allowed,
			Secret:      boolValue(object["secret"]),
		})
	}
	return requirements, nil
}

func requiredStringValue(value any, label string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s is required", label)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return text, nil
}

func optionalStringValue(value any, label string) (string, error) {
	if value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", label)
	}
	return text, nil
}

func validRequirementType(value modulecatalog.ValueType) bool {
	switch value {
	case modulecatalog.ValueString,
		modulecatalog.ValueSecret,
		modulecatalog.ValueBool,
		modulecatalog.ValueInt,
		modulecatalog.ValueFloat,
		modulecatalog.ValueEnum,
		modulecatalog.ValueDuration,
		modulecatalog.ValueURL,
		modulecatalog.ValueHost,
		modulecatalog.ValuePort,
		modulecatalog.ValueCIDR,
		modulecatalog.ValuePath,
		modulecatalog.ValueStringList,
		modulecatalog.ValueStringStringMap:
		return true
	default:
		return false
	}
}

func findingsFromRPC(value any) ([]run.Finding, error) {
	items, err := rpcArray(value, "findings")
	if err != nil {
		return nil, err
	}
	findings := make([]run.Finding, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "findings", index)
		if err != nil {
			return nil, err
		}
		findings = append(findings, run.Finding{
			Title:    stringValue(object["title"]),
			Severity: run.Severity(stringValue(object["severity"])),
			Detail:   stringValue(object["detail"]),
		})
	}
	return findings, nil
}

func artifactsFromRPC(value any) ([]run.Artifact, error) {
	items, err := rpcArray(value, "artifacts")
	if err != nil {
		return nil, err
	}
	artifacts := make([]run.Artifact, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "artifacts", index)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, run.Artifact{
			Name: stringValue(object["name"]),
			Kind: stringValue(object["kind"]),
			Data: stringValue(object["data"]),
			Path: stringValue(object["path"]),
		})
	}
	return artifacts, nil
}

type SessionBroker struct {
	mu           sync.Mutex
	sessions     map[string]*brokerSession
	nextOrder    uint64
	historyLimit int
}

func NewSessionBroker() *SessionBroker {
	return &SessionBroker{
		sessions:     map[string]*brokerSession{},
		historyLimit: defaultSessionHistoryBytes,
	}
}

func (b *SessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	if b == nil {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ordered := make([]*brokerSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		ordered = append(ordered, session)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].order == ordered[j].order {
			return ordered[i].ref.ID < ordered[j].ref.ID
		}
		return ordered[i].order < ordered[j].order
	})
	sessions := make([]run.SessionRef, 0, len(ordered))
	for _, session := range ordered {
		sessions = append(sessions, cloneSessionRef(session.ref))
	}
	return sessions, nil
}

func (b *SessionBroker) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	session, err := b.lookup(sessionID)
	if err != nil {
		return err
	}
	_, err = session.process.client.call(ctx, "session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString(data),
	})
	return err
}

func (b *SessionBroker) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (run.SessionChunk, error) {
	session, err := b.lookup(sessionID)
	if err != nil {
		return run.SessionChunk{}, err
	}
	return session.read(ctx, sessionID, timeout)
}

func (b *SessionBroker) TailSession(ctx context.Context, sessionID string, options run.SessionTailOptions) (run.SessionChunk, error) {
	if err := ctx.Err(); err != nil {
		return run.SessionChunk{}, err
	}
	if options.MaxBytes < 0 {
		return run.SessionChunk{}, errors.New("tail byte count cannot be negative")
	}
	if options.MaxLines < 0 {
		return run.SessionChunk{}, errors.New("tail line count cannot be negative")
	}
	if options.MaxBytes > 0 && options.MaxLines > 0 {
		return run.SessionChunk{}, errors.New("tail byte and line limits are mutually exclusive")
	}
	session, err := b.lookup(sessionID)
	if err != nil {
		return run.SessionChunk{}, err
	}
	return session.tail(sessionID, options), nil
}

func (b *SessionBroker) CloseSession(ctx context.Context, sessionID string) error {
	session, err := b.lookup(sessionID)
	if err != nil {
		return err
	}
	_, callErr := session.process.client.call(ctx, "session/close", map[string]any{
		"sessionId": sessionID,
		"reason":    "operator requested close",
	})
	b.remove(sessionID)
	if !b.hasProcess(session.process) {
		_, _ = session.process.client.call(context.Background(), "shutdown", nil)
		if err := session.process.wait(); err != nil && callErr == nil {
			callErr = err
		}
	}
	return callErr
}

func (b *SessionBroker) adopt(process *moduleProcess, sessions []run.SessionRef) {
	b.mu.Lock()
	if b.sessions == nil {
		b.sessions = map[string]*brokerSession{}
	}
	var adopted []*brokerSession
	for _, session := range sessions {
		if session.ID == "" {
			continue
		}
		order := b.nextOrder
		b.nextOrder++
		if existing, ok := b.sessions[session.ID]; ok {
			order = existing.order
		}
		brokerSession := newBrokerSession(session, process, b.historyLimit)
		brokerSession.order = order
		b.sessions[session.ID] = brokerSession
		adopted = append(adopted, brokerSession)
	}
	b.mu.Unlock()
	for _, session := range adopted {
		go b.pumpSession(session.ref.ID, session)
	}
}

func (b *SessionBroker) lookup(sessionID string) (*brokerSession, error) {
	if b == nil {
		return nil, errors.New("session broker is not configured")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	session, ok := b.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s does not exist", sessionID)
	}
	return session, nil
}

func (b *SessionBroker) markClosed(sessionID string) {
	b.mu.Lock()
	session, ok := b.sessions[sessionID]
	if ok {
		session.ref.State = "closed"
	}
	b.mu.Unlock()
	if ok {
		session.closeLocal()
	}
}

func (b *SessionBroker) remove(sessionID string) {
	b.mu.Lock()
	session, ok := b.sessions[sessionID]
	if ok {
		delete(b.sessions, sessionID)
	}
	b.mu.Unlock()
	if ok {
		session.closeLocal()
	}
}

func (b *SessionBroker) hasProcess(process *moduleProcess) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, session := range b.sessions {
		if session.process == process {
			return true
		}
	}
	return false
}

func (b *SessionBroker) pumpSession(sessionID string, session *brokerSession) {
	for {
		if session.isClosed() {
			return
		}
		values, err := session.process.client.call(context.Background(), "session/read", map[string]any{
			"sessionId": sessionID,
			"timeoutMs": 250,
		})
		if err != nil {
			b.markClosed(sessionID)
			return
		}
		data, err := base64.StdEncoding.DecodeString(stringValue(values["data"]))
		if err != nil {
			b.markClosed(sessionID)
			return
		}
		session.appendData(data)
		if boolValue(values["closed"]) {
			b.markClosed(sessionID)
			return
		}
	}
}

func cloneSessionRef(session run.SessionRef) run.SessionRef {
	session.Capabilities = append([]string(nil), session.Capabilities...)
	return session
}

func sessionsFromRPC(request run.Request, value any) ([]run.SessionRef, error) {
	items, err := rpcArray(value, "sessions")
	if err != nil {
		return nil, err
	}
	sessions := make([]run.SessionRef, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "sessions", index)
		if err != nil {
			return nil, err
		}
		capabilities, err := strictStringSlice(object["capabilities"], fmt.Sprintf("sessions item %d capabilities", index+1))
		if err != nil {
			return nil, err
		}
		session := run.SessionRef{
			ID:                 stringValue(object["id"]),
			RunID:              defaultString(stringValue(object["runId"]), request.ID),
			ModuleID:           defaultString(stringValue(object["moduleId"]), request.ModuleID),
			Target:             defaultString(stringValue(object["target"]), request.Target),
			Name:               stringValue(object["name"]),
			Kind:               defaultString(stringValue(object["kind"]), "shell"),
			State:              defaultString(stringValue(object["state"]), "active"),
			Transport:          defaultString(stringValue(object["transport"]), "stdio"),
			InstalledPayloadID: stringValue(object["installedPayloadId"]),
			Capabilities:       capabilities,
		}
		if session.ID == "" {
			return nil, fmt.Errorf("sessions item %d id is required", index+1)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func installedPayloadsFromRPC(value any) ([]run.InstalledPayloadDescriptor, error) {
	items, err := rpcArray(value, "installedPayloads")
	if err != nil {
		return nil, err
	}
	payloads := make([]run.InstalledPayloadDescriptor, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "installedPayloads", index)
		if err != nil {
			return nil, err
		}
		artifactIDs, err := strictStringSlice(object["artifactIds"], fmt.Sprintf("installedPayloads item %d artifactIds", index+1))
		if err != nil {
			return nil, err
		}
		reconnect, err := payloadProviderRecordFromRPC(object["reconnect"], fmt.Sprintf("installedPayloads item %d reconnect", index+1))
		if err != nil {
			return nil, err
		}
		cleanup, err := payloadProviderRecordFromRPC(object["cleanup"], fmt.Sprintf("installedPayloads item %d cleanup", index+1))
		if err != nil {
			return nil, err
		}
		metadata, err := stringMapFromRPC(object["metadata"], fmt.Sprintf("installedPayloads item %d metadata", index+1))
		if err != nil {
			return nil, err
		}
		payload := run.InstalledPayloadDescriptor{
			Provider:                 stringValue(object["provider"]),
			PayloadID:                stringValue(object["payloadId"]),
			PayloadVersion:           stringValue(object["payloadVersion"]),
			Target:                   stringValue(object["target"]),
			TargetID:                 stringValue(object["targetId"]),
			State:                    stringValue(object["state"]),
			Transport:                stringValue(object["transport"]),
			Endpoint:                 stringValue(object["endpoint"]),
			InstanceKey:              stringValue(object["instanceKey"]),
			StampID:                  stringValue(object["stampId"]),
			ArtifactIDs:              artifactIDs,
			SupportsReconnect:        boolValue(object["supportsReconnect"]),
			SupportsMultipleSessions: boolValue(object["supportsMultipleSessions"]),
			Reconnect:                reconnect,
			Cleanup:                  cleanup,
			Metadata:                 metadata,
		}
		if payload.Provider == "" {
			return nil, fmt.Errorf("installedPayloads item %d provider is required", index+1)
		}
		if payload.PayloadID == "" {
			return nil, fmt.Errorf("installedPayloads item %d payloadId is required", index+1)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

func agentHintsFromRPC(value any) ([]run.AgentHint, error) {
	items, err := rpcArray(value, "agentHints")
	if err != nil {
		return nil, err
	}
	hints := make([]run.AgentHint, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "agentHints", index)
		if err != nil {
			return nil, err
		}
		appliesTo, err := stringMapFromRPC(object["appliesTo"], fmt.Sprintf("agentHints item %d appliesTo", index+1))
		if err != nil {
			return nil, err
		}
		provenance, err := stringMapFromRPC(object["provenance"], fmt.Sprintf("agentHints item %d provenance", index+1))
		if err != nil {
			return nil, err
		}
		hint := run.AgentHint{
			Schema:     stringValue(object["schema"]),
			Phase:      stringValue(object["phase"]),
			Audience:   stringValue(object["audience"]),
			Risk:       stringValue(object["risk"]),
			AppliesTo:  appliesTo,
			Text:       stringValue(object["text"]),
			Provenance: provenance,
		}
		if hint.Schema == "" {
			hint.Schema = "hovel.agent_hint.v1"
		}
		hints = append(hints, hint)
	}
	return hints, nil
}

func payloadProviderRecordFromRPC(value any, label string) (*run.PayloadProviderRecord, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	descriptor, err := optionalAnyMap(object["descriptor"], label+" descriptor")
	if err != nil {
		return nil, err
	}
	return &run.PayloadProviderRecord{
		ProviderID:    stringValue(object["providerId"]),
		Schema:        stringValue(object["schema"]),
		SchemaVersion: stringValue(object["schemaVersion"]),
		Descriptor:    descriptor,
	}, nil
}

func stringMapFromRPC(value any, label string) (map[string]string, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	out := make(map[string]string, len(object))
	for key, item := range object {
		out[key] = stringValue(item)
	}
	return out, nil
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func displayName(moduleID string) string {
	parts := strings.Split(moduleID, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func withStderr(prefix string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, stderr)
}

func moduleFailure(summary, prefix string, err error, stderr string) error {
	var callback callbackError
	if errors.As(err, &callback) {
		return err
	}
	return services.NewModuleExecutionFailure(summary, withStderr(prefix, err, stderr))
}

type callbackError struct {
	err error
}

func (e callbackError) Error() string {
	return e.err.Error()
}

func (e callbackError) Unwrap() error {
	return e.err
}

func (r Runner) appendLog(ctx context.Context, request run.Request, log rpcLog) error {
	if r.Events == nil || r.IDs == nil || r.Clock == nil {
		return nil
	}
	id, err := event.NewID(r.IDs.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType("hovel.module.log")
	if err != nil {
		return err
	}
	level := normalizeModuleLogLevel(log.Level)
	fields := map[string]string{
		"level":   string(level),
		"message": log.Message,
		"logger":  log.Logger,
	}
	for key, value := range log.Fields {
		fields[key] = fmt.Sprint(value)
	}
	if log.Exception != "" {
		fields["exception"] = log.Exception
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Level:     level,
		Message:   log.Message,
		Timestamp: r.Clock.Now(),
		Refs: event.Refs{
			Operation: request.Operation,
			Chain:     request.Chain,
			RunID:     request.ID,
			ModuleID:  request.ModuleID,
			TargetID:  request.Target,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return r.Events.Append(ctx, evt)
}

func normalizeModuleLogLevel(level string) event.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return event.LevelDebug
	case "", "info":
		return event.LevelInfo
	case "warn", "warning":
		return event.LevelWarn
	case "error", "exception", "critical", "fatal":
		return event.LevelError
	default:
		return event.LevelInfo
	}
}

func (r Runner) appendSessionCreated(ctx context.Context, request run.Request, session run.SessionRef) error {
	if r.Events == nil || r.IDs == nil || r.Clock == nil {
		return nil
	}
	id, err := event.NewID(r.IDs.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType("hovel.session.created")
	if err != nil {
		return err
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Message:   "session opened",
		Timestamp: r.Clock.Now(),
		Refs: event.Refs{
			Operation: request.Operation,
			Chain:     request.Chain,
			RunID:     request.ID,
			ModuleID:  request.ModuleID,
			TargetID:  request.Target,
			SessionID: session.ID,
		},
		Fields: map[string]string{
			"sessionId": session.ID,
			"name":      session.Name,
			"kind":      session.Kind,
			"state":     session.State,
			"transport": session.Transport,
		},
	})
	if err != nil {
		return err
	}
	return r.Events.Append(ctx, evt)
}
