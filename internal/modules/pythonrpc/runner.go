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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const defaultTimeout = 5 * time.Second

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

// usesCommand reports whether the entry launches an arbitrary executable
// (any language that speaks the stdio JSON-RPC protocol) rather than the
// built-in Python interpreter path.
func (e ModuleEntry) usesCommand() bool {
	return len(e.Command) > 0
}

type Runner struct {
	PythonPath string
	SDKRoot    string
	ConfigPath string
	Events     services.EventSink
	IDs        services.IDGenerator
	Clock      services.Clock
	Timeout    time.Duration
	Sessions   *SessionBroker
}

func ConfiguredCatalog(ctx context.Context) (modulecatalog.Catalog, error) {
	return Runner{}.Catalog(ctx)
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
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	process, err := r.start(ctx, moduleID)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	defer process.killAndWait()

	info, err := process.client.call(ctx, "handshake", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderr.String())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderr.String())
	}
	stepContracts, err := process.client.call(ctx, "step.describe", nil)
	if err != nil {
		if strings.Contains(err.Error(), "unknown method step.describe") {
			stepContracts = map[string]any{"steps": []any{}}
		} else {
			return modulecatalog.Module{}, moduleFailure("module failed while reporting step contracts", "module step describe failed", err, process.stderr.String())
		}
	}
	_, _ = process.client.call(context.Background(), "shutdown", nil)
	if err := process.wait(); err != nil {
		return modulecatalog.Module{}, moduleFailure("module exited with error", "module exited with error", err, process.stderr.String())
	}
	module, err := moduleFromRPC(moduleID, info, schema, stepContracts)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	return module, nil
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
		return run.Result{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderr.String())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return run.Result{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderr.String())
	}
	if module, err := moduleFromRPC(request.ModuleID, info, schema); err == nil {
		request.ModuleID = module.ID
	}
	executeResult, err := process.client.call(ctx, "execute", map[string]any{
		"runId":        request.ID,
		"moduleId":     request.ModuleID,
		"target":       request.Target,
		"inputs":       request.Inputs,
		"chainConfig":  request.ChainConfig,
		"targetConfig": request.TargetConfig,
	})
	if err != nil {
		return run.Result{}, moduleFailure("module failed during execution", "module execute failed", err, process.stderr.String())
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
			return run.Result{}, moduleFailure("module exited with error", "module exited with error", err, process.stderr.String())
		}
	}
	return result, nil
}

type moduleProcess struct {
	cmd    *exec.Cmd
	client *rpcClient
	stderr *bytes.Buffer
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
	stderr := &bytes.Buffer{}
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
		return r.ConfigPath
	}
	return os.Getenv(ModuleConfigEnv)
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
	path, err := resolveConfigPath(r.configPath())
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
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
	for _, entry := range config.Modules {
		entry.ID = strings.TrimSpace(entry.ID)
		entry.Runtime = strings.TrimSpace(entry.Runtime)
		entry.ProjectDir = strings.TrimSpace(entry.ProjectDir)
		entry.Module = strings.TrimSpace(entry.Module)
		if entry.ID == "" {
			continue
		}
		if entry.Runtime == "" {
			entry.Runtime = modulecatalog.RuntimeJSONRPCStdio
		}
		if entry.Runtime != modulecatalog.RuntimeJSONRPCStdio {
			continue
		}
		if entry.ProjectDir != "" && !filepath.IsAbs(entry.ProjectDir) {
			entry.ProjectDir = filepath.Join(baseDir, entry.ProjectDir)
		}
		if entry.usesCommand() {
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
	return entries, nil
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
	ID           string `json:"id"`
	RunID        string `json:"runId"`
	ModuleID     string `json:"moduleId"`
	Target       string `json:"target"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Transport    string `json:"transport"`
	Capabilities []any  `json:"capabilities"`
}

type frameDecoder struct {
	reader *bufio.Reader
}

func newFrameDecoder(reader io.Reader) *frameDecoder {
	return &frameDecoder{reader: bufio.NewReader(reader)}
}

func (d *frameDecoder) read() (rpcMessage, error) {
	headers := map[string]string{}
	for {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			return rpcMessage{}, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return rpcMessage{}, fmt.Errorf("malformed frame header %q", line)
		}
		headers[strings.ToLower(name)] = strings.TrimSpace(value)
	}
	lengthText := headers["content-length"]
	if lengthText == "" {
		return rpcMessage{}, errors.New("missing Content-Length header")
	}
	length, err := strconv.Atoi(lengthText)
	if err != nil {
		return rpcMessage{}, fmt.Errorf("invalid Content-Length header: %w", err)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(d.reader, body); err != nil {
		return rpcMessage{}, err
	}
	var raw struct {
		ID     *int            `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
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
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func resultFromRPC(request run.Request, values map[string]any, logs []rpcLog) (run.Result, error) {
	args := run.ResultArgs{
		Summary:   stringValue(values["summary"]),
		Findings:  findingsFromRPC(values["findings"]),
		Artifacts: artifactsFromRPC(values["artifacts"]),
		Logs:      logsFromRPC(request, logs),
		Sessions:  sessionsFromRPC(request, values["sessions"]),
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
		Tags:         stringSlice(info["tags"]),
		RuntimeKind:  modulecatalog.RuntimeJSONRPCStdio,
		Author:       "hovel",
		Enabled:      true,
		ChainConfig:  requirementsFromRPC(schema["chainConfig"]),
		TargetConfig: requirementsFromRPC(schema["targetConfig"]),
	}
	if len(stepContractValues) > 0 {
		module.StepContracts = stepContractsFromRPC(stepContractValues[0])
	}
	return module, nil
}

func stepContractsFromRPC(value map[string]any) modulecatalog.StepContractSet {
	set := modulecatalog.StepContractSet{
		Version: strings.TrimSpace(stringValue(value["version"])),
	}
	items, ok := value["steps"].([]any)
	if !ok {
		return set
	}
	set.Steps = make([]modulecatalog.StepContract, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		set.Steps = append(set.Steps, modulecatalog.StepContract{
			ID:           strings.TrimSpace(stringValue(object["id"])),
			Kind:         strings.TrimSpace(stringValue(object["kind"])),
			ConfigSchema: anyMap(object["configSchema"]),
			Requires:     capabilityRequirementsFromRPC(object["requires"]),
			Produces:     capabilityRequirementsFromRPC(object["produces"]),
			Prepare: modulecatalog.StepPrepareContract{
				Materializes: stringSliceFromAny(object["prepare"], "materializes"),
			},
			Cleanup: cleanupContractFromRPC(object["cleanup"]),
		})
	}
	return set
}

func capabilityRequirementsFromRPC(value any) []modulecatalog.CapabilityRequirement {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	requirements := make([]modulecatalog.CapabilityRequirement, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		requirements = append(requirements, modulecatalog.CapabilityRequirement{
			Type:          modulecatalog.CapabilityType(strings.TrimSpace(stringValue(object["type"]))),
			SchemaVersion: strings.TrimSpace(stringValue(object["schemaVersion"])),
			Attributes:    anyMap(object["attributes"]),
			States:        stringSlice(object["states"]),
		})
	}
	return requirements
}

func cleanupContractFromRPC(value any) *modulecatalog.StepCleanupContract {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return &modulecatalog.StepCleanupContract{StepID: strings.TrimSpace(stringValue(object["stepId"]))}
}

func stringSliceFromAny(value any, key string) []string {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return stringSlice(object[key])
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

func requirementsFromRPC(value any) []modulecatalog.Requirement {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	requirements := make([]modulecatalog.Requirement, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		requirements = append(requirements, modulecatalog.Requirement{
			Key:         stringValue(object["key"]),
			Type:        modulecatalog.ValueType(stringValue(object["type"])),
			Required:    boolValue(object["required"]),
			Default:     stringValue(object["default"]),
			Description: stringValue(object["description"]),
			Allowed:     stringSlice(object["allowed"]),
			Secret:      boolValue(object["secret"]),
		})
	}
	return requirements
}

func findingsFromRPC(value any) []run.Finding {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var findings []run.Finding
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		findings = append(findings, run.Finding{
			Title:    stringValue(object["title"]),
			Severity: run.Severity(stringValue(object["severity"])),
			Detail:   stringValue(object["detail"]),
		})
	}
	return findings
}

func artifactsFromRPC(value any) []run.Artifact {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var artifacts []run.Artifact
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		artifacts = append(artifacts, run.Artifact{
			Name: stringValue(object["name"]),
			Kind: stringValue(object["kind"]),
			Data: stringValue(object["data"]),
			Path: stringValue(object["path"]),
		})
	}
	return artifacts
}

type SessionBroker struct {
	mu       sync.Mutex
	sessions map[string]*brokerSession
}

type brokerSession struct {
	ref     run.SessionRef
	process *moduleProcess
}

func NewSessionBroker() *SessionBroker {
	return &SessionBroker{sessions: map[string]*brokerSession{}}
}

func (b *SessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	if b == nil {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	sessions := make([]run.SessionRef, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, cloneSessionRef(session.ref))
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].ID < sessions[j].ID
	})
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
	timeoutMs := int(timeout / time.Millisecond)
	if timeoutMs < 0 {
		timeoutMs = -1
	}
	values, err := session.process.client.call(ctx, "session/read", map[string]any{
		"sessionId": sessionID,
		"timeoutMs": timeoutMs,
	})
	if err != nil {
		return run.SessionChunk{}, err
	}
	data, err := base64.StdEncoding.DecodeString(stringValue(values["data"]))
	if err != nil {
		return run.SessionChunk{}, err
	}
	chunk := run.SessionChunk{
		SessionID: defaultString(stringValue(values["sessionId"]), sessionID),
		Data:      data,
		Closed:    boolValue(values["closed"]),
	}
	if chunk.Closed {
		b.markClosed(sessionID)
	}
	return chunk, nil
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
	defer b.mu.Unlock()
	if b.sessions == nil {
		b.sessions = map[string]*brokerSession{}
	}
	for _, session := range sessions {
		if session.ID == "" {
			continue
		}
		b.sessions[session.ID] = &brokerSession{ref: cloneSessionRef(session), process: process}
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
	defer b.mu.Unlock()
	if session, ok := b.sessions[sessionID]; ok {
		session.ref.State = "closed"
	}
}

func (b *SessionBroker) remove(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, sessionID)
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

func cloneSessionRef(session run.SessionRef) run.SessionRef {
	session.Capabilities = append([]string(nil), session.Capabilities...)
	return session
}

func sessionsFromRPC(request run.Request, value any) []run.SessionRef {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var sessions []run.SessionRef
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		session := run.SessionRef{
			ID:           stringValue(object["id"]),
			RunID:        defaultString(stringValue(object["runId"]), request.ID),
			ModuleID:     defaultString(stringValue(object["moduleId"]), request.ModuleID),
			Target:       defaultString(stringValue(object["target"]), request.Target),
			Name:         stringValue(object["name"]),
			Kind:         defaultString(stringValue(object["kind"]), "shell"),
			State:        defaultString(stringValue(object["state"]), "active"),
			Transport:    defaultString(stringValue(object["transport"]), "stdio"),
			Capabilities: stringSlice(object["capabilities"]),
		}
		if session.ID != "" {
			sessions = append(sessions, session)
		}
	}
	return sessions
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

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, stringValue(item))
	}
	return out
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
	fields := map[string]string{
		"level":   log.Level,
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
		Level:     event.Level(log.Level),
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
