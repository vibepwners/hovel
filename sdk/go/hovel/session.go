package hovel

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SessionRef identifies an interactive session to the daemon and the operator.
type SessionRef struct {
	ID                 string   `json:"id"`
	RunID              string   `json:"runId"`
	ModuleID           string   `json:"moduleId"`
	Target             string   `json:"target"`
	Name               string   `json:"name"`
	Kind               string   `json:"kind"`
	State              string   `json:"state"`
	Transport          string   `json:"transport"`
	InstalledPayloadID string   `json:"installedPayloadId,omitempty"`
	Capabilities       []string `json:"capabilities"`
}

// CapabilityTerminalPTY marks sessions backed by a local pseudoterminal.
const CapabilityTerminalPTY = "terminal.pty"

// TerminalPTYSession is implemented by sessions that expose a local
// pseudoterminal. PTYSession implements it directly; wrappers can embed
// PTYSession and keep the terminal capability visible to Hovel.
type TerminalPTYSession interface {
	TerminalPTYSession() bool
}

// ListenerRef describes a provider-managed listener used to acquire sessions.
type ListenerRef struct {
	ID        string            `json:"id"`
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target,omitempty"`
	Transport string            `json:"transport"`
	Host      string            `json:"host,omitempty"`
	Port      int               `json:"port,omitempty"`
	Pipe      string            `json:"pipe,omitempty"`
	State     string            `json:"state"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (s SessionRef) toRPC() map[string]any {
	capabilities := s.Capabilities
	if capabilities == nil {
		capabilities = []string{}
	}
	return map[string]any{
		"id":                 s.ID,
		"runId":              s.RunID,
		"moduleId":           s.ModuleID,
		"target":             s.Target,
		"name":               s.Name,
		"kind":               s.Kind,
		"state":              s.State,
		"transport":          s.Transport,
		"installedPayloadId": s.InstalledPayloadID,
		"capabilities":       capabilities,
	}
}

// Session is an interactive channel a module opens during Run, such as a shell.
// The daemon drives it on the operator's behalf via Read/Write/Close. Most
// modules embed or use [LineShellSession] instead of implementing this directly.
type Session interface {
	// Open is called once when the session is registered.
	Open() error
	// Write delivers operator input to the session.
	Write(data []byte) error
	// Read returns the next chunk of session output. A non-negative wait bounds
	// how long to block for data; a negative wait blocks indefinitely. Returning
	// empty bytes with a nil error means "no data within the wait".
	Read(wait time.Duration) ([]byte, error)
	// Close terminates the session.
	Close(reason string) error
	// Closed reports whether the session has terminated.
	Closed() bool
}

// SessionOption customizes how a session is opened.
type SessionOption func(*sessionOptions)

type sessionOptions struct {
	name         string
	kind         string
	transport    string
	capabilities []string
}

// WithName sets the operator-facing display name.
func WithName(name string) SessionOption { return func(o *sessionOptions) { o.name = name } }

// WithKind sets the session kind, e.g. "shell" or "terminal".
func WithKind(kind string) SessionOption { return func(o *sessionOptions) { o.kind = kind } }

// WithTransport sets the transport label, e.g. "stdio".
func WithTransport(transport string) SessionOption {
	return func(o *sessionOptions) { o.transport = transport }
}

// WithCapabilities advertises what the operator may do with the session.
func WithCapabilities(capabilities ...string) SessionOption {
	return func(o *sessionOptions) { o.capabilities = capabilities }
}

// LineShellSession is a ready-made [Session] for modules that answer
// newline-delimited commands. Set Handle to map a command line to its output.
// The built-in commands "exit" and "logout" close the session.
type LineShellSession struct {
	// Prompt is written after every command (defaults to "$ ").
	Prompt string
	// Echo writes operator input back to the session output when true.
	Echo bool
	// Handle maps a command line to its output. A returned error is rendered as
	// an "error: ..." line.
	Handle func(command string) (string, error)

	mu     sync.Mutex
	buffer []byte
	queue  [][]byte
	notify chan struct{}
	closed bool
	ready  bool
}

func (s *LineShellSession) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return
	}
	s.notify = make(chan struct{}, 1)
	if s.Prompt == "" {
		s.Prompt = "$ "
	}
	s.ready = true
}

// Open writes the initial prompt.
func (s *LineShellSession) Open() error {
	s.init()
	s.emit([]byte(s.Prompt))
	return nil
}

// Closed reports whether the session has terminated.
func (s *LineShellSession) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *LineShellSession) emit(data []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.queue = append(s.queue, data)
	s.mu.Unlock()
	s.signal()
}

func (s *LineShellSession) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Write feeds operator bytes to the shell, dispatching each complete line.
func (s *LineShellSession) Write(data []byte) error {
	s.init()
	if s.Closed() {
		return nil
	}
	if s.Echo && len(data) > 0 {
		s.emit(append([]byte(nil), data...))
	}
	s.mu.Lock()
	s.buffer = append(s.buffer, data...)
	for {
		idx := bytes.IndexByte(s.buffer, '\n')
		if idx < 0 {
			break
		}
		line := append([]byte(nil), s.buffer[:idx]...)
		s.buffer = s.buffer[idx+1:]
		s.mu.Unlock()
		command := strings.TrimSpace(strings.TrimRight(string(line), "\r"))
		s.handleLine(command)
		s.mu.Lock()
	}
	s.mu.Unlock()
	return nil
}

func (s *LineShellSession) handleLine(command string) {
	switch command {
	case "exit", "logout":
		_ = s.Close("operator requested close")
		return
	case "":
		s.emit([]byte(s.Prompt))
		return
	}
	var output string
	if s.Handle != nil {
		result, err := s.Handle(command)
		if err != nil {
			result = "error: " + err.Error()
		}
		output = result
	}
	if output != "" {
		out := []byte(output)
		if !bytes.HasSuffix(out, []byte{'\n'}) {
			out = append(out, '\n')
		}
		s.emit(out)
	}
	if !s.Closed() {
		s.emit([]byte(s.Prompt))
	}
}

// Read returns the next chunk of output, honoring the wait deadline.
func (s *LineShellSession) Read(wait time.Duration) ([]byte, error) {
	s.init()
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			chunk := s.queue[0]
			s.queue = s.queue[1:]
			s.mu.Unlock()
			return chunk, nil
		}
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return nil, nil
		}
		if wait == 0 {
			return nil, nil
		}
		if wait < 0 {
			<-s.notify
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-s.notify:
			timer.Stop()
		case <-timer.C:
			return nil, nil
		}
	}
}

// Close terminates the session and wakes any blocked reader.
func (s *LineShellSession) Close(reason string) error {
	_ = reason
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.signal()
	return nil
}

// session management --------------------------------------------------------

type sessionScope struct {
	runID    string
	moduleID string
	target   string
}

type sessionEvent struct {
	event  string
	ref    SessionRef
	fields map[string]any
}

type managedSession struct {
	ref     SessionRef
	session Session
}

type sessionManager struct {
	mu       sync.Mutex
	emit     func(sessionEvent)
	sessions map[string]*managedSession
	counter  int
}

func newSessionManager(emit func(sessionEvent)) *sessionManager {
	return &sessionManager{emit: emit, sessions: map[string]*managedSession{}}
}

func (m *sessionManager) forRun(scope sessionScope) *sessionRegistry {
	return &sessionRegistry{manager: m, scope: scope}
}

func (m *sessionManager) open(scope sessionScope, session Session, opts ...sessionOptions) (SessionRef, error) {
	options := sessionOptions{kind: "shell", transport: "stdio", capabilities: []string{"read", "write", "close"}}
	if len(opts) > 0 {
		options = opts[0]
	}
	capabilities := append([]string(nil), options.capabilities...)
	if terminal, ok := session.(TerminalPTYSession); ok && terminal.TerminalPTYSession() {
		capabilities = appendSessionCapability(capabilities, CapabilityTerminalPTY)
	}
	m.mu.Lock()
	m.counter++
	id := fmt.Sprintf("%s-session-%d", scope.runID, m.counter)
	ref := SessionRef{
		ID:           id,
		RunID:        scope.runID,
		ModuleID:     scope.moduleID,
		Target:       scope.target,
		Name:         options.name,
		Kind:         options.kind,
		State:        "active",
		Transport:    options.transport,
		Capabilities: capabilities,
	}
	m.sessions[id] = &managedSession{ref: ref, session: session}
	m.mu.Unlock()
	if err := session.Open(); err != nil {
		return SessionRef{}, err
	}
	m.fire("session.created", ref, nil)
	return ref, nil
}

func appendSessionCapability(capabilities []string, capability string) []string {
	for _, existing := range capabilities {
		if existing == capability {
			return capabilities
		}
	}
	return append(capabilities, capability)
}

func (m *sessionManager) lookup(id string) (*managedSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	managed, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("hovel: unknown session %q", id)
	}
	return managed, nil
}

func (m *sessionManager) write(id string, data []byte) error {
	managed, err := m.lookup(id)
	if err != nil {
		return err
	}
	return managed.session.Write(data)
}

func (m *sessionManager) read(id string, wait time.Duration) ([]byte, bool, error) {
	managed, err := m.lookup(id)
	if err != nil {
		return nil, false, err
	}
	chunk, err := managed.session.Read(wait)
	if err != nil {
		return nil, false, err
	}
	if managed.session.Closed() {
		m.markClosed(id, "closed")
	}
	return chunk, m.state(id) == "closed", nil
}

func (m *sessionManager) close(id, reason string) error {
	managed, err := m.lookup(id)
	if err != nil {
		return err
	}
	if err := managed.session.Close(reason); err != nil {
		return err
	}
	m.markClosed(id, reason)
	return nil
}

func (m *sessionManager) listCommands(id string, req PayloadCommandListRequest) ([]PayloadCommand, error) {
	managed, err := m.lookup(id)
	if err != nil {
		return nil, err
	}
	provider, ok := managed.session.(PayloadCommandProvider)
	if !ok {
		return nil, fmt.Errorf("hovel: session %q does not expose payload commands", id)
	}
	return provider.ListPayloadCommands(req)
}

func (m *sessionManager) runCommand(id string, req PayloadCommandRequest) (PayloadCommandResult, error) {
	managed, err := m.lookup(id)
	if err != nil {
		return PayloadCommandResult{}, err
	}
	provider, ok := managed.session.(PayloadCommandProvider)
	if !ok {
		return PayloadCommandResult{}, fmt.Errorf("hovel: session %q does not expose payload commands", id)
	}
	return provider.RunPayloadCommand(req)
}

func (m *sessionManager) closeAll(reason string) {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.close(id, reason)
	}
}

func (m *sessionManager) state(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if managed, ok := m.sessions[id]; ok {
		return managed.ref.State
	}
	return ""
}

func (m *sessionManager) markClosed(id, reason string) {
	m.mu.Lock()
	managed, ok := m.sessions[id]
	if !ok || managed.ref.State == "closed" {
		m.mu.Unlock()
		return
	}
	managed.ref.State = "closed"
	ref := managed.ref
	m.mu.Unlock()
	m.fire("session.closed", ref, map[string]any{"reason": reason})
}

func (m *sessionManager) refsForRun(runID string) []SessionRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	var refs []SessionRef
	for _, managed := range m.sessions {
		if managed.ref.RunID == runID {
			refs = append(refs, managed.ref)
		}
	}
	return refs
}

func (m *sessionManager) fire(event string, ref SessionRef, fields map[string]any) {
	if m.emit != nil {
		m.emit(sessionEvent{event: event, ref: ref, fields: fields})
	}
}

type sessionRegistry struct {
	manager *sessionManager
	scope   sessionScope
}

func (r *sessionRegistry) open(session Session, opts ...SessionOption) (SessionRef, error) {
	options := sessionOptions{kind: "shell", transport: "stdio", capabilities: []string{"read", "write", "close"}}
	for _, opt := range opts {
		opt(&options)
	}
	return r.manager.open(r.scope, session, options)
}

func (r *sessionRegistry) refs() []SessionRef {
	return r.manager.refsForRun(r.scope.runID)
}
