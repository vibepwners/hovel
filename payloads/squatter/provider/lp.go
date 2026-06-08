package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

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
	reverse   map[string]*reverseTCPListener
	callbacks map[string]reverseTCPCallback
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
		Transport: "squatter/" + reverseTCP,
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
	if req.Config["payload.transport"] == reverseTCP {
		transport = "squatter/" + reverseTCP
		state = "listening"
		if callback, ok := lp.takeReverseCallback(req.Target); ok {
			state = "open"
			lp.mu.Lock()
			lp.callbacks[req.Target] = callback
			lp.mu.Unlock()
		}
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
		lp.listeners = map[string]hovel.ListenerRef{}
		lp.sessions = map[string]hovel.SessionRef{}
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
	delete(lp.listeners, req.Target)
	delete(lp.sessions, req.Target)
	delete(lp.reverse, req.Target)
	delete(lp.callbacks, req.Target)
	return hovel.CleanupResult{Status: "ok"}, nil
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
