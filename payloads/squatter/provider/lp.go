package main

import (
	"fmt"
	"strconv"
	"sync"

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
}

func newPlaceholderLP() *placeholderLP {
	return &placeholderLP{
		listeners: map[string]hovel.ListenerRef{},
		sessions:  map[string]hovel.SessionRef{},
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
	ref := hovel.ListenerRef{
		ID:        "squatter-listener-placeholder-" + req.Target,
		RunID:     req.RunID,
		Target:    req.Target,
		Transport: "squatter/" + reverseTCP,
		Host:      req.Config["payload.lhost"],
		Port:      port,
		State:     "placeholder",
		Fields: map[string]string{
			"note": "reverse TCP listener is not implemented in this scaffold",
		},
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	lp.listeners[req.Target] = ref
	return ref, nil
}

func (lp *placeholderLP) ConnectSession(req hovel.ConnectSessionRequest) (hovel.SessionRef, error) {
	if req.Target == "" {
		return hovel.SessionRef{}, fmt.Errorf("target is required")
	}
	transport := "squatter/" + smbNamedPipe
	if req.Config["payload.transport"] == reverseTCP {
		transport = "squatter/" + reverseTCP
	}
	ref := hovel.SessionRef{
		ID:           "squatter-session-placeholder-" + req.Target,
		RunID:        req.RunID,
		ModuleID:     payloadName + "@" + version,
		Target:       req.Target,
		Name:         "Squatter placeholder session",
		Kind:         "agent",
		State:        "placeholder",
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
		lp.listeners = map[string]hovel.ListenerRef{}
		lp.sessions = map[string]hovel.SessionRef{}
		return hovel.CleanupResult{Status: "ok"}, nil
	}
	delete(lp.listeners, req.Target)
	delete(lp.sessions, req.Target)
	return hovel.CleanupResult{Status: "ok"}, nil
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
