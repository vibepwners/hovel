package pythonrpc

import (
	"context"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/domain/run"
)

const (
	defaultSessionHistoryBytes = 10 * 1024 * 1024
	sessionReadChunkBytes      = 32 * 1024
)

type brokerSession struct {
	ref      run.SessionRef
	process  *moduleProcess
	limit    int
	order    uint64
	datagram bool
	ctx      context.Context
	cancel   context.CancelFunc
	closeMu  sync.Mutex

	mu                   sync.Mutex
	history              []byte
	pending              []byte
	pendingDatagrams     [][]byte
	pendingDatagramBytes int
	closed               bool
	notify               chan struct{}
}

func newBrokerSession(ref run.SessionRef, process *moduleProcess, limit int) *brokerSession {
	if limit <= 0 {
		limit = defaultSessionHistoryBytes
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &brokerSession{
		ref:      cloneSessionRef(ref),
		process:  process,
		limit:    limit,
		datagram: ref.HasCapability(run.SessionCapabilityDatagram),
		ctx:      ctx,
		cancel:   cancel,
		notify:   make(chan struct{}),
	}
}

func (s *brokerSession) appendData(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = appendBounded(s.history, data, s.limit)
	if s.datagram {
		s.appendPendingDatagramLocked(data)
	} else {
		s.pending = appendBounded(s.pending, data, s.limit)
	}
	s.notifyLocked()
}

func (s *brokerSession) appendPendingDatagramLocked(data []byte) {
	datagram := append([]byte(nil), data...)
	s.pendingDatagrams = append(s.pendingDatagrams, datagram)
	s.pendingDatagramBytes += len(datagram)
	for s.pendingDatagramBytes > s.limit && len(s.pendingDatagrams) > 1 {
		s.pendingDatagramBytes -= len(s.pendingDatagrams[0])
		s.pendingDatagrams[0] = nil
		s.pendingDatagrams = s.pendingDatagrams[1:]
	}
}

func (s *brokerSession) read(ctx context.Context, sessionID string, timeout time.Duration) (run.SessionChunk, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		s.mu.Lock()
		if len(s.pendingDatagrams) > 0 {
			data := s.pendingDatagrams[0]
			s.pendingDatagrams[0] = nil
			s.pendingDatagrams = s.pendingDatagrams[1:]
			s.pendingDatagramBytes -= len(data)
			closed := s.closed && len(s.pendingDatagrams) == 0
			s.mu.Unlock()
			return run.SessionChunk{SessionID: sessionID, Data: data, Closed: closed}, nil
		}
		if len(s.pending) > 0 {
			size := len(s.pending)
			if size > sessionReadChunkBytes {
				size = sessionReadChunkBytes
			}
			data := append([]byte(nil), s.pending[:size]...)
			s.pending = s.pending[size:]
			closed := s.closed && len(s.pending) == 0
			s.mu.Unlock()
			return run.SessionChunk{SessionID: sessionID, Data: data, Closed: closed}, nil
		}
		if s.closed {
			s.mu.Unlock()
			return run.SessionChunk{SessionID: sessionID, Closed: true}, nil
		}
		notify := s.notify
		s.mu.Unlock()

		if timeout == 0 {
			return run.SessionChunk{SessionID: sessionID}, nil
		}
		timedOut, err := waitForSessionNotification(ctx, notify, deadline)
		if err != nil {
			return run.SessionChunk{}, err
		}
		if timedOut {
			return run.SessionChunk{SessionID: sessionID}, nil
		}
	}
}

func waitForSessionNotification(ctx context.Context, notify <-chan struct{}, deadline time.Time) (bool, error) {
	if deadline.IsZero() {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-notify:
			return false, nil
		}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return true, nil
	}
	timer := time.NewTimer(remaining)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-notify:
		return false, nil
	case <-timer.C:
		return true, nil
	}
}

func (s *brokerSession) tail(sessionID string, options run.SessionTailOptions) run.SessionChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.history
	switch {
	case options.MaxBytes > 0:
		data = tailBytes(data, options.MaxBytes)
	case options.MaxLines > 0:
		data = tailLines(data, options.MaxLines)
	default:
		data = append([]byte(nil), data...)
	}
	if options.Consume {
		s.pending = nil
		s.pendingDatagrams = nil
		s.pendingDatagramBytes = 0
	}
	return run.SessionChunk{SessionID: sessionID, Data: data, Closed: s.closed}
}

func (s *brokerSession) closeLocal() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.notifyLocked()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *brokerSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *brokerSession) notifyLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

func appendBounded(current, data []byte, limit int) []byte {
	if limit <= 0 {
		return nil
	}
	if len(data) >= limit {
		return append([]byte(nil), data[len(data)-limit:]...)
	}
	out := append(current, data...)
	if overflow := len(out) - limit; overflow > 0 {
		copy(out, out[overflow:])
		out = out[:limit]
	}
	return out
}

func tailBytes(data []byte, maxBytes int) []byte {
	if maxBytes <= 0 || maxBytes >= len(data) {
		return append([]byte(nil), data...)
	}
	return append([]byte(nil), data[len(data)-maxBytes:]...)
}

func tailLines(data []byte, maxLines int) []byte {
	if maxLines <= 0 || len(data) == 0 {
		return append([]byte(nil), data...)
	}
	lines := 0
	i := len(data) - 1
	if data[i] == '\n' {
		i--
	}
	for ; i >= 0; i-- {
		if data[i] != '\n' {
			continue
		}
		lines++
		if lines == maxLines {
			return append([]byte(nil), data[i+1:]...)
		}
	}
	return append([]byte(nil), data...)
}
