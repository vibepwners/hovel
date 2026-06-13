package hovel

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// PTYFrontend runs an interactive frontend attached to the slave side of a
// local pseudoterminal. Bytes written to the Hovel session enter the PTY master;
// bytes emitted by the frontend on output are read back from the PTY master.
type PTYFrontend func(input io.Reader, output io.Writer) error

// PTYSession exposes a local pseudoterminal as a raw Hovel session. It is useful
// for modules that already have a line-oriented local client UI but should still
// be driven over Hovel's raw byte session transport.
type PTYSession struct {
	Frontend PTYFrontend

	mu       sync.Mutex
	master   *os.File
	slave    *os.File
	queue    [][]byte
	notify   chan struct{}
	closed   bool
	ready    bool
	closeOne sync.Once
}

func (s *PTYSession) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return
	}
	s.notify = make(chan struct{}, 1)
	s.ready = true
}

// Open starts the PTY frontend.
func (s *PTYSession) Open() error {
	s.init()
	if s.Frontend == nil {
		return errors.New("pty session frontend is required")
	}
	master, slave, err := openPTY()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.master = master
	s.slave = slave
	s.mu.Unlock()

	go s.readMaster(master)
	go func() {
		err := s.Frontend(slave, slave)
		_ = slave.Close()
		if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
			s.emit([]byte("session frontend error: " + err.Error() + "\n"))
		}
		s.markClosed()
	}()
	return nil
}

// Write delivers raw operator bytes to the PTY master.
func (s *PTYSession) Write(data []byte) error {
	s.init()
	s.mu.Lock()
	master := s.master
	closed := s.closed
	s.mu.Unlock()
	if closed || master == nil || len(data) == 0 {
		return nil
	}
	_, err := master.Write(data)
	return err
}

// Read returns the next PTY output chunk.
func (s *PTYSession) Read(wait time.Duration) ([]byte, error) {
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

// Close terminates the PTY session.
func (s *PTYSession) Close(reason string) error {
	_ = reason
	s.init()
	s.closeOne.Do(func() {
		s.mu.Lock()
		master, slave := s.master, s.slave
		s.closed = true
		s.mu.Unlock()
		if slave != nil {
			_ = slave.Close()
		}
		if master != nil {
			_ = master.Close()
		}
		s.signal()
	})
	return nil
}

// Closed reports whether the session has terminated.
func (s *PTYSession) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *PTYSession) readMaster(master *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := master.Read(buf)
		if n > 0 {
			s.emit(buf[:n])
		}
		if err != nil {
			s.markClosed()
			return
		}
	}
}

func (s *PTYSession) emit(data []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.queue = append(s.queue, append([]byte(nil), data...))
	s.mu.Unlock()
	s.signal()
}

func (s *PTYSession) markClosed() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	master := s.master
	s.mu.Unlock()
	if master != nil {
		_ = master.Close()
	}
	s.signal()
}

func (s *PTYSession) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

var _ Session = (*PTYSession)(nil)
