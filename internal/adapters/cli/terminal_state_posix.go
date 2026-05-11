//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris
// +build aix android darwin dragonfly freebsd illumos ios linux netbsd openbsd solaris

package cli

import (
	"fmt"
	"os"
	"sync"

	"github.com/pkg/term/termios"
)

type promptTerminalState struct {
	once    sync.Once
	restore func() error
	err     error
}

func capturePromptTerminalState() (*promptTerminalState, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("capture terminal state: %w", err)
	}
	current, err := termios.Tcgetattr(tty.Fd())
	if err != nil {
		_ = tty.Close()
		return nil, fmt.Errorf("capture terminal state: %w", err)
	}
	saved := *current
	return &promptTerminalState{
		restore: func() error {
			defer tty.Close()
			if err := termios.Tcsetattr(tty.Fd(), termios.TCSANOW, &saved); err != nil {
				return fmt.Errorf("restore terminal state: %w", err)
			}
			return nil
		},
	}, nil
}

func (s *promptTerminalState) Restore() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		if s.restore != nil {
			s.err = s.restore()
		}
	})
	return s.err
}
