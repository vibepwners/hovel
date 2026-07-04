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
		logCLIError("close tty after capture failure", tty.Close())
		return nil, fmt.Errorf("capture terminal state: %w", err)
	}
	saved := *current
	return &promptTerminalState{
		restore: func() error {
			restoreErr := termios.Tcsetattr(tty.Fd(), termios.TCSANOW, &saved)
			closeErr := tty.Close()
			if restoreErr != nil {
				return fmt.Errorf("restore terminal state: %w", restoreErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close terminal: %w", closeErr)
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
