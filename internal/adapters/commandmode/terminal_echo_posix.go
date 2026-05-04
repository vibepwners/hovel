//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris
// +build aix android darwin dragonfly freebsd illumos ios linux netbsd openbsd solaris

package commandmode

import (
	"os"

	"github.com/pkg/term/termios"
	"golang.org/x/sys/unix"
)

func enableTerminalEcho() (func() error, bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, false
	}
	current, err := termios.Tcgetattr(tty.Fd())
	if err != nil {
		_ = tty.Close()
		return nil, false
	}
	previous := *current
	next := *current
	next.Iflag |= unix.ICRNL
	next.Oflag |= unix.OPOST
	next.Lflag |= unix.ECHO | unix.ICANON | unix.ISIG
	if err := termios.Tcsetattr(tty.Fd(), termios.TCSANOW, &next); err != nil {
		_ = tty.Close()
		return nil, false
	}
	return func() error {
		defer tty.Close()
		return termios.Tcsetattr(tty.Fd(), termios.TCSANOW, &previous)
	}, true
}
