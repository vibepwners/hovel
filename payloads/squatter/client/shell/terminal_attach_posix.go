//go:build !windows

package shell

import (
	"errors"
	"os"
	"syscall"

	"github.com/charmbracelet/x/term"
)

func enterAttachTerminal(input *os.File) func() {
	if input == nil {
		return func() {}
	}
	state, err := term.MakeRaw(input.Fd())
	if err != nil {
		return func() {}
	}
	_ = syscall.SetNonblock(int(input.Fd()), true)
	return func() {
		_ = syscall.SetNonblock(int(input.Fd()), false)
		_ = term.Restore(input.Fd(), state)
	}
}

func readAttachTerminal(input *os.File, buf []byte) (int, bool, error) {
	n, err := input.Read(buf)
	if err == nil {
		return n, false, nil
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return n, true, nil
	}
	return n, false, err
}
