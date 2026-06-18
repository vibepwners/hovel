//go:build windows

package shell

import "os"

func enterAttachTerminal(input *os.File) func() {
	return func() {}
}

func readAttachTerminal(input *os.File, buf []byte) (int, bool, error) {
	n, err := input.Read(buf)
	return n, false, err
}
