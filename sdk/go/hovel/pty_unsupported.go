//go:build !linux

package hovel

import (
	"errors"
	"os"
)

func openPTY() (*os.File, *os.File, *os.File, error) {
	return nil, nil, nil, errors.New("pty sessions are not supported on this platform")
}
