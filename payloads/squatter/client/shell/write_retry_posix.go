//go:build !windows

package shell

import (
	"errors"
	"syscall"
)

func isRetryableWriteError(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR)
}
