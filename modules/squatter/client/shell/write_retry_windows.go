//go:build windows

package shell

func isRetryableWriteError(error) bool {
	return false
}
