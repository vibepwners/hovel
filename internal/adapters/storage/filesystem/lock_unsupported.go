//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package filesystem

func processRunning(int) bool {
	return true
}

func stalePIDLockDetectionSupported() bool {
	return false
}
