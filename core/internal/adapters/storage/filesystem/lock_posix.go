//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package filesystem

import "golang.org/x/sys/unix"

func processRunning(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}

func stalePIDLockDetectionSupported() bool {
	return true
}
