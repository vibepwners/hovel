//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)
// +build !aix,!android,!darwin,!dragonfly,!freebsd,!illumos,!ios,!linux,!netbsd,!openbsd,!solaris

package commandmode

func enableTerminalEcho() (func() error, bool) {
	return nil, false
}
