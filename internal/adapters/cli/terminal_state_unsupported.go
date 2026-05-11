//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)
// +build !aix,!android,!darwin,!dragonfly,!freebsd,!illumos,!ios,!linux,!netbsd,!openbsd,!solaris

package cli

type promptTerminalState struct{}

func capturePromptTerminalState() (*promptTerminalState, error) {
	return &promptTerminalState{}, nil
}

func (s *promptTerminalState) Restore() error {
	return nil
}
