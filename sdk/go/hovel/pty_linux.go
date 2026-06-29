//go:build linux

package hovel

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openPTY() (*os.File, *os.File, *os.File, error) {
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open pty master: %w", err)
	}
	master := os.NewFile(uintptr(masterFD), "/dev/ptmx")
	if err := unlockPTY(masterFD); err != nil {
		logSDKError("close PTY master after unlock failure", master.Close())
		return nil, nil, nil, err
	}
	slaveName, err := ptsName(masterFD)
	if err != nil {
		logSDKError("close PTY master after slave lookup failure", master.Close())
		return nil, nil, nil, err
	}
	inputFD, err := unix.Open(slaveName, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		logSDKError("close PTY master after input slave failure", master.Close())
		return nil, nil, nil, fmt.Errorf("open pty input slave: %w", err)
	}
	outputFD, err := unix.Open(slaveName, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		logSDKError("close PTY master after output slave failure", master.Close())
		logSDKError("close PTY input slave after output slave failure", unix.Close(inputFD))
		return nil, nil, nil, fmt.Errorf("open pty output slave: %w", err)
	}
	return master, os.NewFile(uintptr(inputFD), slaveName), os.NewFile(uintptr(outputFD), slaveName), nil
}

func unlockPTY(fd int) error {
	unlock := 0
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, unlock); err != nil {
		return fmt.Errorf("unlock pty: %w", err)
	}
	return nil
}

func ptsName(fd int) (string, error) {
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return "", fmt.Errorf("get pty slave name: %w", err)
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}
