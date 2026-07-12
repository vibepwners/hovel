//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package pki

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openSecretFile(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, nil, errors.Join(errors.New("pki: open workspace master-key file"), unix.Close(fd))
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, nil, errors.Join(errors.New("pki: workspace master-key file owner or link count is unsafe"), file.Close())
	}
	return file, info, nil
}

func validateSecretFilePermissions(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("pki: workspace master-key file must be owner-only")
	}
	return nil
}
