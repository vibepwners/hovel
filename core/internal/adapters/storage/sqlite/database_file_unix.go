//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sqlite

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func validateDatabaseFileSecurity(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("sqlite database file has unsupported unix metadata")
	}
	if stat.Nlink != 1 {
		return errors.New("sqlite database file must have exactly one hard link")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("sqlite database file must be owned by the current user")
	}
	return nil
}

func validateDatabaseDirectorySecurity(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("sqlite database directory must not be a symbolic link")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("sqlite database directory must be owned by the current user")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("sqlite database directory must not be writable by other principals")
	}
	return nil
}

func openDatabaseFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
