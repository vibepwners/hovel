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
	if info.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.Join(errors.New("pki: workspace master-key file must be owner-only"), file.Close())
	}
	return file, info, nil
}

func secureSecretTempFile(file *os.File) error {
	return file.Chmod(0o600)
}

func ensureSecretDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return validateSecretDirectory(path)
}

func validateSecretDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("pki: workspace secrets path must be a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("pki: workspace secrets directory must be owner-only")
	}
	return nil
}
