package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const workspaceLockFile = "daemon.lock"

type WorkspaceLock struct {
	path string
	file *os.File
}

func AcquireWorkspaceLock(workspacePath, owner string) (*WorkspaceLock, error) {
	if owner == "" {
		return nil, errors.New("lock owner is required")
	}
	if err := os.MkdirAll(workspacePath, 0o755); err != nil {
		return nil, err
	}

	path := filepath.Join(workspacePath, workspaceLockFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, os.ErrExist) {
		if stalePIDWorkspaceLock(path) {
			_ = os.Remove(path)
			file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		}
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("workspace is already locked: %s", path)
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.WriteString(owner + "\n"); err != nil {
		file.Close()
		os.Remove(path)
		return nil, err
	}
	return &WorkspaceLock{path: path, file: file}, nil
}

func stalePIDWorkspaceLock(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	owner := strings.TrimSpace(string(data))
	pidText, ok := strings.CutPrefix(owner, "pid:")
	if !ok {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidText))
	if err != nil || pid <= 0 {
		return false
	}
	return !processRunning(pid)
}

func (l *WorkspaceLock) Release() error {
	if l == nil {
		return nil
	}
	var closeErr error
	if l.file != nil {
		closeErr = l.file.Close()
		l.file = nil
	}
	removeErr := os.Remove(l.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}
