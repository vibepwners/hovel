package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
)

const daemonStatusFile = "daemon.json"

func (s WorkspaceStore) DaemonStatus(ctx context.Context, workspacePath string) (daemon.Status, error) {
	if err := ctx.Err(); err != nil {
		return daemon.Status{}, err
	}

	data, err := os.ReadFile(filepath.Join(workspacePath, daemonStatusFile))
	if errors.Is(err, os.ErrNotExist) {
		return daemon.NotRunning(workspacePath), nil
	}
	if err != nil {
		return daemon.Status{}, err
	}

	var file daemonFile
	if err := json.Unmarshal(data, &file); err != nil {
		return daemon.Status{}, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, file.StartedAt)
	if err != nil {
		return daemon.Status{}, err
	}
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: file.WorkspacePath,
		PID:           file.PID,
		SocketPath:    file.SocketPath,
		HovelConfig:   file.HovelConfig,
		StartedAt:     startedAt,
		Health:        daemon.Health(file.Health),
	})
	if err != nil {
		return daemon.Status{}, err
	}
	return daemon.Running(identity), nil
}

func (s WorkspaceStore) WriteDaemonStatus(ctx context.Context, identity daemon.Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(identity.WorkspacePath, 0o755); err != nil {
		return err
	}

	file := daemonFile{
		WorkspacePath: identity.WorkspacePath,
		PID:           identity.PID,
		SocketPath:    identity.SocketPath,
		HovelConfig:   identity.HovelConfig,
		StartedAt:     identity.StartedAt.Format(time.RFC3339Nano),
		Health:        string(identity.Health),
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(filepath.Join(identity.WorkspacePath, daemonStatusFile), data, 0o644)
}

func (s WorkspaceStore) ClearDaemonStatus(ctx context.Context, workspacePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(workspacePath, daemonStatusFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type daemonFile struct {
	WorkspacePath string `json:"workspacePath"`
	PID           int    `json:"pid"`
	SocketPath    string `json:"socketPath"`
	HovelConfig   string `json:"hovelConfig,omitempty"`
	StartedAt     string `json:"startedAt"`
	Health        string `json:"health"`
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	committed := false
	defer func() {
		if !committed {
			logFilesystemError("remove daemon status temp file", os.Remove(tmpPath))
		}
	}()

	if _, err := file.Write(data); err != nil {
		closeErr := file.Close()
		return errors.Join(err, closeErr)
	}
	if err := file.Chmod(perm); err != nil {
		closeErr := file.Close()
		return errors.Join(err, closeErr)
	}
	if err := file.Sync(); err != nil {
		closeErr := file.Close()
		return errors.Join(err, closeErr)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}
