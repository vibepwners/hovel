package daemonmanager

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

type ServeFunc func(context.Context, daemonruntime.Args) error

type Manager struct {
	Daemons      services.DaemonService
	Serve        ServeFunc
	PollInterval time.Duration
	Timeout      time.Duration
}

func New() Manager {
	store := filesystem.NewWorkspaceStore()
	return Manager{
		Daemons:      services.NewDaemonService(store),
		Serve:        daemonruntime.Serve,
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
	}
}

func (m Manager) Ensure(ctx context.Context, workspacePath string) (*Session, error) {
	m = m.withDefaults()
	workspacePath = workspace.ResolvePath(workspacePath)
	status, err := m.Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacePath})
	if err != nil {
		return nil, err
	}
	if status.State == daemon.StateRunning {
		status = normalizeStatus(status, workspacePath)
		if socketReachable(ctx, status.Identity.SocketPath) {
			return &Session{status: status}, nil
		}
		_ = filesystem.NewWorkspaceStore().ClearDaemonStatus(context.Background(), workspacePath)
		if status, ok := m.statusFromReachableSocket(ctx, workspacePath); ok {
			return &Session{status: status}, nil
		}
	} else if status, ok := m.statusFromReachableSocket(ctx, workspacePath); ok {
		return &Session{status: status}, nil
	}

	daemonCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- m.Serve(daemonCtx, daemonruntime.Args{WorkspacePath: workspacePath})
	}()

	status, err = m.waitRunning(ctx, workspacePath, done)
	if err != nil {
		cancel()
		select {
		case serveErr := <-done:
			if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
				return nil, errors.Join(err, serveErr)
			}
		case <-time.After(m.Timeout):
		}
		return nil, err
	}

	return &Session{
		status: status,
		owned:  true,
		cancel: cancel,
		done:   done,
	}, nil
}

func normalizeStatus(status daemon.Status, workspacePath string) daemon.Status {
	if status.State != daemon.StateRunning || filepath.IsAbs(status.Identity.SocketPath) {
		return status
	}
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           status.Identity.PID,
		SocketPath:    filepath.Join(filepath.Dir(workspacePath), status.Identity.SocketPath),
		StartedAt:     status.Identity.StartedAt,
		Health:        status.Identity.Health,
	})
	if err != nil {
		return status
	}
	return daemon.Running(identity)
}

func (m Manager) statusFromReachableSocket(ctx context.Context, workspacePath string) (daemon.Status, bool) {
	socketPath := filepath.Join(workspacePath, "hoveld.sock")
	if !socketReachable(ctx, socketPath) {
		return daemon.Status{}, false
	}
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           os.Getpid(),
		SocketPath:    socketPath,
		StartedAt:     time.Now().UTC(),
		Health:        daemon.HealthHealthy,
	})
	if err != nil {
		return daemon.Status{}, false
	}
	return daemon.Running(identity), true
}

func socketReachable(ctx context.Context, socketPath string) bool {
	if socketPath == "" {
		return false
	}
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (m Manager) waitRunning(ctx context.Context, workspacePath string, done <-chan error) (daemon.Status, error) {
	deadline := time.NewTimer(m.Timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(m.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return daemon.Status{}, ctx.Err()
		case err := <-done:
			if err == nil {
				return daemon.Status{}, errors.New("daemon exited before it became ready")
			}
			return daemon.Status{}, err
		case <-deadline.C:
			return daemon.Status{}, errors.New("timed out waiting for daemon to start")
		case <-ticker.C:
			status, err := m.Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacePath})
			if err != nil {
				return daemon.Status{}, err
			}
			if status.State == daemon.StateRunning {
				return status, nil
			}
		}
	}
}

func (m Manager) withDefaults() Manager {
	if m.Serve == nil {
		m.Serve = daemonruntime.Serve
	}
	if m.PollInterval == 0 {
		m.PollInterval = 10 * time.Millisecond
	}
	if m.Timeout == 0 {
		m.Timeout = 2 * time.Second
	}
	return m
}

type Session struct {
	status daemon.Status
	owned  bool
	cancel context.CancelFunc
	done   <-chan error
	closed bool
}

func (s *Session) Status() daemon.Status {
	return s.status
}

func (s *Session) Owned() bool {
	return s.owned
}

func (s *Session) Close() error {
	if s == nil || !s.owned || s.closed {
		return nil
	}
	s.closed = true
	s.cancel()
	err := <-s.done
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
