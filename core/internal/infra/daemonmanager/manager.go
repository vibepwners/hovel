package daemonmanager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonruntime"
)

type ServeFunc func(context.Context, daemonruntime.Args) error
type HealthCheck func(context.Context, string) bool
type EndpointNetwork func(string) (string, bool)

type StatusStore interface {
	services.DaemonStore
	ClearDaemonStatus(context.Context, string) error
}

type Manager struct {
	Daemons         services.DaemonService
	Store           StatusStore
	Serve           ServeFunc
	SocketReachable HealthCheck
	EndpointNetwork EndpointNetwork
	PollInterval    time.Duration
	Timeout         time.Duration
}

func New(store StatusStore, healthCheck HealthCheck, endpointNetwork EndpointNetwork, serve ServeFunc) Manager {
	return Manager{
		Daemons:         services.NewDaemonService(store),
		Store:           store,
		Serve:           serve,
		SocketReachable: healthCheck,
		EndpointNetwork: endpointNetwork,
		PollInterval:    10 * time.Millisecond,
		Timeout:         2 * time.Second,
	}
}

func (m Manager) Ensure(ctx context.Context, workspacePath string) (*Session, error) {
	return m.EnsureWithModuleConfig(ctx, workspacePath, "")
}

func (m Manager) EnsureWithModuleConfig(ctx context.Context, workspacePath, moduleConfig string) (*Session, error) {
	return m.EnsureWithConfig(ctx, workspacePath, moduleConfig, "")
}

func (m Manager) EnsureWithConfig(ctx context.Context, workspacePath, moduleConfig, hovelConfig string) (*Session, error) {
	m = m.withDefaults()
	if err := m.validate(); err != nil {
		return nil, err
	}
	workspacePath = workspace.ResolvePath(workspacePath)
	status, err := m.Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacePath})
	if err != nil {
		return nil, err
	}
	if status.State == daemon.StateRunning {
		status = m.normalizeStatus(status, workspacePath)
		if m.socketReachable(ctx, status.Identity.SocketPath) {
			if err := ensureSameHovelConfig(status.Identity.HovelConfig, hovelConfig); err != nil {
				return nil, err
			}
			return &Session{status: status}, nil
		}
		logDaemonManagerError("clear stale daemon status", m.Store.ClearDaemonStatus(context.Background(), workspacePath))
		if status, ok := m.statusFromReachableSocket(ctx, workspacePath); ok {
			if err := ensureSameHovelConfig(status.Identity.HovelConfig, hovelConfig); err != nil {
				return nil, err
			}
			return &Session{status: status}, nil
		}
	} else if status, ok := m.statusFromReachableSocket(ctx, workspacePath); ok {
		if err := ensureSameHovelConfig(status.Identity.HovelConfig, hovelConfig); err != nil {
			return nil, err
		}
		return &Session{status: status}, nil
	}

	daemonCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- m.Serve(daemonCtx, daemonruntime.Args{WorkspacePath: workspacePath, ModuleConfig: moduleConfig, HovelConfig: hovelConfig})
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

func ensureSameHovelConfig(running, requested string) error {
	running = normalizeConfigPath(running)
	requested = normalizeConfigPath(requested)
	if running != requested {
		return errors.New("daemon is already running with a different hovel config; stop it before changing --config")
	}
	return nil
}

func normalizeConfigPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

func (m Manager) normalizeStatus(status daemon.Status, workspacePath string) daemon.Status {
	if status.State != daemon.StateRunning || filepath.IsAbs(status.Identity.SocketPath) || m.isEndpointAddress(status.Identity.SocketPath) {
		return status
	}
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: workspacePath,
		PID:           status.Identity.PID,
		SocketPath:    filepath.Join(filepath.Dir(workspacePath), status.Identity.SocketPath),
		HovelConfig:   status.Identity.HovelConfig,
		StartedAt:     status.Identity.StartedAt,
		Health:        status.Identity.Health,
	})
	if err != nil {
		return status
	}
	return daemon.Running(identity)
}

func (m Manager) isEndpointAddress(value string) bool {
	if m.EndpointNetwork == nil {
		return false
	}
	network, ok := m.EndpointNetwork(value)
	return ok && network == "tcp"
}

func (m Manager) statusFromReachableSocket(ctx context.Context, workspacePath string) (daemon.Status, bool) {
	socketPath := filepath.Join(workspacePath, "hoveld.sock")
	if !m.socketReachable(ctx, socketPath) {
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

func (m Manager) socketReachable(ctx context.Context, socketPath string) bool {
	if socketPath == "" {
		return false
	}
	if m.SocketReachable == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	return m.SocketReachable(ctx, socketPath)
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
	if m.Store != nil {
		m.Daemons = services.NewDaemonService(m.Store)
	}
	if m.PollInterval == 0 {
		m.PollInterval = 10 * time.Millisecond
	}
	if m.Timeout == 0 {
		m.Timeout = 2 * time.Second
	}
	return m
}

func (m Manager) validate() error {
	if m.Store == nil {
		return errors.New("daemon manager store is not configured")
	}
	if m.Serve == nil {
		return errors.New("daemon manager serve function is not configured")
	}
	if m.SocketReachable == nil {
		return errors.New("daemon manager health check is not configured")
	}
	if m.EndpointNetwork == nil {
		return errors.New("daemon manager endpoint parser is not configured")
	}
	return nil
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
