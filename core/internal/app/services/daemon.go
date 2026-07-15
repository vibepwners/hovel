package services

import (
	"context"

	"github.com/vibepwners/hovel/internal/domain/daemon"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

type DaemonStore interface {
	DaemonStatus(context.Context, string) (daemon.Status, error)
}

type DaemonStatusRequest struct {
	WorkspacePath string
}

type DaemonService struct {
	store DaemonStore
}

func NewDaemonService(store DaemonStore) DaemonService {
	return DaemonService{store: store}
}

func (s DaemonService) Status(ctx context.Context, req DaemonStatusRequest) (daemon.Status, error) {
	path := workspace.ResolvePath(req.WorkspacePath)
	return s.store.DaemonStatus(ctx, path)
}
