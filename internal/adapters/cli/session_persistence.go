package cli

import (
	"context"

	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
)

func (a App) withWorkspaceSession(workspacePath string) App {
	if a.session == nil || workspacePath == "" {
		return a
	}
	if _, ok := a.session.(*operatorsession.Session); !ok {
		return a
	}
	a.workspacePath = workspacePath
	return a
}

func (a App) loadWorkspaceSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, ok := a.session.(*operatorsession.Session)
	if !ok || a.workspacePath == "" {
		return nil
	}
	state, ok, err := filesystem.NewWorkspaceStore().LoadOperatorSession(ctx, a.workspacePath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	session.Import(state)
	return nil
}

func (a App) saveWorkspaceSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, ok := a.session.(*operatorsession.Session)
	if !ok || a.workspacePath == "" {
		return nil
	}
	return filesystem.NewWorkspaceStore().SaveOperatorSession(ctx, a.workspacePath, session.Export())
}
