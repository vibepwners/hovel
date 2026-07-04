package cli

import (
	"context"

	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
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
	state, ok, err := sqlitestore.NewStore(a.workspacePath).LoadOperatorSession(ctx)
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
	return sqlitestore.NewStore(a.workspacePath).SaveOperatorSession(ctx, session.Export())
}
