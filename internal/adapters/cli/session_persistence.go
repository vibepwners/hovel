package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
)

const operatorSessionFile = "operator-session.json"

func (a App) withWorkspaceSession(workspacePath string) App {
	if a.session == nil || workspacePath == "" {
		return a
	}
	if _, ok := a.session.(*operatorsession.Session); !ok {
		return a
	}
	a.sessionFile = filepath.Join(workspacePath, operatorSessionFile)
	return a
}

func (a App) loadWorkspaceSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, ok := a.session.(*operatorsession.Session)
	if !ok || a.sessionFile == "" {
		return nil
	}
	data, err := os.ReadFile(a.sessionFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state operatorsession.PersistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	session.Import(state)
	return nil
}

func (a App) saveWorkspaceSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, ok := a.session.(*operatorsession.Session)
	if !ok || a.sessionFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.sessionFile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(session.Export(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(a.sessionFile, data, 0o644)
}
