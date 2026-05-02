package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

const workspaceConfigFile = "workspace.json"

type WorkspaceStore struct{}

func NewWorkspaceStore() WorkspaceStore {
	return WorkspaceStore{}
}

func (s WorkspaceStore) InitWorkspace(ctx context.Context, ws workspace.Workspace) (services.WorkspaceRecord, error) {
	if err := ctx.Err(); err != nil {
		return services.WorkspaceRecord{}, err
	}

	configPath := filepath.Join(ws.Path, workspaceConfigFile)
	existing, err := readWorkspace(configPath)
	if err == nil {
		if err := ensureWorkspaceLayout(ws.Path); err != nil {
			return services.WorkspaceRecord{}, err
		}
		if err := s.EnsureWorkspaceDatabase(ctx, ws.Path); err != nil {
			return services.WorkspaceRecord{}, err
		}
		return services.WorkspaceRecord{Workspace: existing, Created: false}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return services.WorkspaceRecord{}, err
	}

	if err := ensureWorkspaceLayout(ws.Path); err != nil {
		return services.WorkspaceRecord{}, err
	}
	if err := writeWorkspace(configPath, ws); err != nil {
		return services.WorkspaceRecord{}, err
	}
	if err := s.EnsureWorkspaceDatabase(ctx, ws.Path); err != nil {
		return services.WorkspaceRecord{}, err
	}
	return services.WorkspaceRecord{Workspace: ws, Created: true}, nil
}

func ensureWorkspaceLayout(path string) error {
	for _, rel := range []string{
		"",
		"artifacts",
		"logs",
		"modules",
		"throws",
		"services",
	} {
		if err := os.MkdirAll(filepath.Join(path, rel), 0o755); err != nil {
			return err
		}
	}
	return nil
}

type workspaceFile struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
}

func readWorkspace(path string) (workspace.Workspace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return workspace.Workspace{}, err
	}
	var file workspaceFile
	if err := json.Unmarshal(data, &file); err != nil {
		return workspace.Workspace{}, err
	}
	id, err := workspace.NewID(file.ID)
	if err != nil {
		return workspace.Workspace{}, err
	}
	name, err := workspace.NewName(file.Name)
	if err != nil {
		return workspace.Workspace{}, err
	}
	return workspace.New(id, name, file.Path)
}

func writeWorkspace(path string, ws workspace.Workspace) error {
	file := workspaceFile{
		Version: 1,
		ID:      ws.ID.String(),
		Name:    ws.Name.String(),
		Path:    ws.Path,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func (s WorkspaceStore) RecordThrowPlan(ctx context.Context, plan commands.ThrowPlanRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspacePath := workspace.ResolvePath(plan.Workspace)
	if plan.ID == "" {
		return errors.New("throw plan id is required")
	}
	return sqlitestore.NewStore(workspacePath).RecordThrowPlan(ctx, plan)
}

func (s WorkspaceStore) ListThrowPlans(ctx context.Context, workspacePath string) ([]commands.ThrowPlanRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sqlitestore.NewStore(workspacePath).ListThrowPlans(ctx)
}

func (s WorkspaceStore) GetThrowPlan(ctx context.Context, workspacePath, id string) (commands.ThrowPlanRecord, error) {
	if err := ctx.Err(); err != nil {
		return commands.ThrowPlanRecord{}, err
	}
	if id == "" {
		return commands.ThrowPlanRecord{}, errors.New("throw id is required")
	}
	return sqlitestore.NewStore(workspacePath).GetThrowPlan(ctx, id)
}

func (s WorkspaceStore) EnsureWorkspaceDatabase(ctx context.Context, workspacePath string) error {
	return sqlitestore.NewStore(workspacePath).Ensure(ctx)
}

func (s WorkspaceStore) SaveOperatorSession(ctx context.Context, workspacePath string, state operatorsession.PersistedState) error {
	return sqlitestore.NewStore(workspacePath).SaveOperatorSession(ctx, state)
}

func (s WorkspaceStore) LoadOperatorSession(ctx context.Context, workspacePath string) (operatorsession.PersistedState, bool, error) {
	return sqlitestore.NewStore(workspacePath).LoadOperatorSession(ctx)
}
