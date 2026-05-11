package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlitestore "github.com/Vibe-Pwners/hovel/internal/adapters/storage/sqlite"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
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

func safeArtifactName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "artifact.bin"
	}
	return name
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

func (s WorkspaceStore) RecordThrowConfirmation(ctx context.Context, confirmation commands.ThrowConfirmationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspacePath := workspace.ResolvePath(confirmation.Workspace)
	if confirmation.ID == "" {
		return errors.New("throw confirmation id is required")
	}
	return sqlitestore.NewStore(workspacePath).RecordThrowConfirmation(ctx, confirmation)
}

func (s WorkspaceStore) RecordThrow(ctx context.Context, record commands.ThrowRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspacePath := workspace.ResolvePath(record.Workspace)
	if record.ID == "" {
		return errors.New("throw id is required")
	}
	return sqlitestore.NewStore(workspacePath).RecordThrow(ctx, record)
}

func (s WorkspaceStore) MaterializeArtifact(ctx context.Context, materialization commands.ArtifactMaterialization) (commands.ArtifactRecord, error) {
	if err := ctx.Err(); err != nil {
		return commands.ArtifactRecord{}, err
	}
	workspacePath := workspace.ResolvePath(materialization.Workspace)
	if materialization.ThrowID == "" || materialization.RunID == "" {
		return commands.ArtifactRecord{}, errors.New("artifact throw id and run id are required")
	}
	if materialization.Artifact.Name == "" {
		return commands.ArtifactRecord{}, errors.New("artifact name is required")
	}
	if strings.TrimSpace(materialization.Artifact.Path) != "" {
		return s.registerFileArtifact(ctx, workspacePath, materialization)
	}
	data := []byte(materialization.Artifact.Data)
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	artifactID := artifactRecordID(materialization, sha)
	relPath := filepath.Join("artifacts", materialization.ThrowID, materialization.RunID, safeArtifactName(materialization.Artifact.Name))
	absPath := filepath.Join(workspacePath, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return commands.ArtifactRecord{}, err
	}
	if err := os.WriteFile(absPath, data, 0o600); err != nil {
		return commands.ArtifactRecord{}, err
	}
	createdAt := materialization.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	record := commands.ArtifactRecord{
		ID:        artifactID,
		Workspace: workspacePath,
		ThrowID:   materialization.ThrowID,
		RunID:     materialization.RunID,
		ModuleID:  materialization.ModuleID,
		Target:    materialization.Target,
		Name:      materialization.Artifact.Name,
		Kind:      materialization.Artifact.Kind,
		Path:      relPath,
		SHA256:    sha,
		Size:      len(data),
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
	}
	if err := sqlitestore.NewStore(workspacePath).RecordArtifact(ctx, record); err != nil {
		return commands.ArtifactRecord{}, err
	}
	return record, nil
}

func (s WorkspaceStore) registerFileArtifact(ctx context.Context, workspacePath string, materialization commands.ArtifactMaterialization) (commands.ArtifactRecord, error) {
	path := strings.TrimSpace(materialization.Artifact.Path)
	info, err := os.Stat(path)
	if err != nil {
		return commands.ArtifactRecord{}, err
	}
	if info.IsDir() {
		return commands.ArtifactRecord{}, errors.New("artifact path must be a file")
	}
	source, err := os.Open(path)
	if err != nil {
		return commands.ArtifactRecord{}, err
	}
	defer source.Close()
	relPath := filepath.Join("artifacts", materialization.ThrowID, materialization.RunID, safeArtifactName(materialization.Artifact.Name))
	absPath := filepath.Join(workspacePath, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return commands.ArtifactRecord{}, err
	}
	destination, err := os.OpenFile(absPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return commands.ArtifactRecord{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	closeErr := destination.Close()
	if copyErr != nil {
		_ = os.Remove(absPath)
		return commands.ArtifactRecord{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(absPath)
		return commands.ArtifactRecord{}, closeErr
	}
	sha := hex.EncodeToString(hash.Sum(nil))
	createdAt := materialization.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	record := commands.ArtifactRecord{
		ID:        artifactRecordID(materialization, sha),
		Workspace: workspacePath,
		ThrowID:   materialization.ThrowID,
		RunID:     materialization.RunID,
		ModuleID:  materialization.ModuleID,
		Target:    materialization.Target,
		Name:      materialization.Artifact.Name,
		Kind:      materialization.Artifact.Kind,
		Path:      relPath,
		SHA256:    sha,
		Size:      int(written),
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
	}
	if err := sqlitestore.NewStore(workspacePath).RecordArtifact(ctx, record); err != nil {
		return commands.ArtifactRecord{}, err
	}
	return record, nil
}

func artifactRecordID(materialization commands.ArtifactMaterialization, contentSHA string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		materialization.ThrowID,
		materialization.RunID,
		materialization.ModuleID,
		materialization.Target,
		materialization.Artifact.Name,
		contentSHA,
	}, "\x00")))
	return "artifact-" + hex.EncodeToString(sum[:16])
}

func (s WorkspaceStore) RecordEvent(ctx context.Context, workspacePath string, evt event.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return sqlitestore.NewStore(workspacePath).RecordEvent(ctx, evt)
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

func (s WorkspaceStore) GetThrowConfirmation(ctx context.Context, workspacePath, planHash string) (commands.ThrowConfirmationRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return commands.ThrowConfirmationRecord{}, false, err
	}
	if planHash == "" {
		return commands.ThrowConfirmationRecord{}, false, errors.New("throw confirmation plan hash is required")
	}
	return sqlitestore.NewStore(workspacePath).GetThrowConfirmation(ctx, planHash)
}

func (s WorkspaceStore) ListArtifacts(ctx context.Context, workspacePath string) ([]commands.ArtifactRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sqlitestore.NewStore(workspacePath).ListArtifacts(ctx)
}

func (s WorkspaceStore) GetArtifact(ctx context.Context, workspacePath, id string) (commands.ArtifactRecord, error) {
	if err := ctx.Err(); err != nil {
		return commands.ArtifactRecord{}, err
	}
	if id == "" {
		return commands.ArtifactRecord{}, errors.New("artifact id is required")
	}
	return sqlitestore.NewStore(workspacePath).GetArtifact(ctx, id)
}

func (s WorkspaceStore) ListEvents(ctx context.Context, workspacePath string, filter event.Filter) ([]event.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sqlitestore.NewStore(workspacePath).ListEvents(ctx, filter)
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
