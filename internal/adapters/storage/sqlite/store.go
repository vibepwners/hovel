package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	_ "modernc.org/sqlite"
)

type Store struct {
	workspacePath string
}

func NewStore(workspacePath string) Store {
	return Store{workspacePath: workspace.ResolvePath(workspacePath)}
}

func (s Store) Path() string {
	return filepath.Join(s.workspacePath, DatabaseFile)
}

func (s Store) Ensure(ctx context.Context) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	return nil
}

func (s Store) SaveOperatorSession(ctx context.Context, state operatorsession.PersistedState) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	return SaveOperatorSession(ctx, db, state)
}

func (s Store) LoadOperatorSession(ctx context.Context) (operatorsession.PersistedState, bool, error) {
	db, err := s.open(ctx)
	if err != nil {
		return operatorsession.PersistedState{}, false, err
	}
	defer db.Close()
	return LoadOperatorSession(ctx, db)
}

func (s Store) RecordThrowPlan(ctx context.Context, plan commands.ThrowPlanRecord) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	return RecordThrowPlan(ctx, db, plan)
}

func (s Store) ListThrowPlans(ctx context.Context) ([]commands.ThrowPlanRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return ListThrowPlans(ctx, db)
}

func (s Store) GetThrowPlan(ctx context.Context, id string) (commands.ThrowPlanRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.ThrowPlanRecord{}, err
	}
	defer db.Close()
	return GetThrowPlan(ctx, db, id)
}

func (s Store) open(ctx context.Context) (*sql.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.workspacePath, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", s.Path())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, err
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func SaveOperatorSession(ctx context.Context, db *sql.DB, state operatorsession.PersistedState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO operator_sessions(id, state_json, updated_at)
VALUES (1, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	state_json = excluded.state_json,
	updated_at = excluded.updated_at`,
		string(data),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func LoadOperatorSession(ctx context.Context, db *sql.DB) (operatorsession.PersistedState, bool, error) {
	var data string
	err := db.QueryRowContext(ctx, `SELECT state_json FROM operator_sessions WHERE id = 1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return operatorsession.PersistedState{}, false, nil
	}
	if err != nil {
		return operatorsession.PersistedState{}, false, err
	}
	var state operatorsession.PersistedState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return operatorsession.PersistedState{}, false, err
	}
	return state, true, nil
}

func RecordThrowPlan(ctx context.Context, db *sql.DB, plan commands.ThrowPlanRecord) error {
	if plan.ID == "" {
		return errors.New("throw plan id is required")
	}
	targetsJSON, err := json.Marshal(plan.Targets)
	if err != nil {
		return err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(ctx, `
INSERT INTO throw_plans(
	id,
	workspace,
	chain,
	confirmation_id,
	targets_json,
	review,
	intent,
	plan_json,
	created_at,
	updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	workspace = excluded.workspace,
	chain = excluded.chain,
	confirmation_id = excluded.confirmation_id,
	targets_json = excluded.targets_json,
	review = excluded.review,
	intent = excluded.intent,
	plan_json = excluded.plan_json,
	updated_at = excluded.updated_at`,
		plan.ID,
		plan.Workspace,
		plan.Chain,
		plan.ConfirmationID,
		string(targetsJSON),
		plan.Review,
		plan.Intent,
		string(planJSON),
		now,
		now,
	)
	return err
}

func ListThrowPlans(ctx context.Context, db *sql.DB) ([]commands.ThrowPlanRecord, error) {
	rows, err := db.QueryContext(ctx, `SELECT plan_json FROM throw_plans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []commands.ThrowPlanRecord
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var plan commands.ThrowPlanRecord
		if err := json.Unmarshal([]byte(data), &plan); err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(plans, func(i, j int) bool {
		return plans[i].ID < plans[j].ID
	})
	return plans, nil
}

func GetThrowPlan(ctx context.Context, db *sql.DB, id string) (commands.ThrowPlanRecord, error) {
	if id == "" {
		return commands.ThrowPlanRecord{}, errors.New("throw id is required")
	}
	var data string
	if err := db.QueryRowContext(ctx, `SELECT plan_json FROM throw_plans WHERE id = ?`, id).Scan(&data); err != nil {
		return commands.ThrowPlanRecord{}, err
	}
	var plan commands.ThrowPlanRecord
	if err := json.Unmarshal([]byte(data), &plan); err != nil {
		return commands.ThrowPlanRecord{}, err
	}
	return plan, nil
}
