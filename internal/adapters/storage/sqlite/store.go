package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
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
	_, err := s.open(ctx)
	return err
}

func (s Store) SaveOperatorSession(ctx context.Context, state operatorsession.PersistedState) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return SaveOperatorSession(ctx, db, state)
}

func (s Store) LoadOperatorSession(ctx context.Context) (operatorsession.PersistedState, bool, error) {
	db, err := s.open(ctx)
	if err != nil {
		return operatorsession.PersistedState{}, false, err
	}
	return LoadOperatorSession(ctx, db)
}

func (s Store) RecordThrowPlan(ctx context.Context, plan commands.ThrowPlanRecord) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return RecordThrowPlan(ctx, db, plan)
}

func (s Store) RecordThrowConfirmation(ctx context.Context, confirmation commands.ThrowConfirmationRecord) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return RecordThrowConfirmation(ctx, db, confirmation)
}

func (s Store) RecordThrow(ctx context.Context, record commands.ThrowRecord) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return RecordThrow(ctx, db, record)
}

func (s Store) RecordArtifact(ctx context.Context, record commands.ArtifactRecord) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return RecordArtifact(ctx, db, record)
}

func (s Store) Append(ctx context.Context, evt event.Event) error {
	return s.RecordEvent(ctx, evt)
}

func (s Store) RecordEvent(ctx context.Context, evt event.Event) error {
	db, err := s.open(ctx)
	if err != nil {
		return err
	}
	return RecordEvent(ctx, db, evt)
}

func (s Store) ListThrowPlans(ctx context.Context) ([]commands.ThrowPlanRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return ListThrowPlans(ctx, db)
}

func (s Store) GetThrowPlan(ctx context.Context, id string) (commands.ThrowPlanRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.ThrowPlanRecord{}, err
	}
	return GetThrowPlan(ctx, db, id)
}

func (s Store) GetThrowConfirmation(ctx context.Context, planHash string) (commands.ThrowConfirmationRecord, bool, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.ThrowConfirmationRecord{}, false, err
	}
	return GetThrowConfirmation(ctx, db, planHash)
}

func (s Store) ListArtifacts(ctx context.Context) ([]commands.ArtifactRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return ListArtifacts(ctx, db)
}

func (s Store) GetArtifact(ctx context.Context, id string) (commands.ArtifactRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.ArtifactRecord{}, err
	}
	return GetArtifact(ctx, db, id)
}

func (s Store) ListEvents(ctx context.Context, filter event.Filter) ([]event.Event, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return ListEvents(ctx, db, filter)
}

// connCache holds one long-lived *sql.DB per database file. Opening a fresh
// connection pool and re-running migrations on every operation is both slow and
// needlessly destructive; the daemon owns a single workspace for its lifetime,
// so the handle is opened, configured, and migrated exactly once per path.
var connCache sync.Map // map[string]*cachedConn

type cachedConn struct {
	once sync.Once
	db   *sql.DB
	err  error
}

// open returns the shared *sql.DB for this workspace. Callers must NOT close the
// returned handle; it is owned by the cache and reused across operations.
func (s Store) open(ctx context.Context) (*sql.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := s.Path()
	value, _ := connCache.LoadOrStore(path, &cachedConn{})
	cached := value.(*cachedConn)
	cached.once.Do(func() {
		cached.db, cached.err = openDatabase(ctx, s.workspacePath, path)
	})
	return cached.db, cached.err
}

func openDatabase(ctx context.Context, workspacePath, dbPath string) (*sql.DB, error) {
	if err := os.MkdirAll(workspacePath, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// A single connection keeps the SQLite single-writer model simple: the
	// daemon owns one workspace, so serializing operations on one connection is
	// correct and avoids SQLITE_BUSY churn. WAL improves durability and read
	// latency over the default rollback journal.
	db.SetMaxOpenConns(1)
	pragmas := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, err
		}
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

func RecordThrowConfirmation(ctx context.Context, db *sql.DB, confirmation commands.ThrowConfirmationRecord) error {
	if confirmation.ID == "" {
		return errors.New("throw confirmation id is required")
	}
	if confirmation.PlanHash == "" {
		return errors.New("throw confirmation plan hash is required")
	}
	if confirmation.ClientID == "" {
		return errors.New("throw confirmation client id is required")
	}
	if confirmation.ConfirmedAt == "" {
		return errors.New("throw confirmation timestamp is required")
	}
	confirmationJSON, err := json.Marshal(confirmation)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO throw_confirmations(
	id,
	workspace,
	plan_id,
	plan_hash,
	client_id,
	method,
	confirmed_at,
	confirmation_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	workspace = excluded.workspace,
	plan_id = excluded.plan_id,
	plan_hash = excluded.plan_hash,
	client_id = excluded.client_id,
	method = excluded.method,
	confirmed_at = excluded.confirmed_at,
	confirmation_json = excluded.confirmation_json`,
		confirmation.ID,
		confirmation.Workspace,
		confirmation.PlanID,
		confirmation.PlanHash,
		confirmation.ClientID,
		confirmation.Method,
		confirmation.ConfirmedAt,
		string(confirmationJSON),
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

func GetThrowConfirmation(ctx context.Context, db *sql.DB, planHash string) (commands.ThrowConfirmationRecord, bool, error) {
	if planHash == "" {
		return commands.ThrowConfirmationRecord{}, false, errors.New("throw confirmation plan hash is required")
	}
	var data string
	err := db.QueryRowContext(ctx, `
SELECT confirmation_json
FROM throw_confirmations
WHERE plan_hash = ?
ORDER BY confirmed_at DESC
LIMIT 1`, planHash).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return commands.ThrowConfirmationRecord{}, false, nil
	}
	if err != nil {
		return commands.ThrowConfirmationRecord{}, false, err
	}
	var confirmation commands.ThrowConfirmationRecord
	if err := json.Unmarshal([]byte(data), &confirmation); err != nil {
		return commands.ThrowConfirmationRecord{}, false, err
	}
	return confirmation, true, nil
}

func RecordThrow(ctx context.Context, db *sql.DB, record commands.ThrowRecord) error {
	if record.ID == "" {
		return errors.New("throw id is required")
	}
	targetsJSON, err := json.Marshal(record.Targets)
	if err != nil {
		return err
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO throw_records(
	id,
	workspace,
	plan_id,
	plan_hash,
	chain,
	targets_json,
	state,
	throw_json,
	started_at,
	completed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	workspace = excluded.workspace,
	plan_id = excluded.plan_id,
	plan_hash = excluded.plan_hash,
	chain = excluded.chain,
	targets_json = excluded.targets_json,
	state = excluded.state,
	throw_json = excluded.throw_json,
	started_at = excluded.started_at,
	completed_at = excluded.completed_at`,
		record.ID,
		record.Workspace,
		record.PlanID,
		record.PlanHash,
		record.Chain,
		string(targetsJSON),
		record.State,
		string(recordJSON),
		record.StartedAt,
		record.CompletedAt,
	)
	return err
}

func RecordArtifact(ctx context.Context, db *sql.DB, record commands.ArtifactRecord) error {
	if record.ID == "" {
		return errors.New("artifact id is required")
	}
	if record.Path == "" {
		return errors.New("artifact path is required")
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO artifacts(
	id,
	workspace,
	throw_id,
	run_id,
	module_id,
	target,
	name,
	kind,
	path,
	sha256,
	size,
	artifact_json,
	created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	workspace = excluded.workspace,
	throw_id = excluded.throw_id,
	run_id = excluded.run_id,
	module_id = excluded.module_id,
	target = excluded.target,
	name = excluded.name,
	kind = excluded.kind,
	path = excluded.path,
	sha256 = excluded.sha256,
	size = excluded.size,
	artifact_json = excluded.artifact_json,
	created_at = excluded.created_at`,
		record.ID,
		record.Workspace,
		record.ThrowID,
		record.RunID,
		record.ModuleID,
		record.Target,
		record.Name,
		record.Kind,
		record.Path,
		record.SHA256,
		record.Size,
		string(recordJSON),
		record.CreatedAt,
	)
	return err
}

func ListArtifacts(ctx context.Context, db *sql.DB) ([]commands.ArtifactRecord, error) {
	rows, err := db.QueryContext(ctx, `SELECT artifact_json FROM artifacts ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []commands.ArtifactRecord
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var record commands.ArtifactRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt == records[j].CreatedAt {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedAt < records[j].CreatedAt
	})
	return records, nil
}

func GetArtifact(ctx context.Context, db *sql.DB, id string) (commands.ArtifactRecord, error) {
	if id == "" {
		return commands.ArtifactRecord{}, errors.New("artifact id is required")
	}
	var data string
	if err := db.QueryRowContext(ctx, `SELECT artifact_json FROM artifacts WHERE id = ?`, id).Scan(&data); err != nil {
		return commands.ArtifactRecord{}, err
	}
	var record commands.ArtifactRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return commands.ArtifactRecord{}, err
	}
	return record, nil
}

func RecordEvent(ctx context.Context, db *sql.DB, evt event.Event) error {
	if evt.ID == "" {
		return errors.New("event id is required")
	}
	if evt.Type == "" {
		return errors.New("event type is required")
	}
	fieldsJSON, err := json.Marshal(evt.Fields)
	if err != nil {
		return err
	}
	eventJSON, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO events(
	id,
	schema_version,
	timestamp,
	level,
	type,
	message,
	workspace,
	operation,
	chain,
	throw_id,
	run_id,
	module_id,
	target,
	topic,
	fields_json,
	event_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
		evt.ID.String(),
		evt.SchemaVersion,
		evt.Timestamp.UTC().Format(time.RFC3339Nano),
		string(evt.Level),
		evt.Type.String(),
		evt.Message,
		evt.Refs.WorkspaceID,
		evt.Refs.Operation,
		evt.Refs.Chain,
		evt.Refs.ThrowID,
		evt.Refs.RunID,
		evt.Refs.ModuleID,
		evt.Refs.TargetID,
		evt.Topic,
		string(fieldsJSON),
		string(eventJSON),
	)
	return err
}

func ListEvents(ctx context.Context, db *sql.DB, filter event.Filter) ([]event.Event, error) {
	rows, err := db.QueryContext(ctx, `SELECT event_json FROM events ORDER BY timestamp, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []event.Event
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var evt event.Event
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			return nil, err
		}
		if filter.Match(evt) {
			events = append(events, evt)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].ID.String() < events[j].ID.String()
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events, nil
}
