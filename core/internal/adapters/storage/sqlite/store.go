package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/app/commands"
	"github.com/vibepwners/hovel/internal/app/operatorsession"
	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/domain/workspace"
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

// Close releases this workspace's cached database handle. The caller must
// first stop operations using the store; daemon shutdown does this after its
// request handlers have drained. A later open creates a fresh configured pool.
func (s Store) Close() error {
	path := s.Path()
	connMu.Lock()
	db, ok := connCache[path]
	if ok {
		delete(connCache, path)
	}
	connMu.Unlock()
	if !ok {
		return nil
	}
	return db.Close()
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

func (s Store) RecordInstalledPayload(ctx context.Context, record commands.InstalledPayloadRecord) (commands.InstalledPayloadRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return RecordInstalledPayload(ctx, db, record)
}

func (s Store) ListInstalledPayloads(ctx context.Context, workspacePath string, filter commands.InstalledPayloadFilter) ([]commands.InstalledPayloadRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return ListInstalledPayloads(ctx, db, workspacePath, filter)
}

func (s Store) GetInstalledPayload(ctx context.Context, workspacePath, ref string) (commands.InstalledPayloadRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return GetInstalledPayload(ctx, db, workspacePath, ref)
}

func (s Store) UpdateInstalledPayloadState(ctx context.Context, workspacePath, ref, state, reason string) (commands.InstalledPayloadRecord, error) {
	db, err := s.open(ctx)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return UpdateInstalledPayloadState(ctx, db, workspacePath, ref, state, reason)
}

func (s Store) ListInstalledPayloadEvents(ctx context.Context, workspacePath, ref string) ([]commands.InstalledPayloadEvent, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return ListInstalledPayloadEvents(ctx, db, workspacePath, ref)
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
//
// Only successful opens are cached. A failed open (e.g. a request whose context
// was cancelled mid-migration) is never stored, so a transient error cannot
// poison the entry and wedge the workspace for the rest of the process; the next
// call retries with a fresh context.
var (
	connMu    sync.Mutex
	connCache = map[string]*sql.DB{}
)

// open returns the shared *sql.DB for this workspace. Callers must NOT close the
// returned handle; it is owned by the cache and reused across operations.
//
// The lock is held across openDatabase so a path is opened at most once. Opens
// are rare (first access per path) and a daemon owns a single workspace, so the
// brief serialization is immaterial; every later call is just a map lookup.
func (s Store) open(ctx context.Context) (*sql.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := s.Path()
	connMu.Lock()
	defer connMu.Unlock()
	if db, ok := connCache[path]; ok {
		return db, nil
	}
	db, err := openDatabase(ctx, s.workspacePath, path)
	if err != nil {
		return nil, err
	}
	connCache[path] = db
	return db, nil
}

func openDatabase(ctx context.Context, workspacePath, dbPath string) (*sql.DB, error) {
	if err := os.MkdirAll(workspacePath, 0o755); err != nil {
		return nil, err
	}
	if err := validateDatabaseDirectorySecurity(workspacePath); err != nil {
		return nil, err
	}
	anchoredFile, err := ensureOwnerOnlyDatabaseFile(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close anchored sqlite database file", anchoredFile.Close()) }()
	anchoredSidecars, err := prepareSQLiteSidecars(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, sidecar := range anchoredSidecars {
			logSQLiteError("close anchored sqlite sidecar", sidecar.Close())
		}
	}()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// A single connection keeps the SQLite single-writer model simple: the
	// daemon owns one workspace, so serializing operations on one connection is
	// correct and avoids SQLITE_BUSY churn. WAL improves durability and read
	// latency over the default rollback journal.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		closeErr := db.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := verifyDatabaseFileIdentity(dbPath, anchoredFile); err != nil {
		closeErr := db.Close()
		return nil, errors.Join(err, closeErr)
	}
	pragmas := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			closeErr := db.Close()
			return nil, errors.Join(err, closeErr)
		}
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		closeErr := db.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := verifyDatabaseFileIdentity(dbPath, anchoredFile); err != nil {
		closeErr := db.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := verifySQLiteSidecars(dbPath, anchoredSidecars); err != nil {
		closeErr := db.Close()
		return nil, errors.Join(err, closeErr)
	}
	return db, nil
}

var sqliteSidecarSuffixes = [...]string{"-wal", "-shm"}

func prepareSQLiteSidecars(databasePath string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(sqliteSidecarSuffixes))
	for _, suffix := range sqliteSidecarSuffixes {
		file, err := openDatabaseFileNoFollow(databasePath + suffix)
		if err != nil {
			for _, opened := range files {
				err = errors.Join(err, opened.Close())
			}
			return nil, err
		}
		info, err := file.Stat()
		if err == nil && !info.Mode().IsRegular() {
			err = errors.New("sqlite sidecar path must be a regular file")
		}
		if err == nil {
			err = validateDatabaseFileSecurity(info)
		}
		if err == nil {
			err = file.Chmod(0o600)
		}
		if err != nil {
			err = errors.Join(err, file.Close())
			for _, opened := range files {
				err = errors.Join(err, opened.Close())
			}
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func verifySQLiteSidecars(databasePath string, files []*os.File) error {
	if len(files) != len(sqliteSidecarSuffixes) {
		return errors.New("sqlite anchored sidecar set is incomplete")
	}
	var result error
	for index, file := range files {
		result = errors.Join(result, verifyDatabaseFileIdentity(databasePath+sqliteSidecarSuffixes[index], file), file.Chmod(0o600))
	}
	return result
}

func ensureOwnerOnlyDatabaseFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sqlite database path must not be a symbolic link")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := openDatabaseFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, errors.Join(errors.New("sqlite database path must be a regular file"), file.Close())
	}
	if err := validateDatabaseFileSecurity(openedInfo); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := verifyDatabaseFileIdentity(path, file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func verifyDatabaseFileIdentity(path string, anchored *os.File) error {
	if anchored == nil {
		return errors.New("sqlite anchored database file is required")
	}
	anchoredInfo, err := anchored.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(anchoredInfo, pathInfo) {
		return errors.New("sqlite database path changed while it was being opened")
	}
	return nil
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
	defer func() { logSQLiteError("close throw plan rows", rows.Close()) }()

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
	defer func() { logSQLiteError("close artifact rows", rows.Close()) }()

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

func RecordInstalledPayload(ctx context.Context, db *sql.DB, record commands.InstalledPayloadRecord) (commands.InstalledPayloadRecord, error) {
	if record.Workspace == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload workspace is required")
	}
	if record.Provider == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload provider is required")
	}
	if record.PayloadID == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload id is required")
	}
	if record.Target == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload target is required")
	}
	if record.State == "" {
		record.State = commands.PayloadStateInstalled
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if record.CreatedAt == "" {
		record.CreatedAt = now
	}
	if record.UpdatedAt == "" {
		record.UpdatedAt = record.CreatedAt
	}
	if record.LastSeenAt == "" && record.State != commands.PayloadStateRemoved {
		record.LastSeenAt = record.UpdatedAt
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	defer func() { logSQLiteRollback("rollback installed payload transaction", tx.Rollback()) }()

	existing, found, err := findInstalledPayloadIdentity(ctx, tx, record)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	if found {
		record.ID = existing.ID
		record.Handle = existing.Handle
		record.CreatedAt = existing.CreatedAt
		if record.LastSeenAt == "" {
			record.LastSeenAt = existing.LastSeenAt
		}
	} else {
		if record.ID == "" {
			record.ID = installedPayloadID(record)
		}
		if record.Handle == "" {
			record.Handle, err = nextInstalledPayloadHandle(ctx, tx, record.Workspace)
			if err != nil {
				return commands.InstalledPayloadRecord{}, err
			}
		}
	}
	if err := putInstalledPayload(ctx, tx, record); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	if !found {
		if err := insertInstalledPayloadEvent(ctx, tx, commands.InstalledPayloadEvent{
			ID:        installedPayloadEventID(record, "installed", "", record.State, record.UpdatedAt),
			PayloadID: record.ID,
			Handle:    record.Handle,
			Workspace: record.Workspace,
			Type:      "installed",
			To:        record.State,
			Message:   "installed payload recorded",
			CreatedAt: record.UpdatedAt,
		}); err != nil {
			return commands.InstalledPayloadRecord{}, err
		}
	} else if existing.State != record.State {
		if err := insertInstalledPayloadEvent(ctx, tx, commands.InstalledPayloadEvent{
			ID:        installedPayloadEventID(record, "state_changed", existing.State, record.State, record.UpdatedAt),
			PayloadID: record.ID,
			Handle:    record.Handle,
			Workspace: record.Workspace,
			Type:      "state_changed",
			From:      existing.State,
			To:        record.State,
			Message:   "installed payload state changed",
			CreatedAt: record.UpdatedAt,
		}); err != nil {
			return commands.InstalledPayloadRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return record, nil
}

func ListInstalledPayloads(ctx context.Context, db *sql.DB, workspacePath string, filter commands.InstalledPayloadFilter) ([]commands.InstalledPayloadRecord, error) {
	if workspacePath == "" {
		return nil, errors.New("workspace path is required")
	}
	rows, err := db.QueryContext(ctx, `SELECT record_json FROM installed_payloads WHERE workspace = ? ORDER BY created_at, handle`, workspacePath)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close installed payload rows", rows.Close()) }()
	var records []commands.InstalledPayloadRecord
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var record commands.InstalledPayloadRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			return nil, err
		}
		if !filter.IncludeRemoved && record.State == commands.PayloadStateRemoved {
			continue
		}
		if filter.State != "" && record.State != filter.State {
			continue
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func GetInstalledPayload(ctx context.Context, db *sql.DB, workspacePath, ref string) (commands.InstalledPayloadRecord, error) {
	if workspacePath == "" {
		return commands.InstalledPayloadRecord{}, errors.New("workspace path is required")
	}
	if ref == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload reference is required")
	}
	var data string
	err := db.QueryRowContext(ctx, `
SELECT record_json
FROM installed_payloads
WHERE workspace = ? AND (id = ? OR handle = ?)
LIMIT 1`, workspacePath, ref, ref).Scan(&data)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	var record commands.InstalledPayloadRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return record, nil
}

func UpdateInstalledPayloadState(ctx context.Context, db *sql.DB, workspacePath, ref, state, reason string) (commands.InstalledPayloadRecord, error) {
	if state == "" {
		return commands.InstalledPayloadRecord{}, errors.New("installed payload state is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	defer func() { logSQLiteRollback("rollback payload state transaction", tx.Rollback()) }()

	record, err := getInstalledPayloadTx(ctx, tx, workspacePath, ref)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	from := record.State
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.State = state
	record.UpdatedAt = now
	if state == commands.PayloadStateInstalled || state == commands.PayloadStateConnected {
		record.LastSeenAt = now
	}
	if err := putInstalledPayload(ctx, tx, record); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	if err := insertInstalledPayloadEvent(ctx, tx, commands.InstalledPayloadEvent{
		ID:        installedPayloadEventID(record, "state_changed", from, state, now),
		PayloadID: record.ID,
		Handle:    record.Handle,
		Workspace: record.Workspace,
		Type:      "state_changed",
		From:      from,
		To:        state,
		Reason:    reason,
		Message:   "installed payload state changed",
		CreatedAt: now,
	}); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return record, nil
}

func ListInstalledPayloadEvents(ctx context.Context, db *sql.DB, workspacePath, ref string) ([]commands.InstalledPayloadEvent, error) {
	if workspacePath == "" {
		return nil, errors.New("workspace path is required")
	}
	query := `SELECT event_json FROM installed_payload_events WHERE workspace = ?`
	args := []any{workspacePath}
	if ref != "" {
		query += ` AND (payload_id = ? OR handle = ?)`
		args = append(args, ref, ref)
	}
	query += ` ORDER BY created_at, id`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close installed payload event rows", rows.Close()) }()
	var events []commands.InstalledPayloadEvent
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var evt commands.InstalledPayloadEvent
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			return nil, err
		}
		events = append(events, evt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func findInstalledPayloadIdentity(ctx context.Context, tx *sql.Tx, record commands.InstalledPayloadRecord) (commands.InstalledPayloadRecord, bool, error) {
	switch {
	case record.InstanceKey != "":
		return findInstalledPayloadByColumn(ctx, tx, record, "instance_key", record.InstanceKey)
	case record.StampID != "":
		return findInstalledPayloadByColumn(ctx, tx, record, "stamp_id", record.StampID)
	default:
		return commands.InstalledPayloadRecord{}, false, nil
	}
}

func findInstalledPayloadByColumn(ctx context.Context, tx *sql.Tx, record commands.InstalledPayloadRecord, column, value string) (commands.InstalledPayloadRecord, bool, error) {
	var data string
	query := fmt.Sprintf(`
SELECT record_json
FROM installed_payloads
WHERE workspace = ? AND provider = ? AND payload_id = ? AND target = ? AND %s = ?
LIMIT 1`, column)
	err := tx.QueryRowContext(ctx, query, record.Workspace, record.Provider, record.PayloadID, record.Target, value).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return commands.InstalledPayloadRecord{}, false, nil
	}
	if err != nil {
		return commands.InstalledPayloadRecord{}, false, err
	}
	var existing commands.InstalledPayloadRecord
	if err := json.Unmarshal([]byte(data), &existing); err != nil {
		return commands.InstalledPayloadRecord{}, false, err
	}
	return existing, true, nil
}

func nextInstalledPayloadHandle(ctx context.Context, tx *sql.Tx, workspacePath string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT handle FROM installed_payloads WHERE workspace = ?`, workspacePath)
	if err != nil {
		return "", err
	}
	defer func() { logSQLiteError("close launch key entity rows", rows.Close()) }()
	maxHandle := 0
	for rows.Next() {
		var handle string
		if err := rows.Scan(&handle); err != nil {
			return "", err
		}
		number, err := strconv.Atoi(strings.TrimPrefix(handle, "p"))
		if err == nil && strings.HasPrefix(handle, "p") && number > maxHandle {
			maxHandle = number
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("p%d", maxHandle+1), nil
}

func putInstalledPayload(ctx context.Context, tx *sql.Tx, record commands.InstalledPayloadRecord) error {
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO installed_payloads(
	id,
	workspace,
	handle,
	provider,
	payload_id,
	target,
	state,
	instance_key,
	stamp_id,
	transport,
	endpoint,
	record_json,
	created_at,
	updated_at,
	last_seen_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	workspace = excluded.workspace,
	handle = excluded.handle,
	provider = excluded.provider,
	payload_id = excluded.payload_id,
	target = excluded.target,
	state = excluded.state,
	instance_key = excluded.instance_key,
	stamp_id = excluded.stamp_id,
	transport = excluded.transport,
	endpoint = excluded.endpoint,
	record_json = excluded.record_json,
	updated_at = excluded.updated_at,
	last_seen_at = excluded.last_seen_at`,
		record.ID,
		record.Workspace,
		record.Handle,
		record.Provider,
		record.PayloadID,
		record.Target,
		record.State,
		record.InstanceKey,
		record.StampID,
		record.Transport,
		record.Endpoint,
		string(recordJSON),
		record.CreatedAt,
		record.UpdatedAt,
		record.LastSeenAt,
	)
	return err
}

func getInstalledPayloadTx(ctx context.Context, tx *sql.Tx, workspacePath, ref string) (commands.InstalledPayloadRecord, error) {
	var data string
	err := tx.QueryRowContext(ctx, `
SELECT record_json
FROM installed_payloads
WHERE workspace = ? AND (id = ? OR handle = ?)
LIMIT 1`, workspacePath, ref, ref).Scan(&data)
	if err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	var record commands.InstalledPayloadRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return commands.InstalledPayloadRecord{}, err
	}
	return record, nil
}

func insertInstalledPayloadEvent(ctx context.Context, tx *sql.Tx, evt commands.InstalledPayloadEvent) error {
	if evt.ID == "" {
		return errors.New("installed payload event id is required")
	}
	if evt.CreatedAt == "" {
		evt.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	eventJSON, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO installed_payload_events(
	id,
	payload_id,
	handle,
	workspace,
	type,
	from_state,
	to_state,
	reason,
	message,
	event_json,
	created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
		evt.ID,
		evt.PayloadID,
		evt.Handle,
		evt.Workspace,
		evt.Type,
		evt.From,
		evt.To,
		evt.Reason,
		evt.Message,
		string(eventJSON),
		evt.CreatedAt,
	)
	return err
}

func installedPayloadID(record commands.InstalledPayloadRecord) string {
	identity := strings.Join([]string{
		record.Workspace,
		record.Provider,
		record.PayloadID,
		record.Target,
		record.InstanceKey,
		record.StampID,
		record.Endpoint,
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	return "payload-" + hex.EncodeToString(sum[:12])
}

func installedPayloadEventID(record commands.InstalledPayloadRecord, typ, from, to, at string) string {
	identity := strings.Join([]string{
		record.ID,
		record.Handle,
		typ,
		from,
		to,
		at,
		strconv.FormatInt(time.Now().UnixNano(), 10),
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	return "payload-event-" + hex.EncodeToString(sum[:12])
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
	defer func() { logSQLiteError("close run log rows", rows.Close()) }()
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
