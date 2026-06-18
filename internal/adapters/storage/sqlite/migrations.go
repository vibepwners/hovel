package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const DatabaseFile = "workspace.db"

type Migration struct {
	Version int
	Name    string
	SQL     string
}

var Migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_workspace_state",
		SQL: `
CREATE TABLE operator_sessions (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	state_json TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE throw_plans (
	id TEXT PRIMARY KEY,
	workspace TEXT NOT NULL,
	chain TEXT NOT NULL,
	confirmation_id TEXT NOT NULL,
	targets_json TEXT NOT NULL,
	review TEXT NOT NULL,
	intent TEXT NOT NULL,
	plan_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX throw_plans_chain_idx ON throw_plans(chain);
CREATE INDEX throw_plans_created_at_idx ON throw_plans(created_at);
`,
	},
	{
		Version: 2,
		Name:    "throw_confirmations",
		SQL: `
CREATE TABLE throw_confirmations (
	id TEXT PRIMARY KEY,
	workspace TEXT NOT NULL,
	plan_id TEXT NOT NULL,
	plan_hash TEXT NOT NULL,
	client_id TEXT NOT NULL,
	method TEXT NOT NULL,
	confirmed_at TEXT NOT NULL,
	confirmation_json TEXT NOT NULL
);

CREATE INDEX throw_confirmations_plan_hash_idx ON throw_confirmations(plan_hash);
CREATE INDEX throw_confirmations_confirmed_at_idx ON throw_confirmations(confirmed_at);
`,
	},
	{
		Version: 3,
		Name:    "throws_and_artifacts",
		SQL: `
CREATE TABLE throw_records (
	id TEXT PRIMARY KEY,
	workspace TEXT NOT NULL,
	plan_id TEXT NOT NULL,
	plan_hash TEXT NOT NULL,
	chain TEXT NOT NULL,
	targets_json TEXT NOT NULL,
	state TEXT NOT NULL,
	throw_json TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT NOT NULL
);

CREATE INDEX throw_records_plan_hash_idx ON throw_records(plan_hash);
CREATE INDEX throw_records_started_at_idx ON throw_records(started_at);

CREATE TABLE artifacts (
	id TEXT PRIMARY KEY,
	workspace TEXT NOT NULL,
	throw_id TEXT NOT NULL,
	run_id TEXT NOT NULL,
	module_id TEXT NOT NULL,
	target TEXT NOT NULL,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	path TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	size INTEGER NOT NULL,
	artifact_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX artifacts_throw_id_idx ON artifacts(throw_id);
CREATE INDEX artifacts_run_id_idx ON artifacts(run_id);
`,
	},
	{
		Version: 4,
		Name:    "structured_events",
		SQL: `
CREATE TABLE events (
	id TEXT PRIMARY KEY,
	schema_version TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	level TEXT NOT NULL,
	type TEXT NOT NULL,
	message TEXT NOT NULL,
	workspace TEXT NOT NULL,
	operation TEXT NOT NULL,
	chain TEXT NOT NULL,
	throw_id TEXT NOT NULL,
	run_id TEXT NOT NULL,
	module_id TEXT NOT NULL,
	target TEXT NOT NULL,
	topic TEXT NOT NULL,
	fields_json TEXT NOT NULL,
	event_json TEXT NOT NULL
);

CREATE INDEX events_throw_id_idx ON events(throw_id);
CREATE INDEX events_run_id_idx ON events(run_id);
CREATE INDEX events_type_idx ON events(type);
CREATE INDEX events_topic_idx ON events(topic);
CREATE INDEX events_timestamp_idx ON events(timestamp);
`,
	},
	{
		Version: 5,
		Name:    "installed_payload_inventory",
		SQL: `
CREATE TABLE installed_payloads (
	id TEXT PRIMARY KEY,
	workspace TEXT NOT NULL,
	handle TEXT NOT NULL,
	provider TEXT NOT NULL,
	payload_id TEXT NOT NULL,
	target TEXT NOT NULL,
	state TEXT NOT NULL,
	instance_key TEXT NOT NULL,
	stamp_id TEXT NOT NULL,
	transport TEXT NOT NULL,
	endpoint TEXT NOT NULL,
	record_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	last_seen_at TEXT NOT NULL
);

CREATE UNIQUE INDEX installed_payloads_workspace_handle_idx ON installed_payloads(workspace, handle);
CREATE INDEX installed_payloads_workspace_state_idx ON installed_payloads(workspace, state);
CREATE INDEX installed_payloads_provider_payload_idx ON installed_payloads(provider, payload_id);
CREATE INDEX installed_payloads_instance_idx ON installed_payloads(workspace, provider, payload_id, target, instance_key);
CREATE INDEX installed_payloads_stamp_idx ON installed_payloads(workspace, provider, payload_id, target, stamp_id);

CREATE TABLE installed_payload_events (
	id TEXT PRIMARY KEY,
	payload_id TEXT NOT NULL,
	handle TEXT NOT NULL,
	workspace TEXT NOT NULL,
	type TEXT NOT NULL,
	from_state TEXT NOT NULL,
	to_state TEXT NOT NULL,
	reason TEXT NOT NULL,
	message TEXT NOT NULL,
	event_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX installed_payload_events_payload_idx ON installed_payload_events(workspace, payload_id, created_at);
CREATE INDEX installed_payload_events_handle_idx ON installed_payload_events(workspace, handle, created_at);
`,
	},
}

func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	return Apply(ctx, db, Migrations)
}

func Apply(ctx context.Context, db *sql.DB, migrations []Migration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if db == nil {
		return errors.New("sqlite database is required")
	}
	migrations = append([]Migration(nil), migrations...)
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	if err := validateMigrations(migrations); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	checksum TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`); err != nil {
		return err
	}

	applied, err := appliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	known := map[int]Migration{}
	for _, migration := range migrations {
		known[migration.Version] = migration
	}
	for version, record := range applied {
		migration, ok := known[version]
		if !ok {
			return fmt.Errorf("workspace database has unsupported migration version %d", version)
		}
		if record.Name != migration.Name {
			return fmt.Errorf("workspace database migration %d name = %q, want %q", version, record.Name, migration.Name)
		}
		if record.Checksum != migration.Checksum() {
			return fmt.Errorf("workspace database migration %d checksum mismatch", version)
		}
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.Version]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply migration %d %s: %w", migration.Version, migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO schema_migrations(version, name, checksum, applied_at)
VALUES (?, ?, ?, ?)`,
			migration.Version,
			migration.Name,
			migration.Checksum(),
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func validateMigrations(migrations []Migration) error {
	for index, migration := range migrations {
		if migration.Version != index+1 {
			return fmt.Errorf("migration versions must be contiguous starting at 1; got %d at position %d", migration.Version, index)
		}
		if strings.TrimSpace(migration.Name) == "" {
			return fmt.Errorf("migration %d name is required", migration.Version)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			return fmt.Errorf("migration %d SQL is required", migration.Version)
		}
	}
	return nil
}

type migrationRecord struct {
	Name     string
	Checksum string
}

func appliedMigrations(ctx context.Context, tx *sql.Tx) (map[int]migrationRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := map[int]migrationRecord{}
	for rows.Next() {
		var version int
		var record migrationRecord
		if err := rows.Scan(&version, &record.Name, &record.Checksum); err != nil {
			return nil, err
		}
		applied[version] = record
	}
	return applied, rows.Err()
}

func (m Migration) Checksum() string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(m.SQL)))
	return hex.EncodeToString(sum[:])
}
