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
	{
		Version: 6,
		Name:    "workspace_pki",
		SQL: `
CREATE TABLE pki_authorities (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	role TEXT NOT NULL,
	state TEXT NOT NULL,
	parent_authority_id TEXT REFERENCES pki_authorities(id) DEFERRABLE INITIALLY DEFERRED,
	active_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id) DEFERRABLE INITIALLY DEFERRED,
	authority_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX pki_authorities_state_idx ON pki_authorities(state);
CREATE INDEX pki_authorities_parent_idx ON pki_authorities(parent_authority_id);

CREATE TABLE pki_generation_counters (
	certificate_id TEXT PRIMARY KEY,
	last_generation INTEGER NOT NULL CHECK (last_generation > 0)
);

CREATE TABLE pki_certificate_generations (
	id TEXT PRIMARY KEY,
	certificate_id TEXT NOT NULL,
	generation INTEGER NOT NULL CHECK (generation > 0),
	owning_authority_id TEXT REFERENCES pki_authorities(id) DEFERRABLE INITIALLY DEFERRED,
	issuer_authority_id TEXT REFERENCES pki_authorities(id) DEFERRABLE INITIALLY DEFERRED,
	issuer_generation_id TEXT REFERENCES pki_certificate_generations(id) DEFERRABLE INITIALLY DEFERRED,
	serial_scope_id TEXT NOT NULL REFERENCES pki_certificate_generations(id) DEFERRABLE INITIALLY DEFERRED,
	serial_number TEXT NOT NULL,
	state TEXT NOT NULL,
	key_id TEXT NOT NULL REFERENCES pki_key_envelopes(key_id) DEFERRABLE INITIALLY DEFERRED,
	fingerprint_sha256 TEXT NOT NULL,
	generation_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE(certificate_id, generation),
	UNIQUE(serial_scope_id, serial_number)
);

CREATE INDEX pki_generations_certificate_idx ON pki_certificate_generations(certificate_id, generation);
CREATE INDEX pki_generations_authority_idx ON pki_certificate_generations(owning_authority_id);
CREATE INDEX pki_generations_issuer_idx ON pki_certificate_generations(issuer_authority_id);
CREATE INDEX pki_generations_state_idx ON pki_certificate_generations(state);

CREATE TABLE pki_key_envelopes (
	key_id TEXT PRIMARY KEY,
	algorithm TEXT NOT NULL,
	schema_version TEXT NOT NULL,
	cipher TEXT NOT NULL,
	key_version TEXT NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE pki_issuance_intents (
	id TEXT PRIMARY KEY,
	idempotency_key TEXT NOT NULL UNIQUE,
	request_sha256 TEXT NOT NULL,
	kind TEXT NOT NULL,
	authority_id TEXT,
	certificate_id TEXT NOT NULL,
	generation_id TEXT NOT NULL,
	source_generation_id TEXT,
	generation INTEGER NOT NULL CHECK (generation > 0),
	key_id TEXT NOT NULL,
	issuer_authority_id TEXT,
	issuer_generation_id TEXT,
	subject_backend_id TEXT NOT NULL,
	subject_backend_version TEXT NOT NULL,
	subject_package_digest TEXT NOT NULL,
	subject_capability_hash TEXT NOT NULL,
	signing_backend_id TEXT NOT NULL,
	signing_backend_version TEXT NOT NULL,
	signing_package_digest TEXT NOT NULL,
	signing_capability_hash TEXT NOT NULL,
	profile_id TEXT NOT NULL,
	compatibility_target_id TEXT NOT NULL,
	compatibility_version TEXT NOT NULL,
	purpose TEXT NOT NULL,
	export_policy TEXT NOT NULL,
	key_establishment_policy TEXT NOT NULL,
	tls_named_groups_json BLOB NOT NULL,
	chain_generation_ids_json BLOB NOT NULL,
	authority_plan_json BLOB NOT NULL,
	status TEXT NOT NULL,
	owner_token TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	lease_expires_at TEXT NOT NULL,
	result_generation_id TEXT,
	failure TEXT,
	intent_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX pki_issuance_intents_status_idx ON pki_issuance_intents(status, lease_expires_at, updated_at);
CREATE INDEX pki_issuance_intents_certificate_idx ON pki_issuance_intents(certificate_id, generation);

CREATE TABLE pki_audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT UNIQUE,
	action TEXT NOT NULL,
	outcome TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	operation_id TEXT NOT NULL,
	correlation_id TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	details_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX pki_audit_events_resource_idx ON pki_audit_events(resource_type, resource_id, id);
CREATE INDEX pki_audit_events_created_at_idx ON pki_audit_events(created_at);
`,
	},
	{
		Version: 7,
		Name:    "workspace_pki_assignments",
		SQL: `
CREATE TABLE pki_trust_sets (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	active_generation_id TEXT REFERENCES pki_trust_set_generations(id) DEFERRABLE INITIALLY DEFERRED,
	staged_generation_id TEXT REFERENCES pki_trust_set_generations(id) DEFERRABLE INITIALLY DEFERRED,
	state TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	trust_set_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX pki_trust_sets_state_idx ON pki_trust_sets(state);

CREATE TABLE pki_trust_set_generations (
	id TEXT PRIMARY KEY,
	trust_set_id TEXT NOT NULL REFERENCES pki_trust_sets(id) DEFERRABLE INITIALLY DEFERRED,
	generation INTEGER NOT NULL CHECK (generation > 0),
	generation_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE(trust_set_id, generation)
);

CREATE INDEX pki_trust_set_generations_set_idx ON pki_trust_set_generations(trust_set_id, generation);

CREATE TABLE pki_trust_set_members (
	trust_set_generation_id TEXT NOT NULL REFERENCES pki_trust_set_generations(id) ON DELETE RESTRICT,
	member_type TEXT NOT NULL CHECK (member_type IN ('anchor', 'intermediate', 'crl')),
	member_id TEXT NOT NULL,
	position INTEGER NOT NULL CHECK (position >= 0),
	PRIMARY KEY(trust_set_generation_id, member_type, member_id),
	UNIQUE(trust_set_generation_id, member_type, position)
);

CREATE INDEX pki_trust_set_members_member_idx ON pki_trust_set_members(member_type, member_id);

CREATE TABLE pki_assignments (
	id TEXT PRIMARY KEY,
	purpose TEXT NOT NULL,
	consumer_type TEXT NOT NULL,
	consumer_id TEXT NOT NULL,
	profile_id TEXT NOT NULL,
	active_generation_id TEXT REFERENCES pki_certificate_generations(id) DEFERRABLE INITIALLY DEFERRED,
	staged_generation_id TEXT REFERENCES pki_certificate_generations(id) DEFERRABLE INITIALLY DEFERRED,
	trust_set_id TEXT REFERENCES pki_trust_sets(id) DEFERRABLE INITIALLY DEFERRED,
	active_trust_generation_id TEXT REFERENCES pki_trust_set_generations(id) DEFERRABLE INITIALLY DEFERRED,
	staged_trust_generation_id TEXT REFERENCES pki_trust_set_generations(id) DEFERRABLE INITIALLY DEFERRED,
	rotation_policy_id TEXT,
	state TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	assignment_json TEXT NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX pki_assignments_consumer_idx ON pki_assignments(consumer_type, consumer_id);
CREATE UNIQUE INDEX pki_assignments_live_consumer_purpose_idx
	ON pki_assignments(consumer_type, consumer_id, purpose)
	WHERE state <> 'retired';
CREATE INDEX pki_assignments_active_generation_idx ON pki_assignments(active_generation_id);
CREATE INDEX pki_assignments_staged_generation_idx ON pki_assignments(staged_generation_id);
CREATE INDEX pki_assignments_trust_set_idx ON pki_assignments(trust_set_id);
CREATE INDEX pki_assignments_state_idx ON pki_assignments(state);
`,
	},
	{
		Version: 8,
		Name:    "workspace_pki_mutations",
		SQL: `
CREATE TABLE pki_mutations (
	id TEXT PRIMARY KEY,
	idempotency_key TEXT NOT NULL UNIQUE,
	request_sha256 TEXT NOT NULL,
	kind TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	result_json BLOB NOT NULL,
	mutation_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX pki_mutations_resource_idx ON pki_mutations(resource_type, resource_id, created_at);
CREATE INDEX pki_mutations_kind_idx ON pki_mutations(kind, created_at);
`,
	},
	{
		Version: 9,
		Name:    "workspace_pki_revocations",
		SQL: `
CREATE TABLE pki_revocations (
	id TEXT PRIMARY KEY,
	certificate_id TEXT NOT NULL,
	generation_id TEXT NOT NULL UNIQUE REFERENCES pki_certificate_generations(id),
	issuer_authority_id TEXT NOT NULL REFERENCES pki_authorities(id),
	issuer_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id),
	serial_number TEXT NOT NULL,
	reason TEXT NOT NULL,
	previous_state TEXT NOT NULL,
	effective_at TEXT NOT NULL,
	recorded_at TEXT NOT NULL,
	revocation_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL
);

CREATE INDEX pki_revocations_authority_idx
	ON pki_revocations(issuer_authority_id, recorded_at, id);
CREATE INDEX pki_revocations_issuer_generation_idx
	ON pki_revocations(issuer_generation_id, recorded_at, id);
	`,
	},
	{
		Version: 10,
		Name:    "workspace_pki_crls",
		SQL: `
CREATE TABLE pki_crl_counters (
	authority_id TEXT PRIMARY KEY REFERENCES pki_authorities(id),
	last_number INTEGER NOT NULL CHECK (last_number > 0)
);

CREATE TABLE pki_crl_publication_intents (
	id TEXT PRIMARY KEY,
	idempotency_key TEXT NOT NULL UNIQUE,
	request_sha256 TEXT NOT NULL,
	crl_generation_id TEXT NOT NULL UNIQUE,
	authority_id TEXT NOT NULL REFERENCES pki_authorities(id),
	issuer_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id),
	number INTEGER NOT NULL CHECK (number > 0),
	this_update TEXT NOT NULL,
	next_update TEXT NOT NULL,
	signing_backend_id TEXT NOT NULL,
	signing_backend_version TEXT NOT NULL,
	signing_backend_package_digest TEXT NOT NULL,
	signing_backend_capability_hash TEXT NOT NULL,
	signature_algorithm TEXT NOT NULL,
	status TEXT NOT NULL,
	phase TEXT NOT NULL,
	owner_token TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	lease_expires_at TEXT NOT NULL,
	result_crl_generation_id TEXT REFERENCES pki_crl_generations(id) DEFERRABLE INITIALLY DEFERRED,
	signed_fingerprint_sha256 TEXT,
	signed_signature_algorithm TEXT,
	signed_provider_operation_ref TEXT,
	signed_crl_der BLOB,
	signed_at TEXT,
	failure TEXT,
	intent_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(authority_id, number)
);

CREATE INDEX pki_crl_publication_authority_idx
	ON pki_crl_publication_intents(authority_id, number, id);
CREATE INDEX pki_crl_publication_status_idx
	ON pki_crl_publication_intents(status, lease_expires_at, id);

CREATE TABLE pki_crl_generations (
	id TEXT PRIMARY KEY,
	authority_id TEXT NOT NULL REFERENCES pki_authorities(id),
	issuer_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id),
	number INTEGER NOT NULL CHECK (number > 0),
	this_update TEXT NOT NULL,
	next_update TEXT NOT NULL,
	signature_algorithm TEXT NOT NULL,
	fingerprint_sha256 TEXT NOT NULL,
	generation_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE(authority_id, number)
);

CREATE INDEX pki_crl_generations_authority_idx
	ON pki_crl_generations(authority_id, number, id);
CREATE INDEX pki_crl_generations_issuer_idx
	ON pki_crl_generations(issuer_generation_id, number, id);
`,
	},
	{
		Version: 11,
		Name:    "workspace_pki_operations",
		SQL: `
CREATE TABLE pki_operations (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	previous_authority_id TEXT NOT NULL REFERENCES pki_authorities(id),
	previous_authority_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id),
	replacement_authority_id TEXT NOT NULL REFERENCES pki_authorities(id),
	replacement_authority_generation_id TEXT NOT NULL REFERENCES pki_certificate_generations(id),
	trust_set_id TEXT NOT NULL REFERENCES pki_trust_sets(id),
	overlap_trust_generation_id TEXT NOT NULL REFERENCES pki_trust_set_generations(id),
	final_trust_generation_id TEXT REFERENCES pki_trust_set_generations(id),
	consumer_tracking TEXT NOT NULL,
	phase TEXT NOT NULL,
	operation_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	completed_at TEXT,
	failure TEXT
);

CREATE INDEX pki_operations_live_resources_idx
	ON pki_operations(status, trust_set_id, previous_authority_id, replacement_authority_id)
	WHERE kind = 'authority-rollover' AND status NOT IN ('completed', 'failed', 'canceled');
CREATE INDEX pki_operations_status_idx ON pki_operations(status, updated_at, id);

CREATE TABLE pki_operation_required_assignments (
	operation_id TEXT NOT NULL REFERENCES pki_operations(id) ON DELETE RESTRICT,
	assignment_id TEXT NOT NULL REFERENCES pki_assignments(id) ON DELETE RESTRICT,
	position INTEGER NOT NULL CHECK (position >= 0),
	PRIMARY KEY(operation_id, assignment_id),
	UNIQUE(operation_id, position)
);

CREATE INDEX pki_operation_required_assignment_idx
	ON pki_operation_required_assignments(assignment_id, operation_id);

CREATE TABLE pki_consumer_acknowledgements (
	id TEXT PRIMARY KEY,
	operation_id TEXT NOT NULL REFERENCES pki_operations(id) ON DELETE RESTRICT,
	assignment_id TEXT NOT NULL REFERENCES pki_assignments(id) ON DELETE RESTRICT,
	consumer_type TEXT NOT NULL,
	consumer_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	trust_set_generation_id TEXT NOT NULL REFERENCES pki_trust_set_generations(id),
	evidence_ref TEXT,
	acknowledgement_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	acknowledged_at TEXT NOT NULL,
	UNIQUE(operation_id, assignment_id, kind, trust_set_generation_id)
);

CREATE INDEX pki_consumer_acknowledgements_operation_idx
	ON pki_consumer_acknowledgements(operation_id, acknowledged_at, id);
`,
	},
	{
		Version: 12,
		Name:    "workspace_pki_credential_stamps",
		SQL: `
CREATE TABLE pki_credential_stamps (
	id TEXT PRIMARY KEY,
	assignment_id TEXT NOT NULL REFERENCES pki_assignments(id) ON DELETE RESTRICT,
	provider_id TEXT NOT NULL,
	capability TEXT NOT NULL,
	slot_name TEXT NOT NULL,
	status TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	input_artifact_id TEXT NOT NULL,
	input_sha256 TEXT NOT NULL,
	output_artifact_id TEXT,
	output_sha256 TEXT,
	descriptor_sha256 TEXT NOT NULL,
	superseded_by TEXT REFERENCES pki_credential_stamps(id) DEFERRABLE INITIALLY DEFERRED,
	stamp_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	created_at_sort TEXT NOT NULL,
	updated_at_sort TEXT NOT NULL
);

CREATE INDEX pki_credential_stamps_assignment_idx
	ON pki_credential_stamps(assignment_id, created_at_sort, id);
CREATE INDEX pki_credential_stamps_created_idx
	ON pki_credential_stamps(created_at_sort, id);
CREATE INDEX pki_credential_stamps_provider_idx
	ON pki_credential_stamps(provider_id, status, updated_at_sort, id);
CREATE INDEX pki_credential_stamps_output_idx
	ON pki_credential_stamps(output_artifact_id)
	WHERE output_artifact_id IS NOT NULL;
`,
	},
	{
		Version: 13,
		Name:    "workspace_pki_credential_executions",
		SQL: `
CREATE TABLE pki_credential_executions (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	provider_module_id TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	descriptor_sha256 TEXT NOT NULL,
	assignment_id TEXT REFERENCES pki_assignments(id) ON DELETE RESTRICT,
	status TEXT NOT NULL,
	revision INTEGER NOT NULL CHECK (revision > 0),
	execution_json BLOB NOT NULL,
	metadata_schema_version TEXT NOT NULL,
	metadata_algorithm TEXT NOT NULL,
	metadata_key_version TEXT NOT NULL,
	metadata_tag BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	created_at_sort TEXT NOT NULL,
	updated_at_sort TEXT NOT NULL
);

CREATE INDEX pki_credential_executions_created_idx
	ON pki_credential_executions(created_at_sort, id);
CREATE INDEX pki_credential_executions_provider_idx
	ON pki_credential_executions(provider_id, status, updated_at_sort, id);
CREATE INDEX pki_credential_executions_assignment_idx
	ON pki_credential_executions(assignment_id, created_at_sort, id)
	WHERE assignment_id IS NOT NULL;
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
	defer func() { logSQLiteRollback("rollback migration transaction", tx.Rollback()) }()

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
	defer func() { logSQLiteError("close applied migrations rows", rows.Close()) }()

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
