package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	trustMemberAnchor       = "anchor"
	trustMemberIntermediate = "intermediate"
	trustMemberCRL          = "crl"
)

const assignmentSelect = `
SELECT id, purpose, consumer_type, consumer_id, profile_id, active_generation_id,
	staged_generation_id, trust_set_id, active_trust_generation_id,
	staged_trust_generation_id, rotation_policy_id, state, revision,
	assignment_json, metadata_schema_version, metadata_algorithm, metadata_key_version,
	metadata_tag, updated_at
FROM pki_assignments`

const trustSetSelect = `
SELECT id, name, active_generation_id, staged_generation_id, state, revision,
	trust_set_json, metadata_schema_version, metadata_algorithm, metadata_key_version,
	metadata_tag, created_at, updated_at
FROM pki_trust_sets`

const trustSetGenerationSelect = `
SELECT generation_row.id, generation_row.trust_set_id, generation_row.generation,
	generation_row.generation_json, generation_row.metadata_schema_version,
	generation_row.metadata_algorithm, generation_row.metadata_key_version,
	generation_row.metadata_tag, generation_row.created_at,
	COALESCE((SELECT group_concat(member_id, ',') FROM (
		SELECT member_id FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'anchor'
		ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(member_id, ',') FROM (
		SELECT member_id FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'intermediate'
		ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(member_id, ',') FROM (
		SELECT member_id FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'crl'
		ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(position, ',') FROM (
		SELECT position FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'anchor'
		ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(position, ',') FROM (
		SELECT position FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'intermediate'
		ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(position, ',') FROM (
		SELECT position FROM pki_trust_set_members
		WHERE trust_set_generation_id = generation_row.id AND member_type = 'crl'
		ORDER BY position
	)), '')
FROM pki_trust_set_generations AS generation_row`

const mutationSelect = `
SELECT id, idempotency_key, request_sha256, kind, resource_type, resource_id,
	result_json, mutation_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at
FROM pki_mutations`

func (s PKIStore) MutationByKey(ctx context.Context, key string) (apppki.MutationRecord, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.MutationRecord, error) {
		if key == "" {
			return apppki.MutationRecord{}, errors.New("pki sqlite: mutation idempotency key is required")
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return apppki.MutationRecord{}, err
		}
		return s.loadMutation(ctx, db.QueryRowContext(ctx, mutationSelect+` WHERE idempotency_key = ?`, key))
	})
}

func (s PKIStore) CreateAssignment(ctx context.Context, assignment domainpki.Assignment, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := assignment.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, assignment.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, assignment.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, assignment)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki assignment creation", tx.Rollback()) }()
		operation, reserved, err := s.liveAuthorityRolloverForTrustSetTx(ctx, tx, assignment.TrustSetID)
		if err != nil {
			return err
		}
		if reserved {
			return apppki.RejectRolloverReservedMutation(
				operation, apppki.RolloverReservationAssignmentBind,
			)
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if err := insertAssignment(ctx, tx, assignment, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func sameAssignmentBinding(left, right domainpki.Assignment) bool {
	return left.ID == right.ID && left.Purpose == right.Purpose &&
		left.ConsumerType == right.ConsumerType && left.ConsumerID == right.ConsumerID &&
		left.ProfileID == right.ProfileID && left.TrustSetID == right.TrustSetID &&
		left.RotationPolicyID == right.RotationPolicyID
}

func (s PKIStore) Assignment(ctx context.Context, id domainpki.AssignmentID) (domainpki.Assignment, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.Assignment, error) {
		if err := id.Validate(); err != nil {
			return domainpki.Assignment{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.Assignment{}, err
		}
		return s.loadAssignment(ctx, db.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) Assignments(ctx context.Context) ([]domainpki.Assignment, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.Assignment, error) {
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, assignmentSelect+` ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki assignment rows", rows.Close()) }()
		result := make([]domainpki.Assignment, 0)
		for rows.Next() {
			assignment, err := s.loadAssignment(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, assignment)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) UpdateAssignment(ctx context.Context, expectedRevision uint64, assignment domainpki.Assignment, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedRevision, assignment.Revision); err != nil {
			return err
		}
		if err := assignment.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, assignment.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, assignment.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, assignment)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki assignment update", tx.Rollback()) }()
		existing, err := s.loadAssignment(ctx, tx.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, assignment.ID))
		if err != nil {
			return err
		}
		if !sameAssignmentBinding(existing, assignment) {
			return errors.New("pki sqlite: assignment binding is immutable")
		}
		operation, reserved, err := s.liveAuthorityRolloverForTrustSetTx(ctx, tx, assignment.TrustSetID)
		if err != nil {
			return err
		}
		if reserved {
			var generation domainpki.CertificateGeneration
			var action apppki.RolloverReservationAction
			switch mutation.Kind {
			case apppki.MutationAssignmentStage:
				action = apppki.RolloverReservationAssignmentStage
				generation, err = s.loadGeneration(ctx, tx.QueryRowContext(
					ctx, generationSelect+` WHERE id = ?`, assignment.StagedGenerationID,
				))
			case apppki.MutationAssignmentActivate:
				action = apppki.RolloverReservationAssignmentActivate
				generation, err = s.loadGeneration(ctx, tx.QueryRowContext(
					ctx, generationSelect+` WHERE id = ?`, assignment.ActiveGenerationID,
				))
			default:
				return apppki.RejectRolloverReservedMutation(
					operation, apppki.RolloverReservationAssignmentUnbind,
				)
			}
			if err != nil {
				return err
			}
			if err := apppki.ValidateRolloverAssignmentReservation(
				operation, action, existing, assignment, generation,
			); err != nil {
				return err
			}
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if err := updateAssignmentTx(ctx, tx, expectedRevision, assignment, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func updateAssignmentTx(
	ctx context.Context,
	tx *sql.Tx,
	expectedRevision uint64,
	assignment domainpki.Assignment,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	result, err := tx.ExecContext(ctx, `
UPDATE pki_assignments SET
	purpose = ?, consumer_type = ?, consumer_id = ?, profile_id = ?, active_generation_id = ?,
	staged_generation_id = ?, trust_set_id = ?, active_trust_generation_id = ?,
	staged_trust_generation_id = ?, rotation_policy_id = ?, state = ?, revision = ?,
	assignment_json = ?, metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?,
	metadata_tag = ?, updated_at = ?
WHERE id = ? AND revision = ?`, assignment.Purpose, assignment.ConsumerType, assignment.ConsumerID,
		assignment.ProfileID, nullableString(string(assignment.ActiveGenerationID)), nullableString(string(assignment.StagedGenerationID)),
		nullableString(string(assignment.TrustSetID)), nullableString(string(assignment.ActiveTrustGenerationID)),
		nullableString(string(assignment.StagedTrustGenerationID)), nullableString(string(assignment.RotationPolicyID)), assignment.State,
		assignment.Revision, encoded, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		assignment.UpdatedAt.Format(time.RFC3339Nano), assignment.ID, expectedRevision)
	if err != nil {
		return fmt.Errorf("pki sqlite: update assignment: %w", err)
	}
	return requireAssignmentCASRow(ctx, tx, result, assignment.ID)
}

func (s PKIStore) CreateTrustSet(ctx context.Context, trustSet domainpki.TrustSet, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := trustSet.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, trustSet.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, trustSet)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki trust set creation", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if err := insertTrustSet(ctx, tx, trustSet, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) TrustSet(ctx context.Context, id domainpki.TrustSetID) (domainpki.TrustSet, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.TrustSet, error) {
		if err := id.Validate(); err != nil {
			return domainpki.TrustSet{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.TrustSet{}, err
		}
		return s.loadTrustSet(ctx, db.QueryRowContext(ctx, trustSetSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) TrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.TrustSet, error) {
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, trustSetSelect+` ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki trust set rows", rows.Close()) }()
		result := make([]domainpki.TrustSet, 0)
		for rows.Next() {
			trustSet, err := s.loadTrustSet(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, trustSet)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) TrustSetGeneration(ctx context.Context, id domainpki.TrustSetGenerationID) (domainpki.TrustSetGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.TrustSetGeneration, error) {
		if err := id.Validate(); err != nil {
			return domainpki.TrustSetGeneration{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.TrustSetGeneration{}, err
		}
		return s.loadTrustSetGeneration(ctx, db.QueryRowContext(ctx, trustSetGenerationSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) TrustSetGenerations(ctx context.Context, id domainpki.TrustSetID) ([]domainpki.TrustSetGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.TrustSetGeneration, error) {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		var exists int
		if err := db.QueryRowContext(ctx, `SELECT 1 FROM pki_trust_sets WHERE id = ?`, id).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, apppki.ErrNotFound
			}
			return nil, err
		}
		rows, err := db.QueryContext(ctx, trustSetGenerationSelect+` WHERE trust_set_id = ? ORDER BY generation`, id)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki trust set generation rows", rows.Close()) }()
		result := make([]domainpki.TrustSetGeneration, 0)
		for rows.Next() {
			generation, err := s.loadTrustSetGeneration(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, generation)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) StageTrustSetGeneration(ctx context.Context, expectedRevision uint64, trustSet domainpki.TrustSet, generation domainpki.TrustSetGeneration, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedRevision, trustSet.Revision); err != nil {
			return err
		}
		if err := trustSet.Validate(); err != nil {
			return err
		}
		if err := generation.Validate(); err != nil {
			return err
		}
		if generation.TrustSetID != trustSet.ID || trustSet.StagedGenerationID != generation.ID {
			return errors.New("pki sqlite: staged trust generation does not match its trust set")
		}
		if err := validatePersistenceAudit(audit, trustSet.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
			return err
		}
		trustJSON, trustMetadata, err := s.authenticateJSON(ctx, trustSet)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		generationJSON, generationMetadata, err := s.authenticateJSON(ctx, generation)
		if err != nil {
			return err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki trust generation stage", tx.Rollback()) }()
		existing, err := s.loadTrustSet(ctx, tx.QueryRowContext(
			ctx, trustSetSelect+` WHERE id = ?`, trustSet.ID,
		))
		if err != nil {
			return err
		}
		operation, reserved, err := s.liveAuthorityRolloverForTrustSetTx(ctx, tx, trustSet.ID)
		if err != nil {
			return err
		}
		if reserved {
			if err := apppki.ValidateRolloverTrustSetReservation(
				operation, apppki.RolloverReservationTrustSetStage, existing, trustSet, generation,
			); err != nil {
				return err
			}
			rollover := operation.AuthorityRollover
			previous, err := s.loadAuthority(ctx, tx.QueryRowContext(
				ctx, authoritySelect+` WHERE id = ?`, rollover.PreviousAuthorityID,
			))
			if err != nil {
				return err
			}
			replacement, err := s.loadAuthority(ctx, tx.QueryRowContext(
				ctx, authoritySelect+` WHERE id = ?`, rollover.ReplacementAuthorityID,
			))
			if err != nil {
				return err
			}
			if err := s.validateRolloverTrustMaterial(
				ctx, tx, generation, previous, replacement,
				domainpki.AuthorityRolloverTransitionComplete, mutation.CreatedAt,
			); err != nil {
				return apppki.NewRolloverPreconditionError(
					apppki.RolloverPreconditionTrustLayoutInvalid, err.Error(),
				)
			}
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		result, err := updateTrustSetCAS(ctx, tx, expectedRevision, trustSet, trustJSON, trustMetadata)
		if err != nil {
			return err
		}
		if err := requireTrustSetCASRow(ctx, tx, result, trustSet.ID); err != nil {
			return err
		}
		if err := insertTrustSetGeneration(ctx, tx, generation, generationJSON, generationMetadata); err != nil {
			return err
		}
		if err := insertTrustSetMembers(ctx, tx, generation); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) UpdateTrustSet(ctx context.Context, expectedRevision uint64, trustSet domainpki.TrustSet, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedRevision, trustSet.Revision); err != nil {
			return err
		}
		if err := trustSet.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, trustSet.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, trustSet)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki trust set update", tx.Rollback()) }()
		operation, reserved, err := s.liveAuthorityRolloverForTrustSetTx(ctx, tx, trustSet.ID)
		if err != nil {
			return err
		}
		if reserved {
			return apppki.RejectRolloverReservedMutation(
				operation, apppki.RolloverReservationTrustSetActivate,
			)
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		result, err := updateTrustSetCAS(ctx, tx, expectedRevision, trustSet, encoded, metadata)
		if err != nil {
			return err
		}
		if err := requireTrustSetCASRow(ctx, tx, result, trustSet.ID); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) authenticateJSON(ctx context.Context, value any) ([]byte, apppki.ProtectedMetadata, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: encode authenticated metadata: %w", err)
	}
	metadata, err := s.protector.AuthenticateMetadata(ctx, encoded)
	if err != nil {
		return nil, apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: authenticate metadata: %w", err)
	}
	return encoded, metadata, nil
}

type authenticatedMetadataRecord struct {
	id        string
	encoded   []byte
	protected apppki.ProtectedMetadata
}

func loadAuthenticatedMetadataRows(rows *sql.Rows) ([]authenticatedMetadataRecord, error) {
	records := make([]authenticatedMetadataRecord, 0)
	for rows.Next() {
		var record authenticatedMetadataRecord
		if err := rows.Scan(&record.id, &record.encoded, &record.protected.SchemaVersion,
			&record.protected.Algorithm, &record.protected.KeyVersion, &record.protected.Tag); err != nil {
			return nil, errors.Join(err, rows.Close())
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(err, rows.Close())
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s PKIStore) reauthenticateAssignmentMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, assignment_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_assignments ORDER BY id`)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.loadAssignment(ctx, tx.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate assignment %q before rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "assignment")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_assignments
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update assignment %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}

func (s PKIStore) reauthenticateTrustSetMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, trust_set_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_trust_sets ORDER BY id`)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.loadTrustSet(ctx, tx.QueryRowContext(ctx, trustSetSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate trust set %q before rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "trust set")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_trust_sets
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update trust set %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}

func (s PKIStore) reauthenticateTrustSetGenerationMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, generation_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_trust_set_generations ORDER BY id`)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.loadTrustSetGeneration(ctx, tx.QueryRowContext(ctx, trustSetGenerationSelect+` WHERE generation_row.id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate trust set generation %q before rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "trust set generation")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_trust_set_generations
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update trust set generation %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}

func (s PKIStore) reauthenticateMutationMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, mutation_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_mutations ORDER BY id`)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.loadMutation(ctx, tx.QueryRowContext(ctx, mutationSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate mutation %q before rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "mutation")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_mutations
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm,
			reauthenticated.KeyVersion, reauthenticated.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update mutation %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}

func (s PKIStore) reauthenticateMetadataRecord(ctx context.Context, record authenticatedMetadataRecord, targetVersion, resource string) (apppki.ProtectedMetadata, error) {
	if err := s.protector.VerifyMetadata(ctx, record.encoded, record.protected); err != nil {
		return apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: verify %s %q metadata for rewrap: %w", resource, record.id, err)
	}
	reauthenticated, err := s.protector.AuthenticateMetadataWithVersion(ctx, record.encoded, targetVersion)
	if err != nil {
		return apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: authenticate %s %q metadata for rewrap: %w", resource, record.id, err)
	}
	return reauthenticated, nil
}

func insertAssignment(ctx context.Context, tx *sql.Tx, assignment domainpki.Assignment, encoded []byte, metadata apppki.ProtectedMetadata) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_assignments(
	id, purpose, consumer_type, consumer_id, profile_id, active_generation_id, staged_generation_id,
	trust_set_id, active_trust_generation_id, staged_trust_generation_id, rotation_policy_id,
	state, revision, assignment_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, assignment.ID, assignment.Purpose,
		assignment.ConsumerType, assignment.ConsumerID, assignment.ProfileID,
		nullableString(string(assignment.ActiveGenerationID)), nullableString(string(assignment.StagedGenerationID)),
		nullableString(string(assignment.TrustSetID)), nullableString(string(assignment.ActiveTrustGenerationID)),
		nullableString(string(assignment.StagedTrustGenerationID)), nullableString(string(assignment.RotationPolicyID)),
		assignment.State, assignment.Revision, encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, assignment.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store assignment: %w", err)
	}
	return nil
}

func insertMutation(ctx context.Context, tx *sql.Tx, mutation apppki.MutationRecord, encoded []byte, metadata apppki.ProtectedMetadata) error {
	result, err := tx.ExecContext(ctx, `
INSERT INTO pki_mutations(
	id, idempotency_key, request_sha256, kind, resource_type, resource_id,
	result_json, mutation_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(idempotency_key) DO NOTHING`, mutation.ID, mutation.IdempotencyKey,
		mutation.RequestSHA256, mutation.Kind, mutation.ResourceType, mutation.ResourceID,
		[]byte(mutation.ResultJSON), encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, mutation.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store mutation: %w", err)
	}
	inserted, err := casApplied(result)
	if err != nil {
		return err
	}
	if !inserted {
		return apppki.ErrMutationExists
	}
	return nil
}

func insertTrustSet(ctx context.Context, tx *sql.Tx, trustSet domainpki.TrustSet, encoded []byte, metadata apppki.ProtectedMetadata) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_trust_sets(
	id, name, active_generation_id, staged_generation_id, state, revision, trust_set_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, trustSet.ID, trustSet.Name,
		nullableString(string(trustSet.ActiveGenerationID)), nullableString(string(trustSet.StagedGenerationID)),
		trustSet.State, trustSet.Revision, encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, trustSet.CreatedAt.Format(time.RFC3339Nano), trustSet.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store trust set: %w", err)
	}
	return nil
}

func insertTrustSetGeneration(ctx context.Context, tx *sql.Tx, generation domainpki.TrustSetGeneration, encoded []byte, metadata apppki.ProtectedMetadata) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_trust_set_generations(
	id, trust_set_id, generation, generation_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, generation.ID, generation.TrustSetID, generation.Generation,
		encoded, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		generation.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store trust set generation: %w", err)
	}
	return nil
}

func insertTrustSetMembers(ctx context.Context, tx *sql.Tx, generation domainpki.TrustSetGeneration) error {
	for position, id := range generation.AnchorGenerationIDs {
		if err := insertTrustSetMember(ctx, tx, generation.ID, trustMemberAnchor, string(id), position); err != nil {
			return err
		}
	}
	for position, id := range generation.IntermediateGenerationIDs {
		if err := insertTrustSetMember(ctx, tx, generation.ID, trustMemberIntermediate, string(id), position); err != nil {
			return err
		}
	}
	for position, id := range generation.CRLGenerationIDs {
		if err := insertTrustSetMember(ctx, tx, generation.ID, trustMemberCRL, string(id), position); err != nil {
			return err
		}
	}
	return nil
}

func insertTrustSetMember(ctx context.Context, tx *sql.Tx, generationID domainpki.TrustSetGenerationID, memberType, memberID string, position int) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO pki_trust_set_members(trust_set_generation_id, member_type, member_id, position)
VALUES (?, ?, ?, ?)`, generationID, memberType, memberID, position); err != nil {
		return fmt.Errorf("pki sqlite: store trust set member: %w", err)
	}
	return nil
}

func updateTrustSetCAS(ctx context.Context, tx *sql.Tx, expectedRevision uint64, trustSet domainpki.TrustSet, encoded []byte, metadata apppki.ProtectedMetadata) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, `
UPDATE pki_trust_sets SET
	name = ?, active_generation_id = ?, staged_generation_id = ?, state = ?, revision = ?, trust_set_json = ?,
	metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?, updated_at = ?
WHERE id = ? AND revision = ?`, trustSet.Name, nullableString(string(trustSet.ActiveGenerationID)),
		nullableString(string(trustSet.StagedGenerationID)), trustSet.State, trustSet.Revision, encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		trustSet.UpdatedAt.Format(time.RFC3339Nano), trustSet.ID, expectedRevision)
	if err != nil {
		return nil, fmt.Errorf("pki sqlite: update trust set: %w", err)
	}
	return result, nil
}

func (s PKIStore) loadAssignment(ctx context.Context, row rowScanner) (domainpki.Assignment, error) {
	var (
		id               domainpki.AssignmentID
		purpose          domainpki.Purpose
		consumerType     domainpki.ConsumerType
		consumerID       domainpki.ConsumerID
		profileID        domainpki.ProfileID
		activeGeneration sql.NullString
		stagedGeneration sql.NullString
		trustSetID       sql.NullString
		activeTrust      sql.NullString
		stagedTrust      sql.NullString
		rotationPolicyID sql.NullString
		state            domainpki.AssignmentState
		revision         int64
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		updatedAt        string
	)
	if err := row.Scan(&id, &purpose, &consumerType, &consumerID, &profileID, &activeGeneration,
		&stagedGeneration, &trustSetID, &activeTrust, &stagedTrust, &rotationPolicyID, &state, &revision, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.Assignment{}, apppki.ErrNotFound
		}
		return domainpki.Assignment{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.Assignment{}, fmt.Errorf("pki sqlite: verify assignment metadata: %w", err)
	}
	var assignment domainpki.Assignment
	if err := json.Unmarshal(encoded, &assignment); err != nil {
		return domainpki.Assignment{}, fmt.Errorf("pki sqlite: decode assignment: %w", err)
	}
	if err := assignment.Validate(); err != nil {
		return domainpki.Assignment{}, fmt.Errorf("pki sqlite: validate stored assignment: %w", err)
	}
	if revision <= 0 || assignment.ID != id || assignment.Purpose != purpose || assignment.ConsumerType != consumerType ||
		assignment.ConsumerID != consumerID || assignment.ProfileID != profileID ||
		assignment.ActiveGenerationID != domainpki.GenerationID(nullString(activeGeneration)) ||
		assignment.StagedGenerationID != domainpki.GenerationID(nullString(stagedGeneration)) ||
		assignment.TrustSetID != domainpki.TrustSetID(nullString(trustSetID)) ||
		assignment.ActiveTrustGenerationID != domainpki.TrustSetGenerationID(nullString(activeTrust)) ||
		assignment.StagedTrustGenerationID != domainpki.TrustSetGenerationID(nullString(stagedTrust)) ||
		assignment.RotationPolicyID != domainpki.RotationPolicyID(nullString(rotationPolicyID)) ||
		assignment.State != state || assignment.Revision != uint64(revision) ||
		assignment.UpdatedAt.Format(time.RFC3339Nano) != updatedAt {
		return domainpki.Assignment{}, errors.New("pki sqlite: assignment json does not match canonical columns")
	}
	return assignment, nil
}

func (s PKIStore) loadMutation(ctx context.Context, row rowScanner) (apppki.MutationRecord, error) {
	var (
		id             domainpki.MutationID
		idempotencyKey string
		requestSHA256  string
		kind           apppki.MutationKind
		resourceType   string
		resourceID     string
		resultJSON     []byte
		encoded        []byte
		metadata       apppki.ProtectedMetadata
		createdAt      string
	)
	if err := row.Scan(&id, &idempotencyKey, &requestSHA256, &kind, &resourceType,
		&resourceID, &resultJSON, &encoded, &metadata.SchemaVersion, &metadata.Algorithm,
		&metadata.KeyVersion, &metadata.Tag, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.MutationRecord{}, apppki.ErrNotFound
		}
		return apppki.MutationRecord{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return apppki.MutationRecord{}, fmt.Errorf("pki sqlite: verify mutation metadata: %w", err)
	}
	var mutation apppki.MutationRecord
	if err := json.Unmarshal(encoded, &mutation); err != nil {
		return apppki.MutationRecord{}, fmt.Errorf("pki sqlite: decode mutation: %w", err)
	}
	if err := mutation.Validate(); err != nil {
		return apppki.MutationRecord{}, fmt.Errorf("pki sqlite: validate stored mutation: %w", err)
	}
	if mutation.ID != id || mutation.IdempotencyKey != idempotencyKey ||
		mutation.RequestSHA256 != requestSHA256 || mutation.Kind != kind ||
		mutation.ResourceType != resourceType || mutation.ResourceID != resourceID ||
		!bytes.Equal(mutation.ResultJSON, resultJSON) ||
		mutation.CreatedAt.Format(time.RFC3339Nano) != createdAt {
		return apppki.MutationRecord{}, errors.New("pki sqlite: mutation json does not match canonical columns")
	}
	return mutation.Clone(), nil
}

func (s PKIStore) loadTrustSet(ctx context.Context, row rowScanner) (domainpki.TrustSet, error) {
	var (
		id               domainpki.TrustSetID
		name             string
		activeGeneration sql.NullString
		stagedGeneration sql.NullString
		state            domainpki.TrustSetState
		revision         int64
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		createdAt        string
		updatedAt        string
	)
	if err := row.Scan(&id, &name, &activeGeneration, &stagedGeneration, &state, &revision, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.TrustSet{}, apppki.ErrNotFound
		}
		return domainpki.TrustSet{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.TrustSet{}, fmt.Errorf("pki sqlite: verify trust set metadata: %w", err)
	}
	var trustSet domainpki.TrustSet
	if err := json.Unmarshal(encoded, &trustSet); err != nil {
		return domainpki.TrustSet{}, fmt.Errorf("pki sqlite: decode trust set: %w", err)
	}
	if err := trustSet.Validate(); err != nil {
		return domainpki.TrustSet{}, fmt.Errorf("pki sqlite: validate stored trust set: %w", err)
	}
	if revision <= 0 || trustSet.ID != id || trustSet.Name != name ||
		trustSet.ActiveGenerationID != domainpki.TrustSetGenerationID(nullString(activeGeneration)) ||
		trustSet.StagedGenerationID != domainpki.TrustSetGenerationID(nullString(stagedGeneration)) ||
		trustSet.State != state || trustSet.Revision != uint64(revision) ||
		trustSet.CreatedAt.Format(time.RFC3339Nano) != createdAt || trustSet.UpdatedAt.Format(time.RFC3339Nano) != updatedAt {
		return domainpki.TrustSet{}, errors.New("pki sqlite: trust set json does not match canonical columns")
	}
	return trustSet, nil
}

func (s PKIStore) loadTrustSetGeneration(ctx context.Context, row rowScanner) (domainpki.TrustSetGeneration, error) {
	var (
		id                    domainpki.TrustSetGenerationID
		trustSetID            domainpki.TrustSetID
		generation            int64
		encoded               []byte
		metadata              apppki.ProtectedMetadata
		createdAt             string
		anchors               string
		intermediates         string
		crls                  string
		anchorPositions       string
		intermediatePositions string
		crlPositions          string
	)
	if err := row.Scan(&id, &trustSetID, &generation, &encoded, &metadata.SchemaVersion,
		&metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &createdAt,
		&anchors, &intermediates, &crls, &anchorPositions, &intermediatePositions, &crlPositions); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.TrustSetGeneration{}, apppki.ErrNotFound
		}
		return domainpki.TrustSetGeneration{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.TrustSetGeneration{}, fmt.Errorf("pki sqlite: verify trust set generation metadata: %w", err)
	}
	var result domainpki.TrustSetGeneration
	if err := json.Unmarshal(encoded, &result); err != nil {
		return domainpki.TrustSetGeneration{}, fmt.Errorf("pki sqlite: decode trust set generation: %w", err)
	}
	if err := result.Validate(); err != nil {
		return domainpki.TrustSetGeneration{}, fmt.Errorf("pki sqlite: validate stored trust set generation: %w", err)
	}
	if generation <= 0 || result.ID != id || result.TrustSetID != trustSetID || result.Generation != uint64(generation) ||
		result.CreatedAt.Format(time.RFC3339Nano) != createdAt ||
		anchors != joinIDs(result.AnchorGenerationIDs) ||
		intermediates != joinIDs(result.IntermediateGenerationIDs) ||
		crls != joinIDs(result.CRLGenerationIDs) ||
		anchorPositions != contiguousPositions(len(result.AnchorGenerationIDs)) ||
		intermediatePositions != contiguousPositions(len(result.IntermediateGenerationIDs)) ||
		crlPositions != contiguousPositions(len(result.CRLGenerationIDs)) {
		return domainpki.TrustSetGeneration{}, errors.New("pki sqlite: trust set generation json does not match canonical columns")
	}
	return result.Clone(), nil
}

func stringIDs[T ~string](ids []T) []string {
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = string(id)
	}
	return result
}

func joinIDs[T ~string](ids []T) string {
	return strings.Join(stringIDs(ids), ",")
}

func contiguousPositions(count int) string {
	positions := make([]string, count)
	for index := range count {
		positions[index] = fmt.Sprintf("%d", index)
	}
	return strings.Join(positions, ",")
}

func validateCASUpdate(expectedRevision, nextRevision uint64) error {
	if expectedRevision == 0 || expectedRevision == math.MaxUint64 || nextRevision != expectedRevision+1 {
		return errors.New("pki sqlite: invalid revision update")
	}
	return nil
}

func validatePersistenceAudit[T ~string](audit apppki.AuditRecord, resourceID T) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(resourceID) {
		return errors.New("pki sqlite: audit resource does not match mutation")
	}
	return nil
}

func validatePersistenceMutation[T ~string](mutation apppki.MutationRecord, resourceType string, resourceID T) error {
	if err := mutation.Validate(); err != nil {
		return err
	}
	if mutation.ResourceType != resourceType || mutation.ResourceID != string(resourceID) {
		return errors.New("pki sqlite: mutation resource does not match state change")
	}
	return nil
}

func casApplied(result sql.Result) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected == 1 {
		return true, nil
	}
	if affected != 0 {
		return false, errors.New("pki sqlite: compare-and-swap affected an unexpected number of rows")
	}
	return false, nil
}

func requireAssignmentCASRow(ctx context.Context, tx *sql.Tx, result sql.Result, id domainpki.AssignmentID) error {
	applied, err := casApplied(result)
	if err != nil || applied {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pki_assignments WHERE id = ?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.ErrNotFound
		}
		return err
	}
	return apppki.ErrRevisionConflict
}

func requireTrustSetCASRow(ctx context.Context, tx *sql.Tx, result sql.Result, id domainpki.TrustSetID) error {
	applied, err := casApplied(result)
	if err != nil || applied {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pki_trust_sets WHERE id = ?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.ErrNotFound
		}
		return err
	}
	return apppki.ErrRevisionConflict
}
