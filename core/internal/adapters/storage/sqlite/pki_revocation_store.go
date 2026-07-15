package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const revocationSelect = `
SELECT id, certificate_id, generation_id, issuer_authority_id, issuer_generation_id,
	serial_number, reason, previous_state, effective_at, recorded_at, revocation_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_revocations`

func (s PKIStore) Revocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.Revocation, error) {
		if err := id.Validate(); err != nil {
			return domainpki.Revocation{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.Revocation{}, err
		}
		return s.loadRevocation(ctx, db.QueryRowContext(ctx, revocationSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) RevocationForGeneration(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.Revocation, error) {
		if err := id.Validate(); err != nil {
			return domainpki.Revocation{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.Revocation{}, err
		}
		return s.loadRevocation(ctx, db.QueryRowContext(ctx, revocationSelect+` WHERE generation_id = ?`, id))
	})
}

func (s PKIStore) Revocations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.Revocation, error) {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if _, err := s.authority(ctx, id); err != nil {
			return nil, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(
			ctx, revocationSelect+` WHERE issuer_authority_id = ? ORDER BY recorded_at, id`, id,
		)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki revocation rows", rows.Close()) }()
		result := make([]domainpki.Revocation, 0)
		for rows.Next() {
			revocation, err := s.loadRevocation(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, revocation)
		}
		return result, rows.Err()
	})
}

type authenticatedAssignment struct {
	assignment domainpki.Assignment
	encoded    []byte
	metadata   apppki.ProtectedMetadata
}

func (s PKIStore) RecordRevocation(
	ctx context.Context,
	revoked domainpki.CertificateGeneration,
	revocation domainpki.Revocation,
	affected []domainpki.Assignment,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := apppki.ValidateRevocationCommit(revoked, revocation, affected, audit, mutation); err != nil {
			return err
		}
		preparedGeneration, err := s.prepareGenerationResult(ctx, revoked)
		if err != nil {
			return err
		}
		revocationJSON, revocationMetadata, err := s.authenticateJSON(ctx, revocation)
		if err != nil {
			return err
		}
		mutationJSON, mutationMetadata, err := s.authenticateJSON(ctx, mutation)
		if err != nil {
			return err
		}
		preparedAssignments := make([]authenticatedAssignment, len(affected))
		for index, assignment := range affected {
			encoded, metadata, err := s.authenticateJSON(ctx, assignment)
			if err != nil {
				return err
			}
			preparedAssignments[index] = authenticatedAssignment{
				assignment: assignment, encoded: encoded, metadata: metadata,
			}
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki revocation", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		current, err := s.loadGeneration(ctx, tx.QueryRowContext(
			ctx, generationSelect+` WHERE id = ?`, revocation.GenerationID,
		))
		if err != nil {
			return err
		}
		if err := domainpki.ValidateRevocationTransition(current, revoked, revocation); err != nil {
			return err
		}
		assignments, err := s.loadAssignmentsTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := domainpki.ValidateGenerationRevocationAssignments(
			assignments, revocation.GenerationID, revocation.RecordedAt, affected,
		); err != nil {
			return err
		}
		if err := insertRevocation(ctx, tx, revocation, revocationJSON, revocationMetadata); err != nil {
			return err
		}
		generationResult, err := tx.ExecContext(ctx, `
UPDATE pki_certificate_generations
SET state = ?, generation_json = ?, metadata_schema_version = ?, metadata_algorithm = ?,
	metadata_key_version = ?, metadata_tag = ?
WHERE id = ? AND state = ?`, revoked.State, preparedGeneration.generationJSON,
			preparedGeneration.generationMetadata.SchemaVersion, preparedGeneration.generationMetadata.Algorithm,
			preparedGeneration.generationMetadata.KeyVersion, preparedGeneration.generationMetadata.Tag,
			revoked.ID, current.State)
		if err != nil {
			return fmt.Errorf("pki sqlite: update revoked generation: %w", err)
		}
		updated, err := casApplied(generationResult)
		if err != nil {
			return err
		}
		if !updated {
			return apppki.ErrRevisionConflict
		}
		for _, prepared := range preparedAssignments {
			if err := updateAssignmentTx(
				ctx, tx, prepared.assignment.Revision-1, prepared.assignment, prepared.encoded, prepared.metadata,
			); err != nil {
				return err
			}
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) loadAssignmentsTx(ctx context.Context, tx *sql.Tx) ([]domainpki.Assignment, error) {
	rows, err := tx.QueryContext(ctx, assignmentSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki revocation assignment rows", rows.Close()) }()
	result := make([]domainpki.Assignment, 0)
	for rows.Next() {
		assignment, err := s.loadAssignment(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, assignment)
	}
	return result, rows.Err()
}

func insertRevocation(
	ctx context.Context,
	tx *sql.Tx,
	revocation domainpki.Revocation,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_revocations(
	id, certificate_id, generation_id, issuer_authority_id, issuer_generation_id,
	serial_number, reason, previous_state, effective_at, recorded_at, revocation_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, revocation.ID, revocation.CertificateID,
		revocation.GenerationID, revocation.IssuerAuthorityID, revocation.IssuerGenerationID,
		revocation.SerialNumber, revocation.Reason, revocation.PreviousState,
		revocation.EffectiveAt.Format(time.RFC3339Nano), revocation.RecordedAt.Format(time.RFC3339Nano), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag)
	if err != nil {
		return fmt.Errorf("pki sqlite: store revocation: %w", err)
	}
	return nil
}

func (s PKIStore) loadRevocation(ctx context.Context, row rowScanner) (domainpki.Revocation, error) {
	var (
		id                 domainpki.RevocationID
		certificateID      domainpki.CertificateID
		generationID       domainpki.GenerationID
		issuerAuthorityID  domainpki.AuthorityID
		issuerGenerationID domainpki.GenerationID
		serialNumber       domainpki.SerialNumber
		reason             domainpki.RevocationReason
		previousState      domainpki.CertificateState
		effectiveAt        string
		recordedAt         string
		encoded            []byte
		metadata           apppki.ProtectedMetadata
	)
	if err := row.Scan(
		&id, &certificateID, &generationID, &issuerAuthorityID, &issuerGenerationID,
		&serialNumber, &reason, &previousState, &effectiveAt, &recordedAt, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.Revocation{}, apppki.ErrNotFound
		}
		return domainpki.Revocation{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.Revocation{}, fmt.Errorf("pki sqlite: verify revocation metadata: %w", err)
	}
	var revocation domainpki.Revocation
	if err := json.Unmarshal(encoded, &revocation); err != nil {
		return domainpki.Revocation{}, fmt.Errorf("pki sqlite: decode revocation: %w", err)
	}
	if err := revocation.Validate(); err != nil {
		return domainpki.Revocation{}, fmt.Errorf("pki sqlite: validate revocation: %w", err)
	}
	if revocation.ID != id || revocation.CertificateID != certificateID ||
		revocation.GenerationID != generationID || revocation.IssuerAuthorityID != issuerAuthorityID ||
		revocation.IssuerGenerationID != issuerGenerationID || revocation.SerialNumber != serialNumber ||
		revocation.Reason != reason || revocation.PreviousState != previousState ||
		revocation.EffectiveAt.Format(time.RFC3339Nano) != effectiveAt ||
		revocation.RecordedAt.Format(time.RFC3339Nano) != recordedAt {
		return domainpki.Revocation{}, errors.New("pki sqlite: revocation json does not match canonical columns")
	}
	return revocation, nil
}

func (s PKIStore) reauthenticateRevocationMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id, revocation_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_revocations ORDER BY id`)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.loadRevocation(ctx, tx.QueryRowContext(ctx, revocationSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate revocation %q before rewrap: %w", record.id, err)
		}
		metadata, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "revocation")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_revocations
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update revocation %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}
