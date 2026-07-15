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

const credentialStampSelect = `
SELECT id, assignment_id, provider_id, capability, slot_name, status, revision,
	input_artifact_id, input_sha256, output_artifact_id, output_sha256,
	descriptor_sha256, superseded_by, stamp_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at,
	created_at_sort, updated_at_sort
FROM pki_credential_stamps`

func (s PKIStore) CredentialStamp(
	ctx context.Context,
	id domainpki.StampID,
) (domainpki.CredentialStamp, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.CredentialStamp, error) {
		if err := id.Validate(); err != nil {
			return domainpki.CredentialStamp{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.CredentialStamp{}, err
		}
		return s.loadCredentialStamp(
			ctx, db.QueryRowContext(ctx, credentialStampSelect+` WHERE id = ?`, id),
		)
	})
}

func (s PKIStore) CredentialStamps(ctx context.Context) ([]domainpki.CredentialStamp, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.CredentialStamp, error) {
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, credentialStampSelect+` ORDER BY created_at_sort, id`)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki credential stamp rows", rows.Close()) }()
		result := make([]domainpki.CredentialStamp, 0)
		for rows.Next() {
			stamp, err := s.loadCredentialStamp(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, stamp)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) CreateCredentialStamp(
	ctx context.Context,
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if stamp.Status != domainpki.CredentialStampPending {
			return errors.New("pki sqlite: new credential stamp must be pending")
		}
		if err := validateSQLiteCredentialStampRecords(stamp, audit, mutation); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, stamp)
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
		defer func() { logSQLiteRollback("rollback pki credential stamp creation", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		assignment, err := s.loadAssignment(
			ctx, tx.QueryRowContext(
				ctx, assignmentSelect+` WHERE id = ?`, stamp.Plan.Request.AssignmentID,
			),
		)
		if err != nil {
			return err
		}
		if err := domainpki.ValidateCredentialStampAssignment(
			assignment, stamp.Plan.Request,
		); err != nil {
			return err
		}
		if err := insertCredentialStamp(ctx, tx, stamp, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) UpdateCredentialStamp(
	ctx context.Context,
	expectedRevision uint64,
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateSQLiteCredentialStampRecords(stamp, audit, mutation); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, stamp)
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
		defer func() { logSQLiteRollback("rollback pki credential stamp update", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		previous, err := s.loadCredentialStamp(
			ctx, tx.QueryRowContext(ctx, credentialStampSelect+` WHERE id = ?`, stamp.ID),
		)
		if err != nil {
			return err
		}
		if previous.Revision != expectedRevision {
			return apppki.ErrRevisionConflict
		}
		if err := domainpki.ValidateCredentialStampTransition(previous, stamp); err != nil {
			return err
		}
		if stamp.Status == domainpki.CredentialStampSuperseded {
			replacement, err := s.loadCredentialStamp(
				ctx, tx.QueryRowContext(ctx, credentialStampSelect+` WHERE id = ?`, stamp.SupersededBy),
			)
			if err != nil {
				return err
			}
			if err := domainpki.ValidateCredentialStampReplacement(
				previous, replacement, stamp,
			); err != nil {
				return err
			}
		}
		result, err := updateCredentialStampCAS(ctx, tx, expectedRevision, stamp, encoded, metadata)
		if err != nil {
			return err
		}
		applied, err := casApplied(result)
		if err != nil {
			return err
		}
		if !applied {
			return apppki.ErrRevisionConflict
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func insertCredentialStamp(
	ctx context.Context,
	tx *sql.Tx,
	stamp domainpki.CredentialStamp,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	outputID, outputSHA256 := credentialStampOutput(stamp)
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_credential_stamps(
	id, assignment_id, provider_id, capability, slot_name, status, revision,
	input_artifact_id, input_sha256, output_artifact_id, output_sha256,
	descriptor_sha256, superseded_by, stamp_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at,
	created_at_sort, updated_at_sort
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stamp.ID, stamp.Plan.Request.AssignmentID, stamp.ProviderID,
		stamp.Plan.Request.Capability, stamp.Plan.Request.SlotName,
		stamp.Status, stamp.Revision, stamp.Plan.Input.ID, stamp.Plan.Input.SHA256,
		nullableString(outputID), nullableString(outputSHA256), stamp.Plan.DescriptorSHA256,
		nullableString(string(stamp.SupersededBy)), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		stamp.CreatedAt.Format(time.RFC3339Nano), stamp.UpdatedAt.Format(time.RFC3339Nano),
		formatStampSortableTimestamp(stamp.CreatedAt), formatStampSortableTimestamp(stamp.UpdatedAt))
	if err != nil {
		return fmt.Errorf("pki sqlite: store credential stamp: %w", err)
	}
	return nil
}

func updateCredentialStampCAS(
	ctx context.Context,
	tx *sql.Tx,
	expectedRevision uint64,
	stamp domainpki.CredentialStamp,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) (sql.Result, error) {
	outputID, outputSHA256 := credentialStampOutput(stamp)
	result, err := tx.ExecContext(ctx, `
UPDATE pki_credential_stamps SET
	status = ?, revision = ?, output_artifact_id = ?, output_sha256 = ?,
	superseded_by = ?,
	stamp_json = ?, metadata_schema_version = ?, metadata_algorithm = ?,
	metadata_key_version = ?, metadata_tag = ?, updated_at = ?, updated_at_sort = ?
WHERE id = ? AND revision = ?`,
		stamp.Status, stamp.Revision, nullableString(outputID), nullableString(outputSHA256),
		nullableString(string(stamp.SupersededBy)), encoded, metadata.SchemaVersion,
		metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		stamp.UpdatedAt.Format(time.RFC3339Nano), formatStampSortableTimestamp(stamp.UpdatedAt),
		stamp.ID, expectedRevision)
	if err != nil {
		return nil, fmt.Errorf("pki sqlite: update credential stamp: %w", err)
	}
	return result, nil
}

func (s PKIStore) loadCredentialStamp(
	ctx context.Context,
	row rowScanner,
) (domainpki.CredentialStamp, error) {
	var (
		id               domainpki.StampID
		assignmentID     domainpki.AssignmentID
		providerID       domainpki.DeliveryProviderID
		capability       domainpki.DeliveryCapability
		slotName         domainpki.CredentialSlotName
		status           domainpki.CredentialStampStatus
		revision         int64
		inputID          domainpki.StampReferenceID
		inputSHA256      string
		outputID         sql.NullString
		outputSHA256     sql.NullString
		descriptorSHA256 string
		supersededBy     sql.NullString
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		createdAt        string
		updatedAt        string
		createdAtSort    string
		updatedAtSort    string
	)
	if err := row.Scan(
		&id, &assignmentID, &providerID, &capability, &slotName, &status, &revision,
		&inputID, &inputSHA256, &outputID, &outputSHA256, &descriptorSHA256,
		&supersededBy, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag,
		&createdAt, &updatedAt, &createdAtSort, &updatedAtSort,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.CredentialStamp{}, apppki.ErrNotFound
		}
		return domainpki.CredentialStamp{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.CredentialStamp{}, fmt.Errorf("pki sqlite: verify credential stamp metadata: %w", err)
	}
	var stamp domainpki.CredentialStamp
	if err := json.Unmarshal(encoded, &stamp); err != nil {
		return domainpki.CredentialStamp{}, fmt.Errorf("pki sqlite: decode credential stamp: %w", err)
	}
	if err := stamp.Validate(); err != nil {
		return domainpki.CredentialStamp{}, fmt.Errorf("pki sqlite: validate stored credential stamp: %w", err)
	}
	canonicalOutputID, canonicalOutputSHA256 := credentialStampOutput(stamp)
	if revision <= 0 || stamp.ID != id || stamp.Plan.Request.AssignmentID != assignmentID ||
		stamp.ProviderID != providerID || stamp.Plan.Request.Capability != capability ||
		stamp.Plan.Request.SlotName != slotName || stamp.Status != status ||
		stamp.Revision != uint64(revision) || stamp.Plan.Input.ID != inputID ||
		stamp.Plan.Input.SHA256 != inputSHA256 ||
		canonicalOutputID != nullString(outputID) || canonicalOutputSHA256 != nullString(outputSHA256) ||
		stamp.Plan.DescriptorSHA256 != descriptorSHA256 ||
		string(stamp.SupersededBy) != nullString(supersededBy) ||
		stamp.CreatedAt.Format(time.RFC3339Nano) != createdAt ||
		stamp.UpdatedAt.Format(time.RFC3339Nano) != updatedAt ||
		formatStampSortableTimestamp(stamp.CreatedAt) != createdAtSort ||
		formatStampSortableTimestamp(stamp.UpdatedAt) != updatedAtSort {
		return domainpki.CredentialStamp{}, errors.New("pki sqlite: credential stamp json does not match canonical columns")
	}
	return stamp.Clone(), nil
}

func formatStampSortableTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func credentialStampOutput(stamp domainpki.CredentialStamp) (string, string) {
	if stamp.Result == nil || stamp.Result.Destination.Artifact == nil {
		return "", ""
	}
	return string(stamp.Result.Destination.Artifact.ID), stamp.Result.Destination.Artifact.SHA256
}

func validateSQLiteCredentialStampRecords(
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := stamp.Validate(); err != nil {
		return err
	}
	if err := validatePersistenceAudit(audit, stamp.ID); err != nil {
		return err
	}
	expectedKind, expectedAction, expectedOutcome, err :=
		apppki.CredentialStampLifecycleContract(stamp.Status)
	if err != nil {
		return err
	}
	if audit.Action != expectedAction || audit.Outcome != expectedOutcome ||
		audit.ResourceType != apppki.CredentialStampResourceType {
		return errors.New("pki sqlite: credential stamp audit contract does not match")
	}
	if err := validatePersistenceMutation(
		mutation, apppki.CredentialStampResourceType, stamp.ID,
	); err != nil {
		return err
	}
	if mutation.Kind != expectedKind {
		return errors.New("pki sqlite: credential stamp mutation kind does not match")
	}
	return nil
}
