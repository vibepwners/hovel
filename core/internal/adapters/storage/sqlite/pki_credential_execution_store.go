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

const credentialExecutionSelect = `
SELECT id, kind, provider_module_id, provider_id, descriptor_sha256,
	assignment_id, status, revision, execution_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at,
	created_at_sort, updated_at_sort
FROM pki_credential_executions`

func (s PKIStore) CredentialExecution(
	ctx context.Context,
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.CredentialExecution, error) {
		if err := id.Validate(); err != nil {
			return domainpki.CredentialExecution{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.CredentialExecution{}, err
		}
		return s.loadCredentialExecution(
			ctx, db.QueryRowContext(ctx, credentialExecutionSelect+` WHERE id = ?`, id),
		)
	})
}

func (s PKIStore) CredentialExecutions(ctx context.Context) ([]domainpki.CredentialExecution, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.CredentialExecution, error) {
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, credentialExecutionSelect+` ORDER BY created_at_sort, id`)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki credential execution rows", rows.Close()) }()
		result := make([]domainpki.CredentialExecution, 0)
		for rows.Next() {
			execution, err := s.loadCredentialExecution(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, execution)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) CreateCredentialExecution(
	ctx context.Context,
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if execution.Status != domainpki.CredentialExecutionPending {
			return errors.New("pki sqlite: new credential execution must be pending")
		}
		if err := validateSQLiteCredentialExecutionRecords(execution, audit, mutation); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, execution)
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
		defer func() { logSQLiteRollback("rollback pki credential execution creation", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if execution.Plan.Kind != domainpki.CredentialExecutionEncoding {
			assignment, err := s.loadAssignment(
				ctx, tx.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, execution.Plan.AssignmentID),
			)
			if err != nil {
				return err
			}
			if err := domainpki.ValidateCredentialExecutionAssignment(assignment, execution.Plan); err != nil {
				return err
			}
		}
		if err := insertCredentialExecution(ctx, tx, execution, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s PKIStore) UpdateCredentialExecution(
	ctx context.Context,
	expectedRevision uint64,
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateSQLiteCredentialExecutionRecords(execution, audit, mutation); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, execution)
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
		defer func() { logSQLiteRollback("rollback pki credential execution update", tx.Rollback()) }()
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		previous, err := s.loadCredentialExecution(
			ctx, tx.QueryRowContext(ctx, credentialExecutionSelect+` WHERE id = ?`, execution.ID),
		)
		if err != nil {
			return err
		}
		if previous.Revision != expectedRevision {
			return apppki.ErrRevisionConflict
		}
		if err := domainpki.ValidateCredentialExecutionTransition(previous, execution); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
UPDATE pki_credential_executions SET
	status = ?, revision = ?, execution_json = ?, metadata_schema_version = ?,
	metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?,
	updated_at = ?, updated_at_sort = ?
WHERE id = ? AND revision = ?`,
			execution.Status, execution.Revision, encoded, metadata.SchemaVersion,
			metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
			execution.UpdatedAt.Format(time.RFC3339Nano),
			formatStampSortableTimestamp(execution.UpdatedAt), execution.ID, expectedRevision)
		if err != nil {
			return fmt.Errorf("pki sqlite: update credential execution: %w", err)
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

func insertCredentialExecution(
	ctx context.Context,
	tx *sql.Tx,
	execution domainpki.CredentialExecution,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	assignmentID := ""
	if execution.Plan.Kind != domainpki.CredentialExecutionEncoding {
		assignmentID = string(execution.Plan.AssignmentID)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_credential_executions(
	id, kind, provider_module_id, provider_id, descriptor_sha256, assignment_id,
	status, revision, execution_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at, updated_at, created_at_sort,
	updated_at_sort
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		execution.ID, execution.Plan.Kind, execution.Plan.Provider.ModuleID,
		execution.Plan.Provider.ProviderID, execution.Plan.Provider.DescriptorSHA256,
		nullableString(assignmentID), execution.Status, execution.Revision, encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		execution.CreatedAt.Format(time.RFC3339Nano), execution.UpdatedAt.Format(time.RFC3339Nano),
		formatStampSortableTimestamp(execution.CreatedAt),
		formatStampSortableTimestamp(execution.UpdatedAt))
	if err != nil {
		return fmt.Errorf("pki sqlite: store credential execution: %w", err)
	}
	return nil
}

func (s PKIStore) loadCredentialExecution(
	ctx context.Context,
	row rowScanner,
) (domainpki.CredentialExecution, error) {
	var (
		id               domainpki.CredentialExecutionRequestID
		kind             domainpki.CredentialExecutionKind
		providerModuleID string
		providerID       domainpki.DeliveryProviderID
		descriptorSHA256 string
		assignmentID     sql.NullString
		status           domainpki.CredentialExecutionStatus
		revision         int64
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		createdAt        string
		updatedAt        string
		createdAtSort    string
		updatedAtSort    string
	)
	if err := row.Scan(
		&id, &kind, &providerModuleID, &providerID, &descriptorSHA256,
		&assignmentID, &status, &revision, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag,
		&createdAt, &updatedAt, &createdAtSort, &updatedAtSort,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.CredentialExecution{}, apppki.ErrNotFound
		}
		return domainpki.CredentialExecution{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.CredentialExecution{}, fmt.Errorf(
			"pki sqlite: verify credential execution metadata: %w", err,
		)
	}
	var execution domainpki.CredentialExecution
	if err := json.Unmarshal(encoded, &execution); err != nil {
		return domainpki.CredentialExecution{}, fmt.Errorf("pki sqlite: decode credential execution: %w", err)
	}
	if err := execution.Validate(); err != nil {
		return domainpki.CredentialExecution{}, fmt.Errorf("pki sqlite: validate stored credential execution: %w", err)
	}
	canonicalAssignmentID := ""
	if execution.Plan.Kind != domainpki.CredentialExecutionEncoding {
		canonicalAssignmentID = string(execution.Plan.AssignmentID)
	}
	if revision <= 0 || execution.ID != id || execution.Plan.Kind != kind ||
		execution.Plan.Provider.ModuleID != providerModuleID ||
		execution.Plan.Provider.ProviderID != providerID ||
		execution.Plan.Provider.DescriptorSHA256 != descriptorSHA256 ||
		canonicalAssignmentID != nullString(assignmentID) || execution.Status != status ||
		execution.Revision != uint64(revision) ||
		execution.CreatedAt.Format(time.RFC3339Nano) != createdAt ||
		execution.UpdatedAt.Format(time.RFC3339Nano) != updatedAt ||
		formatStampSortableTimestamp(execution.CreatedAt) != createdAtSort ||
		formatStampSortableTimestamp(execution.UpdatedAt) != updatedAtSort {
		return domainpki.CredentialExecution{}, errors.New(
			"pki sqlite: credential execution json does not match canonical columns",
		)
	}
	return execution.Clone(), nil
}

func validateSQLiteCredentialExecutionRecords(
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := execution.Validate(); err != nil {
		return err
	}
	if err := validatePersistenceAudit(audit, execution.ID); err != nil {
		return err
	}
	expectedKind, expectedAction, expectedOutcome, err :=
		apppki.CredentialExecutionLifecycleContract(execution.Status)
	if err != nil {
		return err
	}
	if audit.Action != expectedAction || audit.Outcome != expectedOutcome ||
		audit.ResourceType != apppki.CredentialExecutionResourceType {
		return errors.New("pki sqlite: credential execution audit contract does not match")
	}
	if err := validatePersistenceMutation(
		mutation, apppki.CredentialExecutionResourceType, execution.ID,
	); err != nil {
		return err
	}
	if mutation.Kind != expectedKind {
		return errors.New("pki sqlite: credential execution mutation kind does not match")
	}
	return nil
}
