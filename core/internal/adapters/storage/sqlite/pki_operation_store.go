package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const operationSelect = `
SELECT operation_row.id, operation_row.kind, operation_row.status, operation_row.revision,
	operation_row.previous_authority_id, operation_row.replacement_authority_id,
	operation_row.previous_authority_generation_id, operation_row.replacement_authority_generation_id,
	operation_row.trust_set_id, operation_row.overlap_trust_generation_id,
	operation_row.final_trust_generation_id, operation_row.consumer_tracking,
	operation_row.phase, operation_row.operation_json, operation_row.metadata_schema_version,
	operation_row.metadata_algorithm, operation_row.metadata_key_version, operation_row.metadata_tag,
	operation_row.created_at, operation_row.updated_at, operation_row.completed_at, operation_row.failure,
	COALESCE((SELECT group_concat(assignment_id, ',') FROM (
		SELECT assignment_id FROM pki_operation_required_assignments
		WHERE operation_id = operation_row.id ORDER BY position
	)), ''),
	COALESCE((SELECT group_concat(position, ',') FROM (
		SELECT position FROM pki_operation_required_assignments
		WHERE operation_id = operation_row.id ORDER BY position
	)), '')
FROM pki_operations AS operation_row`

const acknowledgementSelect = `
SELECT id, operation_id, assignment_id, consumer_type, consumer_id, kind,
	trust_set_generation_id, evidence_ref, acknowledgement_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag,
	acknowledged_at
FROM pki_consumer_acknowledgements`

func (s PKIStore) PKIOperation(ctx context.Context, id domainpki.OperationID) (domainpki.Operation, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.Operation, error) {
		if err := id.Validate(); err != nil {
			return domainpki.Operation{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.Operation{}, err
		}
		return s.loadOperation(ctx, db.QueryRowContext(ctx, operationSelect+` WHERE operation_row.id = ?`, id))
	})
}

func (s PKIStore) PKIOperations(ctx context.Context) ([]domainpki.Operation, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.Operation, error) {
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, operationSelect+` ORDER BY operation_row.created_at, operation_row.id`)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki operation rows", rows.Close()) }()
		result := make([]domainpki.Operation, 0)
		for rows.Next() {
			operation, err := s.loadOperation(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, operation)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) liveAuthorityRolloverForTrustSetTx(
	ctx context.Context,
	tx *sql.Tx,
	id domainpki.TrustSetID,
) (domainpki.Operation, bool, error) {
	operation, err := s.loadOperation(ctx, tx.QueryRowContext(
		ctx,
		operationSelect+` WHERE operation_row.kind = ? AND operation_row.status = ? AND operation_row.trust_set_id = ? LIMIT 1`,
		domainpki.OperationKindAuthorityRollover,
		domainpki.OperationStatusWaiting,
		id,
	))
	if errors.Is(err, apppki.ErrNotFound) {
		return domainpki.Operation{}, false, nil
	}
	if err != nil {
		return domainpki.Operation{}, false, err
	}
	return operation, true, nil
}

func (s PKIStore) ConsumerAcknowledgements(
	ctx context.Context,
	id domainpki.OperationID,
) ([]domainpki.ConsumerAcknowledgement, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.ConsumerAcknowledgement, error) {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := s.loadOperation(ctx, db.QueryRowContext(ctx, operationSelect+` WHERE operation_row.id = ?`, id)); err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, acknowledgementSelect+` WHERE operation_id = ? ORDER BY acknowledged_at, id`, id)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki acknowledgement rows", rows.Close()) }()
		result := make([]domainpki.ConsumerAcknowledgement, 0)
		for rows.Next() {
			acknowledgement, err := s.loadConsumerAcknowledgement(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, acknowledgement)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) CreateAuthorityRollover(
	ctx context.Context,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := operation.Validate(); err != nil {
			return err
		}
		if operation.Kind != domainpki.OperationKindAuthorityRollover || operation.AuthorityRollover == nil {
			return errors.New("pki sqlite: operation is not an authority rollover")
		}
		if err := validatePersistenceAudit(audit, operation.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, operation.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, operation)
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
		defer func() { logSQLiteRollback("rollback pki authority rollover creation", tx.Rollback()) }()
		if err := s.validateAuthorityRolloverReferences(ctx, tx, operation); err != nil {
			return err
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if err := insertOperation(ctx, tx, operation, encoded, metadata); err != nil {
			return err
		}
		if err := insertOperationRequiredAssignments(ctx, tx, operation); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitOperationTransaction(ctx, tx)
	})
}

func (s PKIStore) RecordConsumerAcknowledgement(
	ctx context.Context,
	acknowledgement domainpki.ConsumerAcknowledgement,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := acknowledgement.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, acknowledgement.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, acknowledgement.ID); err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, acknowledgement)
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
		defer func() { logSQLiteRollback("rollback pki consumer acknowledgement", tx.Rollback()) }()
		operation, err := s.loadOperation(ctx, tx.QueryRowContext(
			ctx, operationSelect+` WHERE operation_row.id = ?`, acknowledgement.OperationID,
		))
		if err != nil {
			return err
		}
		assignment, err := s.loadAssignment(ctx, tx.QueryRowContext(
			ctx, assignmentSelect+` WHERE id = ?`, acknowledgement.AssignmentID,
		))
		if err != nil {
			return err
		}
		if err := validateAcknowledgementReferences(operation, assignment, acknowledgement); err != nil {
			return err
		}
		if operation.AuthorityRollover.Phase == domainpki.AuthorityRolloverPhaseAwaitingFinalAcknowledgements {
			if err := s.validateRolloverAssignmentRotated(ctx, tx, operation.AuthorityRollover, assignment); err != nil {
				return err
			}
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		if err := insertConsumerAcknowledgement(ctx, tx, acknowledgement, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitOperationTransaction(ctx, tx)
	})
}

func (s PKIStore) ActivateAuthorityRollover(
	ctx context.Context,
	expectedOperationRevision uint64,
	expectedTrustSetRevision uint64,
	operation domainpki.Operation,
	previous domainpki.Authority,
	trustSet domainpki.TrustSet,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.persistAuthorityRolloverAggregate(
		ctx, expectedOperationRevision, expectedTrustSetRevision,
		operation, previous, trustSet, audit, mutation,
		domainpki.AuthorityRolloverTransitionActivateOverlap,
	)
}

func (s PKIStore) CompleteAuthorityRollover(
	ctx context.Context,
	expectedOperationRevision uint64,
	expectedTrustSetRevision uint64,
	operation domainpki.Operation,
	previous domainpki.Authority,
	trustSet domainpki.TrustSet,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.persistAuthorityRolloverAggregate(
		ctx, expectedOperationRevision, expectedTrustSetRevision,
		operation, previous, trustSet, audit, mutation,
		domainpki.AuthorityRolloverTransitionComplete,
	)
}

func (s PKIStore) UpdateAuthorityRollover(
	ctx context.Context,
	expectedRevision uint64,
	expectedTrustSetRevision uint64,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedRevision, operation.Revision); err != nil {
			return err
		}
		if expectedTrustSetRevision == 0 {
			return errors.New("pki sqlite: expected trust set revision must be positive")
		}
		if err := operation.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, operation.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, operation.ID); err != nil {
			return err
		}
		operationJSON, operationMetadata, err := s.authenticateJSON(ctx, operation)
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
		defer func() { logSQLiteRollback("rollback pki authority rollover update", tx.Rollback()) }()
		existing, err := s.loadOperation(ctx, tx.QueryRowContext(
			ctx, operationSelect+` WHERE operation_row.id = ?`, operation.ID,
		))
		if err != nil {
			return err
		}
		if existing.Revision != expectedRevision {
			return apppki.ErrRevisionConflict
		}
		if err := domainpki.ValidateAuthorityRolloverTransition(
			existing, operation, domainpki.AuthorityRolloverTransitionBeginFinalTrust,
		); err != nil {
			return err
		}
		if err := s.validateFinalTrustTransitionReferences(
			ctx, tx, operation, expectedTrustSetRevision,
		); err != nil {
			return err
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		result, err := updateOperationCAS(ctx, tx, expectedRevision, operation, operationJSON, operationMetadata)
		if err != nil {
			return err
		}
		if err := requireOperationCASRow(ctx, tx, result, operation.ID); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitOperationTransaction(ctx, tx)
	})
}

func (s PKIStore) CancelAuthorityRollover(
	ctx context.Context,
	expectedRevision uint64,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedRevision, operation.Revision); err != nil {
			return err
		}
		if err := operation.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, operation.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, operation.ID); err != nil {
			return err
		}
		operationJSON, operationMetadata, err := s.authenticateJSON(ctx, operation)
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
		defer func() { logSQLiteRollback("rollback pki authority rollover cancellation", tx.Rollback()) }()
		existing, err := s.loadOperation(ctx, tx.QueryRowContext(
			ctx, operationSelect+` WHERE operation_row.id = ?`, operation.ID,
		))
		if err != nil {
			return err
		}
		if existing.Revision != expectedRevision {
			return apppki.ErrRevisionConflict
		}
		if err := domainpki.ValidateAuthorityRolloverTransition(
			existing, operation, domainpki.AuthorityRolloverTransitionCancel,
		); err != nil {
			return err
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		result, err := updateOperationCAS(
			ctx, tx, expectedRevision, operation, operationJSON, operationMetadata,
		)
		if err != nil {
			return err
		}
		if err := requireOperationCASRow(ctx, tx, result, operation.ID); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitOperationTransaction(ctx, tx)
	})
}

func (s PKIStore) validateFinalTrustTransitionReferences(
	ctx context.Context,
	tx *sql.Tx,
	operation domainpki.Operation,
	expectedTrustSetRevision uint64,
) error {
	rollover := operation.AuthorityRollover
	if rollover == nil {
		return errors.New("pki sqlite: authority rollover payload is required")
	}
	trustSet, err := s.loadTrustSet(ctx, tx.QueryRowContext(ctx, trustSetSelect+` WHERE id = ?`, rollover.TrustSetID))
	if err != nil {
		return err
	}
	if trustSet.Revision != expectedTrustSetRevision {
		return apppki.ErrRevisionConflict
	}
	if trustSet.StagedGenerationID != rollover.FinalTrustGenerationID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionTrustChanged, "rollover final trust generation is not staged",
		)
	}
	finalTrust, err := s.loadTrustSetGeneration(ctx, tx.QueryRowContext(
		ctx, trustSetGenerationSelect+` WHERE generation_row.id = ?`, rollover.FinalTrustGenerationID,
	))
	if err != nil {
		return err
	}
	previous, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, rollover.PreviousAuthorityID))
	if err != nil {
		return err
	}
	replacement, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, rollover.ReplacementAuthorityID))
	if err != nil {
		return err
	}
	if previous.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
		replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID ||
		(replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked) ||
		finalTrust.TrustSetID != trustSet.ID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
		)
	}
	if err := s.validateRolloverTrustMaterial(
		ctx, tx, finalTrust, previous, replacement,
		domainpki.AuthorityRolloverTransitionBeginFinalTrust, operation.UpdatedAt,
	); err != nil {
		return apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionTrustLayoutInvalid, err.Error())
	}
	return s.validateAllRolloverAssignmentsRotated(ctx, tx, rollover)
}

func (s PKIStore) persistAuthorityRolloverAggregate(
	ctx context.Context,
	expectedOperationRevision uint64,
	expectedTrustSetRevision uint64,
	operation domainpki.Operation,
	previous domainpki.Authority,
	trustSet domainpki.TrustSet,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
	transition domainpki.AuthorityRolloverTransition,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := validateCASUpdate(expectedOperationRevision, operation.Revision); err != nil {
			return err
		}
		if err := validateCASUpdate(expectedTrustSetRevision, trustSet.Revision); err != nil {
			return err
		}
		if err := operation.Validate(); err != nil {
			return err
		}
		if err := previous.Validate(); err != nil {
			return err
		}
		if err := trustSet.Validate(); err != nil {
			return err
		}
		if err := validatePersistenceAudit(audit, operation.ID); err != nil {
			return err
		}
		if err := validatePersistenceMutation(mutation, audit.ResourceType, operation.ID); err != nil {
			return err
		}
		operationJSON, operationMetadata, err := s.authenticateJSON(ctx, operation)
		if err != nil {
			return err
		}
		authorityJSON, authorityMetadata, err := s.authenticateJSON(ctx, previous)
		if err != nil {
			return err
		}
		trustSetJSON, trustSetMetadata, err := s.authenticateJSON(ctx, trustSet)
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
		defer func() { logSQLiteRollback("rollback pki authority rollover aggregate", tx.Rollback()) }()
		existingOperation, err := s.loadOperation(ctx, tx.QueryRowContext(
			ctx, operationSelect+` WHERE operation_row.id = ?`, operation.ID,
		))
		if err != nil {
			return err
		}
		existingAuthority, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, previous.ID))
		if err != nil {
			return err
		}
		existingTrustSet, err := s.loadTrustSet(ctx, tx.QueryRowContext(ctx, trustSetSelect+` WHERE id = ?`, trustSet.ID))
		if err != nil {
			return err
		}
		if existingOperation.Revision != expectedOperationRevision || existingTrustSet.Revision != expectedTrustSetRevision {
			return apppki.ErrRevisionConflict
		}
		if err := domainpki.ValidateAuthorityRolloverAggregateTransition(
			existingOperation, operation, existingAuthority, previous, existingTrustSet, trustSet, transition,
		); err != nil {
			return err
		}
		rollover := operation.AuthorityRollover
		replacement, err := s.loadAuthority(ctx, tx.QueryRowContext(
			ctx, authoritySelect+` WHERE id = ?`, rollover.ReplacementAuthorityID,
		))
		if err != nil {
			return err
		}
		if existingAuthority.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
			replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID ||
			(replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked) {
			return apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
			)
		}
		trustGenerationID := rollover.OverlapTrustGenerationID
		if transition == domainpki.AuthorityRolloverTransitionComplete {
			trustGenerationID = rollover.FinalTrustGenerationID
		}
		trustGeneration, err := s.loadTrustSetGeneration(ctx, tx.QueryRowContext(
			ctx, trustSetGenerationSelect+` WHERE generation_row.id = ?`, trustGenerationID,
		))
		if err != nil {
			return err
		}
		if err := s.validateRolloverTrustMaterial(
			ctx, tx, trustGeneration, existingAuthority, replacement, transition, operation.UpdatedAt,
		); err != nil {
			return apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionTrustLayoutInvalid, err.Error(),
			)
		}
		if transition == domainpki.AuthorityRolloverTransitionComplete {
			if err := s.validateAllRolloverAssignmentsRotated(ctx, tx, rollover); err != nil {
				return err
			}
		}
		if err := insertMutation(ctx, tx, mutation, mutationJSON, mutationMetadata); err != nil {
			return err
		}
		operationResult, err := updateOperationCAS(
			ctx, tx, expectedOperationRevision, operation, operationJSON, operationMetadata,
		)
		if err != nil {
			return err
		}
		if err := requireOperationCASRow(ctx, tx, operationResult, operation.ID); err != nil {
			return err
		}
		authorityResult, err := updateRolloverAuthorityCAS(
			ctx, tx, existingAuthority, previous, authorityJSON, authorityMetadata,
		)
		if err != nil {
			return err
		}
		if applied, err := casApplied(authorityResult); err != nil {
			return err
		} else if !applied {
			return apppki.ErrRevisionConflict
		}
		trustResult, err := updateTrustSetCAS(
			ctx, tx, expectedTrustSetRevision, trustSet, trustSetJSON, trustSetMetadata,
		)
		if err != nil {
			return err
		}
		if err := requireTrustSetCASRow(ctx, tx, trustResult, trustSet.ID); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitOperationTransaction(ctx, tx)
	})
}

func (s PKIStore) validateAuthorityRolloverReferences(
	ctx context.Context,
	tx *sql.Tx,
	operation domainpki.Operation,
) error {
	rollover := operation.AuthorityRollover
	previous, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, rollover.PreviousAuthorityID))
	if err != nil {
		return err
	}
	replacement, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, rollover.ReplacementAuthorityID))
	if err != nil {
		return err
	}
	trustSet, err := s.loadTrustSet(ctx, tx.QueryRowContext(ctx, trustSetSelect+` WHERE id = ?`, rollover.TrustSetID))
	if err != nil {
		return err
	}
	overlap, err := s.loadTrustSetGeneration(ctx, tx.QueryRowContext(
		ctx, trustSetGenerationSelect+` WHERE generation_row.id = ?`, rollover.OverlapTrustGenerationID,
	))
	if err != nil {
		return err
	}
	if rollover.PreviousAuthorityGenerationID != previous.ActiveGenerationID ||
		rollover.ReplacementAuthorityGenerationID != replacement.ActiveGenerationID ||
		trustSet.StagedGenerationID != overlap.ID || overlap.TrustSetID != trustSet.ID {
		return errors.New("pki sqlite: authority rollover references incompatible persisted state")
	}
	if err := s.validateRolloverTrustMaterial(
		ctx, tx, overlap, previous, replacement,
		domainpki.AuthorityRolloverTransitionActivateOverlap, operation.CreatedAt,
	); err != nil {
		return err
	}
	switch previous.State {
	case domainpki.AuthorityStateActive, domainpki.AuthorityStateLocked, domainpki.AuthorityStateCompromised:
	default:
		return errors.New("pki sqlite: previous authority state cannot start rollover")
	}
	if replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked {
		return errors.New("pki sqlite: replacement authority state cannot start rollover")
	}
	var conflictingOperationID string
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM pki_operations
WHERE kind = ? AND status NOT IN (?, ?, ?) AND (
	trust_set_id = ? OR previous_authority_id IN (?, ?) OR replacement_authority_id IN (?, ?)
)
LIMIT 1`,
		domainpki.OperationKindAuthorityRollover,
		domainpki.OperationStatusCompleted, domainpki.OperationStatusFailed, domainpki.OperationStatusCanceled,
		rollover.TrustSetID,
		rollover.PreviousAuthorityID, rollover.ReplacementAuthorityID,
		rollover.PreviousAuthorityID, rollover.ReplacementAuthorityID,
	).Scan(&conflictingOperationID)
	if err == nil {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionResourceReserved,
			fmt.Sprintf("operation %q already reserves an authority or trust set", conflictingOperationID),
		)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for _, assignmentID := range rollover.RequiredAssignmentIDs {
		assignment, err := s.loadAssignment(ctx, tx.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, assignmentID))
		if err != nil {
			return err
		}
		if assignment.TrustSetID != trustSet.ID ||
			!assignment.Purpose.RequiresPeerTrust() ||
			(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
			return errors.New("pki sqlite: authority rollover references an ineligible assignment")
		}
	}
	if rollover.ConsumerTracking == domainpki.RolloverConsumerTrackingAllTracked {
		eligible, err := eligibleRolloverAssignmentIDs(ctx, tx, trustSet.ID)
		if err != nil {
			return err
		}
		if !slices.Equal(rollover.RequiredAssignmentIDs, eligible) {
			return errors.New("pki sqlite: all-tracked rollover assignment snapshot changed before persistence")
		}
	}
	return nil
}

func eligibleRolloverAssignmentIDs(
	ctx context.Context,
	tx *sql.Tx,
	trustSetID domainpki.TrustSetID,
) ([]domainpki.AssignmentID, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id
FROM pki_assignments
WHERE trust_set_id = ? AND purpose IN (?, ?, ?, ?) AND state IN (?, ?)
ORDER BY id`,
		trustSetID,
		domainpki.PurposeTLSClient,
		domainpki.PurposeMTLSServer,
		domainpki.PurposeMTLSClient,
		domainpki.PurposeDualRoleMTLS,
		domainpki.AssignmentStateActive,
		domainpki.AssignmentStateDegraded,
	)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close eligible rollover assignment rows", rows.Close()) }()
	result := make([]domainpki.AssignmentID, 0)
	for rows.Next() {
		var id domainpki.AssignmentID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s PKIStore) validateAllRolloverAssignmentsRotated(
	ctx context.Context,
	tx *sql.Tx,
	rollover *domainpki.AuthorityRollover,
) error {
	for _, assignmentID := range rollover.RequiredAssignmentIDs {
		assignment, err := s.loadAssignment(ctx, tx.QueryRowContext(ctx, assignmentSelect+` WHERE id = ?`, assignmentID))
		if err != nil {
			return err
		}
		if err := s.validateRolloverAssignmentRotated(ctx, tx, rollover, assignment); err != nil {
			return err
		}
	}
	return nil
}

func (s PKIStore) validateRolloverAssignmentRotated(
	ctx context.Context,
	tx *sql.Tx,
	rollover *domainpki.AuthorityRollover,
	assignment domainpki.Assignment,
) error {
	if assignment.TrustSetID != rollover.TrustSetID ||
		(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentsNotRotated, "rollover assignment is not an eligible active consumer",
		)
	}
	generation, err := s.loadGeneration(ctx, tx.QueryRowContext(
		ctx, generationSelect+` WHERE id = ?`, assignment.ActiveGenerationID,
	))
	if err != nil {
		return err
	}
	if generation.State != domainpki.CertificateStateActive ||
		generation.IssuerAuthorityID != rollover.ReplacementAuthorityID ||
		generation.IssuerGenerationID != rollover.ReplacementAuthorityGenerationID ||
		assignment.ActiveTrustGenerationID != rollover.OverlapTrustGenerationID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentsNotRotated,
			"rollover assignment has not activated a usable replacement-issued leaf with overlap trust",
		)
	}
	return nil
}

func (s PKIStore) validateRolloverTrustMaterial(
	ctx context.Context,
	tx *sql.Tx,
	trust domainpki.TrustSetGeneration,
	previous domainpki.Authority,
	replacement domainpki.Authority,
	transition domainpki.AuthorityRolloverTransition,
	now time.Time,
) error {
	previousGeneration, err := s.loadGeneration(ctx, tx.QueryRowContext(
		ctx, generationSelect+` WHERE id = ?`, previous.ActiveGenerationID,
	))
	if err != nil {
		return err
	}
	replacementGeneration, err := s.loadGeneration(ctx, tx.QueryRowContext(
		ctx, generationSelect+` WHERE id = ?`, replacement.ActiveGenerationID,
	))
	if err != nil {
		return err
	}
	material := domainpki.TrustMaterial{
		Certificates: make([]domainpki.CertificateGeneration, 0,
			len(trust.AnchorGenerationIDs)+len(trust.IntermediateGenerationIDs)),
		CRLs: make([]domainpki.CRLGeneration, 0, len(trust.CRLGenerationIDs)),
	}
	certificateIDs := make([]domainpki.GenerationID, 0,
		len(trust.AnchorGenerationIDs)+len(trust.IntermediateGenerationIDs))
	certificateIDs = append(certificateIDs, trust.AnchorGenerationIDs...)
	certificateIDs = append(certificateIDs, trust.IntermediateGenerationIDs...)
	for _, id := range certificateIDs {
		generation, err := s.loadGeneration(ctx, tx.QueryRowContext(ctx, generationSelect+` WHERE id = ?`, id))
		if err != nil {
			return err
		}
		material.Certificates = append(material.Certificates, generation)
	}
	for _, id := range trust.CRLGenerationIDs {
		generation, err := s.loadCRLGeneration(ctx, tx.QueryRowContext(
			ctx, crlGenerationSelect+` WHERE generation_row.id = ?`, id,
		))
		if err != nil {
			return err
		}
		material.CRLs = append(material.CRLs, generation)
	}
	if transition == domainpki.AuthorityRolloverTransitionActivateOverlap {
		return domainpki.ValidateAuthorityRolloverOverlapMaterial(
			trust, previous, replacement, previousGeneration, replacementGeneration, material, now,
		)
	}
	return domainpki.ValidateAuthorityRolloverFinalMaterial(
		trust, previous, replacement, previousGeneration, replacementGeneration, material, now,
	)
}

func validateAcknowledgementReferences(
	operation domainpki.Operation,
	assignment domainpki.Assignment,
	acknowledgement domainpki.ConsumerAcknowledgement,
) error {
	if operation.Kind != domainpki.OperationKindAuthorityRollover || operation.AuthorityRollover == nil ||
		operation.Status != domainpki.OperationStatusWaiting {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionWrongPhase, "operation does not accept this acknowledgement",
		)
	}
	targetGenerationID, err := operation.AuthorityRollover.ActiveAcknowledgementTarget()
	if err != nil || targetGenerationID != acknowledgement.TrustSetGenerationID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionWrongPhase, "operation does not accept this acknowledgement",
		)
	}
	if !containsAssignmentIDSorted(operation.AuthorityRollover.RequiredAssignmentIDs, acknowledgement.AssignmentID) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentIneligible, "acknowledgement assignment is not required",
		)
	}
	if assignment.ID != acknowledgement.AssignmentID || assignment.ConsumerType != acknowledgement.ConsumerType ||
		assignment.ConsumerID != acknowledgement.ConsumerID || assignment.TrustSetID != operation.AuthorityRollover.TrustSetID ||
		(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentIneligible,
			"acknowledgement consumer snapshot does not match an active assignment",
		)
	}
	return nil
}

func insertOperation(
	ctx context.Context,
	tx *sql.Tx,
	operation domainpki.Operation,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	rollover := operation.AuthorityRollover
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_operations(
	id, kind, status, revision, previous_authority_id, replacement_authority_id,
	previous_authority_generation_id, replacement_authority_generation_id,
	trust_set_id, overlap_trust_generation_id, final_trust_generation_id,
	consumer_tracking, phase, operation_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at,
	completed_at, failure
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		operation.ID, operation.Kind, operation.Status, operation.Revision,
		rollover.PreviousAuthorityID, rollover.ReplacementAuthorityID,
		rollover.PreviousAuthorityGenerationID, rollover.ReplacementAuthorityGenerationID, rollover.TrustSetID,
		rollover.OverlapTrustGenerationID, nullableString(string(rollover.FinalTrustGenerationID)),
		rollover.ConsumerTracking, rollover.Phase, encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, operation.CreatedAt.Format(time.RFC3339Nano),
		operation.UpdatedAt.Format(time.RFC3339Nano), nullableTime(operation.CompletedAt), nullableString(operation.Failure))
	if err != nil {
		return fmt.Errorf("pki sqlite: store operation: %w", err)
	}
	return nil
}

func insertOperationRequiredAssignments(ctx context.Context, tx *sql.Tx, operation domainpki.Operation) error {
	for position, assignmentID := range operation.AuthorityRollover.RequiredAssignmentIDs {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO pki_operation_required_assignments(operation_id, assignment_id, position)
VALUES (?, ?, ?)`, operation.ID, assignmentID, position); err != nil {
			return fmt.Errorf("pki sqlite: store operation required assignment: %w", err)
		}
	}
	return nil
}

func insertConsumerAcknowledgement(
	ctx context.Context,
	tx *sql.Tx,
	acknowledgement domainpki.ConsumerAcknowledgement,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	result, err := tx.ExecContext(ctx, `
INSERT INTO pki_consumer_acknowledgements(
	id, operation_id, assignment_id, consumer_type, consumer_id, kind,
	trust_set_generation_id, evidence_ref, acknowledgement_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag,
	acknowledged_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(operation_id, assignment_id, kind, trust_set_generation_id) DO NOTHING`,
		acknowledgement.ID, acknowledgement.OperationID, acknowledgement.AssignmentID,
		acknowledgement.ConsumerType, acknowledgement.ConsumerID, acknowledgement.Kind,
		acknowledgement.TrustSetGenerationID, nullableString(acknowledgement.EvidenceRef), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		acknowledgement.AcknowledgedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store consumer acknowledgement: %w", err)
	}
	inserted, err := casApplied(result)
	if err != nil {
		return err
	}
	if !inserted {
		return apppki.ErrAcknowledgementExists
	}
	return nil
}

func updateOperationCAS(
	ctx context.Context,
	tx *sql.Tx,
	expectedRevision uint64,
	operation domainpki.Operation,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) (sql.Result, error) {
	rollover := operation.AuthorityRollover
	if rollover == nil {
		return nil, errors.New("pki sqlite: authority rollover payload is required")
	}
	result, err := tx.ExecContext(ctx, `
UPDATE pki_operations SET
	status = ?, revision = ?, final_trust_generation_id = ?, phase = ?,
	operation_json = ?, metadata_schema_version = ?, metadata_algorithm = ?,
	metadata_key_version = ?, metadata_tag = ?, updated_at = ?, completed_at = ?, failure = ?
WHERE id = ? AND revision = ?`,
		operation.Status, operation.Revision, nullableString(string(rollover.FinalTrustGenerationID)), rollover.Phase,
		encoded, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		operation.UpdatedAt.Format(time.RFC3339Nano), nullableTime(operation.CompletedAt),
		nullableString(operation.Failure), operation.ID, expectedRevision)
	if err != nil {
		return nil, fmt.Errorf("pki sqlite: update operation: %w", err)
	}
	return result, nil
}

func requireOperationCASRow(
	ctx context.Context,
	tx *sql.Tx,
	result sql.Result,
	id domainpki.OperationID,
) error {
	applied, err := casApplied(result)
	if err != nil || applied {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pki_operations WHERE id = ?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.ErrNotFound
		}
		return err
	}
	return apppki.ErrRevisionConflict
}

func updateRolloverAuthorityCAS(
	ctx context.Context,
	tx *sql.Tx,
	existing domainpki.Authority,
	next domainpki.Authority,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, `
UPDATE pki_authorities SET
	state = ?, authority_json = ?, metadata_schema_version = ?, metadata_algorithm = ?,
	metadata_key_version = ?, metadata_tag = ?, updated_at = ?
WHERE id = ? AND state = ? AND active_generation_id = ? AND updated_at = ?`,
		next.State, encoded, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		next.UpdatedAt.Format(time.RFC3339Nano), existing.ID, existing.State, existing.ActiveGenerationID,
		existing.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("pki sqlite: update rollover authority: %w", err)
	}
	return result, nil
}

func (s PKIStore) loadOperation(ctx context.Context, row rowScanner) (domainpki.Operation, error) {
	var (
		id                    domainpki.OperationID
		kind                  domainpki.OperationKind
		status                domainpki.OperationStatus
		revision              int64
		previousAuthority     domainpki.AuthorityID
		replacementAuthority  domainpki.AuthorityID
		previousGeneration    domainpki.GenerationID
		replacementGeneration domainpki.GenerationID
		trustSetID            domainpki.TrustSetID
		overlapTrust          domainpki.TrustSetGenerationID
		finalTrust            sql.NullString
		consumerTracking      domainpki.RolloverConsumerTracking
		phase                 domainpki.AuthorityRolloverPhase
		encoded               []byte
		metadata              apppki.ProtectedMetadata
		createdAt             string
		updatedAt             string
		completedAt           sql.NullString
		failure               sql.NullString
		requiredAssignments   string
		requiredPositions     string
	)
	if err := row.Scan(&id, &kind, &status, &revision, &previousAuthority, &replacementAuthority,
		&previousGeneration, &replacementGeneration,
		&trustSetID, &overlapTrust, &finalTrust, &consumerTracking, &phase, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag,
		&createdAt, &updatedAt, &completedAt, &failure, &requiredAssignments, &requiredPositions); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.Operation{}, apppki.ErrNotFound
		}
		return domainpki.Operation{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.Operation{}, fmt.Errorf("pki sqlite: verify operation metadata: %w", err)
	}
	var operation domainpki.Operation
	if err := json.Unmarshal(encoded, &operation); err != nil {
		return domainpki.Operation{}, fmt.Errorf("pki sqlite: decode operation: %w", err)
	}
	if err := operation.Validate(); err != nil {
		return domainpki.Operation{}, fmt.Errorf("pki sqlite: validate stored operation: %w", err)
	}
	assignmentIDs, err := parseAssignmentIDs(requiredAssignments, requiredPositions)
	if err != nil {
		return domainpki.Operation{}, err
	}
	if operation.AuthorityRollover == nil || revision <= 0 || operation.ID != id || operation.Kind != kind ||
		operation.Status != status || operation.Revision != uint64(revision) ||
		operation.AuthorityRollover.PreviousAuthorityID != previousAuthority ||
		operation.AuthorityRollover.ReplacementAuthorityID != replacementAuthority ||
		operation.AuthorityRollover.PreviousAuthorityGenerationID != previousGeneration ||
		operation.AuthorityRollover.ReplacementAuthorityGenerationID != replacementGeneration ||
		operation.AuthorityRollover.TrustSetID != trustSetID ||
		operation.AuthorityRollover.OverlapTrustGenerationID != overlapTrust ||
		operation.AuthorityRollover.FinalTrustGenerationID != domainpki.TrustSetGenerationID(nullString(finalTrust)) ||
		operation.AuthorityRollover.ConsumerTracking != consumerTracking || operation.AuthorityRollover.Phase != phase ||
		!slicesEqualAssignmentIDs(operation.AuthorityRollover.RequiredAssignmentIDs, assignmentIDs) ||
		operation.CreatedAt.Format(time.RFC3339Nano) != createdAt || operation.UpdatedAt.Format(time.RFC3339Nano) != updatedAt ||
		formatOptionalTime(operation.CompletedAt) != nullString(completedAt) || operation.Failure != nullString(failure) {
		return domainpki.Operation{}, errors.New("pki sqlite: operation json does not match canonical columns")
	}
	return operation.Clone(), nil
}

func (s PKIStore) loadConsumerAcknowledgement(
	ctx context.Context,
	row rowScanner,
) (domainpki.ConsumerAcknowledgement, error) {
	var (
		id                   domainpki.AcknowledgementID
		operationID          domainpki.OperationID
		assignmentID         domainpki.AssignmentID
		consumerType         domainpki.ConsumerType
		consumerID           domainpki.ConsumerID
		kind                 domainpki.AcknowledgementKind
		trustSetGenerationID domainpki.TrustSetGenerationID
		evidenceRef          sql.NullString
		encoded              []byte
		metadata             apppki.ProtectedMetadata
		acknowledgedAt       string
	)
	if err := row.Scan(&id, &operationID, &assignmentID, &consumerType, &consumerID, &kind,
		&trustSetGenerationID, &evidenceRef, &encoded, &metadata.SchemaVersion,
		&metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &acknowledgedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.ConsumerAcknowledgement{}, apppki.ErrNotFound
		}
		return domainpki.ConsumerAcknowledgement{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.ConsumerAcknowledgement{}, fmt.Errorf("pki sqlite: verify acknowledgement metadata: %w", err)
	}
	var acknowledgement domainpki.ConsumerAcknowledgement
	if err := json.Unmarshal(encoded, &acknowledgement); err != nil {
		return domainpki.ConsumerAcknowledgement{}, fmt.Errorf("pki sqlite: decode acknowledgement: %w", err)
	}
	if err := acknowledgement.Validate(); err != nil {
		return domainpki.ConsumerAcknowledgement{}, fmt.Errorf("pki sqlite: validate stored acknowledgement: %w", err)
	}
	if acknowledgement.ID != id || acknowledgement.OperationID != operationID ||
		acknowledgement.AssignmentID != assignmentID || acknowledgement.ConsumerType != consumerType ||
		acknowledgement.ConsumerID != consumerID || acknowledgement.Kind != kind ||
		acknowledgement.TrustSetGenerationID != trustSetGenerationID ||
		acknowledgement.EvidenceRef != nullString(evidenceRef) ||
		acknowledgement.AcknowledgedAt.Format(time.RFC3339Nano) != acknowledgedAt {
		return domainpki.ConsumerAcknowledgement{}, errors.New("pki sqlite: acknowledgement json does not match canonical columns")
	}
	return acknowledgement, nil
}

func parseAssignmentIDs(ids, positions string) ([]domainpki.AssignmentID, error) {
	if ids == "" && positions == "" {
		return nil, nil
	}
	idParts := strings.Split(ids, ",")
	positionParts := strings.Split(positions, ",")
	if len(idParts) != len(positionParts) {
		return nil, errors.New("pki sqlite: operation assignment positions do not match ids")
	}
	result := make([]domainpki.AssignmentID, len(idParts))
	for index, rawID := range idParts {
		id := domainpki.AssignmentID(rawID)
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if positionParts[index] != fmt.Sprint(index) {
			return nil, errors.New("pki sqlite: operation assignment positions are not contiguous")
		}
		result[index] = id
	}
	return result, nil
}

func containsAssignmentIDSorted(ids []domainpki.AssignmentID, target domainpki.AssignmentID) bool {
	_, found := slices.BinarySearch(ids, target)
	return found
}

func slicesEqualAssignmentIDs(left, right []domainpki.AssignmentID) bool {
	return slices.Equal(left, right)
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.Format(time.RFC3339Nano)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339Nano)
}

func commitOperationTransaction(ctx context.Context, tx *sql.Tx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func (s PKIStore) reauthenticateOperationMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	for _, table := range []struct {
		name       string
		jsonColumn string
		resource   string
	}{
		{name: "pki_operations", jsonColumn: "operation_json", resource: "operation"},
		{name: "pki_consumer_acknowledgements", jsonColumn: "acknowledgement_json", resource: "acknowledgement"},
	} {
		query := fmt.Sprintf(`SELECT id, %s, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag FROM %s`, table.jsonColumn, table.name)
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		records, err := loadAuthenticatedMetadataRows(rows)
		if err != nil {
			return err
		}
		for _, record := range records {
			metadata, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, table.resource)
			if err != nil {
				return err
			}
			update := fmt.Sprintf(`UPDATE %s SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ? WHERE id = ?`, table.name)
			if _, err := tx.ExecContext(ctx, update, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag, record.id); err != nil {
				return err
			}
		}
	}
	return nil
}
