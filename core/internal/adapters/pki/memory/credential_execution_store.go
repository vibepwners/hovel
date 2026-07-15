package memory

import (
	"context"
	"errors"
	"slices"
	"strings"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func (s *Store) CredentialExecution(
	ctx context.Context,
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	execution, exists := s.credentialExecutions[id]
	if !exists {
		return domainpki.CredentialExecution{}, apppki.ErrNotFound
	}
	return execution.Clone(), nil
}

func (s *Store) CredentialExecutions(ctx context.Context) ([]domainpki.CredentialExecution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.CredentialExecution, 0, len(s.credentialExecutions))
	for _, execution := range s.credentialExecutions {
		result = append(result, execution.Clone())
	}
	slices.SortFunc(result, func(left, right domainpki.CredentialExecution) int {
		if left.CreatedAt.Equal(right.CreatedAt) {
			return strings.Compare(string(left.ID), string(right.ID))
		}
		return left.CreatedAt.Compare(right.CreatedAt)
	})
	return result, nil
}

func (s *Store) CreateCredentialExecution(
	ctx context.Context,
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if execution.Status != domainpki.CredentialExecutionPending {
		return errors.New("pki: new credential execution must be pending")
	}
	if err := validateCredentialExecutionPersistenceRecords(execution, audit, mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if execution.Plan.Kind != domainpki.CredentialExecutionEncoding {
		assignment, exists := s.assignments[execution.Plan.AssignmentID]
		if !exists {
			return apppki.ErrNotFound
		}
		if err := domainpki.ValidateCredentialExecutionAssignment(assignment, execution.Plan); err != nil {
			return err
		}
	}
	if _, exists := s.credentialExecutions[execution.ID]; exists {
		return errors.New("pki: credential execution already exists")
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.credentialExecutions[execution.ID] = execution.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) UpdateCredentialExecution(
	ctx context.Context,
	expectedRevision uint64,
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentialExecutionPersistenceRecords(execution, audit, mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	previous, exists := s.credentialExecutions[execution.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if previous.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if err := domainpki.ValidateCredentialExecutionTransition(previous, execution); err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.credentialExecutions[execution.ID] = execution.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func validateCredentialExecutionPersistenceRecords(
	execution domainpki.CredentialExecution,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := execution.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	expectedKind, expectedAction, expectedOutcome, err :=
		apppki.CredentialExecutionLifecycleContract(execution.Status)
	if err != nil {
		return err
	}
	if audit.Action != expectedAction || audit.Outcome != expectedOutcome ||
		audit.ResourceType != apppki.CredentialExecutionResourceType ||
		audit.ResourceID != string(execution.ID) {
		return errors.New("pki: credential execution audit does not match state change")
	}
	if mutation.Kind != expectedKind ||
		mutation.ResourceType != apppki.CredentialExecutionResourceType {
		return errors.New("pki: credential execution mutation does not match state change")
	}
	return validateMemoryMutation(
		mutation, apppki.CredentialExecutionResourceType, execution.ID,
	)
}
