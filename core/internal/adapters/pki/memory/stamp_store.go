package memory

import (
	"context"
	"errors"
	"slices"
	"strings"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func (s *Store) CredentialStamp(
	ctx context.Context,
	id domainpki.StampID,
) (domainpki.CredentialStamp, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stamp, exists := s.credentialStamps[id]
	if !exists {
		return domainpki.CredentialStamp{}, apppki.ErrNotFound
	}
	return stamp.Clone(), nil
}

func (s *Store) CredentialStamps(ctx context.Context) ([]domainpki.CredentialStamp, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.CredentialStamp, 0, len(s.credentialStamps))
	for _, stamp := range s.credentialStamps {
		result = append(result, stamp.Clone())
	}
	slices.SortFunc(result, func(left, right domainpki.CredentialStamp) int {
		if left.CreatedAt.Equal(right.CreatedAt) {
			return strings.Compare(string(left.ID), string(right.ID))
		}
		return left.CreatedAt.Compare(right.CreatedAt)
	})
	return result, nil
}

func (s *Store) CreateCredentialStamp(
	ctx context.Context,
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := stamp.Validate(); err != nil {
		return err
	}
	if stamp.Status != domainpki.CredentialStampPending {
		return errors.New("pki: new credential stamp must be pending")
	}
	if err := validateCredentialStampPersistenceRecords(stamp, audit, mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	assignment, exists := s.assignments[stamp.Plan.Request.AssignmentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := domainpki.ValidateCredentialStampAssignment(
		assignment, stamp.Plan.Request,
	); err != nil {
		return err
	}
	if _, exists := s.credentialStamps[stamp.ID]; exists {
		return errors.New("pki: credential stamp already exists")
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.credentialStamps[stamp.ID] = stamp.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) UpdateCredentialStamp(
	ctx context.Context,
	expectedRevision uint64,
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentialStampPersistenceRecords(stamp, audit, mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	previous, exists := s.credentialStamps[stamp.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if previous.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if err := domainpki.ValidateCredentialStampTransition(previous, stamp); err != nil {
		return err
	}
	if stamp.Status == domainpki.CredentialStampSuperseded {
		replacement, exists := s.credentialStamps[stamp.SupersededBy]
		if !exists {
			return apppki.ErrNotFound
		}
		if err := domainpki.ValidateCredentialStampReplacement(
			previous, replacement, stamp,
		); err != nil {
			return err
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.credentialStamps[stamp.ID] = stamp.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func validateCredentialStampPersistenceRecords(
	stamp domainpki.CredentialStamp,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := stamp.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	expectedKind, expectedAction, expectedOutcome, err :=
		apppki.CredentialStampLifecycleContract(stamp.Status)
	if err != nil {
		return err
	}
	if audit.Action != expectedAction || audit.Outcome != expectedOutcome ||
		audit.ResourceType != apppki.CredentialStampResourceType ||
		audit.ResourceID != string(stamp.ID) {
		return errors.New("pki: credential stamp audit does not match state change")
	}
	if mutation.Kind != expectedKind {
		return errors.New("pki: credential stamp mutation kind does not match state change")
	}
	if mutation.ResourceType != apppki.CredentialStampResourceType {
		return errors.New("pki: credential stamp mutation resource type does not match")
	}
	return validateMemoryMutation(mutation, apppki.CredentialStampResourceType, stamp.ID)
}
