package memory

import (
	"context"
	"errors"
	"sort"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func (s *Store) BeginCRLPublication(
	ctx context.Context,
	candidate apppki.CRLPublicationIntent,
	revocations []domainpki.Revocation,
) (apppki.CRLPublicationIntent, bool, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := apppki.ValidateNewCRLPublicationIntent(candidate); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, exists := s.crlIntentKeys[candidate.IdempotencyKey]; exists {
		return s.crlIntents[id].Clone(), false, nil
	}
	if _, exists := s.crlIntents[candidate.ID]; exists {
		return apppki.CRLPublicationIntent{}, false, errors.New("pki: crl publication intent already exists")
	}
	authority, exists := s.authorities[candidate.AuthorityID]
	if !exists {
		return apppki.CRLPublicationIntent{}, false, apppki.ErrNotFound
	}
	issuer, exists := s.generations[candidate.IssuerGenerationID]
	if !exists {
		return apppki.CRLPublicationIntent{}, false, apppki.ErrNotFound
	}
	if authority.ActiveGenerationID != issuer.ID || issuer.OwningAuthorityID != authority.ID ||
		issuer.State != domainpki.CertificateStateActive ||
		issuer.Template.KeyUsage&domainpki.KeyUsageCRLSign == 0 ||
		!candidate.SignatureAlgorithm.CompatibleWith(issuer.Template.Key.Algorithm) {
		return apppki.CRLPublicationIntent{}, false, errors.New("pki: crl publication issuer is not the active authorized authority generation")
	}
	currentRevocations := make([]domainpki.Revocation, 0, len(s.revocations))
	for _, revocation := range s.revocations {
		currentRevocations = append(currentRevocations, revocation)
	}
	if err := apppki.ValidateCRLRevocationSnapshot(candidate, currentRevocations); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := apppki.ValidateCRLRevocationSnapshot(candidate, revocations); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if s.crlCounters[candidate.AuthorityID] == domainpki.MaximumSequenceNumber {
		return apppki.CRLPublicationIntent{}, false, errors.New("pki: crl number counter is exhausted")
	}
	intent := candidate.Clone()
	intent.Number = s.crlCounters[candidate.AuthorityID] + 1
	if err := intent.Validate(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	s.crlCounters[intent.AuthorityID] = intent.Number
	s.crlIntents[intent.ID] = intent.Clone()
	s.crlIntentKeys[intent.IdempotencyKey] = intent.ID
	return intent.Clone(), true, nil
}

func (s *Store) CRLPublicationByKey(ctx context.Context, key string) (apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, exists := s.crlIntentKeys[key]
	if !exists {
		return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
	}
	return s.crlIntents[id].Clone(), nil
}

func (s *Store) CRLPublication(ctx context.Context, id domainpki.CRLPublicationID) (apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := id.Validate(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
	}
	return intent.Clone(), nil
}

func (s *Store) CRLPublications(ctx context.Context, id domainpki.AuthorityID) ([]apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.authorities[id]; !exists {
		return nil, apppki.ErrNotFound
	}
	result := make([]apppki.CRLPublicationIntent, 0)
	for _, intent := range s.crlIntents {
		if intent.AuthorityID == id {
			result = append(result, intent.Clone())
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Number == result[right].Number {
			return result[left].ID < result[right].ID
		}
		return result[left].Number < result[right].Number
	})
	return result, nil
}

func (s *Store) PendingCRLPublications(
	ctx context.Context,
	eligibleAt time.Time,
	updatedBefore time.Time,
	limit int,
) ([]apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if eligibleAt.IsZero() || updatedBefore.IsZero() || updatedBefore.After(eligibleAt) ||
		limit < 1 || limit > apppki.MaximumPendingCRLPublicationBatch {
		return nil, errors.New("pki: pending crl publication query is invalid")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]apppki.CRLPublicationIntent, 0, limit)
	for _, intent := range s.crlIntents {
		if intent.Status == apppki.CRLPublicationStatusPending &&
			!intent.LeaseExpiresAt.After(eligibleAt) && !intent.UpdatedAt.After(updatedBefore) {
			result = append(result, intent.Clone())
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].LeaseExpiresAt.Equal(result[right].LeaseExpiresAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].LeaseExpiresAt.Before(result[right].LeaseExpiresAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) ClaimCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	expected apppki.CRLPublicationOwnership,
	ownerToken string,
	claimedAt time.Time,
) (apppki.CRLPublicationIntent, bool, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.CRLPublicationIntent{}, false, apppki.ErrNotFound
	}
	if apppki.ValidateCRLPublicationOwnership(intent, expected) != nil || claimedAt.UTC().Truncate(time.Second).Before(intent.LeaseExpiresAt) {
		return intent.Clone(), false, nil
	}
	claimed, err := apppki.ClaimCRLPublicationIntent(intent, ownerToken, claimedAt)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	s.crlIntents[id] = claimed.Clone()
	return claimed.Clone(), true, nil
}

func (s *Store) StartCRLPublicationSigning(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	startedAt time.Time,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
	}
	if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := apppki.ValidateCRLSigningAttemptAudit(intent, audit); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if !audit.CreatedAt.UTC().Truncate(time.Second).Equal(startedAt.UTC().Truncate(time.Second)) {
		return apppki.CRLPublicationIntent{}, errors.New("pki: crl signing start and audit times differ")
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	started, err := apppki.StartCRLPublicationSigningIntent(intent, startedAt)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.crlIntents[id] = started.Clone()
	s.audits = append(s.audits, audit.Clone())
	return started.Clone(), nil
}

func (s *Store) RenewCRLPublicationLease(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	renewedAt time.Time,
) (apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
	}
	if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	renewed, err := apppki.RenewCRLPublicationLeaseIntent(intent, renewedAt)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.crlIntents[id] = renewed.Clone()
	return renewed.Clone(), nil
}

func (s *Store) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
	}
	if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := apppki.ValidateCRLSigningConfirmedAudit(intent, checkpoint, audit); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	signed, err := apppki.CheckpointCRLPublicationSignedIntent(intent, checkpoint)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if err := ctx.Err(); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	s.crlIntents[id] = signed.Clone()
	s.audits = append(s.audits, audit.Clone())
	return signed.Clone(), nil
}

func (s *Store) CompleteCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	generation domainpki.CRLGeneration,
	audit apppki.AuditRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
		return err
	}
	if err := apppki.ValidateCRLPublicationCompletion(intent, generation); err != nil {
		return err
	}
	if err := apppki.ValidateCRLPublicationAudit(intent, generation, audit); err != nil {
		return err
	}
	if _, exists := s.crlGenerations[generation.ID]; exists {
		return errors.New("pki: crl generation already exists")
	}
	for _, existing := range s.crlGenerations {
		if existing.AuthorityID == generation.AuthorityID && existing.Number == generation.Number {
			return errors.New("pki: crl number already exists for authority")
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	completed, err := apppki.CompleteCRLPublicationIntent(intent, audit.CreatedAt)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.crlGenerations[generation.ID] = generation.Clone()
	s.crlIntents[id] = completed
	s.audits = append(s.audits, audit.Clone())
	return nil
}

func (s *Store) FailCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	failure string,
	failedAt time.Time,
	stage apppki.CRLPublicationFailureStage,
	audit apppki.AuditRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.crlIntents[id]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
		return err
	}
	if err := apppki.ValidateCRLPublicationFailureAudit(intent, stage, audit); err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	failed, err := apppki.FailCRLPublicationIntent(intent, failure, failedAt)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.crlIntents[id] = failed
	s.audits = append(s.audits, audit.Clone())
	return nil
}

func (s *Store) CRLGeneration(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.CRLGeneration{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.CRLGeneration{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	generation, exists := s.crlGenerations[id]
	if !exists {
		return domainpki.CRLGeneration{}, apppki.ErrNotFound
	}
	return generation.Clone(), nil
}

func (s *Store) CRLGenerations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.authorities[id]; !exists {
		return nil, apppki.ErrNotFound
	}
	result := make([]domainpki.CRLGeneration, 0)
	for _, generation := range s.crlGenerations {
		if generation.AuthorityID == id {
			result = append(result, generation.Clone())
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Number == result[right].Number {
			return result[left].ID < result[right].ID
		}
		return result[left].Number < result[right].Number
	})
	return result, nil
}
