package memory

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type Store struct {
	mu                   sync.RWMutex
	authorities          map[domainpki.AuthorityID]domainpki.Authority
	generations          map[domainpki.GenerationID]domainpki.CertificateGeneration
	keys                 map[domainpki.KeyID]apppki.KeyMaterial
	counters             map[domainpki.CertificateID]uint64
	intents              map[domainpki.IssuanceID]apppki.IssuanceIntent
	intentKeys           map[string]domainpki.IssuanceID
	assignments          map[domainpki.AssignmentID]domainpki.Assignment
	trustSets            map[domainpki.TrustSetID]domainpki.TrustSet
	trustGens            map[domainpki.TrustSetGenerationID]domainpki.TrustSetGeneration
	mutations            map[domainpki.MutationID]apppki.MutationRecord
	mutationKeys         map[string]domainpki.MutationID
	revocations          map[domainpki.RevocationID]domainpki.Revocation
	revokedByGen         map[domainpki.GenerationID]domainpki.RevocationID
	crlCounters          map[domainpki.AuthorityID]uint64
	crlIntents           map[domainpki.CRLPublicationID]apppki.CRLPublicationIntent
	crlIntentKeys        map[string]domainpki.CRLPublicationID
	crlGenerations       map[domainpki.CRLGenerationID]domainpki.CRLGeneration
	operations           map[domainpki.OperationID]domainpki.Operation
	acknowledgements     map[domainpki.AcknowledgementID]domainpki.ConsumerAcknowledgement
	acknowledgementKeys  map[consumerAcknowledgementKey]domainpki.AcknowledgementID
	credentialStamps     map[domainpki.StampID]domainpki.CredentialStamp
	credentialExecutions map[domainpki.CredentialExecutionRequestID]domainpki.CredentialExecution
	exports              map[domainpki.GenerationID]bool
	audits               []apppki.AuditRecord
}

func NewStore() *Store {
	return &Store{
		authorities:          map[domainpki.AuthorityID]domainpki.Authority{},
		generations:          map[domainpki.GenerationID]domainpki.CertificateGeneration{},
		keys:                 map[domainpki.KeyID]apppki.KeyMaterial{},
		counters:             map[domainpki.CertificateID]uint64{},
		intents:              map[domainpki.IssuanceID]apppki.IssuanceIntent{},
		intentKeys:           map[string]domainpki.IssuanceID{},
		assignments:          map[domainpki.AssignmentID]domainpki.Assignment{},
		trustSets:            map[domainpki.TrustSetID]domainpki.TrustSet{},
		trustGens:            map[domainpki.TrustSetGenerationID]domainpki.TrustSetGeneration{},
		mutations:            map[domainpki.MutationID]apppki.MutationRecord{},
		mutationKeys:         map[string]domainpki.MutationID{},
		revocations:          map[domainpki.RevocationID]domainpki.Revocation{},
		revokedByGen:         map[domainpki.GenerationID]domainpki.RevocationID{},
		crlCounters:          map[domainpki.AuthorityID]uint64{},
		crlIntents:           map[domainpki.CRLPublicationID]apppki.CRLPublicationIntent{},
		crlIntentKeys:        map[string]domainpki.CRLPublicationID{},
		crlGenerations:       map[domainpki.CRLGenerationID]domainpki.CRLGeneration{},
		operations:           map[domainpki.OperationID]domainpki.Operation{},
		acknowledgements:     map[domainpki.AcknowledgementID]domainpki.ConsumerAcknowledgement{},
		acknowledgementKeys:  map[consumerAcknowledgementKey]domainpki.AcknowledgementID{},
		credentialStamps:     map[domainpki.StampID]domainpki.CredentialStamp{},
		credentialExecutions: map[domainpki.CredentialExecutionRequestID]domainpki.CredentialExecution{},
		exports:              map[domainpki.GenerationID]bool{},
	}
}

func (s *Store) MutationByKey(ctx context.Context, key string) (apppki.MutationRecord, error) {
	if err := ctx.Err(); err != nil {
		return apppki.MutationRecord{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, exists := s.mutationKeys[key]
	if !exists {
		return apppki.MutationRecord{}, apppki.ErrNotFound
	}
	return s.mutations[id].Clone(), nil
}

func (s *Store) BeginIssuance(ctx context.Context, candidate apppki.IssuanceIntent) (apppki.IssuanceIntent, bool, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if err := apppki.ValidateNewIssuanceIntent(candidate); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, exists := s.intentKeys[candidate.IdempotencyKey]; exists {
		return s.intents[id].Clone(), false, nil
	}
	if _, exists := s.intents[candidate.ID]; exists {
		return apppki.IssuanceIntent{}, false, errors.New("pki: issuance intent already exists")
	}
	intent := candidate.Clone()
	if intent.Generation == 0 {
		if s.counters[intent.CertificateID] == domainpki.MaximumSequenceNumber {
			return apppki.IssuanceIntent{}, false, errors.New("pki: certificate generation counter is exhausted")
		}
		intent.Generation = s.counters[intent.CertificateID] + 1
	} else if intent.Generation != 1 || s.counters[intent.CertificateID] != 0 {
		return apppki.IssuanceIntent{}, false, errors.New("pki: explicit issuance generation must initialize a new certificate at generation one")
	}
	if err := intent.Validate(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	s.counters[intent.CertificateID] = intent.Generation
	s.intents[intent.ID] = intent.Clone()
	s.intentKeys[intent.IdempotencyKey] = intent.ID
	return intent.Clone(), true, nil
}

func (s *Store) IssuanceByKey(ctx context.Context, key string) (apppki.IssuanceIntent, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuanceIntent{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, exists := s.intentKeys[key]
	if !exists {
		return apppki.IssuanceIntent{}, apppki.ErrNotFound
	}
	return s.intents[id].Clone(), nil
}

func (s *Store) PendingIssuances(ctx context.Context, eligibleAt, updatedBefore time.Time, limit int) ([]apppki.IssuanceIntent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if eligibleAt.IsZero() || updatedBefore.IsZero() || updatedBefore.After(eligibleAt) || limit < 1 || limit > apppki.MaximumPendingIssuanceBatch {
		return nil, errors.New("pki: invalid pending issuance query")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]apppki.IssuanceIntent, 0, limit)
	for _, intent := range s.intents {
		if intent.Status == apppki.IssuanceStatusPending && !intent.LeaseExpiresAt.After(eligibleAt) && !intent.UpdatedAt.After(updatedBefore) {
			result = append(result, intent.Clone())
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LeaseExpiresAt.Equal(result[j].LeaseExpiresAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].LeaseExpiresAt.Before(result[j].LeaseExpiresAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) ClaimIssuance(ctx context.Context, id domainpki.IssuanceID, expected apppki.IssuanceOwnership, ownerToken string, claimedAt time.Time) (apppki.IssuanceIntent, bool, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.intents[id]
	if !exists {
		return apppki.IssuanceIntent{}, false, apppki.ErrNotFound
	}
	if apppki.ValidateIssuanceOwnership(intent, expected.OwnerToken, expected.Revision) != nil || claimedAt.Before(intent.LeaseExpiresAt) {
		return intent.Clone(), false, nil
	}
	claimed, err := apppki.ClaimIssuanceIntent(intent, ownerToken, claimedAt)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	s.intents[id] = claimed.Clone()
	return claimed, true, nil
}

func (s *Store) CompleteAuthorityIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, authority domainpki.Authority, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	if err := apppki.ValidateGenerationKeyBinding(generation, material); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.intents[intentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	if intent.Kind != apppki.IssuanceKindAuthority {
		return errors.New("pki: authority completion requires an authority intent")
	}
	if err := audits.Validate(intent.Kind, generation.ID, intent.SourceGenerationID, intent.SigningAuthorityID()); err != nil {
		return err
	}
	if err := apppki.ValidateAuthorityIssuanceCompletion(intent, authority, generation, material); err != nil {
		return err
	}
	if _, exists := s.authorities[authority.ID]; exists {
		return errors.New("pki: authority already exists")
	}
	if err := s.checkGenerationConflictsLocked(generation); err != nil {
		return err
	}
	if _, exists := s.keys[material.ID]; exists {
		return errors.New("pki: key already exists")
	}
	completed, err := apppki.CompleteIssuanceIntent(intent, audits.CompletedAt())
	if err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked(audits.Records()); err != nil {
		return err
	}
	s.authorities[authority.ID] = authority.Clone()
	s.generations[generation.ID] = generation.Clone()
	s.keys[material.ID] = material.Clone()
	s.intents[intentID] = completed
	s.audits = append(s.audits, audits.Records()...)
	return nil
}

func (s *Store) CompleteCertificateIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	if err := apppki.ValidateGenerationKeyBinding(generation, material); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.intents[intentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	if intent.Kind != apppki.IssuanceKindCertificate && intent.Kind != apppki.IssuanceKindCertificateRotation {
		return errors.New("pki: certificate completion requires a new-key certificate intent")
	}
	if err := audits.Validate(intent.Kind, generation.ID, intent.SourceGenerationID, intent.SigningAuthorityID()); err != nil {
		return err
	}
	if err := apppki.ValidateIssuanceCompletion(intent, generation); err != nil {
		return err
	}
	if intent.Kind == apppki.IssuanceKindCertificateRotation {
		source, exists := s.generations[intent.SourceGenerationID]
		if !exists {
			return errors.New("pki: rotation source generation does not exist")
		}
		if err := apppki.ValidateLifecycleSourceEligibility(source); err != nil {
			return err
		}
		if err := apppki.ValidateLifecycleGenerationTransition(intent.Kind, source, generation); err != nil {
			return err
		}
	}
	if err := s.checkGenerationConflictsLocked(generation); err != nil {
		return err
	}
	if _, exists := s.keys[material.ID]; exists {
		return errors.New("pki: key already exists")
	}
	completed, err := apppki.CompleteIssuanceIntent(intent, audits.CompletedAt())
	if err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked(audits.Records()); err != nil {
		return err
	}
	s.generations[generation.ID] = generation.Clone()
	s.keys[material.ID] = material.Clone()
	s.intents[intentID] = completed
	s.audits = append(s.audits, audits.Records()...)
	return nil
}

func (s *Store) FailIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, failure string, updatedAt time.Time, audit apppki.AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.intents[intentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	failed, err := apppki.FailIssuanceIntent(intent, failure, updatedAt)
	if err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.intents[intentID] = failed
	s.audits = append(s.audits, audit.Clone())
	return nil
}

func (s *Store) CompleteCertificateRenewal(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	if err := apppki.ValidateGenerationKeyBinding(generation, material); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.intents[intentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	if err := audits.Validate(intent.Kind, generation.ID, intent.SourceGenerationID, intent.SigningAuthorityID()); err != nil {
		return err
	}
	if intent.Kind != apppki.IssuanceKindCertificateRenewal {
		return errors.New("pki: renewal completion requires a renewal intent")
	}
	if err := apppki.ValidateIssuanceCompletion(intent, generation); err != nil {
		return err
	}
	source, exists := s.generations[intent.SourceGenerationID]
	if !exists {
		return errors.New("pki: renewal source generation does not exist")
	}
	if err := apppki.ValidateLifecycleSourceEligibility(source); err != nil {
		return err
	}
	if err := apppki.ValidateLifecycleGenerationTransition(intent.Kind, source, generation); err != nil {
		return err
	}
	if err := s.checkGenerationConflictsLocked(generation); err != nil {
		return err
	}
	existing, exists := s.keys[material.ID]
	if !exists || !apppki.KeyMaterialsEqual(existing, material) {
		return errors.New("pki: renewal key does not match persisted key material")
	}
	completed, err := apppki.CompleteIssuanceIntent(intent, audits.CompletedAt())
	if err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked(audits.Records()); err != nil {
		return err
	}
	s.generations[generation.ID] = generation.Clone()
	s.intents[intentID] = completed
	s.audits = append(s.audits, audits.Records()...)
	return nil
}

func (s *Store) checkGenerationConflictsLocked(generation domainpki.CertificateGeneration) error {
	if _, exists := s.generations[generation.ID]; exists {
		return errors.New("pki: certificate generation already exists")
	}
	for _, existing := range s.generations {
		if existing.CertificateID == generation.CertificateID && existing.Generation == generation.Generation {
			return errors.New("pki: certificate generation number already exists")
		}
	}
	if s.serialExistsLocked(generation) {
		return errors.New("pki: certificate serial number already exists for issuer generation")
	}
	return nil
}

func (s *Store) serialExistsLocked(candidate domainpki.CertificateGeneration) bool {
	candidateScope := candidate.IssuerGenerationID
	if candidateScope == "" {
		candidateScope = candidate.ID
	}
	for _, existing := range s.generations {
		existingScope := existing.IssuerGenerationID
		if existingScope == "" {
			existingScope = existing.ID
		}
		if existingScope == candidateScope && existing.Template.SerialNumber == candidate.Template.SerialNumber {
			return true
		}
	}
	return false
}

func (s *Store) Authority(ctx context.Context, id domainpki.AuthorityID) (domainpki.Authority, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.Authority{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	authority, ok := s.authorities[id]
	if !ok {
		return domainpki.Authority{}, apppki.ErrNotFound
	}
	return authority.Clone(), nil
}

func (s *Store) Authorities(ctx context.Context) ([]domainpki.Authority, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.Authority, 0, len(s.authorities))
	for _, authority := range s.authorities {
		result = append(result, authority.Clone())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Store) Generation(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	generation, ok := s.generations[id]
	if !ok {
		return domainpki.CertificateGeneration{}, apppki.ErrNotFound
	}
	return generation.Clone(), nil
}

func (s *Store) Generations(ctx context.Context, id domainpki.CertificateID) ([]domainpki.CertificateGeneration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.CertificateGeneration, 0)
	for _, generation := range s.generations {
		if generation.CertificateID == id {
			result = append(result, generation.Clone())
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Generation < result[j].Generation })
	if len(result) == 0 {
		return nil, apppki.ErrNotFound
	}
	return result, nil
}

func (s *Store) CertificateGenerations(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.CertificateGeneration, 0, len(s.generations))
	for _, generation := range s.generations {
		result = append(result, generation.Clone())
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CertificateID == result[j].CertificateID {
			return result[i].Generation < result[j].Generation
		}
		return result[i].CertificateID < result[j].CertificateID
	})
	return result, nil
}

func (s *Store) CreateAssignment(ctx context.Context, assignment domainpki.Assignment, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := assignment.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(assignment.ID) {
		return errors.New("pki: assignment audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, assignment.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if _, exists := s.assignments[assignment.ID]; exists {
		return errors.New("pki: assignment already exists")
	}
	if operation, reserved := s.liveAuthorityRolloverForTrustSetLocked(assignment.TrustSetID); reserved {
		return apppki.RejectRolloverReservedMutation(
			operation, apppki.RolloverReservationAssignmentBind,
		)
	}
	for _, existing := range s.assignments {
		if existing.State != domainpki.AssignmentStateRetired &&
			existing.ConsumerType == assignment.ConsumerType && existing.ConsumerID == assignment.ConsumerID && existing.Purpose == assignment.Purpose {
			return errors.New("pki: assignment consumer purpose already exists")
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.assignments[assignment.ID] = assignment
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) Assignment(ctx context.Context, id domainpki.AssignmentID) (domainpki.Assignment, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.Assignment{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.Assignment{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	assignment, exists := s.assignments[id]
	if !exists {
		return domainpki.Assignment{}, apppki.ErrNotFound
	}
	return assignment, nil
}

func (s *Store) Assignments(ctx context.Context) ([]domainpki.Assignment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.Assignment, 0, len(s.assignments))
	for _, assignment := range s.assignments {
		result = append(result, assignment)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Store) Revocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.Revocation{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.Revocation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	revocation, exists := s.revocations[id]
	if !exists {
		return domainpki.Revocation{}, apppki.ErrNotFound
	}
	return revocation, nil
}

func (s *Store) RevocationForGeneration(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.Revocation{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.Revocation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	revocationID, exists := s.revokedByGen[id]
	if !exists {
		return domainpki.Revocation{}, apppki.ErrNotFound
	}
	return s.revocations[revocationID], nil
}

func (s *Store) Revocations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
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
	result := make([]domainpki.Revocation, 0)
	for _, revocation := range s.revocations {
		if revocation.IssuerAuthorityID == id {
			result = append(result, revocation)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].RecordedAt.Equal(result[j].RecordedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].RecordedAt.Before(result[j].RecordedAt)
	})
	return result, nil
}

func (s *Store) RecordRevocation(
	ctx context.Context,
	revoked domainpki.CertificateGeneration,
	revocation domainpki.Revocation,
	affected []domainpki.Assignment,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := apppki.ValidateRevocationCommit(revoked, revocation, affected, audit, mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if _, exists := s.revocations[revocation.ID]; exists {
		return errors.New("pki: revocation already exists")
	}
	if _, exists := s.revokedByGen[revocation.GenerationID]; exists {
		return errors.New("pki: certificate generation is already revoked")
	}
	current, exists := s.generations[revocation.GenerationID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := domainpki.ValidateRevocationTransition(current, revoked, revocation); err != nil {
		return err
	}
	assignments := make([]domainpki.Assignment, 0, len(s.assignments))
	for _, assignment := range s.assignments {
		assignments = append(assignments, assignment)
	}
	if err := domainpki.ValidateGenerationRevocationAssignments(
		assignments, revocation.GenerationID, revocation.RecordedAt, affected,
	); err != nil {
		return err
	}
	s.generations[revoked.ID] = revoked.Clone()
	s.revocations[revocation.ID] = revocation
	s.revokedByGen[revocation.GenerationID] = revocation.ID
	for _, assignment := range affected {
		s.assignments[assignment.ID] = assignment
	}
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) UpdateAssignment(ctx context.Context, expectedRevision uint64, assignment domainpki.Assignment, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMemoryCASUpdate(expectedRevision, assignment.Revision); err != nil {
		return err
	}
	if err := assignment.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(assignment.ID) {
		return errors.New("pki: assignment audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, assignment.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existing, exists := s.assignments[assignment.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if !sameAssignmentBinding(existing, assignment) {
		return errors.New("pki: assignment binding is immutable")
	}
	if operation, reserved := s.liveAuthorityRolloverForTrustSetLocked(assignment.TrustSetID); reserved {
		var generation domainpki.CertificateGeneration
		var action apppki.RolloverReservationAction
		switch mutation.Kind {
		case apppki.MutationAssignmentStage:
			action = apppki.RolloverReservationAssignmentStage
			generation, exists = s.generations[assignment.StagedGenerationID]
		case apppki.MutationAssignmentActivate:
			action = apppki.RolloverReservationAssignmentActivate
			generation, exists = s.generations[assignment.ActiveGenerationID]
		default:
			return apppki.RejectRolloverReservedMutation(
				operation, apppki.RolloverReservationAssignmentUnbind,
			)
		}
		if !exists {
			return apppki.ErrNotFound
		}
		if err := apppki.ValidateRolloverAssignmentReservation(
			operation, action, existing, assignment, generation,
		); err != nil {
			return err
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.assignments[assignment.ID] = assignment
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func sameAssignmentBinding(left, right domainpki.Assignment) bool {
	return left.ID == right.ID && left.Purpose == right.Purpose &&
		left.ConsumerType == right.ConsumerType && left.ConsumerID == right.ConsumerID &&
		left.ProfileID == right.ProfileID && left.TrustSetID == right.TrustSetID &&
		left.RotationPolicyID == right.RotationPolicyID
}

func validateMemoryMutation[T ~string](mutation apppki.MutationRecord, resourceType string, resourceID T) error {
	if err := mutation.Validate(); err != nil {
		return err
	}
	if mutation.ResourceType != resourceType || mutation.ResourceID != string(resourceID) {
		return errors.New("pki: mutation resource does not match state change")
	}
	return nil
}

func (s *Store) validateMutationAvailableLocked(mutation apppki.MutationRecord) error {
	if _, exists := s.mutationKeys[mutation.IdempotencyKey]; exists {
		return apppki.ErrMutationExists
	}
	if _, exists := s.mutations[mutation.ID]; exists {
		return errors.New("pki: mutation id already exists")
	}
	return nil
}

func (s *Store) recordMutationLocked(mutation apppki.MutationRecord) {
	s.mutations[mutation.ID] = mutation.Clone()
	s.mutationKeys[mutation.IdempotencyKey] = mutation.ID
}

func (s *Store) validateAuditIDsAvailableLocked(records []apppki.AuditRecord) error {
	ids := make(map[string]struct{}, len(s.audits)+len(records))
	for _, existing := range s.audits {
		ids[existing.ID] = struct{}{}
	}
	for _, record := range records {
		if _, exists := ids[record.ID]; exists {
			return errors.New("pki: audit record id already exists")
		}
		ids[record.ID] = struct{}{}
	}
	return nil
}

func (s *Store) CreateTrustSet(ctx context.Context, trustSet domainpki.TrustSet, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := trustSet.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(trustSet.ID) {
		return errors.New("pki: trust set audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if _, exists := s.trustSets[trustSet.ID]; exists {
		return errors.New("pki: trust set already exists")
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.trustSets[trustSet.ID] = trustSet
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) TrustSet(ctx context.Context, id domainpki.TrustSetID) (domainpki.TrustSet, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.TrustSet{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.TrustSet{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	trustSet, exists := s.trustSets[id]
	if !exists {
		return domainpki.TrustSet{}, apppki.ErrNotFound
	}
	return trustSet, nil
}

func (s *Store) TrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domainpki.TrustSet, 0, len(s.trustSets))
	for _, trustSet := range s.trustSets {
		result = append(result, trustSet)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Store) TrustSetGeneration(ctx context.Context, id domainpki.TrustSetGenerationID) (domainpki.TrustSetGeneration, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.TrustSetGeneration{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.TrustSetGeneration{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	generation, exists := s.trustGens[id]
	if !exists {
		return domainpki.TrustSetGeneration{}, apppki.ErrNotFound
	}
	return generation.Clone(), nil
}

func (s *Store) TrustSetGenerations(ctx context.Context, id domainpki.TrustSetID) ([]domainpki.TrustSetGeneration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.trustSets[id]; !exists {
		return nil, apppki.ErrNotFound
	}
	result := make([]domainpki.TrustSetGeneration, 0)
	for _, generation := range s.trustGens {
		if generation.TrustSetID == id {
			result = append(result, generation.Clone())
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Generation < result[j].Generation })
	return result, nil
}

func (s *Store) StageTrustSetGeneration(ctx context.Context, expectedRevision uint64, trustSet domainpki.TrustSet, generation domainpki.TrustSetGeneration, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMemoryCASUpdate(expectedRevision, trustSet.Revision); err != nil {
		return err
	}
	if err := trustSet.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if generation.TrustSetID != trustSet.ID || trustSet.StagedGenerationID != generation.ID {
		return errors.New("pki: staged trust generation does not match its trust set")
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(trustSet.ID) {
		return errors.New("pki: trust set audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existing, exists := s.trustSets[trustSet.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if operation, reserved := s.liveAuthorityRolloverForTrustSetLocked(trustSet.ID); reserved {
		if err := apppki.ValidateRolloverTrustSetReservation(
			operation, apppki.RolloverReservationTrustSetStage, existing, trustSet, generation,
		); err != nil {
			return err
		}
		rollover := operation.AuthorityRollover
		previous, previousExists := s.authorities[rollover.PreviousAuthorityID]
		replacement, replacementExists := s.authorities[rollover.ReplacementAuthorityID]
		if !previousExists || !replacementExists {
			return apppki.ErrNotFound
		}
		if err := s.validateRolloverTrustMaterialLocked(
			generation, previous, replacement,
			domainpki.AuthorityRolloverTransitionComplete, mutation.CreatedAt,
		); err != nil {
			return apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionTrustLayoutInvalid, err.Error(),
			)
		}
	}
	if _, exists := s.trustGens[generation.ID]; exists {
		return errors.New("pki: trust set generation already exists")
	}
	for _, existingGeneration := range s.trustGens {
		if existingGeneration.TrustSetID == generation.TrustSetID && existingGeneration.Generation == generation.Generation {
			return errors.New("pki: trust set generation number already exists")
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.trustGens[generation.ID] = generation.Clone()
	s.trustSets[trustSet.ID] = trustSet
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) UpdateTrustSet(ctx context.Context, expectedRevision uint64, trustSet domainpki.TrustSet, audit apppki.AuditRecord, mutation apppki.MutationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMemoryCASUpdate(expectedRevision, trustSet.Revision); err != nil {
		return err
	}
	if err := trustSet.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(trustSet.ID) {
		return errors.New("pki: trust set audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, trustSet.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existing, exists := s.trustSets[trustSet.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if operation, reserved := s.liveAuthorityRolloverForTrustSetLocked(trustSet.ID); reserved {
		return apppki.RejectRolloverReservedMutation(
			operation, apppki.RolloverReservationTrustSetActivate,
		)
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	s.trustSets[trustSet.ID] = trustSet
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func validateMemoryCASUpdate(expectedRevision, nextRevision uint64) error {
	if expectedRevision == 0 || expectedRevision == domainpki.MaximumSequenceNumber || nextRevision != expectedRevision+1 {
		return errors.New("pki: invalid revision update")
	}
	return nil
}

func (s *Store) LoadKey(ctx context.Context, id domainpki.KeyID) (apppki.KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	material, ok := s.keys[id]
	if !ok {
		return apppki.KeyMaterial{}, apppki.ErrNotFound
	}
	return material.Clone(), nil
}

func (s *Store) DeleteKey(ctx context.Context, id domainpki.KeyID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, generation := range s.generations {
		if generation.KeyID == id {
			return errors.New("pki: key is referenced by a certificate generation")
		}
	}
	if _, ok := s.keys[id]; !ok {
		return apppki.ErrNotFound
	}
	delete(s.keys, id)
	return nil
}

func (s *Store) AllowPrivateExport(id domainpki.GenerationID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exports[id] = true
}

func (s *Store) DenyPrivateExport(id domainpki.GenerationID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.exports, id)
}

func (s *Store) AuthorizePrivateKeyExport(ctx context.Context, id domainpki.GenerationID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.exports[id] {
		return errors.New("pki: private key export is not authorized")
	}
	return nil
}

func (s *Store) AppendPKIAudit(ctx context.Context, record apppki.AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{record}); err != nil {
		return err
	}
	s.audits = append(s.audits, record.Clone())
	return nil
}

func (s *Store) AuditRecords() []apppki.AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]apppki.AuditRecord, len(s.audits))
	for index, record := range s.audits {
		result[index] = record.Clone()
	}
	return result
}

var _ apppki.Persistence = (*Store)(nil)
var _ apppki.ExportAuthorizer = (*Store)(nil)
var _ apppki.AuditSink = (*Store)(nil)
