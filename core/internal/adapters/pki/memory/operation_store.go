package memory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type consumerAcknowledgementKey struct {
	operationID          domainpki.OperationID
	assignmentID         domainpki.AssignmentID
	kind                 domainpki.AcknowledgementKind
	trustSetGenerationID domainpki.TrustSetGenerationID
}

func acknowledgementKey(acknowledgement domainpki.ConsumerAcknowledgement) consumerAcknowledgementKey {
	return consumerAcknowledgementKey{
		operationID: acknowledgement.OperationID, assignmentID: acknowledgement.AssignmentID,
		kind: acknowledgement.Kind, trustSetGenerationID: acknowledgement.TrustSetGenerationID,
	}
}

func (s *Store) PKIOperation(ctx context.Context, id domainpki.OperationID) (domainpki.Operation, error) {
	if err := ctx.Err(); err != nil {
		return domainpki.Operation{}, err
	}
	if err := id.Validate(); err != nil {
		return domainpki.Operation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return domainpki.Operation{}, err
	}
	operation, exists := s.operations[id]
	if !exists {
		return domainpki.Operation{}, apppki.ErrNotFound
	}
	return operation.Clone(), nil
}

func (s *Store) PKIOperations(ctx context.Context) ([]domainpki.Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]domainpki.Operation, 0, len(s.operations))
	for _, operation := range s.operations {
		result = append(result, operation.Clone())
	}
	slices.SortFunc(result, func(left, right domainpki.Operation) int {
		if left.CreatedAt.Equal(right.CreatedAt) {
			return strings.Compare(string(left.ID), string(right.ID))
		}
		return left.CreatedAt.Compare(right.CreatedAt)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) ConsumerAcknowledgements(
	ctx context.Context,
	id domainpki.OperationID,
) ([]domainpki.ConsumerAcknowledgement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, exists := s.operations[id]; !exists {
		return nil, apppki.ErrNotFound
	}
	result := make([]domainpki.ConsumerAcknowledgement, 0)
	for _, acknowledgement := range s.acknowledgements {
		if acknowledgement.OperationID == id {
			result = append(result, acknowledgement)
		}
	}
	slices.SortFunc(result, func(left, right domainpki.ConsumerAcknowledgement) int {
		if left.AcknowledgedAt.Equal(right.AcknowledgedAt) {
			return strings.Compare(string(left.ID), string(right.ID))
		}
		return left.AcknowledgedAt.Compare(right.AcknowledgedAt)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) CreateAuthorityRollover(
	ctx context.Context,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := operation.Validate(); err != nil {
		return err
	}
	if operation.Kind != domainpki.OperationKindAuthorityRollover || operation.AuthorityRollover == nil {
		return errors.New("pki: operation is not an authority rollover")
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(operation.ID) {
		return errors.New("pki: authority rollover audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, operation.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if _, exists := s.operations[operation.ID]; exists {
		return errors.New("pki: operation already exists")
	}
	rollover := operation.AuthorityRollover
	previous, previousExists := s.authorities[rollover.PreviousAuthorityID]
	replacement, replacementExists := s.authorities[rollover.ReplacementAuthorityID]
	trustSet, trustSetExists := s.trustSets[rollover.TrustSetID]
	overlap, overlapExists := s.trustGens[rollover.OverlapTrustGenerationID]
	if !previousExists || !replacementExists || !trustSetExists || !overlapExists {
		return apppki.ErrNotFound
	}
	if rollover.PreviousAuthorityGenerationID != previous.ActiveGenerationID ||
		rollover.ReplacementAuthorityGenerationID != replacement.ActiveGenerationID ||
		trustSet.StagedGenerationID != overlap.ID || overlap.TrustSetID != trustSet.ID {
		return errors.New("pki: authority rollover references incompatible persisted state")
	}
	if err := s.validateRolloverTrustMaterialLocked(
		overlap, previous, replacement, domainpki.AuthorityRolloverTransitionActivateOverlap, operation.CreatedAt,
	); err != nil {
		return err
	}
	switch previous.State {
	case domainpki.AuthorityStateActive, domainpki.AuthorityStateLocked, domainpki.AuthorityStateCompromised:
	default:
		return errors.New("pki: previous authority state cannot start rollover")
	}
	if replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked {
		return errors.New("pki: replacement authority state cannot start rollover")
	}
	for _, assignmentID := range rollover.RequiredAssignmentIDs {
		assignment, exists := s.assignments[assignmentID]
		if !exists || assignment.TrustSetID != trustSet.ID ||
			!assignment.Purpose.RequiresPeerTrust() ||
			(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
			return errors.New("pki: authority rollover references an ineligible assignment")
		}
	}
	if rollover.ConsumerTracking == domainpki.RolloverConsumerTrackingAllTracked &&
		!slices.Equal(rollover.RequiredAssignmentIDs, s.eligibleRolloverAssignmentIDsLocked(trustSet.ID)) {
		return errors.New("pki: all-tracked rollover assignment snapshot changed before persistence")
	}
	for _, existing := range s.operations {
		if rolloverResourcesOverlap(existing, operation) {
			return apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionResourceReserved,
				"authority or trust set already has a live rollover operation",
			)
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operations[operation.ID] = operation.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) RecordConsumerAcknowledgement(
	ctx context.Context,
	acknowledgement domainpki.ConsumerAcknowledgement,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(acknowledgement.ID) {
		return errors.New("pki: acknowledgement audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, acknowledgement.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	if _, exists := s.acknowledgements[acknowledgement.ID]; exists {
		return errors.New("pki: acknowledgement id already exists")
	}
	if _, exists := s.acknowledgementKeys[acknowledgementKey(acknowledgement)]; exists {
		return apppki.ErrAcknowledgementExists
	}
	operation, exists := s.operations[acknowledgement.OperationID]
	if !exists {
		return apppki.ErrNotFound
	}
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
	if !containsAssignmentID(operation.AuthorityRollover.RequiredAssignmentIDs, acknowledgement.AssignmentID) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentIneligible, "acknowledgement assignment is not required",
		)
	}
	assignment, exists := s.assignments[acknowledgement.AssignmentID]
	if !exists {
		return apppki.ErrNotFound
	}
	if assignment.ConsumerType != acknowledgement.ConsumerType || assignment.ConsumerID != acknowledgement.ConsumerID ||
		assignment.TrustSetID != operation.AuthorityRollover.TrustSetID ||
		(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentIneligible,
			"acknowledgement consumer snapshot does not match an active assignment",
		)
	}
	if operation.AuthorityRollover.Phase == domainpki.AuthorityRolloverPhaseAwaitingFinalAcknowledgements {
		if err := s.validateRolloverAssignmentRotatedLocked(operation.AuthorityRollover, assignment); err != nil {
			return err
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.acknowledgements[acknowledgement.ID] = acknowledgement
	s.acknowledgementKeys[acknowledgementKey(acknowledgement)] = acknowledgement.ID
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) ActivateAuthorityRollover(
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

func (s *Store) CompleteAuthorityRollover(
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

func (s *Store) UpdateAuthorityRollover(
	ctx context.Context,
	expectedRevision uint64,
	expectedTrustSetRevision uint64,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := validateMemoryCASUpdate(expectedRevision, operation.Revision); err != nil {
		return err
	}
	if expectedTrustSetRevision == 0 {
		return errors.New("pki: expected trust set revision must be positive")
	}
	if err := operation.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(operation.ID) {
		return errors.New("pki: authority rollover update audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, operation.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existing, exists := s.operations[operation.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if err := domainpki.ValidateAuthorityRolloverTransition(
		existing, operation, domainpki.AuthorityRolloverTransitionBeginFinalTrust,
	); err != nil {
		return err
	}
	if err := s.validateFinalTrustTransitionReferencesLocked(operation, expectedTrustSetRevision); err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operations[operation.ID] = operation.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) CancelAuthorityRollover(
	ctx context.Context,
	expectedRevision uint64,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	if err := validateMemoryCASUpdate(expectedRevision, operation.Revision); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(operation.ID) {
		return errors.New("pki: authority rollover cancellation audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, operation.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existing, exists := s.operations[operation.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return apppki.ErrRevisionConflict
	}
	if err := domainpki.ValidateAuthorityRolloverTransition(
		existing, operation, domainpki.AuthorityRolloverTransitionCancel,
	); err != nil {
		return err
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operations[operation.ID] = operation.Clone()
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func (s *Store) validateFinalTrustTransitionReferencesLocked(
	operation domainpki.Operation,
	expectedTrustSetRevision uint64,
) error {
	rollover := operation.AuthorityRollover
	if rollover == nil {
		return errors.New("pki: authority rollover payload is required")
	}
	trustSet, exists := s.trustSets[rollover.TrustSetID]
	if !exists {
		return apppki.ErrNotFound
	}
	if trustSet.Revision != expectedTrustSetRevision {
		return apppki.ErrRevisionConflict
	}
	if trustSet.StagedGenerationID != rollover.FinalTrustGenerationID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionTrustChanged, "rollover final trust generation is not staged",
		)
	}
	finalTrust, exists := s.trustGens[rollover.FinalTrustGenerationID]
	if !exists {
		return apppki.ErrNotFound
	}
	previous, previousExists := s.authorities[rollover.PreviousAuthorityID]
	replacement, replacementExists := s.authorities[rollover.ReplacementAuthorityID]
	if !previousExists || !replacementExists {
		return apppki.ErrNotFound
	}
	if previous.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
		replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID ||
		(replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked) ||
		finalTrust.TrustSetID != trustSet.ID {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
		)
	}
	if err := s.validateRolloverTrustMaterialLocked(
		finalTrust, previous, replacement, domainpki.AuthorityRolloverTransitionBeginFinalTrust, operation.UpdatedAt,
	); err != nil {
		return apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionTrustLayoutInvalid, err.Error())
	}
	return s.validateAllRolloverAssignmentsRotatedLocked(rollover)
}

func (s *Store) persistAuthorityRolloverAggregate(
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
	if err := validateMemoryCASUpdate(expectedOperationRevision, operation.Revision); err != nil {
		return err
	}
	if err := validateMemoryCASUpdate(expectedTrustSetRevision, trustSet.Revision); err != nil {
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
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.ResourceID != string(operation.ID) {
		return errors.New("pki: authority rollover aggregate audit resource does not match")
	}
	if err := validateMemoryMutation(mutation, audit.ResourceType, operation.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateMutationAvailableLocked(mutation); err != nil {
		return err
	}
	existingOperation, exists := s.operations[operation.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	existingAuthority, exists := s.authorities[previous.ID]
	if !exists {
		return apppki.ErrNotFound
	}
	existingTrustSet, exists := s.trustSets[trustSet.ID]
	if !exists {
		return apppki.ErrNotFound
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
	replacement, exists := s.authorities[rollover.ReplacementAuthorityID]
	if !exists {
		return apppki.ErrNotFound
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
	trustGeneration, exists := s.trustGens[trustGenerationID]
	if !exists {
		return apppki.ErrNotFound
	}
	if err := s.validateRolloverTrustMaterialLocked(
		trustGeneration, existingAuthority, replacement, transition, operation.UpdatedAt,
	); err != nil {
		return apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionTrustLayoutInvalid, err.Error())
	}
	if transition == domainpki.AuthorityRolloverTransitionComplete {
		if err := s.validateAllRolloverAssignmentsRotatedLocked(rollover); err != nil {
			return err
		}
	}
	if err := s.validateAuditIDsAvailableLocked([]apppki.AuditRecord{audit}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operations[operation.ID] = operation.Clone()
	s.authorities[previous.ID] = previous.Clone()
	s.trustSets[trustSet.ID] = trustSet
	s.audits = append(s.audits, audit.Clone())
	s.recordMutationLocked(mutation)
	return nil
}

func containsAssignmentID(ids []domainpki.AssignmentID, target domainpki.AssignmentID) bool {
	_, found := slices.BinarySearch(ids, target)
	return found
}

func (s *Store) eligibleRolloverAssignmentIDsLocked(trustSetID domainpki.TrustSetID) []domainpki.AssignmentID {
	result := make([]domainpki.AssignmentID, 0)
	for _, assignment := range s.assignments {
		if assignment.TrustSetID == trustSetID && assignment.Purpose.RequiresPeerTrust() &&
			(assignment.State == domainpki.AssignmentStateActive || assignment.State == domainpki.AssignmentStateDegraded) {
			result = append(result, assignment.ID)
		}
	}
	slices.Sort(result)
	return result
}

func rolloverResourcesOverlap(existing, candidate domainpki.Operation) bool {
	if existing.Kind != domainpki.OperationKindAuthorityRollover || existing.AuthorityRollover == nil ||
		existing.Status == domainpki.OperationStatusCompleted || existing.Status == domainpki.OperationStatusFailed ||
		existing.Status == domainpki.OperationStatusCanceled || candidate.AuthorityRollover == nil {
		return false
	}
	existingRollover := existing.AuthorityRollover
	candidateRollover := candidate.AuthorityRollover
	return existingRollover.TrustSetID == candidateRollover.TrustSetID ||
		existingRollover.PreviousAuthorityID == candidateRollover.PreviousAuthorityID ||
		existingRollover.PreviousAuthorityID == candidateRollover.ReplacementAuthorityID ||
		existingRollover.ReplacementAuthorityID == candidateRollover.PreviousAuthorityID ||
		existingRollover.ReplacementAuthorityID == candidateRollover.ReplacementAuthorityID
}

func (s *Store) liveAuthorityRolloverForTrustSetLocked(
	id domainpki.TrustSetID,
) (domainpki.Operation, bool) {
	for _, operation := range s.operations {
		if operation.Kind == domainpki.OperationKindAuthorityRollover &&
			operation.Status == domainpki.OperationStatusWaiting && operation.AuthorityRollover != nil &&
			operation.AuthorityRollover.TrustSetID == id {
			return operation.Clone(), true
		}
	}
	return domainpki.Operation{}, false
}

func (s *Store) validateAllRolloverAssignmentsRotatedLocked(rollover *domainpki.AuthorityRollover) error {
	for _, assignmentID := range rollover.RequiredAssignmentIDs {
		assignment, exists := s.assignments[assignmentID]
		if !exists {
			return apppki.ErrNotFound
		}
		if err := s.validateRolloverAssignmentRotatedLocked(rollover, assignment); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) validateRolloverAssignmentRotatedLocked(
	rollover *domainpki.AuthorityRollover,
	assignment domainpki.Assignment,
) error {
	if assignment.TrustSetID != rollover.TrustSetID ||
		(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
		return apppki.NewRolloverPreconditionError(
			apppki.RolloverPreconditionAssignmentsNotRotated, "rollover assignment is not an eligible active consumer",
		)
	}
	generation, exists := s.generations[assignment.ActiveGenerationID]
	if !exists {
		return apppki.ErrNotFound
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

func (s *Store) validateRolloverTrustMaterialLocked(
	trust domainpki.TrustSetGeneration,
	previous domainpki.Authority,
	replacement domainpki.Authority,
	transition domainpki.AuthorityRolloverTransition,
	now time.Time,
) error {
	previousGeneration, exists := s.generations[previous.ActiveGenerationID]
	if !exists {
		return apppki.ErrNotFound
	}
	replacementGeneration, exists := s.generations[replacement.ActiveGenerationID]
	if !exists {
		return apppki.ErrNotFound
	}
	material := domainpki.TrustMaterial{
		Certificates: make([]domainpki.CertificateGeneration, 0,
			len(trust.AnchorGenerationIDs)+len(trust.IntermediateGenerationIDs)),
		CRLs: make([]domainpki.CRLGeneration, 0, len(trust.CRLGenerationIDs)),
	}
	for _, id := range trust.AnchorGenerationIDs {
		generation, exists := s.generations[id]
		if !exists {
			return apppki.ErrNotFound
		}
		material.Certificates = append(material.Certificates, generation)
	}
	for _, id := range trust.IntermediateGenerationIDs {
		generation, exists := s.generations[id]
		if !exists {
			return apppki.ErrNotFound
		}
		material.Certificates = append(material.Certificates, generation)
	}
	for _, id := range trust.CRLGenerationIDs {
		generation, exists := s.crlGenerations[id]
		if !exists {
			return apppki.ErrNotFound
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
