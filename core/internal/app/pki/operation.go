package pki

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	auditResourceOperation       = "operation"
	auditResourceAcknowledgement = "consumer-acknowledgement"
	auditDetailOperationID       = "operationId"
	auditDetailAssignmentID      = "assignmentId"
	auditDetailTrustGenerationID = "trustSetGenerationId"
)

type StartAuthorityRolloverRequest struct {
	IdempotencyKey           string                             `json:"idempotencyKey"`
	OperationID              domainpki.OperationID              `json:"operationId,omitempty"`
	PreviousAuthorityID      domainpki.AuthorityID              `json:"previousAuthorityId"`
	ReplacementAuthorityID   domainpki.AuthorityID              `json:"replacementAuthorityId"`
	TrustSetID               domainpki.TrustSetID               `json:"trustSetId"`
	OverlapTrustGenerationID domainpki.TrustSetGenerationID     `json:"overlapTrustGenerationId"`
	ConsumerTracking         domainpki.RolloverConsumerTracking `json:"consumerTracking"`
	RequiredAssignmentIDs    []domainpki.AssignmentID           `json:"requiredAssignmentIds,omitempty"`
}

type AcknowledgeAuthorityRolloverRequest struct {
	IdempotencyKey    string                      `json:"idempotencyKey"`
	AcknowledgementID domainpki.AcknowledgementID `json:"acknowledgementId,omitempty"`
	OperationID       domainpki.OperationID       `json:"operationId"`
	AssignmentID      domainpki.AssignmentID      `json:"assignmentId"`
	EvidenceRef       string                      `json:"evidenceRef,omitempty"`
}

type ActivateAuthorityRolloverRequest struct {
	IdempotencyKey           string                `json:"idempotencyKey"`
	OperationID              domainpki.OperationID `json:"operationId"`
	ExpectedRevision         uint64                `json:"expectedRevision"`
	ExpectedTrustSetRevision uint64                `json:"expectedTrustSetRevision"`
}

type BeginAuthorityRolloverFinalTrustRequest struct {
	IdempotencyKey           string                         `json:"idempotencyKey"`
	OperationID              domainpki.OperationID          `json:"operationId"`
	ExpectedRevision         uint64                         `json:"expectedRevision"`
	ExpectedTrustSetRevision uint64                         `json:"expectedTrustSetRevision"`
	FinalTrustGenerationID   domainpki.TrustSetGenerationID `json:"finalTrustGenerationId"`
}

type CompleteAuthorityRolloverRequest struct {
	IdempotencyKey           string                `json:"idempotencyKey"`
	OperationID              domainpki.OperationID `json:"operationId"`
	ExpectedRevision         uint64                `json:"expectedRevision"`
	ExpectedTrustSetRevision uint64                `json:"expectedTrustSetRevision"`
}

type CancelAuthorityRolloverRequest struct {
	IdempotencyKey   string                `json:"idempotencyKey"`
	OperationID      domainpki.OperationID `json:"operationId"`
	ExpectedRevision uint64                `json:"expectedRevision"`
}

type OperationInspection struct {
	Operation            domainpki.Operation                 `json:"operation"`
	Acknowledgements     []domainpki.ConsumerAcknowledgement `json:"acknowledgements"`
	MissingAssignmentIDs []domainpki.AssignmentID            `json:"missingAssignmentIds"`
}

func (i OperationInspection) Clone() OperationInspection {
	return OperationInspection{
		Operation:            i.Operation.Clone(),
		Acknowledgements:     append([]domainpki.ConsumerAcknowledgement(nil), i.Acknowledgements...),
		MissingAssignmentIDs: append([]domainpki.AssignmentID(nil), i.MissingAssignmentIDs...),
	}
}

func (s Service) ListOperations(ctx context.Context) ([]domainpki.Operation, error) {
	operations, err := s.persistence.PKIOperations(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.Operation, len(operations))
	for index, operation := range operations {
		if err := operation.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed operation: %w", err)
		}
		result[index] = operation.Clone()
	}
	return result, nil
}

func (s Service) InspectOperation(ctx context.Context, id domainpki.OperationID) (OperationInspection, error) {
	if err := id.Validate(); err != nil {
		return OperationInspection{}, err
	}
	operation, err := s.persistence.PKIOperation(ctx, id)
	if err != nil {
		return OperationInspection{}, err
	}
	acknowledgements, err := s.persistence.ConsumerAcknowledgements(ctx, id)
	if err != nil {
		return OperationInspection{}, err
	}
	return inspectOperation(operation, acknowledgements)
}

func (s Service) StartAuthorityRollover(
	ctx context.Context,
	request StartAuthorityRolloverRequest,
) (OperationInspection, error) {
	normalized, err := normalizeAuthorityRolloverRequest(request)
	if err != nil {
		return OperationInspection{}, err
	}
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationAuthorityRollover, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	previous, err := s.persistence.Authority(ctx, normalized.PreviousAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	replacement, err := s.persistence.Authority(ctx, normalized.ReplacementAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	if err := validateRolloverAuthorities(previous, replacement); err != nil {
		return OperationInspection{}, err
	}
	trustSet, err := s.persistence.TrustSet(ctx, normalized.TrustSetID)
	if err != nil {
		return OperationInspection{}, err
	}
	if trustSet.StagedGenerationID != normalized.OverlapTrustGenerationID {
		return OperationInspection{}, errors.New("pki: rollover overlap generation is not staged on its trust set")
	}
	overlap, err := s.persistence.TrustSetGeneration(ctx, normalized.OverlapTrustGenerationID)
	if err != nil {
		return OperationInspection{}, err
	}
	if err := s.validateRolloverOverlapMaterial(ctx, trustSet, overlap, previous, replacement, s.clock.Now().UTC()); err != nil {
		return OperationInspection{}, err
	}
	required, err := s.resolveRolloverAssignments(ctx, normalized.ConsumerTracking, normalized.RequiredAssignmentIDs, trustSet.ID)
	if err != nil {
		return OperationInspection{}, err
	}
	if err := s.ensureNoLiveAuthorityRollover(ctx, previous.ID, replacement.ID, trustSet.ID); err != nil {
		return OperationInspection{}, err
	}
	operationID := normalized.OperationID
	if operationID == "" {
		operationID, err = s.newOperationID("operation")
		if err != nil {
			return OperationInspection{}, err
		}
	}
	now := s.clock.Now().UTC()
	rollover := domainpki.AuthorityRollover{
		PreviousAuthorityID: previous.ID, PreviousAuthorityGenerationID: previous.ActiveGenerationID,
		ReplacementAuthorityID: replacement.ID, ReplacementAuthorityGenerationID: replacement.ActiveGenerationID,
		TrustSetID: trustSet.ID, OverlapTrustGenerationID: overlap.ID,
		ConsumerTracking: normalized.ConsumerTracking, RequiredAssignmentIDs: required,
		Phase: domainpki.AuthorityRolloverPhaseAwaitingOverlapAcknowledgements,
	}
	operation, err := domainpki.NewOperation(domainpki.OperationArgs{
		ID: operationID, Kind: domainpki.OperationKindAuthorityRollover,
		Status: domainpki.OperationStatusWaiting, Revision: 1, AuthorityRollover: &rollover,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAuthorityRollover, AuditOutcomeAttempted,
		auditResourceOperation, string(operation.ID), map[string]string{
			"previousAuthorityId": string(previous.ID), "replacementAuthorityId": string(replacement.ID),
			auditDetailTrustGenerationID: string(overlap.ID),
		})
	if err != nil {
		return OperationInspection{}, err
	}
	result, err := inspectOperation(operation, nil)
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(ctx, s, scope, MutationAuthorityRollover, auditResourceOperation, string(operation.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.CreateAuthorityRollover(ctx, operation, audit, mutation)
		})
}

func (s Service) AcknowledgeAuthorityRollover(
	ctx context.Context,
	request AcknowledgeAuthorityRolloverRequest,
) (OperationInspection, error) {
	normalized := request
	normalized.IdempotencyKey = ""
	normalized.EvidenceRef = strings.TrimSpace(request.EvidenceRef)
	if err := normalized.OperationID.Validate(); err != nil {
		return OperationInspection{}, err
	}
	if err := normalized.AssignmentID.Validate(); err != nil {
		return OperationInspection{}, err
	}
	if normalized.AcknowledgementID != "" {
		if err := normalized.AcknowledgementID.Validate(); err != nil {
			return OperationInspection{}, err
		}
	}
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationConsumerAcknowledge, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	operation, err := s.persistence.PKIOperation(ctx, normalized.OperationID)
	if err != nil {
		return OperationInspection{}, err
	}
	rollover, targetGenerationID, err := activeRolloverAcknowledgementTarget(operation, normalized.AssignmentID)
	if err != nil {
		return OperationInspection{}, err
	}
	assignment, err := s.persistence.Assignment(ctx, normalized.AssignmentID)
	if err != nil {
		return OperationInspection{}, err
	}
	if assignment.TrustSetID != rollover.TrustSetID ||
		(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionAssignmentIneligible, "acknowledgement assignment is no longer active",
		)
	}
	acknowledgementID := normalized.AcknowledgementID
	if acknowledgementID == "" {
		acknowledgementID, err = s.newAcknowledgementID("ack")
		if err != nil {
			return OperationInspection{}, err
		}
	}
	acknowledgement, err := domainpki.NewConsumerAcknowledgement(domainpki.ConsumerAcknowledgementArgs{
		ID: acknowledgementID, OperationID: operation.ID, AssignmentID: assignment.ID,
		ConsumerType: assignment.ConsumerType, ConsumerID: assignment.ConsumerID,
		Kind:                 domainpki.AcknowledgementKindTrustSetGeneration,
		TrustSetGenerationID: targetGenerationID,
		EvidenceRef:          normalized.EvidenceRef, AcknowledgedAt: s.clock.Now().UTC(),
	})
	if err != nil {
		return OperationInspection{}, err
	}
	acknowledgements, err := s.persistence.ConsumerAcknowledgements(ctx, operation.ID)
	if err != nil {
		return OperationInspection{}, err
	}
	for _, existing := range acknowledgements {
		if existing.AssignmentID == acknowledgement.AssignmentID && existing.Kind == acknowledgement.Kind &&
			existing.TrustSetGenerationID == acknowledgement.TrustSetGenerationID {
			return OperationInspection{}, ErrAcknowledgementExists
		}
	}
	acknowledgements = append(acknowledgements, acknowledgement)
	result, err := inspectOperation(operation, acknowledgements)
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionConsumerAcknowledge, AuditOutcomeSucceeded,
		auditResourceAcknowledgement, string(acknowledgement.ID), map[string]string{
			auditDetailOperationID: string(operation.ID), auditDetailAssignmentID: string(assignment.ID),
			auditDetailTrustGenerationID: string(acknowledgement.TrustSetGenerationID),
		})
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(ctx, s, scope, MutationConsumerAcknowledge,
		auditResourceAcknowledgement, string(acknowledgement.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.RecordConsumerAcknowledgement(ctx, acknowledgement, audit, mutation)
		})
}

func (s Service) ActivateAuthorityRollover(
	ctx context.Context,
	request ActivateAuthorityRolloverRequest,
) (OperationInspection, error) {
	if err := validateOperationTransitionRequest(request.OperationID, request.ExpectedRevision); err != nil {
		return OperationInspection{}, err
	}
	if request.ExpectedTrustSetRevision == 0 {
		return OperationInspection{}, errors.New("pki: expected trust set revision must be positive")
	}
	normalized := request
	normalized.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationRolloverActivate, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	inspection, err := s.InspectOperation(ctx, request.OperationID)
	if err != nil {
		return OperationInspection{}, err
	}
	operation := inspection.Operation
	if operation.Revision != request.ExpectedRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if operation.AuthorityRollover == nil ||
		operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingOverlapAcknowledgements {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, "rollover is not awaiting overlap acknowledgements",
		)
	}
	if len(inspection.MissingAssignmentIDs) != 0 {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionMissingAcknowledgements, "overlap trust acknowledgements are incomplete",
		)
	}
	rollover := operation.AuthorityRollover
	trustSet, err := s.persistence.TrustSet(ctx, rollover.TrustSetID)
	if err != nil {
		return OperationInspection{}, err
	}
	if trustSet.Revision != request.ExpectedTrustSetRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if trustSet.StagedGenerationID != rollover.OverlapTrustGenerationID {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustChanged, "overlap trust is no longer staged",
		)
	}
	previous, err := s.persistence.Authority(ctx, rollover.PreviousAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	replacement, err := s.persistence.Authority(ctx, rollover.ReplacementAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	if previous.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
		replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID ||
		(replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked) {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
		)
	}
	now := s.clock.Now().UTC()
	overlap, err := s.persistence.TrustSetGeneration(ctx, rollover.OverlapTrustGenerationID)
	if err != nil {
		return OperationInspection{}, err
	}
	if err := s.validateRolloverOverlapMaterial(ctx, trustSet, overlap, previous, replacement, now); err != nil {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustLayoutInvalid, err.Error(),
		)
	}
	updatedTrustSet, err := activateRolloverTrustSet(trustSet, now)
	if err != nil {
		return OperationInspection{}, err
	}
	updatedPrevious := previous.Clone()
	if updatedPrevious.State != domainpki.AuthorityStateCompromised {
		updatedPrevious.State = domainpki.AuthorityStateRetiring
	}
	updatedPrevious.UpdatedAt = now
	if err := updatedPrevious.Validate(); err != nil {
		return OperationInspection{}, err
	}
	updatedOperation, err := transitionAuthorityRollover(
		operation, domainpki.AuthorityRolloverTransitionActivateOverlap, "", now,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	result, err := inspectOperation(updatedOperation, inspection.Acknowledgements)
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAuthorityRollover, AuditOutcomeSucceeded,
		auditResourceOperation, string(operation.ID), map[string]string{
			"phase":                      string(updatedOperation.AuthorityRollover.Phase),
			auditDetailTrustGenerationID: string(updatedTrustSet.ActiveGenerationID),
		})
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(ctx, s, scope, MutationRolloverActivate, auditResourceOperation, string(operation.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.ActivateAuthorityRollover(
				ctx, request.ExpectedRevision, request.ExpectedTrustSetRevision,
				updatedOperation, updatedPrevious, updatedTrustSet, audit, mutation,
			)
		})
}

func (s Service) BeginAuthorityRolloverFinalTrust(
	ctx context.Context,
	request BeginAuthorityRolloverFinalTrustRequest,
) (OperationInspection, error) {
	if err := validateOperationTransitionRequest(request.OperationID, request.ExpectedRevision); err != nil {
		return OperationInspection{}, err
	}
	if err := request.FinalTrustGenerationID.Validate(); err != nil {
		return OperationInspection{}, err
	}
	if request.ExpectedTrustSetRevision == 0 {
		return OperationInspection{}, errors.New("pki: expected trust set revision must be positive")
	}
	normalized := request
	normalized.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationRolloverFinalTrust, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	inspection, err := s.InspectOperation(ctx, request.OperationID)
	if err != nil {
		return OperationInspection{}, err
	}
	operation := inspection.Operation
	if operation.Revision != request.ExpectedRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if operation.AuthorityRollover == nil ||
		operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingLeafRotation {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, "rollover is not awaiting leaf rotation",
		)
	}
	rollover := operation.AuthorityRollover
	if err := s.validateRolloverLeafAssignments(ctx, rollover.Clone()); err != nil {
		return OperationInspection{}, err
	}
	trustSet, err := s.persistence.TrustSet(ctx, rollover.TrustSetID)
	if err != nil {
		return OperationInspection{}, err
	}
	if trustSet.StagedGenerationID != request.FinalTrustGenerationID {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustChanged, "final trust generation is not staged",
		)
	}
	if trustSet.Revision != request.ExpectedTrustSetRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	finalTrust, err := s.persistence.TrustSetGeneration(ctx, request.FinalTrustGenerationID)
	if err != nil {
		return OperationInspection{}, err
	}
	previous, err := s.persistence.Authority(ctx, rollover.PreviousAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	replacement, err := s.persistence.Authority(ctx, rollover.ReplacementAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	if finalTrust.TrustSetID != trustSet.ID ||
		previous.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
		replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
		)
	}
	if err := s.validateRolloverFinalMaterial(
		ctx, trustSet, finalTrust, previous, replacement, s.clock.Now().UTC(),
	); err != nil {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustLayoutInvalid, err.Error(),
		)
	}
	updatedOperation, err := transitionAuthorityRollover(
		operation, domainpki.AuthorityRolloverTransitionBeginFinalTrust,
		finalTrust.ID, s.clock.Now().UTC(),
	)
	if err != nil {
		return OperationInspection{}, err
	}
	result, err := inspectOperation(updatedOperation, inspection.Acknowledgements)
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAuthorityRollover, AuditOutcomeAttempted,
		auditResourceOperation, string(operation.ID), map[string]string{
			"phase":                      string(updatedOperation.AuthorityRollover.Phase),
			auditDetailTrustGenerationID: string(finalTrust.ID),
		})
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(ctx, s, scope, MutationRolloverFinalTrust, auditResourceOperation, string(operation.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.UpdateAuthorityRollover(
				ctx, request.ExpectedRevision, request.ExpectedTrustSetRevision, updatedOperation, audit, mutation,
			)
		})
}

func (s Service) CompleteAuthorityRollover(
	ctx context.Context,
	request CompleteAuthorityRolloverRequest,
) (OperationInspection, error) {
	if err := validateOperationTransitionRequest(request.OperationID, request.ExpectedRevision); err != nil {
		return OperationInspection{}, err
	}
	if request.ExpectedTrustSetRevision == 0 {
		return OperationInspection{}, errors.New("pki: expected trust set revision must be positive")
	}
	normalized := request
	normalized.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationRolloverComplete, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	inspection, err := s.InspectOperation(ctx, request.OperationID)
	if err != nil {
		return OperationInspection{}, err
	}
	operation := inspection.Operation
	if operation.Revision != request.ExpectedRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if operation.AuthorityRollover == nil ||
		operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingFinalAcknowledgements {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, "rollover is not awaiting final acknowledgements",
		)
	}
	if len(inspection.MissingAssignmentIDs) != 0 {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionMissingAcknowledgements, "final trust acknowledgements are incomplete",
		)
	}
	rollover := operation.AuthorityRollover
	trustSet, err := s.persistence.TrustSet(ctx, rollover.TrustSetID)
	if err != nil {
		return OperationInspection{}, err
	}
	if trustSet.Revision != request.ExpectedTrustSetRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if trustSet.StagedGenerationID != rollover.FinalTrustGenerationID {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustChanged, "final trust is no longer staged",
		)
	}
	previous, err := s.persistence.Authority(ctx, rollover.PreviousAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	replacement, err := s.persistence.Authority(ctx, rollover.ReplacementAuthorityID)
	if err != nil {
		return OperationInspection{}, err
	}
	if previous.ActiveGenerationID != rollover.PreviousAuthorityGenerationID ||
		replacement.ActiveGenerationID != rollover.ReplacementAuthorityGenerationID ||
		(replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked) {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionAuthorityChanged, "authority generation snapshot is no longer current",
		)
	}
	now := s.clock.Now().UTC()
	finalTrust, err := s.persistence.TrustSetGeneration(ctx, rollover.FinalTrustGenerationID)
	if err != nil {
		return OperationInspection{}, err
	}
	if err := s.validateRolloverFinalMaterial(ctx, trustSet, finalTrust, previous, replacement, now); err != nil {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionTrustLayoutInvalid, err.Error(),
		)
	}
	updatedTrustSet, err := activateRolloverTrustSet(trustSet, now)
	if err != nil {
		return OperationInspection{}, err
	}
	updatedPrevious := previous.Clone()
	if updatedPrevious.State != domainpki.AuthorityStateCompromised {
		updatedPrevious.State = domainpki.AuthorityStateRetired
	}
	updatedPrevious.UpdatedAt = now
	if err := updatedPrevious.Validate(); err != nil {
		return OperationInspection{}, err
	}
	updatedOperation, err := transitionAuthorityRollover(
		operation, domainpki.AuthorityRolloverTransitionComplete, rollover.FinalTrustGenerationID, now,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	result, err := inspectOperation(updatedOperation, inspection.Acknowledgements)
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAuthorityRollover, AuditOutcomeSucceeded,
		auditResourceOperation, string(operation.ID), map[string]string{
			"phase":                      string(updatedOperation.AuthorityRollover.Phase),
			auditDetailTrustGenerationID: string(updatedTrustSet.ActiveGenerationID),
		})
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(ctx, s, scope, MutationRolloverComplete, auditResourceOperation, string(operation.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.CompleteAuthorityRollover(
				ctx, request.ExpectedRevision, request.ExpectedTrustSetRevision,
				updatedOperation, updatedPrevious, updatedTrustSet, audit, mutation,
			)
		})
}

func (s Service) CancelAuthorityRollover(
	ctx context.Context,
	request CancelAuthorityRolloverRequest,
) (OperationInspection, error) {
	if err := validateOperationTransitionRequest(request.OperationID, request.ExpectedRevision); err != nil {
		return OperationInspection{}, err
	}
	normalized := request
	normalized.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[OperationInspection](
		ctx, s, request.IdempotencyKey, MutationRolloverCancel, normalized,
	)
	if err != nil {
		return OperationInspection{}, err
	}
	if exists {
		return replayed.Clone(), nil
	}
	inspection, err := s.InspectOperation(ctx, request.OperationID)
	if err != nil {
		return OperationInspection{}, err
	}
	if inspection.Operation.Revision != request.ExpectedRevision {
		return OperationInspection{}, ErrRevisionConflict
	}
	if inspection.Operation.Status != domainpki.OperationStatusWaiting ||
		inspection.Operation.AuthorityRollover == nil ||
		inspection.Operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingOverlapAcknowledgements {
		return OperationInspection{}, NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, "rollover is cancelable only before overlap activation",
		)
	}
	updated, err := transitionAuthorityRollover(
		inspection.Operation, domainpki.AuthorityRolloverTransitionCancel, "", s.clock.Now().UTC(),
	)
	if err != nil {
		return OperationInspection{}, err
	}
	result, err := inspectOperation(updated, inspection.Acknowledgements)
	if err != nil {
		return OperationInspection{}, err
	}
	audit, err := s.newAuditRecord(
		scope.audit, AuditActionAuthorityRollover, AuditOutcomeSucceeded,
		auditResourceOperation, string(updated.ID), map[string]string{"status": string(updated.Status)},
	)
	if err != nil {
		return OperationInspection{}, err
	}
	return commitMutation(
		ctx, s, scope, MutationRolloverCancel, auditResourceOperation, string(updated.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.CancelAuthorityRollover(
				ctx, request.ExpectedRevision, updated, audit, mutation,
			)
		},
	)
}

func normalizeAuthorityRolloverRequest(request StartAuthorityRolloverRequest) (StartAuthorityRolloverRequest, error) {
	normalized := request
	normalized.IdempotencyKey = ""
	normalized.RequiredAssignmentIDs = append([]domainpki.AssignmentID(nil), request.RequiredAssignmentIDs...)
	slices.Sort(normalized.RequiredAssignmentIDs)
	if normalized.OperationID != "" {
		if err := normalized.OperationID.Validate(); err != nil {
			return StartAuthorityRolloverRequest{}, err
		}
	}
	if err := normalized.PreviousAuthorityID.Validate(); err != nil {
		return StartAuthorityRolloverRequest{}, err
	}
	if err := normalized.ReplacementAuthorityID.Validate(); err != nil {
		return StartAuthorityRolloverRequest{}, err
	}
	if err := normalized.TrustSetID.Validate(); err != nil {
		return StartAuthorityRolloverRequest{}, err
	}
	if err := normalized.OverlapTrustGenerationID.Validate(); err != nil {
		return StartAuthorityRolloverRequest{}, err
	}
	if err := normalized.ConsumerTracking.Validate(); err != nil {
		return StartAuthorityRolloverRequest{}, err
	}
	for index, id := range normalized.RequiredAssignmentIDs {
		if err := id.Validate(); err != nil {
			return StartAuthorityRolloverRequest{}, err
		}
		if index > 0 && normalized.RequiredAssignmentIDs[index-1] == id {
			return StartAuthorityRolloverRequest{}, errors.New("pki: rollover required assignments contain a duplicate")
		}
	}
	switch normalized.ConsumerTracking {
	case domainpki.RolloverConsumerTrackingAllTracked, domainpki.RolloverConsumerTrackingNone:
		if len(normalized.RequiredAssignmentIDs) != 0 {
			return StartAuthorityRolloverRequest{}, errors.New("pki: rollover tracking mode does not accept explicit assignments")
		}
	case domainpki.RolloverConsumerTrackingExplicit:
		if len(normalized.RequiredAssignmentIDs) == 0 {
			return StartAuthorityRolloverRequest{}, errors.New("pki: explicit rollover tracking requires assignments")
		}
	}
	return normalized, nil
}

func validateRolloverAuthorities(previous, replacement domainpki.Authority) error {
	if err := domainpki.ValidateAuthorityRolloverAuthorities(previous, replacement); err != nil {
		return err
	}
	switch previous.State {
	case domainpki.AuthorityStateActive, domainpki.AuthorityStateLocked, domainpki.AuthorityStateCompromised:
	default:
		return fmt.Errorf("pki: previous authority cannot roll over while %s", previous.State)
	}
	if replacement.State != domainpki.AuthorityStateActive && replacement.State != domainpki.AuthorityStateLocked {
		return fmt.Errorf("pki: replacement authority cannot take over while %s", replacement.State)
	}
	return nil
}

func (s Service) validateRolloverOverlapMaterial(
	ctx context.Context,
	trustSet domainpki.TrustSet,
	overlap domainpki.TrustSetGeneration,
	previous domainpki.Authority,
	replacement domainpki.Authority,
	now time.Time,
) error {
	if err := trustSet.Validate(); err != nil {
		return err
	}
	if err := overlap.Validate(); err != nil {
		return err
	}
	if overlap.TrustSetID != trustSet.ID || overlap.ID != trustSet.StagedGenerationID {
		return errors.New("pki: rollover overlap generation belongs to another trust set")
	}
	previousGeneration, err := s.persistence.Generation(ctx, previous.ActiveGenerationID)
	if err != nil {
		return err
	}
	replacementGeneration, err := s.persistence.Generation(ctx, replacement.ActiveGenerationID)
	if err != nil {
		return err
	}
	material, err := s.loadTrustMaterial(ctx, overlap)
	if err != nil {
		return err
	}
	return domainpki.ValidateAuthorityRolloverOverlapMaterial(
		overlap, previous, replacement, previousGeneration, replacementGeneration, material, now,
	)
}

func (s Service) validateRolloverFinalMaterial(
	ctx context.Context,
	trustSet domainpki.TrustSet,
	finalTrust domainpki.TrustSetGeneration,
	previous domainpki.Authority,
	replacement domainpki.Authority,
	now time.Time,
) error {
	if finalTrust.TrustSetID != trustSet.ID || finalTrust.ID != trustSet.StagedGenerationID {
		return errors.New("pki: rollover final generation belongs to another trust set")
	}
	previousGeneration, err := s.persistence.Generation(ctx, previous.ActiveGenerationID)
	if err != nil {
		return err
	}
	replacementGeneration, err := s.persistence.Generation(ctx, replacement.ActiveGenerationID)
	if err != nil {
		return err
	}
	material, err := s.loadTrustMaterial(ctx, finalTrust)
	if err != nil {
		return err
	}
	return domainpki.ValidateAuthorityRolloverFinalMaterial(
		finalTrust, previous, replacement, previousGeneration, replacementGeneration, material, now,
	)
}

func (s Service) resolveRolloverAssignments(
	ctx context.Context,
	tracking domainpki.RolloverConsumerTracking,
	explicit []domainpki.AssignmentID,
	trustSetID domainpki.TrustSetID,
) ([]domainpki.AssignmentID, error) {
	if tracking == domainpki.RolloverConsumerTrackingNone {
		return nil, nil
	}
	assignments, err := s.persistence.Assignments(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[domainpki.AssignmentID]domainpki.Assignment, len(assignments))
	for _, assignment := range assignments {
		byID[assignment.ID] = assignment
	}
	if tracking == domainpki.RolloverConsumerTrackingExplicit {
		result := append([]domainpki.AssignmentID(nil), explicit...)
		for _, id := range result {
			assignment, exists := byID[id]
			if !exists || assignment.TrustSetID != trustSetID ||
				!assignment.Purpose.RequiresPeerTrust() ||
				(assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded) {
				return nil, fmt.Errorf("pki: rollover assignment %q is not an eligible trust consumer", id)
			}
		}
		return result, nil
	}
	result := make([]domainpki.AssignmentID, 0)
	for _, assignment := range assignments {
		if assignment.TrustSetID == trustSetID && assignment.Purpose.RequiresPeerTrust() &&
			(assignment.State == domainpki.AssignmentStateActive || assignment.State == domainpki.AssignmentStateDegraded) {
			result = append(result, assignment.ID)
		}
	}
	slices.Sort(result)
	return result, nil
}

func (s Service) ensureNoLiveAuthorityRollover(
	ctx context.Context,
	previousAuthorityID domainpki.AuthorityID,
	replacementAuthorityID domainpki.AuthorityID,
	trustSetID domainpki.TrustSetID,
) error {
	operations, err := s.persistence.PKIOperations(ctx)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if operation.Kind != domainpki.OperationKindAuthorityRollover || operation.AuthorityRollover == nil ||
			operation.Status == domainpki.OperationStatusCompleted || operation.Status == domainpki.OperationStatusFailed ||
			operation.Status == domainpki.OperationStatusCanceled {
			continue
		}
		existing := operation.AuthorityRollover
		if existing.TrustSetID == trustSetID || existing.PreviousAuthorityID == previousAuthorityID ||
			existing.PreviousAuthorityID == replacementAuthorityID ||
			existing.ReplacementAuthorityID == previousAuthorityID ||
			existing.ReplacementAuthorityID == replacementAuthorityID {
			return NewRolloverPreconditionError(
				RolloverPreconditionResourceReserved,
				fmt.Sprintf("operation %q already reserves an authority or trust set", operation.ID),
			)
		}
	}
	return nil
}

func activeRolloverAcknowledgementTarget(
	operation domainpki.Operation,
	assignmentID domainpki.AssignmentID,
) (domainpki.AuthorityRollover, domainpki.TrustSetGenerationID, error) {
	if err := operation.Validate(); err != nil {
		return domainpki.AuthorityRollover{}, "", err
	}
	if operation.Kind != domainpki.OperationKindAuthorityRollover || operation.AuthorityRollover == nil ||
		operation.Status != domainpki.OperationStatusWaiting {
		return domainpki.AuthorityRollover{}, "", NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, "operation is not accepting trust acknowledgements",
		)
	}
	rollover := operation.AuthorityRollover.Clone()
	if !slices.Contains(rollover.RequiredAssignmentIDs, assignmentID) {
		return domainpki.AuthorityRollover{}, "", NewRolloverPreconditionError(
			RolloverPreconditionAssignmentIneligible, "assignment is not required by the rollover operation",
		)
	}
	target, err := rollover.ActiveAcknowledgementTarget()
	if err != nil {
		return domainpki.AuthorityRollover{}, "", NewRolloverPreconditionError(
			RolloverPreconditionWrongPhase, err.Error(),
		)
	}
	return rollover, target, nil
}

func validateOperationTransitionRequest(id domainpki.OperationID, expectedRevision uint64) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if expectedRevision == 0 {
		return errors.New("pki: expected operation revision must be positive")
	}
	return nil
}

func activateRolloverTrustSet(trustSet domainpki.TrustSet, now time.Time) (domainpki.TrustSet, error) {
	if trustSet.StagedGenerationID == "" {
		return domainpki.TrustSet{}, errors.New("pki: rollover trust set has no staged generation")
	}
	updated := trustSet
	updated.ActiveGenerationID = trustSet.StagedGenerationID
	updated.StagedGenerationID = ""
	updated.State = domainpki.TrustSetStateActive
	var err error
	updated.Revision, err = nextRevision(trustSet.Revision)
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	updated.UpdatedAt = now.UTC()
	if err := updated.Validate(); err != nil {
		return domainpki.TrustSet{}, err
	}
	return updated, nil
}

func transitionAuthorityRollover(
	operation domainpki.Operation,
	transition domainpki.AuthorityRolloverTransition,
	finalTrustGenerationID domainpki.TrustSetGenerationID,
	now time.Time,
) (domainpki.Operation, error) {
	if operation.AuthorityRollover == nil {
		return domainpki.Operation{}, errors.New("pki: operation has no authority rollover payload")
	}
	revision, err := nextRevision(operation.Revision)
	if err != nil {
		return domainpki.Operation{}, err
	}
	rollover := operation.AuthorityRollover.Clone()
	status := domainpki.OperationStatusWaiting
	completedAt := time.Time{}
	switch transition {
	case domainpki.AuthorityRolloverTransitionActivateOverlap:
		rollover.Phase = domainpki.AuthorityRolloverPhaseAwaitingLeafRotation
	case domainpki.AuthorityRolloverTransitionBeginFinalTrust:
		rollover.Phase = domainpki.AuthorityRolloverPhaseAwaitingFinalAcknowledgements
		rollover.FinalTrustGenerationID = finalTrustGenerationID
	case domainpki.AuthorityRolloverTransitionComplete:
		rollover.Phase = domainpki.AuthorityRolloverPhaseCompleted
		status = domainpki.OperationStatusCompleted
		completedAt = now.UTC()
	case domainpki.AuthorityRolloverTransitionCancel:
		status = domainpki.OperationStatusCanceled
		completedAt = now.UTC()
	default:
		return domainpki.Operation{}, fmt.Errorf("pki: unsupported authority rollover transition %q", transition)
	}
	next, err := domainpki.NewOperation(domainpki.OperationArgs{
		ID: operation.ID, Kind: operation.Kind, Status: status, Revision: revision,
		AuthorityRollover: &rollover, CreatedAt: operation.CreatedAt, UpdatedAt: now.UTC(),
		CompletedAt: completedAt,
	})
	if err != nil {
		return domainpki.Operation{}, err
	}
	if err := domainpki.ValidateAuthorityRolloverTransition(operation, next, transition); err != nil {
		return domainpki.Operation{}, err
	}
	return next, nil
}

func (s Service) validateRolloverLeafAssignments(ctx context.Context, rollover domainpki.AuthorityRollover) error {
	for _, assignmentID := range rollover.RequiredAssignmentIDs {
		assignment, err := s.persistence.Assignment(ctx, assignmentID)
		if err != nil {
			return err
		}
		if assignment.State != domainpki.AssignmentStateActive && assignment.State != domainpki.AssignmentStateDegraded {
			return NewRolloverPreconditionError(
				RolloverPreconditionAssignmentsNotRotated, fmt.Sprintf("assignment %q is not active", assignmentID),
			)
		}
		generation, err := s.persistence.Generation(ctx, assignment.ActiveGenerationID)
		if err != nil {
			return err
		}
		if generation.IssuerAuthorityID != rollover.ReplacementAuthorityID ||
			generation.IssuerGenerationID != rollover.ReplacementAuthorityGenerationID ||
			assignment.ActiveTrustGenerationID != rollover.OverlapTrustGenerationID {
			return NewRolloverPreconditionError(
				RolloverPreconditionAssignmentsNotRotated,
				fmt.Sprintf("assignment %q has not activated replacement issuer and overlap trust", assignmentID),
			)
		}
	}
	return nil
}

func inspectOperation(
	operation domainpki.Operation,
	acknowledgements []domainpki.ConsumerAcknowledgement,
) (OperationInspection, error) {
	if err := operation.Validate(); err != nil {
		return OperationInspection{}, err
	}
	type acknowledgementIdentity struct {
		assignmentID         domainpki.AssignmentID
		kind                 domainpki.AcknowledgementKind
		trustSetGenerationID domainpki.TrustSetGenerationID
	}
	seen := make(map[acknowledgementIdentity]struct{}, len(acknowledgements))
	acknowledged := make(map[domainpki.AssignmentID]struct{}, len(acknowledgements))
	targetGenerationID := domainpki.TrustSetGenerationID("")
	if operation.AuthorityRollover != nil {
		targetGenerationID = operation.AuthorityRollover.OverlapTrustGenerationID
		if operation.AuthorityRollover.Phase == domainpki.AuthorityRolloverPhaseAwaitingFinalAcknowledgements {
			targetGenerationID = operation.AuthorityRollover.FinalTrustGenerationID
		}
	}
	resultAcknowledgements := append([]domainpki.ConsumerAcknowledgement(nil), acknowledgements...)
	for _, acknowledgement := range resultAcknowledgements {
		if err := acknowledgement.Validate(); err != nil {
			return OperationInspection{}, err
		}
		if acknowledgement.OperationID != operation.ID {
			return OperationInspection{}, errors.New("pki: acknowledgement belongs to another operation")
		}
		if operation.AuthorityRollover != nil {
			rollover := operation.AuthorityRollover
			if !slices.Contains(rollover.RequiredAssignmentIDs, acknowledgement.AssignmentID) ||
				(acknowledgement.TrustSetGenerationID != rollover.OverlapTrustGenerationID &&
					acknowledgement.TrustSetGenerationID != rollover.FinalTrustGenerationID) {
				return OperationInspection{}, errors.New("pki: acknowledgement does not belong to the rollover contract")
			}
		}
		identity := acknowledgementIdentity{
			assignmentID: acknowledgement.AssignmentID, kind: acknowledgement.Kind,
			trustSetGenerationID: acknowledgement.TrustSetGenerationID,
		}
		if _, exists := seen[identity]; exists {
			return OperationInspection{}, errors.New("pki: operation contains duplicate consumer acknowledgements")
		}
		seen[identity] = struct{}{}
		if acknowledgement.Kind == domainpki.AcknowledgementKindTrustSetGeneration &&
			acknowledgement.TrustSetGenerationID == targetGenerationID {
			acknowledged[acknowledgement.AssignmentID] = struct{}{}
		}
	}
	slices.SortFunc(resultAcknowledgements, func(left, right domainpki.ConsumerAcknowledgement) int {
		if left.AcknowledgedAt.Equal(right.AcknowledgedAt) {
			return strings.Compare(string(left.ID), string(right.ID))
		}
		return left.AcknowledgedAt.Compare(right.AcknowledgedAt)
	})
	missing := make([]domainpki.AssignmentID, 0)
	if operation.AuthorityRollover != nil {
		for _, id := range operation.AuthorityRollover.RequiredAssignmentIDs {
			if _, exists := acknowledged[id]; !exists {
				missing = append(missing, id)
			}
		}
	}
	return OperationInspection{
		Operation: operation.Clone(), Acknowledgements: resultAcknowledgements, MissingAssignmentIDs: missing,
	}, nil
}

func (s Service) newOperationID(prefix string) (domainpki.OperationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewOperationID(value)
}

func (s Service) newAcknowledgementID(prefix string) (domainpki.AcknowledgementID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewAcknowledgementID(value)
}
