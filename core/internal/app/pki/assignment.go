package pki

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	auditResourceAssignment = "assignment"
	auditResourceTrustSet   = "trust-set"
)

type AssignmentInspection struct {
	Assignment            domainpki.Assignment             `json:"assignment"`
	ActiveGeneration      *domainpki.CertificateGeneration `json:"activeGeneration,omitempty"`
	StagedGeneration      *domainpki.CertificateGeneration `json:"stagedGeneration,omitempty"`
	TrustSet              *domainpki.TrustSet              `json:"trustSet,omitempty"`
	ActiveTrustGeneration *domainpki.TrustSetGeneration    `json:"activeTrustGeneration,omitempty"`
	StagedTrustGeneration *domainpki.TrustSetGeneration    `json:"stagedTrustGeneration,omitempty"`
}

type TrustSetInspection struct {
	TrustSet         domainpki.TrustSet            `json:"trustSet"`
	ActiveGeneration *domainpki.TrustSetGeneration `json:"activeGeneration,omitempty"`
	StagedGeneration *domainpki.TrustSetGeneration `json:"stagedGeneration,omitempty"`
}

type CreateTrustSetRequest struct {
	IdempotencyKey string               `json:"idempotencyKey"`
	ID             domainpki.TrustSetID `json:"id,omitempty"`
	Name           string               `json:"name"`
}

type StageTrustSetRequest struct {
	IdempotencyKey            string                         `json:"idempotencyKey"`
	TrustSetID                domainpki.TrustSetID           `json:"trustSetId"`
	ExpectedRevision          uint64                         `json:"expectedRevision"`
	GenerationID              domainpki.TrustSetGenerationID `json:"generationId,omitempty"`
	AnchorGenerationIDs       []domainpki.GenerationID       `json:"anchorGenerationIds"`
	IntermediateGenerationIDs []domainpki.GenerationID       `json:"intermediateGenerationIds,omitempty"`
	CRLGenerationIDs          []domainpki.CRLGenerationID    `json:"crlGenerationIds,omitempty"`
}

type ActivateTrustSetRequest struct {
	IdempotencyKey   string               `json:"idempotencyKey"`
	TrustSetID       domainpki.TrustSetID `json:"trustSetId"`
	ExpectedRevision uint64               `json:"expectedRevision"`
}

type BindAssignmentRequest struct {
	IdempotencyKey   string                     `json:"idempotencyKey"`
	ID               domainpki.AssignmentID     `json:"id,omitempty"`
	Purpose          domainpki.Purpose          `json:"purpose"`
	ConsumerType     domainpki.ConsumerType     `json:"consumerType"`
	ConsumerID       domainpki.ConsumerID       `json:"consumerId"`
	ProfileID        domainpki.ProfileID        `json:"profileId"`
	TrustSetID       domainpki.TrustSetID       `json:"trustSetId,omitempty"`
	RotationPolicyID domainpki.RotationPolicyID `json:"rotationPolicyId,omitempty"`
}

type StageAssignmentRequest struct {
	IdempotencyKey   string                 `json:"idempotencyKey"`
	AssignmentID     domainpki.AssignmentID `json:"assignmentId"`
	GenerationID     domainpki.GenerationID `json:"generationId"`
	ExpectedRevision uint64                 `json:"expectedRevision"`
}

type ActivateAssignmentRequest struct {
	IdempotencyKey   string                 `json:"idempotencyKey"`
	AssignmentID     domainpki.AssignmentID `json:"assignmentId"`
	ExpectedRevision uint64                 `json:"expectedRevision"`
}

type UnbindAssignmentRequest struct {
	IdempotencyKey   string                 `json:"idempotencyKey"`
	AssignmentID     domainpki.AssignmentID `json:"assignmentId"`
	ExpectedRevision uint64                 `json:"expectedRevision"`
}

func (s Service) ListAssignments(ctx context.Context) ([]domainpki.Assignment, error) {
	assignments, err := s.persistence.Assignments(ctx)
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		if err := assignment.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed assignment: %w", err)
		}
	}
	return assignments, nil
}

func (s Service) InspectAssignment(ctx context.Context, id domainpki.AssignmentID) (AssignmentInspection, error) {
	if err := id.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	assignment, err := s.persistence.Assignment(ctx, id)
	if err != nil {
		return AssignmentInspection{}, err
	}
	inspection := AssignmentInspection{Assignment: assignment}
	if assignment.ActiveGenerationID != "" {
		generation, err := s.persistence.Generation(ctx, assignment.ActiveGenerationID)
		if err != nil {
			return AssignmentInspection{}, err
		}
		inspection.ActiveGeneration = pointerToGeneration(generation)
	}
	if assignment.StagedGenerationID != "" {
		generation, err := s.persistence.Generation(ctx, assignment.StagedGenerationID)
		if err != nil {
			return AssignmentInspection{}, err
		}
		inspection.StagedGeneration = pointerToGeneration(generation)
	}
	if assignment.TrustSetID != "" {
		trustSet, err := s.persistence.TrustSet(ctx, assignment.TrustSetID)
		if err != nil {
			return AssignmentInspection{}, err
		}
		inspection.TrustSet = &trustSet
		if assignment.ActiveTrustGenerationID != "" {
			generation, err := s.assignmentTrustGeneration(ctx, assignment, assignment.ActiveTrustGenerationID)
			if err != nil {
				return AssignmentInspection{}, err
			}
			inspection.ActiveTrustGeneration = pointerToTrustSetGeneration(generation)
		}
		if assignment.StagedTrustGenerationID != "" {
			generation, err := s.assignmentTrustGeneration(ctx, assignment, assignment.StagedTrustGenerationID)
			if err != nil {
				return AssignmentInspection{}, err
			}
			inspection.StagedTrustGeneration = pointerToTrustSetGeneration(generation)
		}
	}
	return inspection, nil
}

func (s Service) ListTrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	trustSets, err := s.persistence.TrustSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, trustSet := range trustSets {
		if err := trustSet.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed trust set: %w", err)
		}
	}
	return trustSets, nil
}

func (s Service) InspectTrustSet(ctx context.Context, id domainpki.TrustSetID) (TrustSetInspection, error) {
	if err := id.Validate(); err != nil {
		return TrustSetInspection{}, err
	}
	trustSet, err := s.persistence.TrustSet(ctx, id)
	if err != nil {
		return TrustSetInspection{}, err
	}
	inspection := TrustSetInspection{TrustSet: trustSet}
	if trustSet.ActiveGenerationID != "" {
		generation, err := s.persistence.TrustSetGeneration(ctx, trustSet.ActiveGenerationID)
		if err != nil {
			return TrustSetInspection{}, err
		}
		inspection.ActiveGeneration = pointerToTrustSetGeneration(generation)
	}
	if trustSet.StagedGenerationID != "" {
		generation, err := s.persistence.TrustSetGeneration(ctx, trustSet.StagedGenerationID)
		if err != nil {
			return TrustSetInspection{}, err
		}
		inspection.StagedGeneration = pointerToTrustSetGeneration(generation)
	}
	return inspection, nil
}

func (s Service) CreateTrustSet(ctx context.Context, request CreateTrustSetRequest) (domainpki.TrustSet, error) {
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	normalizedRequest.Name = strings.TrimSpace(request.Name)
	scope, replayed, exists, err := prepareMutation[domainpki.TrustSet](ctx, s, request.IdempotencyKey, MutationTrustSetCreate, normalizedRequest)
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	if exists {
		return replayed, nil
	}
	id := request.ID
	if id == "" {
		id, err = s.newTrustSetID("trust")
		if err != nil {
			return domainpki.TrustSet{}, err
		}
	}
	now := s.clock.Now().UTC()
	trustSet, err := domainpki.NewTrustSet(domainpki.TrustSetArgs{
		ID: id, Name: normalizedRequest.Name, State: domainpki.TrustSetStatePending,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionTrustSetCreate, AuditOutcomeSucceeded, auditResourceTrustSet, string(id), nil)
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	return commitMutation(ctx, s, scope, MutationTrustSetCreate, auditResourceTrustSet, string(id), trustSet,
		func(mutation MutationRecord) error {
			return s.persistence.CreateTrustSet(ctx, trustSet, audit, mutation)
		})
}

func (s Service) StageTrustSet(ctx context.Context, request StageTrustSetRequest) (TrustSetInspection, error) {
	if err := request.TrustSetID.Validate(); err != nil {
		return TrustSetInspection{}, err
	}
	if request.ExpectedRevision == 0 {
		return TrustSetInspection{}, errors.New("pki: expected trust set revision must be positive")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[TrustSetInspection](ctx, s, request.IdempotencyKey, MutationTrustSetStage, normalizedRequest)
	if err != nil {
		return TrustSetInspection{}, err
	}
	if exists {
		return replayed, nil
	}
	trustSet, err := s.persistence.TrustSet(ctx, request.TrustSetID)
	if err != nil {
		return TrustSetInspection{}, err
	}
	if trustSet.Revision != request.ExpectedRevision {
		return TrustSetInspection{}, ErrRevisionConflict
	}
	if trustSet.State == domainpki.TrustSetStateRetired {
		return TrustSetInspection{}, errors.New("pki: retired trust set cannot stage a generation")
	}
	if trustSet.StagedGenerationID != "" {
		return TrustSetInspection{}, errors.New("pki: trust set already has a staged generation")
	}
	if err := s.validateTrustCertificateGenerations(ctx, request.AnchorGenerationIDs); err != nil {
		return TrustSetInspection{}, err
	}
	if err := s.validateTrustCertificateGenerations(ctx, request.IntermediateGenerationIDs); err != nil {
		return TrustSetInspection{}, err
	}
	if err := s.validateTrustCRLGenerations(ctx, request.CRLGenerationIDs,
		request.AnchorGenerationIDs, request.IntermediateGenerationIDs, s.clock.Now().UTC()); err != nil {
		return TrustSetInspection{}, err
	}
	generations, err := s.persistence.TrustSetGenerations(ctx, trustSet.ID)
	if err != nil {
		return TrustSetInspection{}, err
	}
	generationNumber, err := nextTrustSetGenerationNumber(generations)
	if err != nil {
		return TrustSetInspection{}, err
	}
	generationID := request.GenerationID
	if generationID == "" {
		generationID, err = s.newTrustSetGenerationID("trustgen")
		if err != nil {
			return TrustSetInspection{}, err
		}
	}
	now := s.clock.Now().UTC()
	generation, err := domainpki.NewTrustSetGeneration(domainpki.TrustSetGenerationArgs{
		ID: generationID, TrustSetID: trustSet.ID, Generation: generationNumber,
		AnchorGenerationIDs: request.AnchorGenerationIDs, IntermediateGenerationIDs: request.IntermediateGenerationIDs,
		CRLGenerationIDs: request.CRLGenerationIDs, CreatedAt: now,
	})
	if err != nil {
		return TrustSetInspection{}, err
	}
	staged := trustSet
	staged.StagedGenerationID = generation.ID
	staged.Revision, err = nextRevision(trustSet.Revision)
	if err != nil {
		return TrustSetInspection{}, err
	}
	staged.UpdatedAt = now
	if err := staged.Validate(); err != nil {
		return TrustSetInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionTrustSetStage, AuditOutcomeSucceeded, auditResourceTrustSet, string(trustSet.ID), map[string]string{"trustSetGenerationId": string(generation.ID)})
	if err != nil {
		return TrustSetInspection{}, err
	}
	result := TrustSetInspection{TrustSet: staged, StagedGeneration: pointerToTrustSetGeneration(generation)}
	return commitMutation(ctx, s, scope, MutationTrustSetStage, auditResourceTrustSet, string(trustSet.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.StageTrustSetGeneration(ctx, request.ExpectedRevision, staged, generation, audit, mutation)
		})
}

func (s Service) ActivateTrustSet(ctx context.Context, request ActivateTrustSetRequest) (TrustSetInspection, error) {
	if err := request.TrustSetID.Validate(); err != nil {
		return TrustSetInspection{}, err
	}
	if request.ExpectedRevision == 0 {
		return TrustSetInspection{}, errors.New("pki: expected trust set revision must be positive")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[TrustSetInspection](ctx, s, request.IdempotencyKey, MutationTrustSetActivate, normalizedRequest)
	if err != nil {
		return TrustSetInspection{}, err
	}
	if exists {
		return replayed, nil
	}
	trustSet, err := s.persistence.TrustSet(ctx, request.TrustSetID)
	if err != nil {
		return TrustSetInspection{}, err
	}
	if trustSet.Revision != request.ExpectedRevision {
		return TrustSetInspection{}, ErrRevisionConflict
	}
	if trustSet.StagedGenerationID == "" {
		return TrustSetInspection{}, errors.New("pki: trust set has no staged generation")
	}
	generation, err := s.persistence.TrustSetGeneration(ctx, trustSet.StagedGenerationID)
	if err != nil {
		return TrustSetInspection{}, err
	}
	if generation.TrustSetID != trustSet.ID {
		return TrustSetInspection{}, errors.New("pki: staged trust generation belongs to another trust set")
	}
	if err := s.validateTrustSetGeneration(ctx, generation); err != nil {
		return TrustSetInspection{}, err
	}
	updated := trustSet
	updated.ActiveGenerationID = trustSet.StagedGenerationID
	updated.StagedGenerationID = ""
	updated.State = domainpki.TrustSetStateActive
	updated.Revision, err = nextRevision(trustSet.Revision)
	if err != nil {
		return TrustSetInspection{}, err
	}
	updated.UpdatedAt = s.clock.Now().UTC()
	if err := updated.Validate(); err != nil {
		return TrustSetInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionTrustSetActivate, AuditOutcomeSucceeded, auditResourceTrustSet, string(trustSet.ID), map[string]string{"trustSetGenerationId": string(generation.ID)})
	if err != nil {
		return TrustSetInspection{}, err
	}
	result := TrustSetInspection{TrustSet: updated, ActiveGeneration: pointerToTrustSetGeneration(generation)}
	return commitMutation(ctx, s, scope, MutationTrustSetActivate, auditResourceTrustSet, string(trustSet.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.UpdateTrustSet(ctx, request.ExpectedRevision, updated, audit, mutation)
		})
}

func (s Service) BindAssignment(ctx context.Context, request BindAssignmentRequest) (domainpki.Assignment, error) {
	if request.RotationPolicyID != "" {
		return domainpki.Assignment{}, errors.New("pki: rotation policies are not implemented; omit rotationPolicyId")
	}
	profile, ok := domainpki.BuiltInProfile(request.ProfileID)
	if !ok {
		return domainpki.Assignment{}, fmt.Errorf("pki: unknown profile %q", request.ProfileID)
	}
	if profile.Purpose != request.Purpose {
		return domainpki.Assignment{}, errors.New("pki: assignment purpose does not match profile")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[domainpki.Assignment](ctx, s, request.IdempotencyKey, MutationAssignmentBind, normalizedRequest)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	if exists {
		return replayed, nil
	}
	if err := s.validateAssignmentTrustSet(ctx, request.Purpose, request.TrustSetID); err != nil {
		return domainpki.Assignment{}, err
	}
	id := request.ID
	if id == "" {
		id, err = s.newAssignmentID("assignment")
		if err != nil {
			return domainpki.Assignment{}, err
		}
	}
	assignment, err := domainpki.NewAssignment(domainpki.AssignmentArgs{
		ID: id, Purpose: request.Purpose, ConsumerType: request.ConsumerType, ConsumerID: request.ConsumerID,
		ProfileID: request.ProfileID, TrustSetID: request.TrustSetID, RotationPolicyID: request.RotationPolicyID,
		State: domainpki.AssignmentStatePending, Revision: 1, UpdatedAt: s.clock.Now().UTC(),
	})
	if err != nil {
		return domainpki.Assignment{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAssignmentBind, AuditOutcomeSucceeded, auditResourceAssignment, string(id), map[string]string{"consumerType": string(assignment.ConsumerType), "consumerId": string(assignment.ConsumerID)})
	if err != nil {
		return domainpki.Assignment{}, err
	}
	return commitMutation(ctx, s, scope, MutationAssignmentBind, auditResourceAssignment, string(id), assignment,
		func(mutation MutationRecord) error {
			return s.persistence.CreateAssignment(ctx, assignment, audit, mutation)
		})
}

func (s Service) StageAssignment(ctx context.Context, request StageAssignmentRequest) (AssignmentInspection, error) {
	if err := request.AssignmentID.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	if err := request.GenerationID.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	if request.ExpectedRevision == 0 {
		return AssignmentInspection{}, errors.New("pki: expected assignment revision must be positive")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[AssignmentInspection](ctx, s, request.IdempotencyKey, MutationAssignmentStage, normalizedRequest)
	if err != nil {
		return AssignmentInspection{}, err
	}
	if exists {
		return replayed, nil
	}
	assignment, err := s.persistence.Assignment(ctx, request.AssignmentID)
	if err != nil {
		return AssignmentInspection{}, err
	}
	if assignment.Revision != request.ExpectedRevision {
		return AssignmentInspection{}, ErrRevisionConflict
	}
	if assignment.State == domainpki.AssignmentStateDisabled || assignment.State == domainpki.AssignmentStateRetired {
		return AssignmentInspection{}, fmt.Errorf("pki: %s assignment cannot stage a generation", assignment.State)
	}
	if assignment.StagedGenerationID != "" {
		return AssignmentInspection{}, errors.New("pki: assignment already has a staged generation")
	}
	generation, err := s.persistence.Generation(ctx, request.GenerationID)
	if err != nil {
		return AssignmentInspection{}, err
	}
	now := s.clock.Now().UTC()
	if err := validateAssignmentGenerationAt(assignment, generation, now); err != nil {
		return AssignmentInspection{}, err
	}
	trustGenerationID, err := s.resolveAssignmentTrustGeneration(ctx, assignment.Purpose, assignment.TrustSetID)
	if err != nil {
		return AssignmentInspection{}, err
	}
	updated := assignment
	updated.StagedGenerationID = generation.ID
	updated.StagedTrustGenerationID = trustGenerationID
	updated.Revision, err = nextRevision(assignment.Revision)
	if err != nil {
		return AssignmentInspection{}, err
	}
	updated.UpdatedAt = now
	if err := updated.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAssignmentStage, AuditOutcomeSucceeded, auditResourceAssignment, string(assignment.ID), map[string]string{"certificateGenerationId": string(generation.ID)})
	if err != nil {
		return AssignmentInspection{}, err
	}
	inspection := AssignmentInspection{Assignment: updated, StagedGeneration: pointerToGeneration(generation)}
	if trustGenerationID != "" {
		trustGeneration, err := s.persistence.TrustSetGeneration(ctx, trustGenerationID)
		if err != nil {
			return AssignmentInspection{}, err
		}
		inspection.StagedTrustGeneration = pointerToTrustSetGeneration(trustGeneration)
	}
	return commitMutation(ctx, s, scope, MutationAssignmentStage, auditResourceAssignment, string(assignment.ID), inspection,
		func(mutation MutationRecord) error {
			return s.persistence.UpdateAssignment(ctx, request.ExpectedRevision, updated, audit, mutation)
		})
}

func (s Service) ActivateAssignment(ctx context.Context, request ActivateAssignmentRequest) (AssignmentInspection, error) {
	if err := request.AssignmentID.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	if request.ExpectedRevision == 0 {
		return AssignmentInspection{}, errors.New("pki: expected assignment revision must be positive")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[AssignmentInspection](ctx, s, request.IdempotencyKey, MutationAssignmentActivate, normalizedRequest)
	if err != nil {
		return AssignmentInspection{}, err
	}
	if exists {
		return replayed, nil
	}
	assignment, err := s.persistence.Assignment(ctx, request.AssignmentID)
	if err != nil {
		return AssignmentInspection{}, err
	}
	if assignment.Revision != request.ExpectedRevision {
		return AssignmentInspection{}, ErrRevisionConflict
	}
	if assignment.StagedGenerationID == "" {
		return AssignmentInspection{}, errors.New("pki: assignment has no staged generation")
	}
	generation, err := s.persistence.Generation(ctx, assignment.StagedGenerationID)
	if err != nil {
		return AssignmentInspection{}, err
	}
	now := s.clock.Now().UTC()
	if err := validateAssignmentGenerationAt(assignment, generation, now); err != nil {
		return AssignmentInspection{}, err
	}
	if assignment.Purpose.RequiresPeerTrust() && assignment.StagedTrustGenerationID == "" {
		return AssignmentInspection{}, errors.New("pki: assignment has no staged trust generation")
	}
	if assignment.StagedTrustGenerationID != "" {
		if _, err := s.assignmentTrustGeneration(ctx, assignment, assignment.StagedTrustGenerationID); err != nil {
			return AssignmentInspection{}, err
		}
	}
	if err := s.validateAssignmentTrustSet(ctx, assignment.Purpose, assignment.TrustSetID); err != nil {
		return AssignmentInspection{}, err
	}
	updated := assignment
	updated.ActiveGenerationID = assignment.StagedGenerationID
	updated.ActiveTrustGenerationID = assignment.StagedTrustGenerationID
	updated.StagedGenerationID = ""
	updated.StagedTrustGenerationID = ""
	updated.State = domainpki.AssignmentStateActive
	updated.Revision, err = nextRevision(assignment.Revision)
	if err != nil {
		return AssignmentInspection{}, err
	}
	updated.UpdatedAt = now
	if err := updated.Validate(); err != nil {
		return AssignmentInspection{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAssignmentActivate, AuditOutcomeSucceeded, auditResourceAssignment, string(assignment.ID), map[string]string{"certificateGenerationId": string(generation.ID)})
	if err != nil {
		return AssignmentInspection{}, err
	}
	inspection := AssignmentInspection{Assignment: updated, ActiveGeneration: pointerToGeneration(generation)}
	if updated.ActiveTrustGenerationID != "" {
		trustGeneration, err := s.persistence.TrustSetGeneration(ctx, updated.ActiveTrustGenerationID)
		if err != nil {
			return AssignmentInspection{}, err
		}
		inspection.ActiveTrustGeneration = pointerToTrustSetGeneration(trustGeneration)
	}
	return commitMutation(ctx, s, scope, MutationAssignmentActivate, auditResourceAssignment, string(assignment.ID), inspection,
		func(mutation MutationRecord) error {
			return s.persistence.UpdateAssignment(ctx, request.ExpectedRevision, updated, audit, mutation)
		})
}

func (s Service) UnbindAssignment(ctx context.Context, request UnbindAssignmentRequest) (domainpki.Assignment, error) {
	if err := request.AssignmentID.Validate(); err != nil {
		return domainpki.Assignment{}, err
	}
	if request.ExpectedRevision == 0 {
		return domainpki.Assignment{}, errors.New("pki: expected assignment revision must be positive")
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	scope, replayed, exists, err := prepareMutation[domainpki.Assignment](ctx, s, request.IdempotencyKey, MutationAssignmentUnbind, normalizedRequest)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	if exists {
		return replayed, nil
	}
	assignment, err := s.persistence.Assignment(ctx, request.AssignmentID)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	if assignment.Revision != request.ExpectedRevision {
		return domainpki.Assignment{}, ErrRevisionConflict
	}
	if assignment.State == domainpki.AssignmentStateRetired {
		return domainpki.Assignment{}, errors.New("pki: assignment is already retired")
	}
	updated := assignment
	updated.StagedGenerationID = ""
	updated.StagedTrustGenerationID = ""
	updated.State = domainpki.AssignmentStateRetired
	updated.Revision, err = nextRevision(assignment.Revision)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	updated.UpdatedAt = s.clock.Now().UTC()
	if err := updated.Validate(); err != nil {
		return domainpki.Assignment{}, err
	}
	audit, err := s.newAuditRecord(scope.audit, AuditActionAssignmentUnbind, AuditOutcomeSucceeded, auditResourceAssignment, string(assignment.ID), nil)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	return commitMutation(ctx, s, scope, MutationAssignmentUnbind, auditResourceAssignment, string(assignment.ID), updated,
		func(mutation MutationRecord) error {
			return s.persistence.UpdateAssignment(ctx, request.ExpectedRevision, updated, audit, mutation)
		})
}

func (s Service) validateTrustCertificateGenerations(ctx context.Context, ids []domainpki.GenerationID) error {
	for _, id := range ids {
		generation, err := s.persistence.Generation(ctx, id)
		if err != nil {
			return err
		}
		if !generation.Template.BasicConstraints.IsCA {
			return fmt.Errorf("pki: trust certificate generation %q is not a certificate authority", id)
		}
		if generation.State != domainpki.CertificateStateActive && generation.State != domainpki.CertificateStateSuperseded {
			return fmt.Errorf("pki: trust certificate generation %q is not usable", id)
		}
	}
	return nil
}

func (s Service) validateAssignmentTrustSet(ctx context.Context, purpose domainpki.Purpose, id domainpki.TrustSetID) error {
	_, err := s.resolveAssignmentTrustGeneration(ctx, purpose, id)
	return err
}

func (s Service) resolveAssignmentTrustGeneration(ctx context.Context, purpose domainpki.Purpose, id domainpki.TrustSetID) (domainpki.TrustSetGenerationID, error) {
	if id == "" {
		if purpose.RequiresPeerTrust() {
			return "", errors.New("pki: assignment purpose requires a trust set")
		}
		return "", nil
	}
	trustSet, err := s.persistence.TrustSet(ctx, id)
	if err != nil {
		return "", err
	}
	if trustSet.State != domainpki.TrustSetStateActive || trustSet.ActiveGenerationID == "" {
		return "", errors.New("pki: assignment trust set is not active")
	}
	generation, err := s.persistence.TrustSetGeneration(ctx, trustSet.ActiveGenerationID)
	if err != nil {
		return "", err
	}
	if generation.TrustSetID != trustSet.ID {
		return "", errors.New("pki: active trust generation belongs to another trust set")
	}
	if err := s.validateTrustSetGeneration(ctx, generation); err != nil {
		return "", err
	}
	return generation.ID, nil
}

func (s Service) assignmentTrustGeneration(ctx context.Context, assignment domainpki.Assignment, id domainpki.TrustSetGenerationID) (domainpki.TrustSetGeneration, error) {
	generation, err := s.persistence.TrustSetGeneration(ctx, id)
	if err != nil {
		return domainpki.TrustSetGeneration{}, err
	}
	if generation.TrustSetID != assignment.TrustSetID {
		return domainpki.TrustSetGeneration{}, errors.New("pki: assignment trust generation belongs to another trust set")
	}
	if err := s.validateTrustSetGeneration(ctx, generation); err != nil {
		return domainpki.TrustSetGeneration{}, err
	}
	return generation, nil
}

func (s Service) validateTrustSetGeneration(ctx context.Context, generation domainpki.TrustSetGeneration) error {
	material, err := s.loadTrustMaterial(ctx, generation)
	if err != nil {
		return err
	}
	return domainpki.ValidateTrustSetGenerationMaterial(generation, material, s.clock.Now().UTC())
}

func (s Service) loadTrustMaterial(
	ctx context.Context,
	generation domainpki.TrustSetGeneration,
) (domainpki.TrustMaterial, error) {
	certificateIDs := make([]domainpki.GenerationID, 0,
		len(generation.AnchorGenerationIDs)+len(generation.IntermediateGenerationIDs))
	certificateIDs = append(certificateIDs, generation.AnchorGenerationIDs...)
	certificateIDs = append(certificateIDs, generation.IntermediateGenerationIDs...)
	material := domainpki.TrustMaterial{
		Certificates: make([]domainpki.CertificateGeneration, 0, len(certificateIDs)),
		CRLs:         make([]domainpki.CRLGeneration, 0, len(generation.CRLGenerationIDs)),
	}
	for _, id := range certificateIDs {
		certificate, err := s.persistence.Generation(ctx, id)
		if err != nil {
			return domainpki.TrustMaterial{}, err
		}
		material.Certificates = append(material.Certificates, certificate)
	}
	for _, id := range generation.CRLGenerationIDs {
		crl, err := s.persistence.CRLGeneration(ctx, id)
		if err != nil {
			return domainpki.TrustMaterial{}, err
		}
		material.CRLs = append(material.CRLs, crl)
	}
	return material, nil
}

func (s Service) validateTrustCRLGenerations(
	ctx context.Context,
	crlIDs []domainpki.CRLGenerationID,
	anchorIDs []domainpki.GenerationID,
	intermediateIDs []domainpki.GenerationID,
	now time.Time,
) error {
	trustedIssuers := make(map[domainpki.GenerationID]struct{}, len(anchorIDs)+len(intermediateIDs))
	for _, id := range anchorIDs {
		trustedIssuers[id] = struct{}{}
	}
	for _, id := range intermediateIDs {
		trustedIssuers[id] = struct{}{}
	}
	for _, id := range crlIDs {
		generation, err := s.persistence.CRLGeneration(ctx, id)
		if err != nil {
			return err
		}
		if err := generation.Validate(); err != nil {
			return fmt.Errorf("pki: validate trust crl generation %q: %w", id, err)
		}
		if !generation.FreshAt(now) {
			return fmt.Errorf("pki: trust crl generation %q is not fresh", id)
		}
		if _, trusted := trustedIssuers[generation.IssuerGenerationID]; !trusted {
			return fmt.Errorf("pki: trust crl generation %q issuer is not in the trust generation", id)
		}
	}
	return nil
}

func validateAssignmentGeneration(assignment domainpki.Assignment, generation domainpki.CertificateGeneration) error {
	if generation.ProfileID != assignment.ProfileID || generation.Purpose != assignment.Purpose {
		return errors.New("pki: certificate generation does not match assignment profile and purpose")
	}
	if generation.State != domainpki.CertificateStateActive {
		return errors.New("pki: assignment certificate generation is not active")
	}
	return nil
}

func validateAssignmentGenerationAt(
	assignment domainpki.Assignment,
	generation domainpki.CertificateGeneration,
	now time.Time,
) error {
	if err := validateAssignmentGeneration(assignment, generation); err != nil {
		return err
	}
	if now.Before(generation.Template.NotBefore) || !now.Before(generation.Template.NotAfter) {
		return fmt.Errorf(
			"pki: assignment certificate generation %q is not currently valid",
			generation.ID,
		)
	}
	return nil
}

func nextRevision(current uint64) (uint64, error) {
	if current == 0 || current == math.MaxUint64 {
		return 0, errors.New("pki: revision is invalid or exhausted")
	}
	return current + 1, nil
}

func nextTrustSetGenerationNumber(generations []domainpki.TrustSetGeneration) (uint64, error) {
	var maximum uint64
	for _, generation := range generations {
		if generation.Generation > maximum {
			maximum = generation.Generation
		}
	}
	if maximum == math.MaxUint64 {
		return 0, errors.New("pki: trust set generation counter is exhausted")
	}
	return maximum + 1, nil
}

func pointerToGeneration(generation domainpki.CertificateGeneration) *domainpki.CertificateGeneration {
	clone := generation.Clone()
	return &clone
}

func pointerToTrustSetGeneration(generation domainpki.TrustSetGeneration) *domainpki.TrustSetGeneration {
	clone := generation.Clone()
	return &clone
}

func (s Service) newAssignmentID(prefix string) (domainpki.AssignmentID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewAssignmentID(value)
}

func (s Service) newTrustSetID(prefix string) (domainpki.TrustSetID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewTrustSetID(value)
}

func (s Service) newTrustSetGenerationID(prefix string) (domainpki.TrustSetGenerationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewTrustSetGenerationID(value)
}
