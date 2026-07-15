package pki

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const CredentialExecutionResourceType = "credential-execution"

// ErrCredentialExecutionInProgress reports a retry that matches a durable
// pending execution. Callers must not repeat the provider side effect.
var ErrCredentialExecutionInProgress = errors.New("pki: credential execution is already in progress")

type credentialExecutionPlanIdentity struct {
	ID   domainpki.CredentialExecutionRequestID `json:"id"`
	Plan domainpki.CredentialExecutionPlan      `json:"plan"`
}

func CredentialExecutionLifecycleContract(
	status domainpki.CredentialExecutionStatus,
) (MutationKind, AuditAction, AuditOutcome, error) {
	switch status {
	case domainpki.CredentialExecutionPending:
		return MutationCredentialExecutionCreate, AuditActionCredentialExecutionPlan,
			AuditOutcomeAttempted, nil
	case domainpki.CredentialExecutionSucceeded:
		return MutationCredentialExecutionSucceed, AuditActionCredentialExecutionSucceed,
			AuditOutcomeSucceeded, nil
	case domainpki.CredentialExecutionFailed:
		return MutationCredentialExecutionFail, AuditActionCredentialExecutionFail,
			AuditOutcomeFailed, nil
	default:
		return "", "", "", fmt.Errorf(
			"pki: credential execution status %q has no lifecycle contract", status,
		)
	}
}

func (s Service) ListCredentialExecutions(ctx context.Context) ([]domainpki.CredentialExecution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	executions, err := s.persistence.CredentialExecutions(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.CredentialExecution, len(executions))
	for i, execution := range executions {
		if err := execution.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed credential execution: %w", err)
		}
		result[i] = execution.Clone()
	}
	return result, nil
}

func (s Service) InspectCredentialExecution(
	ctx context.Context,
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	if err := id.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	execution, err := s.persistence.CredentialExecution(ctx, id)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if err := execution.Validate(); err != nil {
		return domainpki.CredentialExecution{}, fmt.Errorf(
			"pki: validate inspected credential execution: %w", err,
		)
	}
	return execution.Clone(), nil
}

func (s Service) RecordCredentialExecutionPlan(
	ctx context.Context,
	idempotencyKey string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if execution.Status != domainpki.CredentialExecutionPending {
		return domainpki.CredentialExecution{}, errors.New("pki: credential execution plan must be pending")
	}
	if existing, exists, err := s.resolveCredentialExecutionPlan(ctx, execution); err != nil || exists {
		return existing, err
	}
	kind, action, outcome, err := CredentialExecutionLifecycleContract(execution.Status)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	scope, replay, exists, err := prepareMutation[domainpki.CredentialExecution](
		ctx, s, idempotencyKey, kind, credentialExecutionPlanIdentity{
			ID: execution.ID, Plan: execution.Plan.Clone(),
		},
	)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if exists {
		return s.resolveReplayedCredentialExecutionPlan(replay, execution)
	}
	if execution.Plan.Kind != domainpki.CredentialExecutionEncoding {
		assignment, err := s.persistence.Assignment(ctx, execution.Plan.AssignmentID)
		if err != nil {
			return domainpki.CredentialExecution{}, err
		}
		if err := domainpki.ValidateCredentialExecutionAssignment(assignment, execution.Plan); err != nil {
			return domainpki.CredentialExecution{}, err
		}
	}
	audit, err := s.newAuditRecord(
		scope.audit, action, outcome,
		CredentialExecutionResourceType, string(execution.ID),
		map[string]string{
			"kind":       string(execution.Plan.Kind),
			"providerId": string(execution.Plan.Provider.ProviderID),
			"moduleId":   execution.Plan.Provider.ModuleID,
		},
	)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	mutation, err := s.newMutationRecord(
		kind, scope, CredentialExecutionResourceType, string(execution.ID), execution.Clone(),
	)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if err := s.persistence.CreateCredentialExecution(ctx, execution, audit, mutation); err != nil {
		if existing, exists, resolveErr := s.resolveCredentialExecutionPlan(ctx, execution); resolveErr != nil || exists {
			return existing, resolveErr
		}
		return domainpki.CredentialExecution{}, err
	}
	return execution.Clone(), nil
}

func (s Service) resolveCredentialExecutionPlan(
	ctx context.Context,
	requested domainpki.CredentialExecution,
) (domainpki.CredentialExecution, bool, error) {
	existing, err := s.persistence.CredentialExecution(ctx, requested.ID)
	if errors.Is(err, ErrNotFound) {
		return domainpki.CredentialExecution{}, false, nil
	}
	if err != nil {
		return domainpki.CredentialExecution{}, false, err
	}
	resolved, err := s.resolveReplayedCredentialExecutionPlan(existing, requested)
	return resolved, true, err
}

func (s Service) resolveReplayedCredentialExecutionPlan(
	existing domainpki.CredentialExecution,
	requested domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	if err := existing.Validate(); err != nil {
		return domainpki.CredentialExecution{}, fmt.Errorf(
			"pki: validate existing credential execution: %w", err,
		)
	}
	if existing.ID != requested.ID || !reflect.DeepEqual(existing.Plan, requested.Plan) {
		return domainpki.CredentialExecution{}, ErrIdempotencyConflict
	}
	if existing.Status == domainpki.CredentialExecutionPending {
		return domainpki.CredentialExecution{}, ErrCredentialExecutionInProgress
	}
	return existing.Clone(), nil
}

func (s Service) RecordCredentialExecutionTransition(
	ctx context.Context,
	idempotencyKey string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if execution.Status == domainpki.CredentialExecutionPending {
		return domainpki.CredentialExecution{}, errors.New("pki: credential execution transition must be terminal")
	}
	kind, action, outcome, err := CredentialExecutionLifecycleContract(execution.Status)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	scope, replay, exists, err := prepareMutation[domainpki.CredentialExecution](
		ctx, s, idempotencyKey, kind, execution,
	)
	if err != nil || exists {
		return replay, err
	}
	previous, err := s.persistence.CredentialExecution(ctx, execution.ID)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if err := domainpki.ValidateCredentialExecutionTransition(previous, execution); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	audit, err := s.newAuditRecord(
		scope.audit, action, outcome,
		CredentialExecutionResourceType, string(execution.ID),
		map[string]string{"status": string(execution.Status)},
	)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	return commitMutation(
		ctx, s, scope, kind,
		CredentialExecutionResourceType, string(execution.ID), execution.Clone(),
		func(mutation MutationRecord) error {
			return s.persistence.UpdateCredentialExecution(
				ctx, previous.Revision, execution, audit, mutation,
			)
		},
	)
}
