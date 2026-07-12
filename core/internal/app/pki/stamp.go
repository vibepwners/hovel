package pki

import (
	"context"
	"errors"
	"fmt"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const CredentialStampResourceType = "credential-stamp"

func CredentialStampLifecycleContract(
	status domainpki.CredentialStampStatus,
) (MutationKind, AuditAction, AuditOutcome, error) {
	switch status {
	case domainpki.CredentialStampPending:
		return MutationCredentialStampCreate, AuditActionCredentialStampPlan,
			AuditOutcomeAttempted, nil
	case domainpki.CredentialStampSucceeded:
		return MutationCredentialStampSucceed, AuditActionCredentialStampSucceed,
			AuditOutcomeSucceeded, nil
	case domainpki.CredentialStampFailed:
		return MutationCredentialStampFail, AuditActionCredentialStampFail,
			AuditOutcomeFailed, nil
	case domainpki.CredentialStampSuperseded:
		return MutationCredentialStampSupersede, AuditActionCredentialStampSupersede,
			AuditOutcomeSucceeded, nil
	default:
		return "", "", "", fmt.Errorf(
			"pki: credential stamp status %q has no lifecycle contract", status,
		)
	}
}

func (s Service) ListCredentialStamps(ctx context.Context) ([]domainpki.CredentialStamp, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stamps, err := s.persistence.CredentialStamps(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.CredentialStamp, len(stamps))
	for i, stamp := range stamps {
		if err := stamp.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed credential stamp: %w", err)
		}
		result[i] = stamp.Clone()
	}
	return result, nil
}

func (s Service) InspectCredentialStamp(
	ctx context.Context,
	id domainpki.StampID,
) (domainpki.CredentialStamp, error) {
	if err := id.Validate(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	stamp, err := s.persistence.CredentialStamp(ctx, id)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if err := stamp.Validate(); err != nil {
		return domainpki.CredentialStamp{}, fmt.Errorf("pki: validate inspected credential stamp: %w", err)
	}
	return stamp.Clone(), nil
}

func (s Service) RecordCredentialStampPlan(
	ctx context.Context,
	idempotencyKey string,
	stamp domainpki.CredentialStamp,
) (domainpki.CredentialStamp, error) {
	if err := stamp.Validate(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if stamp.Status != domainpki.CredentialStampPending {
		return domainpki.CredentialStamp{}, errors.New("pki: credential stamp plan must be pending")
	}
	kind, action, outcome, err := CredentialStampLifecycleContract(stamp.Status)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	scope, replay, exists, err := prepareMutation[domainpki.CredentialStamp](
		ctx, s, idempotencyKey, kind, stamp,
	)
	if err != nil || exists {
		return replay, err
	}
	assignment, err := s.persistence.Assignment(ctx, stamp.Plan.Request.AssignmentID)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if err := domainpki.ValidateCredentialStampAssignment(
		assignment, stamp.Plan.Request,
	); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	audit, err := s.newAuditRecord(
		scope.audit, action, outcome,
		CredentialStampResourceType, string(stamp.ID),
		map[string]string{
			"assignmentId": string(stamp.Plan.Request.AssignmentID),
			"providerId":   string(stamp.ProviderID),
			"capability":   string(stamp.Plan.Request.Capability),
		},
	)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	return commitMutation(
		ctx, s, scope, kind,
		CredentialStampResourceType, string(stamp.ID), stamp.Clone(),
		func(mutation MutationRecord) error {
			return s.persistence.CreateCredentialStamp(ctx, stamp, audit, mutation)
		},
	)
}

func (s Service) RecordCredentialStampTransition(
	ctx context.Context,
	idempotencyKey string,
	stamp domainpki.CredentialStamp,
) (domainpki.CredentialStamp, error) {
	if err := stamp.Validate(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if stamp.Status == domainpki.CredentialStampPending {
		return domainpki.CredentialStamp{}, errors.New("pki: credential stamp transition must be terminal")
	}
	kind, action, outcome, err := CredentialStampLifecycleContract(stamp.Status)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	scope, replay, exists, err := prepareMutation[domainpki.CredentialStamp](
		ctx, s, idempotencyKey, kind, stamp,
	)
	if err != nil || exists {
		return replay, err
	}
	previous, err := s.persistence.CredentialStamp(ctx, stamp.ID)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if err := domainpki.ValidateCredentialStampTransition(previous, stamp); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	audit, err := s.newAuditRecord(
		scope.audit, action, outcome,
		CredentialStampResourceType, string(stamp.ID),
		map[string]string{"status": string(stamp.Status)},
	)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	return commitMutation(
		ctx, s, scope, kind,
		CredentialStampResourceType, string(stamp.ID), stamp.Clone(),
		func(mutation MutationRecord) error {
			return s.persistence.UpdateCredentialStamp(
				ctx, previous.Revision, stamp, audit, mutation,
			)
		},
	)
}
