package pki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	auditDetailRevocationID            = "revocationId"
	auditDetailRevocationReason        = "reason"
	auditDetailRevocationEffectiveAt   = "effectiveAt"
	auditDetailAffectedAssignmentCount = "affectedAssignmentCount"
)

type RevokeCertificateRequest struct {
	IdempotencyKey string                     `json:"idempotencyKey,omitempty"`
	GenerationID   domainpki.GenerationID     `json:"generationId"`
	Reason         domainpki.RevocationReason `json:"reason"`
	EffectiveAt    time.Time                  `json:"effectiveAt,omitzero"`
}

type CertificateRevocationResult struct {
	Revocation          domainpki.Revocation            `json:"revocation"`
	Generation          domainpki.CertificateGeneration `json:"generation"`
	AffectedAssignments []domainpki.Assignment          `json:"affectedAssignments"`
}

func (r CertificateRevocationResult) Clone() CertificateRevocationResult {
	result := r
	result.Generation = r.Generation.Clone()
	result.AffectedAssignments = append([]domainpki.Assignment(nil), r.AffectedAssignments...)
	return result
}

func (r CertificateRevocationResult) Validate() error {
	if err := r.Revocation.Validate(); err != nil {
		return err
	}
	if err := r.Generation.Validate(); err != nil {
		return err
	}
	if r.Generation.ID != r.Revocation.GenerationID ||
		r.Generation.CertificateID != r.Revocation.CertificateID ||
		r.Generation.State != domainpki.CertificateStateRevoked {
		return errors.New("pki: revocation result generation does not match its record")
	}
	for index, assignment := range r.AffectedAssignments {
		if err := assignment.Validate(); err != nil {
			return err
		}
		if index > 0 && r.AffectedAssignments[index-1].ID >= assignment.ID {
			return errors.New("pki: affected assignments must be unique and sorted")
		}
	}
	return nil
}

// ValidateRevocationCommit verifies the exact typed state, audit, and public
// idempotency result that persistence must commit atomically.
func ValidateRevocationCommit(
	revoked domainpki.CertificateGeneration,
	revocation domainpki.Revocation,
	affected []domainpki.Assignment,
	audit AuditRecord,
	mutation MutationRecord,
) error {
	result := CertificateRevocationResult{
		Revocation: revocation, Generation: revoked, AffectedAssignments: affected,
	}
	if err := result.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.Action != AuditActionCertificateRevoke || audit.Outcome != AuditOutcomeSucceeded ||
		audit.ResourceType != auditResourceGeneration || audit.ResourceID != string(revocation.GenerationID) {
		return errors.New("pki: revocation audit does not identify the revoked generation")
	}
	expectedDetails := map[string]string{
		auditDetailRevocationID:            string(revocation.ID),
		auditDetailRevocationReason:        string(revocation.Reason),
		auditDetailRevocationEffectiveAt:   revocation.EffectiveAt.Format(time.RFC3339),
		auditDetailAffectedAssignmentCount: strconv.Itoa(len(affected)),
	}
	if !maps.Equal(audit.Details, expectedDetails) {
		return errors.New("pki: revocation audit details do not match the committed result")
	}
	if err := mutation.Validate(); err != nil {
		return err
	}
	if mutation.Kind != MutationCertificateRevoke || mutation.ResourceType != auditResourceGeneration ||
		mutation.ResourceID != string(revocation.GenerationID) {
		return errors.New("pki: revocation mutation does not identify the revoked generation")
	}
	expectedJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("pki: encode expected revocation result: %w", err)
	}
	if !bytes.Equal(expectedJSON, mutation.ResultJSON) {
		return errors.New("pki: revocation mutation result does not match the committed state")
	}
	return nil
}

func (s Service) InspectRevocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	if err := id.Validate(); err != nil {
		return domainpki.Revocation{}, err
	}
	revocation, err := s.persistence.Revocation(ctx, id)
	if err != nil {
		return domainpki.Revocation{}, err
	}
	if err := revocation.Validate(); err != nil {
		return domainpki.Revocation{}, fmt.Errorf("pki: validate inspected revocation: %w", err)
	}
	return revocation, nil
}

func (s Service) InspectGenerationRevocation(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	if err := id.Validate(); err != nil {
		return domainpki.Revocation{}, err
	}
	revocation, err := s.persistence.RevocationForGeneration(ctx, id)
	if err != nil {
		return domainpki.Revocation{}, err
	}
	if err := revocation.Validate(); err != nil {
		return domainpki.Revocation{}, fmt.Errorf("pki: validate generation revocation: %w", err)
	}
	return revocation, nil
}

func (s Service) ListAuthorityRevocations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	revocations, err := s.persistence.Revocations(ctx, id)
	if err != nil {
		return nil, err
	}
	result := append([]domainpki.Revocation(nil), revocations...)
	for index, revocation := range result {
		if err := revocation.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed revocation: %w", err)
		}
		if revocation.IssuerAuthorityID != id {
			return nil, errors.New("pki: listed revocation belongs to another authority")
		}
		if index > 0 {
			previous := result[index-1]
			isOutOfOrder := revocation.RecordedAt.Before(previous.RecordedAt) ||
				revocation.RecordedAt.Equal(previous.RecordedAt) && revocation.ID <= previous.ID
			if isOutOfOrder {
				return nil, errors.New("pki: revocations are not sorted by recording time and id")
			}
		}
	}
	return result, nil
}

func (s Service) RevokeCertificate(ctx context.Context, request RevokeCertificateRequest) (CertificateRevocationResult, error) {
	if err := request.GenerationID.Validate(); err != nil {
		return CertificateRevocationResult{}, err
	}
	if err := request.Reason.Validate(); err != nil {
		return CertificateRevocationResult{}, err
	}
	normalizedRequest := request
	normalizedRequest.IdempotencyKey = ""
	if !normalizedRequest.EffectiveAt.IsZero() {
		normalizedRequest.EffectiveAt = normalizedRequest.EffectiveAt.UTC().Truncate(time.Second)
	}
	scope, replayed, exists, err := prepareMutation[CertificateRevocationResult](
		ctx, s, request.IdempotencyKey, MutationCertificateRevoke, normalizedRequest,
	)
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	if exists {
		if err := replayed.Validate(); err != nil {
			return CertificateRevocationResult{}, fmt.Errorf("pki: validate replayed revocation: %w", err)
		}
		return replayed.Clone(), nil
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	effectiveAt := normalizedRequest.EffectiveAt
	if effectiveAt.IsZero() {
		effectiveAt = now
	}
	generation, err := s.persistence.Generation(ctx, request.GenerationID)
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	revocationID, err := s.newRevocationID("revocation")
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	revoked, revocation, err := domainpki.RevokeCertificateGeneration(
		generation, revocationID, request.Reason, effectiveAt, now,
	)
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	assignments, err := s.persistence.Assignments(ctx)
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	affected := make([]domainpki.Assignment, 0)
	for _, assignment := range assignments {
		updated, changed, updateErr := domainpki.ApplyGenerationRevocation(assignment, generation.ID, now)
		if updateErr != nil {
			return CertificateRevocationResult{}, updateErr
		}
		if changed {
			affected = append(affected, updated)
		}
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].ID < affected[j].ID })
	audit, err := s.newAuditRecord(
		scope.audit, AuditActionCertificateRevoke, AuditOutcomeSucceeded,
		auditResourceGeneration, string(generation.ID), map[string]string{
			auditDetailRevocationID:            string(revocation.ID),
			auditDetailRevocationReason:        string(revocation.Reason),
			auditDetailRevocationEffectiveAt:   revocation.EffectiveAt.Format(time.RFC3339),
			auditDetailAffectedAssignmentCount: strconv.Itoa(len(affected)),
		},
	)
	if err != nil {
		return CertificateRevocationResult{}, err
	}
	result := CertificateRevocationResult{
		Revocation: revocation, Generation: revoked, AffectedAssignments: affected,
	}
	if err := result.Validate(); err != nil {
		return CertificateRevocationResult{}, err
	}
	return commitMutation(
		ctx, s, scope, MutationCertificateRevoke, auditResourceGeneration, string(generation.ID), result,
		func(mutation MutationRecord) error {
			return s.persistence.RecordRevocation(ctx, revoked, revocation, affected, audit, mutation)
		},
	)
}
