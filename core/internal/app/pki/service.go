package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	resourceIDRandomBytes            = 16
	serialRandomBytes                = 16
	maxRandomRetries                 = 8
	auditResourceAuthority           = "authority"
	auditResourceGeneration          = "certificate-generation"
	auditResourceKey                 = "key"
	auditDetailGenerationID          = "certificateGenerationId"
	auditDetailIssuanceKind          = "issuanceKind"
	auditDetailSourceGenerationID    = "sourceGenerationId"
	issuanceFailureSigning           = "certificate signing failed"
	issuanceStageKeyGeneration       = "key-generation"
	issuanceStageKeyLoad             = "key-load"
	issuanceStageKeyValidation       = "key-validation"
	issuanceStageCertificateSigning  = "certificate-signing"
	issuanceStageResultConstruction  = "result-construction"
	issuanceStageLifecycleValidation = "lifecycle-validation"
	issuanceStageInventoryCommit     = "inventory-commit"
	issuanceStageReconciliation      = "reconciliation"
	minimumIssuanceReconcileAge      = time.Minute
	maximumIssuanceReconcileAge      = 24 * time.Hour
	issuanceFailureReconciled        = "issuance abandoned during reconciliation"
)

var (
	ErrNotFound               = errors.New("pki: not found")
	ErrRevisionConflict       = errors.New("pki: revision conflict")
	ErrPrivateKeyExportDenied = errors.New("pki: private key export is not allowed")
	ErrIssuanceInProgress     = errors.New("pki: issuance is already pending reconciliation")
	ErrMutationExists         = errors.New("pki: mutation idempotency key already exists")
	ErrAcknowledgementExists  = errors.New("pki: consumer acknowledgement already exists")
	ErrIdempotencyConflict    = errors.New("pki: idempotency key was already used for a different request")
)

type IssuancePersistence interface {
	BeginIssuance(context.Context, IssuanceIntent) (IssuanceIntent, bool, error)
	IssuanceByKey(context.Context, string) (IssuanceIntent, error)
	PendingIssuances(context.Context, time.Time, time.Time, int) ([]IssuanceIntent, error)
	ClaimIssuance(context.Context, domainpki.IssuanceID, IssuanceOwnership, string, time.Time) (IssuanceIntent, bool, error)
	CompleteAuthorityIssuance(context.Context, domainpki.IssuanceID, IssuanceOwnership, domainpki.Authority, domainpki.CertificateGeneration, ValidatedKeyMaterial, IssuanceCompletionAudits) error
	CompleteCertificateIssuance(context.Context, domainpki.IssuanceID, IssuanceOwnership, domainpki.CertificateGeneration, ValidatedKeyMaterial, IssuanceCompletionAudits) error
	CompleteCertificateRenewal(context.Context, domainpki.IssuanceID, IssuanceOwnership, domainpki.CertificateGeneration, ValidatedKeyMaterial, IssuanceCompletionAudits) error
	FailIssuance(context.Context, domainpki.IssuanceID, IssuanceOwnership, string, time.Time, AuditRecord) error
}

type InventoryPersistence interface {
	Authority(context.Context, domainpki.AuthorityID) (domainpki.Authority, error)
	Authorities(context.Context) ([]domainpki.Authority, error)
	Generation(context.Context, domainpki.GenerationID) (domainpki.CertificateGeneration, error)
	Generations(context.Context, domainpki.CertificateID) ([]domainpki.CertificateGeneration, error)
	CertificateGenerations(context.Context) ([]domainpki.CertificateGeneration, error)
	LoadKey(context.Context, domainpki.KeyID) (KeyMaterial, error)
	DeleteKey(context.Context, domainpki.KeyID) error
}

type AssignmentPersistence interface {
	MutationByKey(context.Context, string) (MutationRecord, error)
	CreateAssignment(context.Context, domainpki.Assignment, AuditRecord, MutationRecord) error
	Assignment(context.Context, domainpki.AssignmentID) (domainpki.Assignment, error)
	Assignments(context.Context) ([]domainpki.Assignment, error)
	UpdateAssignment(context.Context, uint64, domainpki.Assignment, AuditRecord, MutationRecord) error
	CreateTrustSet(context.Context, domainpki.TrustSet, AuditRecord, MutationRecord) error
	TrustSet(context.Context, domainpki.TrustSetID) (domainpki.TrustSet, error)
	TrustSets(context.Context) ([]domainpki.TrustSet, error)
	TrustSetGeneration(context.Context, domainpki.TrustSetGenerationID) (domainpki.TrustSetGeneration, error)
	TrustSetGenerations(context.Context, domainpki.TrustSetID) ([]domainpki.TrustSetGeneration, error)
	StageTrustSetGeneration(context.Context, uint64, domainpki.TrustSet, domainpki.TrustSetGeneration, AuditRecord, MutationRecord) error
	UpdateTrustSet(context.Context, uint64, domainpki.TrustSet, AuditRecord, MutationRecord) error
}

type RevocationPersistence interface {
	Revocation(context.Context, domainpki.RevocationID) (domainpki.Revocation, error)
	RevocationForGeneration(context.Context, domainpki.GenerationID) (domainpki.Revocation, error)
	Revocations(context.Context, domainpki.AuthorityID) ([]domainpki.Revocation, error)
	RecordRevocation(context.Context, domainpki.CertificateGeneration, domainpki.Revocation, []domainpki.Assignment, AuditRecord, MutationRecord) error
}

type CRLPersistence interface {
	BeginCRLPublication(context.Context, CRLPublicationIntent, []domainpki.Revocation) (CRLPublicationIntent, bool, error)
	CRLPublication(context.Context, domainpki.CRLPublicationID) (CRLPublicationIntent, error)
	CRLPublicationByKey(context.Context, string) (CRLPublicationIntent, error)
	CRLPublications(context.Context, domainpki.AuthorityID) ([]CRLPublicationIntent, error)
	PendingCRLPublications(context.Context, time.Time, time.Time, int) ([]CRLPublicationIntent, error)
	ClaimCRLPublication(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, string, time.Time) (CRLPublicationIntent, bool, error)
	StartCRLPublicationSigning(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, time.Time, AuditRecord) (CRLPublicationIntent, error)
	RenewCRLPublicationLease(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, time.Time) (CRLPublicationIntent, error)
	CheckpointCRLPublicationSigned(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, CRLSignedCheckpoint, AuditRecord) (CRLPublicationIntent, error)
	CompleteCRLPublication(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, domainpki.CRLGeneration, AuditRecord) error
	FailCRLPublication(context.Context, domainpki.CRLPublicationID, CRLPublicationOwnership, string, time.Time, CRLPublicationFailureStage, AuditRecord) error
	CRLGeneration(context.Context, domainpki.CRLGenerationID) (domainpki.CRLGeneration, error)
	CRLGenerations(context.Context, domainpki.AuthorityID) ([]domainpki.CRLGeneration, error)
}

type OperationPersistence interface {
	PKIOperation(context.Context, domainpki.OperationID) (domainpki.Operation, error)
	PKIOperations(context.Context) ([]domainpki.Operation, error)
	ConsumerAcknowledgements(context.Context, domainpki.OperationID) ([]domainpki.ConsumerAcknowledgement, error)
	CreateAuthorityRollover(context.Context, domainpki.Operation, AuditRecord, MutationRecord) error
	RecordConsumerAcknowledgement(context.Context, domainpki.ConsumerAcknowledgement, AuditRecord, MutationRecord) error
	ActivateAuthorityRollover(context.Context, uint64, uint64, domainpki.Operation, domainpki.Authority, domainpki.TrustSet, AuditRecord, MutationRecord) error
	UpdateAuthorityRollover(context.Context, uint64, uint64, domainpki.Operation, AuditRecord, MutationRecord) error
	CompleteAuthorityRollover(context.Context, uint64, uint64, domainpki.Operation, domainpki.Authority, domainpki.TrustSet, AuditRecord, MutationRecord) error
	CancelAuthorityRollover(context.Context, uint64, domainpki.Operation, AuditRecord, MutationRecord) error
}

type CredentialStampPersistence interface {
	CredentialStamp(context.Context, domainpki.StampID) (domainpki.CredentialStamp, error)
	CredentialStamps(context.Context) ([]domainpki.CredentialStamp, error)
	CreateCredentialStamp(context.Context, domainpki.CredentialStamp, AuditRecord, MutationRecord) error
	UpdateCredentialStamp(context.Context, uint64, domainpki.CredentialStamp, AuditRecord, MutationRecord) error
}

type CredentialExecutionPersistence interface {
	CredentialExecution(context.Context, domainpki.CredentialExecutionRequestID) (domainpki.CredentialExecution, error)
	CredentialExecutions(context.Context) ([]domainpki.CredentialExecution, error)
	CreateCredentialExecution(context.Context, domainpki.CredentialExecution, AuditRecord, MutationRecord) error
	UpdateCredentialExecution(context.Context, uint64, domainpki.CredentialExecution, AuditRecord, MutationRecord) error
}

type Persistence interface {
	IssuancePersistence
	InventoryPersistence
	AssignmentPersistence
	RevocationPersistence
	CRLPersistence
	OperationPersistence
	CredentialStampPersistence
	CredentialExecutionPersistence
}

type AuthorityInspection struct {
	Authority        domainpki.Authority
	ActiveGeneration domainpki.CertificateGeneration
}

func (s Service) ListAuthorities(ctx context.Context) ([]domainpki.Authority, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	authorities, err := s.persistence.Authorities(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.Authority, len(authorities))
	for index, authority := range authorities {
		if err := authority.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed authority: %w", err)
		}
		result[index] = authority.Clone()
	}
	return result, nil
}

func (s Service) InspectAuthority(ctx context.Context, id domainpki.AuthorityID) (AuthorityInspection, error) {
	if err := id.Validate(); err != nil {
		return AuthorityInspection{}, err
	}
	authority, err := s.persistence.Authority(ctx, id)
	if err != nil {
		return AuthorityInspection{}, err
	}
	generation, err := s.persistence.Generation(ctx, authority.ActiveGenerationID)
	if err != nil {
		return AuthorityInspection{}, err
	}
	if generation.OwningAuthorityID != authority.ID {
		return AuthorityInspection{}, errors.New("pki: active authority generation belongs to another authority")
	}
	return AuthorityInspection{Authority: authority.Clone(), ActiveGeneration: generation.Clone()}, nil
}

func (s Service) ListCertificateGenerations(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	generations, err := s.persistence.CertificateGenerations(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.CertificateGeneration, len(generations))
	for index, generation := range generations {
		if err := generation.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed certificate generation: %w", err)
		}
		result[index] = generation.Clone()
	}
	return result, nil
}

func (s Service) InspectCertificateGeneration(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	if err := id.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	generation, err := s.persistence.Generation(ctx, id)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if err := generation.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki: validate inspected certificate generation: %w", err)
	}
	return generation.Clone(), nil
}

type SigningAuthorizer interface {
	SigningLeaseController
	AuthorizeSigning(context.Context, domainpki.AuthorityID, AuditContext) error
}

type ExportAuthorizer interface {
	AuthorizePrivateKeyExport(context.Context, domainpki.GenerationID) error
}

// CredentialUseAuthorizer approves assignment material delivery into a
// provider process without granting private-key export to the caller.
type CredentialUseAuthorizer interface {
	AuthorizeCredentialUse(context.Context, domainpki.AssignmentID) error
}

type IssuanceReconciliationAuthorizer interface {
	AuthorizeIssuanceReconciliation(context.Context, AuditContext) error
}

type CRLPublicationReconciliationAuthorizer interface {
	AuthorizeCRLPublicationReconciliation(context.Context, AuditContext) error
}

type Clock interface {
	Now() time.Time
}

type Service struct {
	persistence   Persistence
	backends      BackendRegistry
	validators    ValidatorRegistry
	authorizer    SigningAuthorizer
	exporter      ExportAuthorizer
	credentialUse CredentialUseAuthorizer
	audit         AuditSink
	auditCtx      AuditContextProvider
	reconciler    IssuanceReconciliationAuthorizer
	crlReconciler CRLPublicationReconciliationAuthorizer
	clock         Clock
	random        io.Reader
	randomMu      *sync.Mutex
}

func NewService(ctx context.Context, persistence Persistence, backend Backend, validator Validator, authorizer SigningAuthorizer, exporter ExportAuthorizer, audit AuditSink, auditCtx AuditContextProvider, clock Clock, random io.Reader) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	registry, err := NewStaticBackendRegistry(backend)
	if err != nil {
		return Service{}, err
	}
	return NewServiceWithBackendRegistry(ctx, persistence, registry, validator, authorizer, exporter, audit, auditCtx, clock, random)
}

func NewServiceWithBackendRegistry(ctx context.Context, persistence Persistence, backends BackendRegistry, validator Validator, authorizer SigningAuthorizer, exporter ExportAuthorizer, audit AuditSink, auditCtx AuditContextProvider, clock Clock, random io.Reader) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	if backends == nil || validator == nil {
		return Service{}, errors.New("pki: backend registry and independent validator are required")
	}
	descriptors, err := backends.BackendDescriptors(ctx)
	if err != nil {
		return Service{}, err
	}
	if len(descriptors) != 1 {
		return Service{}, errors.New("pki: one shared validator is only valid for a single-backend registry")
	}
	validators := make(map[domainpki.BackendID]Validator, len(descriptors))
	for _, descriptor := range descriptors {
		validators[descriptor.ID] = validator
	}
	validatorRegistry, err := NewStaticValidatorRegistry(validators)
	if err != nil {
		return Service{}, err
	}
	return NewServiceWithCryptoRegistries(ctx, persistence, backends, validatorRegistry, authorizer, exporter, audit, auditCtx, clock, random)
}

func NewServiceWithCryptoRegistries(ctx context.Context, persistence Persistence, backends BackendRegistry, validators ValidatorRegistry, authorizer SigningAuthorizer, exporter ExportAuthorizer, audit AuditSink, auditCtx AuditContextProvider, clock Clock, random io.Reader) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	if persistence == nil || backends == nil || validators == nil || authorizer == nil || exporter == nil || audit == nil || auditCtx == nil || clock == nil || random == nil {
		return Service{}, errors.New("pki: complete service dependencies are required")
	}
	descriptors, err := backends.BackendDescriptors(ctx)
	if err != nil {
		return Service{}, err
	}
	for _, descriptor := range descriptors {
		if _, err := validators.ResolveValidator(ctx, descriptor.ID); err != nil {
			return Service{}, err
		}
	}
	reconciler, ok := auditCtx.(IssuanceReconciliationAuthorizer)
	if !ok {
		reconciler = denyIssuanceReconciliation{}
	}
	crlReconciler, ok := auditCtx.(CRLPublicationReconciliationAuthorizer)
	if !ok {
		crlReconciler = denyCRLPublicationReconciliation{}
	}
	credentialUse, ok := auditCtx.(CredentialUseAuthorizer)
	if !ok {
		credentialUse = denyCredentialUse{}
	}
	return Service{persistence: persistence, backends: backends, validators: validators, authorizer: authorizer, exporter: exporter, credentialUse: credentialUse, audit: audit, auditCtx: auditCtx, reconciler: reconciler, crlReconciler: crlReconciler, clock: clock, random: random, randomMu: &sync.Mutex{}}, nil
}

type denyIssuanceReconciliation struct{}

func (denyIssuanceReconciliation) AuthorizeIssuanceReconciliation(context.Context, AuditContext) error {
	return errors.New("pki: issuance reconciliation is not authorized")
}

type denyCRLPublicationReconciliation struct{}

func (denyCRLPublicationReconciliation) AuthorizeCRLPublicationReconciliation(context.Context, AuditContext) error {
	return errors.New("pki: crl publication reconciliation is not authorized")
}

type denyCredentialUse struct{}

func (denyCredentialUse) AuthorizeCredentialUse(context.Context, domainpki.AssignmentID) error {
	return errors.New("pki: credential use is not authorized")
}

func (s Service) BackendDescriptors(ctx context.Context) ([]domainpki.BackendDescriptor, error) {
	return s.backends.BackendDescriptors(ctx)
}

func (s Service) ReconcilePendingIssuance(ctx context.Context, idempotencyKey string, staleAfter time.Duration) (IssuanceIntent, error) {
	if err := validateIdempotencyKey(idempotencyKey); err != nil {
		return IssuanceIntent{}, err
	}
	if staleAfter < minimumIssuanceReconcileAge || staleAfter > maximumIssuanceReconcileAge {
		return IssuanceIntent{}, fmt.Errorf("pki: issuance reconciliation age must be between %s and %s", minimumIssuanceReconcileAge, maximumIssuanceReconcileAge)
	}
	intent, err := s.persistence.IssuanceByKey(ctx, idempotencyKey)
	if err != nil {
		return IssuanceIntent{}, err
	}
	if intent.Status != IssuanceStatusPending {
		return intent.Clone(), nil
	}
	now := s.clock.Now().UTC()
	if now.Sub(intent.UpdatedAt) < staleAfter || now.Before(intent.LeaseExpiresAt) {
		return IssuanceIntent{}, ErrIssuanceInProgress
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return IssuanceIntent{}, err
	}
	if err := s.reconciler.AuthorizeIssuanceReconciliation(ctx, auditContext); err != nil {
		return IssuanceIntent{}, fmt.Errorf("pki: authorize issuance reconciliation: %w", err)
	}
	claimed, ok, err := s.claimIssuanceForReconciliation(ctx, intent, now)
	if err != nil {
		return IssuanceIntent{}, err
	}
	if !ok {
		return IssuanceIntent{}, ErrIssuanceInProgress
	}
	return s.failReconciledIssuance(ctx, claimed, auditContext, now)
}

func (s Service) ReconcilePendingIssuances(ctx context.Context, staleAfter time.Duration, limit int) ([]IssuanceIntent, error) {
	if staleAfter < minimumIssuanceReconcileAge || staleAfter > maximumIssuanceReconcileAge {
		return nil, fmt.Errorf("pki: issuance reconciliation age must be between %s and %s", minimumIssuanceReconcileAge, maximumIssuanceReconcileAge)
	}
	if limit < 1 || limit > MaximumPendingIssuanceBatch {
		return nil, fmt.Errorf("pki: pending issuance batch must contain between 1 and %d records", MaximumPendingIssuanceBatch)
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.reconciler.AuthorizeIssuanceReconciliation(ctx, auditContext); err != nil {
		return nil, fmt.Errorf("pki: authorize issuance reconciliation: %w", err)
	}
	now := s.clock.Now().UTC()
	pending, err := s.persistence.PendingIssuances(ctx, now, now.Add(-staleAfter), limit)
	if err != nil {
		return nil, err
	}
	results := make([]IssuanceIntent, 0, len(pending))
	for _, intent := range pending {
		claimed, ok, claimErr := s.claimIssuanceForReconciliation(ctx, intent, now)
		if claimErr != nil {
			return nil, claimErr
		}
		if !ok {
			continue
		}
		failed, failErr := s.failReconciledIssuance(ctx, claimed, auditContext, now)
		if failErr != nil {
			return nil, failErr
		}
		results = append(results, failed)
	}
	return results, nil
}

func (s Service) claimIssuanceForReconciliation(ctx context.Context, intent IssuanceIntent, now time.Time) (IssuanceIntent, bool, error) {
	ownerToken, err := s.randomID("reconciler")
	if err != nil {
		return IssuanceIntent{}, false, err
	}
	return s.persistence.ClaimIssuance(ctx, intent.ID, intent.Ownership(), ownerToken, now)
}

func (s Service) failReconciledIssuance(ctx context.Context, intent IssuanceIntent, auditContext AuditContext, now time.Time) (IssuanceIntent, error) {
	record, err := s.newAuditRecord(auditContext, AuditActionIssuance, AuditOutcomeFailed, auditResourceAuthority, string(signingAuthorityIDForIntent(intent)), map[string]string{
		"certificateGenerationId": string(intent.GenerationID),
		"stage":                   issuanceStageReconciliation,
	})
	if err != nil {
		return IssuanceIntent{}, err
	}
	if err := s.persistence.FailIssuance(ctx, intent.ID, intent.Ownership(), issuanceFailureReconciled, now, record); err != nil {
		return IssuanceIntent{}, err
	}
	return s.persistence.IssuanceByKey(ctx, intent.IdempotencyKey)
}

func initialAuthorityState(role domainpki.AuthorityRole) domainpki.AuthorityState {
	if role == domainpki.AuthorityRoleRoot {
		return domainpki.AuthorityStateLocked
	}
	return domainpki.AuthorityStateActive
}

func (s Service) UnlockAuthoritySigning(ctx context.Context, id domainpki.AuthorityID, duration time.Duration) (SigningLease, error) {
	authority, err := s.persistence.Authority(ctx, id)
	if err != nil {
		return SigningLease{}, err
	}
	if authority.State != domainpki.AuthorityStateActive && authority.State != domainpki.AuthorityStateLocked {
		return SigningLease{}, fmt.Errorf("pki: authority %q cannot be unlocked while %s", id, authority.State)
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return SigningLease{}, err
	}
	lease, err := s.authorizer.UnlockSigning(ctx, id, duration, auditContext)
	if err != nil {
		if auditErr := s.appendAuditWithContext(ctx, auditContext, AuditActionAuthorityUnlock, AuditOutcomeFailed, auditResourceAuthority, string(id), nil); auditErr != nil {
			return SigningLease{}, errors.Join(err, auditErr)
		}
		return SigningLease{}, err
	}
	details := map[string]string{
		"grantedAt": lease.GrantedAt.Format(time.RFC3339Nano),
		"expiresAt": lease.ExpiresAt.Format(time.RFC3339Nano),
	}
	if err := s.appendAuditWithContext(ctx, auditContext, AuditActionAuthorityUnlock, AuditOutcomeSucceeded, auditResourceAuthority, string(id), details); err != nil {
		lockErr := s.authorizer.LockSigning(context.WithoutCancel(ctx), id, auditContext)
		return SigningLease{}, errors.Join(err, lockErr)
	}
	return lease, nil
}

func (s Service) LockAuthoritySigning(ctx context.Context, id domainpki.AuthorityID) error {
	if _, err := s.persistence.Authority(ctx, id); err != nil {
		return err
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return err
	}
	if err := s.authorizer.LockSigning(ctx, id, auditContext); err != nil {
		if auditErr := s.appendAuditWithContext(ctx, auditContext, AuditActionAuthorityLock, AuditOutcomeFailed, auditResourceAuthority, string(id), nil); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}
	return s.appendAuditWithContext(ctx, auditContext, AuditActionAuthorityLock, AuditOutcomeSucceeded, auditResourceAuthority, string(id), nil)
}

func (s Service) AuthoritySigningLease(ctx context.Context, id domainpki.AuthorityID) (SigningLease, bool, error) {
	if _, err := s.persistence.Authority(ctx, id); err != nil {
		return SigningLease{}, false, err
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return SigningLease{}, false, err
	}
	return s.authorizer.SigningLease(ctx, id, auditContext)
}

type CreateAuthorityRequest struct {
	IdempotencyKey    string                         `json:"idempotencyKey"`
	ID                domainpki.AuthorityID          `json:"id,omitempty"`
	CertificateID     domainpki.CertificateID        `json:"certificateId,omitempty"`
	GenerationID      domainpki.GenerationID         `json:"generationId,omitempty"`
	KeyID             domainpki.KeyID                `json:"keyId,omitempty"`
	Name              string                         `json:"name"`
	Role              domainpki.AuthorityRole        `json:"role"`
	ParentAuthorityID domainpki.AuthorityID          `json:"parentAuthorityId,omitempty"`
	ProfileID         domainpki.ProfileID            `json:"profileId,omitempty"`
	BackendID         domainpki.BackendID            `json:"backendId,omitempty"`
	Template          *domainpki.CertificateTemplate `json:"template,omitempty"`
	Labels            map[string]string              `json:"labels,omitempty"`
	ExportPolicy      domainpki.ExportPolicy         `json:"exportPolicy,omitempty"`
}

type CreateAuthorityResult struct {
	Authority  domainpki.Authority             `json:"authority"`
	Generation domainpki.CertificateGeneration `json:"generation"`
}

func (s Service) CreateAuthority(ctx context.Context, req CreateAuthorityRequest) (_ CreateAuthorityResult, resultErr error) {
	if err := ctx.Err(); err != nil {
		return CreateAuthorityResult{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return CreateAuthorityResult{}, errors.New("pki: authority name is required")
	}
	if err := req.Role.Validate(); err != nil {
		return CreateAuthorityResult{}, err
	}
	profile, err := authorityProfile(req.Role, req.ProfileID)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	if req.BackendID != "" {
		if err := req.BackendID.Validate(); err != nil {
			return CreateAuthorityResult{}, err
		}
		profile.Backend = req.BackendID
	}
	compatibility, ok := domainpki.BuiltInCompatibilityTarget(profile.Compatibility)
	if !ok {
		return CreateAuthorityResult{}, fmt.Errorf("pki: compatibility target %q is unavailable", profile.Compatibility)
	}
	tlsNamedGroups, err := domainpki.ResolveTLSNamedGroups(compatibility, profile.KeyEstablishment)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	exportPolicy, err := resolveExportPolicy(profile.ExportPolicy, req.ExportPolicy)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	normalizedRequest := req
	normalizedRequest.IdempotencyKey = ""
	normalizedRequest.Name = name
	normalizedRequest.ProfileID = profile.ID
	normalizedRequest.BackendID = profile.Backend
	digest, err := requestDigest(normalizedRequest)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	idempotencyKey, err := resolveIdempotencyKey(req.IdempotencyKey, IssuanceKindAuthority, digest, auditContext)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	intent, intentExists, err := s.existingIssuance(ctx, idempotencyKey, IssuanceKindAuthority, digest)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	if intentExists && intent.Status == IssuanceStatusCompleted {
		authority, loadErr := s.persistence.Authority(ctx, intent.AuthorityID)
		if loadErr != nil {
			return CreateAuthorityResult{}, loadErr
		}
		generation, loadErr := s.persistence.Generation(ctx, intent.ResultGenerationID)
		if loadErr != nil {
			return CreateAuthorityResult{}, loadErr
		}
		return CreateAuthorityResult{Authority: authority.Clone(), Generation: generation.Clone()}, nil
	}
	backend, validator, descriptor, err := s.resolveBackend(ctx, profile)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	var ids authorityIDs
	var template domainpki.CertificateTemplate
	if intentExists {
		ids = authorityIDs{authority: intent.AuthorityID, certificate: intent.CertificateID, generation: intent.GenerationID, key: intent.KeyID}
		template = intent.Template.Clone()
		if intent.ProfileID != profile.ID || intent.IssuerAuthorityID != req.ParentAuthorityID || intent.Generation != 1 {
			return CreateAuthorityResult{}, errors.New("pki: persisted authority issuance plan is inconsistent")
		}
	} else {
		ids, err = s.authorityIDs(req)
		if err != nil {
			return CreateAuthorityResult{}, err
		}
		template, err = s.resolveTemplate(req.Template, profile, descriptor, name, now)
		if err != nil {
			return CreateAuthorityResult{}, err
		}
	}
	if !template.BasicConstraints.IsCA {
		return CreateAuthorityResult{}, errors.New("pki: authority template must create a ca certificate")
	}

	var parentAuthority domainpki.Authority
	var parentGeneration domainpki.CertificateGeneration
	var signer KeyMaterial
	signingBackend, signingValidator := backend, validator
	signingDescriptor := descriptor
	if req.Role == domainpki.AuthorityRoleSubordinate {
		if req.ParentAuthorityID == "" {
			return CreateAuthorityResult{}, errors.New("pki: subordinate authority requires a parent")
		}
		if err := req.ParentAuthorityID.Validate(); err != nil {
			return CreateAuthorityResult{}, err
		}
		parentAuthority, parentGeneration, signer, err = s.signer(ctx, req.ParentAuthorityID)
		if err != nil {
			return CreateAuthorityResult{}, err
		}
		signingBackend, signingValidator, signingDescriptor, err = s.resolveSigningBackend(ctx, parentGeneration, signer)
		if err != nil {
			return CreateAuthorityResult{}, err
		}
		if template.NotBefore.Before(parentGeneration.Template.NotBefore) || template.NotAfter.After(parentGeneration.Template.NotAfter) {
			return CreateAuthorityResult{}, errors.New("pki: subordinate validity must be contained by parent validity")
		}
		if err := validateSubordinatePathLength(parentGeneration.Template.BasicConstraints, template.BasicConstraints); err != nil {
			return CreateAuthorityResult{}, err
		}
	}
	chain := []domainpki.GenerationID(nil)
	if parentGeneration.ID != "" {
		chain = append(chain, parentGeneration.ID)
		chain = append(chain, parentGeneration.ChainGenerationIDs...)
	}
	if !intentExists {
		issuanceID, idErr := s.newIssuanceID("issuance")
		if idErr != nil {
			return CreateAuthorityResult{}, idErr
		}
		ownerToken, ownerErr := s.randomID("worker")
		if ownerErr != nil {
			return CreateAuthorityResult{}, ownerErr
		}
		candidate := IssuanceIntent{
			ID: issuanceID, IdempotencyKey: idempotencyKey, RequestSHA256: digest, Kind: IssuanceKindAuthority,
			AuthorityID: ids.authority, CertificateID: ids.certificate, GenerationID: ids.generation, Generation: 1,
			KeyID: ids.key, IssuerAuthorityID: req.ParentAuthorityID, IssuerGenerationID: parentGeneration.ID,
			SubjectBackendID: descriptor.ID, SubjectBackendVersion: descriptor.Version,
			SubjectPackageDigest: descriptor.PackageDigest, SubjectCapabilityHash: descriptor.CapabilityHash,
			SigningBackendID: signingDescriptor.ID, SigningBackendVersion: signingDescriptor.Version,
			SigningPackageDigest: signingDescriptor.PackageDigest, SigningCapabilityHash: signingDescriptor.CapabilityHash,
			ProfileID: profile.ID, CompatibilityTargetID: profile.Compatibility, CompatibilityVersion: compatibility.Version,
			Purpose: profile.Purpose, ExportPolicy: exportPolicy, KeyEstablishment: profile.KeyEstablishment,
			TLSNamedGroups:     append([]domainpki.TLSNamedGroup(nil), tlsNamedGroups...),
			ChainGenerationIDs: append([]domainpki.GenerationID(nil), chain...),
			AuthorityPlan: &AuthorityIssuancePlan{
				Name: name, Role: req.Role, Origin: domainpki.OriginGenerated,
				ParentAuthorityID: req.ParentAuthorityID, State: initialAuthorityState(req.Role),
				ProfileID: profile.ID, SignerRef: string(ids.key), ExportPolicy: exportPolicy,
				CreatedAt: now, Labels: req.Labels,
			},
			Template: template.Clone(),
			Status:   IssuanceStatusPending, OwnerToken: ownerToken, Revision: 1,
			LeaseExpiresAt: now.Add(DefaultIssuanceLease), CreatedAt: now, UpdatedAt: now,
		}
		var created bool
		intent, created, err = s.persistence.BeginIssuance(ctx, candidate)
		if err != nil {
			return CreateAuthorityResult{}, err
		}
		if intent.Kind != IssuanceKindAuthority || intent.RequestSHA256 != digest || intent.IdempotencyKey != idempotencyKey {
			return CreateAuthorityResult{}, errors.New("pki: idempotency key raced with a different authority issuance request")
		}
		if intent.Status == IssuanceStatusCompleted {
			authority, loadErr := s.persistence.Authority(ctx, intent.AuthorityID)
			if loadErr != nil {
				return CreateAuthorityResult{}, loadErr
			}
			generation, loadErr := s.persistence.Generation(ctx, intent.ResultGenerationID)
			if loadErr != nil {
				return CreateAuthorityResult{}, loadErr
			}
			return CreateAuthorityResult{Authority: authority.Clone(), Generation: generation.Clone()}, nil
		}
		if intent.Status != IssuanceStatusPending {
			return CreateAuthorityResult{}, errors.New("pki: authority issuance is not pending")
		}
		if !created {
			return CreateAuthorityResult{}, ErrIssuanceInProgress
		}
	}
	if err := validateBackendCommitment("subject", descriptor, intent.SubjectBackendID, intent.SubjectBackendVersion, intent.SubjectPackageDigest, intent.SubjectCapabilityHash); err != nil {
		return CreateAuthorityResult{}, err
	}
	if err := validateBackendCommitment("signing", signingDescriptor, intent.SigningBackendID, intent.SigningBackendVersion, intent.SigningPackageDigest, intent.SigningCapabilityHash); err != nil {
		return CreateAuthorityResult{}, err
	}
	ctx, cancelIssuance := context.WithTimeout(ctx, DefaultIssuanceLease)
	defer cancelIssuance()
	failureStage := issuanceStageKeyGeneration
	issuanceCompleted := false
	defer func() {
		if resultErr != nil && !issuanceCompleted {
			resultErr = s.recordIssuanceFailure(ctx, intent, auditContext, signingAuthorityIDForIntent(intent), failureStage, resultErr)
		}
	}()

	generatedKey, err := backend.GenerateKey(ctx, ids.key, template.Key)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	defer clear(generatedKey.PrivateKeyPKCS8)
	if err := ValidateBackendKeyIdentity(descriptor.ID, generatedKey); err != nil {
		return CreateAuthorityResult{}, err
	}
	failureStage = issuanceStageKeyValidation
	key := generatedKey.Clone()
	validatedKey, err := ValidateKeyMaterial(ctx, validator, template.Key, key)
	if err != nil {
		return CreateAuthorityResult{}, fmt.Errorf("pki: backend key validation failed: %w", err)
	}
	defer validatedKey.Clear()
	key = validatedKey.Material()
	defer clear(key.PrivateKeyPKCS8)
	if req.Role == domainpki.AuthorityRoleRoot {
		signer = key
		if err := s.appendAudit(ctx, AuditActionSigningAuthorization, AuditOutcomeAllowed, auditResourceAuthority, string(ids.authority), map[string]string{"mode": "self-signed-root"}); err != nil {
			return CreateAuthorityResult{}, err
		}
	}
	defer clear(signer.PrivateKeyPKCS8)
	if !template.SignatureAlgorithm.CompatibleWith(signer.Algorithm) {
		return CreateAuthorityResult{}, fmt.Errorf("pki: signature algorithm %q is incompatible with issuer key algorithm %q", template.SignatureAlgorithm, signer.Algorithm)
	}
	signingAuthorityID := ids.authority
	if parentAuthority.ID != "" {
		signingAuthorityID = parentAuthority.ID
	}
	failureStage = issuanceStageCertificateSigning
	issued, err := s.issue(ctx, signingBackend, signingValidator, template, key.PublicKeySPKI, parentGeneration.CertificateDER, signer)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	failureStage = issuanceStageResultConstruction
	template.SignatureAlgorithm = issued.SignatureAlgorithm
	generation, err := domainpki.NewCertificateGeneration(domainpki.GenerationArgs{
		CertificateID:                ids.certificate,
		ID:                           ids.generation,
		Generation:                   intent.Generation,
		OwningAuthorityID:            ids.authority,
		IssuerAuthorityID:            parentAuthority.ID,
		IssuerGenerationID:           parentGeneration.ID,
		ProfileID:                    profile.ID,
		Template:                     template,
		BackendID:                    descriptor.ID,
		BackendVersion:               descriptor.Version,
		BackendPackageDigest:         descriptor.PackageDigest,
		BackendCapabilityHash:        descriptor.CapabilityHash,
		SigningBackendID:             signingDescriptor.ID,
		SigningBackendVersion:        signingDescriptor.Version,
		SigningBackendPackageDigest:  signingDescriptor.PackageDigest,
		SigningBackendCapabilityHash: signingDescriptor.CapabilityHash,
		CompatibilityTargetID:        intent.CompatibilityTargetID,
		CompatibilityVersion:         intent.CompatibilityVersion,
		Purpose:                      intent.Purpose,
		ExportPolicy:                 intent.ExportPolicy,
		KeyEstablishment:             intent.KeyEstablishment,
		TLSNamedGroups:               intent.TLSNamedGroups,
		FingerprintSHA256:            issued.FingerprintSHA256,
		SubjectKeyID:                 issued.SubjectKeyID,
		AuthorityKeyID:               issued.AuthorityKeyID,
		State:                        domainpki.CertificateStateActive,
		KeyID:                        key.ID,
		CertificateDER:               issued.CertificateDER,
		PublicKeySPKI:                issued.PublicKeySPKI,
		ChainGenerationIDs:           intent.ChainGenerationIDs,
		CreatedAt:                    now,
	})
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	signerMode := domainpki.SignerModeLocal
	if key.ExternalHandle != nil {
		signerMode = domainpki.SignerModeExternal
	}
	authority, err := plannedAuthority(intent, signerMode)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	completionAudits, err := s.newIssuanceCompletionAudits(
		auditContext,
		IssuanceKindAuthority,
		signingAuthorityID,
		ids.generation,
		"",
	)
	if err != nil {
		return CreateAuthorityResult{}, err
	}
	failureStage = issuanceStageInventoryCommit
	if err := s.persistence.CompleteAuthorityIssuance(ctx, intent.ID, intent.Ownership(), authority, generation, validatedKey, completionAudits); err != nil {
		return CreateAuthorityResult{}, err
	}
	issuanceCompleted = true
	return CreateAuthorityResult{Authority: authority.Clone(), Generation: generation.Clone()}, nil
}

type IssueCertificateRequest struct {
	IdempotencyKey    string                         `json:"idempotencyKey"`
	CertificateID     domainpki.CertificateID        `json:"certificateId,omitempty"`
	GenerationID      domainpki.GenerationID         `json:"generationId,omitempty"`
	KeyID             domainpki.KeyID                `json:"keyId,omitempty"`
	IssuerAuthorityID domainpki.AuthorityID          `json:"issuerAuthorityId"`
	Name              string                         `json:"name"`
	ProfileID         domainpki.ProfileID            `json:"profileId,omitempty"`
	BackendID         domainpki.BackendID            `json:"backendId,omitempty"`
	Template          *domainpki.CertificateTemplate `json:"template,omitempty"`
}

type certificateIssuanceOptions struct {
	kind               IssuanceKind
	reuseKey           bool
	sourceGenerationID domainpki.GenerationID
	requestSHA256      string
	sourceGeneration   *domainpki.CertificateGeneration
}

func (s Service) IssueCertificate(ctx context.Context, req IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	return s.issueCertificate(ctx, req, certificateIssuanceOptions{kind: IssuanceKindCertificate})
}

func (s Service) issueCertificate(ctx context.Context, req IssueCertificateRequest, options certificateIssuanceOptions) (_ domainpki.CertificateGeneration, resultErr error) {
	if err := ctx.Err(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if err := options.kind.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if options.kind == IssuanceKindAuthority {
		return domainpki.CertificateGeneration{}, errors.New("pki: leaf issuance cannot use authority issuance kind")
	}
	if options.reuseKey && req.KeyID == "" {
		return domainpki.CertificateGeneration{}, errors.New("pki: key reuse requires an existing key id")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return domainpki.CertificateGeneration{}, errors.New("pki: certificate name is required")
	}
	if req.IssuerAuthorityID == "" {
		return domainpki.CertificateGeneration{}, errors.New("pki: issuer authority id is required")
	}
	if err := req.IssuerAuthorityID.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	var profile domainpki.Profile
	if options.sourceGeneration != nil {
		var profileErr error
		profile, profileErr = lifecycleProfile(*options.sourceGeneration, req.BackendID, options.reuseKey)
		if profileErr != nil {
			return domainpki.CertificateGeneration{}, profileErr
		}
	} else {
		profileID := req.ProfileID
		if profileID == "" {
			profileID = domainpki.ProfileTLSServer
		}
		var ok bool
		profile, ok = domainpki.BuiltInProfile(profileID)
		if !ok || profile.AuthorityRole != "" {
			return domainpki.CertificateGeneration{}, fmt.Errorf("pki: leaf profile %q is not supported", profileID)
		}
		if req.BackendID != "" {
			if err := req.BackendID.Validate(); err != nil {
				return domainpki.CertificateGeneration{}, err
			}
			profile.Backend = req.BackendID
		}
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	normalizedRequest := req
	normalizedRequest.IdempotencyKey = ""
	normalizedRequest.Name = name
	normalizedRequest.ProfileID = profile.ID
	normalizedRequest.BackendID = profile.Backend
	digest := options.requestSHA256
	if digest == "" {
		digest, err = requestDigest(normalizedRequest)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	idempotencyKey, err := resolveIdempotencyKey(req.IdempotencyKey, options.kind, digest, auditContext)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	intent, intentExists, err := s.existingIssuance(ctx, idempotencyKey, options.kind, digest)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if intentExists && intent.Status == IssuanceStatusCompleted {
		return s.persistence.Generation(ctx, intent.ResultGenerationID)
	}
	if options.sourceGeneration != nil {
		if err := validateLifecycleSourceBase(*options.sourceGeneration, options.kind, req); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
		if intentExists {
			persistedTemplate := intent.Template.Clone()
			req.Template = &persistedTemplate
		} else if req.Template == nil {
			lifecycleTemplate, templateErr := s.lifecycleTemplate(*options.sourceGeneration, nil, options.reuseKey)
			if templateErr != nil {
				return domainpki.CertificateGeneration{}, templateErr
			}
			req.Template = &lifecycleTemplate
		}
		if err := validateLifecycleSource(*options.sourceGeneration, options.kind, req); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	backend, validator, descriptor, err := s.resolveBackend(ctx, profile)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	issuer, issuerGeneration, signer, err := s.signer(ctx, req.IssuerAuthorityID)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	defer clear(signer.PrivateKeyPKCS8)
	signingBackend, signingValidator, signingDescriptor, err := s.resolveSigningBackend(ctx, issuerGeneration, signer)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	var certificateID domainpki.CertificateID
	var generationID domainpki.GenerationID
	var keyID domainpki.KeyID
	var template domainpki.CertificateTemplate
	if intentExists {
		certificateID, generationID, keyID = intent.CertificateID, intent.GenerationID, intent.KeyID
		template = intent.Template.Clone()
		if intent.ProfileID != profile.ID || intent.IssuerAuthorityID != req.IssuerAuthorityID {
			return domainpki.CertificateGeneration{}, errors.New("pki: persisted certificate issuance plan is inconsistent")
		}
	} else {
		certificateID, generationID, keyID = req.CertificateID, req.GenerationID, req.KeyID
		if certificateID != "" {
			if err := certificateID.Validate(); err != nil {
				return domainpki.CertificateGeneration{}, err
			}
		} else if certificateID, err = s.newCertificateID("cert"); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
		if generationID != "" {
			if err := generationID.Validate(); err != nil {
				return domainpki.CertificateGeneration{}, err
			}
		} else if generationID, err = s.newGenerationID("certgen"); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
		if keyID != "" {
			if err := keyID.Validate(); err != nil {
				return domainpki.CertificateGeneration{}, err
			}
		} else if keyID, err = s.newKeyID("key"); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
		template, err = s.resolveTemplate(req.Template, profile, descriptor, name, now)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	if template.BasicConstraints.IsCA {
		return domainpki.CertificateGeneration{}, errors.New("pki: leaf issuance template cannot create a ca")
	}
	if template.NotBefore.Before(issuerGeneration.Template.NotBefore) || template.NotAfter.After(issuerGeneration.Template.NotAfter) {
		return domainpki.CertificateGeneration{}, errors.New("pki: certificate validity must be contained by issuer validity")
	}
	compatibilityVersion := ""
	var tlsNamedGroups []domainpki.TLSNamedGroup
	if options.sourceGeneration != nil {
		compatibilityVersion = options.sourceGeneration.CompatibilityVersion
		tlsNamedGroups = append([]domainpki.TLSNamedGroup(nil), options.sourceGeneration.TLSNamedGroups...)
		if err := domainpki.ValidateKeyEstablishment(profile.KeyEstablishment, tlsNamedGroups); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	} else {
		compatibility, ok := domainpki.BuiltInCompatibilityTarget(profile.Compatibility)
		if !ok {
			return domainpki.CertificateGeneration{}, fmt.Errorf("pki: compatibility target %q is unavailable", profile.Compatibility)
		}
		compatibilityVersion = compatibility.Version
		tlsNamedGroups, err = domainpki.ResolveTLSNamedGroups(compatibility, profile.KeyEstablishment)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	chain := append([]domainpki.GenerationID{issuerGeneration.ID}, issuerGeneration.ChainGenerationIDs...)
	if !intentExists {
		issuanceID, idErr := s.newIssuanceID("issuance")
		if idErr != nil {
			return domainpki.CertificateGeneration{}, idErr
		}
		ownerToken, ownerErr := s.randomID("worker")
		if ownerErr != nil {
			return domainpki.CertificateGeneration{}, ownerErr
		}
		candidate := IssuanceIntent{
			ID: issuanceID, IdempotencyKey: idempotencyKey, RequestSHA256: digest, Kind: options.kind,
			CertificateID: certificateID, GenerationID: generationID, SourceGenerationID: options.sourceGenerationID, KeyID: keyID,
			IssuerAuthorityID: req.IssuerAuthorityID, IssuerGenerationID: issuerGeneration.ID,
			SubjectBackendID: descriptor.ID, SubjectBackendVersion: descriptor.Version,
			SubjectPackageDigest: descriptor.PackageDigest, SubjectCapabilityHash: descriptor.CapabilityHash,
			SigningBackendID: signingDescriptor.ID, SigningBackendVersion: signingDescriptor.Version,
			SigningPackageDigest: signingDescriptor.PackageDigest, SigningCapabilityHash: signingDescriptor.CapabilityHash,
			ProfileID: profile.ID, CompatibilityTargetID: profile.Compatibility, CompatibilityVersion: compatibilityVersion,
			Purpose: profile.Purpose, ExportPolicy: profile.ExportPolicy, KeyEstablishment: profile.KeyEstablishment,
			TLSNamedGroups:     append([]domainpki.TLSNamedGroup(nil), tlsNamedGroups...),
			ChainGenerationIDs: append([]domainpki.GenerationID(nil), chain...), Template: template.Clone(),
			Status: IssuanceStatusPending, OwnerToken: ownerToken, Revision: 1,
			LeaseExpiresAt: now.Add(DefaultIssuanceLease), CreatedAt: now, UpdatedAt: now,
		}
		var created bool
		intent, created, err = s.persistence.BeginIssuance(ctx, candidate)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
		if intent.Kind != options.kind || intent.RequestSHA256 != digest || intent.IdempotencyKey != idempotencyKey {
			return domainpki.CertificateGeneration{}, errors.New("pki: idempotency key raced with a different certificate issuance request")
		}
		if intent.Status == IssuanceStatusCompleted {
			return s.persistence.Generation(ctx, intent.ResultGenerationID)
		}
		if intent.Status != IssuanceStatusPending {
			return domainpki.CertificateGeneration{}, errors.New("pki: certificate issuance is not pending")
		}
		if !created {
			return domainpki.CertificateGeneration{}, ErrIssuanceInProgress
		}
	}
	if err := validateBackendCommitment("subject", descriptor, intent.SubjectBackendID, intent.SubjectBackendVersion, intent.SubjectPackageDigest, intent.SubjectCapabilityHash); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if err := validateBackendCommitment("signing", signingDescriptor, intent.SigningBackendID, intent.SigningBackendVersion, intent.SigningPackageDigest, intent.SigningCapabilityHash); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	ctx, cancelIssuance := context.WithTimeout(ctx, DefaultIssuanceLease)
	defer cancelIssuance()
	failureStage := issuanceStageKeyGeneration
	if options.reuseKey {
		failureStage = issuanceStageKeyLoad
	}
	issuanceCompleted := false
	defer func() {
		if resultErr != nil && !issuanceCompleted {
			resultErr = s.recordIssuanceFailure(ctx, intent, auditContext, req.IssuerAuthorityID, failureStage, resultErr)
		}
	}()
	var key KeyMaterial
	if options.reuseKey {
		key, err = s.persistence.LoadKey(ctx, keyID)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	} else {
		key, err = backend.GenerateKey(ctx, keyID, template.Key)
		if err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	defer clear(key.PrivateKeyPKCS8)
	if err := ValidateBackendKeyIdentity(descriptor.ID, key); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	failureStage = issuanceStageKeyValidation
	validatedKey, err := ValidateKeyMaterial(ctx, validator, template.Key, key)
	if err != nil {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki: backend key validation failed: %w", err)
	}
	defer validatedKey.Clear()
	key = validatedKey.Material()
	defer clear(key.PrivateKeyPKCS8)
	if !template.SignatureAlgorithm.CompatibleWith(signer.Algorithm) {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki: signature algorithm %q is incompatible with issuer key algorithm %q", template.SignatureAlgorithm, signer.Algorithm)
	}
	failureStage = issuanceStageCertificateSigning
	issued, err := s.issue(ctx, signingBackend, signingValidator, template, key.PublicKeySPKI, issuerGeneration.CertificateDER, signer)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	failureStage = issuanceStageResultConstruction
	template.SignatureAlgorithm = issued.SignatureAlgorithm
	generation, err := domainpki.NewCertificateGeneration(domainpki.GenerationArgs{
		CertificateID:                certificateID,
		ID:                           generationID,
		Generation:                   intent.Generation,
		IssuerAuthorityID:            issuer.ID,
		IssuerGenerationID:           issuerGeneration.ID,
		ProfileID:                    intent.ProfileID,
		Template:                     template,
		BackendID:                    descriptor.ID,
		BackendVersion:               descriptor.Version,
		BackendPackageDigest:         descriptor.PackageDigest,
		BackendCapabilityHash:        descriptor.CapabilityHash,
		SigningBackendID:             signingDescriptor.ID,
		SigningBackendVersion:        signingDescriptor.Version,
		SigningBackendPackageDigest:  signingDescriptor.PackageDigest,
		SigningBackendCapabilityHash: signingDescriptor.CapabilityHash,
		CompatibilityTargetID:        intent.CompatibilityTargetID,
		CompatibilityVersion:         intent.CompatibilityVersion,
		Purpose:                      intent.Purpose,
		ExportPolicy:                 intent.ExportPolicy,
		KeyEstablishment:             intent.KeyEstablishment,
		TLSNamedGroups:               intent.TLSNamedGroups,
		FingerprintSHA256:            issued.FingerprintSHA256,
		SubjectKeyID:                 issued.SubjectKeyID,
		AuthorityKeyID:               issued.AuthorityKeyID,
		State:                        domainpki.CertificateStateActive,
		KeyID:                        key.ID,
		CertificateDER:               issued.CertificateDER,
		PublicKeySPKI:                issued.PublicKeySPKI,
		ChainGenerationIDs:           intent.ChainGenerationIDs,
		CreatedAt:                    now,
	})
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if options.sourceGeneration != nil {
		failureStage = issuanceStageLifecycleValidation
		if err := ValidateLifecycleGenerationTransition(options.kind, *options.sourceGeneration, generation); err != nil {
			return domainpki.CertificateGeneration{}, err
		}
	}
	completionAudits, err := s.newIssuanceCompletionAudits(
		auditContext,
		options.kind,
		issuer.ID,
		generationID,
		options.sourceGenerationID,
	)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	failureStage = issuanceStageInventoryCommit
	var completionErr error
	if options.reuseKey {
		completionErr = s.persistence.CompleteCertificateRenewal(ctx, intent.ID, intent.Ownership(), generation, validatedKey, completionAudits)
	} else {
		completionErr = s.persistence.CompleteCertificateIssuance(ctx, intent.ID, intent.Ownership(), generation, validatedKey, completionAudits)
	}
	if completionErr != nil {
		return domainpki.CertificateGeneration{}, completionErr
	}
	issuanceCompleted = true
	return generation.Clone(), nil
}

func (s Service) ExportBundle(ctx context.Context, generationID domainpki.GenerationID, purpose domainpki.Purpose, includePrivate bool) (result domainpki.Bundle, resultErr error) {
	defer func() {
		if resultErr != nil {
			result.Clear()
		}
	}()
	if err := generationID.Validate(); err != nil {
		return domainpki.Bundle{}, err
	}
	if err := purpose.Validate(); err != nil {
		return domainpki.Bundle{}, err
	}
	generation, err := s.persistence.Generation(ctx, generationID)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	if generation.State != domainpki.CertificateStateActive {
		return domainpki.Bundle{}, fmt.Errorf("pki: certificate generation %q cannot be exported while %s", generation.ID, generation.State)
	}
	if generation.Purpose != purpose {
		return domainpki.Bundle{}, fmt.Errorf("pki: bundle purpose %q does not match certificate generation purpose %q", purpose, generation.Purpose)
	}
	certificate, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, generation.CertificateDER)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	publicKey, err := domainpki.NewBinary(domainpki.MediaTypePublicKey, generation.PublicKeySPKI)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	var privateKey *domainpki.Binary
	var privateKeyRef *domainpki.KeyReference
	if includePrivate {
		if err := s.authorizePrivateExport(ctx, generation); err != nil {
			return domainpki.Bundle{}, err
		}
		defer func() {
			if resultErr != nil {
				auditErr := s.appendAudit(context.WithoutCancel(ctx), AuditActionPrivateExport, AuditOutcomeFailed, auditResourceGeneration, string(generation.ID), map[string]string{"purpose": string(purpose)})
				resultErr = errors.Join(resultErr, auditErr)
			}
		}()
		validated, accessErr := s.accessKey(ctx, generation, "private-export")
		if accessErr != nil {
			return domainpki.Bundle{}, accessErr
		}
		defer validated.Clear()
		key := validated.Material()
		defer key.Clear()
		if key.ExternalHandle != nil {
			privateKeyRef = &domainpki.KeyReference{
				KeyID: generation.KeyID, ProviderID: string(key.ExternalHandle.BackendID),
				Capabilities: key.ExternalHandle.Capabilities,
			}
		} else {
			privateKey = &domainpki.Binary{
				MediaType: domainpki.MediaTypePrivateKey,
				Encoding:  domainpki.EncodingBase64DER,
				Data:      key.PrivateKeyPKCS8,
			}
		}
	}
	chain, trust, err := s.bundleChain(ctx, generation)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	publicDigest := sha256.Sum256(generation.PublicKeySPKI)
	bundleID, err := s.newBundleID("bundle")
	if err != nil {
		return domainpki.Bundle{}, err
	}
	result, err = domainpki.NewBundle(domainpki.BundleArgs{
		SchemaVersion:           domainpki.BundleSchemaV1,
		ID:                      bundleID,
		CertificateID:           generation.CertificateID,
		CertificateGenerationID: generation.ID,
		Generation:              generation.Generation,
		Purpose:                 purpose,
		CompatibilityTargetID:   generation.CompatibilityTargetID,
		CompatibilityVersion:    generation.CompatibilityVersion,
		KeyEstablishmentPolicy:  generation.KeyEstablishment,
		TLSNamedGroups:          generation.TLSNamedGroups,
		Certificate:             certificate,
		PublicKey:               publicKey,
		PrivateKey:              privateKey,
		PrivateKeyRef:           privateKeyRef,
		Chain:                   chain,
		TrustAnchors:            trust,
		Fingerprints: domainpki.Fingerprints{
			CertificateSHA256: generation.FingerprintSHA256,
			PublicKeySHA256:   hex.EncodeToString(publicDigest[:]),
		},
		NotBefore: generation.Template.NotBefore,
		NotAfter:  generation.Template.NotAfter,
	})
	if err != nil {
		return domainpki.Bundle{}, err
	}
	validator, err := s.validators.ResolveValidator(ctx, generation.BackendID)
	if err != nil {
		return result, err
	}
	if err := validator.ValidateBundle(ctx, result, s.clock.Now().UTC()); err != nil {
		return result, fmt.Errorf("pki: verify exported credential bundle: %w", err)
	}
	if includePrivate {
		if err := s.appendAudit(ctx, AuditActionPrivateExport, AuditOutcomeSucceeded, auditResourceGeneration, string(generation.ID), map[string]string{"purpose": string(purpose)}); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s Service) authorizePrivateExport(ctx context.Context, generation domainpki.CertificateGeneration) error {
	if generation.ExportPolicy != domainpki.ExportPolicyExplicit {
		if err := s.appendAudit(ctx, AuditActionExportAuthorization, AuditOutcomeDenied, auditResourceGeneration, string(generation.ID), map[string]string{"reason": "export-policy"}); err != nil {
			return errors.Join(ErrPrivateKeyExportDenied, err)
		}
		return ErrPrivateKeyExportDenied
	}
	if err := s.exporter.AuthorizePrivateKeyExport(ctx, generation.ID); err != nil {
		if auditErr := s.appendAudit(ctx, AuditActionExportAuthorization, AuditOutcomeDenied, auditResourceGeneration, string(generation.ID), map[string]string{"reason": "authorizer"}); auditErr != nil {
			return errors.Join(ErrPrivateKeyExportDenied, err, auditErr)
		}
		return fmt.Errorf("%w: %v", ErrPrivateKeyExportDenied, err)
	}
	return s.appendAudit(ctx, AuditActionExportAuthorization, AuditOutcomeAllowed, auditResourceGeneration, string(generation.ID), nil)
}

func (s Service) signer(ctx context.Context, id domainpki.AuthorityID) (domainpki.Authority, domainpki.CertificateGeneration, KeyMaterial, error) {
	if err := id.Validate(); err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	authority, err := s.persistence.Authority(ctx, id)
	if err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	if authority.State != domainpki.AuthorityStateActive && authority.State != domainpki.AuthorityStateLocked {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, fmt.Errorf("pki: authority %q cannot issue while %s", id, authority.State)
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	lease, active, err := s.authorizer.SigningLease(ctx, id, auditContext)
	if err != nil || !active {
		if err == nil {
			err = ErrAuthoritySigningLocked
		}
		if auditErr := s.appendAuditWithContext(ctx, auditContext, AuditActionSigningAuthorization, AuditOutcomeDenied, auditResourceAuthority, string(id), map[string]string{"reason": "signing-lease"}); auditErr != nil {
			return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.Join(err, auditErr)
		}
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	if err := lease.Validate(); err != nil || !lease.matches(auditContext) || !now.Before(lease.ExpiresAt) {
		if err == nil {
			err = ErrAuthoritySigningLocked
		}
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	if err := s.authorizer.AuthorizeSigning(ctx, id, auditContext); err != nil {
		if auditErr := s.appendAuditWithContext(ctx, auditContext, AuditActionSigningAuthorization, AuditOutcomeDenied, auditResourceAuthority, string(id), map[string]string{"reason": "authorizer"}); auditErr != nil {
			return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.Join(err, auditErr)
		}
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	if err := s.appendAuditWithContext(ctx, auditContext, AuditActionSigningAuthorization, AuditOutcomeAllowed, auditResourceAuthority, string(id), map[string]string{"leaseExpiresAt": lease.ExpiresAt.Format(time.RFC3339Nano)}); err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	generation, err := s.persistence.Generation(ctx, authority.ActiveGenerationID)
	if err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	if !generation.Template.BasicConstraints.IsCA || generation.Template.KeyUsage&domainpki.KeyUsageCertificateSign == 0 {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: active authority generation cannot sign certificates")
	}
	if generation.OwningAuthorityID != authority.ID || generation.ID != authority.ActiveGenerationID {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: active generation does not belong to the signing authority")
	}
	if generation.State != domainpki.CertificateStateActive {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, fmt.Errorf("pki: authority generation %q cannot sign while %s", generation.ID, generation.State)
	}
	if now.Before(generation.Template.NotBefore) || !now.Before(generation.Template.NotAfter) {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, fmt.Errorf("pki: authority generation %q is not currently valid", generation.ID)
	}
	validated, err := s.accessKey(ctx, generation, "certificate-signing")
	if err != nil {
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, err
	}
	defer validated.Clear()
	material := validated.Material()
	if authority.SignerRef != string(generation.KeyID) || material.ID != generation.KeyID {
		clear(material.PrivateKeyPKCS8)
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: authority signer reference does not match its active generation key")
	}
	switch authority.SignerMode {
	case domainpki.SignerModeLocal:
		if material.ExternalHandle != nil {
			clear(material.PrivateKeyPKCS8)
			return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: local authority signer resolved to external custody")
		}
	case domainpki.SignerModeExternal:
		if material.ExternalHandle == nil {
			clear(material.PrivateKeyPKCS8)
			return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: external authority signer resolved to local custody")
		}
	default:
		clear(material.PrivateKeyPKCS8)
		return domainpki.Authority{}, domainpki.CertificateGeneration{}, KeyMaterial{}, errors.New("pki: authority has no usable signing mode")
	}
	return authority, generation, material, nil
}

func (s Service) accessKey(ctx context.Context, generation domainpki.CertificateGeneration, purpose string) (ValidatedKeyMaterial, error) {
	details := map[string]string{"purpose": purpose, "certificateGenerationId": string(generation.ID)}
	key, err := s.persistence.LoadKey(ctx, generation.KeyID)
	if err != nil {
		auditErr := s.appendAudit(context.WithoutCancel(ctx), AuditActionKeyAccess, AuditOutcomeFailed, auditResourceKey, string(generation.KeyID), details)
		return ValidatedKeyMaterial{}, errors.Join(err, auditErr)
	}
	defer clear(key.PrivateKeyPKCS8)
	validated, err := s.validateLoadedKey(ctx, generation, key)
	if err != nil {
		auditErr := s.appendAudit(context.WithoutCancel(ctx), AuditActionKeyAccess, AuditOutcomeFailed, auditResourceKey, string(generation.KeyID), details)
		return ValidatedKeyMaterial{}, errors.Join(err, auditErr)
	}
	if err := s.appendAudit(ctx, AuditActionKeyAccess, AuditOutcomeSucceeded, auditResourceKey, string(generation.KeyID), details); err != nil {
		validated.Clear()
		return ValidatedKeyMaterial{}, err
	}
	return validated, nil
}

func (s Service) appendAudit(ctx context.Context, action AuditAction, outcome AuditOutcome, resourceType, resourceID string, details map[string]string) error {
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return err
	}
	return s.appendAuditWithContext(ctx, auditContext, action, outcome, resourceType, resourceID, details)
}

func (s Service) resolveAuditContext(ctx context.Context) (AuditContext, error) {
	auditContext, err := s.auditCtx.AuditContext(ctx)
	if err != nil {
		return AuditContext{}, fmt.Errorf("pki: resolve audit context: %w", err)
	}
	if err := auditContext.Validate(); err != nil {
		return AuditContext{}, err
	}
	return auditContext, nil
}

func (s Service) appendAuditWithContext(ctx context.Context, auditContext AuditContext, action AuditAction, outcome AuditOutcome, resourceType, resourceID string, details map[string]string) error {
	record, err := s.newAuditRecord(auditContext, action, outcome, resourceType, resourceID, details)
	if err != nil {
		return err
	}
	if err := s.audit.AppendPKIAudit(ctx, record); err != nil {
		return fmt.Errorf("pki: append audit record: %w", err)
	}
	return nil
}

func (s Service) newIssuanceCompletionAudits(
	auditContext AuditContext,
	kind IssuanceKind,
	signingAuthorityID domainpki.AuthorityID,
	generationID domainpki.GenerationID,
	sourceGenerationID domainpki.GenerationID,
) (IssuanceCompletionAudits, error) {
	if err := signingAuthorityID.Validate(); err != nil {
		return IssuanceCompletionAudits{}, err
	}
	details := map[string]string{
		auditDetailGenerationID: string(generationID),
		auditDetailIssuanceKind: string(kind),
	}
	if sourceGenerationID != "" {
		details[auditDetailSourceGenerationID] = string(sourceGenerationID)
	}
	signingUse, err := s.newAuditRecord(
		auditContext,
		AuditActionSigningUse,
		AuditOutcomeSucceeded,
		auditResourceAuthority,
		string(signingAuthorityID),
		details,
	)
	if err != nil {
		return IssuanceCompletionAudits{}, err
	}
	result := IssuanceCompletionAudits{SigningUse: signingUse}
	var lifecycleAction AuditAction
	switch kind {
	case IssuanceKindAuthority, IssuanceKindCertificate:
		if sourceGenerationID != "" {
			return IssuanceCompletionAudits{}, errors.New("pki: ordinary issuance cannot name a lifecycle source")
		}
	case IssuanceKindCertificateRenewal:
		lifecycleAction = AuditActionCertificateRenew
	case IssuanceKindCertificateRotation:
		lifecycleAction = AuditActionCertificateRotate
	default:
		return IssuanceCompletionAudits{}, fmt.Errorf("pki: unsupported issuance kind %q", kind)
	}
	if lifecycleAction != "" {
		if err := sourceGenerationID.Validate(); err != nil {
			return IssuanceCompletionAudits{}, err
		}
		lifecycle, lifecycleErr := s.newAuditRecord(
			auditContext,
			lifecycleAction,
			AuditOutcomeSucceeded,
			auditResourceGeneration,
			string(generationID),
			map[string]string{auditDetailSourceGenerationID: string(sourceGenerationID)},
		)
		if lifecycleErr != nil {
			return IssuanceCompletionAudits{}, lifecycleErr
		}
		result.Lifecycle = &lifecycle
	}
	if err := result.Validate(kind, generationID, sourceGenerationID, signingAuthorityID); err != nil {
		return IssuanceCompletionAudits{}, err
	}
	return result, nil
}

func (s Service) newAuditRecord(auditContext AuditContext, action AuditAction, outcome AuditOutcome, resourceType, resourceID string, details map[string]string) (AuditRecord, error) {
	id, err := s.randomID("audit")
	if err != nil {
		return AuditRecord{}, err
	}
	return newAuditRecordWithID(
		auditContext, id, action, outcome, resourceType, resourceID, details, s.clock.Now().UTC(),
	)
}

func newAuditRecordWithID(
	auditContext AuditContext,
	id string,
	action AuditAction,
	outcome AuditOutcome,
	resourceType string,
	resourceID string,
	details map[string]string,
	createdAt time.Time,
) (AuditRecord, error) {
	if err := auditContext.Validate(); err != nil {
		return AuditRecord{}, err
	}
	record := AuditRecord{
		ID:            id,
		Action:        action,
		Outcome:       outcome,
		ActorID:       auditContext.ActorID,
		OperationID:   auditContext.OperationID,
		CorrelationID: auditContext.CorrelationID,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Details:       details,
		CreatedAt:     createdAt.UTC(),
	}
	if err := record.Validate(); err != nil {
		return AuditRecord{}, err
	}
	return record, nil
}

func (s Service) validateLoadedKey(ctx context.Context, generation domainpki.CertificateGeneration, key KeyMaterial) (ValidatedKeyMaterial, error) {
	if key.ID != generation.KeyID || key.Algorithm != generation.Template.Key.Algorithm ||
		!bytes.Equal(key.PublicKeySPKI, generation.PublicKeySPKI) {
		return ValidatedKeyMaterial{}, errors.New("pki: stored key does not match certificate generation metadata")
	}
	validator, err := s.validators.ResolveValidator(ctx, generation.BackendID)
	if err != nil {
		return ValidatedKeyMaterial{}, fmt.Errorf("pki: resolve validator for stored key backend %q: %w", generation.BackendID, err)
	}
	validated, err := ValidateKeyMaterial(ctx, validator, generation.Template.Key, key)
	if err != nil {
		return ValidatedKeyMaterial{}, fmt.Errorf("pki: validate stored key for certificate generation %q: %w", generation.ID, err)
	}
	return validated, nil
}

func (s Service) issue(ctx context.Context, backend Backend, validator Validator, template domainpki.CertificateTemplate, subjectSPKI, issuerDER []byte, signer KeyMaterial) (IssuedCertificate, error) {
	request := IssueRequest{
		Template:             template.Clone(),
		SubjectPublicKeySPKI: append([]byte(nil), subjectSPKI...),
		IssuerCertificateDER: append([]byte(nil), issuerDER...),
		Signer:               signer.Clone(),
	}
	defer clear(request.Signer.PrivateKeyPKCS8)
	issued, err := backend.Issue(ctx, request)
	if err != nil {
		return IssuedCertificate{}, err
	}
	validated, err := validator.ValidateIssued(ctx, ValidationRequest{Template: template, CertificateDER: issued.CertificateDER, SubjectPublicKeySPKI: subjectSPKI, IssuerCertificateDER: issuerDER})
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("pki: backend output validation failed: %w", err)
	}
	return validated, nil
}

func authorityProfile(role domainpki.AuthorityRole, requested domainpki.ProfileID) (domainpki.Profile, error) {
	if requested == "" {
		if role == domainpki.AuthorityRoleRoot {
			requested = domainpki.ProfileRootModern
		} else {
			requested = domainpki.ProfileSubordinateModern
		}
	}
	profile, ok := domainpki.BuiltInProfile(requested)
	if !ok || profile.AuthorityRole != role {
		return domainpki.Profile{}, fmt.Errorf("pki: profile %q does not match authority role %q", requested, role)
	}
	return profile, nil
}

func (s Service) resolveBackend(ctx context.Context, profile domainpki.Profile) (Backend, Validator, domainpki.BackendDescriptor, error) {
	backend, err := s.backends.ResolveBackend(ctx, profile.Backend)
	if err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, err
	}
	descriptor := backend.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, fmt.Errorf("pki: validate selected backend descriptor: %w", err)
	}
	if descriptor.ID != profile.Backend {
		return nil, nil, domainpki.BackendDescriptor{}, fmt.Errorf("pki: selected backend %q does not match profile backend %q", descriptor.ID, profile.Backend)
	}
	validator, err := s.validators.ResolveValidator(ctx, descriptor.ID)
	if err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, err
	}
	return backend, validator, descriptor.Clone(), nil
}

func (s Service) resolveSigningBackend(ctx context.Context, issuer domainpki.CertificateGeneration, signer KeyMaterial) (Backend, Validator, domainpki.BackendDescriptor, error) {
	backendID := issuer.BackendID
	if signer.ExternalHandle != nil {
		if signer.ExternalHandle.BackendID != issuer.BackendID {
			return nil, nil, domainpki.BackendDescriptor{}, errors.New("pki: external signer backend does not match issuer generation backend")
		}
		backendID = signer.ExternalHandle.BackendID
	}
	backend, err := s.backends.ResolveBackend(ctx, backendID)
	if err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, fmt.Errorf("pki: resolve issuer signing backend %q: %w", backendID, err)
	}
	descriptor := backend.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, fmt.Errorf("pki: validate issuer signing backend descriptor: %w", err)
	}
	if err := validateBackendCommitment("issuer key", descriptor, issuer.BackendID, issuer.BackendVersion, issuer.BackendPackageDigest, issuer.BackendCapabilityHash); err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, err
	}
	validator, err := s.validators.ResolveValidator(ctx, backendID)
	if err != nil {
		return nil, nil, domainpki.BackendDescriptor{}, fmt.Errorf("pki: resolve issuer signing validator %q: %w", backendID, err)
	}
	return backend, validator, descriptor.Clone(), nil
}

func validateBackendCommitment(label string, descriptor domainpki.BackendDescriptor, id domainpki.BackendID, version, packageDigest, capabilityHash string) error {
	if descriptor.ID != id || descriptor.Version != version || descriptor.PackageDigest != packageDigest || descriptor.CapabilityHash != capabilityHash {
		return fmt.Errorf("pki: %s backend descriptor changed after issuance planning", label)
	}
	return nil
}

func resolveExportPolicy(profile, requested domainpki.ExportPolicy) (domainpki.ExportPolicy, error) {
	if requested == "" {
		return profile, nil
	}
	if err := requested.Validate(); err != nil {
		return "", err
	}
	if profile == domainpki.ExportPolicyNever && requested != domainpki.ExportPolicyNever ||
		profile == domainpki.ExportPolicyPublicOnly && requested == domainpki.ExportPolicyExplicit {
		return "", errors.New("pki: requested export policy weakens the profile policy")
	}
	return requested, nil
}

func validateSubordinatePathLength(parent, child domainpki.BasicConstraints) error {
	if !parent.IsCA {
		return errors.New("pki: parent generation is not a ca certificate")
	}
	if parent.MaxPathLen == 0 && !parent.MaxPathLenZero {
		return nil
	}
	if parent.MaxPathLenZero {
		return errors.New("pki: parent authority path length forbids subordinate authorities")
	}
	remaining := parent.MaxPathLen - 1
	if child.MaxPathLen == 0 && !child.MaxPathLenZero {
		return errors.New("pki: subordinate authority cannot be unconstrained beneath a constrained parent")
	}
	childLimit := child.MaxPathLen
	if child.MaxPathLenZero {
		childLimit = 0
	}
	if childLimit > remaining {
		return fmt.Errorf("pki: subordinate path length %d exceeds parent remaining path length %d", childLimit, remaining)
	}
	return nil
}

func (s Service) resolveTemplate(explicit *domainpki.CertificateTemplate, profile domainpki.Profile, descriptor domainpki.BackendDescriptor, commonName string, now time.Time) (domainpki.CertificateTemplate, error) {
	if explicit != nil {
		result := explicit.Clone()
		if err := result.Validate(); err != nil {
			return domainpki.CertificateTemplate{}, err
		}
		if !descriptor.SupportsKey(result.Key.Algorithm) || !descriptor.SupportsSignature(result.SignatureAlgorithm) {
			return domainpki.CertificateTemplate{}, errors.New("pki: selected crypto backend does not support the template algorithms")
		}
		if err := validateTemplateAgainstProfile(result, profile, now); err != nil {
			return domainpki.CertificateTemplate{}, err
		}
		return result, nil
	}
	serial, err := s.newSerial()
	if err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	result := domainpki.CertificateTemplate{
		SerialNumber:           serial,
		Subject:                domainpki.DistinguishedName{CommonName: commonName},
		NotBefore:              now.Add(-profile.Backdate),
		NotAfter:               now.Add(profile.Validity),
		Key:                    profile.Key,
		SignatureAlgorithm:     profile.Signature,
		BasicConstraints:       profile.BasicConstraints,
		KeyUsage:               profile.KeyUsage,
		ExtendedKeyUsages:      append([]domainpki.ExtendedKeyUsage(nil), profile.ExtendedKeyUsage...),
		SubjectKeyIdentifier:   domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier: domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
	if !result.BasicConstraints.IsCA && (profile.Purpose == domainpki.PurposeTLSServer || profile.Purpose == domainpki.PurposeMTLSServer || profile.Purpose == domainpki.PurposeDualRoleMTLS) {
		result.SubjectAlternativeNames.DNSNames = []string{commonName}
	}
	if err := result.Validate(); err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	if err := validateTemplateAgainstProfile(result, profile, now); err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	return result, nil
}

func validateTemplateAgainstProfile(template domainpki.CertificateTemplate, profile domainpki.Profile, now time.Time) error {
	earliestNotBefore := now.Add(-profile.Backdate)
	latestNotAfter := now.Add(profile.Validity)
	if template.NotBefore.Before(earliestNotBefore) || template.NotBefore.After(now) || template.NotAfter.After(latestNotAfter) {
		return errors.New("pki: certificate template validity is outside the selected profile issuance window")
	}
	if template.NotAfter.Sub(template.NotBefore) > profile.Validity+profile.Backdate {
		return errors.New("pki: certificate template validity exceeds the selected profile window")
	}
	if profile.AuthorityRole != "" {
		if template.BasicConstraints != profile.BasicConstraints {
			return errors.New("pki: authority template basic constraints do not match the selected profile")
		}
	} else if template.BasicConstraints.IsCA {
		return errors.New("pki: leaf profile cannot issue a ca certificate")
	}
	if template.KeyUsage != profile.KeyUsage {
		return errors.New("pki: certificate template key usage does not match the selected profile")
	}
	if len(template.ExtendedKeyUsages) != len(profile.ExtendedKeyUsage) || len(template.UnknownExtendedKeyUsages) != 0 {
		return errors.New("pki: certificate template extended key usages do not match the selected profile")
	}
	for _, required := range profile.ExtendedKeyUsage {
		found := false
		for _, actual := range template.ExtendedKeyUsages {
			if actual == required {
				found = true
				break
			}
		}
		if !found {
			return errors.New("pki: certificate template extended key usages do not match the selected profile")
		}
	}
	target, ok := domainpki.BuiltInCompatibilityTarget(profile.Compatibility)
	if !ok {
		return fmt.Errorf("pki: compatibility target %q is unavailable", profile.Compatibility)
	}
	if !target.SupportsKey(template.Key.Algorithm) || !target.SupportsSignature(template.SignatureAlgorithm) {
		return fmt.Errorf("pki: certificate template algorithms are incompatible with target %q", target.ID)
	}
	return nil
}

func (s Service) bundleChain(ctx context.Context, leaf domainpki.CertificateGeneration) ([]domainpki.CertificateMember, []domainpki.CertificateMember, error) {
	chain := make([]domainpki.CertificateMember, 0, len(leaf.ChainGenerationIDs))
	trust := make([]domainpki.CertificateMember, 0, 1)
	for _, id := range leaf.ChainGenerationIDs {
		generation, err := s.persistence.Generation(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		binary, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, generation.CertificateDER)
		if err != nil {
			return nil, nil, err
		}
		member := domainpki.CertificateMember{GenerationID: generation.ID, Binary: binary}
		if generation.IssuerGenerationID == "" {
			trust = append(trust, member)
		} else {
			chain = append(chain, member)
		}
	}
	return chain, trust, nil
}

type authorityIDs struct {
	authority   domainpki.AuthorityID
	certificate domainpki.CertificateID
	generation  domainpki.GenerationID
	key         domainpki.KeyID
}

func (s Service) authorityIDs(req CreateAuthorityRequest) (authorityIDs, error) {
	result := authorityIDs{authority: req.ID, certificate: req.CertificateID, generation: req.GenerationID, key: req.KeyID}
	var err error
	if result.authority == "" {
		result.authority, err = s.newAuthorityID("authority")
	}
	if err == nil && result.certificate == "" {
		result.certificate, err = s.newCertificateID("cert")
	}
	if err == nil && result.generation == "" {
		result.generation, err = s.newGenerationID("certgen")
	}
	if err == nil && result.key == "" {
		result.key, err = s.newKeyID("key")
	}
	if err != nil {
		return authorityIDs{}, err
	}
	if err := result.authority.Validate(); err != nil {
		return authorityIDs{}, err
	}
	if err := result.certificate.Validate(); err != nil {
		return authorityIDs{}, err
	}
	if err := result.generation.Validate(); err != nil {
		return authorityIDs{}, err
	}
	if err := result.key.Validate(); err != nil {
		return authorityIDs{}, err
	}
	return result, nil
}

func (s Service) newSerial() (domainpki.SerialNumber, error) {
	for range maxRandomRetries {
		value := make([]byte, serialRandomBytes)
		if err := s.readRandom(value); err != nil {
			return "", fmt.Errorf("pki: generate serial number: %w", err)
		}
		value[0] &= 0x7f
		serial, err := domainpki.NewSerialNumber(value)
		if err == nil {
			return serial, nil
		}
	}
	return "", errors.New("pki: failed to generate a positive serial number")
}

func (s Service) randomID(prefix string) (string, error) {
	value := make([]byte, resourceIDRandomBytes)
	if err := s.readRandom(value); err != nil {
		return "", fmt.Errorf("pki: generate %s id: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(value), nil
}

func (s Service) readRandom(value []byte) error {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	_, err := io.ReadFull(s.random, value)
	return err
}

func (s Service) newAuthorityID(prefix string) (domainpki.AuthorityID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewAuthorityID(value)
}

func (s Service) newCertificateID(prefix string) (domainpki.CertificateID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewCertificateID(value)
}

func (s Service) newGenerationID(prefix string) (domainpki.GenerationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewGenerationID(value)
}

func (s Service) newKeyID(prefix string) (domainpki.KeyID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewKeyID(value)
}

func (s Service) newIssuanceID(prefix string) (domainpki.IssuanceID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewIssuanceID(value)
}

func (s Service) newMutationID(prefix string) (domainpki.MutationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewMutationID(value)
}

func (s Service) newRevocationID(prefix string) (domainpki.RevocationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewRevocationID(value)
}

func requestDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("pki: encode request: %w", err)
	}
	return issuanceRequestDigest(encoded), nil
}

func resolveIdempotencyKey[T ~string](explicit string, kind T, requestSHA256 string, auditContext AuditContext) (string, error) {
	if err := auditContext.Validate(); err != nil {
		return "", err
	}
	if explicit != "" {
		if err := validateIdempotencyKey(explicit); err != nil {
			return "", err
		}
		return scopedIdempotencyKey(struct {
			Version string `json:"version"`
			Kind    string `json:"kind"`
			ActorID string `json:"actorId"`
			Key     string `json:"key"`
		}{Version: "v1", Kind: string(kind), ActorID: auditContext.ActorID, Key: explicit})
	}
	return scopedIdempotencyKey(struct {
		Version       string `json:"version"`
		Kind          string `json:"kind"`
		ActorID       string `json:"actorId"`
		OperationID   string `json:"operationId"`
		CorrelationID string `json:"correlationId"`
		RequestSHA256 string `json:"requestSha256"`
	}{
		Version: "v1", Kind: string(kind), ActorID: auditContext.ActorID,
		OperationID: auditContext.OperationID, CorrelationID: auditContext.CorrelationID,
		RequestSHA256: requestSHA256,
	})
}

func scopedIdempotencyKey(scope any) (string, error) {
	digest, err := requestDigest(scope)
	if err != nil {
		return "", err
	}
	key := "pki:v1:" + digest
	if err := validateIdempotencyKey(key); err != nil {
		return "", err
	}
	return key, nil
}

func (s Service) existingIssuance(ctx context.Context, key string, kind IssuanceKind, digest string) (IssuanceIntent, bool, error) {
	intent, err := s.persistence.IssuanceByKey(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return IssuanceIntent{}, false, nil
	}
	if err != nil {
		return IssuanceIntent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return IssuanceIntent{}, false, fmt.Errorf("pki: validate persisted issuance intent: %w", err)
	}
	if intent.Kind != kind || intent.RequestSHA256 != digest {
		return IssuanceIntent{}, false, ErrIdempotencyConflict
	}
	if intent.Status == IssuanceStatusFailed {
		return IssuanceIntent{}, false, fmt.Errorf("pki: prior issuance attempt failed: %s", intent.Failure)
	}
	if intent.Status == IssuanceStatusPending {
		return IssuanceIntent{}, false, ErrIssuanceInProgress
	}
	return intent.Clone(), true, nil
}

func (s Service) recordIssuanceFailure(ctx context.Context, intent IssuanceIntent, auditContext AuditContext, authorityID domainpki.AuthorityID, stage string, cause error) error {
	if intent.ID == "" || intent.Status != IssuanceStatusPending {
		return cause
	}
	record, recordErr := s.newAuditRecord(auditContext, AuditActionIssuance, AuditOutcomeFailed, auditResourceAuthority, string(authorityID), map[string]string{
		"certificateGenerationId": string(intent.GenerationID),
		"stage":                   stage,
	})
	if recordErr != nil {
		return errors.Join(cause, recordErr)
	}
	failure := "issuance failed during " + stage
	if stage == issuanceStageCertificateSigning {
		failure = issuanceFailureSigning
	}
	failErr := s.persistence.FailIssuance(context.WithoutCancel(ctx), intent.ID, intent.Ownership(), failure, s.clock.Now().UTC(), record)
	return errors.Join(cause, failErr)
}

func signingAuthorityIDForIntent(intent IssuanceIntent) domainpki.AuthorityID {
	if intent.IssuerAuthorityID != "" {
		return intent.IssuerAuthorityID
	}
	return intent.AuthorityID
}

func (s Service) newBundleID(prefix string) (domainpki.BundleID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewBundleID(value)
}
