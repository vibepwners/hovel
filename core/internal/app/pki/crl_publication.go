package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	DefaultCRLValidity                = 24 * time.Hour
	DefaultCRLLease                   = 5 * time.Minute
	MaximumPendingCRLPublicationBatch = 100
	MaximumProviderOperationRefBytes  = 1024

	crlRequestDigestBytes   = sha256.Size
	crlLeaseRenewalInterval = DefaultCRLLease / 3
	crlTransitionAttempts   = 3
	crlTransitionTimeout    = DefaultCRLLease / 10
	crlLeaseSafetyMargin    = DefaultCRLLease / 5
	crlTransitionRetryDelay = 100 * time.Millisecond
	auditResourceCRL        = "crl-generation"

	auditDetailCRLPublicationID      = "crlPublicationId"
	auditDetailCRLIssuerGeneration   = "issuerGenerationId"
	auditDetailCRLNumber             = "number"
	auditDetailCRLRevocationCount    = "revocationCount"
	auditDetailCRLFingerprint        = "fingerprintSha256"
	auditDetailCRLSignatureAlgorithm = "signatureAlgorithm"
	auditDetailProviderOperationRef  = "providerOperationRef"
	auditDetailCRLStage              = "stage"
)

var ErrCRLPublicationInProgress = errors.New("pki: crl publication is already in progress")

type retryableCRLPublicationError struct {
	err error
}

func (e retryableCRLPublicationError) Error() string { return e.err.Error() }
func (e retryableCRLPublicationError) Unwrap() error { return e.err }

func retryableCRLError(err error) error {
	if err == nil || isRetryableCRLError(err) {
		return err
	}
	return retryableCRLPublicationError{err: err}
}

func isRetryableCRLError(err error) bool {
	var retryable retryableCRLPublicationError
	return errors.As(err, &retryable)
}

func checkpointMatches(left, right CRLSignedCheckpoint) bool {
	return left.FingerprintSHA256 == right.FingerprintSHA256 &&
		left.SignatureAlgorithm == right.SignatureAlgorithm &&
		left.ProviderOperationRef == right.ProviderOperationRef &&
		left.RecordedAt.Equal(right.RecordedAt) &&
		bytes.Equal(left.CRLDER, right.CRLDER)
}

func crlPublicationIntentsEqual(left, right CRLPublicationIntent) bool {
	if left.ID != right.ID || left.IdempotencyKey != right.IdempotencyKey ||
		left.RequestSHA256 != right.RequestSHA256 || left.CRLGenerationID != right.CRLGenerationID ||
		left.AuthorityID != right.AuthorityID || left.IssuerGenerationID != right.IssuerGenerationID ||
		left.Number != right.Number || !left.ThisUpdate.Equal(right.ThisUpdate) ||
		!left.NextUpdate.Equal(right.NextUpdate) || !slices.Equal(left.RevocationIDs, right.RevocationIDs) ||
		left.SigningBackendID != right.SigningBackendID || left.SigningBackendVersion != right.SigningBackendVersion ||
		left.SigningBackendPackageDigest != right.SigningBackendPackageDigest ||
		left.SigningBackendCapabilityHash != right.SigningBackendCapabilityHash ||
		left.SignatureAlgorithm != right.SignatureAlgorithm || left.Status != right.Status ||
		left.Phase != right.Phase || left.OwnerToken != right.OwnerToken || left.Revision != right.Revision ||
		!left.LeaseExpiresAt.Equal(right.LeaseExpiresAt) ||
		left.ResultCRLGenerationID != right.ResultCRLGenerationID || left.Failure != right.Failure ||
		!left.CreatedAt.Equal(right.CreatedAt) || !left.UpdatedAt.Equal(right.UpdatedAt) {
		return false
	}
	if (left.SignedCheckpoint == nil) != (right.SignedCheckpoint == nil) {
		return false
	}
	return left.SignedCheckpoint == nil || checkpointMatches(
		left.SignedCheckpoint.Clone(), right.SignedCheckpoint.Clone(),
	)
}

func isExactCRLLeaseRenewal(before, after CRLPublicationIntent) bool {
	expected, err := RenewCRLPublicationLeaseIntent(before, after.UpdatedAt)
	return err == nil && crlPublicationIntentsEqual(expected, after)
}

func maxTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

type CRLPublicationFailureStage string

const (
	CRLPublicationFailureStageProvider       CRLPublicationFailureStage = "provider"
	CRLPublicationFailureStageValidation     CRLPublicationFailureStage = "validation"
	CRLPublicationFailureStageConstruction   CRLPublicationFailureStage = "construction"
	CRLPublicationFailureStageCompletion     CRLPublicationFailureStage = "completion"
	CRLPublicationFailureStageExpired        CRLPublicationFailureStage = "expired"
	CRLPublicationFailureStageReconciliation CRLPublicationFailureStage = "reconciliation"
)

func (s CRLPublicationFailureStage) Validate() error {
	switch s {
	case CRLPublicationFailureStageProvider, CRLPublicationFailureStageValidation,
		CRLPublicationFailureStageConstruction, CRLPublicationFailureStageCompletion,
		CRLPublicationFailureStageExpired, CRLPublicationFailureStageReconciliation:
		return nil
	default:
		return fmt.Errorf("pki: unsupported crl publication failure stage %q", s)
	}
}

// CRLPublicationStatus is the closed lifecycle of a durable CRL signing plan.
type CRLPublicationStatus string

const (
	CRLPublicationStatusPending   CRLPublicationStatus = "pending"
	CRLPublicationStatusCompleted CRLPublicationStatus = "completed"
	CRLPublicationStatusFailed    CRLPublicationStatus = "failed"
)

func (s CRLPublicationStatus) Validate() error {
	switch s {
	case CRLPublicationStatusPending, CRLPublicationStatusCompleted, CRLPublicationStatusFailed:
		return nil
	default:
		return fmt.Errorf("pki: unsupported crl publication status %q", s)
	}
}

// CRLPublicationPhase records how far a pending publication progressed across
// the non-transactional provider boundary.
type CRLPublicationPhase string

const (
	CRLPublicationPhasePlanned CRLPublicationPhase = "planned"
	CRLPublicationPhaseSigning CRLPublicationPhase = "signing"
	CRLPublicationPhaseSigned  CRLPublicationPhase = "signed"
)

func (p CRLPublicationPhase) Validate() error {
	switch p {
	case CRLPublicationPhasePlanned, CRLPublicationPhaseSigning, CRLPublicationPhaseSigned:
		return nil
	default:
		return fmt.Errorf("pki: unsupported crl publication phase %q", p)
	}
}

// ProviderOperationRef identifies a provider-owned signing operation when the
// backend can expose one. Empty is valid for synchronous local backends.
type ProviderOperationRef string

func (r ProviderOperationRef) Validate() error {
	value := string(r)
	if value == "" {
		return nil
	}
	if value != strings.TrimSpace(value) || len(value) > MaximumProviderOperationRefBytes ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("pki: provider operation reference is not canonical")
	}
	return nil
}

// CRLSignedCheckpoint is durably committed immediately after a provider
// returns. It lets recovery validate and finish without invoking the signer a
// second time.
type CRLSignedCheckpoint struct {
	FingerprintSHA256    string                       `json:"fingerprintSha256"`
	SignatureAlgorithm   domainpki.SignatureAlgorithm `json:"signatureAlgorithm"`
	CRLDER               []byte                       `json:"crlDer"`
	ProviderOperationRef ProviderOperationRef         `json:"providerOperationRef,omitempty"`
	RecordedAt           time.Time                    `json:"recordedAt"`
}

func NewCRLSignedCheckpoint(issued IssuedCRL, recordedAt time.Time) (CRLSignedCheckpoint, error) {
	issued = issued.Clone()
	if err := issued.Validate(); err != nil {
		return CRLSignedCheckpoint{}, err
	}
	recordedAt = recordedAt.UTC().Truncate(time.Second)
	if recordedAt.IsZero() {
		return CRLSignedCheckpoint{}, errors.New("pki: crl signed checkpoint time is required")
	}
	return CRLSignedCheckpoint{
		FingerprintSHA256: issued.FingerprintSHA256, SignatureAlgorithm: issued.SignatureAlgorithm,
		CRLDER: issued.CRLDER, ProviderOperationRef: issued.ProviderOperationRef, RecordedAt: recordedAt,
	}, nil
}

func (c CRLSignedCheckpoint) Clone() CRLSignedCheckpoint {
	result := c
	result.CRLDER = append([]byte(nil), c.CRLDER...)
	return result
}

func (c CRLSignedCheckpoint) Validate() error {
	if err := (IssuedCRL{
		CRLDER: c.CRLDER, FingerprintSHA256: c.FingerprintSHA256,
		SignatureAlgorithm: c.SignatureAlgorithm, ProviderOperationRef: c.ProviderOperationRef,
	}).Validate(); err != nil {
		return err
	}
	if c.RecordedAt.IsZero() || c.RecordedAt != c.RecordedAt.UTC().Truncate(time.Second) {
		return errors.New("pki: crl signed checkpoint time is not canonical")
	}
	return nil
}

// CRLPublicationIntent is the immutable plan persisted before a provider may
// use an authority key. Number is atomically reserved by BeginCRLPublication.
type CRLPublicationIntent struct {
	ID                           domainpki.CRLPublicationID   `json:"id"`
	IdempotencyKey               string                       `json:"idempotencyKey"`
	RequestSHA256                string                       `json:"requestSha256"`
	CRLGenerationID              domainpki.CRLGenerationID    `json:"crlGenerationId"`
	AuthorityID                  domainpki.AuthorityID        `json:"authorityId"`
	IssuerGenerationID           domainpki.GenerationID       `json:"issuerGenerationId"`
	Number                       uint64                       `json:"number"`
	ThisUpdate                   time.Time                    `json:"thisUpdate"`
	NextUpdate                   time.Time                    `json:"nextUpdate"`
	RevocationIDs                []domainpki.RevocationID     `json:"revocationIds"`
	SigningBackendID             domainpki.BackendID          `json:"signingBackendId"`
	SigningBackendVersion        string                       `json:"signingBackendVersion"`
	SigningBackendPackageDigest  string                       `json:"signingBackendPackageDigest,omitempty"`
	SigningBackendCapabilityHash string                       `json:"signingBackendCapabilityHash"`
	SignatureAlgorithm           domainpki.SignatureAlgorithm `json:"signatureAlgorithm"`
	Status                       CRLPublicationStatus         `json:"status"`
	Phase                        CRLPublicationPhase          `json:"phase"`
	OwnerToken                   string                       `json:"ownerToken"`
	Revision                     uint64                       `json:"revision"`
	LeaseExpiresAt               time.Time                    `json:"leaseExpiresAt"`
	ResultCRLGenerationID        domainpki.CRLGenerationID    `json:"resultCrlGenerationId,omitempty"`
	SignedCheckpoint             *CRLSignedCheckpoint         `json:"signedCheckpoint,omitempty"`
	Failure                      string                       `json:"failure,omitempty"`
	CreatedAt                    time.Time                    `json:"createdAt"`
	UpdatedAt                    time.Time                    `json:"updatedAt"`
}

type CRLPublicationOwnership struct {
	OwnerToken string `json:"ownerToken"`
	Revision   uint64 `json:"revision"`
}

func (i CRLPublicationIntent) Ownership() CRLPublicationOwnership {
	return CRLPublicationOwnership{OwnerToken: i.OwnerToken, Revision: i.Revision}
}

func (i CRLPublicationIntent) Clone() CRLPublicationIntent {
	result := i
	result.RevocationIDs = append([]domainpki.RevocationID(nil), i.RevocationIDs...)
	if i.SignedCheckpoint != nil {
		checkpoint := i.SignedCheckpoint.Clone()
		result.SignedCheckpoint = &checkpoint
	}
	return result
}

func (i CRLPublicationIntent) Validate() error {
	if err := i.ID.Validate(); err != nil {
		return err
	}
	if err := validateIdempotencyKey(i.IdempotencyKey); err != nil {
		return err
	}
	digest, err := hex.DecodeString(i.RequestSHA256)
	if err != nil || len(digest) != crlRequestDigestBytes || i.RequestSHA256 != strings.ToLower(i.RequestSHA256) {
		return errors.New("pki: crl publication request digest must be canonical sha256")
	}
	if err := i.CRLGenerationID.Validate(); err != nil {
		return err
	}
	if err := i.AuthorityID.Validate(); err != nil {
		return err
	}
	if err := i.IssuerGenerationID.Validate(); err != nil {
		return err
	}
	if i.Number > domainpki.MaximumSequenceNumber {
		return errors.New("pki: crl publication number exceeds the supported range")
	}
	validity := i.NextUpdate.Sub(i.ThisUpdate)
	if i.ThisUpdate.IsZero() || i.NextUpdate.IsZero() ||
		i.ThisUpdate != i.ThisUpdate.UTC().Truncate(time.Second) ||
		i.NextUpdate != i.NextUpdate.UTC().Truncate(time.Second) ||
		validity < domainpki.MinimumCRLValidity || validity > domainpki.MaximumCRLValidity {
		return errors.New("pki: crl publication update window is invalid")
	}
	if len(i.RevocationIDs) > domainpki.MaximumCRLRevocations {
		return errors.New("pki: crl publication has too many revocations")
	}
	for index, id := range i.RevocationIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		if index > 0 && i.RevocationIDs[index-1] >= id {
			return errors.New("pki: crl publication revocation ids must be unique and sorted")
		}
	}
	if err := i.SigningBackendID.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(i.SigningBackendVersion) == "" || strings.TrimSpace(i.SigningBackendCapabilityHash) == "" {
		return errors.New("pki: crl publication backend commitment is required")
	}
	if err := i.SignatureAlgorithm.Validate(); err != nil {
		return err
	}
	if err := i.Status.Validate(); err != nil {
		return err
	}
	if err := i.Phase.Validate(); err != nil {
		return err
	}
	if !validIssuanceOwner(i.OwnerToken) || i.Revision == 0 || i.Revision > domainpki.MaximumSequenceNumber {
		return errors.New("pki: crl publication ownership is invalid")
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() || i.CreatedAt != i.CreatedAt.UTC().Truncate(time.Second) ||
		i.UpdatedAt != i.UpdatedAt.UTC().Truncate(time.Second) || i.UpdatedAt.Before(i.CreatedAt) {
		return errors.New("pki: crl publication timestamps are invalid")
	}
	if i.LeaseExpiresAt.IsZero() || i.LeaseExpiresAt != i.LeaseExpiresAt.UTC().Truncate(time.Second) ||
		i.Status == CRLPublicationStatusPending && !i.LeaseExpiresAt.After(i.UpdatedAt) {
		return errors.New("pki: crl publication lease is invalid")
	}
	switch i.Status {
	case CRLPublicationStatusPending:
		if i.ResultCRLGenerationID != "" || i.Failure != "" {
			return errors.New("pki: pending crl publication cannot have a result or failure")
		}
	case CRLPublicationStatusCompleted:
		if i.Phase != CRLPublicationPhaseSigned || i.ResultCRLGenerationID != i.CRLGenerationID ||
			i.Failure != "" || i.Number == 0 || !i.UpdatedAt.Before(i.NextUpdate) {
			return errors.New("pki: completed crl publication does not match its plan")
		}
	case CRLPublicationStatusFailed:
		if i.ResultCRLGenerationID != "" || !validIssuanceFailure(i.Failure) {
			return errors.New("pki: failed crl publication requires a canonical failure")
		}
	}
	if i.Phase == CRLPublicationPhaseSigned {
		if i.SignedCheckpoint == nil {
			return errors.New("pki: signed crl publication requires a checkpoint")
		}
		if err := i.SignedCheckpoint.Validate(); err != nil {
			return err
		}
		if i.SignedCheckpoint.SignatureAlgorithm != i.SignatureAlgorithm ||
			i.SignedCheckpoint.RecordedAt.Before(i.CreatedAt) ||
			i.UpdatedAt.Before(i.SignedCheckpoint.RecordedAt) {
			return errors.New("pki: crl signed checkpoint does not match its publication")
		}
	} else if i.SignedCheckpoint != nil {
		return errors.New("pki: unsigned crl publication cannot have a checkpoint")
	}
	return nil
}

func ValidateNewCRLPublicationIntent(intent CRLPublicationIntent) error {
	if intent.Status != CRLPublicationStatusPending || intent.Phase != CRLPublicationPhasePlanned ||
		intent.Number != 0 || intent.Revision != 1 || intent.SignedCheckpoint != nil ||
		intent.ResultCRLGenerationID != "" || intent.Failure != "" {
		return errors.New("pki: new crl publication must be an unnumbered pending plan")
	}
	validated := intent.Clone()
	validated.Number = 1
	return validated.Validate()
}

func ValidateCRLPublicationOwnership(intent CRLPublicationIntent, ownership CRLPublicationOwnership) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Status != CRLPublicationStatusPending || intent.OwnerToken != ownership.OwnerToken || intent.Revision != ownership.Revision {
		return errors.New("pki: crl publication ownership changed")
	}
	return nil
}

func StartCRLPublicationSigningIntent(intent CRLPublicationIntent, startedAt time.Time) (CRLPublicationIntent, error) {
	startedAt = startedAt.UTC().Truncate(time.Second)
	if intent.Status != CRLPublicationStatusPending || intent.Phase != CRLPublicationPhasePlanned ||
		intent.Number == 0 || startedAt.Before(intent.UpdatedAt) || !startedAt.Before(intent.NextUpdate) {
		return CRLPublicationIntent{}, errors.New("pki: crl publication cannot start signing")
	}
	if intent.Revision >= domainpki.MaximumSequenceNumber {
		return CRLPublicationIntent{}, errors.New("pki: crl publication revision is exhausted")
	}
	result := intent.Clone()
	result.Phase = CRLPublicationPhaseSigning
	result.Revision++
	result.UpdatedAt = startedAt
	result.LeaseExpiresAt = startedAt.Add(DefaultCRLLease)
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func RenewCRLPublicationLeaseIntent(intent CRLPublicationIntent, renewedAt time.Time) (CRLPublicationIntent, error) {
	renewedAt = renewedAt.UTC().Truncate(time.Second)
	if intent.Status != CRLPublicationStatusPending || intent.Phase == CRLPublicationPhasePlanned ||
		renewedAt.Before(intent.UpdatedAt) || !renewedAt.Before(intent.LeaseExpiresAt) {
		return CRLPublicationIntent{}, errors.New("pki: crl publication lease cannot be renewed")
	}
	if intent.Revision >= domainpki.MaximumSequenceNumber {
		return CRLPublicationIntent{}, errors.New("pki: crl publication revision is exhausted")
	}
	result := intent.Clone()
	result.Revision++
	result.UpdatedAt = renewedAt
	result.LeaseExpiresAt = renewedAt.Add(DefaultCRLLease)
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func CheckpointCRLPublicationSignedIntent(
	intent CRLPublicationIntent,
	checkpoint CRLSignedCheckpoint,
) (CRLPublicationIntent, error) {
	if intent.Status != CRLPublicationStatusPending || intent.Phase != CRLPublicationPhaseSigning ||
		intent.Number == 0 {
		return CRLPublicationIntent{}, errors.New("pki: crl publication cannot record a signed checkpoint")
	}
	if err := checkpoint.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	if checkpoint.SignatureAlgorithm != intent.SignatureAlgorithm {
		return CRLPublicationIntent{}, errors.New("pki: crl signed checkpoint does not match its publication")
	}
	if intent.Revision >= domainpki.MaximumSequenceNumber {
		return CRLPublicationIntent{}, errors.New("pki: crl publication revision is exhausted")
	}
	result := intent.Clone()
	result.Phase = CRLPublicationPhaseSigned
	result.Revision++
	result.UpdatedAt = maxTime(intent.UpdatedAt, checkpoint.RecordedAt)
	result.LeaseExpiresAt = result.UpdatedAt.Add(DefaultCRLLease)
	cloned := checkpoint.Clone()
	result.SignedCheckpoint = &cloned
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func ClaimCRLPublicationIntent(intent CRLPublicationIntent, ownerToken string, claimedAt time.Time) (CRLPublicationIntent, error) {
	claimedAt = claimedAt.UTC().Truncate(time.Second)
	if intent.Status != CRLPublicationStatusPending || claimedAt.Before(intent.LeaseExpiresAt) {
		return CRLPublicationIntent{}, errors.New("pki: crl publication is not eligible for stale reconciliation")
	}
	if !validIssuanceOwner(ownerToken) {
		return CRLPublicationIntent{}, errors.New("pki: crl publication reconciliation owner is invalid")
	}
	if intent.Revision >= domainpki.MaximumSequenceNumber {
		return CRLPublicationIntent{}, errors.New("pki: crl publication revision is exhausted")
	}
	result := intent.Clone()
	result.OwnerToken = ownerToken
	result.Revision++
	result.UpdatedAt = claimedAt
	result.LeaseExpiresAt = claimedAt.Add(DefaultCRLLease)
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func ValidateCRLRevocationSnapshot(intent CRLPublicationIntent, revocations []domainpki.Revocation) error {
	ids := make([]domainpki.RevocationID, 0, len(revocations))
	for _, revocation := range revocations {
		if err := revocation.Validate(); err != nil {
			return err
		}
		if revocation.IssuerAuthorityID == intent.AuthorityID &&
			revocation.IssuerGenerationID == intent.IssuerGenerationID &&
			!revocation.EffectiveAt.After(intent.ThisUpdate) {
			ids = append(ids, revocation.ID)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	if !slices.Equal(ids, intent.RevocationIDs) {
		return errors.New("pki: crl publication revocation snapshot changed")
	}
	return nil
}

func CompleteCRLPublicationIntent(intent CRLPublicationIntent, completedAt time.Time) (CRLPublicationIntent, error) {
	completedAt = completedAt.UTC().Truncate(time.Second)
	if intent.Status != CRLPublicationStatusPending || intent.Phase != CRLPublicationPhaseSigned ||
		intent.Number == 0 || completedAt.Before(intent.UpdatedAt) || !completedAt.Before(intent.NextUpdate) {
		return CRLPublicationIntent{}, errors.New("pki: only a fresh signed crl publication can complete")
	}
	result := intent.Clone()
	result.Status = CRLPublicationStatusCompleted
	result.ResultCRLGenerationID = result.CRLGenerationID
	result.UpdatedAt = completedAt
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func FailCRLPublicationIntent(intent CRLPublicationIntent, failure string, failedAt time.Time) (CRLPublicationIntent, error) {
	if intent.Status != CRLPublicationStatusPending || intent.Number == 0 {
		return CRLPublicationIntent{}, errors.New("pki: only a numbered pending crl publication can fail")
	}
	result := intent.Clone()
	result.Status = CRLPublicationStatusFailed
	result.Failure = strings.TrimSpace(failure)
	result.UpdatedAt = failedAt.UTC().Truncate(time.Second)
	if err := result.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	return result, nil
}

func ValidateCRLPublicationCompletion(intent CRLPublicationIntent, generation domainpki.CRLGeneration) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if intent.Phase != CRLPublicationPhaseSigned || intent.SignedCheckpoint == nil ||
		generation.ID != intent.CRLGenerationID || generation.AuthorityID != intent.AuthorityID ||
		generation.IssuerGenerationID != intent.IssuerGenerationID || generation.Number != intent.Number ||
		!generation.ThisUpdate.Equal(intent.ThisUpdate) || !generation.NextUpdate.Equal(intent.NextUpdate) ||
		!slices.Equal(generation.RevocationIDs, intent.RevocationIDs) ||
		generation.SigningBackendID != intent.SigningBackendID ||
		generation.SigningBackendVersion != intent.SigningBackendVersion ||
		generation.SigningBackendPackageDigest != intent.SigningBackendPackageDigest ||
		generation.SigningBackendCapabilityHash != intent.SigningBackendCapabilityHash ||
		generation.SignatureAlgorithm != intent.SignatureAlgorithm ||
		generation.FingerprintSHA256 != intent.SignedCheckpoint.FingerprintSHA256 ||
		!bytes.Equal(generation.CRLDER, intent.SignedCheckpoint.CRLDER) ||
		generation.CreatedAt.Before(intent.SignedCheckpoint.RecordedAt) || !generation.CreatedAt.Before(intent.NextUpdate) {
		return errors.New("pki: crl generation does not match its durable publication plan")
	}
	return nil
}

func ValidateCRLPublicationAudit(intent CRLPublicationIntent, generation domainpki.CRLGeneration, audit AuditRecord) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.Action != AuditActionCRLPublish || audit.Outcome != AuditOutcomeSucceeded ||
		audit.ResourceType != auditResourceCRL || audit.ResourceID != string(generation.ID) ||
		audit.CreatedAt.UTC().Truncate(time.Second).Before(generation.CreatedAt) ||
		!audit.CreatedAt.UTC().Truncate(time.Second).Before(intent.NextUpdate) {
		return errors.New("pki: crl publication audit does not identify the published generation")
	}
	expected := map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLRevocationCount:    strconv.Itoa(len(intent.RevocationIDs)),
		auditDetailCRLFingerprint:        generation.FingerprintSHA256,
		auditDetailCRLSignatureAlgorithm: string(generation.SignatureAlgorithm),
	}
	if !maps.Equal(audit.Details, expected) {
		return errors.New("pki: crl publication audit details do not match the result")
	}
	return nil
}

func ValidateCRLSigningAttemptAudit(intent CRLPublicationIntent, audit AuditRecord) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.Action != AuditActionSigningUse || audit.Outcome != AuditOutcomeAttempted ||
		audit.ResourceType != auditResourceAuthority || audit.ResourceID != string(intent.AuthorityID) ||
		audit.CreatedAt.Before(intent.UpdatedAt) || !audit.CreatedAt.Before(intent.NextUpdate) {
		return errors.New("pki: crl signing attempt audit does not identify the signing authority")
	}
	expected := map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(intent.SignatureAlgorithm),
	}
	if !maps.Equal(audit.Details, expected) {
		return errors.New("pki: crl signing attempt audit details do not match the durable plan")
	}
	return nil
}

func ValidateCRLSigningConfirmedAudit(intent CRLPublicationIntent, checkpoint CRLSignedCheckpoint, audit AuditRecord) error {
	if err := checkpoint.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.Action != AuditActionSigningUse || audit.Outcome != AuditOutcomeSucceeded ||
		audit.ResourceType != auditResourceAuthority || audit.ResourceID != string(intent.AuthorityID) ||
		!audit.CreatedAt.UTC().Truncate(time.Second).Equal(checkpoint.RecordedAt) {
		return errors.New("pki: crl signing confirmation audit does not identify the signing authority")
	}
	expected := map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(checkpoint.SignatureAlgorithm),
		auditDetailCRLFingerprint:        checkpoint.FingerprintSHA256,
	}
	if checkpoint.ProviderOperationRef != "" {
		expected[auditDetailProviderOperationRef] = string(checkpoint.ProviderOperationRef)
	}
	if !maps.Equal(audit.Details, expected) {
		return errors.New("pki: crl signing confirmation audit details do not match the checkpoint")
	}
	return nil
}

func ValidateCRLPublicationFailureAudit(intent CRLPublicationIntent, stage CRLPublicationFailureStage, audit AuditRecord) error {
	if err := stage.Validate(); err != nil {
		return err
	}
	if err := audit.Validate(); err != nil {
		return err
	}
	if audit.Action != AuditActionCRLPublish || audit.Outcome != AuditOutcomeFailed ||
		audit.ResourceType != auditResourceCRL || audit.ResourceID != string(intent.CRLGenerationID) {
		return errors.New("pki: crl publication failure audit does not identify the planned generation")
	}
	expected := map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(intent.SignatureAlgorithm),
		auditDetailCRLStage:              string(stage),
	}
	if !maps.Equal(audit.Details, expected) {
		return errors.New("pki: crl publication failure audit details do not match the durable plan")
	}
	return nil
}

func CRLPublicationIDFromAudit(audit AuditRecord) (domainpki.CRLPublicationID, error) {
	if err := audit.Validate(); err != nil {
		return "", err
	}
	if audit.Action != AuditActionCRLPublish && audit.Action != AuditActionSigningUse {
		return "", errors.New("pki: audit record is not associated with crl publication")
	}
	return domainpki.NewCRLPublicationID(audit.Details[auditDetailCRLPublicationID])
}

type PublishCRLRequest struct {
	IdempotencyKey     string                       `json:"idempotencyKey,omitempty"`
	AuthorityID        domainpki.AuthorityID        `json:"authorityId"`
	IssuerGenerationID domainpki.GenerationID       `json:"issuerGenerationId,omitempty"`
	ValiditySeconds    uint32                       `json:"validitySeconds,omitempty"`
	SignatureAlgorithm domainpki.SignatureAlgorithm `json:"signatureAlgorithm,omitempty"`
}

type ReconcileCRLPublicationRequest struct {
	PublicationID     domainpki.CRLPublicationID `json:"publicationId"`
	StaleAfterSeconds uint32                     `json:"staleAfterSeconds"`
}

type ReconcileCRLPublicationsRequest struct {
	StaleAfterSeconds uint32 `json:"staleAfterSeconds"`
	Limit             uint32 `json:"limit"`
}

func (s Service) ReconcileCRLPublication(
	ctx context.Context,
	request ReconcileCRLPublicationRequest,
) (CRLPublicationIntent, error) {
	return s.ReconcilePendingCRLPublication(ctx, request.PublicationID, time.Duration(request.StaleAfterSeconds)*time.Second)
}

func (s Service) ReconcileCRLPublications(
	ctx context.Context,
	request ReconcileCRLPublicationsRequest,
) ([]CRLPublicationIntent, error) {
	if request.Limit > uint32(MaximumPendingCRLPublicationBatch) {
		return nil, fmt.Errorf("pki: pending crl publication batch cannot exceed %d records", MaximumPendingCRLPublicationBatch)
	}
	return s.ReconcilePendingCRLPublications(ctx, time.Duration(request.StaleAfterSeconds)*time.Second, int(request.Limit))
}

type CRLPublicationResult struct {
	Publication CRLPublicationIntent    `json:"publication"`
	Generation  domainpki.CRLGeneration `json:"generation"`
}

func (r CRLPublicationResult) Clone() CRLPublicationResult {
	return CRLPublicationResult{Publication: r.Publication.Clone(), Generation: r.Generation.Clone()}
}

func (r CRLPublicationResult) Validate() error {
	if r.Publication.Status != CRLPublicationStatusCompleted || r.Publication.ResultCRLGenerationID != r.Generation.ID {
		return errors.New("pki: crl publication result is incomplete")
	}
	return ValidateCRLPublicationCompletion(r.Publication, r.Generation)
}

func (s Service) InspectCRLPublication(ctx context.Context, id domainpki.CRLPublicationID) (CRLPublicationIntent, error) {
	if err := id.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	intent, err := s.persistence.CRLPublication(ctx, id)
	if err != nil {
		return CRLPublicationIntent{}, err
	}
	if err := intent.Validate(); err != nil {
		return CRLPublicationIntent{}, fmt.Errorf("pki: validate inspected crl publication: %w", err)
	}
	return intent.Clone(), nil
}

func (s Service) ListCRLPublications(ctx context.Context, id domainpki.AuthorityID) ([]CRLPublicationIntent, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	intents, err := s.persistence.CRLPublications(ctx, id)
	if err != nil {
		return nil, err
	}
	result := make([]CRLPublicationIntent, len(intents))
	for index, intent := range intents {
		if err := intent.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed crl publication: %w", err)
		}
		if intent.AuthorityID != id {
			return nil, errors.New("pki: listed crl publication belongs to another authority")
		}
		if index > 0 && (intents[index-1].Number > intent.Number ||
			intents[index-1].Number == intent.Number && intents[index-1].ID >= intent.ID) {
			return nil, errors.New("pki: crl publications are not sorted by number and id")
		}
		result[index] = intent.Clone()
	}
	return result, nil
}

func (s Service) InspectCRLGeneration(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	if err := id.Validate(); err != nil {
		return domainpki.CRLGeneration{}, err
	}
	generation, err := s.persistence.CRLGeneration(ctx, id)
	if err != nil {
		return domainpki.CRLGeneration{}, err
	}
	if err := generation.Validate(); err != nil {
		return domainpki.CRLGeneration{}, fmt.Errorf("pki: validate inspected crl generation: %w", err)
	}
	return generation.Clone(), nil
}

func (s Service) ListCRLGenerations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	generations, err := s.persistence.CRLGenerations(ctx, id)
	if err != nil {
		return nil, err
	}
	result := make([]domainpki.CRLGeneration, len(generations))
	for index, generation := range generations {
		if err := generation.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate listed crl generation: %w", err)
		}
		if generation.AuthorityID != id {
			return nil, errors.New("pki: listed crl generation belongs to another authority")
		}
		if index > 0 && (generations[index-1].Number > generation.Number ||
			generations[index-1].Number == generation.Number && generations[index-1].ID >= generation.ID) {
			return nil, errors.New("pki: crl generations are not sorted by number and id")
		}
		result[index] = generation.Clone()
	}
	return result, nil
}

func (s Service) ReconcilePendingCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	staleAfter time.Duration,
) (CRLPublicationIntent, error) {
	if err := id.Validate(); err != nil {
		return CRLPublicationIntent{}, err
	}
	if staleAfter < minimumIssuanceReconcileAge || staleAfter > maximumIssuanceReconcileAge {
		return CRLPublicationIntent{}, fmt.Errorf("pki: crl publication reconciliation age must be between %s and %s", minimumIssuanceReconcileAge, maximumIssuanceReconcileAge)
	}
	intent, err := s.persistence.CRLPublication(ctx, id)
	if err != nil {
		return CRLPublicationIntent{}, err
	}
	if intent.Status != CRLPublicationStatusPending {
		return intent.Clone(), nil
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	if now.Sub(intent.UpdatedAt) < staleAfter || now.Before(intent.LeaseExpiresAt) {
		return CRLPublicationIntent{}, ErrCRLPublicationInProgress
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return CRLPublicationIntent{}, err
	}
	if err := s.crlReconciler.AuthorizeCRLPublicationReconciliation(ctx, auditContext); err != nil {
		return CRLPublicationIntent{}, fmt.Errorf("pki: authorize crl publication reconciliation: %w", err)
	}
	claimed, ok, err := s.claimCRLPublicationForReconciliation(ctx, intent, now)
	if err != nil {
		return CRLPublicationIntent{}, err
	}
	if !ok {
		return CRLPublicationIntent{}, ErrCRLPublicationInProgress
	}
	return s.reconcileClaimedCRLPublication(ctx, claimed, auditContext)
}

func (s Service) ReconcilePendingCRLPublications(
	ctx context.Context,
	staleAfter time.Duration,
	limit int,
) ([]CRLPublicationIntent, error) {
	if staleAfter < minimumIssuanceReconcileAge || staleAfter > maximumIssuanceReconcileAge {
		return nil, fmt.Errorf("pki: crl publication reconciliation age must be between %s and %s", minimumIssuanceReconcileAge, maximumIssuanceReconcileAge)
	}
	if limit < 1 || limit > MaximumPendingCRLPublicationBatch {
		return nil, fmt.Errorf("pki: pending crl publication batch must contain between 1 and %d records", MaximumPendingCRLPublicationBatch)
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.crlReconciler.AuthorizeCRLPublicationReconciliation(ctx, auditContext); err != nil {
		return nil, fmt.Errorf("pki: authorize crl publication reconciliation: %w", err)
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	pending, err := s.persistence.PendingCRLPublications(ctx, now, now.Add(-staleAfter), limit)
	if err != nil {
		return nil, err
	}
	result := make([]CRLPublicationIntent, 0, len(pending))
	for _, intent := range pending {
		claimed, ok, claimErr := s.claimCRLPublicationForReconciliation(ctx, intent, now)
		if claimErr != nil {
			return nil, claimErr
		}
		if !ok {
			continue
		}
		reconciled, reconcileErr := s.reconcileClaimedCRLPublication(ctx, claimed, auditContext)
		if reconcileErr != nil {
			return nil, reconcileErr
		}
		result = append(result, reconciled.Clone())
	}
	return result, nil
}

func (s Service) claimCRLPublicationForReconciliation(
	ctx context.Context,
	intent CRLPublicationIntent,
	now time.Time,
) (CRLPublicationIntent, bool, error) {
	ownerToken, err := s.randomID("crl-reconciler")
	if err != nil {
		return CRLPublicationIntent{}, false, err
	}
	return s.persistence.ClaimCRLPublication(ctx, intent.ID, intent.Ownership(), ownerToken, now)
}

func (s Service) reconcileClaimedCRLPublication(
	ctx context.Context,
	intent CRLPublicationIntent,
	auditContext AuditContext,
) (CRLPublicationIntent, error) {
	if intent.Phase != CRLPublicationPhaseSigned {
		if err := s.recordCRLPublicationFailure(
			ctx, intent, auditContext, CRLPublicationFailureStageReconciliation,
		); err != nil {
			return CRLPublicationIntent{}, err
		}
		return s.persistence.CRLPublication(ctx, intent.ID)
	}
	validator, request, err := s.resolveCRLCheckpointValidation(ctx, intent)
	if err != nil {
		if isRetryableCRLError(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return CRLPublicationIntent{}, err
		}
		if failErr := s.recordCRLPublicationFailure(
			ctx, intent, auditContext, CRLPublicationFailureStageValidation,
		); failErr != nil {
			return CRLPublicationIntent{}, errors.Join(err, failErr)
		}
		return s.persistence.CRLPublication(ctx, intent.ID)
	}
	result, latestIntent, stage, err := s.completeSignedCRLPublication(
		ctx, intent, auditContext, validator, request,
	)
	if err == nil {
		return result.Publication.Clone(), nil
	}
	if isRetryableCRLError(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return CRLPublicationIntent{}, err
	}
	if failErr := s.recordCRLPublicationFailure(ctx, latestIntent, auditContext, stage); failErr != nil {
		return CRLPublicationIntent{}, errors.Join(err, failErr)
	}
	return s.persistence.CRLPublication(ctx, intent.ID)
}

func (s Service) resolveCRLCheckpointValidation(
	ctx context.Context,
	intent CRLPublicationIntent,
) (CRLValidator, CRLValidationRequest, error) {
	issuer, err := s.persistence.Generation(ctx, intent.IssuerGenerationID)
	if err != nil {
		return nil, CRLValidationRequest{}, retryableCRLError(err)
	}
	if err := issuer.Validate(); err != nil {
		return nil, CRLValidationRequest{}, err
	}
	if issuer.ID != intent.IssuerGenerationID || issuer.OwningAuthorityID != intent.AuthorityID ||
		issuer.Template.KeyUsage&domainpki.KeyUsageCRLSign == 0 ||
		!intent.SignatureAlgorithm.CompatibleWith(issuer.Template.Key.Algorithm) {
		return nil, CRLValidationRequest{}, errors.New("pki: signed crl checkpoint issuer does not match its plan")
	}
	backend, err := s.backends.ResolveBackend(ctx, intent.SigningBackendID)
	if err != nil {
		return nil, CRLValidationRequest{}, retryableCRLError(err)
	}
	descriptor := backend.Descriptor()
	if err := validateBackendCommitment(
		"crl validation", descriptor, intent.SigningBackendID, intent.SigningBackendVersion,
		intent.SigningBackendPackageDigest, intent.SigningBackendCapabilityHash,
	); err != nil {
		return nil, CRLValidationRequest{}, err
	}
	if !descriptor.SupportsCRL || !descriptor.SupportsSignature(intent.SignatureAlgorithm) {
		return nil, CRLValidationRequest{}, errors.New("pki: committed backend no longer supports crl validation")
	}
	validatorBackend, err := s.validators.ResolveValidator(ctx, intent.SigningBackendID)
	if err != nil {
		return nil, CRLValidationRequest{}, retryableCRLError(err)
	}
	validator, ok := validatorBackend.(CRLValidator)
	if !ok {
		return nil, CRLValidationRequest{}, errors.New("pki: committed backend has no crl validator")
	}
	revocations, err := s.persistence.Revocations(ctx, intent.AuthorityID)
	if err != nil {
		return nil, CRLValidationRequest{}, retryableCRLError(err)
	}
	entries, err := crlEntries(intent, revocations)
	if err != nil {
		return nil, CRLValidationRequest{}, err
	}
	request := CRLValidationRequest{
		Number: intent.Number, ThisUpdate: intent.ThisUpdate, NextUpdate: intent.NextUpdate,
		Entries: entries, SignatureAlgorithm: intent.SignatureAlgorithm,
		IssuerCertificateDER: issuer.CertificateDER,
	}
	if err := request.Validate(); err != nil {
		return nil, CRLValidationRequest{}, err
	}
	return validator, request.Clone(), nil
}

type crlPublicationLease struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	intent CRLPublicationIntent
	err    error
}

func (s Service) startCRLPublicationLease(
	ctx context.Context,
	cancelProvider context.CancelFunc,
	intent CRLPublicationIntent,
) *crlPublicationLease {
	heartbeatContext, cancelHeartbeat := context.WithCancel(ctx)
	lease := &crlPublicationLease{
		cancel: cancelHeartbeat,
		done:   make(chan struct{}),
		intent: intent.Clone(),
	}
	go func() {
		defer close(lease.done)
		ticker := time.NewTicker(crlLeaseRenewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatContext.Done():
				return
			case <-ticker.C:
				lease.mu.Lock()
				current := lease.intent.Clone()
				lease.mu.Unlock()
				renewalContext, cancelRenewal, budgetErr := s.crlOwnedTransitionContext(
					heartbeatContext, current,
				)
				if budgetErr != nil {
					lease.mu.Lock()
					lease.err = fmt.Errorf("pki: crl publication heartbeat lost its lease budget: %w", budgetErr)
					lease.mu.Unlock()
					cancelProvider()
					return
				}
				renewed, err := s.persistence.RenewCRLPublicationLease(
					renewalContext,
					current.ID,
					current.Ownership(),
					s.clock.Now().UTC().Truncate(time.Second),
				)
				cancelRenewal()
				if err != nil {
					if heartbeatContext.Err() != nil {
						return
					}
					lease.mu.Lock()
					lease.err = fmt.Errorf("pki: renew crl publication lease: %w", err)
					lease.mu.Unlock()
					cancelProvider()
					return
				}
				lease.mu.Lock()
				lease.intent = renewed.Clone()
				lease.mu.Unlock()
			}
		}
	}()
	return lease
}

func (l *crlPublicationLease) Stop() (CRLPublicationIntent, error) {
	l.cancel()
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.intent.Clone(), l.err
}

type crlLeaseResolutionPolicy uint8

const (
	crlLeaseResolutionBounded crlLeaseResolutionPolicy = iota + 1
	crlLeaseResolutionUntilOwnershipChanges
)

func crlLeaseResolutionExhausted(policy crlLeaseResolutionPolicy, attempts int) bool {
	return policy == crlLeaseResolutionBounded && attempts >= crlTransitionAttempts
}

func waitForCRLTransitionRetry() {
	timer := time.NewTimer(crlTransitionRetryDelay)
	defer timer.Stop()
	<-timer.C
}

func crlTransitionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), crlTransitionTimeout)
}

func (s Service) crlOwnedTransitionContext(
	ctx context.Context,
	intent CRLPublicationIntent,
) (context.Context, context.CancelFunc, error) {
	remaining := intent.LeaseExpiresAt.Sub(s.clock.Now().UTC().Truncate(time.Second)) - crlLeaseSafetyMargin
	if remaining <= 0 {
		return nil, nil, errors.New("pki: crl publication lease has no transition budget")
	}
	if remaining > crlTransitionTimeout {
		remaining = crlTransitionTimeout
	}
	transitionContext, cancelTransition := context.WithTimeout(context.WithoutCancel(ctx), remaining)
	return transitionContext, cancelTransition, nil
}

// stopAndFenceCRLPublicationLease closes the heartbeat and then renews the
// latest ownership revision synchronously. The returned lease remains valid
// through the caller's immediately following atomic state transition.
func (s Service) stopAndFenceCRLPublicationLease(
	ctx context.Context,
	lease *crlPublicationLease,
	policy crlLeaseResolutionPolicy,
) (CRLPublicationIntent, error) {
	intent, leaseErr := lease.Stop()
	if leaseErr != nil {
		var resolutionErr error
	resolveHeartbeat:
		for attempts := 0; ; attempts++ {
			resolutionContext, cancelResolution := crlTransitionContext(ctx)
			persisted, loadErr := s.persistence.CRLPublication(resolutionContext, intent.ID)
			cancelResolution()
			if loadErr == nil {
				switch {
				case crlPublicationIntentsEqual(persisted, intent):
				case isExactCRLLeaseRenewal(intent, persisted):
					intent = persisted.Clone()
				default:
					return intent, retryableCRLError(errors.Join(
						leaseErr,
						errors.New("pki: crl publication ownership changed after an uncertain heartbeat renewal"),
					))
				}
				break resolveHeartbeat
			}
			resolutionErr = loadErr
			if crlLeaseResolutionExhausted(policy, attempts+1) {
				return intent, retryableCRLError(errors.Join(leaseErr, resolutionErr))
			}
			waitForCRLTransitionRetry()
		}
	}
	return s.fenceCRLPublicationOwnership(ctx, intent, policy)
}

func (s Service) fenceCRLPublicationOwnership(
	ctx context.Context,
	intent CRLPublicationIntent,
	policy crlLeaseResolutionPolicy,
) (CRLPublicationIntent, error) {
	var fenceErr error
	for attempts := 0; ; attempts++ {
		fenceContext, cancelFence, budgetErr := s.crlOwnedTransitionContext(ctx, intent)
		if budgetErr != nil {
			if policy == crlLeaseResolutionBounded {
				return intent, retryableCRLError(budgetErr)
			}
			return s.reacquireCRLPublicationOwnership(ctx, intent)
		}
		renewed, err := s.persistence.RenewCRLPublicationLease(
			fenceContext,
			intent.ID,
			intent.Ownership(),
			s.clock.Now().UTC().Truncate(time.Second),
		)
		cancelFence()
		if err == nil {
			if !isExactCRLLeaseRenewal(intent, renewed) {
				return intent, retryableCRLError(errors.New("pki: crl lease fence returned an invalid transition"))
			}
			return renewed.Clone(), nil
		}
		fenceErr = err
		loadContext, cancelLoad := crlTransitionContext(ctx)
		persisted, loadErr := s.persistence.CRLPublication(loadContext, intent.ID)
		cancelLoad()
		if loadErr != nil {
			fenceErr = errors.Join(err, loadErr)
		} else if isExactCRLLeaseRenewal(intent, persisted) {
			return persisted.Clone(), nil
		} else if !crlPublicationIntentsEqual(persisted, intent) {
			return intent, retryableCRLError(errors.Join(
				fenceErr,
				errors.New("pki: crl publication ownership changed while fencing its lease"),
			))
		}
		if crlLeaseResolutionExhausted(policy, attempts+1) {
			return intent, retryableCRLError(fmt.Errorf(
				"pki: fence crl publication lease after %d attempts: %w",
				attempts+1,
				fenceErr,
			))
		}
		waitForCRLTransitionRetry()
	}
}

func (s Service) reacquireCRLPublicationOwnership(
	ctx context.Context,
	intent CRLPublicationIntent,
) (CRLPublicationIntent, error) {
	var expectedClaim *CRLPublicationIntent
	for {
		loadContext, cancelLoad := crlTransitionContext(ctx)
		persisted, loadErr := s.persistence.CRLPublication(loadContext, intent.ID)
		cancelLoad()
		if loadErr != nil {
			waitForCRLTransitionRetry()
			continue
		}
		if expectedClaim != nil && crlPublicationIntentsEqual(persisted, *expectedClaim) {
			return persisted.Clone(), nil
		}
		if !crlPublicationIntentsEqual(persisted, intent) {
			return intent, retryableCRLError(
				errors.New("pki: crl publication ownership changed before lease reacquisition"),
			)
		}
		if expectedClaim == nil {
			now := s.clock.Now().UTC().Truncate(time.Second)
			if now.Before(intent.LeaseExpiresAt) {
				waitForCRLTransitionRetry()
				continue
			}
			ownerToken, err := s.randomID("crl-checkpoint")
			if err != nil {
				waitForCRLTransitionRetry()
				continue
			}
			expected, err := ClaimCRLPublicationIntent(intent, ownerToken, now)
			if err != nil {
				return intent, err
			}
			expectedClaim = &expected
		}
		claimContext, cancelClaim := crlTransitionContext(ctx)
		claimed, ok, claimErr := s.persistence.ClaimCRLPublication(
			claimContext,
			intent.ID,
			intent.Ownership(),
			expectedClaim.OwnerToken,
			expectedClaim.UpdatedAt,
		)
		cancelClaim()
		if claimErr == nil && ok && crlPublicationIntentsEqual(claimed, *expectedClaim) {
			return claimed.Clone(), nil
		}
		loadContext, cancelLoad = crlTransitionContext(ctx)
		persisted, loadErr = s.persistence.CRLPublication(loadContext, intent.ID)
		cancelLoad()
		if loadErr != nil {
			waitForCRLTransitionRetry()
			continue
		}
		if crlPublicationIntentsEqual(persisted, *expectedClaim) {
			return persisted.Clone(), nil
		}
		if !crlPublicationIntentsEqual(persisted, intent) {
			return intent, retryableCRLError(
				errors.New("pki: crl publication ownership changed during lease reacquisition"),
			)
		}
		waitForCRLTransitionRetry()
	}
}

func (s Service) checkpointSignedCRLPublication(
	ctx context.Context,
	intent CRLPublicationIntent,
	checkpoint CRLSignedCheckpoint,
	audit AuditRecord,
) (CRLPublicationIntent, error) {
	var checkpointErr error
	for {
		expected, err := CheckpointCRLPublicationSignedIntent(intent, checkpoint)
		if err != nil {
			return intent, err
		}
		checkpointContext, cancelCheckpoint, budgetErr := s.crlOwnedTransitionContext(ctx, intent)
		if budgetErr != nil {
			intent, err = s.fenceCRLPublicationOwnership(
				ctx, intent, crlLeaseResolutionUntilOwnershipChanges,
			)
			if err != nil {
				return intent, err
			}
			continue
		}
		persisted, err := s.persistence.CheckpointCRLPublicationSigned(
			checkpointContext, intent.ID, intent.Ownership(), checkpoint, audit,
		)
		cancelCheckpoint()
		if err == nil {
			if !crlPublicationIntentsEqual(persisted, expected) {
				return intent, retryableCRLError(errors.New("pki: crl checkpoint returned an invalid transition"))
			}
			return persisted.Clone(), nil
		}
		checkpointErr = err
		loadContext, cancelLoad := crlTransitionContext(ctx)
		persisted, loadErr := s.persistence.CRLPublication(loadContext, intent.ID)
		cancelLoad()
		if loadErr == nil && crlPublicationIntentsEqual(persisted, expected) {
			return persisted.Clone(), nil
		}
		if loadErr != nil {
			checkpointErr = errors.Join(err, loadErr)
		} else if !crlPublicationIntentsEqual(persisted, intent) {
			return intent, retryableCRLError(errors.Join(
				checkpointErr,
				errors.New("pki: crl publication ownership changed while checkpointing signed output"),
			))
		}
		intent, err = s.fenceCRLPublicationOwnership(
			ctx, intent, crlLeaseResolutionUntilOwnershipChanges,
		)
		if err != nil {
			return intent, retryableCRLError(errors.Join(checkpointErr, err))
		}
		waitForCRLTransitionRetry()
	}
}

func (s Service) PublishCRL(ctx context.Context, request PublishCRLRequest) (_ CRLPublicationResult, resultErr error) {
	if err := request.AuthorityID.Validate(); err != nil {
		return CRLPublicationResult{}, err
	}
	if request.SignatureAlgorithm != "" && request.SignatureAlgorithm != domainpki.SignatureAlgorithmAuto {
		if err := request.SignatureAlgorithm.Validate(); err != nil {
			return CRLPublicationResult{}, err
		}
	}
	validity := DefaultCRLValidity
	if request.ValiditySeconds != 0 {
		validity = time.Duration(request.ValiditySeconds) * time.Second
	}
	if validity < domainpki.MinimumCRLValidity || validity > domainpki.MaximumCRLValidity {
		return CRLPublicationResult{}, errors.New("pki: crl validity is outside the supported range")
	}
	normalized := request
	normalized.IdempotencyKey = ""
	normalized.ValiditySeconds = uint32(validity / time.Second)
	if normalized.SignatureAlgorithm == "" {
		normalized.SignatureAlgorithm = domainpki.SignatureAlgorithmAuto
	}
	auditContext, err := s.resolveAuditContext(ctx)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	digest, err := requestDigest(normalized)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	idempotencyKey, err := resolveIdempotencyKey(request.IdempotencyKey, "crl-publish", digest, auditContext)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	intent, exists, err := s.crlPublicationByKey(ctx, idempotencyKey, digest)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	if exists && intent.Status == CRLPublicationStatusCompleted {
		return s.completedCRLPublication(ctx, intent)
	}
	if exists && intent.Status == CRLPublicationStatusFailed {
		return CRLPublicationResult{}, fmt.Errorf("pki: persisted crl publication failed: %s", intent.Failure)
	}
	if exists {
		return CRLPublicationResult{}, ErrCRLPublicationInProgress
	}

	authority, issuer, signer, err := s.signer(ctx, request.AuthorityID)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	defer clear(signer.PrivateKeyPKCS8)
	if request.IssuerGenerationID != "" && request.IssuerGenerationID != issuer.ID {
		return CRLPublicationResult{}, errors.New("pki: requested crl issuer is not the authority active generation")
	}
	if issuer.Template.KeyUsage&domainpki.KeyUsageCRLSign == 0 {
		return CRLPublicationResult{}, errors.New("pki: authority generation is not authorized for crl signing")
	}
	signatureAlgorithm := request.SignatureAlgorithm
	if signatureAlgorithm == "" || signatureAlgorithm == domainpki.SignatureAlgorithmAuto {
		signatureAlgorithm, err = domainpki.DefaultSignatureAlgorithm(issuer.Template.Key)
		if err != nil {
			return CRLPublicationResult{}, err
		}
	}
	if !signatureAlgorithm.CompatibleWith(signer.Algorithm) {
		return CRLPublicationResult{}, errors.New("pki: crl signature algorithm is incompatible with the authority key")
	}
	backend, validator, descriptor, err := s.resolveSigningBackend(ctx, issuer, signer)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	issuerCapability, ok := backend.(CRLIssuer)
	if !descriptor.SupportsCRL || !ok {
		return CRLPublicationResult{}, errors.New("pki: selected signing backend does not support crl issuance")
	}
	if !descriptor.SupportsSignature(signatureAlgorithm) {
		return CRLPublicationResult{}, errors.New("pki: selected signing backend does not support the crl signature algorithm")
	}
	validatorCapability, ok := validator.(CRLValidator)
	if !ok {
		return CRLPublicationResult{}, errors.New("pki: selected signing validator does not support crl validation")
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	revocations, listErr := s.persistence.Revocations(ctx, authority.ID)
	if listErr != nil {
		return CRLPublicationResult{}, listErr
	}
	revocationIDs := make([]domainpki.RevocationID, 0, len(revocations))
	for _, revocation := range revocations {
		if revocation.IssuerGenerationID == issuer.ID && !revocation.EffectiveAt.After(now) {
			revocationIDs = append(revocationIDs, revocation.ID)
		}
	}
	sort.Slice(revocationIDs, func(left, right int) bool { return revocationIDs[left] < revocationIDs[right] })
	publicationID, idErr := s.newCRLPublicationID("crl-publication")
	if idErr != nil {
		return CRLPublicationResult{}, idErr
	}
	generationID, idErr := s.newCRLGenerationID("crl")
	if idErr != nil {
		return CRLPublicationResult{}, idErr
	}
	ownerToken, idErr := s.randomID("worker")
	if idErr != nil {
		return CRLPublicationResult{}, idErr
	}
	candidate := CRLPublicationIntent{
		ID: publicationID, IdempotencyKey: idempotencyKey, RequestSHA256: digest,
		CRLGenerationID: generationID, AuthorityID: authority.ID, IssuerGenerationID: issuer.ID,
		ThisUpdate: now, NextUpdate: now.Add(validity), RevocationIDs: revocationIDs,
		SigningBackendID: descriptor.ID, SigningBackendVersion: descriptor.Version,
		SigningBackendPackageDigest: descriptor.PackageDigest, SigningBackendCapabilityHash: descriptor.CapabilityHash,
		SignatureAlgorithm: signatureAlgorithm,
		Status:             CRLPublicationStatusPending, Phase: CRLPublicationPhasePlanned,
		OwnerToken: ownerToken, Revision: 1,
		LeaseExpiresAt: now.Add(DefaultCRLLease), CreatedAt: now, UpdatedAt: now,
	}
	intent, created, err := s.persistence.BeginCRLPublication(ctx, candidate, revocations)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	if intent.IdempotencyKey != idempotencyKey || intent.RequestSHA256 != digest {
		return CRLPublicationResult{}, ErrIdempotencyConflict
	}
	if !created {
		switch intent.Status {
		case CRLPublicationStatusCompleted:
			return s.completedCRLPublication(ctx, intent)
		case CRLPublicationStatusFailed:
			return CRLPublicationResult{}, fmt.Errorf("pki: persisted crl publication failed: %s", intent.Failure)
		default:
			return CRLPublicationResult{}, ErrCRLPublicationInProgress
		}
	}
	if intent.Status != CRLPublicationStatusPending {
		return CRLPublicationResult{}, ErrCRLPublicationInProgress
	}
	failureStage := CRLPublicationFailureStageConstruction
	publicationCompleted := false
	retainSignedForReconciliation := false
	defer func() {
		retryable := isRetryableCRLError(resultErr) || errors.Is(resultErr, context.Canceled) ||
			errors.Is(resultErr, context.DeadlineExceeded)
		if resultErr != nil && !publicationCompleted && !retainSignedForReconciliation && !retryable {
			resultErr = s.failCRLPublication(context.WithoutCancel(ctx), intent, auditContext, failureStage, resultErr)
		}
	}()
	if issuer.ID != intent.IssuerGenerationID || authority.ID != intent.AuthorityID ||
		signatureAlgorithm != intent.SignatureAlgorithm {
		return CRLPublicationResult{}, errors.New("pki: active signer does not match the durable crl publication plan")
	}
	if err := validateBackendCommitment("crl signing", descriptor, intent.SigningBackendID, intent.SigningBackendVersion, intent.SigningBackendPackageDigest, intent.SigningBackendCapabilityHash); err != nil {
		return CRLPublicationResult{}, err
	}
	if current := s.clock.Now().UTC().Truncate(time.Second); !current.Before(intent.NextUpdate) {
		failureStage = CRLPublicationFailureStageExpired
		return CRLPublicationResult{}, errors.New("pki: crl publication plan expired before signing")
	}
	revocations, err = s.persistence.Revocations(ctx, intent.AuthorityID)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	entries, err := crlEntries(intent, revocations)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	issueRequest := CRLIssueRequest{
		Number: intent.Number, ThisUpdate: intent.ThisUpdate, NextUpdate: intent.NextUpdate,
		Entries: entries, SignatureAlgorithm: intent.SignatureAlgorithm,
		IssuerCertificateDER: issuer.CertificateDER, Signer: signer,
	}
	defer clear(issueRequest.Signer.PrivateKeyPKCS8)
	signingAttempt, err := s.newCRLSigningAttemptAudit(auditContext, intent)
	if err != nil {
		failureStage = CRLPublicationFailureStageCompletion
		return CRLPublicationResult{}, err
	}
	intent, err = s.persistence.StartCRLPublicationSigning(
		ctx,
		intent.ID,
		intent.Ownership(),
		signingAttempt.CreatedAt.UTC().Truncate(time.Second),
		signingAttempt,
	)
	if err != nil {
		failureStage = CRLPublicationFailureStageCompletion
		return CRLPublicationResult{}, fmt.Errorf("pki: start durable crl signing: %w", err)
	}
	signingConfirmationAuditID, err := s.randomID("audit")
	if err != nil {
		failureStage = CRLPublicationFailureStageCompletion
		return CRLPublicationResult{}, fmt.Errorf("pki: reserve crl signing confirmation audit id: %w", err)
	}
	failureStage = CRLPublicationFailureStageProvider
	providerContext, cancelProvider := context.WithTimeout(ctx, DefaultCRLLease)
	defer cancelProvider()
	providerLease := s.startCRLPublicationLease(providerContext, cancelProvider, intent)
	providerRequest := issueRequest.Clone()
	defer clear(providerRequest.Signer.PrivateKeyPKCS8)
	providerResult, err := issuerCapability.IssueCRL(providerContext, providerRequest)
	if err != nil {
		var leaseErr error
		intent, leaseErr = providerLease.Stop()
		cancelProvider()
		return CRLPublicationResult{}, errors.Join(err, leaseErr)
	}
	issued := providerResult.Clone()
	intent, leaseErr := s.stopAndFenceCRLPublicationLease(
		ctx, providerLease, crlLeaseResolutionUntilOwnershipChanges,
	)
	cancelProvider()
	if leaseErr != nil {
		return CRLPublicationResult{}, leaseErr
	}
	failureStage = CRLPublicationFailureStageValidation
	if err := issued.Validate(); err != nil {
		return CRLPublicationResult{}, fmt.Errorf("pki: validate backend crl result: %w", err)
	}
	checkpoint, signingConfirmed, err := s.newCRLSigningConfirmed(
		auditContext, signingConfirmationAuditID, intent, issued,
	)
	if err != nil {
		failureStage = CRLPublicationFailureStageCompletion
		return CRLPublicationResult{}, err
	}
	intent, err = s.checkpointSignedCRLPublication(
		context.WithoutCancel(ctx), intent, checkpoint, signingConfirmed,
	)
	if err != nil {
		failureStage = CRLPublicationFailureStageCompletion
		return CRLPublicationResult{}, err
	}
	result, latestIntent, stage, err := s.completeSignedCRLPublication(
		ctx, intent, auditContext, validatorCapability, issueRequest.ValidationRequest(),
	)
	intent = latestIntent
	failureStage = stage
	if err != nil {
		retainSignedForReconciliation = isRetryableCRLError(err) || errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded)
		return CRLPublicationResult{}, err
	}
	publicationCompleted = true
	return result, nil
}

func (s Service) completeSignedCRLPublication(
	ctx context.Context,
	intent CRLPublicationIntent,
	auditContext AuditContext,
	validator CRLValidator,
	validationRequest CRLValidationRequest,
) (CRLPublicationResult, CRLPublicationIntent, CRLPublicationFailureStage, error) {
	stage := CRLPublicationFailureStageValidation
	if intent.Status != CRLPublicationStatusPending || intent.Phase != CRLPublicationPhaseSigned ||
		intent.SignedCheckpoint == nil {
		return CRLPublicationResult{}, intent, stage, errors.New("pki: crl publication has no signed checkpoint")
	}
	checkpoint := intent.SignedCheckpoint.Clone()
	if current := s.clock.Now().UTC().Truncate(time.Second); !current.Before(intent.NextUpdate) {
		return CRLPublicationResult{}, intent, CRLPublicationFailureStageExpired,
			errors.New("pki: signed crl publication expired before validation")
	}
	validationContext, cancelValidation := context.WithTimeout(ctx, DefaultCRLLease)
	defer cancelValidation()
	validationLease := s.startCRLPublicationLease(validationContext, cancelValidation, intent)
	validationResult, validationErr := validator.ValidateCRL(
		validationContext,
		validationRequest.Clone(),
		append([]byte(nil), checkpoint.CRLDER...),
	)
	latestIntent, leaseErr := s.stopAndFenceCRLPublicationLease(
		ctx, validationLease, crlLeaseResolutionBounded,
	)
	cancelValidation()
	if leaseErr != nil {
		return CRLPublicationResult{}, latestIntent, stage, leaseErr
	}
	if validationErr != nil {
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(
			fmt.Errorf("pki: backend crl validation failed: %w", validationErr),
		)
	}
	validationResult = validationResult.Clone()
	if err := validationResult.Validate(); err != nil {
		return CRLPublicationResult{}, latestIntent, stage,
			retryableCRLError(fmt.Errorf("pki: validate independent crl result: %w", err))
	}
	if validationResult.Decision == CRLValidationDecisionRejected {
		return CRLPublicationResult{}, latestIntent, stage, fmt.Errorf(
			"pki: independent crl validation rejected the checkpoint (%s): %s",
			validationResult.Rejection.Code,
			validationResult.Rejection.Message,
		)
	}
	if validationResult.Accepted == nil {
		return CRLPublicationResult{}, latestIntent, stage,
			retryableCRLError(errors.New("pki: accepted crl validation result is missing"))
	}
	validated := validationResult.Accepted.Clone()
	if checkpoint.FingerprintSHA256 != validated.FingerprintSHA256 ||
		checkpoint.SignatureAlgorithm != validated.SignatureAlgorithm ||
		!bytes.Equal(checkpoint.CRLDER, validated.CRLDER) {
		return CRLPublicationResult{}, latestIntent, stage,
			errors.New("pki: signed checkpoint and validator crl results differ")
	}
	latestIntent, leaseErr = s.fenceCRLPublicationOwnership(
		ctx, latestIntent, crlLeaseResolutionBounded,
	)
	if leaseErr != nil {
		return CRLPublicationResult{}, latestIntent, stage, leaseErr
	}
	stage = CRLPublicationFailureStageConstruction
	createdAt := s.clock.Now().UTC().Truncate(time.Second)
	if !createdAt.Before(latestIntent.NextUpdate) {
		return CRLPublicationResult{}, latestIntent, CRLPublicationFailureStageExpired,
			errors.New("pki: signed crl publication expired before completion")
	}
	generation, err := domainpki.NewCRLGeneration(domainpki.CRLGenerationArgs{
		ID: latestIntent.CRLGenerationID, AuthorityID: latestIntent.AuthorityID,
		IssuerGenerationID: latestIntent.IssuerGenerationID, Number: latestIntent.Number,
		ThisUpdate: latestIntent.ThisUpdate, NextUpdate: latestIntent.NextUpdate,
		RevocationIDs: latestIntent.RevocationIDs, SigningBackendID: latestIntent.SigningBackendID,
		SigningBackendVersion:        latestIntent.SigningBackendVersion,
		SigningBackendPackageDigest:  latestIntent.SigningBackendPackageDigest,
		SigningBackendCapabilityHash: latestIntent.SigningBackendCapabilityHash,
		SignatureAlgorithm:           latestIntent.SignatureAlgorithm, FingerprintSHA256: validated.FingerprintSHA256,
		CRLDER: validated.CRLDER, CreatedAt: createdAt,
	})
	if err != nil {
		return CRLPublicationResult{}, latestIntent, stage, err
	}
	audit, err := s.newAuditRecord(
		auditContext,
		AuditActionCRLPublish,
		AuditOutcomeSucceeded,
		auditResourceCRL,
		string(generation.ID),
		map[string]string{
			auditDetailCRLPublicationID:      string(latestIntent.ID),
			auditDetailCRLIssuerGeneration:   string(latestIntent.IssuerGenerationID),
			auditDetailCRLNumber:             strconv.FormatUint(latestIntent.Number, 10),
			auditDetailCRLRevocationCount:    strconv.Itoa(len(latestIntent.RevocationIDs)),
			auditDetailCRLFingerprint:        generation.FingerprintSHA256,
			auditDetailCRLSignatureAlgorithm: string(generation.SignatureAlgorithm),
		},
	)
	if err != nil {
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(err)
	}
	stage = CRLPublicationFailureStageCompletion
	completionContext, cancelCompletion, budgetErr := s.crlOwnedTransitionContext(ctx, latestIntent)
	if budgetErr != nil {
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(budgetErr)
	}
	defer cancelCompletion()
	if err := s.persistence.CompleteCRLPublication(
		completionContext, latestIntent.ID, latestIntent.Ownership(), generation, audit,
	); err != nil {
		persisted, loadErr := s.persistence.CRLPublicationByKey(
			completionContext, latestIntent.IdempotencyKey,
		)
		if loadErr == nil && persisted.Status == CRLPublicationStatusCompleted {
			result, replayErr := s.completedCRLPublication(completionContext, persisted)
			if replayErr == nil {
				return result, persisted, stage, nil
			}
			loadErr = replayErr
		}
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(errors.Join(err, loadErr))
	}
	completed, err := CompleteCRLPublicationIntent(latestIntent, audit.CreatedAt)
	if err != nil {
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(err)
	}
	result := CRLPublicationResult{Publication: completed, Generation: generation}
	if err := result.Validate(); err != nil {
		return CRLPublicationResult{}, latestIntent, stage, retryableCRLError(err)
	}
	return result.Clone(), completed, stage, nil
}

func crlEntries(intent CRLPublicationIntent, revocations []domainpki.Revocation) ([]CRLEntry, error) {
	byID := make(map[domainpki.RevocationID]domainpki.Revocation, len(revocations))
	for _, revocation := range revocations {
		if err := revocation.Validate(); err != nil {
			return nil, err
		}
		byID[revocation.ID] = revocation
	}
	entries := make([]CRLEntry, len(intent.RevocationIDs))
	for index, id := range intent.RevocationIDs {
		revocation, ok := byID[id]
		if !ok {
			return nil, errors.New("pki: crl publication revocation is missing")
		}
		if revocation.IssuerAuthorityID != intent.AuthorityID ||
			revocation.IssuerGenerationID != intent.IssuerGenerationID ||
			revocation.EffectiveAt.After(intent.ThisUpdate) {
			return nil, errors.New("pki: crl publication revocation does not match its durable scope")
		}
		entries[index] = CRLEntry{RevocationID: id, SerialNumber: revocation.SerialNumber, RevokedAt: revocation.EffectiveAt, Reason: revocation.Reason}
	}
	return entries, nil
}

func (s Service) crlPublicationByKey(ctx context.Context, key, digest string) (CRLPublicationIntent, bool, error) {
	intent, err := s.persistence.CRLPublicationByKey(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return CRLPublicationIntent{}, false, nil
	}
	if err != nil {
		return CRLPublicationIntent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return CRLPublicationIntent{}, false, err
	}
	if intent.RequestSHA256 != digest {
		return CRLPublicationIntent{}, false, ErrIdempotencyConflict
	}
	return intent.Clone(), true, nil
}

func (s Service) failCRLPublication(
	ctx context.Context,
	intent CRLPublicationIntent,
	auditContext AuditContext,
	stage CRLPublicationFailureStage,
	cause error,
) error {
	return errors.Join(cause, s.recordCRLPublicationFailure(ctx, intent, auditContext, stage))
}

func (s Service) recordCRLPublicationFailure(
	ctx context.Context,
	intent CRLPublicationIntent,
	auditContext AuditContext,
	stage CRLPublicationFailureStage,
) error {
	if err := stage.Validate(); err != nil {
		return err
	}
	audit, err := s.newAuditRecord(auditContext, AuditActionCRLPublish, AuditOutcomeFailed, auditResourceCRL, string(intent.CRLGenerationID), map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(intent.SignatureAlgorithm),
		auditDetailCRLStage:              string(stage),
	})
	if err != nil {
		return err
	}
	failure := "crl publication failed during " + string(stage)
	return s.persistence.FailCRLPublication(ctx, intent.ID, intent.Ownership(), failure,
		s.clock.Now().UTC().Truncate(time.Second), stage, audit)
}

func (s Service) newCRLSigningAttemptAudit(auditContext AuditContext, intent CRLPublicationIntent) (AuditRecord, error) {
	audit, err := s.newAuditRecord(auditContext, AuditActionSigningUse, AuditOutcomeAttempted, auditResourceAuthority, string(intent.AuthorityID), map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(intent.SignatureAlgorithm),
	})
	if err != nil {
		return AuditRecord{}, err
	}
	if err := ValidateCRLSigningAttemptAudit(intent, audit); err != nil {
		return AuditRecord{}, err
	}
	return audit, nil
}

func (s Service) newCRLSigningConfirmed(
	auditContext AuditContext,
	auditID string,
	intent CRLPublicationIntent,
	issued IssuedCRL,
) (CRLSignedCheckpoint, AuditRecord, error) {
	details := map[string]string{
		auditDetailCRLPublicationID:      string(intent.ID),
		auditDetailCRLIssuerGeneration:   string(intent.IssuerGenerationID),
		auditDetailCRLNumber:             strconv.FormatUint(intent.Number, 10),
		auditDetailCRLSignatureAlgorithm: string(issued.SignatureAlgorithm),
		auditDetailCRLFingerprint:        issued.FingerprintSHA256,
	}
	if issued.ProviderOperationRef != "" {
		details[auditDetailProviderOperationRef] = string(issued.ProviderOperationRef)
	}
	audit, err := newAuditRecordWithID(
		auditContext,
		auditID,
		AuditActionSigningUse,
		AuditOutcomeSucceeded,
		auditResourceAuthority,
		string(intent.AuthorityID),
		details,
		s.clock.Now().UTC(),
	)
	if err != nil {
		return CRLSignedCheckpoint{}, AuditRecord{}, err
	}
	checkpoint, err := NewCRLSignedCheckpoint(issued, audit.CreatedAt)
	if err != nil {
		return CRLSignedCheckpoint{}, AuditRecord{}, err
	}
	if err := ValidateCRLSigningConfirmedAudit(intent, checkpoint, audit); err != nil {
		return CRLSignedCheckpoint{}, AuditRecord{}, err
	}
	return checkpoint, audit, nil
}

func (s Service) completedCRLPublication(ctx context.Context, intent CRLPublicationIntent) (CRLPublicationResult, error) {
	if intent.Status != CRLPublicationStatusCompleted {
		return CRLPublicationResult{}, errors.New("pki: crl publication is not completed")
	}
	generation, err := s.persistence.CRLGeneration(ctx, intent.ResultCRLGenerationID)
	if err != nil {
		return CRLPublicationResult{}, err
	}
	result := CRLPublicationResult{Publication: intent, Generation: generation}
	if err := result.Validate(); err != nil {
		return CRLPublicationResult{}, err
	}
	return result.Clone(), nil
}

func (s Service) newCRLPublicationID(prefix string) (domainpki.CRLPublicationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewCRLPublicationID(value)
}

func (s Service) newCRLGenerationID(prefix string) (domainpki.CRLGenerationID, error) {
	value, err := s.randomID(prefix)
	if err != nil {
		return "", err
	}
	return domainpki.NewCRLGenerationID(value)
}
