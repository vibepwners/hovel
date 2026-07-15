package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	MaximumMutationResultBytes = 1024 * 1024
	mutationRequestDigestBytes = sha256.Size
)

// MutationKind identifies one synchronous, atomically recorded PKI change.
type MutationKind string

const (
	MutationTrustSetCreate             MutationKind = "trust-set-create"
	MutationTrustSetStage              MutationKind = "trust-set-stage"
	MutationTrustSetActivate           MutationKind = "trust-set-activate"
	MutationAssignmentBind             MutationKind = "assignment-bind"
	MutationAssignmentStage            MutationKind = "assignment-stage"
	MutationAssignmentActivate         MutationKind = "assignment-activate"
	MutationAssignmentUnbind           MutationKind = "assignment-unbind"
	MutationCertificateRevoke          MutationKind = "certificate-revoke"
	MutationAuthorityRollover          MutationKind = "authority-rollover-start"
	MutationConsumerAcknowledge        MutationKind = "consumer-acknowledge"
	MutationRolloverActivate           MutationKind = "authority-rollover-activate"
	MutationRolloverFinalTrust         MutationKind = "authority-rollover-final-trust"
	MutationRolloverComplete           MutationKind = "authority-rollover-complete"
	MutationRolloverCancel             MutationKind = "authority-rollover-cancel"
	MutationCredentialStampCreate      MutationKind = "credential-stamp-create"
	MutationCredentialStampSucceed     MutationKind = "credential-stamp-succeed"
	MutationCredentialStampFail        MutationKind = "credential-stamp-fail"
	MutationCredentialStampSupersede   MutationKind = "credential-stamp-supersede"
	MutationCredentialExecutionCreate  MutationKind = "credential-execution-create"
	MutationCredentialExecutionSucceed MutationKind = "credential-execution-succeed"
	MutationCredentialExecutionFail    MutationKind = "credential-execution-fail"
)

func (k MutationKind) Validate() error {
	switch k {
	case MutationTrustSetCreate, MutationTrustSetStage, MutationTrustSetActivate,
		MutationAssignmentBind, MutationAssignmentStage, MutationAssignmentActivate,
		MutationAssignmentUnbind, MutationCertificateRevoke,
		MutationAuthorityRollover, MutationConsumerAcknowledge, MutationRolloverActivate,
		MutationRolloverFinalTrust, MutationRolloverComplete, MutationRolloverCancel,
		MutationCredentialStampCreate, MutationCredentialStampSucceed,
		MutationCredentialStampFail, MutationCredentialStampSupersede,
		MutationCredentialExecutionCreate, MutationCredentialExecutionSucceed,
		MutationCredentialExecutionFail:
		return nil
	default:
		return fmt.Errorf("pki: unsupported mutation kind %q", k)
	}
}

// MutationRecord stores the public result of a synchronous mutation in the
// same transaction as the state change and audit event. It never contains key
// material or secret export responses.
type MutationRecord struct {
	ID             domainpki.MutationID `json:"id"`
	IdempotencyKey string               `json:"idempotencyKey"`
	RequestSHA256  string               `json:"requestSha256"`
	Kind           MutationKind         `json:"kind"`
	ResourceType   string               `json:"resourceType"`
	ResourceID     string               `json:"resourceId"`
	ResultJSON     json.RawMessage      `json:"result"`
	CreatedAt      time.Time            `json:"createdAt"`
}

func (r MutationRecord) Clone() MutationRecord {
	result := r
	result.ResultJSON = append(json.RawMessage(nil), r.ResultJSON...)
	return result
}

func (r MutationRecord) Validate() error {
	if err := r.ID.Validate(); err != nil {
		return err
	}
	if err := validateIdempotencyKey(r.IdempotencyKey); err != nil {
		return err
	}
	digest, err := hex.DecodeString(r.RequestSHA256)
	if err != nil || len(digest) != mutationRequestDigestBytes || r.RequestSHA256 != strings.ToLower(r.RequestSHA256) {
		return errors.New("pki: mutation request digest must be canonical sha256")
	}
	if err := r.Kind.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalAuditText(r.ResourceType, "mutation resource type", maximumAuditResourceBytes); err != nil {
		return err
	}
	if err := validateCanonicalAuditText(r.ResourceID, "mutation resource id", maximumAuditResourceBytes); err != nil {
		return err
	}
	if len(r.ResultJSON) == 0 || len(r.ResultJSON) > MaximumMutationResultBytes || !json.Valid(r.ResultJSON) {
		return errors.New("pki: mutation result must be bounded valid json")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, r.ResultJSON); err != nil || !bytes.Equal(compact.Bytes(), r.ResultJSON) {
		return errors.New("pki: mutation result json is not canonical")
	}
	if r.CreatedAt.IsZero() || r.CreatedAt != r.CreatedAt.UTC() {
		return errors.New("pki: mutation creation time must be canonical utc")
	}
	return nil
}

type mutationScope struct {
	idempotencyKey string
	requestSHA256  string
	audit          AuditContext
}

func prepareMutation[T any](ctx context.Context, service Service, explicitKey string, kind MutationKind, normalizedRequest any) (mutationScope, T, bool, error) {
	var zero T
	if err := kind.Validate(); err != nil {
		return mutationScope{}, zero, false, err
	}
	auditContext, err := service.resolveAuditContext(ctx)
	if err != nil {
		return mutationScope{}, zero, false, err
	}
	digest, err := requestDigest(normalizedRequest)
	if err != nil {
		return mutationScope{}, zero, false, err
	}
	key, err := resolveIdempotencyKey(explicitKey, kind, digest, auditContext)
	if err != nil {
		return mutationScope{}, zero, false, err
	}
	scope := mutationScope{idempotencyKey: key, requestSHA256: digest, audit: auditContext}
	result, exists, err := replayMutation[T](ctx, service, scope, kind)
	return scope, result, exists, err
}

func replayMutation[T any](ctx context.Context, service Service, scope mutationScope, kind MutationKind) (T, bool, error) {
	var zero T
	record, err := service.persistence.MutationByKey(ctx, scope.idempotencyKey)
	if errors.Is(err, ErrNotFound) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if err := record.Validate(); err != nil {
		return zero, false, fmt.Errorf("pki: validate persisted mutation: %w", err)
	}
	if record.Kind != kind || record.RequestSHA256 != scope.requestSHA256 {
		return zero, false, ErrIdempotencyConflict
	}
	var result T
	if err := json.Unmarshal(record.ResultJSON, &result); err != nil {
		return zero, false, fmt.Errorf("pki: decode persisted mutation result: %w", err)
	}
	return result, true, nil
}

func (s Service) newMutationRecord(kind MutationKind, scope mutationScope, resourceType, resourceID string, result any) (MutationRecord, error) {
	id, err := s.newMutationID("mutation")
	if err != nil {
		return MutationRecord{}, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return MutationRecord{}, fmt.Errorf("pki: encode mutation result: %w", err)
	}
	record := MutationRecord{
		ID: id, IdempotencyKey: scope.idempotencyKey, RequestSHA256: scope.requestSHA256,
		Kind: kind, ResourceType: resourceType, ResourceID: resourceID,
		ResultJSON: encoded, CreatedAt: s.clock.Now().UTC(),
	}
	if err := record.Validate(); err != nil {
		return MutationRecord{}, err
	}
	return record, nil
}

func commitMutation[T any](ctx context.Context, service Service, scope mutationScope, kind MutationKind, resourceType, resourceID string, result T, commit func(MutationRecord) error) (T, error) {
	record, err := service.newMutationRecord(kind, scope, resourceType, resourceID, result)
	if err != nil {
		var zero T
		return zero, err
	}
	if err := commit(record); err != nil {
		if errors.Is(err, ErrMutationExists) {
			replayed, exists, replayErr := replayMutation[T](ctx, service, scope, kind)
			if replayErr != nil {
				var zero T
				return zero, replayErr
			}
			if exists {
				return replayed, nil
			}
		}
		var zero T
		return zero, err
	}
	return result, nil
}
