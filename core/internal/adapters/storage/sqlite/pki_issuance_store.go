package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const issuanceSelect = `
SELECT id, idempotency_key, request_sha256, kind, authority_id, certificate_id,
	generation_id, source_generation_id, generation, key_id, issuer_authority_id, issuer_generation_id,
	subject_backend_id, subject_backend_version, subject_package_digest, subject_capability_hash,
	signing_backend_id, signing_backend_version, signing_package_digest, signing_capability_hash, profile_id,
	compatibility_target_id, compatibility_version, purpose, export_policy, key_establishment_policy,
	tls_named_groups_json, chain_generation_ids_json, authority_plan_json, status,
	owner_token, revision, lease_expires_at, result_generation_id, failure, intent_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
FROM pki_issuance_intents`

func (s PKIStore) BeginIssuance(ctx context.Context, candidate apppki.IssuanceIntent) (apppki.IssuanceIntent, bool, error) {
	var result apppki.IssuanceIntent
	var created bool
	err := s.protector.WithStableKeyEpoch(ctx, func() error {
		var beginErr error
		result, created, beginErr = s.beginIssuanceStable(ctx, candidate)
		return beginErr
	})
	return result, created, err
}

func (s PKIStore) beginIssuanceStable(ctx context.Context, candidate apppki.IssuanceIntent) (apppki.IssuanceIntent, bool, error) {
	if err := apppki.ValidateNewIssuanceIntent(candidate); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	defer func() { logSQLiteRollback("rollback pki issuance begin", tx.Rollback()) }()
	existing, err := s.loadIssuance(ctx, tx.QueryRowContext(ctx, issuanceSelect+` WHERE idempotency_key = ?`, candidate.IdempotencyKey))
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, apppki.ErrNotFound) {
		return apppki.IssuanceIntent{}, false, err
	}
	intent := candidate.Clone()
	if intent.Generation == 0 {
		intent.Generation, err = reserveGenerationTx(ctx, tx, intent.CertificateID)
	} else {
		err = initializeGenerationCounterTx(ctx, tx, intent.CertificateID, intent.Generation)
	}
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	encoded, metadata, err := s.encodeIssuance(ctx, intent)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if err := insertIssuance(ctx, tx, intent, encoded, metadata); err != nil {
		rollbackErr := tx.Rollback()
		existing, loadErr := s.issuanceByKey(ctx, intent.IdempotencyKey)
		if loadErr == nil {
			return existing, false, nil
		}
		return apppki.IssuanceIntent{}, false, errors.Join(err, rollbackErr)
	}
	if err := tx.Commit(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	return intent.Clone(), true, nil
}

func (s PKIStore) IssuanceByKey(ctx context.Context, key string) (apppki.IssuanceIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.IssuanceIntent, error) {
		return s.issuanceByKey(ctx, key)
	})
}

func (s PKIStore) issuanceByKey(ctx context.Context, key string) (apppki.IssuanceIntent, error) {
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.IssuanceIntent{}, err
	}
	return s.loadIssuance(ctx, db.QueryRowContext(ctx, issuanceSelect+` WHERE idempotency_key = ?`, key))
}

func (s PKIStore) PendingIssuances(ctx context.Context, eligibleAt, updatedBefore time.Time, limit int) ([]apppki.IssuanceIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]apppki.IssuanceIntent, error) {
		return s.pendingIssuances(ctx, eligibleAt, updatedBefore, limit)
	})
}

func (s PKIStore) pendingIssuances(ctx context.Context, eligibleAt, updatedBefore time.Time, limit int) ([]apppki.IssuanceIntent, error) {
	if eligibleAt.IsZero() || updatedBefore.IsZero() || updatedBefore.After(eligibleAt) || limit < 1 || limit > apppki.MaximumPendingIssuanceBatch {
		return nil, errors.New("pki sqlite: invalid pending issuance query")
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, issuanceSelect+` WHERE status = ? AND lease_expires_at <= ? AND updated_at <= ? ORDER BY updated_at, lease_expires_at, id LIMIT ?`,
		apppki.IssuanceStatusPending, eligibleAt.UTC().Format(time.RFC3339Nano), updatedBefore.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pending issuance rows", rows.Close()) }()
	result := make([]apppki.IssuanceIntent, 0, limit)
	for rows.Next() {
		intent, err := s.loadIssuance(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intent)
	}
	return result, rows.Err()
}

func (s PKIStore) ClaimIssuance(ctx context.Context, id domainpki.IssuanceID, expected apppki.IssuanceOwnership, ownerToken string, claimedAt time.Time) (apppki.IssuanceIntent, bool, error) {
	var result apppki.IssuanceIntent
	var claimed bool
	err := s.protector.WithStableKeyEpoch(ctx, func() error {
		var claimErr error
		result, claimed, claimErr = s.claimIssuanceStable(ctx, id, expected, ownerToken, claimedAt)
		return claimErr
	})
	return result, claimed, err
}

func (s PKIStore) claimIssuanceStable(ctx context.Context, id domainpki.IssuanceID, expected apppki.IssuanceOwnership, ownerToken string, claimedAt time.Time) (apppki.IssuanceIntent, bool, error) {
	if err := id.Validate(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	defer func() { logSQLiteRollback("rollback pki issuance claim", tx.Rollback()) }()
	intent, err := s.loadIssuance(ctx, tx.QueryRowContext(ctx, issuanceSelect+` WHERE id = ?`, id))
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if apppki.ValidateIssuanceOwnership(intent, expected.OwnerToken, expected.Revision) != nil || claimedAt.Before(intent.LeaseExpiresAt) {
		return intent, false, nil
	}
	claimedIntent, err := apppki.ClaimIssuanceIntent(intent, ownerToken, claimedAt)
	if err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if err := s.updateIssuance(ctx, tx, claimedIntent, intent.Ownership()); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return apppki.IssuanceIntent{}, false, err
	}
	return claimedIntent, true, nil
}

func (s PKIStore) CompleteAuthorityIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, authority domainpki.Authority, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		return s.completeAuthorityIssuanceStable(ctx, intentID, ownership, authority, generation, validated, audits)
	})
}

func (s PKIStore) completeAuthorityIssuanceStable(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, authority domainpki.Authority, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	if err := authority.Validate(); err != nil {
		return err
	}
	if authority.ActiveGenerationID != generation.ID || generation.OwningAuthorityID != authority.ID {
		return errors.New("pki sqlite: authority and active generation do not match")
	}
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	prepared, err := s.prepareIssuanceResult(ctx, generation, validated)
	if err != nil {
		return err
	}
	authorityJSON, err := json.Marshal(authority)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode authority: %w", err)
	}
	authorityMetadata, err := s.protector.AuthenticateMetadata(ctx, authorityJSON)
	if err != nil {
		return fmt.Errorf("pki sqlite: authenticate authority: %w", err)
	}
	return s.completeIssuance(ctx, intentID, ownership, generation, audits, issuanceResultAuthority, func(intent apppki.IssuanceIntent) error {
		return apppki.ValidateAuthorityIssuanceCompletion(intent, authority, generation, material)
	}, func(tx *sql.Tx) error {
		if err := insertProtectedKey(ctx, tx, prepared.protected); err != nil {
			return err
		}
		if err := insertAuthority(ctx, tx, authority, authorityJSON, authorityMetadata); err != nil {
			return err
		}
		if err := insertGeneration(ctx, tx, generation, prepared.generationJSON, prepared.generationMetadata); err != nil {
			return err
		}
		if err := appendPKIAudit(ctx, tx, pkiAuditAuthorityCreated, pkiResourceAuthority, string(authority.ID)); err != nil {
			return err
		}
		return nil
	})
}

func (s PKIStore) CompleteCertificateIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		return s.completeCertificateIssuanceStable(ctx, intentID, ownership, generation, validated, audits)
	})
}

func (s PKIStore) completeCertificateIssuanceStable(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	prepared, err := s.prepareIssuanceResult(ctx, generation, validated)
	if err != nil {
		return err
	}
	return s.completeIssuance(ctx, intentID, ownership, generation, audits, issuanceResultCertificate, nil, func(tx *sql.Tx) error {
		if err := insertProtectedKey(ctx, tx, prepared.protected); err != nil {
			return err
		}
		return insertGeneration(ctx, tx, generation, prepared.generationJSON, prepared.generationMetadata)
	})
}

func (s PKIStore) CompleteCertificateRenewal(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial, audits apppki.IssuanceCompletionAudits) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := generation.Validate(); err != nil {
			return err
		}
		material := validated.Material()
		defer clear(material.PrivateKeyPKCS8)
		if err := apppki.ValidateGenerationKeyBinding(generation, material); err != nil {
			return err
		}
		existing, err := s.loadKey(ctx, generation.KeyID)
		if err != nil {
			return err
		}
		defer clear(existing.PrivateKeyPKCS8)
		if !apppki.KeyMaterialsEqual(existing, material) {
			return errors.New("pki sqlite: renewal key does not match persisted key material")
		}
		prepared, err := s.prepareGenerationResult(ctx, generation)
		if err != nil {
			return err
		}
		return s.completeIssuance(ctx, intentID, ownership, generation, audits, issuanceResultRenewal, nil, func(tx *sql.Tx) error {
			return insertGeneration(ctx, tx, generation, prepared.generationJSON, prepared.generationMetadata)
		})
	})
}

func (s PKIStore) FailIssuance(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, failure string, updatedAt time.Time, audit apppki.AuditRecord) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		return s.failIssuanceStable(ctx, intentID, ownership, failure, updatedAt, audit)
	})
}

func (s PKIStore) failIssuanceStable(ctx context.Context, intentID domainpki.IssuanceID, ownership apppki.IssuanceOwnership, failure string, updatedAt time.Time, audit apppki.AuditRecord) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { logSQLiteRollback("rollback pki issuance failure", tx.Rollback()) }()
	intent, err := s.loadIssuance(ctx, tx.QueryRowContext(ctx, issuanceSelect+` WHERE id = ?`, intentID))
	if err != nil {
		return err
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	failed, err := apppki.FailIssuanceIntent(intent, failure, updatedAt)
	if err != nil {
		return err
	}
	if err := s.updateIssuance(ctx, tx, failed, ownership); err != nil {
		return err
	}
	if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

type preparedIssuanceResult struct {
	protected          apppki.ProtectedKeyMaterial
	generationJSON     []byte
	generationMetadata apppki.ProtectedMetadata
}

type preparedGenerationResult struct {
	generationJSON     []byte
	generationMetadata apppki.ProtectedMetadata
}

type issuanceResultKind uint8

const (
	issuanceResultAuthority issuanceResultKind = iota + 1
	issuanceResultCertificate
	issuanceResultRenewal
)

func (k issuanceResultKind) accepts(kind apppki.IssuanceKind) bool {
	switch k {
	case issuanceResultAuthority:
		return kind == apppki.IssuanceKindAuthority
	case issuanceResultCertificate:
		return kind == apppki.IssuanceKindCertificate || kind == apppki.IssuanceKindCertificateRotation
	case issuanceResultRenewal:
		return kind == apppki.IssuanceKindCertificateRenewal
	default:
		return false
	}
}

func (k issuanceResultKind) validateIntent(intent apppki.IssuanceIntent, generation domainpki.CertificateGeneration) error {
	if !k.accepts(intent.Kind) {
		return errors.New("pki sqlite: issuance result path does not match its durable kind")
	}
	if k == issuanceResultAuthority && generation.OwningAuthorityID != intent.AuthorityID {
		return errors.New("pki sqlite: authority issuance result does not match its durable plan")
	}
	return nil
}

func (k issuanceResultKind) storesKey() bool {
	return k == issuanceResultAuthority || k == issuanceResultCertificate
}

func (s PKIStore) prepareIssuanceResult(ctx context.Context, generation domainpki.CertificateGeneration, validated apppki.ValidatedKeyMaterial) (preparedIssuanceResult, error) {
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	if err := apppki.ValidateGenerationKeyBinding(generation, material); err != nil {
		return preparedIssuanceResult{}, err
	}
	prepared, err := s.prepareGenerationResult(ctx, generation)
	if err != nil {
		return preparedIssuanceResult{}, err
	}
	protected, err := s.protectAndVerify(ctx, validated)
	if err != nil {
		return preparedIssuanceResult{}, err
	}
	return preparedIssuanceResult{
		protected: protected, generationJSON: prepared.generationJSON,
		generationMetadata: prepared.generationMetadata,
	}, nil
}

func (s PKIStore) prepareGenerationResult(ctx context.Context, generation domainpki.CertificateGeneration) (preparedGenerationResult, error) {
	if err := generation.Validate(); err != nil {
		return preparedGenerationResult{}, err
	}
	if generation.Generation > math.MaxInt64 {
		return preparedGenerationResult{}, errors.New("pki sqlite: generation number exceeds sqlite integer range")
	}
	encoded, err := json.Marshal(generation)
	if err != nil {
		return preparedGenerationResult{}, fmt.Errorf("pki sqlite: encode certificate generation: %w", err)
	}
	metadata, err := s.protector.AuthenticateMetadata(ctx, encoded)
	if err != nil {
		return preparedGenerationResult{}, fmt.Errorf("pki sqlite: authenticate certificate generation: %w", err)
	}
	return preparedGenerationResult{generationJSON: encoded, generationMetadata: metadata}, nil
}

func (s PKIStore) completeIssuance(
	ctx context.Context,
	intentID domainpki.IssuanceID,
	ownership apppki.IssuanceOwnership,
	generation domainpki.CertificateGeneration,
	audits apppki.IssuanceCompletionAudits,
	resultKind issuanceResultKind,
	validateResult func(apppki.IssuanceIntent) error,
	insertResult func(*sql.Tx) error,
) error {
	db, err := s.store.open(ctx)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { logSQLiteRollback("rollback pki issuance completion", tx.Rollback()) }()
	intent, err := s.loadIssuance(ctx, tx.QueryRowContext(ctx, issuanceSelect+` WHERE id = ?`, intentID))
	if err != nil {
		return err
	}
	if err := apppki.ValidateIssuanceOwnership(intent, ownership.OwnerToken, ownership.Revision); err != nil {
		return err
	}
	if err := audits.Validate(intent.Kind, generation.ID, intent.SourceGenerationID, intent.SigningAuthorityID()); err != nil {
		return err
	}
	if err := resultKind.validateIntent(intent, generation); err != nil {
		return err
	}
	if err := apppki.ValidateIssuanceCompletion(intent, generation); err != nil {
		return err
	}
	if validateResult != nil {
		if err := validateResult(intent); err != nil {
			return err
		}
	}
	if intent.SourceGenerationID != "" {
		source, err := s.loadGeneration(ctx, tx.QueryRowContext(ctx, generationSelect+` WHERE id = ?`, intent.SourceGenerationID))
		if err != nil {
			return err
		}
		if err := apppki.ValidateLifecycleSourceEligibility(source); err != nil {
			return err
		}
		if err := apppki.ValidateLifecycleGenerationTransition(intent.Kind, source, generation); err != nil {
			return err
		}
	}
	if err := insertResult(tx); err != nil {
		return err
	}
	if err := appendPKIAudit(ctx, tx, pkiAuditGenerationCreated, pkiResourceGeneration, string(generation.ID)); err != nil {
		return err
	}
	if resultKind.storesKey() {
		if err := appendPKIAudit(ctx, tx, pkiAuditKeyStored, pkiResourceKey, string(generation.KeyID)); err != nil {
			return err
		}
	}
	completed, err := apppki.CompleteIssuanceIntent(intent, audits.CompletedAt())
	if err != nil {
		return err
	}
	if err := s.updateIssuance(ctx, tx, completed, ownership); err != nil {
		return err
	}
	for _, audit := range audits.Records() {
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func reserveGenerationTx(ctx context.Context, tx *sql.Tx, id domainpki.CertificateID) (uint64, error) {
	var generation int64
	err := tx.QueryRowContext(ctx, `
INSERT INTO pki_generation_counters(certificate_id, last_generation)
VALUES (?, 1)
ON CONFLICT(certificate_id) DO UPDATE SET last_generation = last_generation + 1
WHERE last_generation < ?
RETURNING last_generation`, id, int64(math.MaxInt64)).Scan(&generation)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("pki sqlite: certificate generation counter is exhausted")
		}
		return 0, fmt.Errorf("pki sqlite: reserve certificate generation: %w", err)
	}
	return uint64(generation), nil
}

func initializeGenerationCounterTx(ctx context.Context, tx *sql.Tx, id domainpki.CertificateID, generation uint64) error {
	if generation != 1 {
		return errors.New("pki sqlite: explicit issuance generation must be one")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pki_generation_counters(certificate_id, last_generation) VALUES (?, 1)`, id); err != nil {
		return fmt.Errorf("pki sqlite: initialize certificate generation counter: %w", err)
	}
	return nil
}

func (s PKIStore) encodeIssuance(ctx context.Context, intent apppki.IssuanceIntent) ([]byte, apppki.ProtectedMetadata, error) {
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: encode issuance intent: %w", err)
	}
	metadata, err := s.protector.AuthenticateMetadata(ctx, encoded)
	if err != nil {
		return nil, apppki.ProtectedMetadata{}, fmt.Errorf("pki sqlite: authenticate issuance intent: %w", err)
	}
	return encoded, metadata, nil
}

func insertIssuance(ctx context.Context, tx *sql.Tx, intent apppki.IssuanceIntent, encoded []byte, metadata apppki.ProtectedMetadata) error {
	tlsNamedGroupsJSON, err := json.Marshal(intent.TLSNamedGroups)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode issuance tls named groups: %w", err)
	}
	chainGenerationIDsJSON, err := json.Marshal(intent.ChainGenerationIDs)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode issuance chain generation ids: %w", err)
	}
	authorityPlanJSON, err := json.Marshal(intent.AuthorityPlan)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode issuance authority plan: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO pki_issuance_intents(
	id, idempotency_key, request_sha256, kind, authority_id, certificate_id,
	generation_id, source_generation_id, generation, key_id, issuer_authority_id, issuer_generation_id,
	subject_backend_id, subject_backend_version, subject_package_digest, subject_capability_hash,
	signing_backend_id, signing_backend_version, signing_package_digest, signing_capability_hash, profile_id,
	compatibility_target_id, compatibility_version, purpose, export_policy, key_establishment_policy,
	tls_named_groups_json, chain_generation_ids_json, authority_plan_json, status,
	owner_token, revision, lease_expires_at, result_generation_id, failure, intent_json, metadata_schema_version,
	metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		intent.ID, intent.IdempotencyKey, intent.RequestSHA256, intent.Kind, nullableString(string(intent.AuthorityID)),
		intent.CertificateID, intent.GenerationID, nullableString(string(intent.SourceGenerationID)), intent.Generation, intent.KeyID, nullableString(string(intent.IssuerAuthorityID)),
		nullableString(string(intent.IssuerGenerationID)), intent.SubjectBackendID, intent.SubjectBackendVersion,
		intent.SubjectPackageDigest, intent.SubjectCapabilityHash, intent.SigningBackendID, intent.SigningBackendVersion,
		intent.SigningPackageDigest, intent.SigningCapabilityHash, intent.ProfileID,
		intent.CompatibilityTargetID, intent.CompatibilityVersion, intent.Purpose, intent.ExportPolicy,
		intent.KeyEstablishment, tlsNamedGroupsJSON, chainGenerationIDsJSON, authorityPlanJSON, intent.Status,
		intent.OwnerToken, intent.Revision, intent.LeaseExpiresAt.Format(time.RFC3339Nano),
		nullableString(string(intent.ResultGenerationID)), nullableString(intent.Failure), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		intent.CreatedAt.Format(time.RFC3339Nano), intent.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store issuance intent: %w", err)
	}
	return nil
}

func (s PKIStore) updateIssuance(ctx context.Context, tx *sql.Tx, intent apppki.IssuanceIntent, expected apppki.IssuanceOwnership) error {
	encoded, metadata, err := s.encodeIssuance(ctx, intent)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE pki_issuance_intents
SET status = ?, owner_token = ?, revision = ?, lease_expires_at = ?, result_generation_id = ?, failure = ?, intent_json = ?,
	metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?,
	metadata_tag = ?, updated_at = ?
WHERE id = ? AND status = ? AND owner_token = ? AND revision = ?`, intent.Status, intent.OwnerToken, intent.Revision,
		intent.LeaseExpiresAt.Format(time.RFC3339Nano), nullableString(string(intent.ResultGenerationID)), nullableString(intent.Failure), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		intent.UpdatedAt.Format(time.RFC3339Nano), intent.ID, apppki.IssuanceStatusPending, expected.OwnerToken, expected.Revision)
	if err != nil {
		return fmt.Errorf("pki sqlite: update issuance intent: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("pki sqlite: issuance update affected an unexpected number of rows")
	}
	return nil
}

func (s PKIStore) loadIssuance(ctx context.Context, row rowScanner) (apppki.IssuanceIntent, error) {
	var (
		id                     domainpki.IssuanceID
		idempotencyKey         string
		requestSHA256          string
		kind                   apppki.IssuanceKind
		authorityID            sql.NullString
		certificateID          domainpki.CertificateID
		generationID           domainpki.GenerationID
		sourceGenerationID     sql.NullString
		generation             int64
		keyID                  domainpki.KeyID
		issuerAuthorityID      sql.NullString
		issuerGenerationID     sql.NullString
		subjectBackendID       domainpki.BackendID
		subjectBackendVersion  string
		subjectPackageDigest   string
		subjectCapabilityHash  string
		signingBackendID       domainpki.BackendID
		signingBackendVersion  string
		signingPackageDigest   string
		signingCapabilityHash  string
		profileID              domainpki.ProfileID
		compatibilityTargetID  domainpki.CompatibilityTargetID
		compatibilityVersion   string
		purpose                domainpki.Purpose
		exportPolicy           domainpki.ExportPolicy
		keyEstablishment       domainpki.KeyEstablishmentPolicy
		tlsNamedGroupsJSON     []byte
		chainGenerationIDsJSON []byte
		authorityPlanJSON      []byte
		status                 apppki.IssuanceStatus
		ownerToken             string
		revision               int64
		leaseExpiresAt         string
		resultGenerationID     sql.NullString
		failure                sql.NullString
		encoded                []byte
		metadata               apppki.ProtectedMetadata
		createdAt              string
		updatedAt              string
	)
	if err := row.Scan(&id, &idempotencyKey, &requestSHA256, &kind, &authorityID, &certificateID,
		&generationID, &sourceGenerationID, &generation, &keyID, &issuerAuthorityID, &issuerGenerationID,
		&subjectBackendID, &subjectBackendVersion, &subjectPackageDigest, &subjectCapabilityHash,
		&signingBackendID, &signingBackendVersion, &signingPackageDigest, &signingCapabilityHash, &profileID,
		&compatibilityTargetID, &compatibilityVersion, &purpose, &exportPolicy, &keyEstablishment,
		&tlsNamedGroupsJSON, &chainGenerationIDsJSON, &authorityPlanJSON, &status,
		&ownerToken, &revision, &leaseExpiresAt, &resultGenerationID, &failure, &encoded, &metadata.SchemaVersion, &metadata.Algorithm,
		&metadata.KeyVersion, &metadata.Tag, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.IssuanceIntent{}, apppki.ErrNotFound
		}
		return apppki.IssuanceIntent{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: verify issuance intent metadata: %w", err)
	}
	var intent apppki.IssuanceIntent
	if err := json.Unmarshal(encoded, &intent); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: decode issuance intent: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: validate issuance intent: %w", err)
	}
	var tlsNamedGroups []domainpki.TLSNamedGroup
	if err := json.Unmarshal(tlsNamedGroupsJSON, &tlsNamedGroups); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: decode issuance tls named groups: %w", err)
	}
	var chainGenerationIDs []domainpki.GenerationID
	if err := json.Unmarshal(chainGenerationIDsJSON, &chainGenerationIDs); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: decode issuance chain generation ids: %w", err)
	}
	var authorityPlan *apppki.AuthorityIssuancePlan
	if err := json.Unmarshal(authorityPlanJSON, &authorityPlan); err != nil {
		return apppki.IssuanceIntent{}, fmt.Errorf("pki sqlite: decode issuance authority plan: %w", err)
	}
	if generation <= 0 || intent.ID != id || intent.IdempotencyKey != idempotencyKey || intent.RequestSHA256 != requestSHA256 ||
		intent.Kind != kind || intent.AuthorityID != domainpki.AuthorityID(nullString(authorityID)) ||
		intent.CertificateID != certificateID || intent.GenerationID != generationID || intent.Generation != uint64(generation) ||
		intent.SourceGenerationID != domainpki.GenerationID(nullString(sourceGenerationID)) ||
		intent.KeyID != keyID || intent.IssuerAuthorityID != domainpki.AuthorityID(nullString(issuerAuthorityID)) ||
		intent.IssuerGenerationID != domainpki.GenerationID(nullString(issuerGenerationID)) ||
		intent.SubjectBackendID != subjectBackendID || intent.SubjectBackendVersion != subjectBackendVersion ||
		intent.SubjectPackageDigest != subjectPackageDigest || intent.SubjectCapabilityHash != subjectCapabilityHash ||
		intent.SigningBackendID != signingBackendID || intent.SigningBackendVersion != signingBackendVersion ||
		intent.SigningPackageDigest != signingPackageDigest || intent.SigningCapabilityHash != signingCapabilityHash ||
		intent.ProfileID != profileID || intent.CompatibilityTargetID != compatibilityTargetID ||
		intent.CompatibilityVersion != compatibilityVersion || intent.Purpose != purpose ||
		intent.ExportPolicy != exportPolicy || intent.KeyEstablishment != keyEstablishment ||
		!slices.Equal(intent.TLSNamedGroups, tlsNamedGroups) || !slices.Equal(intent.ChainGenerationIDs, chainGenerationIDs) ||
		!reflect.DeepEqual(intent.AuthorityPlan, authorityPlan) ||
		intent.Status != status || intent.OwnerToken != ownerToken ||
		revision <= 0 || intent.Revision != uint64(revision) || intent.LeaseExpiresAt.Format(time.RFC3339Nano) != leaseExpiresAt ||
		intent.ResultGenerationID != domainpki.GenerationID(nullString(resultGenerationID)) || intent.Failure != nullString(failure) ||
		intent.CreatedAt.Format(time.RFC3339Nano) != createdAt || intent.UpdatedAt.Format(time.RFC3339Nano) != updatedAt {
		return apppki.IssuanceIntent{}, errors.New("pki sqlite: issuance intent json does not match canonical columns")
	}
	return intent.Clone(), nil
}

func appendApplicationPKIAudit(ctx context.Context, tx *sql.Tx, record apppki.AuditRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	details, err := json.Marshal(record.Details)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode audit details: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO pki_audit_events(
	event_id, action, outcome, actor_id, operation_id, correlation_id,
	resource_type, resource_id, details_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, record.Action, record.Outcome, record.ActorID,
		record.OperationID, record.CorrelationID, record.ResourceType, record.ResourceID, details,
		record.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: append application audit record: %w", err)
	}
	return nil
}
