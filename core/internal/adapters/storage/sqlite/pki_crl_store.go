package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const crlPublicationSelect = `
SELECT id, idempotency_key, request_sha256, crl_generation_id, authority_id,
	issuer_generation_id, number, this_update, next_update, signing_backend_id,
	signing_backend_version, signing_backend_package_digest, signing_backend_capability_hash,
	signature_algorithm, status, phase, owner_token, revision, lease_expires_at, result_crl_generation_id,
	signed_fingerprint_sha256, signed_signature_algorithm, signed_provider_operation_ref, signed_crl_der, signed_at, failure,
	intent_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag,
	created_at, updated_at
FROM pki_crl_publication_intents`

const crlGenerationSelect = `
SELECT id, authority_id, issuer_generation_id, number, this_update, next_update,
	signature_algorithm, fingerprint_sha256, generation_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at
FROM pki_crl_generations`

func (s PKIStore) BeginCRLPublication(
	ctx context.Context,
	candidate apppki.CRLPublicationIntent,
	revocations []domainpki.Revocation,
) (apppki.CRLPublicationIntent, bool, error) {
	var result apppki.CRLPublicationIntent
	var created bool
	err := s.protector.WithStableKeyEpoch(ctx, func() error {
		var beginErr error
		result, created, beginErr = s.beginCRLPublication(ctx, candidate, revocations)
		return beginErr
	})
	return result, created, err
}

func (s PKIStore) beginCRLPublication(
	ctx context.Context,
	candidate apppki.CRLPublicationIntent,
	revocations []domainpki.Revocation,
) (apppki.CRLPublicationIntent, bool, error) {
	if err := apppki.ValidateNewCRLPublicationIntent(candidate); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	defer func() { logSQLiteRollback("rollback pki crl publication begin", tx.Rollback()) }()
	existing, err := s.loadCRLPublication(ctx, tx.QueryRowContext(
		ctx, crlPublicationSelect+` WHERE idempotency_key = ?`, candidate.IdempotencyKey,
	))
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, apppki.ErrNotFound) {
		return apppki.CRLPublicationIntent{}, false, err
	}
	authority, err := s.loadAuthority(ctx, tx.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, candidate.AuthorityID))
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	issuer, err := s.loadGeneration(ctx, tx.QueryRowContext(ctx, generationSelect+` WHERE id = ?`, candidate.IssuerGenerationID))
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if authority.ActiveGenerationID != issuer.ID || issuer.OwningAuthorityID != authority.ID ||
		issuer.State != domainpki.CertificateStateActive ||
		issuer.Template.KeyUsage&domainpki.KeyUsageCRLSign == 0 ||
		!candidate.SignatureAlgorithm.CompatibleWith(issuer.Template.Key.Algorithm) {
		return apppki.CRLPublicationIntent{}, false, errors.New("pki sqlite: crl issuer is not the active authorized authority generation")
	}
	currentRevocations, err := s.loadAuthorityRevocationsTx(ctx, tx, candidate.AuthorityID)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := apppki.ValidateCRLRevocationSnapshot(candidate, currentRevocations); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := apppki.ValidateCRLRevocationSnapshot(candidate, revocations); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	intent := candidate.Clone()
	intent.Number, err = reserveCRLNumberTx(ctx, tx, intent.AuthorityID)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	encoded, metadata, err := s.authenticateJSON(ctx, intent)
	if err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	if err := insertCRLPublication(ctx, tx, intent, encoded, metadata); err != nil {
		rollbackErr := tx.Rollback()
		existing, loadErr := s.crlPublicationByKey(ctx, intent.IdempotencyKey)
		if loadErr == nil {
			return existing, false, nil
		}
		return apppki.CRLPublicationIntent{}, false, errors.Join(err, rollbackErr)
	}
	if err := commitCRLTransaction(ctx, tx); err != nil {
		return apppki.CRLPublicationIntent{}, false, err
	}
	return intent.Clone(), true, nil
}

func reserveCRLNumberTx(ctx context.Context, tx *sql.Tx, id domainpki.AuthorityID) (uint64, error) {
	var number int64
	err := tx.QueryRowContext(ctx, `
INSERT INTO pki_crl_counters(authority_id, last_number)
VALUES (?, 1)
ON CONFLICT(authority_id) DO UPDATE SET last_number = last_number + 1
WHERE last_number < ?
RETURNING last_number`, id, int64(domainpki.MaximumSequenceNumber)).Scan(&number)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("pki sqlite: crl number counter is exhausted")
		}
		return 0, fmt.Errorf("pki sqlite: reserve crl number: %w", err)
	}
	return uint64(number), nil
}

func (s PKIStore) CRLPublicationByKey(ctx context.Context, key string) (apppki.CRLPublicationIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.CRLPublicationIntent, error) {
		return s.crlPublicationByKey(ctx, key)
	})
}

func (s PKIStore) CRLPublication(ctx context.Context, id domainpki.CRLPublicationID) (apppki.CRLPublicationIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.CRLPublicationIntent, error) {
		if err := id.Validate(); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		return s.loadCRLPublication(ctx, db.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) CRLPublications(ctx context.Context, id domainpki.AuthorityID) ([]apppki.CRLPublicationIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]apppki.CRLPublicationIntent, error) {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if _, err := s.authority(ctx, id); err != nil {
			return nil, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, crlPublicationSelect+` WHERE authority_id = ? ORDER BY number, id`, id)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki crl publication rows", rows.Close()) }()
		result := make([]apppki.CRLPublicationIntent, 0)
		for rows.Next() {
			intent, err := s.loadCRLPublication(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, intent)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) crlPublicationByKey(ctx context.Context, key string) (apppki.CRLPublicationIntent, error) {
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	return s.loadCRLPublication(ctx, db.QueryRowContext(ctx, crlPublicationSelect+` WHERE idempotency_key = ?`, key))
}

func (s PKIStore) PendingCRLPublications(
	ctx context.Context,
	eligibleAt time.Time,
	updatedBefore time.Time,
	limit int,
) ([]apppki.CRLPublicationIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]apppki.CRLPublicationIntent, error) {
		if eligibleAt.IsZero() || updatedBefore.IsZero() || updatedBefore.After(eligibleAt) ||
			limit < 1 || limit > apppki.MaximumPendingCRLPublicationBatch {
			return nil, errors.New("pki sqlite: invalid pending crl publication query")
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, crlPublicationSelect+`
WHERE status = ? AND lease_expires_at <= ? AND updated_at <= ?
ORDER BY lease_expires_at, id LIMIT ?`, apppki.CRLPublicationStatusPending,
			eligibleAt.UTC().Format(time.RFC3339Nano), updatedBefore.UTC().Format(time.RFC3339Nano), limit)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pending crl publication rows", rows.Close()) }()
		result := make([]apppki.CRLPublicationIntent, 0, limit)
		for rows.Next() {
			intent, err := s.loadCRLPublication(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, intent)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) ClaimCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	expected apppki.CRLPublicationOwnership,
	ownerToken string,
	claimedAt time.Time,
) (apppki.CRLPublicationIntent, bool, error) {
	var result apppki.CRLPublicationIntent
	var claimed bool
	err := s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := id.Validate(); err != nil {
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
		defer func() { logSQLiteRollback("rollback pki crl publication claim", tx.Rollback()) }()
		intent, err := s.loadCRLPublication(ctx, tx.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, id))
		if err != nil {
			return err
		}
		claimTime := claimedAt.UTC().Truncate(time.Second)
		if apppki.ValidateCRLPublicationOwnership(intent, expected) != nil || claimTime.Before(intent.LeaseExpiresAt) {
			result = intent.Clone()
			return nil
		}
		claimedIntent, err := apppki.ClaimCRLPublicationIntent(intent, ownerToken, claimTime)
		if err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, claimedIntent)
		if err != nil {
			return err
		}
		if err := updateCRLPublication(ctx, tx, intent.Ownership(), claimedIntent, encoded, metadata); err != nil {
			return err
		}
		if err := commitCRLTransaction(ctx, tx); err != nil {
			return err
		}
		result = claimedIntent.Clone()
		claimed = true
		return nil
	})
	return result, claimed, err
}

func (s PKIStore) StartCRLPublicationSigning(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	startedAt time.Time,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	return s.transitionCRLPublication(ctx, id, ownership, &audit, func(intent apppki.CRLPublicationIntent) (apppki.CRLPublicationIntent, error) {
		if err := apppki.ValidateCRLSigningAttemptAudit(intent, audit); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		if !audit.CreatedAt.UTC().Truncate(time.Second).Equal(startedAt.UTC().Truncate(time.Second)) {
			return apppki.CRLPublicationIntent{}, errors.New("pki sqlite: crl signing start and audit times differ")
		}
		return apppki.StartCRLPublicationSigningIntent(intent, startedAt)
	})
}

func (s PKIStore) RenewCRLPublicationLease(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	renewedAt time.Time,
) (apppki.CRLPublicationIntent, error) {
	return s.transitionCRLPublication(ctx, id, ownership, nil, func(intent apppki.CRLPublicationIntent) (apppki.CRLPublicationIntent, error) {
		return apppki.RenewCRLPublicationLeaseIntent(intent, renewedAt)
	})
}

func (s PKIStore) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	return s.transitionCRLPublication(ctx, id, ownership, &audit, func(intent apppki.CRLPublicationIntent) (apppki.CRLPublicationIntent, error) {
		if err := apppki.ValidateCRLSigningConfirmedAudit(intent, checkpoint, audit); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		return apppki.CheckpointCRLPublicationSignedIntent(intent, checkpoint)
	})
}

func (s PKIStore) transitionCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	audit *apppki.AuditRecord,
	transition func(apppki.CRLPublicationIntent) (apppki.CRLPublicationIntent, error),
) (apppki.CRLPublicationIntent, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.CRLPublicationIntent, error) {
		if err := id.Validate(); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		defer func() { logSQLiteRollback("rollback pki crl publication transition", tx.Rollback()) }()
		intent, err := s.loadCRLPublication(ctx, tx.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, id))
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		updated, err := transition(intent)
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, updated)
		if err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		if err := updateCRLPublication(ctx, tx, intent.Ownership(), updated, encoded, metadata); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		if audit != nil {
			if err := appendApplicationPKIAudit(ctx, tx, *audit); err != nil {
				return apppki.CRLPublicationIntent{}, err
			}
		}
		if err := commitCRLTransaction(ctx, tx); err != nil {
			return apppki.CRLPublicationIntent{}, err
		}
		return updated.Clone(), nil
	})
}

func (s PKIStore) CompleteCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	generation domainpki.CRLGeneration,
	audit apppki.AuditRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		if err := generation.Validate(); err != nil {
			return err
		}
		generationJSON, generationMetadata, err := s.authenticateJSON(ctx, generation)
		if err != nil {
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
		defer func() { logSQLiteRollback("rollback pki crl publication completion", tx.Rollback()) }()
		intent, err := s.loadCRLPublication(ctx, tx.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
			return err
		}
		if err := apppki.ValidateCRLPublicationCompletion(intent, generation); err != nil {
			return err
		}
		if err := apppki.ValidateCRLPublicationAudit(intent, generation, audit); err != nil {
			return err
		}
		completed, err := apppki.CompleteCRLPublicationIntent(intent, audit.CreatedAt)
		if err != nil {
			return err
		}
		completedJSON, completedMetadata, err := s.authenticateJSON(ctx, completed)
		if err != nil {
			return err
		}
		if err := insertCRLGeneration(ctx, tx, generation, generationJSON, generationMetadata); err != nil {
			return err
		}
		if err := updateCRLPublication(ctx, tx, intent.Ownership(), completed, completedJSON, completedMetadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitCRLTransaction(ctx, tx)
	})
}

func (s PKIStore) FailCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	failure string,
	failedAt time.Time,
	stage apppki.CRLPublicationFailureStage,
	audit apppki.AuditRecord,
) error {
	return s.protector.WithStableKeyEpoch(ctx, func() error {
		db, err := s.store.open(ctx)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { logSQLiteRollback("rollback pki crl publication failure", tx.Rollback()) }()
		intent, err := s.loadCRLPublication(ctx, tx.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if err := apppki.ValidateCRLPublicationOwnership(intent, ownership); err != nil {
			return err
		}
		if err := apppki.ValidateCRLPublicationFailureAudit(intent, stage, audit); err != nil {
			return err
		}
		failed, err := apppki.FailCRLPublicationIntent(intent, failure, failedAt)
		if err != nil {
			return err
		}
		encoded, metadata, err := s.authenticateJSON(ctx, failed)
		if err != nil {
			return err
		}
		if err := updateCRLPublication(ctx, tx, intent.Ownership(), failed, encoded, metadata); err != nil {
			return err
		}
		if err := appendApplicationPKIAudit(ctx, tx, audit); err != nil {
			return err
		}
		return commitCRLTransaction(ctx, tx)
	})
}

func commitCRLTransaction(ctx context.Context, tx *sql.Tx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func (s PKIStore) CRLGeneration(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.CRLGeneration, error) {
		if err := id.Validate(); err != nil {
			return domainpki.CRLGeneration{}, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return domainpki.CRLGeneration{}, err
		}
		return s.loadCRLGeneration(ctx, db.QueryRowContext(ctx, crlGenerationSelect+` WHERE id = ?`, id))
	})
}

func (s PKIStore) CRLGenerations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.CRLGeneration, error) {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if _, err := s.authority(ctx, id); err != nil {
			return nil, err
		}
		db, err := s.store.open(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, crlGenerationSelect+` WHERE authority_id = ? ORDER BY number, id`, id)
		if err != nil {
			return nil, err
		}
		defer func() { logSQLiteError("close pki crl generation rows", rows.Close()) }()
		result := make([]domainpki.CRLGeneration, 0)
		for rows.Next() {
			generation, err := s.loadCRLGeneration(ctx, rows)
			if err != nil {
				return nil, err
			}
			result = append(result, generation)
		}
		return result, rows.Err()
	})
}

func (s PKIStore) loadAuthorityRevocationsTx(ctx context.Context, tx *sql.Tx, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	rows, err := tx.QueryContext(ctx, revocationSelect+` WHERE issuer_authority_id = ? ORDER BY recorded_at, id`, id)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki crl snapshot rows", rows.Close()) }()
	result := make([]domainpki.Revocation, 0)
	for rows.Next() {
		revocation, err := s.loadRevocation(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, revocation)
	}
	return result, rows.Err()
}

func insertCRLPublication(ctx context.Context, tx *sql.Tx, intent apppki.CRLPublicationIntent, encoded []byte, metadata apppki.ProtectedMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_crl_publication_intents(
	id, idempotency_key, request_sha256, crl_generation_id, authority_id, issuer_generation_id,
	number, this_update, next_update, signing_backend_id, signing_backend_version,
	signing_backend_package_digest, signing_backend_capability_hash, status, phase, owner_token,
	signature_algorithm, revision, lease_expires_at, result_crl_generation_id,
	signed_fingerprint_sha256, signed_signature_algorithm, signed_provider_operation_ref, signed_crl_der, signed_at,
	failure, intent_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		intent.ID, intent.IdempotencyKey, intent.RequestSHA256, intent.CRLGenerationID,
		intent.AuthorityID, intent.IssuerGenerationID, intent.Number,
		intent.ThisUpdate.Format(time.RFC3339Nano), intent.NextUpdate.Format(time.RFC3339Nano),
		intent.SigningBackendID, intent.SigningBackendVersion, intent.SigningBackendPackageDigest,
		intent.SigningBackendCapabilityHash, intent.Status, intent.Phase, intent.OwnerToken, intent.SignatureAlgorithm, intent.Revision,
		intent.LeaseExpiresAt.Format(time.RFC3339Nano), nullableString(string(intent.ResultCRLGenerationID)),
		checkpointFingerprint(intent.SignedCheckpoint), checkpointSignatureAlgorithm(intent.SignedCheckpoint),
		checkpointProviderOperationRef(intent.SignedCheckpoint), checkpointDER(intent.SignedCheckpoint),
		checkpointRecordedAt(intent.SignedCheckpoint), nullableString(intent.Failure), encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, intent.CreatedAt.Format(time.RFC3339Nano),
		intent.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: insert crl publication: %w", err)
	}
	return nil
}

func checkpointFingerprint(checkpoint *apppki.CRLSignedCheckpoint) any {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.FingerprintSHA256
}

func checkpointSignatureAlgorithm(checkpoint *apppki.CRLSignedCheckpoint) any {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.SignatureAlgorithm
}

func checkpointProviderOperationRef(checkpoint *apppki.CRLSignedCheckpoint) any {
	if checkpoint == nil || checkpoint.ProviderOperationRef == "" {
		return nil
	}
	return checkpoint.ProviderOperationRef
}

func checkpointDER(checkpoint *apppki.CRLSignedCheckpoint) any {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.CRLDER
}

func checkpointRecordedAt(checkpoint *apppki.CRLSignedCheckpoint) any {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.RecordedAt.Format(time.RFC3339Nano)
}

func updateCRLPublication(
	ctx context.Context,
	tx *sql.Tx,
	expected apppki.CRLPublicationOwnership,
	intent apppki.CRLPublicationIntent,
	encoded []byte,
	metadata apppki.ProtectedMetadata,
) error {
	result, err := tx.ExecContext(ctx, `
UPDATE pki_crl_publication_intents
SET status = ?, phase = ?, owner_token = ?, revision = ?, lease_expires_at = ?,
	result_crl_generation_id = ?, signed_fingerprint_sha256 = ?, signed_signature_algorithm = ?,
	signed_provider_operation_ref = ?, signed_crl_der = ?, signed_at = ?, failure = ?,
	intent_json = ?, metadata_schema_version = ?,
	metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?, updated_at = ?
WHERE id = ? AND status = ? AND owner_token = ? AND revision = ?`,
		intent.Status, intent.Phase, intent.OwnerToken, intent.Revision, intent.LeaseExpiresAt.Format(time.RFC3339Nano),
		nullableString(string(intent.ResultCRLGenerationID)), checkpointFingerprint(intent.SignedCheckpoint),
		checkpointSignatureAlgorithm(intent.SignedCheckpoint), checkpointProviderOperationRef(intent.SignedCheckpoint),
		checkpointDER(intent.SignedCheckpoint), checkpointRecordedAt(intent.SignedCheckpoint), nullableString(intent.Failure), encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		intent.UpdatedAt.Format(time.RFC3339Nano), intent.ID, apppki.CRLPublicationStatusPending,
		expected.OwnerToken, expected.Revision)
	if err != nil {
		return fmt.Errorf("pki sqlite: update crl publication: %w", err)
	}
	updated, err := casApplied(result)
	if err != nil {
		return err
	}
	if !updated {
		return apppki.ErrRevisionConflict
	}
	return nil
}

func insertCRLGeneration(ctx context.Context, tx *sql.Tx, generation domainpki.CRLGeneration, encoded []byte, metadata apppki.ProtectedMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_crl_generations(
	id, authority_id, issuer_generation_id, number, this_update, next_update,
	signature_algorithm, fingerprint_sha256, generation_json, metadata_schema_version, metadata_algorithm,
	metadata_key_version, metadata_tag, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generation.ID, generation.AuthorityID, generation.IssuerGenerationID, generation.Number,
		generation.ThisUpdate.Format(time.RFC3339Nano), generation.NextUpdate.Format(time.RFC3339Nano),
		generation.SignatureAlgorithm, generation.FingerprintSHA256, encoded, metadata.SchemaVersion, metadata.Algorithm,
		metadata.KeyVersion, metadata.Tag, generation.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: insert crl generation: %w", err)
	}
	return nil
}

func (s PKIStore) loadCRLPublication(ctx context.Context, row rowScanner) (apppki.CRLPublicationIntent, error) {
	var (
		id                           domainpki.CRLPublicationID
		idempotencyKey               string
		requestSHA256                string
		crlGenerationID              domainpki.CRLGenerationID
		authorityID                  domainpki.AuthorityID
		issuerGenerationID           domainpki.GenerationID
		number                       int64
		thisUpdate                   string
		nextUpdate                   string
		signingBackendID             domainpki.BackendID
		signingBackendVersion        string
		signingBackendPackageDigest  string
		signingBackendCapabilityHash string
		signatureAlgorithm           domainpki.SignatureAlgorithm
		status                       apppki.CRLPublicationStatus
		phase                        apppki.CRLPublicationPhase
		ownerToken                   string
		revision                     int64
		leaseExpiresAt               string
		resultCRLGenerationID        sql.NullString
		signedFingerprint            sql.NullString
		signedSignatureAlgorithm     sql.NullString
		signedProviderOperationRef   sql.NullString
		signedCRLDER                 []byte
		signedAt                     sql.NullString
		failure                      sql.NullString
		encoded                      []byte
		metadata                     apppki.ProtectedMetadata
		createdAt                    string
		updatedAt                    string
	)
	if err := row.Scan(&id, &idempotencyKey, &requestSHA256, &crlGenerationID, &authorityID,
		&issuerGenerationID, &number, &thisUpdate, &nextUpdate, &signingBackendID,
		&signingBackendVersion, &signingBackendPackageDigest, &signingBackendCapabilityHash,
		&signatureAlgorithm, &status, &phase, &ownerToken, &revision, &leaseExpiresAt, &resultCRLGenerationID,
		&signedFingerprint, &signedSignatureAlgorithm, &signedProviderOperationRef, &signedCRLDER, &signedAt, &failure,
		&encoded, &metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion,
		&metadata.Tag, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.CRLPublicationIntent{}, apppki.ErrNotFound
		}
		return apppki.CRLPublicationIntent{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return apppki.CRLPublicationIntent{}, fmt.Errorf("pki sqlite: verify crl publication metadata: %w", err)
	}
	var intent apppki.CRLPublicationIntent
	if err := json.Unmarshal(encoded, &intent); err != nil {
		return apppki.CRLPublicationIntent{}, fmt.Errorf("pki sqlite: decode crl publication: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return apppki.CRLPublicationIntent{}, fmt.Errorf("pki sqlite: validate crl publication: %w", err)
	}
	if number <= 0 || revision <= 0 || intent.ID != id || intent.IdempotencyKey != idempotencyKey ||
		intent.RequestSHA256 != requestSHA256 || intent.CRLGenerationID != crlGenerationID ||
		intent.AuthorityID != authorityID || intent.IssuerGenerationID != issuerGenerationID ||
		intent.Number != uint64(number) || intent.ThisUpdate.Format(time.RFC3339Nano) != thisUpdate ||
		intent.NextUpdate.Format(time.RFC3339Nano) != nextUpdate || intent.SigningBackendID != signingBackendID ||
		intent.SigningBackendVersion != signingBackendVersion ||
		intent.SigningBackendPackageDigest != signingBackendPackageDigest ||
		intent.SigningBackendCapabilityHash != signingBackendCapabilityHash || intent.Status != status || intent.Phase != phase ||
		intent.SignatureAlgorithm != signatureAlgorithm ||
		intent.OwnerToken != ownerToken || intent.Revision != uint64(revision) ||
		intent.LeaseExpiresAt.Format(time.RFC3339Nano) != leaseExpiresAt ||
		intent.ResultCRLGenerationID != domainpki.CRLGenerationID(nullString(resultCRLGenerationID)) ||
		!checkpointMatchesCanonicalColumns(intent.SignedCheckpoint, signedFingerprint, signedSignatureAlgorithm,
			signedProviderOperationRef, signedCRLDER, signedAt) ||
		intent.Failure != nullString(failure) || intent.CreatedAt.Format(time.RFC3339Nano) != createdAt ||
		intent.UpdatedAt.Format(time.RFC3339Nano) != updatedAt {
		return apppki.CRLPublicationIntent{}, errors.New("pki sqlite: crl publication json does not match canonical columns")
	}
	return intent.Clone(), nil
}

func checkpointMatchesCanonicalColumns(
	checkpoint *apppki.CRLSignedCheckpoint,
	fingerprint sql.NullString,
	signatureAlgorithm sql.NullString,
	providerOperationRef sql.NullString,
	encoded []byte,
	recordedAt sql.NullString,
) bool {
	if checkpoint == nil {
		return !fingerprint.Valid && !signatureAlgorithm.Valid && !providerOperationRef.Valid &&
			len(encoded) == 0 && !recordedAt.Valid
	}
	return fingerprint.Valid && fingerprint.String == checkpoint.FingerprintSHA256 &&
		signatureAlgorithm.Valid && signatureAlgorithm.String == string(checkpoint.SignatureAlgorithm) &&
		providerOperationRef.String == string(checkpoint.ProviderOperationRef) &&
		providerOperationRef.Valid == (checkpoint.ProviderOperationRef != "") &&
		bytes.Equal(encoded, checkpoint.CRLDER) && recordedAt.Valid &&
		recordedAt.String == checkpoint.RecordedAt.Format(time.RFC3339Nano)
}

func (s PKIStore) loadCRLGeneration(ctx context.Context, row rowScanner) (domainpki.CRLGeneration, error) {
	var (
		id                 domainpki.CRLGenerationID
		authorityID        domainpki.AuthorityID
		issuerGenerationID domainpki.GenerationID
		number             int64
		thisUpdate         string
		nextUpdate         string
		signatureAlgorithm domainpki.SignatureAlgorithm
		fingerprint        string
		encoded            []byte
		metadata           apppki.ProtectedMetadata
		createdAt          string
	)
	if err := row.Scan(&id, &authorityID, &issuerGenerationID, &number, &thisUpdate,
		&nextUpdate, &signatureAlgorithm, &fingerprint, &encoded, &metadata.SchemaVersion, &metadata.Algorithm,
		&metadata.KeyVersion, &metadata.Tag, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.CRLGeneration{}, apppki.ErrNotFound
		}
		return domainpki.CRLGeneration{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.CRLGeneration{}, fmt.Errorf("pki sqlite: verify crl generation metadata: %w", err)
	}
	var generation domainpki.CRLGeneration
	if err := json.Unmarshal(encoded, &generation); err != nil {
		return domainpki.CRLGeneration{}, fmt.Errorf("pki sqlite: decode crl generation: %w", err)
	}
	if err := generation.Validate(); err != nil {
		return domainpki.CRLGeneration{}, fmt.Errorf("pki sqlite: validate crl generation: %w", err)
	}
	if number <= 0 || generation.ID != id || generation.AuthorityID != authorityID ||
		generation.IssuerGenerationID != issuerGenerationID || generation.Number != uint64(number) ||
		generation.ThisUpdate.Format(time.RFC3339Nano) != thisUpdate ||
		generation.NextUpdate.Format(time.RFC3339Nano) != nextUpdate ||
		generation.SignatureAlgorithm != signatureAlgorithm ||
		generation.FingerprintSHA256 != fingerprint || generation.CreatedAt.Format(time.RFC3339Nano) != createdAt {
		return domainpki.CRLGeneration{}, errors.New("pki sqlite: crl generation json does not match canonical columns")
	}
	return generation.Clone(), nil
}

func (s PKIStore) reauthenticateCRLMetadata(ctx context.Context, tx *sql.Tx, targetVersion string) error {
	publicationRows, err := tx.QueryContext(ctx, `
SELECT id, intent_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_crl_publication_intents ORDER BY id`)
	if err != nil {
		return err
	}
	publicationRecords, err := loadAuthenticatedMetadataRows(publicationRows)
	if err != nil {
		return err
	}
	for _, record := range publicationRecords {
		if _, err := s.loadCRLPublication(ctx, tx.QueryRowContext(ctx, crlPublicationSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate crl publication %q before rewrap: %w", record.id, err)
		}
		metadata, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "crl publication")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_crl_publication_intents
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update crl publication %q metadata authentication: %w", record.id, err)
		}
	}
	generationRows, err := tx.QueryContext(ctx, `
SELECT id, generation_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_crl_generations ORDER BY id`)
	if err != nil {
		return err
	}
	generationRecords, err := loadAuthenticatedMetadataRows(generationRows)
	if err != nil {
		return err
	}
	for _, record := range generationRecords {
		if _, err := s.loadCRLGeneration(ctx, tx.QueryRowContext(ctx, crlGenerationSelect+` WHERE id = ?`, record.id)); err != nil {
			return fmt.Errorf("pki sqlite: validate crl generation %q before rewrap: %w", record.id, err)
		}
		metadata, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, "crl generation")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_crl_generations
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag, record.id); err != nil {
			return fmt.Errorf("pki sqlite: update crl generation %q metadata authentication: %w", record.id, err)
		}
	}
	return nil
}
