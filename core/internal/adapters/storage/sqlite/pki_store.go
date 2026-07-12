package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const (
	pkiAuditAuthorityCreated  = "authority-created"
	pkiAuditGenerationCreated = "certificate-generation-created"
	pkiAuditKeyStored         = "key-envelope-stored"
	pkiAuditKeyDeleted        = "key-envelope-deleted"
	pkiAuditKeyRewrapped      = "key-envelope-rewrapped"
	pkiResourceAuthority      = "authority"
	pkiResourceGeneration     = "certificate-generation"
	pkiResourceKey            = "key"
	pkiStorageAuditActor      = "hoveld-storage"
	pkiStorageAuditOperation  = "pki-persistence"
	pkiStorageAuditOutcome    = "succeeded"
)

type PKIStore struct {
	store     Store
	protector apppki.KeyProtector
}

func NewPKIStore(workspacePath string, workspaceID workspace.ID, protector apppki.KeyProtector) (PKIStore, error) {
	if _, err := workspace.NewID(workspaceID.String()); err != nil {
		return PKIStore{}, err
	}
	if protector == nil {
		return PKIStore{}, errors.New("pki sqlite: key protector is required")
	}
	if protector.WorkspaceID() != workspaceID {
		return PKIStore{}, errors.New("pki sqlite: key protector belongs to a different workspace")
	}
	return PKIStore{store: NewStore(workspacePath), protector: protector}, nil
}

func (s PKIStore) WorkspaceID() workspace.ID {
	return s.protector.WorkspaceID()
}

func (s PKIStore) WorkspacePath() string {
	return s.store.workspacePath
}

// Close releases the shared workspace database handle after callers have
// stopped all PKI operations.
func (s PKIStore) Close() error {
	return s.store.Close()
}

func (s PKIStore) Authority(ctx context.Context, id domainpki.AuthorityID) (domainpki.Authority, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.Authority, error) {
		return s.authority(ctx, id)
	})
}

func (s PKIStore) authority(ctx context.Context, id domainpki.AuthorityID) (domainpki.Authority, error) {
	if err := id.Validate(); err != nil {
		return domainpki.Authority{}, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return domainpki.Authority{}, err
	}
	authority, err := s.loadAuthority(ctx, db.QueryRowContext(ctx, authoritySelect+` WHERE id = ?`, id))
	if err != nil {
		return domainpki.Authority{}, err
	}
	if authority.ID != id {
		return domainpki.Authority{}, errors.New("pki sqlite: loaded an unexpected authority")
	}
	return authority, nil
}

func (s PKIStore) Authorities(ctx context.Context) ([]domainpki.Authority, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.Authority, error) {
		return s.authorities(ctx)
	})
}

func (s PKIStore) authorities(ctx context.Context) ([]domainpki.Authority, error) {
	db, err := s.store.open(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, authoritySelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki authority rows", rows.Close()) }()
	result := make([]domainpki.Authority, 0)
	for rows.Next() {
		authority, err := s.loadAuthority(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, authority)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s PKIStore) Generation(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (domainpki.CertificateGeneration, error) {
		return s.generation(ctx, id)
	})
}

func (s PKIStore) generation(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	if err := id.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	return s.loadGeneration(ctx, db.QueryRowContext(ctx, generationSelect+` WHERE id = ?`, id))
}

func (s PKIStore) Generations(ctx context.Context, id domainpki.CertificateID) ([]domainpki.CertificateGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.CertificateGeneration, error) {
		return s.generations(ctx, id)
	})
}

func (s PKIStore) generations(ctx context.Context, id domainpki.CertificateID) ([]domainpki.CertificateGeneration, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, generationSelect+` WHERE certificate_id = ? ORDER BY generation`, id)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki generation rows", rows.Close()) }()
	result := make([]domainpki.CertificateGeneration, 0)
	for rows.Next() {
		generation, err := s.loadGeneration(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, generation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, apppki.ErrNotFound
	}
	return result, nil
}

func (s PKIStore) CertificateGenerations(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() ([]domainpki.CertificateGeneration, error) {
		return s.certificateGenerations(ctx)
	})
}

func (s PKIStore) certificateGenerations(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	db, err := s.store.open(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, generationSelect+` ORDER BY certificate_id, generation, id`)
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki certificate generation rows", rows.Close()) }()
	result := make([]domainpki.CertificateGeneration, 0)
	for rows.Next() {
		generation, err := s.loadGeneration(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, generation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s PKIStore) protectAndVerify(ctx context.Context, validated apppki.ValidatedKeyMaterial) (apppki.ProtectedKeyMaterial, error) {
	material := validated.Material()
	defer clear(material.PrivateKeyPKCS8)
	if err := material.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	protected, err := s.protector.Seal(ctx, material)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	if err := protected.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	opened, err := s.protector.Open(ctx, protected)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki sqlite: verify protected key envelope: %w", err)
	}
	defer clear(opened.PrivateKeyPKCS8)
	if !validated.Matches(opened) {
		return apppki.ProtectedKeyMaterial{}, errors.New("pki sqlite: key protector changed validated key material")
	}
	return protected.Clone(), nil
}

func insertProtectedKey(ctx context.Context, tx *sql.Tx, protected apppki.ProtectedKeyMaterial) error {
	if err := protected.Validate(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO pki_key_envelopes(key_id, algorithm, schema_version, cipher, key_version, nonce, ciphertext, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, protected.KeyID, protected.Algorithm, protected.SchemaVersion, protected.Cipher,
		protected.KeyVersion, protected.Nonce, protected.Ciphertext, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("pki sqlite: store key envelope: %w", err)
	}
	return nil
}

func (s PKIStore) LoadKey(ctx context.Context, id domainpki.KeyID) (apppki.KeyMaterial, error) {
	return withStableKeyEpochResult(ctx, s.protector, func() (apppki.KeyMaterial, error) {
		return s.loadKey(ctx, id)
	})
}

func (s PKIStore) loadKey(ctx context.Context, id domainpki.KeyID) (apppki.KeyMaterial, error) {
	if err := id.Validate(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return apppki.KeyMaterial{}, err
	}
	protected := apppki.ProtectedKeyMaterial{KeyID: id}
	if err := db.QueryRowContext(ctx, `
SELECT algorithm, schema_version, cipher, key_version, nonce, ciphertext
FROM pki_key_envelopes WHERE key_id = ?`, id).Scan(&protected.Algorithm, &protected.SchemaVersion, &protected.Cipher, &protected.KeyVersion, &protected.Nonce, &protected.Ciphertext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apppki.KeyMaterial{}, apppki.ErrNotFound
		}
		return apppki.KeyMaterial{}, err
	}
	material, err := s.protector.Open(ctx, protected)
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki sqlite: open key envelope: %w", err)
	}
	// Open transfers ownership of the decrypted material to this store. Transfer
	// that ownership again to the caller rather than retaining an uncleared
	// duplicate of the private key in this stack frame.
	return material, nil
}

func withStableKeyEpochResult[T any](ctx context.Context, protector apppki.KeyProtector, operation func() (T, error)) (T, error) {
	var result T
	err := protector.WithStableKeyEpoch(ctx, func() error {
		var operationErr error
		result, operationErr = operation()
		return operationErr
	})
	return result, err
}

func (s PKIStore) DeleteKey(ctx context.Context, id domainpki.KeyID) error {
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
	defer func() { logSQLiteRollback("rollback pki key deletion", tx.Rollback()) }()
	result, err := tx.ExecContext(ctx, `DELETE FROM pki_key_envelopes WHERE key_id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return apppki.ErrNotFound
	}
	if affected != 1 {
		return errors.New("pki sqlite: key deletion affected an unexpected number of rows")
	}
	if err := appendPKIAudit(ctx, tx, pkiAuditKeyDeleted, pkiResourceKey, string(id)); err != nil {
		return err
	}
	return tx.Commit()
}

// RewrapKeys decrypts every stored key with its recorded master-key version
// and seals it with the provider's active version in one transaction. The
// provider must retain old versions until this operation commits.
func (s PKIStore) RewrapKeys(ctx context.Context) (int, error) {
	targetVersion, err := s.protector.ActiveKeyVersion(ctx)
	if err != nil {
		return 0, err
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { logSQLiteRollback("rollback pki key rewrap", tx.Rollback()) }()
	rows, err := tx.QueryContext(ctx, `
SELECT key_id, algorithm, schema_version, cipher, key_version, nonce, ciphertext
FROM pki_key_envelopes ORDER BY key_id`)
	if err != nil {
		return 0, err
	}
	protectedKeys := make([]apppki.ProtectedKeyMaterial, 0)
	for rows.Next() {
		var protected apppki.ProtectedKeyMaterial
		if err := rows.Scan(&protected.KeyID, &protected.Algorithm, &protected.SchemaVersion, &protected.Cipher, &protected.KeyVersion, &protected.Nonce, &protected.Ciphertext); err != nil {
			closeErr := rows.Close()
			return 0, errors.Join(err, closeErr)
		}
		protectedKeys = append(protectedKeys, protected)
	}
	if err := rows.Err(); err != nil {
		closeErr := rows.Close()
		return 0, errors.Join(err, closeErr)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, protected := range protectedKeys {
		rewrapped, err := s.rewrapKey(ctx, protected, targetVersion)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_key_envelopes
SET schema_version = ?, cipher = ?, key_version = ?, nonce = ?, ciphertext = ?
WHERE key_id = ?`, rewrapped.SchemaVersion, rewrapped.Cipher, rewrapped.KeyVersion,
			rewrapped.Nonce, rewrapped.Ciphertext, rewrapped.KeyID); err != nil {
			return 0, fmt.Errorf("pki sqlite: update rewrapped key %q: %w", protected.KeyID, err)
		}
		if err := appendPKIAudit(ctx, tx, pkiAuditKeyRewrapped, pkiResourceKey, string(protected.KeyID)); err != nil {
			return 0, err
		}
	}
	metadataRows, err := tx.QueryContext(ctx, `
SELECT id, generation_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_certificate_generations ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type metadataRecord struct {
		id        domainpki.GenerationID
		encoded   []byte
		protected apppki.ProtectedMetadata
	}
	metadataRecords := make([]metadataRecord, 0)
	for metadataRows.Next() {
		var record metadataRecord
		if err := metadataRows.Scan(&record.id, &record.encoded, &record.protected.SchemaVersion,
			&record.protected.Algorithm, &record.protected.KeyVersion, &record.protected.Tag); err != nil {
			closeErr := metadataRows.Close()
			return 0, errors.Join(err, closeErr)
		}
		metadataRecords = append(metadataRecords, record)
	}
	if err := metadataRows.Err(); err != nil {
		closeErr := metadataRows.Close()
		return 0, errors.Join(err, closeErr)
	}
	if err := metadataRows.Close(); err != nil {
		return 0, err
	}
	for _, record := range metadataRecords {
		if err := s.protector.VerifyMetadata(ctx, record.encoded, record.protected); err != nil {
			return 0, fmt.Errorf("pki sqlite: verify generation %q metadata for rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.protector.AuthenticateMetadataWithVersion(ctx, record.encoded, targetVersion)
		if err != nil {
			return 0, fmt.Errorf("pki sqlite: authenticate generation %q metadata for rewrap: %w", record.id, err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_certificate_generations
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return 0, fmt.Errorf("pki sqlite: update generation %q metadata authentication: %w", record.id, err)
		}
	}
	authorityRows, err := tx.QueryContext(ctx, `
SELECT id, authority_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_authorities ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type authorityMetadataRecord struct {
		id        domainpki.AuthorityID
		encoded   []byte
		protected apppki.ProtectedMetadata
	}
	authorityMetadataRecords := make([]authorityMetadataRecord, 0)
	for authorityRows.Next() {
		var record authorityMetadataRecord
		if err := authorityRows.Scan(&record.id, &record.encoded, &record.protected.SchemaVersion,
			&record.protected.Algorithm, &record.protected.KeyVersion, &record.protected.Tag); err != nil {
			closeErr := authorityRows.Close()
			return 0, errors.Join(err, closeErr)
		}
		authorityMetadataRecords = append(authorityMetadataRecords, record)
	}
	if err := authorityRows.Err(); err != nil {
		closeErr := authorityRows.Close()
		return 0, errors.Join(err, closeErr)
	}
	if err := authorityRows.Close(); err != nil {
		return 0, err
	}
	for _, record := range authorityMetadataRecords {
		if err := s.protector.VerifyMetadata(ctx, record.encoded, record.protected); err != nil {
			return 0, fmt.Errorf("pki sqlite: verify authority %q metadata for rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.protector.AuthenticateMetadataWithVersion(ctx, record.encoded, targetVersion)
		if err != nil {
			return 0, fmt.Errorf("pki sqlite: authenticate authority %q metadata for rewrap: %w", record.id, err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_authorities
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return 0, fmt.Errorf("pki sqlite: update authority %q metadata authentication: %w", record.id, err)
		}
	}
	issuanceRows, err := tx.QueryContext(ctx, `
SELECT id, intent_json, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag
FROM pki_issuance_intents ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type issuanceMetadataRecord struct {
		id        domainpki.IssuanceID
		encoded   []byte
		protected apppki.ProtectedMetadata
	}
	issuanceMetadataRecords := make([]issuanceMetadataRecord, 0)
	for issuanceRows.Next() {
		var record issuanceMetadataRecord
		if err := issuanceRows.Scan(&record.id, &record.encoded, &record.protected.SchemaVersion,
			&record.protected.Algorithm, &record.protected.KeyVersion, &record.protected.Tag); err != nil {
			closeErr := issuanceRows.Close()
			return 0, errors.Join(err, closeErr)
		}
		issuanceMetadataRecords = append(issuanceMetadataRecords, record)
	}
	if err := issuanceRows.Err(); err != nil {
		closeErr := issuanceRows.Close()
		return 0, errors.Join(err, closeErr)
	}
	if err := issuanceRows.Close(); err != nil {
		return 0, err
	}
	for _, record := range issuanceMetadataRecords {
		if err := s.protector.VerifyMetadata(ctx, record.encoded, record.protected); err != nil {
			return 0, fmt.Errorf("pki sqlite: verify issuance %q metadata for rewrap: %w", record.id, err)
		}
		reauthenticated, err := s.protector.AuthenticateMetadataWithVersion(ctx, record.encoded, targetVersion)
		if err != nil {
			return 0, fmt.Errorf("pki sqlite: authenticate issuance %q metadata for rewrap: %w", record.id, err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE pki_issuance_intents
SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, reauthenticated.SchemaVersion, reauthenticated.Algorithm, reauthenticated.KeyVersion,
			reauthenticated.Tag, record.id); err != nil {
			return 0, fmt.Errorf("pki sqlite: update issuance %q metadata authentication: %w", record.id, err)
		}
	}
	if err := s.reauthenticateAssignmentMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateTrustSetMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateTrustSetGenerationMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateMutationMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateRevocationMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateCRLMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateOperationMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateCredentialStampMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	if err := s.reauthenticateCredentialExecutionMetadata(ctx, tx, targetVersion); err != nil {
		return 0, err
	}
	versions, err := referencedMasterKeyVersions(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("pki sqlite: verify rewrapped master-key references: %w", err)
	}
	for _, version := range versions {
		if version != targetVersion {
			return 0, fmt.Errorf(
				"pki sqlite: rewrap left master-key version %q referenced; want only %q",
				version, targetVersion,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(protectedKeys), nil
}

func (s PKIStore) ReferencedMasterKeyVersions(ctx context.Context) ([]string, error) {
	db, err := s.store.open(ctx)
	if err != nil {
		return nil, err
	}
	return referencedMasterKeyVersions(ctx, db)
}

type rowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func referencedMasterKeyVersions(ctx context.Context, queryer rowsQueryer) ([]string, error) {
	var query strings.Builder
	query.WriteString("SELECT key_version FROM pki_key_envelopes")
	for _, table := range authenticatedPKIMetadataTableNames() {
		query.WriteString("\nUNION SELECT metadata_key_version FROM ")
		query.WriteString(table)
	}
	rows, err := queryer.QueryContext(ctx, query.String())
	if err != nil {
		return nil, err
	}
	defer func() { logSQLiteError("close pki master-key version rows", rows.Close()) }()
	versions := make([]string, 0)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		if err := apppki.ValidateKeyVersion(version); err != nil {
			return nil, fmt.Errorf("pki sqlite: invalid referenced master-key version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(versions)
	return versions, nil
}

// authenticatedPKIMetadataTableNames is the complete inventory of PKI tables
// whose JSON records are authenticated by a workspace master key. Keeping the
// inventory in one place makes retirement checks fail closed as new ledgers are
// added. The schema parity test must be updated with every migration that adds
// another metadata_key_version column.
func authenticatedPKIMetadataTableNames() []string {
	return []string{
		"pki_assignments",
		"pki_authorities",
		"pki_certificate_generations",
		"pki_consumer_acknowledgements",
		"pki_credential_executions",
		"pki_credential_stamps",
		"pki_crl_generations",
		"pki_crl_publication_intents",
		"pki_issuance_intents",
		"pki_mutations",
		"pki_operations",
		"pki_revocations",
		"pki_trust_set_generations",
		"pki_trust_sets",
	}
}

func (s PKIStore) reauthenticateCredentialStampMetadata(
	ctx context.Context,
	tx *sql.Tx,
	targetVersion string,
) error {
	return s.reauthenticateCredentialLedgerMetadata(
		ctx,
		tx,
		targetVersion,
		"pki_credential_stamps",
		"stamp_json",
		"credential stamp",
		func(ctx context.Context, id string) error {
			_, err := s.loadCredentialStamp(
				ctx,
				tx.QueryRowContext(ctx, credentialStampSelect+` WHERE id = ?`, id),
			)
			return err
		},
	)
}

func (s PKIStore) reauthenticateCredentialExecutionMetadata(
	ctx context.Context,
	tx *sql.Tx,
	targetVersion string,
) error {
	return s.reauthenticateCredentialLedgerMetadata(
		ctx,
		tx,
		targetVersion,
		"pki_credential_executions",
		"execution_json",
		"credential execution",
		func(ctx context.Context, id string) error {
			_, err := s.loadCredentialExecution(
				ctx,
				tx.QueryRowContext(ctx, credentialExecutionSelect+` WHERE id = ?`, id),
			)
			return err
		},
	)
}

func (s PKIStore) reauthenticateCredentialLedgerMetadata(
	ctx context.Context,
	tx *sql.Tx,
	targetVersion string,
	table string,
	jsonColumn string,
	resource string,
	validate func(context.Context, string) error,
) error {
	query := fmt.Sprintf(
		"SELECT id, %s, metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag FROM %s ORDER BY id",
		jsonColumn,
		table,
	)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	records, err := loadAuthenticatedMetadataRows(rows)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := validate(ctx, record.id); err != nil {
			return fmt.Errorf("pki sqlite: validate %s %q before rewrap: %w", resource, record.id, err)
		}
		metadata, err := s.reauthenticateMetadataRecord(ctx, record, targetVersion, resource)
		if err != nil {
			return err
		}
		update := fmt.Sprintf(
			"UPDATE %s SET metadata_schema_version = ?, metadata_algorithm = ?, metadata_key_version = ?, metadata_tag = ? WHERE id = ?",
			table,
		)
		if _, err := tx.ExecContext(
			ctx,
			update,
			metadata.SchemaVersion,
			metadata.Algorithm,
			metadata.KeyVersion,
			metadata.Tag,
			record.id,
		); err != nil {
			return fmt.Errorf("pki sqlite: update %s %q metadata authentication: %w", resource, record.id, err)
		}
	}
	return nil
}

func (s PKIStore) rewrapKey(ctx context.Context, protected apppki.ProtectedKeyMaterial, targetVersion string) (apppki.ProtectedKeyMaterial, error) {
	material, err := s.protector.Open(ctx, protected)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki sqlite: open key %q for rewrap: %w", protected.KeyID, err)
	}
	defer clear(material.PrivateKeyPKCS8)
	rewrapped, err := s.protector.SealWithVersion(ctx, material, targetVersion)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki sqlite: seal key %q for rewrap: %w", protected.KeyID, err)
	}
	if err := rewrapped.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki sqlite: validate rewrapped key %q: %w", protected.KeyID, err)
	}
	if rewrapped.KeyVersion != targetVersion || rewrapped.KeyID != protected.KeyID || rewrapped.Algorithm != protected.Algorithm {
		return apppki.ProtectedKeyMaterial{}, errors.New("pki sqlite: rewrapped key metadata changed")
	}
	opened, err := s.protector.Open(ctx, rewrapped)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki sqlite: verify rewrapped key %q: %w", protected.KeyID, err)
	}
	defer clear(opened.PrivateKeyPKCS8)
	if !keyMaterialsEqual(material, opened) {
		return apppki.ProtectedKeyMaterial{}, errors.New("pki sqlite: rewrapped key material changed")
	}
	return rewrapped.Clone(), nil
}

func keyMaterialsEqual(left, right apppki.KeyMaterial) bool {
	return apppki.KeyMaterialsEqual(left, right)
}

func insertAuthority(ctx context.Context, tx *sql.Tx, authority domainpki.Authority, encoded []byte, metadata apppki.ProtectedMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_authorities(
	id, name, role, state, parent_authority_id, active_generation_id, authority_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, authority.ID, authority.Name, authority.Role, authority.State,
		nullableString(string(authority.ParentAuthorityID)), authority.ActiveGenerationID, encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		authority.CreatedAt.Format(time.RFC3339Nano), authority.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store authority: %w", err)
	}
	return nil
}

func insertGeneration(ctx context.Context, tx *sql.Tx, generation domainpki.CertificateGeneration, encoded []byte, metadata apppki.ProtectedMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_certificate_generations(
	id, certificate_id, generation, owning_authority_id, issuer_authority_id,
	issuer_generation_id, serial_scope_id, serial_number, state, key_id, fingerprint_sha256, generation_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, generation.ID, generation.CertificateID, generation.Generation,
		nullableString(string(generation.OwningAuthorityID)), nullableString(string(generation.IssuerAuthorityID)), nullableString(string(generation.IssuerGenerationID)),
		serialScope(generation), generation.Template.SerialNumber, generation.State, generation.KeyID, generation.FingerprintSHA256, encoded,
		metadata.SchemaVersion, metadata.Algorithm, metadata.KeyVersion, metadata.Tag,
		generation.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: store certificate generation: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

const authoritySelect = `
SELECT id, name, role, state, parent_authority_id, active_generation_id, authority_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at, updated_at
FROM pki_authorities`

func (s PKIStore) loadAuthority(ctx context.Context, row rowScanner) (domainpki.Authority, error) {
	var (
		storedID         domainpki.AuthorityID
		name             string
		role             domainpki.AuthorityRole
		state            domainpki.AuthorityState
		parentID         sql.NullString
		activeGeneration domainpki.GenerationID
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		createdAt        string
		updatedAt        string
	)
	if err := row.Scan(&storedID, &name, &role, &state, &parentID, &activeGeneration, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.Authority{}, apppki.ErrNotFound
		}
		return domainpki.Authority{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.Authority{}, fmt.Errorf("pki sqlite: verify authority metadata: %w", err)
	}
	var authority domainpki.Authority
	if err := json.Unmarshal(encoded, &authority); err != nil {
		return domainpki.Authority{}, fmt.Errorf("pki sqlite: decode authority: %w", err)
	}
	if err := authority.Validate(); err != nil {
		return domainpki.Authority{}, fmt.Errorf("pki sqlite: validate stored authority: %w", err)
	}
	if authority.ID != storedID || authority.Name != name || authority.Role != role || authority.State != state ||
		authority.ParentAuthorityID != domainpki.AuthorityID(nullString(parentID)) || authority.ActiveGenerationID != activeGeneration ||
		authority.CreatedAt.Format(time.RFC3339Nano) != createdAt || authority.UpdatedAt.Format(time.RFC3339Nano) != updatedAt {
		return domainpki.Authority{}, errors.New("pki sqlite: authority json does not match canonical columns")
	}
	return authority.Clone(), nil
}

const generationSelect = `
SELECT id, certificate_id, generation, owning_authority_id, issuer_authority_id,
	issuer_generation_id, serial_scope_id, serial_number, state, key_id, fingerprint_sha256, generation_json,
	metadata_schema_version, metadata_algorithm, metadata_key_version, metadata_tag, created_at
FROM pki_certificate_generations`

func (s PKIStore) loadGeneration(ctx context.Context, row rowScanner) (domainpki.CertificateGeneration, error) {
	var (
		id               domainpki.GenerationID
		certificateID    domainpki.CertificateID
		generationNumber int64
		owningAuthority  sql.NullString
		issuerAuthority  sql.NullString
		issuerGeneration sql.NullString
		serialScopeID    domainpki.GenerationID
		serialNumber     domainpki.SerialNumber
		state            domainpki.CertificateState
		keyID            domainpki.KeyID
		fingerprint      string
		encoded          []byte
		metadata         apppki.ProtectedMetadata
		createdAt        string
	)
	if err := row.Scan(&id, &certificateID, &generationNumber, &owningAuthority, &issuerAuthority,
		&issuerGeneration, &serialScopeID, &serialNumber, &state, &keyID, &fingerprint, &encoded,
		&metadata.SchemaVersion, &metadata.Algorithm, &metadata.KeyVersion, &metadata.Tag, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domainpki.CertificateGeneration{}, apppki.ErrNotFound
		}
		return domainpki.CertificateGeneration{}, err
	}
	if err := s.protector.VerifyMetadata(ctx, encoded, metadata); err != nil {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki sqlite: verify certificate generation metadata: %w", err)
	}
	generation, err := decodeGeneration(encoded)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if generationNumber <= 0 || generation.ID != id || generation.CertificateID != certificateID || generation.Generation != uint64(generationNumber) ||
		generation.OwningAuthorityID != domainpki.AuthorityID(nullString(owningAuthority)) ||
		generation.IssuerAuthorityID != domainpki.AuthorityID(nullString(issuerAuthority)) ||
		generation.IssuerGenerationID != domainpki.GenerationID(nullString(issuerGeneration)) ||
		serialScope(generation) != serialScopeID || generation.Template.SerialNumber != serialNumber ||
		generation.State != state || generation.KeyID != keyID || generation.FingerprintSHA256 != fingerprint ||
		generation.CreatedAt.Format(time.RFC3339Nano) != createdAt {
		return domainpki.CertificateGeneration{}, errors.New("pki sqlite: certificate generation json does not match canonical columns")
	}
	return generation, nil
}

func serialScope(generation domainpki.CertificateGeneration) domainpki.GenerationID {
	if generation.IssuerGenerationID != "" {
		return generation.IssuerGenerationID
	}
	return generation.ID
}

func decodeGeneration(encoded []byte) (domainpki.CertificateGeneration, error) {
	var generation domainpki.CertificateGeneration
	if err := json.Unmarshal(encoded, &generation); err != nil {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki sqlite: decode certificate generation: %w", err)
	}
	if err := generation.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, fmt.Errorf("pki sqlite: validate stored certificate generation: %w", err)
	}
	return generation.Clone(), nil
}

func nullString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func appendPKIAudit(ctx context.Context, tx *sql.Tx, action, resourceType, resourceID string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO pki_audit_events(
	event_id, action, outcome, actor_id, operation_id, correlation_id,
	resource_type, resource_id, details_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, nil, action, pkiStorageAuditOutcome, pkiStorageAuditActor,
		pkiStorageAuditOperation, resourceID, resourceType, resourceID, `{}`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("pki sqlite: append audit event: %w", err)
	}
	return nil
}

func (s PKIStore) AppendPKIAudit(ctx context.Context, record apppki.AuditRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	details, err := json.Marshal(record.Details)
	if err != nil {
		return fmt.Errorf("pki sqlite: encode audit details: %w", err)
	}
	db, err := s.store.open(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
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

var _ apppki.Persistence = PKIStore{}
var _ apppki.AuditSink = PKIStore{}
