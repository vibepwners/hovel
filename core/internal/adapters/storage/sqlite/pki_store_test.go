package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

const testEntropyBytes = 1 << 20

func newTestEntropy(seed uint64) *bytes.Reader {
	data := make([]byte, testEntropyBytes)
	var input [16]byte
	for offset, counter := 0, uint64(0); offset < len(data); offset, counter = offset+sha256.Size, counter+1 {
		binary.LittleEndian.PutUint64(input[:8], seed)
		binary.LittleEndian.PutUint64(input[8:], counter)
		digest := sha256.Sum256(input[:])
		copy(data[offset:], digest[:])
	}
	return bytes.NewReader(data)
}

func domainWorkspaceID(t *testing.T, value string) workspace.ID {
	t.Helper()
	id, err := workspace.NewID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newTestPKIStore(
	t *testing.T,
	workspacePath string,
	workspaceID workspace.ID,
	protector apppki.KeyProtector,
) PKIStore {
	t.Helper()
	store, err := NewPKIStore(workspacePath, workspaceID, protector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close sqlite PKI test store: %v", err)
		}
	})
	return store
}

type testMasterKeyProvider struct {
	key infrapki.MasterKey
}

type trackingKeyProtector struct {
	apppki.KeyProtector
	openedPrivateKey []byte
}

func (p *trackingKeyProtector) Open(
	ctx context.Context,
	protected apppki.ProtectedKeyMaterial,
) (apppki.KeyMaterial, error) {
	material, err := p.KeyProtector.Open(ctx, protected)
	if err == nil {
		p.openedPrivateKey = material.PrivateKeyPKCS8
	}
	return material, err
}

type rotatingTestMasterKeyProvider struct {
	active string
	keys   map[string]infrapki.MasterKey
}

type controlledMasterKeyProvider struct {
	mu             sync.Mutex
	active         string
	keys           map[string]infrapki.MasterKey
	switchOnLookup bool
	switchTo       string
	failVersion    string
	failAfter      int
	versionCalls   int
}

func (p *controlledMasterKeyProvider) ActiveMasterKey(context.Context) (string, infrapki.MasterKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.keys[p.active]
	if !ok {
		return "", infrapki.MasterKey{}, errors.New("active controlled master key is unavailable")
	}
	return p.active, key, nil
}

func (p *controlledMasterKeyProvider) MasterKey(_ context.Context, version string) (infrapki.MasterKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.switchOnLookup {
		p.active = p.switchTo
		p.switchOnLookup = false
	}
	if version == p.failVersion {
		p.versionCalls++
		if p.failAfter > 0 && p.versionCalls >= p.failAfter {
			return infrapki.MasterKey{}, errors.New("injected controlled master-key failure")
		}
	}
	key, ok := p.keys[version]
	if !ok {
		return infrapki.MasterKey{}, errors.New("controlled master-key version is unavailable")
	}
	return key, nil
}

func (p *rotatingTestMasterKeyProvider) ActiveMasterKey(context.Context) (string, infrapki.MasterKey, error) {
	key, ok := p.keys[p.active]
	if !ok {
		return "", infrapki.MasterKey{}, errors.New("active test master key is unavailable")
	}
	return p.active, key, nil
}

func (p *rotatingTestMasterKeyProvider) MasterKey(_ context.Context, version string) (infrapki.MasterKey, error) {
	key, ok := p.keys[version]
	if !ok {
		return infrapki.MasterKey{}, errors.New("test master key version is unavailable")
	}
	return key, nil
}

func (p testMasterKeyProvider) ActiveMasterKey(context.Context) (string, infrapki.MasterKey, error) {
	return "test-v1", p.key, nil
}

func (p testMasterKeyProvider) MasterKey(_ context.Context, version string) (infrapki.MasterKey, error) {
	if version != "test-v1" {
		return infrapki.MasterKey{}, errors.New("unknown test master-key version")
	}
	return p.key, nil
}

type pkiTestAuthorization struct{}

func (pkiTestAuthorization) AuditContext(context.Context) (apppki.AuditContext, error) {
	return apppki.AuditContext{ActorID: "sqlite-test", OperationID: "sqlite-operation", CorrelationID: "sqlite-correlation"}, nil
}

func (pkiTestAuthorization) AuthorizeSigning(context.Context, domainpki.AuthorityID, apppki.AuditContext) error {
	return nil
}

func (pkiTestAuthorization) UnlockSigning(_ context.Context, id domainpki.AuthorityID, duration time.Duration, scope apppki.AuditContext) (apppki.SigningLease, error) {
	if duration == 0 {
		duration = apppki.DefaultSigningLeaseDuration
	}
	grantedAt := time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)
	return apppki.SigningLease{AuthorityID: id, GrantedAt: grantedAt, ExpiresAt: grantedAt.Add(duration), ActorID: scope.ActorID, OperationID: scope.OperationID}, nil
}

func (pkiTestAuthorization) LockSigning(context.Context, domainpki.AuthorityID, apppki.AuditContext) error {
	return nil
}

func (pkiTestAuthorization) SigningLease(_ context.Context, id domainpki.AuthorityID, scope apppki.AuditContext) (apppki.SigningLease, bool, error) {
	grantedAt := time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)
	return apppki.SigningLease{AuthorityID: id, GrantedAt: grantedAt, ExpiresAt: grantedAt.Add(apppki.MaximumSigningLeaseDuration), ActorID: scope.ActorID, OperationID: scope.OperationID}, true, nil
}

func (pkiTestAuthorization) AuthorizePrivateKeyExport(context.Context, domainpki.GenerationID) error {
	return nil
}

func (pkiTestAuthorization) AuthorizeCRLPublicationReconciliation(context.Context, apppki.AuditContext) error {
	return nil
}

type pkiTestClock struct {
	now time.Time
}

func (c pkiTestClock) Now() time.Time {
	return c.now
}

func TestPKIStorePersistsEncryptedKeyAndAuthority(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x5a}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := domainWorkspaceID(t, "workspace-durable")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x44))
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "durable root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	loadedAuthority, err := store.Authority(t.Context(), created.Authority.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedGeneration, err := store.Generation(t.Context(), created.Generation.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedKey, err := store.LoadKey(t.Context(), created.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedAuthority.ID != created.Authority.ID || loadedGeneration.ID != created.Generation.ID || loadedKey.ID != created.Generation.KeyID {
		t.Fatalf("loaded pki state = authority %q generation %q key %q", loadedAuthority.ID, loadedGeneration.ID, loadedKey.ID)
	}
	authorities, err := store.Authorities(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	generations, err := store.CertificateGenerations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 1 || authorities[0].ID != created.Authority.ID || len(generations) != 1 || generations[0].ID != created.Generation.ID {
		t.Fatalf("listed pki state = authorities %#v, generations %#v", authorities, generations)
	}

	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := db.QueryRowContext(t.Context(), `SELECT ciphertext FROM pki_key_envelopes WHERE key_id = ?`, loadedKey.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	encodedPrivateKey := base64.StdEncoding.EncodeToString(loadedKey.PrivateKeyPKCS8)
	if bytes.Contains(ciphertext, loadedKey.PrivateKeyPKCS8) || strings.Contains(string(ciphertext), encodedPrivateKey) {
		t.Fatal("stored key envelope contains plaintext private key material")
	}
	var auditCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 5 {
		t.Fatalf("pki audit event count = %d, want 5", auditCount)
	}
	var applicationAuditCount int
	if err := db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM pki_audit_events
WHERE event_id IS NOT NULL AND actor_id = ? AND operation_id = ? AND correlation_id = ?`,
		"sqlite-test", "sqlite-operation", "sqlite-correlation").Scan(&applicationAuditCount); err != nil {
		t.Fatal(err)
	}
	if applicationAuditCount != 2 {
		t.Fatalf("application audit event count = %d, want 2", applicationAuditCount)
	}

	if _, err := db.ExecContext(t.Context(), `UPDATE pki_key_envelopes SET ciphertext = zeroblob(length(ciphertext)) WHERE key_id = ?`, loadedKey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadKey(t.Context(), loadedKey.ID); err == nil {
		t.Fatal("LoadKey() accepted tampered stored ciphertext")
	}
}

func TestPKIStorePersistsRenewalWithoutDuplicatingKey(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x58)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x59),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:lifecycle-root", Name: "SQLite lifecycle root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:lifecycle-leaf", IssuerAuthorityID: root.Authority.ID, Name: "sqlite.lifecycle.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "sqlite:lifecycle-renew", SourceGenerationID: original.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Generation.KeyID != original.KeyID {
		t.Fatalf("renewal key = %q, want %q", renewed.Generation.KeyID, original.KeyID)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var keyCount, generationCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_key_envelopes`).Scan(&keyCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_certificate_generations`).Scan(&generationCount); err != nil {
		t.Fatal(err)
	}
	if keyCount != 2 || generationCount != 3 {
		t.Fatalf("renewal inventory = %d keys/%d generations, want 2/3", keyCount, generationCount)
	}
	rotated, err := service.RotateCertificate(t.Context(), apppki.RotateCertificateRequest{
		IdempotencyKey: "sqlite:lifecycle-rotate", SourceGenerationID: renewed.Generation.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Generation.KeyID == original.KeyID {
		t.Fatal("rotation reused the original key")
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_key_envelopes`).Scan(&keyCount); err != nil {
		t.Fatal(err)
	}
	if keyCount != 3 {
		t.Fatalf("rotation key count = %d, want 3", keyCount)
	}
	var lifecycleAuditCount int
	if err := db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM pki_audit_events
WHERE event_id IS NOT NULL AND action IN (?, ?)`,
		apppki.AuditActionCertificateRenew, apppki.AuditActionCertificateRotate,
	).Scan(&lifecycleAuditCount); err != nil {
		t.Fatal(err)
	}
	if lifecycleAuditCount != 2 {
		t.Fatalf("lifecycle application audit count = %d, want 2", lifecycleAuditCount)
	}
}

func TestPKIStorePersistsRevocationAndAssignmentDegradation(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x60)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x61),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:revocation-root", Name: "SQLite revocation root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:revocation-leaf", IssuerAuthorityID: root.Authority.ID, Name: "sqlite-revocation.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "sqlite:revocation-bind", ID: "assignment-sqlite-revocation",
		Purpose: domainpki.PurposeTLSServer, ConsumerType: domainpki.ConsumerService,
		ConsumerID: "service-sqlite-revocation", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "sqlite:revocation-stage", AssignmentID: assignment.ID,
		GenerationID: leaf.ID, ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	activated, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "sqlite:revocation-activate", AssignmentID: assignment.ID,
		ExpectedRevision: staged.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.RevokeCertificate(t.Context(), apppki.RevokeCertificateRequest{
		IdempotencyKey: "sqlite:revocation-commit", GenerationID: leaf.ID,
		Reason: domainpki.RevocationReasonCessationOfOperation,
	})
	if err != nil {
		t.Fatal(err)
	}
	storedGeneration, err := store.Generation(t.Context(), leaf.ID)
	if err != nil || storedGeneration.State != domainpki.CertificateStateRevoked {
		t.Fatalf("Generation() = %#v, %v", storedGeneration, err)
	}
	storedRevocation, err := store.RevocationForGeneration(t.Context(), leaf.ID)
	if err != nil || storedRevocation != result.Revocation {
		t.Fatalf("RevocationForGeneration() = %#v, %v", storedRevocation, err)
	}
	storedAssignment, err := store.Assignment(t.Context(), assignment.ID)
	if err != nil || storedAssignment.State != domainpki.AssignmentStateDegraded ||
		storedAssignment.Revision != activated.Assignment.Revision+1 {
		t.Fatalf("Assignment() = %#v, %v", storedAssignment, err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var revocationCount, mutationCount, auditCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_revocations`).Scan(&revocationCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(
		t.Context(), `SELECT COUNT(*) FROM pki_mutations WHERE kind = ?`, apppki.MutationCertificateRevoke,
	).Scan(&mutationCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(
		t.Context(), `SELECT COUNT(*) FROM pki_audit_events WHERE action = ?`, apppki.AuditActionCertificateRevoke,
	).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if revocationCount != 1 || mutationCount != 1 || auditCount != 1 {
		t.Fatalf("revocation inventory = %d records/%d mutations/%d audits, want 1/1/1", revocationCount, mutationCount, auditCount)
	}
	crl, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "sqlite:crl-publish", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	loadedCRL, err := store.CRLGeneration(t.Context(), crl.Generation.ID)
	if err != nil || !bytes.Equal(loadedCRL.CRLDER, crl.Generation.CRLDER) {
		t.Fatalf("CRLGeneration() = %#v, %v", loadedCRL, err)
	}
	listedCRLs, err := store.CRLGenerations(t.Context(), root.Authority.ID)
	if err != nil || len(listedCRLs) != 1 || listedCRLs[0].Number != 1 {
		t.Fatalf("CRLGenerations() = %#v, %v", listedCRLs, err)
	}
	replayedCRL, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "sqlite:crl-publish", AuthorityID: root.Authority.ID,
	})
	if err != nil || replayedCRL.Generation.ID != crl.Generation.ID {
		t.Fatalf("replayed PublishCRL() = %#v, %v", replayedCRL, err)
	}
	var crlGenerationCount, crlIntentCount, crlAuditCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_crl_generations`).Scan(&crlGenerationCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_crl_publication_intents`).Scan(&crlIntentCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(
		t.Context(), `SELECT COUNT(*) FROM pki_audit_events WHERE action = ?`, apppki.AuditActionCRLPublish,
	).Scan(&crlAuditCount); err != nil {
		t.Fatal(err)
	}
	if crlGenerationCount != 1 || crlIntentCount != 1 || crlAuditCount != 1 {
		t.Fatalf("crl inventory = %d generations/%d intents/%d audits, want 1/1/1", crlGenerationCount, crlIntentCount, crlAuditCount)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_crl_generations SET number = 2 WHERE id = ?`, crl.Generation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CRLGeneration(t.Context(), crl.Generation.ID); err == nil ||
		!strings.Contains(err.Error(), "does not match canonical columns") {
		t.Fatalf("CRLGeneration() error = %v, want canonical-column tamper rejection", err)
	}
	if _, err := db.ExecContext(
		t.Context(), `UPDATE pki_revocations SET reason = ? WHERE id = ?`,
		domainpki.RevocationReasonKeyCompromise, result.Revocation.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revocation(t.Context(), result.Revocation.ID); err == nil ||
		!strings.Contains(err.Error(), "does not match canonical columns") {
		t.Fatalf("Revocation() error = %v, want canonical-column tamper rejection", err)
	}
}

func TestPKIStoreBeginsOneCRLPublicationUnderConcurrentRetries(t *testing.T) {
	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x81)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x82),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:crl-concurrent-root", Name: "SQLite CRL concurrent root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	type beginResult struct {
		intent  apppki.CRLPublicationIntent
		created bool
		err     error
	}
	results := make(chan beginResult, workers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			createdAt := time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)
			candidate := apppki.CRLPublicationIntent{
				ID:             domainpki.CRLPublicationID(fmt.Sprintf("crl-publication-concurrent-%d", index)),
				IdempotencyKey: "sqlite:crl-concurrent", RequestSHA256: strings.Repeat("a", sha256.Size*2),
				CRLGenerationID: domainpki.CRLGenerationID(fmt.Sprintf("crl-concurrent-%d", index)),
				AuthorityID:     root.Authority.ID, IssuerGenerationID: root.Generation.ID,
				ThisUpdate: createdAt, NextUpdate: createdAt.Add(24 * time.Hour),
				SigningBackendID:             root.Generation.SigningBackendID,
				SigningBackendVersion:        root.Generation.SigningBackendVersion,
				SigningBackendPackageDigest:  root.Generation.SigningBackendPackageDigest,
				SigningBackendCapabilityHash: root.Generation.SigningBackendCapabilityHash,
				SignatureAlgorithm:           domainpki.SignatureAlgorithmECDSASHA256,
				Status:                       apppki.CRLPublicationStatusPending, Phase: apppki.CRLPublicationPhasePlanned,
				OwnerToken: fmt.Sprintf("worker-concurrent-%d", index), Revision: 1,
				LeaseExpiresAt: createdAt.Add(apppki.DefaultCRLLease), CreatedAt: createdAt, UpdatedAt: createdAt,
			}
			intent, created, beginErr := store.BeginCRLPublication(t.Context(), candidate, nil)
			results <- beginResult{intent: intent, created: created, err: beginErr}
		}(worker)
	}
	close(start)
	group.Wait()
	close(results)
	createdCount := 0
	var publicationID domainpki.CRLPublicationID
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			createdCount++
		}
		if publicationID == "" {
			publicationID = result.intent.ID
		}
		if result.intent.ID != publicationID || result.intent.Number != 1 {
			t.Fatalf("BeginCRLPublication() = %#v, want one reserved publication", result.intent)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created publications = %d, want 1", createdCount)
	}
}

func TestPKIStoreRejectsCRLAlgorithmIncompatibleWithIssuerKey(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x83)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x84),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:crl-algorithm-root", Name: "SQLite CRL algorithm root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := root.Authority.CreatedAt
	descriptor := infrapki.NewBackend().Descriptor()
	candidate := apppki.CRLPublicationIntent{
		ID: "crl-publication-algorithm", IdempotencyKey: "sqlite:crl-algorithm",
		RequestSHA256: strings.Repeat("a", sha256.Size*2), CRLGenerationID: "crl-algorithm",
		AuthorityID: root.Authority.ID, IssuerGenerationID: root.Generation.ID,
		ThisUpdate: createdAt, NextUpdate: createdAt.Add(apppki.DefaultCRLValidity),
		SigningBackendID: descriptor.ID, SigningBackendVersion: descriptor.Version,
		SigningBackendPackageDigest: descriptor.PackageDigest, SigningBackendCapabilityHash: descriptor.CapabilityHash,
		SignatureAlgorithm: domainpki.SignatureAlgorithmSHA256WithRSA,
		Status:             apppki.CRLPublicationStatusPending, Phase: apppki.CRLPublicationPhasePlanned,
		OwnerToken: "worker-algorithm", Revision: 1,
		LeaseExpiresAt: createdAt.Add(apppki.DefaultCRLLease), CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if _, _, err := store.BeginCRLPublication(t.Context(), candidate, nil); err == nil {
		t.Fatal("BeginCRLPublication() accepted an RSA algorithm for an ECDSA issuer")
	}
}

func TestPKIStoreRejectsLifecycleCompletionAfterSourceRevocation(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x5a)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x5b),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:revocation-race-root", Name: "SQLite revocation race root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:revocation-race-leaf", IssuerAuthorityID: root.Authority.ID, Name: "sqlite-revocation-race.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "sqlite:revocation-race-renew", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.loadIssuance(t.Context(), db.QueryRowContext(
		t.Context(), issuanceSelect+` WHERE kind = ? AND result_generation_id = ?`,
		apppki.IssuanceKindCertificateRenewal, renewed.Generation.ID,
	))
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingTestIssuance(completed, "issuance-sqlite-revocation-race", "sqlite:test:revocation-race-retry")
	insertTestIssuance(t, store, pending)
	revokedSource := source.Clone()
	revokedSource.State = domainpki.CertificateStateRevoked
	updateTestGeneration(t, store, revokedSource)
	key, err := store.LoadKey(t.Context(), source.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), renewed.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	completionAudits := latestApplicationAudits(t, db, 2)
	audits := apppki.IssuanceCompletionAudits{
		SigningUse: completionAudits[0],
		Lifecycle:  pointerToPKIAudit(completionAudits[1]),
	}
	var auditCountBefore int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteCertificateRenewal(
		t.Context(), pending.ID, pending.Ownership(), renewed.Generation, validated, audits,
	); err == nil || !strings.Contains(err.Error(), "while revoked") {
		t.Fatalf("CompleteCertificateRenewal() error = %v, want revoked-source rejection", err)
	}
	stored, err := store.IssuanceByKey(t.Context(), pending.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var auditCountAfter int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountAfter); err != nil {
		t.Fatal(err)
	}
	if stored.Status != apppki.IssuanceStatusPending || auditCountAfter != auditCountBefore {
		t.Fatal("rejected lifecycle completion changed the intent or appended an audit")
	}
}

func TestPKIStoreBindsAuthorityCompletionToDurablePlan(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x5c)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x5d),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:authority-plan-root", Name: "SQLite authority plan root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.loadIssuance(t.Context(), db.QueryRowContext(
		t.Context(), issuanceSelect+` WHERE kind = ? AND result_generation_id = ?`,
		apppki.IssuanceKindAuthority, root.Generation.ID,
	))
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingTestIssuance(completed, "issuance-sqlite-authority-plan", "sqlite:test:authority-plan-retry")
	pending.AuthorityID = "authority-different-plan"
	insertTestIssuance(t, store, pending)
	key, err := store.LoadKey(t.Context(), root.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), root.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	signingUse := latestApplicationAudits(t, db, 1)[0]
	signingUse.ID = "audit-sqlite-authority-plan"
	signingUse.ResourceID = string(pending.AuthorityID)
	audits := apppki.IssuanceCompletionAudits{SigningUse: signingUse}
	if err := store.CompleteAuthorityIssuance(
		t.Context(), pending.ID, pending.Ownership(), root.Authority, root.Generation, validated, audits,
	); err == nil || !strings.Contains(err.Error(), "does not match its durable plan") {
		t.Fatalf("CompleteAuthorityIssuance() error = %v, want durable-plan rejection", err)
	}
}

func TestPKIStoreRollsBackLifecycleCompletionOnAuditIDCollision(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x5e)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x5f),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:audit-collision-root", Name: "SQLite audit collision root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:audit-collision-leaf", IssuerAuthorityID: root.Authority.ID, Name: "sqlite-audit-collision.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "sqlite:audit-collision-renew", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.loadIssuance(t.Context(), db.QueryRowContext(
		t.Context(), issuanceSelect+` WHERE kind = ? AND result_generation_id = ?`,
		apppki.IssuanceKindCertificateRenewal, renewed.Generation.ID,
	))
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingTestIssuance(completed, "issuance-sqlite-audit-collision", "sqlite:test:audit-collision-retry")
	insertTestIssuance(t, store, pending)
	applicationAudits := latestApplicationAudits(t, db, 4)
	signingUse := applicationAudits[2]
	signingUse.ID = applicationAudits[0].ID
	audits := apppki.IssuanceCompletionAudits{
		SigningUse: signingUse,
		Lifecycle:  pointerToPKIAudit(applicationAudits[3]),
	}
	if _, err := db.ExecContext(
		t.Context(), `DELETE FROM pki_certificate_generations WHERE id = ?`, renewed.Generation.ID,
	); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadKey(t.Context(), source.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), renewed.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	var auditCountBefore int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteCertificateRenewal(
		t.Context(), pending.ID, pending.Ownership(), renewed.Generation, validated, audits,
	); err == nil {
		t.Fatal("CompleteCertificateRenewal() accepted an existing audit id")
	}
	if _, err := store.Generation(t.Context(), renewed.Generation.ID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want rolled-back result", err)
	}
	stored, err := store.IssuanceByKey(t.Context(), pending.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var auditCountAfter int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountAfter); err != nil {
		t.Fatal(err)
	}
	if stored.Status != apppki.IssuanceStatusPending || auditCountAfter != auditCountBefore {
		t.Fatal("audit-id collision changed the intent or audit inventory")
	}
}

func TestPKIStoreRollsBackRotationKeyOnAuditIDCollision(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x60)})
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x61),
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:rotation-collision-root", Name: "SQLite rotation collision root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:rotation-collision-leaf", IssuerAuthorityID: root.Authority.ID, Name: "sqlite-rotation-collision.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.RotateCertificate(t.Context(), apppki.RotateCertificateRequest{
		IdempotencyKey: "sqlite:rotation-collision-rotate", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.loadIssuance(t.Context(), db.QueryRowContext(
		t.Context(), issuanceSelect+` WHERE kind = ? AND result_generation_id = ?`,
		apppki.IssuanceKindCertificateRotation, rotated.Generation.ID,
	))
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingTestIssuance(completed, "issuance-sqlite-rotation-collision", "sqlite:test:rotation-collision-retry")
	insertTestIssuance(t, store, pending)
	applicationAudits := latestApplicationAudits(t, db, 4)
	signingUse := applicationAudits[2]
	signingUse.ID = applicationAudits[0].ID
	audits := apppki.IssuanceCompletionAudits{
		SigningUse: signingUse,
		Lifecycle:  pointerToPKIAudit(applicationAudits[3]),
	}
	key, err := store.LoadKey(t.Context(), rotated.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), rotated.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	if _, err := db.ExecContext(
		t.Context(), `DELETE FROM pki_certificate_generations WHERE id = ?`, rotated.Generation.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(
		t.Context(), `DELETE FROM pki_key_envelopes WHERE key_id = ?`, rotated.Generation.KeyID,
	); err != nil {
		t.Fatal(err)
	}
	var auditCountBefore int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteCertificateIssuance(
		t.Context(), pending.ID, pending.Ownership(), rotated.Generation, validated, audits,
	); err == nil {
		t.Fatal("CompleteCertificateIssuance() accepted an existing audit id")
	}
	if _, err := store.Generation(t.Context(), rotated.Generation.ID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want rolled-back result", err)
	}
	if _, err := store.LoadKey(t.Context(), rotated.Generation.KeyID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("LoadKey() error = %v, want rolled-back key", err)
	}
	stored, err := store.IssuanceByKey(t.Context(), pending.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var auditCountAfter int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_audit_events`).Scan(&auditCountAfter); err != nil {
		t.Fatal(err)
	}
	if stored.Status != apppki.IssuanceStatusPending || stored.ResultGenerationID != "" || auditCountAfter != auditCountBefore {
		t.Fatal("rotation audit-id collision changed the intent or audit inventory")
	}
}

func pendingTestIssuance(completed apppki.IssuanceIntent, id domainpki.IssuanceID, key string) apppki.IssuanceIntent {
	pending := completed.Clone()
	pending.ID = id
	pending.IdempotencyKey = key
	pending.Status = apppki.IssuanceStatusPending
	pending.ResultGenerationID = ""
	pending.Failure = ""
	pending.OwnerToken = "sqlite-test-retry-owner"
	pending.Revision = 1
	return pending
}

func insertTestIssuance(t *testing.T, store PKIStore, intent apppki.IssuanceIntent) {
	t.Helper()
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, metadata, err := store.encodeIssuance(t.Context(), intent)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { logSQLiteRollback("rollback test issuance insert", tx.Rollback()) }()
	if err := insertIssuance(t.Context(), tx, intent, encoded, metadata); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func updateTestGeneration(t *testing.T, store PKIStore, generation domainpki.CertificateGeneration) {
	t.Helper()
	prepared, err := store.prepareGenerationResult(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(t.Context(), `
UPDATE pki_certificate_generations
SET state = ?, generation_json = ?, metadata_schema_version = ?, metadata_algorithm = ?,
	metadata_key_version = ?, metadata_tag = ?
WHERE id = ?`, generation.State, prepared.generationJSON, prepared.generationMetadata.SchemaVersion,
		prepared.generationMetadata.Algorithm, prepared.generationMetadata.KeyVersion,
		prepared.generationMetadata.Tag, generation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatalf("updated generation rows = %d, %v", affected, err)
	}
}

func latestApplicationAudits(t *testing.T, db *sql.DB, limit int) []apppki.AuditRecord {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `
SELECT event_id, action, outcome, actor_id, operation_id, correlation_id,
	resource_type, resource_id, details_json, created_at
FROM pki_audit_events
WHERE event_id IS NOT NULL
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { logSQLiteError("close latest application audit rows", rows.Close()) }()
	reversed := make([]apppki.AuditRecord, 0, limit)
	for rows.Next() {
		var record apppki.AuditRecord
		var details []byte
		var createdAt string
		if err := rows.Scan(
			&record.ID, &record.Action, &record.Outcome, &record.ActorID, &record.OperationID,
			&record.CorrelationID, &record.ResourceType, &record.ResourceID, &details, &createdAt,
		); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(details, &record.Details); err != nil {
			t.Fatal(err)
		}
		record.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			t.Fatal(err)
		}
		reversed = append(reversed, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(reversed) != limit {
		t.Fatalf("loaded application audits = %d, want %d", len(reversed), limit)
	}
	result := make([]apppki.AuditRecord, len(reversed))
	for index := range reversed {
		result[len(reversed)-1-index] = reversed[index]
	}
	return result
}

func pointerToPKIAudit(record apppki.AuditRecord) *apppki.AuditRecord {
	clone := record.Clone()
	return &clone
}

func TestPKIStoreReportsMissingRecords(t *testing.T) {
	t.Parallel()

	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x11}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-missing")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	otherWorkspaceID := domainWorkspaceID(t, "workspace-other")
	otherProtector, err := infrapki.NewEnvelopeProtector(otherWorkspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPKIStore(workspacePath, workspaceID, otherProtector); err == nil {
		t.Fatal("NewPKIStore() accepted a protector scoped to another workspace")
	}
	if _, err := store.Authority(t.Context(), "authority-missing"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Authority() error = %v, want ErrNotFound", err)
	}
	if _, err := store.Generation(t.Context(), "certgen-missing"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want ErrNotFound", err)
	}
	if _, err := store.Generations(t.Context(), "cert-missing"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generations() error = %v, want ErrNotFound", err)
	}
	if _, err := store.LoadKey(t.Context(), "key-missing"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("LoadKey() error = %v, want ErrNotFound", err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO pki_generation_counters(certificate_id, last_generation) VALUES (?, ?)`, "cert-exhausted", int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x31))
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "counter root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{CertificateID: "cert-exhausted", IssuerAuthorityID: root.Authority.ID, Name: "exhausted.test"}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("IssueCertificate() error = %v, want exhausted counter", err)
	}
}

func TestPKIStorePersistsAssignmentsAndTrustSetsWithCAS(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x31)})
	now := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	trustSet := domainpki.TrustSet{
		ID: "trust-edge", Name: "Edge trust", State: domainpki.TrustSetStatePending,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateTrustSet(t.Context(), trustSet, assignmentTestAudit(apppki.AuditActionTrustSetCreate, trustSet.ID, now),
		assignmentTestMutation(t, "trust-create", apppki.MutationTrustSetCreate, trustSet.ID, now, trustSet)); err != nil {
		t.Fatal(err)
	}
	if mutation, err := store.MutationByKey(t.Context(), "test:trust-create"); err != nil || mutation.ResourceID != string(trustSet.ID) {
		t.Fatalf("MutationByKey() = %#v, %v", mutation, err)
	}
	trustGeneration := domainpki.TrustSetGeneration{
		ID: "trust-edge-generation-1", TrustSetID: trustSet.ID, Generation: 1,
		AnchorGenerationIDs:       []domainpki.GenerationID{"root-generation-old", "root-generation-new"},
		IntermediateGenerationIDs: []domainpki.GenerationID{"issuer-generation"},
		CRLGenerationIDs:          []domainpki.CRLGenerationID{"issuer-crl-generation"}, CreatedAt: now.Add(time.Minute),
	}
	stagedTrust := trustSet
	stagedTrust.StagedGenerationID = trustGeneration.ID
	stagedTrust.Revision = 2
	stagedTrust.UpdatedAt = now.Add(time.Minute)
	if err := store.StageTrustSetGeneration(t.Context(), trustSet.Revision, stagedTrust, trustGeneration,
		assignmentTestAudit(apppki.AuditActionTrustSetStage, trustSet.ID, stagedTrust.UpdatedAt),
		assignmentTestMutation(t, "trust-stage", apppki.MutationTrustSetStage, trustSet.ID, stagedTrust.UpdatedAt, stagedTrust)); err != nil {
		t.Fatal(err)
	}
	staleGeneration := trustGeneration.Clone()
	staleGeneration.ID = "trust-edge-generation-stale"
	staleGeneration.Generation = 2
	staleTrust := stagedTrust
	staleTrust.StagedGenerationID = staleGeneration.ID
	if err := store.StageTrustSetGeneration(t.Context(), trustSet.Revision, staleTrust, staleGeneration,
		assignmentTestAudit(apppki.AuditActionTrustSetStage, trustSet.ID, stagedTrust.UpdatedAt),
		assignmentTestMutation(t, "trust-stage-stale", apppki.MutationTrustSetStage, trustSet.ID, stagedTrust.UpdatedAt, staleTrust)); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale StageTrustSetGeneration() error = %v, want revision conflict", err)
	}
	if _, err := store.MutationByKey(t.Context(), "test:trust-stage-stale"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("rolled-back mutation error = %v, want not found", err)
	}
	activeTrust := stagedTrust
	activeTrust.ActiveGenerationID = trustGeneration.ID
	activeTrust.StagedGenerationID = ""
	activeTrust.State = domainpki.TrustSetStateActive
	activeTrust.Revision = 3
	activeTrust.UpdatedAt = now.Add(2 * time.Minute)
	if err := store.UpdateTrustSet(t.Context(), stagedTrust.Revision, activeTrust,
		assignmentTestAudit(apppki.AuditActionTrustSetActivate, trustSet.ID, activeTrust.UpdatedAt),
		assignmentTestMutation(t, "trust-activate", apppki.MutationTrustSetActivate, trustSet.ID, activeTrust.UpdatedAt, activeTrust)); err != nil {
		t.Fatal(err)
	}

	assignment := domainpki.Assignment{
		ID: "assignment-edge", Purpose: domainpki.PurposeTLSClient,
		ConsumerType: domainpki.ConsumerMeshNode, ConsumerID: "mesh-provider/node-edge",
		ProfileID: domainpki.ProfileTLSClient, TrustSetID: trustSet.ID,
		State: domainpki.AssignmentStatePending, Revision: 1, UpdatedAt: now,
	}
	if err := store.CreateAssignment(t.Context(), assignment,
		assignmentTestAudit(apppki.AuditActionAssignmentBind, assignment.ID, now),
		assignmentTestMutation(t, "assignment-create", apppki.MutationAssignmentBind, assignment.ID, now, assignment)); err != nil {
		t.Fatal(err)
	}
	retired := assignment
	retired.State = domainpki.AssignmentStateRetired
	retired.Revision = 2
	retired.UpdatedAt = now.Add(3 * time.Minute)
	if err := store.UpdateAssignment(t.Context(), assignment.Revision, retired,
		assignmentTestAudit(apppki.AuditActionAssignmentUnbind, assignment.ID, retired.UpdatedAt),
		assignmentTestMutation(t, "assignment-retire", apppki.MutationAssignmentUnbind, assignment.ID, retired.UpdatedAt, retired)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateAssignment(t.Context(), assignment.Revision, retired,
		assignmentTestAudit(apppki.AuditActionAssignmentUnbind, assignment.ID, retired.UpdatedAt),
		assignmentTestMutation(t, "assignment-retire-stale", apppki.MutationAssignmentUnbind, assignment.ID, retired.UpdatedAt, retired)); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale UpdateAssignment() error = %v, want revision conflict", err)
	}
	changedBinding := retired
	changedBinding.ConsumerID = "mesh-provider/node-other"
	changedBinding.Revision = 3
	changedBinding.UpdatedAt = now.Add(4 * time.Minute)
	if err := store.UpdateAssignment(t.Context(), retired.Revision, changedBinding,
		assignmentTestAudit(apppki.AuditActionAssignmentUnbind, changedBinding.ID, changedBinding.UpdatedAt),
		assignmentTestMutation(t, "assignment-change", apppki.MutationAssignmentUnbind, changedBinding.ID, changedBinding.UpdatedAt, changedBinding)); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("UpdateAssignment() changed binding error = %v", err)
	}
	rebound := assignment
	rebound.ID = "assignment-edge-rebound"
	rebound.UpdatedAt = now.Add(4 * time.Minute)
	if err := store.CreateAssignment(t.Context(), rebound,
		assignmentTestAudit(apppki.AuditActionAssignmentBind, rebound.ID, rebound.UpdatedAt),
		assignmentTestMutation(t, "assignment-rebind", apppki.MutationAssignmentBind, rebound.ID, rebound.UpdatedAt, rebound)); err != nil {
		t.Fatalf("CreateAssignment() after retirement error = %v", err)
	}

	loadedAssignment, err := store.Assignment(t.Context(), assignment.ID)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := store.Assignments(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	loadedTrust, err := store.TrustSet(t.Context(), trustSet.ID)
	if err != nil {
		t.Fatal(err)
	}
	trustSets, err := store.TrustSets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	loadedGeneration, err := store.TrustSetGeneration(t.Context(), trustGeneration.ID)
	if err != nil {
		t.Fatal(err)
	}
	trustGenerations, err := store.TrustSetGenerations(t.Context(), trustSet.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedAssignment.State != domainpki.AssignmentStateRetired || len(assignments) != 2 ||
		loadedTrust.State != domainpki.TrustSetStateActive || len(trustSets) != 1 ||
		loadedGeneration.ID != trustGeneration.ID || len(trustGenerations) != 1 {
		t.Fatalf("loaded assignment/trust state = %#v %#v %#v", loadedAssignment, loadedTrust, loadedGeneration)
	}
	loadedGeneration.AnchorGenerationIDs[0] = "mutated"
	reloadedGeneration, err := store.TrustSetGeneration(t.Context(), trustGeneration.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedGeneration.AnchorGenerationIDs[0] != "root-generation-old" {
		t.Fatal("TrustSetGeneration() returned store-owned slices")
	}

	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var memberCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_trust_set_members WHERE trust_set_generation_id = ?`, trustGeneration.ID).Scan(&memberCount); err != nil {
		t.Fatal(err)
	}
	if memberCount != 4 {
		t.Fatalf("trust set member count = %d, want 4", memberCount)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET member_id = ? WHERE trust_set_generation_id = ? AND member_type = ? AND position = 0`, "tampered-root", trustGeneration.ID, trustMemberAnchor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TrustSetGeneration(t.Context(), trustGeneration.ID); err == nil {
		t.Fatal("TrustSetGeneration() accepted normalized members that disagree with authenticated json")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET member_id = ? WHERE trust_set_generation_id = ? AND member_type = ? AND position = 0`, "root-generation-old", trustGeneration.ID, trustMemberAnchor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET position = 7 WHERE trust_set_generation_id = ? AND member_type = ? AND position = 1`, trustGeneration.ID, trustMemberAnchor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TrustSetGeneration(t.Context(), trustGeneration.ID); err == nil {
		t.Fatal("TrustSetGeneration() accepted noncontiguous normalized member positions")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET position = 1 WHERE trust_set_generation_id = ? AND member_type = ? AND position = 7`, trustGeneration.ID, trustMemberAnchor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_mutations SET result_json = ? WHERE idempotency_key = ?`, []byte(`{"tampered":true}`), "test:trust-create"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MutationByKey(t.Context(), "test:trust-create"); err == nil {
		t.Fatal("MutationByKey() accepted result columns that disagree with authenticated json")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_assignments SET profile_id = ? WHERE id = ?`, "tampered-profile", assignment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Assignment(t.Context(), assignment.ID); err == nil {
		t.Fatal("Assignment() accepted canonical columns that disagree with authenticated json")
	}
}

func TestPKIStoreRewrapsAssignmentAndTrustMetadata(t *testing.T) {
	t.Parallel()

	provider := &rotatingTestMasterKeyProvider{
		active: "v1",
		keys: map[string]infrapki.MasterKey{
			"v1": mustTestMasterKey(t, 0x41),
			"v2": mustTestMasterKey(t, 0x42),
		},
	}
	store := newAssignmentTestPKIStore(t, provider)
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	trustSet := domainpki.TrustSet{ID: "trust-rewrap", Name: "Rewrap trust", State: domainpki.TrustSetStatePending, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTrustSet(t.Context(), trustSet, assignmentTestAudit(apppki.AuditActionTrustSetCreate, trustSet.ID, now),
		assignmentTestMutation(t, "rewrap-trust-create", apppki.MutationTrustSetCreate, trustSet.ID, now, trustSet)); err != nil {
		t.Fatal(err)
	}
	generation := domainpki.TrustSetGeneration{
		ID: "trust-rewrap-generation-1", TrustSetID: trustSet.ID, Generation: 1,
		AnchorGenerationIDs: []domainpki.GenerationID{"root-generation"}, CreatedAt: now,
	}
	staged := trustSet
	staged.StagedGenerationID = generation.ID
	staged.Revision = 2
	if err := store.StageTrustSetGeneration(t.Context(), trustSet.Revision, staged, generation,
		assignmentTestAudit(apppki.AuditActionTrustSetStage, trustSet.ID, now),
		assignmentTestMutation(t, "rewrap-trust-stage", apppki.MutationTrustSetStage, trustSet.ID, now, staged)); err != nil {
		t.Fatal(err)
	}
	assignment := domainpki.Assignment{
		ID: "assignment-rewrap", Purpose: domainpki.PurposeTLSClient,
		ConsumerType: domainpki.ConsumerExternal, ConsumerID: "external:rewrap",
		ProfileID: domainpki.ProfileTLSClient, TrustSetID: trustSet.ID,
		State: domainpki.AssignmentStatePending, Revision: 1, UpdatedAt: now,
	}
	if err := store.CreateAssignment(t.Context(), assignment,
		assignmentTestAudit(apppki.AuditActionAssignmentBind, assignment.ID, now),
		assignmentTestMutation(t, "rewrap-assignment-create", apppki.MutationAssignmentBind, assignment.ID, now, assignment)); err != nil {
		t.Fatal(err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET member_id = ? WHERE trust_set_generation_id = ?`, "tampered-root", generation.ID); err != nil {
		t.Fatal(err)
	}
	provider.active = "v2"
	if _, err := store.RewrapKeys(t.Context()); err == nil {
		t.Fatal("RewrapKeys() accepted normalized trust members that disagree with authenticated json")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_trust_set_members SET member_id = ? WHERE trust_set_generation_id = ?`, "root-generation", generation.ID); err != nil {
		t.Fatal(err)
	}
	if count, err := store.RewrapKeys(t.Context()); err != nil || count != 0 {
		t.Fatalf("RewrapKeys() = %d, %v; want 0, nil", count, err)
	}
	versions, err := store.ReferencedMasterKeyVersions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0] != "v2" {
		t.Fatalf("ReferencedMasterKeyVersions() = %v, want [v2]", versions)
	}
	if _, err := store.Assignment(t.Context(), assignment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TrustSetGeneration(t.Context(), generation.ID); err != nil {
		t.Fatal(err)
	}
}

func newAssignmentTestPKIStore(t *testing.T, provider infrapki.MasterKeyProvider) PKIStore {
	t.Helper()
	workspaceID := domainWorkspaceID(t, "workspace-assignment-test")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, provider)
	if err != nil {
		t.Fatal(err)
	}
	return newTestPKIStore(t, t.TempDir(), workspaceID, protector)
}

func mustTestMasterKey(t *testing.T, value byte) infrapki.MasterKey {
	t.Helper()
	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{value}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func assignmentTestAudit[T ~string](action apppki.AuditAction, resourceID T, createdAt time.Time) apppki.AuditRecord {
	return apppki.AuditRecord{
		ID: "audit-" + string(resourceID) + "-" + string(action), Action: action, Outcome: apppki.AuditOutcomeSucceeded,
		ActorID: "sqlite-test", OperationID: "sqlite-operation", CorrelationID: "sqlite-correlation",
		ResourceType: "pki-resource", ResourceID: string(resourceID), CreatedAt: createdAt,
	}
}

func assignmentTestMutation[T ~string](t *testing.T, key string, kind apppki.MutationKind, resourceID T, createdAt time.Time, result any) apppki.MutationRecord {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(key))
	return apppki.MutationRecord{
		ID: domainpki.MutationID("mutation-" + key), IdempotencyKey: "test:" + key,
		RequestSHA256: fmt.Sprintf("%x", digest), Kind: kind,
		ResourceType: "pki-resource", ResourceID: string(resourceID),
		ResultJSON: encoded, CreatedAt: createdAt.UTC(),
	}
}

func activateCredentialLedgerTestAssignment(
	t *testing.T,
	service apppki.Service,
	assignment domainpki.Assignment,
	suffix string,
) domainpki.Assignment {
	t.Helper()
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:credential-ledger-root:" + suffix,
		ID:             domainpki.AuthorityID("authority-credential-ledger-" + suffix),
		CertificateID:  domainpki.CertificateID("certificate-credential-ledger-root-" + suffix),
		GenerationID:   domainpki.GenerationID("generation-credential-ledger-root-" + suffix),
		KeyID:          domainpki.KeyID("key-credential-ledger-root-" + suffix),
		Name:           "credential ledger root " + suffix,
		Role:           domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(
		t.Context(),
		root.Authority.ID,
		apppki.DefaultSigningLeaseDuration,
	); err != nil {
		t.Fatal(err)
	}
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey:    "sqlite:credential-ledger-leaf:" + suffix,
		CertificateID:     domainpki.CertificateID("certificate-credential-ledger-leaf-" + suffix),
		GenerationID:      domainpki.GenerationID("generation-credential-ledger-leaf-" + suffix),
		KeyID:             domainpki.KeyID("key-credential-ledger-leaf-" + suffix),
		IssuerAuthorityID: root.Authority.ID,
		Name:              "credential-ledger-" + suffix + ".test",
		ProfileID:         domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey:   "sqlite:credential-ledger-stage:" + suffix,
		AssignmentID:     assignment.ID,
		GenerationID:     leaf.ID,
		ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	activated, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey:   "sqlite:credential-ledger-activate:" + suffix,
		AssignmentID:     assignment.ID,
		ExpectedRevision: staged.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return activated.Assignment
}

func sqliteTestCredentialStamp(
	t *testing.T,
	assignment domainpki.Assignment,
	id domainpki.StampID,
	createdAt time.Time,
) domainpki.CredentialStamp {
	t.Helper()
	descriptor, err := domainpki.NewCredentialDeliveryDescriptor(
		domainpki.CredentialDeliveryDescriptorArgs{
			SchemaVersion: domainpki.CredentialDeliverySchemaV1,
			Slots: []domainpki.CredentialSlot{{
				Name: "tls-server", Purpose: domainpki.PurposeTLSServer,
				EndpointRole:           domainpki.CredentialEndpointServer,
				ConsumerType:           domainpki.ConsumerMeshListener,
				AcceptedBundleVersions: []string{domainpki.BundleSchemaV1},
				AcceptedProfiles:       []domainpki.ProfileID{domainpki.ProfileTLSServer},
				AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{
					domainpki.CompatibilityPortableX509,
				},
				AcceptedProjections: []domainpki.CredentialProjection{
					domainpki.CredentialProjectionCertificateDER,
				},
				AcceptedMaterialForms: []domainpki.CredentialMaterialForm{
					domainpki.CredentialMaterialPublic,
				},
				MaximumEncodedBytes: 16,
				RemainderPolicy:     domainpki.StampRemainderRequireExact,
				PrivateMaterial:     domainpki.PrivateMaterialForbidden,
			}},
			Capabilities: []domainpki.DeliveryCapability{
				domainpki.DeliveryCapabilityStampStandard,
			},
			StampTargetKinds: []domainpki.StampTargetKind{
				domainpki.StampTargetNamedSlot,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := domainpki.NewNamedSlotStampTarget(
		domainpki.NamedSlotTarget{Name: "tls-server"},
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := domainpki.NewCredentialStampMaterial(
		domainpki.CredentialMaterialReference{
			Projection:   domainpki.CredentialProjectionCertificateDER,
			Form:         domainpki.CredentialMaterialPublic,
			GenerationID: assignment.ActiveGenerationID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := domainpki.NewCredentialStampPlan(
		descriptor,
		domainpki.CredentialStampRequest{
			AssignmentID: assignment.ID,
			Capability:   domainpki.DeliveryCapabilityStampStandard,
			SlotName:     "tls-server",
			Target:       target,
			Material:     material,
			EncodedBytes: 16,
			Credential: domainpki.ResolvedCredentialMetadata{
				BundleVersion:         domainpki.BundleSchemaV1,
				Purpose:               domainpki.PurposeTLSServer,
				ConsumerType:          domainpki.ConsumerMeshListener,
				ProfileID:             domainpki.ProfileTLSServer,
				CompatibilityTargetID: domainpki.CompatibilityPortableX509,
			},
		},
		domainpki.StampArtifactReference{
			Kind:   domainpki.StampArtifactWorkspace,
			ID:     domainpki.StampReferenceID("artifact-sqlite-input-" + string(id)),
			SHA256: strings.Repeat("b", 64),
		},
		[]domainpki.StampedMaterialDigest{{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Reference:  domainpki.StampReferenceID(assignment.ActiveGenerationID),
			SHA256:     strings.Repeat("c", 64),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := domainpki.NewCredentialStamp(domainpki.CredentialStampArgs{
		SchemaVersion:   domainpki.CredentialStampSchemaV1,
		ID:              id,
		ProviderID:      "provider-sqlite-stamp",
		ProviderVersion: "1.0.0",
		Plan:            plan,
		CreatedAt:       createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

func TestPKIStoreRejectsMetadataMismatchAndAtomicRollback(t *testing.T) {
	t.Parallel()

	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x61}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-integrity")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x45))
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{ID: "authority-integrity", CertificateID: "cert-integrity", GenerationID: "certgen-integrity", KeyID: "key-integrity", Name: "integrity root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteKey(t.Context(), created.Generation.KeyID); err == nil {
		t.Fatal("DeleteKey() removed a key referenced by a certificate generation")
	}
	if err := store.DeleteKey(t.Context(), "key-missing-delete"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("DeleteKey() missing error = %v, want ErrNotFound", err)
	}

	duplicateRequest := apppki.CreateAuthorityRequest{ID: created.Authority.ID, CertificateID: "cert-rollback", GenerationID: "certgen-rollback", KeyID: "key-rollback", Name: "duplicate authority", Role: domainpki.AuthorityRoleRoot}
	_, err = service.CreateAuthority(t.Context(), duplicateRequest)
	if err == nil {
		t.Fatal("CreateAuthority() accepted a duplicate authority id")
	}
	if _, err := service.CreateAuthority(t.Context(), duplicateRequest); err == nil || !strings.Contains(err.Error(), "prior issuance attempt failed") {
		t.Fatalf("CreateAuthority() failed retry error = %v, want durable prior failure", err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_key_envelopes WHERE key_id = ?`, "key-rollback").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed authority transaction left an orphaned key envelope")
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_generation_counters WHERE certificate_id = ?`, "cert-rollback").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("failed authority transaction lost its durable generation reservation")
	}
	var status apppki.IssuanceStatus
	if err := db.QueryRowContext(t.Context(), `SELECT status FROM pki_issuance_intents WHERE certificate_id = ?`, "cert-rollback").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != apppki.IssuanceStatusFailed {
		t.Fatalf("failed authority transaction intent status = %q, want terminal failure", status)
	}

	tamperedAuthority := created.Authority.Clone()
	tamperedAuthority.ExportPolicy = domainpki.ExportPolicyExplicit
	encodedAuthority, err := json.Marshal(tamperedAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_authorities SET authority_json = ? WHERE id = ?`, encodedAuthority, created.Authority.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authority(t.Context(), created.Authority.ID); err == nil || !strings.Contains(err.Error(), "verify authority metadata") {
		t.Fatalf("Authority() error = %v, want authenticated metadata failure", err)
	}

	tampered := created.Generation.Clone()
	tampered.ExportPolicy = domainpki.ExportPolicyExplicit
	encoded, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_certificate_generations SET generation_json = ? WHERE id = ?`, encoded, created.Generation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Generation(t.Context(), created.Generation.ID); err == nil || !strings.Contains(err.Error(), "verify certificate generation metadata") {
		t.Fatalf("Generation() error = %v, want authenticated metadata failure", err)
	}
}

func TestPKIStoreAllocatesConcurrentGenerations(t *testing.T) {
	t.Parallel()

	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x71}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-concurrent")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x46))
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{ID: "authority-concurrent", CertificateID: "cert-root-concurrent", GenerationID: "certgen-root-concurrent", KeyID: "key-root-concurrent", Name: "concurrent root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 12
	numbers := make(chan uint64, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			generation, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
				CertificateID:     "cert-shared-lineage",
				GenerationID:      domainpki.GenerationID(fmt.Sprintf("certgen-shared-%d", index)),
				KeyID:             domainpki.KeyID(fmt.Sprintf("key-shared-%d", index)),
				IssuerAuthorityID: root.Authority.ID,
				Name:              fmt.Sprintf("listener-%d.test", index),
			})
			if err != nil {
				errs <- err
				return
			}
			numbers <- generation.Generation
		}()
	}
	wait.Wait()
	close(errs)
	close(numbers)
	for err := range errs {
		t.Error(err)
	}
	got := make([]int, 0, workers)
	for number := range numbers {
		got = append(got, int(number))
	}
	sort.Ints(got)
	if len(got) != workers {
		t.Fatalf("issued generations = %v, want %d", got, workers)
	}
	for index, number := range got {
		if number != index+1 {
			t.Fatalf("issued generations = %v, want contiguous unique values", got)
		}
	}
}

func TestPKIStoreUsesOwnerOnlyFullDurability(t *testing.T) {
	t.Parallel()

	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x72}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-permissions")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database permissions = %o, want owner-only", info.Mode().Perm())
	}
	var synchronous int
	if err := db.QueryRowContext(t.Context(), `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 2 {
		t.Fatalf("PRAGMA synchronous = %d, want FULL (2)", synchronous)
	}
}

func TestPKIStoreLoadKeyTransfersDecryptedMaterialOwnership(t *testing.T) {
	t.Parallel()

	workspaceID := domainWorkspaceID(t, "workspace-load-key-ownership")
	protector, err := infrapki.NewEnvelopeProtector(
		workspaceID,
		testMasterKeyProvider{key: mustTestMasterKey(t, 0x4f)},
	)
	if err != nil {
		t.Fatal(err)
	}
	trackingProtector := &trackingKeyProtector{KeyProtector: protector}
	store := newTestPKIStore(t, t.TempDir(), workspaceID, trackingProtector)
	service, err := apppki.NewService(
		t.Context(),
		store,
		infrapki.NewBackend(),
		infrapki.NewValidator(),
		pkiTestAuthorization{},
		pkiTestAuthorization{},
		store,
		pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 12, 16, 0, 0, 0, time.UTC)},
		newTestEntropy(0x50),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		ID: "authority-load-key-ownership", CertificateID: "cert-load-key-ownership",
		GenerationID: "generation-load-key-ownership", KeyID: "key-load-key-ownership",
		Name: "load key ownership", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	trackingProtector.openedPrivateKey = nil
	material, err := store.LoadKey(t.Context(), created.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKeyPKCS8)
	if len(material.PrivateKeyPKCS8) == 0 || len(trackingProtector.openedPrivateKey) == 0 {
		t.Fatal("LoadKey() returned no private key material")
	}
	if &material.PrivateKeyPKCS8[0] != &trackingProtector.openedPrivateKey[0] {
		t.Fatal("LoadKey() copied decrypted private key material instead of transferring ownership")
	}
}

func TestAuthenticatedPKIMetadataTableInventoryMatchesSchema(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(
		t,
		testMasterKeyProvider{key: mustTestMasterKey(t, 0x51)},
	)
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(t.Context(), `
SELECT DISTINCT schema_row.name
FROM sqlite_schema AS schema_row, pragma_table_info(schema_row.name) AS column_row
WHERE schema_row.type = 'table' AND column_row.name = 'metadata_key_version'
ORDER BY schema_row.name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { logSQLiteError("close authenticated PKI table inventory rows", rows.Close()) }()
	actual := make([]string, 0)
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		actual = append(actual, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	expected := authenticatedPKIMetadataTableNames()
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("authenticated PKI metadata table inventory = %v, want %v", actual, expected)
	}
}

func TestPKIStoreRewrapsCredentialLedgerMetadata(t *testing.T) {
	t.Parallel()

	provider := &rotatingTestMasterKeyProvider{
		active: "master-v1",
		keys: map[string]infrapki.MasterKey{
			"master-v1": mustTestMasterKey(t, 0x52),
			"master-v2": mustTestMasterKey(t, 0x53),
		},
	}
	store := newAssignmentTestPKIStore(t, provider)
	clock := pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}
	service, err := apppki.NewService(
		t.Context(),
		store,
		infrapki.NewBackend(),
		infrapki.NewValidator(),
		pkiTestAuthorization{},
		pkiTestAuthorization{},
		store,
		pkiTestAuthorization{},
		clock,
		newTestEntropy(0x54),
	)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "sqlite:credential-ledger-rewrap-assignment",
		ID:             "assignment-credential-ledger-rewrap",
		Purpose:        domainpki.PurposeTLSServer,
		ConsumerType:   domainpki.ConsumerMeshListener,
		ConsumerID:     "mesh-provider/credential-ledger-rewrap",
		ProfileID:      domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment = activateCredentialLedgerTestAssignment(t, service, assignment, "rewrap")
	stamp := sqliteTestCredentialStamp(
		t,
		assignment,
		"credential-stamp-rewrap",
		clock.now,
	)
	stamp, err = service.RecordCredentialStampPlan(
		t.Context(),
		"sqlite:credential-ledger-rewrap-stamp",
		stamp,
	)
	if err != nil {
		t.Fatal(err)
	}

	secret := domainpki.CredentialBytes("credential-ledger-rewrap-private-material")
	defer clear(secret)
	digest := sha256.Sum256(secret)
	execution, err := domainpki.NewRuntimeCredentialExecution(
		domainpki.CredentialRuntimeRequest{
			SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
			Provider: domainpki.CredentialProviderTarget{
				ModuleID: "mesh-provider-module", ProviderID: "mesh-provider",
				ProviderVersion: "1.0.0", DescriptorSHA256: strings.Repeat("a", 64),
			},
			RequestID:    "credential-execution-rewrap",
			AssignmentID: assignment.ID,
			SlotName:     "tls-server",
			Credential: domainpki.ResolvedCredentialMetadata{
				BundleVersion: domainpki.BundleSchemaV1, Purpose: domainpki.PurposeTLSServer,
				ConsumerType: domainpki.ConsumerMeshListener, ProfileID: domainpki.ProfileTLSServer,
				CompatibilityTargetID: domainpki.CompatibilityPortableX509,
			},
			Material: domainpki.ResolvedCredentialMaterial{
				Projection: domainpki.CredentialProjectionBundle,
				Form:       domainpki.CredentialMaterialPrivateBytes,
				Encoding:   "hovel-bundle-json",
				SHA256:     fmt.Sprintf("%x", digest),
				Data:       secret,
			},
			Scope: domainpki.CredentialOperationScope{ListenerID: "listener-rewrap"},
		},
		clock.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	execution, err = service.RecordCredentialExecutionPlan(
		t.Context(),
		"sqlite:credential-ledger-rewrap-execution",
		execution,
	)
	if err != nil {
		t.Fatal(err)
	}

	provider.active = "master-v2"
	if count, err := store.RewrapKeys(t.Context()); err != nil || count != 2 {
		t.Fatalf("RewrapKeys() = %d, %v; want 2, nil", count, err)
	}
	versions, err := store.ReferencedMasterKeyVersions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0] != "master-v2" {
		t.Fatalf("ReferencedMasterKeyVersions() = %v, want [master-v2]", versions)
	}
	delete(provider.keys, "master-v1")
	if _, err := store.CredentialStamp(t.Context(), stamp.ID); err != nil {
		t.Fatalf("CredentialStamp() after retiring master-v1: %v", err)
	}
	if _, err := store.CredentialExecution(t.Context(), execution.ID); err != nil {
		t.Fatalf("CredentialExecution() after retiring master-v1: %v", err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyMasterKeyVersion(
		t,
		db,
		`SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_credential_stamps`,
		"master-v2",
	)
	assertOnlyMasterKeyVersion(
		t,
		db,
		`SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_credential_executions`,
		"master-v2",
	)
}

func TestPKIStoreRewrapsKeysBeforeRetiringMasterKey(t *testing.T) {
	t.Parallel()

	first, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x10}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	second, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x20}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	provider := &rotatingTestMasterKeyProvider{active: "master-v1", keys: map[string]infrapki.MasterKey{"master-v1": first, "master-v2": second}}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-rewrap")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, provider)
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	// Save a complete root so the encrypted key and its relational references
	// are committed atomically.
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x33))
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{ID: "authority-rewrap", CertificateID: "cert-rewrap", GenerationID: "certgen-rewrap", KeyID: "key-rewrap", Name: "rewrap root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	crl, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "sqlite:crl-rewrap", AuthorityID: created.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.active = "master-v2"
	count, err := store.RewrapKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rewrapped key count = %d, want 1", count)
	}
	delete(provider.keys, "master-v1")
	loaded, err := store.LoadKey(t.Context(), created.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PrivateKeyPKCS8) == 0 {
		t.Fatal("rewrapped key has no private material")
	}
	if _, err := store.Authority(t.Context(), created.Authority.ID); err != nil {
		t.Fatalf("authority metadata was not rewrapped: %v", err)
	}
	if _, err := store.CRLPublication(t.Context(), crl.Publication.ID); err != nil {
		t.Fatalf("CRL publication metadata was not rewrapped: %v", err)
	}
	if _, err := store.CRLGeneration(t.Context(), crl.Generation.ID); err != nil {
		t.Fatalf("CRL generation metadata was not rewrapped: %v", err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var keyVersion string
	if err := db.QueryRowContext(t.Context(), `SELECT key_version FROM pki_key_envelopes WHERE key_id = ?`, created.Generation.KeyID).Scan(&keyVersion); err != nil {
		t.Fatal(err)
	}
	if keyVersion != "master-v2" {
		t.Fatalf("stored master-key version = %q, want master-v2", keyVersion)
	}
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_crl_publication_intents`, "master-v2")
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_crl_generations`, "master-v2")
}

func TestPKIStoreRewrapPinsTargetVersionAndRollsBackFailures(t *testing.T) {
	t.Parallel()

	first, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x31}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	second, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x32}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	third, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x33}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	provider := &controlledMasterKeyProvider{
		active: "master-v1",
		keys: map[string]infrapki.MasterKey{
			"master-v1": first,
			"master-v2": second,
			"master-v3": third,
		},
	}
	workspacePath := t.TempDir()
	workspaceID := domainWorkspaceID(t, "workspace-rewrap-pinned")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, provider)
	if err != nil {
		t.Fatal(err)
	}
	store := newTestPKIStore(t, workspacePath, workspaceID, protector)
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{}, pkiTestAuthorization{}, store, pkiTestAuthorization{}, pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x73))
	if err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		_, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
			ID:            domainpki.AuthorityID(fmt.Sprintf("authority-pinned-%d", index)),
			CertificateID: domainpki.CertificateID(fmt.Sprintf("cert-pinned-%d", index)),
			GenerationID:  domainpki.GenerationID(fmt.Sprintf("certgen-pinned-%d", index)),
			KeyID:         domainpki.KeyID(fmt.Sprintf("key-pinned-%d", index)),
			Name:          fmt.Sprintf("pinned root %d", index),
			Role:          domainpki.AuthorityRoleRoot,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	provider.active = "master-v2"
	provider.switchOnLookup = true
	provider.switchTo = "master-v3"
	provider.mu.Unlock()
	if count, err := store.RewrapKeys(t.Context()); err != nil || count != 2 {
		t.Fatalf("RewrapKeys() = %d, %v; want 2, nil", count, err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT key_version), MIN(key_version), MAX(key_version) FROM pki_key_envelopes`, "master-v2")
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_certificate_generations`, "master-v2")
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_authorities`, "master-v2")

	provider.mu.Lock()
	provider.active = "master-v3"
	provider.failVersion = "master-v3"
	provider.failAfter = 3
	provider.versionCalls = 0
	provider.mu.Unlock()
	if _, err := store.RewrapKeys(t.Context()); err == nil {
		t.Fatal("RewrapKeys() accepted an injected mid-operation failure")
	}
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT key_version), MIN(key_version), MAX(key_version) FROM pki_key_envelopes`, "master-v2")
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_certificate_generations`, "master-v2")
	assertOnlyMasterKeyVersion(t, db, `SELECT COUNT(DISTINCT metadata_key_version), MIN(metadata_key_version), MAX(metadata_key_version) FROM pki_authorities`, "master-v2")
}

func assertOnlyMasterKeyVersion(t *testing.T, db *sql.DB, query, expected string) {
	t.Helper()
	var count int
	var minimum, maximum string
	if err := db.QueryRowContext(t.Context(), query).Scan(&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if count != 1 || minimum != expected || maximum != expected {
		t.Fatalf("master-key versions = count %d, min %q, max %q; want only %q", count, minimum, maximum, expected)
	}
}

func TestPKIStorePersistsAuthorityRolloverAcknowledgements(t *testing.T) {
	t.Parallel()

	key, err := infrapki.NewMasterKey(bytes.Repeat([]byte{0x6d}, infrapki.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := domainWorkspaceID(t, "workspace-rollover")
	protector, err := infrapki.NewEnvelopeProtector(workspaceID, testMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewPKIStore(t.TempDir(), workspaceID, protector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logSQLiteError("close rollover test store", store.Close()) })
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(), pkiTestAuthorization{},
		pkiTestAuthorization{}, store, pkiTestAuthorization{},
		pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}, newTestEntropy(0x91),
	)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:rollover-previous", ID: "authority-sqlite-rollover-previous",
		CertificateID: "certificate-sqlite-rollover-previous",
		GenerationID:  "generation-sqlite-rollover-previous", KeyID: "key-sqlite-rollover-previous",
		Name: "SQLite rollover previous root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "sqlite:rollover-replacement", ID: "authority-sqlite-rollover-replacement",
		CertificateID: "certificate-sqlite-rollover-replacement",
		GenerationID:  "generation-sqlite-rollover-replacement", KeyID: "key-sqlite-rollover-replacement",
		Name: "SQLite rollover replacement root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{
		IdempotencyKey: "sqlite:rollover-trust-create", ID: "trust-sqlite-rollover", Name: "SQLite rollover trust",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "sqlite:rollover-trust-initial", TrustSetID: trustSet.ID,
		ExpectedRevision: trustSet.Revision, GenerationID: "trustgen-sqlite-rollover-initial",
		AnchorGenerationIDs: []domainpki.GenerationID{previous.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	activeTrust, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		IdempotencyKey: "sqlite:rollover-trust-activate", TrustSetID: trustSet.ID,
		ExpectedRevision: initialTrust.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(
		t.Context(), previous.Authority.ID, apppki.DefaultSigningLeaseDuration,
	); err != nil {
		t.Fatal(err)
	}
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:rollover-leaf", CertificateID: "certificate-sqlite-rollover-leaf",
		GenerationID: "generation-sqlite-rollover-leaf", KeyID: "key-sqlite-rollover-leaf",
		IssuerAuthorityID: previous.Authority.ID, Name: "sqlite-rollover-listener.test",
		ProfileID: domainpki.ProfileMTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "sqlite:rollover-assignment-bind", ID: "assignment-sqlite-rollover",
		Purpose: domainpki.PurposeMTLSServer, ConsumerType: domainpki.ConsumerMeshListener,
		ConsumerID: "mesh-provider/sqlite-rollover", ProfileID: domainpki.ProfileMTLSServer,
		TrustSetID: trustSet.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedAssignment, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "sqlite:rollover-assignment-stage", AssignmentID: assignment.ID,
		GenerationID: leaf.ID, ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "sqlite:rollover-assignment-activate", AssignmentID: assignment.ID,
		ExpectedRevision: stagedAssignment.Assignment.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	overlap, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "sqlite:rollover-trust-overlap", TrustSetID: trustSet.ID,
		ExpectedRevision: activeTrust.TrustSet.Revision, GenerationID: "trustgen-sqlite-rollover-overlap",
		AnchorGenerationIDs: []domainpki.GenerationID{previous.Generation.ID, replacement.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if overlap.StagedGeneration == nil {
		t.Fatal("StageTrustSet() omitted SQLite rollover overlap generation")
	}
	cancelable, err := service.StartAuthorityRollover(t.Context(), apppki.StartAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-cancelable-start", OperationID: "operation-sqlite-rollover-cancelable",
		PreviousAuthorityID: previous.Authority.ID, ReplacementAuthorityID: replacement.Authority.ID,
		TrustSetID: trustSet.ID, OverlapTrustGenerationID: overlap.StagedGeneration.ID,
		ConsumerTracking:      domainpki.RolloverConsumerTrackingExplicit,
		RequiredAssignmentIDs: []domainpki.AssignmentID{assignment.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CancelAuthorityRollover(t.Context(), apppki.CancelAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-cancel", OperationID: cancelable.Operation.ID,
		ExpectedRevision: cancelable.Operation.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	started, err := service.StartAuthorityRollover(t.Context(), apppki.StartAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-start", OperationID: "operation-sqlite-rollover",
		PreviousAuthorityID: previous.Authority.ID, ReplacementAuthorityID: replacement.Authority.ID,
		TrustSetID: trustSet.ID, OverlapTrustGenerationID: overlap.StagedGeneration.ID,
		ConsumerTracking:      domainpki.RolloverConsumerTrackingExplicit,
		RequiredAssignmentIDs: []domainpki.AssignmentID{assignment.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	acknowledged, err := service.AcknowledgeAuthorityRollover(t.Context(), apppki.AcknowledgeAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-ack", AcknowledgementID: "ack-sqlite-rollover",
		OperationID: started.Operation.ID, AssignmentID: assignment.ID, EvidenceRef: "sqlite-provider-receipt:3",
	})
	if err != nil {
		t.Fatal(err)
	}
	activated, err := service.ActivateAuthorityRollover(t.Context(), apppki.ActivateAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-activate", OperationID: started.Operation.ID,
		ExpectedRevision: started.Operation.Revision, ExpectedTrustSetRevision: overlap.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(
		t.Context(), replacement.Authority.ID, apppki.DefaultSigningLeaseDuration,
	); err != nil {
		t.Fatal(err)
	}
	replacementLeaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "sqlite:rollover-replacement-leaf",
		CertificateID:  "certificate-sqlite-rollover-replacement-leaf",
		GenerationID:   "generation-sqlite-rollover-replacement-leaf", KeyID: "key-sqlite-rollover-replacement-leaf",
		IssuerAuthorityID: replacement.Authority.ID, Name: "sqlite-rollover-listener.test",
		ProfileID: domainpki.ProfileMTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	currentAssignment, err := service.InspectAssignment(t.Context(), assignment.ID)
	if err != nil {
		t.Fatal(err)
	}
	stagedReplacement, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "sqlite:rollover-replacement-stage", AssignmentID: assignment.ID,
		GenerationID: replacementLeaf.ID, ExpectedRevision: currentAssignment.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "sqlite:rollover-replacement-activate", AssignmentID: assignment.ID,
		ExpectedRevision: stagedReplacement.Assignment.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	activeOverlap, err := service.InspectTrustSet(t.Context(), trustSet.ID)
	if err != nil {
		t.Fatal(err)
	}
	finalTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "sqlite:rollover-trust-final", TrustSetID: trustSet.ID,
		ExpectedRevision: activeOverlap.TrustSet.Revision, GenerationID: "trustgen-sqlite-rollover-final",
		AnchorGenerationIDs: []domainpki.GenerationID{replacement.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalTrust.StagedGeneration == nil {
		t.Fatal("StageTrustSet() omitted SQLite rollover final generation")
	}
	awaitingFinal, err := service.BeginAuthorityRolloverFinalTrust(
		t.Context(), apppki.BeginAuthorityRolloverFinalTrustRequest{
			IdempotencyKey: "sqlite:rollover-begin-final", OperationID: activated.Operation.ID,
			ExpectedRevision: activated.Operation.Revision, ExpectedTrustSetRevision: finalTrust.TrustSet.Revision,
			FinalTrustGenerationID: finalTrust.StagedGeneration.ID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcknowledgeAuthorityRollover(t.Context(), apppki.AcknowledgeAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-final-ack", AcknowledgementID: "ack-sqlite-rollover-final",
		OperationID: awaitingFinal.Operation.ID, AssignmentID: assignment.ID,
		EvidenceRef: "sqlite-provider-receipt:8",
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := service.CompleteAuthorityRollover(t.Context(), apppki.CompleteAuthorityRolloverRequest{
		IdempotencyKey: "sqlite:rollover-complete", OperationID: awaitingFinal.Operation.ID,
		ExpectedRevision: awaitingFinal.Operation.Revision, ExpectedTrustSetRevision: finalTrust.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Operation.Status != domainpki.OperationStatusCompleted || len(completed.Acknowledgements) != 2 {
		t.Fatalf("completed SQLite rollover = %#v", completed)
	}
	loaded, err := service.InspectOperation(t.Context(), started.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(acknowledged.MissingAssignmentIDs) != 0 || loaded.Operation.Status != domainpki.OperationStatusCompleted ||
		len(loaded.Acknowledgements) != 2 || loaded.Acknowledgements[0].EvidenceRef != "sqlite-provider-receipt:3" ||
		loaded.Acknowledgements[1].EvidenceRef != "sqlite-provider-receipt:8" {
		t.Fatalf("persisted rollover = %#v", loaded)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var operationCount, acknowledgementCount int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_operations`).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pki_consumer_acknowledgements`).Scan(&acknowledgementCount); err != nil {
		t.Fatal(err)
	}
	if operationCount != 2 || acknowledgementCount != 2 {
		t.Fatalf("operation/acknowledgement rows = %d/%d, want 2/2", operationCount, acknowledgementCount)
	}
	if _, err := db.ExecContext(t.Context(), `
UPDATE pki_consumer_acknowledgements SET evidence_ref = ? WHERE id = ?`,
		"tampered-evidence", "ack-sqlite-rollover-final"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InspectOperation(t.Context(), started.Operation.ID); err == nil {
		t.Fatal("InspectOperation() accepted acknowledgement canonical-column tampering")
	}
	if _, err := db.ExecContext(t.Context(), `
UPDATE pki_consumer_acknowledgements SET evidence_ref = ? WHERE id = ?`,
		"sqlite-provider-receipt:8", "ack-sqlite-rollover-final"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_operations SET phase = ? WHERE id = ?`,
		domainpki.AuthorityRolloverPhaseAwaitingLeafRotation, started.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InspectOperation(t.Context(), started.Operation.ID); err == nil {
		t.Fatal("InspectOperation() accepted operation canonical-column tampering")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE pki_operations SET phase = ?, operation_json = ? WHERE id = ?`,
		domainpki.AuthorityRolloverPhaseCompleted, []byte(`{"tampered":true}`), started.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InspectOperation(t.Context(), started.Operation.ID); err == nil {
		t.Fatal("InspectOperation() accepted operation authenticated-metadata tampering")
	}
}
