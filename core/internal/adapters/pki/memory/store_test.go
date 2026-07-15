package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

func TestStoreRejectsCRLAlgorithmIncompatibleWithIssuerKey(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:crl-algorithm-root", Name: "memory CRL algorithm root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := root.Authority.CreatedAt
	descriptor := infrapki.NewBackend().Descriptor()
	candidate := apppki.CRLPublicationIntent{
		ID: "crl-publication-algorithm", IdempotencyKey: "memory:crl-algorithm",
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

type testClock struct{ now time.Time }

type cancelBeforeCommitContext struct {
	context.Context
	errCalls int
}

type cancelAfterFirstCheckContext struct {
	context.Context
	firstCheck chan struct{}
	errCalls   int
}

func (c *cancelAfterFirstCheckContext) Err() error {
	c.errCalls++
	if c.errCalls == 1 {
		close(c.firstCheck)
		return nil
	}
	return context.Canceled
}

func TestOperationReadsRecheckContextAfterWaitingForLock(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := &cancelAfterFirstCheckContext{Context: t.Context(), firstCheck: make(chan struct{})}
	store.mu.Lock()
	result := make(chan error, 1)
	go func() {
		_, err := store.PKIOperations(ctx)
		result <- err
	}()
	<-ctx.firstCheck
	store.mu.Unlock()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("PKIOperations() error = %v, want context canceled", err)
	}
}

func (c *cancelBeforeCommitContext) Err() error {
	c.errCalls++
	if c.errCalls > 1 {
		return context.Canceled
	}
	return nil
}

type testAuditContext struct{}

type allowLeaseApprover struct{}

func (allowLeaseApprover) AuthorizeSigningLease(context.Context, domainpki.AuthorityID, time.Duration, apppki.AuditContext) error {
	return nil
}

func (testAuditContext) AuditContext(context.Context) (apppki.AuditContext, error) {
	return apppki.AuditContext{ActorID: "memory-test", OperationID: "memory-operation", CorrelationID: "memory-correlation"}, nil
}

const testRandomMask uint64 = 0xa5a5a5a5a5a5a5a5

func (c testClock) Now() time.Time { return c.now }

func TestStoreChecksCRLRenewalContextAtCommitBoundary(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	intent := apppki.CRLPublicationIntent{
		ID: "crl-publication-renewal-context", IdempotencyKey: "memory:crl-renewal-context",
		RequestSHA256: strings.Repeat("a", sha256.Size*2), CRLGenerationID: "crl-renewal-context",
		AuthorityID: "authority-renewal-context", IssuerGenerationID: "certgen-renewal-context", Number: 1,
		ThisUpdate: createdAt, NextUpdate: createdAt.Add(time.Hour),
		SigningBackendID: "backend-renewal-context", SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("b", sha256.Size*2),
		SignatureAlgorithm:           domainpki.SignatureAlgorithmECDSASHA256,
		Status:                       apppki.CRLPublicationStatusPending,
		Phase:                        apppki.CRLPublicationPhaseSigning,
		OwnerToken:                   "worker-renewal-context", Revision: 2,
		LeaseExpiresAt: createdAt.Add(apppki.DefaultCRLLease), CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	store.crlIntents[intent.ID] = intent.Clone()
	ctx := &cancelBeforeCommitContext{Context: t.Context()}
	if _, err := store.RenewCRLPublicationLease(
		ctx, intent.ID, intent.Ownership(), createdAt.Add(time.Minute),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("RenewCRLPublicationLease() error = %v, want context canceled", err)
	}
	if persisted := store.crlIntents[intent.ID]; !persisted.UpdatedAt.Equal(intent.UpdatedAt) ||
		persisted.Revision != intent.Revision {
		t.Fatalf("canceled renewal changed publication: %#v", persisted)
	}
}

func newTestService(t *testing.T, store *Store) apppki.Service {
	t.Helper()
	randomBytes := make([]byte, 1<<16)
	for offset := 0; offset+16 <= len(randomBytes); offset += 16 {
		binary.LittleEndian.PutUint64(randomBytes[offset:offset+8], uint64(offset/16+1))
		binary.LittleEndian.PutUint64(randomBytes[offset+8:offset+16], uint64(offset/16+1)^testRandomMask)
	}
	random := bytes.NewReader(randomBytes)
	clock := testClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}
	leases, err := apppki.NewSigningLeaseManager(clock, allowLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), leases, store, store, testAuditContext{}, clock, random)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestStoreDefensivelyCopiesKeys(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	created, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{ID: "authority-copy", CertificateID: "cert-copy", GenerationID: "certgen-copy", KeyID: "key-copy", Name: "copy root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadKey(t.Context(), created.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), loaded.PrivateKeyPKCS8...)
	loaded.PrivateKeyPKCS8[0] = 9
	reloaded, err := store.LoadKey(t.Context(), created.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded.PrivateKeyPKCS8, want) {
		t.Fatal("LoadKey() returned store-owned private key bytes")
	}
}

func TestStoreRollsBackCRLCompletionOnAuditIDCollision(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:crl-audit-root", Name: "memory CRL audit root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, apppki.DefaultSigningLeaseDuration); err != nil {
		t.Fatal(err)
	}
	published, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "memory:crl-audit", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var publicationAudit apppki.AuditRecord
	for _, audit := range store.audits {
		if audit.Action == apppki.AuditActionCRLPublish && audit.Outcome == apppki.AuditOutcomeSucceeded {
			publicationAudit = audit.Clone()
		}
	}
	if publicationAudit.ID == "" {
		t.Fatal("published CRL has no success audit")
	}
	pending := published.Publication.Clone()
	pending.Status = apppki.CRLPublicationStatusPending
	pending.ResultCRLGenerationID = ""
	pending.UpdatedAt = pending.CreatedAt
	if err := pending.Validate(); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	delete(store.crlGenerations, published.Generation.ID)
	store.crlIntents[pending.ID] = pending.Clone()
	auditCount := len(store.audits)
	store.mu.Unlock()
	if err := store.CompleteCRLPublication(
		t.Context(), pending.ID, pending.Ownership(), published.Generation, publicationAudit,
	); err == nil {
		t.Fatal("CompleteCRLPublication() accepted an existing audit id")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if _, exists := store.crlGenerations[published.Generation.ID]; exists ||
		store.crlIntents[pending.ID].Status != apppki.CRLPublicationStatusPending || len(store.audits) != auditCount {
		t.Fatal("audit collision changed CRL generation, publication, or audit inventory")
	}
}

func TestStoreRejectsDuplicateAuditRecordIDs(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	if _, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:duplicate-audit-root", Name: "duplicate audit root", Role: domainpki.AuthorityRoleRoot,
	}); err != nil {
		t.Fatal(err)
	}
	records := store.AuditRecords()
	if len(records) == 0 {
		t.Fatal("authority creation did not append an audit")
	}
	if err := store.AppendPKIAudit(t.Context(), records[0]); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("AppendPKIAudit() error = %v, want duplicate-id rejection", err)
	}
}

func TestStoreSupportsConcurrentKeyAccess(t *testing.T) {
	t.Parallel()

	const workers = 32
	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{ID: "authority-concurrent", CertificateID: "cert-root-concurrent", GenerationID: "certgen-root-concurrent", KeyID: "key-root-concurrent", Name: "concurrent root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, apppki.MaximumSigningLeaseDuration); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			id := domainpki.KeyID(fmt.Sprintf("key-concurrent-%d", index))
			generation, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
				CertificateID:     "cert-concurrent",
				GenerationID:      domainpki.GenerationID(fmt.Sprintf("certgen-concurrent-%d", index)),
				KeyID:             id,
				IssuerAuthorityID: root.Authority.ID,
				Name:              fmt.Sprintf("concurrent-%d.test", index),
			})
			if err != nil {
				errCh <- err
				return
			}
			loaded, err := store.LoadKey(t.Context(), id)
			if err != nil {
				errCh <- err
				return
			}
			if loaded.ID != id || len(loaded.PrivateKeyPKCS8) == 0 || generation.KeyID != id {
				errCh <- fmt.Errorf("loaded key %q does not match stored key", id)
			}
		}()
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestStoreClaimPreventsStaleIssuanceOwnerFromFailing(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		ID: "authority-claim", CertificateID: "cert-root-claim", GenerationID: "certgen-root-claim",
		KeyID: "key-root-claim", Name: "claim root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	intent, created, err := store.BeginIssuance(t.Context(), apppki.IssuanceIntent{
		ID: "issuance-claim", IdempotencyKey: "memory:issuance-claim",
		RequestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Kind:          apppki.IssuanceKindCertificate, CertificateID: "cert-claim", GenerationID: "certgen-claim", KeyID: "key-claim",
		IssuerAuthorityID: root.Authority.ID, IssuerGenerationID: root.Generation.ID,
		SubjectBackendID: root.Generation.BackendID, SubjectBackendVersion: root.Generation.BackendVersion,
		SubjectPackageDigest: root.Generation.BackendPackageDigest, SubjectCapabilityHash: root.Generation.BackendCapabilityHash,
		SigningBackendID: root.Generation.BackendID, SigningBackendVersion: root.Generation.BackendVersion,
		SigningPackageDigest: root.Generation.BackendPackageDigest, SigningCapabilityHash: root.Generation.BackendCapabilityHash,
		ProfileID: domainpki.ProfileTLSServer, CompatibilityTargetID: root.Generation.CompatibilityTargetID,
		CompatibilityVersion: root.Generation.CompatibilityVersion, Purpose: domainpki.PurposeTLSServer,
		ExportPolicy: root.Generation.ExportPolicy, KeyEstablishment: domainpki.KeyEstablishmentClassicalCompatible,
		TLSNamedGroups: []domainpki.TLSNamedGroup{
			domainpki.TLSNamedGroupX25519, domainpki.TLSNamedGroupP256,
			domainpki.TLSNamedGroupP384, domainpki.TLSNamedGroupP521,
		},
		ChainGenerationIDs: []domainpki.GenerationID{root.Generation.ID},
		Template:           root.Generation.Template.Clone(), Status: apppki.IssuanceStatusPending,
		OwnerToken: "original-worker", Revision: 1, LeaseExpiresAt: createdAt.Add(time.Minute), CreatedAt: createdAt, UpdatedAt: createdAt,
	})
	if err != nil || !created {
		t.Fatalf("BeginIssuance() created=%t err=%v", created, err)
	}
	if _, claimed, err := store.ClaimIssuance(t.Context(), intent.ID, intent.Ownership(), "reconciler", intent.LeaseExpiresAt.Add(-time.Second)); err != nil || claimed {
		t.Fatalf("live ClaimIssuance() claimed=%t err=%v", claimed, err)
	}
	claimedIntent, claimed, err := store.ClaimIssuance(t.Context(), intent.ID, intent.Ownership(), "reconciler", intent.LeaseExpiresAt)
	if err != nil || !claimed {
		t.Fatalf("expired ClaimIssuance() claimed=%t err=%v", claimed, err)
	}
	audit := apppki.AuditRecord{
		ID: "audit-claim", Action: apppki.AuditActionIssuance, Outcome: apppki.AuditOutcomeFailed,
		ActorID: "memory-test", OperationID: "memory-operation", CorrelationID: "memory-correlation",
		ResourceType: "issuance", ResourceID: string(intent.ID), CreatedAt: claimedIntent.UpdatedAt,
	}
	if err := store.FailIssuance(t.Context(), intent.ID, intent.Ownership(), "stale worker", claimedIntent.UpdatedAt, audit); err == nil {
		t.Fatal("FailIssuance() accepted stale ownership")
	}
	if err := store.FailIssuance(t.Context(), intent.ID, claimedIntent.Ownership(), "reconciled", claimedIntent.UpdatedAt, audit); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsLifecycleCompletionAfterSourceRevocation(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:revocation-race-root", Name: "revocation race root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "memory:revocation-race-leaf", IssuerAuthorityID: root.Authority.ID, Name: "revocation-race.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "memory:revocation-race-renew", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	var intent apppki.IssuanceIntent
	for id, candidate := range store.intents {
		if candidate.Kind == apppki.IssuanceKindCertificateRenewal && candidate.ResultGenerationID == renewed.Generation.ID {
			intent = candidate.Clone()
			intent.Status = apppki.IssuanceStatusPending
			intent.ResultGenerationID = ""
			store.intents[id] = intent.Clone()
			break
		}
	}
	revokedSource := store.generations[source.ID]
	revokedSource.State = domainpki.CertificateStateRevoked
	store.generations[source.ID] = revokedSource
	key := store.keys[source.KeyID].Clone()
	auditCount := len(store.audits)
	completionAudits := apppki.IssuanceCompletionAudits{
		SigningUse: store.audits[auditCount-2].Clone(),
		Lifecycle:  pointerToAuditRecord(store.audits[auditCount-1]),
	}
	store.mu.Unlock()
	if intent.ID == "" {
		t.Fatal("renewal issuance intent was not persisted")
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), renewed.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	if err := store.CompleteCertificateRenewal(
		t.Context(), intent.ID, intent.Ownership(), renewed.Generation, validated, completionAudits,
	); err == nil || !strings.Contains(err.Error(), "while revoked") {
		t.Fatalf("CompleteCertificateRenewal() error = %v, want revoked-source rejection", err)
	}
	storedIntent, err := store.IssuanceByKey(t.Context(), intent.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if storedIntent.Status != apppki.IssuanceStatusPending || len(store.AuditRecords()) != auditCount {
		t.Fatal("rejected lifecycle completion changed the intent or appended an audit")
	}
}

func TestStoreRollsBackLifecycleCompletionOnAuditIDCollision(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:audit-collision-root", Name: "audit collision root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "memory:audit-collision-leaf", IssuerAuthorityID: root.Authority.ID, Name: "audit-collision.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "memory:audit-collision-renew", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	var intent apppki.IssuanceIntent
	for id, candidate := range store.intents {
		if candidate.Kind == apppki.IssuanceKindCertificateRenewal && candidate.ResultGenerationID == renewed.Generation.ID {
			intent = candidate.Clone()
			intent.Status = apppki.IssuanceStatusPending
			intent.ResultGenerationID = ""
			store.intents[id] = intent.Clone()
			break
		}
	}
	key := store.keys[source.KeyID].Clone()
	auditCount := len(store.audits)
	completionAudits := apppki.IssuanceCompletionAudits{
		SigningUse: store.audits[auditCount-2].Clone(),
		Lifecycle:  pointerToAuditRecord(store.audits[auditCount-1]),
	}
	completionAudits.SigningUse.ID = store.audits[0].ID
	delete(store.generations, renewed.Generation.ID)
	store.mu.Unlock()
	if intent.ID == "" {
		t.Fatal("renewal issuance intent was not persisted")
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), renewed.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	if err := store.CompleteCertificateRenewal(
		t.Context(), intent.ID, intent.Ownership(), renewed.Generation, validated, completionAudits,
	); err == nil || !strings.Contains(err.Error(), "audit record id already exists") {
		t.Fatalf("CompleteCertificateRenewal() error = %v, want audit-id collision", err)
	}
	if _, err := store.Generation(t.Context(), renewed.Generation.ID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want rolled-back result", err)
	}
	storedIntent, err := store.IssuanceByKey(t.Context(), intent.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if storedIntent.Status != apppki.IssuanceStatusPending || len(store.AuditRecords()) != auditCount {
		t.Fatal("audit-id collision changed the intent or audit inventory")
	}
}

func TestStoreLifecycleUsesSourcePolicyInsteadOfBuiltInDefaults(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:source-policy-root", Name: "source policy root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "memory:source-policy-leaf", IssuerAuthorityID: root.Authority.ID, Name: "source-policy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	storedSource := store.generations[source.ID]
	storedSource.Purpose = domainpki.PurposeMTLSServer
	storedSource.ExportPolicy = domainpki.ExportPolicyNever
	if err := storedSource.Validate(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.generations[source.ID] = storedSource
	store.mu.Unlock()

	renewed, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "memory:source-policy-renew", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Generation.ProfileID != domainpki.ProfileTLSServer ||
		renewed.Generation.Purpose != storedSource.Purpose || renewed.Generation.ExportPolicy != storedSource.ExportPolicy {
		t.Fatalf("renewed generation policy = %#v, want source policy", renewed.Generation)
	}
	store.mu.RLock()
	var intent apppki.IssuanceIntent
	for _, candidate := range store.intents {
		if candidate.Kind == apppki.IssuanceKindCertificateRenewal && candidate.ResultGenerationID == renewed.Generation.ID {
			intent = candidate.Clone()
			break
		}
	}
	store.mu.RUnlock()
	if intent.ID == "" {
		t.Fatal("renewal issuance intent was not persisted")
	}
	if intent.Purpose != storedSource.Purpose || intent.ExportPolicy != storedSource.ExportPolicy ||
		intent.CompatibilityTargetID != storedSource.CompatibilityTargetID ||
		intent.CompatibilityVersion != storedSource.CompatibilityVersion {
		t.Fatalf("renewal intent policy = %#v, want source policy", intent)
	}
}

func TestStoreReplaysCompletedLifecycleAfterSourceBecomesIneligible(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:lifecycle-replay-root", Name: "lifecycle replay root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "memory:lifecycle-replay-leaf", IssuerAuthorityID: root.Authority.ID, Name: "lifecycle-replay.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := apppki.RenewCertificateRequest{
		IdempotencyKey: "memory:lifecycle-replay-renew", SourceGenerationID: source.ID,
	}
	renewed, err := service.RenewCertificate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	ineligible := store.generations[source.ID]
	ineligible.State = domainpki.CertificateStateRevoked
	store.generations[source.ID] = ineligible
	store.mu.Unlock()
	replayed, err := service.RenewCertificate(t.Context(), request)
	if err != nil || replayed.Generation.ID != renewed.Generation.ID {
		t.Fatalf("RenewCertificate() replay = %#v, %v; want completed generation", replayed, err)
	}
}

func TestStoreRollsBackRotationKeyOnAuditIDCollision(t *testing.T) {
	t.Parallel()

	store := NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "memory:rotation-collision-root", Name: "rotation collision root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "memory:rotation-collision-leaf", IssuerAuthorityID: root.Authority.ID, Name: "rotation-collision.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.RotateCertificate(t.Context(), apppki.RotateCertificateRequest{
		IdempotencyKey: "memory:rotation-collision-rotate", SourceGenerationID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	var intent apppki.IssuanceIntent
	for id, candidate := range store.intents {
		if candidate.Kind == apppki.IssuanceKindCertificateRotation && candidate.ResultGenerationID == rotated.Generation.ID {
			intent = candidate.Clone()
			intent.Status = apppki.IssuanceStatusPending
			intent.ResultGenerationID = ""
			store.intents[id] = intent.Clone()
			break
		}
	}
	key := store.keys[rotated.Generation.KeyID].Clone()
	auditCount := len(store.audits)
	audits := apppki.IssuanceCompletionAudits{
		SigningUse: store.audits[auditCount-2].Clone(),
		Lifecycle:  pointerToAuditRecord(store.audits[auditCount-1]),
	}
	audits.SigningUse.ID = store.audits[0].ID
	delete(store.generations, rotated.Generation.ID)
	delete(store.keys, rotated.Generation.KeyID)
	store.mu.Unlock()
	if intent.ID == "" {
		t.Fatal("rotation issuance intent was not persisted")
	}
	validated, err := apppki.ValidateKeyMaterial(t.Context(), infrapki.NewValidator(), rotated.Generation.Template.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	if err := store.CompleteCertificateIssuance(
		t.Context(), intent.ID, intent.Ownership(), rotated.Generation, validated, audits,
	); err == nil || !strings.Contains(err.Error(), "audit record id already exists") {
		t.Fatalf("CompleteCertificateIssuance() error = %v, want audit-id collision", err)
	}
	if _, err := store.Generation(t.Context(), rotated.Generation.ID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want rolled-back result", err)
	}
	if _, err := store.LoadKey(t.Context(), rotated.Generation.KeyID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("LoadKey() error = %v, want rolled-back key", err)
	}
	storedIntent, err := store.IssuanceByKey(t.Context(), intent.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if storedIntent.Status != apppki.IssuanceStatusPending || storedIntent.ResultGenerationID != "" ||
		len(store.AuditRecords()) != auditCount {
		t.Fatal("rotation audit-id collision changed the intent or audit inventory")
	}
}

func pointerToAuditRecord(record apppki.AuditRecord) *apppki.AuditRecord {
	clone := record.Clone()
	return &clone
}
