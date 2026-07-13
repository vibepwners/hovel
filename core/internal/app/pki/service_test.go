package pki_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pkimemory "github.com/vibepwners/hovel/internal/adapters/pki/memory"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

type fixedClock struct {
	now time.Time
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

type cancellationAwareBackendRegistry struct {
	called chan struct{}
	once   sync.Once
}

func (r *cancellationAwareBackendRegistry) ResolveBackend(
	context.Context,
	domainpki.BackendID,
) (apppki.Backend, error) {
	return nil, errors.New("unexpected backend resolution")
}

func (r *cancellationAwareBackendRegistry) BackendDescriptors(
	ctx context.Context,
) ([]domainpki.BackendDescriptor, error) {
	r.once.Do(func() { close(r.called) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type switchableReader struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	failing bool
}

type rolloverRacePersistence struct {
	apppki.Persistence
	beforeCreate func() error
}

func (p *rolloverRacePersistence) CreateAuthorityRollover(
	ctx context.Context,
	operation domainpki.Operation,
	audit apppki.AuditRecord,
	mutation apppki.MutationRecord,
) error {
	hook := p.beforeCreate
	p.beforeCreate = nil
	if hook != nil {
		if err := hook(); err != nil {
			return err
		}
	}
	return p.Persistence.CreateAuthorityRollover(ctx, operation, audit, mutation)
}

func newSwitchableReader(data []byte) *switchableReader {
	return &switchableReader{reader: bytes.NewReader(data)}
}

func (r *switchableReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failing {
		return 0, errors.New("test random source failed")
	}
	return r.reader.Read(buffer)
}

func (r *switchableReader) SetFailing(failing bool) {
	r.mu.Lock()
	r.failing = failing
	r.mu.Unlock()
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Add(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type fixedAuditContext struct{}

type allowSigningLeaseApprover struct{}

func (allowSigningLeaseApprover) AuthorizeSigningLease(context.Context, domainpki.AuthorityID, time.Duration, apppki.AuditContext) error {
	return nil
}

func (fixedAuditContext) AuditContext(context.Context) (apppki.AuditContext, error) {
	return apppki.AuditContext{ActorID: "test-operator", OperationID: "test-operation", CorrelationID: "test-correlation"}, nil
}

func (fixedAuditContext) AuthorizeIssuanceReconciliation(context.Context, apppki.AuditContext) error {
	return nil
}

func (fixedAuditContext) AuthorizeCRLPublicationReconciliation(context.Context, apppki.AuditContext) error {
	return nil
}

func (fixedAuditContext) AuthorizeCredentialUse(context.Context, domainpki.AssignmentID) error {
	return nil
}

type misleadingBackend struct {
	apppki.Backend
}

type namedBackend struct {
	delegate   apppki.Backend
	descriptor domainpki.BackendDescriptor
}

type sourceReusingBackend struct {
	apppki.Backend
	mu    sync.Mutex
	reuse *apppki.KeyMaterial
}

type blockingCRLBackend struct {
	apppki.Backend
	issuer  apppki.CRLIssuer
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

type invalidCRLBackend struct {
	apppki.Backend
	mu    sync.Mutex
	calls int
}

type countingCRLBackend struct {
	apppki.Backend
	mu    sync.Mutex
	calls int
}

type mutatingCRLBackend struct {
	apppki.Backend
}

type mutatingCRLValidator struct {
	apppki.Validator
	delegate apppki.CRLValidator
}

type cancelBlockingCRLValidator struct {
	apppki.Validator
	entered chan struct{}
}

type transientCRLValidator struct {
	apppki.Validator
	delegate  apppki.CRLValidator
	mu        sync.Mutex
	remaining int
}

type rejectingBundleValidator struct {
	apppki.Validator
	privateKeyAlias []byte
}

func (v *rejectingBundleValidator) ValidateBundle(
	_ context.Context,
	bundle domainpki.Bundle,
	_ time.Time,
) error {
	if bundle.PrivateKey != nil {
		v.privateKeyAlias = bundle.PrivateKey.Data
	}
	return errors.New("test bundle validation failed")
}

type crashAfterCRLCheckpointPersistence struct {
	apppki.Persistence
}

type crlPersistenceOperation uint8

const (
	crlPersistenceOperationRenew crlPersistenceOperation = iota + 1
	crlPersistenceOperationCheckpoint
	crlPersistenceOperationComplete
)

type recordingCRLPersistence struct {
	apppki.Persistence
	mu         sync.Mutex
	operations []crlPersistenceOperation
}

type transientCheckpointPersistence struct {
	apppki.Persistence
	mu        sync.Mutex
	remaining int
	calls     int
}

type transientGenerationPersistence struct {
	apppki.Persistence
	mu        sync.Mutex
	remaining int
}

type committedRenewalErrorPersistence struct {
	apppki.Persistence
	mu        sync.Mutex
	remaining int
}

type committedCheckpointErrorPersistence struct {
	apppki.Persistence
	mu        sync.Mutex
	remaining int
}

type checkpointOwnershipChangePersistence struct {
	apppki.Persistence
	mu      sync.Mutex
	changed bool
}

func (p *recordingCRLPersistence) record(operation crlPersistenceOperation) {
	p.mu.Lock()
	p.operations = append(p.operations, operation)
	p.mu.Unlock()
}

func (p *recordingCRLPersistence) Operations() []crlPersistenceOperation {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]crlPersistenceOperation(nil), p.operations...)
}

func (p *recordingCRLPersistence) RenewCRLPublicationLease(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	renewedAt time.Time,
) (apppki.CRLPublicationIntent, error) {
	p.record(crlPersistenceOperationRenew)
	return p.Persistence.RenewCRLPublicationLease(ctx, id, ownership, renewedAt)
}

func (p *recordingCRLPersistence) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	p.record(crlPersistenceOperationCheckpoint)
	return p.Persistence.CheckpointCRLPublicationSigned(ctx, id, ownership, checkpoint, audit)
}

func (p *recordingCRLPersistence) CompleteCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	generation domainpki.CRLGeneration,
	audit apppki.AuditRecord,
) error {
	p.record(crlPersistenceOperationComplete)
	return p.Persistence.CompleteCRLPublication(ctx, id, ownership, generation, audit)
}

func (p *transientCheckpointPersistence) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	p.mu.Lock()
	p.calls++
	if p.remaining > 0 {
		p.remaining--
		p.mu.Unlock()
		return apppki.CRLPublicationIntent{}, errors.New("transient checkpoint persistence failure")
	}
	p.mu.Unlock()
	return p.Persistence.CheckpointCRLPublicationSigned(ctx, id, ownership, checkpoint, audit)
}

func (p *transientCheckpointPersistence) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *transientGenerationPersistence) Generation(
	ctx context.Context,
	id domainpki.GenerationID,
) (domainpki.CertificateGeneration, error) {
	p.mu.Lock()
	if p.remaining > 0 {
		p.remaining--
		p.mu.Unlock()
		return domainpki.CertificateGeneration{}, errors.New("transient generation lookup failure")
	}
	p.mu.Unlock()
	return p.Persistence.Generation(ctx, id)
}

func (p *committedRenewalErrorPersistence) RenewCRLPublicationLease(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	renewedAt time.Time,
) (apppki.CRLPublicationIntent, error) {
	renewed, err := p.Persistence.RenewCRLPublicationLease(ctx, id, ownership, renewedAt)
	if err != nil {
		return renewed, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remaining > 0 {
		p.remaining--
		return apppki.CRLPublicationIntent{}, errors.New("committed renewal response lost")
	}
	return renewed, nil
}

func (p *committedCheckpointErrorPersistence) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	signed, err := p.Persistence.CheckpointCRLPublicationSigned(ctx, id, ownership, checkpoint, audit)
	if err != nil {
		return signed, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remaining > 0 {
		p.remaining--
		return apppki.CRLPublicationIntent{}, errors.New("committed checkpoint response lost")
	}
	return signed, nil
}

func (p *checkpointOwnershipChangePersistence) CheckpointCRLPublicationSigned(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	checkpoint apppki.CRLSignedCheckpoint,
	audit apppki.AuditRecord,
) (apppki.CRLPublicationIntent, error) {
	signed, err := p.Persistence.CheckpointCRLPublicationSigned(ctx, id, ownership, checkpoint, audit)
	if err != nil {
		return signed, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.changed {
		return signed, nil
	}
	p.changed = true
	_, claimed, err := p.ClaimCRLPublication(
		ctx,
		id,
		signed.Ownership(),
		"reconciler-checkpoint-race",
		signed.LeaseExpiresAt,
	)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	if !claimed {
		return apppki.CRLPublicationIntent{}, errors.New("checkpoint ownership change was not claimed")
	}
	return apppki.CRLPublicationIntent{}, errors.New("checkpoint response lost after ownership changed")
}

func (p crashAfterCRLCheckpointPersistence) CompleteCRLPublication(
	context.Context,
	domainpki.CRLPublicationID,
	apppki.CRLPublicationOwnership,
	domainpki.CRLGeneration,
	apppki.AuditRecord,
) error {
	return errors.New("simulated crash after crl checkpoint")
}

func (p crashAfterCRLCheckpointPersistence) FailCRLPublication(
	ctx context.Context,
	id domainpki.CRLPublicationID,
	ownership apppki.CRLPublicationOwnership,
	failure string,
	failedAt time.Time,
	stage apppki.CRLPublicationFailureStage,
	audit apppki.AuditRecord,
) error {
	intent, err := p.CRLPublication(ctx, id)
	if err != nil {
		return err
	}
	if intent.Phase == apppki.CRLPublicationPhaseSigned {
		return errors.New("simulated process loss before terminal crl transition")
	}
	return p.Persistence.FailCRLPublication(ctx, id, ownership, failure, failedAt, stage, audit)
}

func (b *invalidCRLBackend) IssueCRL(_ context.Context, request apppki.CRLIssueRequest) (apppki.IssuedCRL, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	return apppki.IssuedCRL{
		CRLDER: []byte{0xff}, FingerprintSHA256: "not-a-fingerprint",
		SignatureAlgorithm: request.SignatureAlgorithm,
	}, nil
}

func (b *invalidCRLBackend) Calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *countingCRLBackend) IssueCRL(ctx context.Context, request apppki.CRLIssueRequest) (apppki.IssuedCRL, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	issuer, ok := b.Backend.(apppki.CRLIssuer)
	if !ok {
		return apppki.IssuedCRL{}, errors.New("test backend has no crl issuer")
	}
	return issuer.IssueCRL(ctx, request)
}

func (b *countingCRLBackend) Calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *mutatingCRLBackend) IssueCRL(ctx context.Context, request apppki.CRLIssueRequest) (apppki.IssuedCRL, error) {
	issuer, ok := b.Backend.(apppki.CRLIssuer)
	if !ok {
		return apppki.IssuedCRL{}, errors.New("test backend has no crl issuer")
	}
	result, err := issuer.IssueCRL(ctx, request.Clone())
	if len(request.Entries) != 0 {
		request.Entries[0].RevocationID = "revocation-mutated-by-provider"
	}
	if len(request.IssuerCertificateDER) != 0 {
		request.IssuerCertificateDER[0] ^= 0xff
	}
	if len(request.Signer.PrivateKeyPKCS8) != 0 {
		request.Signer.PrivateKeyPKCS8[0] ^= 0xff
	}
	return result, err
}

func (v mutatingCRLValidator) ValidateCRL(
	ctx context.Context,
	request apppki.CRLValidationRequest,
	encoded []byte,
) (apppki.CRLValidationResult, error) {
	result, err := v.delegate.ValidateCRL(ctx, request.Clone(), append([]byte(nil), encoded...))
	if len(request.Entries) != 0 {
		request.Entries[0].RevocationID = "revocation-mutated-by-validator"
	}
	if len(request.IssuerCertificateDER) != 0 {
		request.IssuerCertificateDER[0] ^= 0xff
	}
	if len(encoded) != 0 {
		encoded[0] ^= 0xff
	}
	return result, err
}

func (v cancelBlockingCRLValidator) ValidateCRL(
	ctx context.Context,
	_ apppki.CRLValidationRequest,
	_ []byte,
) (apppki.CRLValidationResult, error) {
	select {
	case v.entered <- struct{}{}:
	case <-ctx.Done():
		return apppki.CRLValidationResult{}, ctx.Err()
	}
	<-ctx.Done()
	return apppki.CRLValidationResult{}, ctx.Err()
}

func (v *transientCRLValidator) ValidateCRL(
	ctx context.Context,
	request apppki.CRLValidationRequest,
	encoded []byte,
) (apppki.CRLValidationResult, error) {
	v.mu.Lock()
	if v.remaining > 0 {
		v.remaining--
		v.mu.Unlock()
		return apppki.CRLValidationResult{}, errors.New("transient validator transport failure")
	}
	v.mu.Unlock()
	return v.delegate.ValidateCRL(ctx, request, encoded)
}

func (b *blockingCRLBackend) IssueCRL(ctx context.Context, request apppki.CRLIssueRequest) (apppki.IssuedCRL, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case b.entered <- struct{}{}:
	case <-ctx.Done():
		return apppki.IssuedCRL{}, ctx.Err()
	}
	select {
	case <-b.release:
		return b.issuer.IssueCRL(ctx, request)
	case <-ctx.Done():
		return apppki.IssuedCRL{}, ctx.Err()
	}
}

func (b *blockingCRLBackend) Calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *sourceReusingBackend) GenerateKey(ctx context.Context, id domainpki.KeyID, spec domainpki.KeySpec) (apppki.KeyMaterial, error) {
	b.mu.Lock()
	var reused *apppki.KeyMaterial
	if b.reuse != nil {
		clone := b.reuse.Clone()
		reused = &clone
	}
	b.mu.Unlock()
	if reused == nil {
		return b.Backend.GenerateKey(ctx, id, spec)
	}
	material := reused.Clone()
	material.ID = id
	return material, nil
}

func (b *sourceReusingBackend) Reuse(material apppki.KeyMaterial) {
	b.mu.Lock()
	clone := material.Clone()
	b.reuse = &clone
	b.mu.Unlock()
}

func (b namedBackend) Descriptor() domainpki.BackendDescriptor { return b.descriptor.Clone() }
func (b namedBackend) GenerateKey(ctx context.Context, id domainpki.KeyID, spec domainpki.KeySpec) (apppki.KeyMaterial, error) {
	return b.delegate.GenerateKey(ctx, id, spec)
}
func (b namedBackend) Issue(ctx context.Context, request apppki.IssueRequest) (apppki.IssuedCertificate, error) {
	return b.delegate.Issue(ctx, request)
}

type overridingPersistence struct {
	apppki.Persistence
	loadKeyOverride   *apppki.KeyMaterial
	generationMutator func(domainpki.CertificateGeneration) domainpki.CertificateGeneration
}

func (p overridingPersistence) LoadKey(ctx context.Context, id domainpki.KeyID) (apppki.KeyMaterial, error) {
	if p.loadKeyOverride != nil {
		result := p.loadKeyOverride.Clone()
		result.ID = id
		return result, nil
	}
	return p.Persistence.LoadKey(ctx, id)
}

func (p overridingPersistence) Generation(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	generation, err := p.Persistence.Generation(ctx, id)
	if err != nil || p.generationMutator == nil {
		return generation, err
	}
	return p.generationMutator(generation), nil
}

func (b misleadingBackend) Issue(ctx context.Context, request apppki.IssueRequest) (apppki.IssuedCertificate, error) {
	issued, err := b.Backend.Issue(ctx, request)
	if err != nil {
		return apppki.IssuedCertificate{}, err
	}
	clear(request.SubjectPublicKeySPKI)
	clear(request.Signer.PrivateKeyPKCS8)
	issued.PublicKeySPKI = []byte("untrusted metadata")
	issued.FingerprintSHA256 = strings.Repeat("0", 64)
	issued.SubjectKeyID = []byte("wrong")
	issued.AuthorityKeyID = []byte("wrong")
	return issued, nil
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func TestServiceRenewsAndRotatesCertificateLineage(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	random := newSwitchableReader(deterministicRandomBytes(0))
	service := newTestServiceWithRandom(t, store, random)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:lifecycle-root", Name: "lifecycle root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	original, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:lifecycle-leaf", IssuerAuthorityID: root.Authority.ID,
		Name: "lifecycle.test", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	renewRequest := apppki.RenewCertificateRequest{
		IdempotencyKey: "test:lifecycle-renew", SourceGenerationID: original.ID,
	}
	renewed, err := service.RenewCertificate(t.Context(), renewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Kind != apppki.IssuanceKindCertificateRenewal || !renewed.KeyReused ||
		renewed.Generation.CertificateID != original.CertificateID || renewed.Generation.Generation != 2 ||
		renewed.Generation.KeyID != original.KeyID || !bytes.Equal(renewed.Generation.PublicKeySPKI, original.PublicKeySPKI) ||
		bytes.Equal(renewed.Generation.CertificateDER, original.CertificateDER) {
		t.Fatalf("RenewCertificate() = %#v", renewed)
	}
	for name, mutate := range map[string]func(*domainpki.CertificateGeneration){
		"revoked state": func(generation *domainpki.CertificateGeneration) {
			generation.State = domainpki.CertificateStateRevoked
		},
		"export policy drift": func(generation *domainpki.CertificateGeneration) {
			generation.ExportPolicy = domainpki.ExportPolicyNever
		},
		"compatibility version drift": func(generation *domainpki.CertificateGeneration) {
			generation.CompatibilityVersion += "-drift"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := renewed.Generation.Clone()
			mutate(&candidate)
			if err := apppki.ValidateLifecycleGenerationTransition(
				apppki.IssuanceKindCertificateRenewal, original, candidate,
			); err == nil {
				t.Fatal("ValidateLifecycleGenerationTransition() accepted policy drift")
			}
		})
	}
	random.SetFailing(true)
	replayed, err := service.RenewCertificate(t.Context(), renewRequest)
	if err != nil || replayed.Generation.ID != renewed.Generation.ID {
		t.Fatalf("idempotent RenewCertificate() = %#v, %v", replayed, err)
	}
	if _, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: renewRequest.IdempotencyKey, SourceGenerationID: renewed.Generation.ID,
	}); !errors.Is(err, apppki.ErrIdempotencyConflict) {
		t.Fatalf("conflicting RenewCertificate() error = %v, want ErrIdempotencyConflict", err)
	}
	random.SetFailing(false)
	rotated, err := service.RotateCertificate(t.Context(), apppki.RotateCertificateRequest{
		IdempotencyKey: "test:lifecycle-rotate", SourceGenerationID: renewed.Generation.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Kind != apppki.IssuanceKindCertificateRotation || rotated.KeyReused ||
		rotated.Generation.CertificateID != original.CertificateID || rotated.Generation.Generation != 3 ||
		rotated.Generation.KeyID == renewed.Generation.KeyID || bytes.Equal(rotated.Generation.PublicKeySPKI, renewed.Generation.PublicKeySPKI) {
		t.Fatalf("RotateCertificate() = %#v", rotated)
	}
	generations, err := store.Generations(t.Context(), original.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 3 {
		t.Fatalf("certificate lineage length = %d, want 3", len(generations))
	}
	lifecycleAudits := map[apppki.AuditAction]apppki.AuditRecord{}
	for _, audit := range store.AuditRecords() {
		if audit.Action == apppki.AuditActionCertificateRenew || audit.Action == apppki.AuditActionCertificateRotate {
			lifecycleAudits[audit.Action] = audit
		}
	}
	for action, expected := range map[apppki.AuditAction]struct {
		generation domainpki.GenerationID
		source     domainpki.GenerationID
	}{
		apppki.AuditActionCertificateRenew:  {generation: renewed.Generation.ID, source: original.ID},
		apppki.AuditActionCertificateRotate: {generation: rotated.Generation.ID, source: renewed.Generation.ID},
	} {
		audit, ok := lifecycleAudits[action]
		if !ok || audit.ResourceID != string(expected.generation) || audit.Details["sourceGenerationId"] != string(expected.source) {
			t.Fatalf("lifecycle audit %q = %#v", action, audit)
		}
	}
	if _, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "test:lifecycle-authority-renew", SourceGenerationID: root.Generation.ID,
	}); err == nil {
		t.Fatal("RenewCertificate() accepted an authority generation")
	}
}

func TestServiceRejectsRotationThatReusesSourceKeyBeforeCommit(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	backend := &sourceReusingBackend{Backend: infrapki.NewBackend()}
	service := newTestServiceWithBackend(t, store, backend)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:reuse-root", Name: "reuse root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	source, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:reuse-leaf", IssuerAuthorityID: root.Authority.ID, Name: "reuse.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceKey, err := store.LoadKey(t.Context(), source.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	backend.Reuse(sourceKey)
	const (
		generationID domainpki.GenerationID = "certgen-reused-source-key"
		keyID        domainpki.KeyID        = "key-reused-source-key"
	)
	if _, err := service.RotateCertificate(t.Context(), apppki.RotateCertificateRequest{
		IdempotencyKey: "test:reuse-rotate", SourceGenerationID: source.ID,
		GenerationID: generationID, KeyID: keyID,
	}); err == nil || !strings.Contains(err.Error(), "distinct key") {
		t.Fatalf("RotateCertificate() error = %v, want distinct-key rejection", err)
	}
	if _, err := store.Generation(t.Context(), generationID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("Generation() error = %v, want no committed invalid generation", err)
	}
	if _, err := store.LoadKey(t.Context(), keyID); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("LoadKey() error = %v, want no committed invalid key", err)
	}
	for _, audit := range store.AuditRecords() {
		if audit.Action == apppki.AuditActionCertificateRotate && audit.ResourceID == string(generationID) {
			t.Fatalf("invalid rotation committed success audit %#v", audit)
		}
	}
}

func TestServiceRevokesCertificateAndUpdatesAffectedAssignments(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:revocation-root", Name: "revocation root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:revocation-leaf", IssuerAuthorityID: root.Authority.ID,
		Name: "revocation.test", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:revocation-bind-active", ID: "assignment-revocation-active",
		Purpose: domainpki.PurposeTLSServer, ConsumerType: domainpki.ConsumerService,
		ConsumerID: "service-revocation-active", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedActive, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "test:revocation-stage-active", AssignmentID: active.ID,
		GenerationID: leaf.ID, ExpectedRevision: active.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	activated, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "test:revocation-activate", AssignmentID: active.ID,
		ExpectedRevision: stagedActive.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:revocation-bind-pending", ID: "assignment-revocation-pending",
		Purpose: domainpki.PurposeTLSServer, ConsumerType: domainpki.ConsumerExternal,
		ConsumerID: "external-revocation-pending", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedPending, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "test:revocation-stage-pending", AssignmentID: pending.ID,
		GenerationID: leaf.ID, ExpectedRevision: pending.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := apppki.RevokeCertificateRequest{
		IdempotencyKey: "test:revocation-commit", GenerationID: leaf.ID,
		Reason: domainpki.RevocationReasonKeyCompromise,
	}
	result, err := service.RevokeCertificate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.Generation.State != domainpki.CertificateStateRevoked ||
		result.Revocation.PreviousState != domainpki.CertificateStateActive ||
		result.Revocation.Reason != domainpki.RevocationReasonKeyCompromise ||
		len(result.AffectedAssignments) != 2 {
		t.Fatalf("RevokeCertificate() = %#v", result)
	}
	activeAfter := result.AffectedAssignments[0]
	pendingAfter := result.AffectedAssignments[1]
	if activeAfter.ID != active.ID || activeAfter.State != domainpki.AssignmentStateDegraded ||
		activeAfter.ActiveGenerationID != leaf.ID || activeAfter.Revision != activated.Assignment.Revision+1 {
		t.Fatalf("active assignment after revocation = %#v", activeAfter)
	}
	if pendingAfter.ID != pending.ID || pendingAfter.State != domainpki.AssignmentStatePending ||
		pendingAfter.StagedGenerationID != "" || pendingAfter.Revision != stagedPending.Assignment.Revision+1 {
		t.Fatalf("pending assignment after revocation = %#v", pendingAfter)
	}
	byID, err := service.InspectRevocation(t.Context(), result.Revocation.ID)
	if err != nil || byID != result.Revocation {
		t.Fatalf("InspectRevocation() = %#v, %v", byID, err)
	}
	byGeneration, err := service.InspectGenerationRevocation(t.Context(), leaf.ID)
	if err != nil || byGeneration != result.Revocation {
		t.Fatalf("InspectGenerationRevocation() = %#v, %v", byGeneration, err)
	}
	listed, err := service.ListAuthorityRevocations(t.Context(), root.Authority.ID)
	if err != nil || len(listed) != 1 || listed[0] != result.Revocation {
		t.Fatalf("ListAuthorityRevocations() = %#v, %v", listed, err)
	}
	if _, err := service.ListAuthorityRevocations(t.Context(), "authority-revocation-missing"); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("ListAuthorityRevocations() missing authority error = %v, want not found", err)
	}
	replayed, err := service.RevokeCertificate(t.Context(), request)
	if err != nil || replayed.Revocation.ID != result.Revocation.ID {
		t.Fatalf("idempotent RevokeCertificate() = %#v, %v", replayed, err)
	}
	if _, err := service.RevokeCertificate(t.Context(), apppki.RevokeCertificateRequest{
		IdempotencyKey: "test:revocation-second-key", GenerationID: leaf.ID,
		Reason: domainpki.RevocationReasonSuperseded,
	}); err == nil || !strings.Contains(err.Error(), "while revoked") {
		t.Fatalf("second RevokeCertificate() error = %v, want already-revoked rejection", err)
	}
	if _, err := service.RenewCertificate(t.Context(), apppki.RenewCertificateRequest{
		IdempotencyKey: "test:revocation-renew", SourceGenerationID: leaf.ID,
	}); err == nil || !strings.Contains(err.Error(), "while revoked") {
		t.Fatalf("RenewCertificate() error = %v, want revoked-source rejection", err)
	}
	if _, err := service.RevokeCertificate(t.Context(), apppki.RevokeCertificateRequest{
		IdempotencyKey: "test:revocation-root-self", GenerationID: root.Generation.ID,
		Reason: domainpki.RevocationReasonCACompromise,
	}); err == nil || !strings.Contains(err.Error(), "must be distrusted") {
		t.Fatalf("root RevokeCertificate() error = %v, want distrust guidance", err)
	}
	var revokeAuditCount int
	for _, audit := range store.AuditRecords() {
		if audit.Action == apppki.AuditActionCertificateRevoke && audit.ResourceID == string(leaf.ID) {
			revokeAuditCount++
		}
	}
	if revokeAuditCount != 1 {
		t.Fatalf("certificate revoke audit count = %d, want 1", revokeAuditCount)
	}
}

func TestRevokeCertificateRequestOmitsDefaultEffectiveTime(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(apppki.RevokeCertificateRequest{
		GenerationID: "certgen-revoke-wire", Reason: domainpki.RevocationReasonUnspecified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "effectiveAt") {
		t.Fatalf("RevokeCertificateRequest JSON = %s, want omitted default effective time", encoded)
	}
}

func TestServicePublishesAndReplaysSignedCRL(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-root", Name: "crl root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:crl-leaf", IssuerAuthorityID: root.Authority.ID,
		Name: "crl.test", ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := service.RevokeCertificate(t.Context(), apppki.RevokeCertificateRequest{
		IdempotencyKey: "test:crl-revoke", GenerationID: leaf.ID,
		Reason: domainpki.RevocationReasonKeyCompromise,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := apppki.PublishCRLRequest{IdempotencyKey: "test:crl-publish", AuthorityID: root.Authority.ID}
	result, err := service.PublishCRL(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.Generation.Number != 1 || len(result.Generation.RevocationIDs) != 1 ||
		result.Generation.RevocationIDs[0] != revoked.Revocation.ID ||
		result.Publication.Status != apppki.CRLPublicationStatusCompleted ||
		result.Generation.SignatureAlgorithm != domainpki.SignatureAlgorithmECDSASHA256 {
		t.Fatalf("PublishCRL() = %#v", result)
	}
	inspectedPublication, err := service.InspectCRLPublication(t.Context(), result.Publication.ID)
	if err != nil || inspectedPublication.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("InspectCRLPublication() = %#v, %v", inspectedPublication, err)
	}
	listedPublications, err := service.ListCRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(listedPublications) != 1 || listedPublications[0].ID != result.Publication.ID {
		t.Fatalf("ListCRLPublications() = %#v, %v", listedPublications, err)
	}
	parsed, err := x509.ParseRevocationList(result.Generation.CRLDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(root.Generation.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("verify published CRL signature: %v", err)
	}
	serial, err := leaf.Template.SerialNumber.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 ||
		!bytes.Equal(parsed.RevokedCertificateEntries[0].SerialNumber.Bytes(), serial) {
		t.Fatalf("published CRL entries = %#v", parsed.RevokedCertificateEntries)
	}
	inspected, err := service.InspectCRLGeneration(t.Context(), result.Generation.ID)
	if err != nil || !bytes.Equal(inspected.CRLDER, result.Generation.CRLDER) {
		t.Fatalf("InspectCRLGeneration() = %#v, %v", inspected, err)
	}
	listed, err := service.ListCRLGenerations(t.Context(), root.Authority.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != result.Generation.ID {
		t.Fatalf("ListCRLGenerations() = %#v, %v", listed, err)
	}
	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{
		IdempotencyKey: "test:crl-trust-create", Name: "CRL trust",
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "test:crl-trust-stage", TrustSetID: trustSet.ID,
		ExpectedRevision: trustSet.Revision, AnchorGenerationIDs: []domainpki.GenerationID{root.Generation.ID},
		CRLGenerationIDs: []domainpki.CRLGenerationID{result.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stagedTrust.StagedGeneration == nil || len(stagedTrust.StagedGeneration.CRLGenerationIDs) != 1 {
		t.Fatalf("StageTrustSet() = %#v", stagedTrust)
	}
	replayed, err := service.PublishCRL(t.Context(), request)
	if err != nil || replayed.Generation.ID != result.Generation.ID ||
		!bytes.Equal(replayed.Generation.CRLDER, result.Generation.CRLDER) {
		t.Fatalf("replayed PublishCRL() = %#v, %v", replayed, err)
	}
	second, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-publish-second", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation.Number != 2 || second.Generation.ID == result.Generation.ID {
		t.Fatalf("second PublishCRL() = %#v", second)
	}
	var publishAudits int
	for _, audit := range store.AuditRecords() {
		if audit.Action == apppki.AuditActionCRLPublish {
			publishAudits++
		}
	}
	if publishAudits != 2 {
		t.Fatalf("crl publish audit count = %d, want 2", publishAudits)
	}
}

func TestServicePreventsConcurrentCRLSigningForOneIdempotencyKey(t *testing.T) {
	store := pkimemory.NewStore()
	builtin := infrapki.NewBackend()
	backend := &blockingCRLBackend{
		Backend: builtin, issuer: builtin,
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	service := newTestServiceWithBackend(t, store, backend)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-concurrency-root", Name: "crl concurrency root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	request := apppki.PublishCRLRequest{IdempotencyKey: "test:crl-concurrency", AuthorityID: root.Authority.ID}
	type publicationResult struct {
		value apppki.CRLPublicationResult
		err   error
	}
	first := make(chan publicationResult, 1)
	go func() {
		value, publishErr := service.PublishCRL(t.Context(), request)
		first <- publicationResult{value: value, err: publishErr}
	}()
	select {
	case <-backend.entered:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if _, err := service.PublishCRL(t.Context(), request); !errors.Is(err, apppki.ErrCRLPublicationInProgress) {
		t.Fatalf("concurrent PublishCRL() error = %v, want in progress", err)
	}
	close(backend.release)
	completed := <-first
	if completed.err != nil || completed.value.Publication.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("first PublishCRL() = %#v, %v", completed.value, completed.err)
	}
	if calls := backend.Calls(); calls != 1 {
		t.Fatalf("IssueCRL() calls = %d, want 1", calls)
	}
}

func TestServiceIsolatesCRLProviderAndValidatorInputs(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	builtinBackend := infrapki.NewBackend()
	builtinValidator := infrapki.NewValidator()
	backend := &mutatingCRLBackend{Backend: builtinBackend}
	validator := mutatingCRLValidator{Validator: builtinValidator, delegate: builtinValidator}
	service := newTestServiceWithCrypto(t, store, backend, validator, fixedClock{now: fixedTestTime})
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-isolation-root", Name: "crl isolation root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	result, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-isolation", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(root.Generation.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(result.Generation.CRLDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
}

func TestServiceFencesCRLOwnershipThroughCheckpointAndCompletion(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	persistence := &recordingCRLPersistence{Persistence: store}
	service := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-fencing-root", Name: "crl fencing root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	result, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-fencing", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []crlPersistenceOperation{
		crlPersistenceOperationRenew,
		crlPersistenceOperationCheckpoint,
		crlPersistenceOperationRenew,
		crlPersistenceOperationRenew,
		crlPersistenceOperationComplete,
	}
	operations := persistence.Operations()
	if len(operations) != len(want) {
		t.Fatalf("CRL persistence operations = %v, want %v", operations, want)
	}
	for index := range want {
		if operations[index] != want[index] {
			t.Fatalf("CRL persistence operations = %v, want %v", operations, want)
		}
	}
	if result.Publication.Revision != 6 {
		t.Fatalf("completed publication revision = %d, want 6", result.Publication.Revision)
	}
}

func TestServiceRetriesTransientCRLCheckpointPersistenceFailure(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	persistence := &transientCheckpointPersistence{Persistence: store, remaining: 1}
	service := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-checkpoint-retry-root", Name: "crl checkpoint retry root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	result, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-checkpoint-retry", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Publication.Status != apppki.CRLPublicationStatusCompleted || persistence.Calls() != 2 {
		t.Fatalf("PublishCRL() = %#v with %d checkpoint calls, want completed with 2 calls", result, persistence.Calls())
	}
}

func TestServiceRecoversCommittedCRLLeaseRenewalWithLostResponse(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	persistence := &committedRenewalErrorPersistence{Persistence: store, remaining: 1}
	service := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-renewal-uncertain-root", Name: "crl renewal uncertain root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	result, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-renewal-uncertain", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Publication.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("PublishCRL() = %#v", result)
	}
}

func TestServiceRecoversCommittedCRLCheckpointWithLostResponse(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	persistence := &committedCheckpointErrorPersistence{Persistence: store, remaining: 1}
	service := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-checkpoint-uncertain-root", Name: "crl checkpoint uncertain root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	result, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-checkpoint-uncertain", AuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Publication.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("PublishCRL() = %#v", result)
	}
}

func TestServiceDoesNotAdoptChangedCRLCheckpointOwnership(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	persistence := &checkpointOwnershipChangePersistence{Persistence: store}
	service := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-checkpoint-owner-root", Name: "crl checkpoint owner root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	if _, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-checkpoint-owner", AuthorityID: root.Authority.ID,
	}); err == nil {
		t.Fatal("PublishCRL() adopted changed checkpoint ownership")
	}
	publications, err := store.CRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(publications) != 1 {
		t.Fatalf("CRLPublications() = %#v, %v", publications, err)
	}
	pending := publications[0]
	if pending.Status != apppki.CRLPublicationStatusPending ||
		pending.Phase != apppki.CRLPublicationPhaseSigned ||
		pending.OwnerToken != "reconciler-checkpoint-race" {
		t.Fatalf("publication with changed ownership = %#v", pending)
	}
}

func TestServicePreservesSignedCRLAfterTransientValidatorError(t *testing.T) {
	store := pkimemory.NewStore()
	builtinValidator := infrapki.NewValidator()
	validator := &transientCRLValidator{
		Validator: builtinValidator, delegate: builtinValidator, remaining: 1,
	}
	service := newTestServiceWithCrypto(
		t, store, infrapki.NewBackend(), validator, fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-validator-transient-root", Name: "crl validator transient root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	if _, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-validator-transient", AuthorityID: root.Authority.ID,
	}); err == nil {
		t.Fatal("PublishCRL() accepted transient validator failure")
	}
	publications, err := store.CRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(publications) != 1 {
		t.Fatalf("CRLPublications() = %#v, %v", publications, err)
	}
	pending := publications[0]
	if pending.Status != apppki.CRLPublicationStatusPending ||
		pending.Phase != apppki.CRLPublicationPhaseSigned || pending.SignedCheckpoint == nil {
		t.Fatalf("publication after transient validator error = %#v", pending)
	}
	recovery := newTestServiceWithPersistenceAndBackend(
		t, store, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime.Add(10 * time.Minute)},
	)
	reconciled, err := recovery.ReconcilePendingCRLPublication(t.Context(), pending.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("reconciled publication = %#v", reconciled)
	}
}

func TestServiceLeavesSignedCRLCheckpointRecoverableAfterCancellation(t *testing.T) {
	store := pkimemory.NewStore()
	builtinValidator := infrapki.NewValidator()
	validator := cancelBlockingCRLValidator{
		Validator: builtinValidator,
		entered:   make(chan struct{}, 1),
	}
	service := newTestServiceWithCrypto(
		t, store, infrapki.NewBackend(), validator, fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-cancel-root", Name: "crl cancel root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, publishErr := service.PublishCRL(ctx, apppki.PublishCRLRequest{
			IdempotencyKey: "test:crl-cancel", AuthorityID: root.Authority.ID,
		})
		result <- publishErr
	}()
	select {
	case <-validator.entered:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishCRL() error = %v, want context cancellation", err)
	}
	publications, err := store.CRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(publications) != 1 {
		t.Fatalf("CRLPublications() = %#v, %v", publications, err)
	}
	pending := publications[0]
	if pending.Status != apppki.CRLPublicationStatusPending ||
		pending.Phase != apppki.CRLPublicationPhaseSigned || pending.SignedCheckpoint == nil {
		t.Fatalf("canceled publication = %#v", pending)
	}
	recovery := newTestServiceWithPersistenceAndBackend(
		t, store, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime.Add(10 * time.Minute)},
	)
	reconciled, err := recovery.ReconcilePendingCRLPublication(t.Context(), pending.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("reconciled publication = %#v", reconciled)
	}
}

func TestServicePreservesSignedCRLCheckpointAfterTransientReconciliationFailure(t *testing.T) {
	store := pkimemory.NewStore()
	crashing := crashAfterCRLCheckpointPersistence{Persistence: store}
	service := newTestServiceWithPersistenceAndBackend(
		t, crashing, store, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-transient-reconcile-root", Name: "crl transient reconcile root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	if _, err := service.PublishCRL(t.Context(), apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-transient-reconcile", AuthorityID: root.Authority.ID,
	}); err == nil {
		t.Fatal("PublishCRL() unexpectedly completed across simulated crash")
	}
	publications, err := store.CRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(publications) != 1 {
		t.Fatalf("CRLPublications() = %#v, %v", publications, err)
	}
	persistence := &transientGenerationPersistence{Persistence: store, remaining: 1}
	clock := &mutableClock{now: fixedTestTime.Add(10 * time.Minute)}
	recovery := newTestServiceWithPersistenceAndBackend(
		t, persistence, store, infrapki.NewBackend(), clock,
	)
	if _, err := recovery.ReconcilePendingCRLPublication(
		t.Context(), publications[0].ID, time.Minute,
	); err == nil {
		t.Fatal("ReconcilePendingCRLPublication() accepted transient generation lookup failure")
	}
	pending, err := store.CRLPublication(t.Context(), publications[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != apppki.CRLPublicationStatusPending ||
		pending.Phase != apppki.CRLPublicationPhaseSigned || pending.SignedCheckpoint == nil {
		t.Fatalf("publication after transient reconciliation failure = %#v", pending)
	}
	clock.Add(10 * time.Minute)
	reconciled, err := recovery.ReconcilePendingCRLPublication(t.Context(), pending.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.CRLPublicationStatusCompleted {
		t.Fatalf("reconciled publication = %#v", reconciled)
	}
}

func TestServiceAuditsAndCanonicallyFailsInvalidProviderCRL(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	backend := &invalidCRLBackend{Backend: infrapki.NewBackend()}
	service := newTestServiceWithBackend(t, store, backend)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-invalid-root", Name: "crl invalid root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	request := apppki.PublishCRLRequest{IdempotencyKey: "test:crl-invalid", AuthorityID: root.Authority.ID}
	if _, err := service.PublishCRL(t.Context(), request); err == nil {
		t.Fatal("PublishCRL() accepted invalid provider output")
	}
	if _, err := service.PublishCRL(t.Context(), request); err == nil || backend.Calls() != 1 {
		t.Fatalf("failed replay error = %v, IssueCRL() calls = %d", err, backend.Calls())
	}
	var signingAttempts, publicationFailures int
	var publicationID domainpki.CRLPublicationID
	for _, audit := range store.AuditRecords() {
		if audit.Action == apppki.AuditActionSigningUse && audit.Outcome == apppki.AuditOutcomeAttempted {
			signingAttempts++
		}
		if audit.Action == apppki.AuditActionCRLPublish && audit.Outcome == apppki.AuditOutcomeFailed {
			publicationFailures++
			publicationID, err = apppki.CRLPublicationIDFromAudit(audit)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if signingAttempts != 1 || publicationFailures != 1 {
		t.Fatalf("CRL failure audits = %d signing attempts/%d publication failures, want 1/1", signingAttempts, publicationFailures)
	}
	intent, err := store.CRLPublication(t.Context(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status != apppki.CRLPublicationStatusFailed ||
		intent.Failure != "crl publication failed during validation" {
		t.Fatalf("failed CRL publication = %#v", intent)
	}
}

func TestServiceReconcilesStalePendingCRLPublication(t *testing.T) {
	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-reconcile-root", Name: "crl reconcile root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := infrapki.NewBackend().Descriptor()
	createdAt := fixedTestTime.Add(-10 * time.Minute)
	intent := apppki.CRLPublicationIntent{
		ID: "crl-publication-stale", IdempotencyKey: "test:crl-stale", RequestSHA256: strings.Repeat("a", sha256.Size*2),
		CRLGenerationID: "crl-stale", AuthorityID: root.Authority.ID, IssuerGenerationID: root.Generation.ID,
		ThisUpdate: createdAt, NextUpdate: createdAt.Add(24 * time.Hour),
		SigningBackendID: descriptor.ID, SigningBackendVersion: descriptor.Version,
		SigningBackendPackageDigest: descriptor.PackageDigest, SigningBackendCapabilityHash: descriptor.CapabilityHash,
		SignatureAlgorithm: domainpki.SignatureAlgorithmECDSASHA256,
		Status:             apppki.CRLPublicationStatusPending, Phase: apppki.CRLPublicationPhasePlanned,
		OwnerToken: "worker-stale", Revision: 1,
		LeaseExpiresAt: createdAt.Add(apppki.DefaultCRLLease), CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if _, created, err := store.BeginCRLPublication(t.Context(), intent, nil); err != nil || !created {
		t.Fatalf("BeginCRLPublication() created=%t err=%v", created, err)
	}
	reconciled, err := service.ReconcilePendingCRLPublication(t.Context(), intent.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.CRLPublicationStatusFailed || reconciled.Revision != 2 ||
		reconciled.Failure != "crl publication failed during reconciliation" {
		t.Fatalf("ReconcilePendingCRLPublication() = %#v", reconciled)
	}
}

func TestServiceReconcilesSignedCRLCheckpointWithoutSigningAgain(t *testing.T) {
	store := pkimemory.NewStore()
	backend := &countingCRLBackend{Backend: infrapki.NewBackend()}
	crashing := crashAfterCRLCheckpointPersistence{Persistence: store}
	service := newTestServiceWithPersistenceAndBackend(t, crashing, store, backend, fixedClock{now: fixedTestTime})
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:crl-checkpoint-root", Name: "crl checkpoint root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	request := apppki.PublishCRLRequest{
		IdempotencyKey: "test:crl-checkpoint", AuthorityID: root.Authority.ID,
	}
	if _, err := service.PublishCRL(t.Context(), request); err == nil {
		t.Fatal("PublishCRL() unexpectedly completed across simulated crash")
	}
	if backend.Calls() != 1 {
		t.Fatalf("IssueCRL() calls = %d, want 1 before reconciliation", backend.Calls())
	}
	publications, err := store.CRLPublications(t.Context(), root.Authority.ID)
	if err != nil || len(publications) != 1 {
		t.Fatalf("CRLPublications() = %#v, %v", publications, err)
	}
	pending := publications[0]
	if pending.Status != apppki.CRLPublicationStatusPending ||
		pending.Phase != apppki.CRLPublicationPhaseSigned || pending.SignedCheckpoint == nil {
		t.Fatalf("signed pending publication = %#v", pending)
	}
	recoveryClock := fixedClock{now: fixedTestTime.Add(10 * time.Minute)}
	recovery := newTestServiceWithPersistenceAndBackend(t, store, store, infrapki.NewBackend(), recoveryClock)
	reconciled, err := recovery.ReconcilePendingCRLPublication(
		t.Context(), pending.ID, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.CRLPublicationStatusCompleted ||
		reconciled.Phase != apppki.CRLPublicationPhaseSigned {
		t.Fatalf("reconciled publication = %#v", reconciled)
	}
	if backend.Calls() != 1 {
		t.Fatalf("IssueCRL() calls after reconciliation = %d, want 1", backend.Calls())
	}
	if _, err := store.CRLGeneration(t.Context(), reconciled.ResultCRLGenerationID); err != nil {
		t.Fatal(err)
	}
}

func TestServiceIssuesHierarchyAndExportsBundles(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name: "Hovel test root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	subordinate, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name:              "Hovel test subordinate",
		Role:              domainpki.AuthorityRoleSubordinate,
		ParentAuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, subordinate.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IssuerAuthorityID: subordinate.Authority.ID,
		Name:              "listener.test",
		ProfileID:         domainpki.ProfilePQHybridMutual,
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Generation != 1 || len(leaf.ChainGenerationIDs) != 2 {
		t.Fatalf("leaf generation = %#v", leaf)
	}
	if leaf.KeyEstablishment != domainpki.KeyEstablishmentHybridPQRequired || leaf.Template.SignatureAlgorithm == domainpki.SignatureAlgorithmAuto || len(leaf.TLSNamedGroups) == 0 {
		t.Fatalf("leaf did not persist resolved security policy: %#v", leaf)
	}
	if leaf.ChainGenerationIDs[0] != subordinate.Generation.ID || leaf.ChainGenerationIDs[1] != root.Generation.ID {
		t.Fatalf("leaf chain ids = %v", leaf.ChainGenerationIDs)
	}
	authorities, err := service.ListAuthorities(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	listedAuthorityIDs := make(map[domainpki.AuthorityID]struct{}, len(authorities))
	for _, authority := range authorities {
		listedAuthorityIDs[authority.ID] = struct{}{}
	}
	if len(authorities) != 2 {
		t.Fatalf("ListAuthorities() = %#v", authorities)
	}
	if _, ok := listedAuthorityIDs[root.Authority.ID]; !ok {
		t.Fatalf("ListAuthorities() omitted root: %#v", authorities)
	}
	if _, ok := listedAuthorityIDs[subordinate.Authority.ID]; !ok {
		t.Fatalf("ListAuthorities() omitted subordinate: %#v", authorities)
	}
	inspection, err := service.InspectAuthority(t.Context(), subordinate.Authority.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Authority.ID != subordinate.Authority.ID || inspection.ActiveGeneration.ID != subordinate.Generation.ID {
		t.Fatalf("InspectAuthority() = %#v", inspection)
	}
	generations, err := service.ListCertificateGenerations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 3 {
		t.Fatalf("ListCertificateGenerations() returned %d generations, want 3", len(generations))
	}
	inspectedLeaf, err := service.InspectCertificateGeneration(t.Context(), leaf.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inspectedLeaf.ID != leaf.ID || inspectedLeaf.KeyID != leaf.KeyID {
		t.Fatalf("InspectCertificateGeneration() = %#v", inspectedLeaf)
	}

	if _, err := service.ExportBundle(t.Context(), leaf.ID, domainpki.PurposeDualRoleMTLS, true); !errors.Is(err, apppki.ErrPrivateKeyExportDenied) {
		t.Fatalf("unauthorized private export error = %v", err)
	}
	if _, err := service.ExportBundle(t.Context(), leaf.ID, domainpki.PurposeCodeSigning, false); err == nil {
		t.Fatal("ExportBundle() accepted a purpose that differs from the certificate profile")
	}
	store.AllowPrivateExport(leaf.ID)
	privateBundle, err := service.ExportBundle(t.Context(), leaf.ID, domainpki.PurposeDualRoleMTLS, true)
	if err != nil {
		t.Fatal(err)
	}
	defer privateBundle.Clear()
	if privateBundle.PrivateKey == nil || len(privateBundle.Chain) != 1 || len(privateBundle.TrustAnchors) != 1 {
		t.Fatalf("private bundle = %#v", privateBundle)
	}
	if privateBundle.KeyEstablishmentPolicy != domainpki.KeyEstablishmentHybridPQRequired || privateBundle.CompatibilityTargetID != domainpki.CompatibilityGo126PQHybrid {
		t.Fatalf("private bundle quantum-safe metadata = %#v", privateBundle)
	}
	if privateBundle.Chain[0].GenerationID != subordinate.Generation.ID || privateBundle.TrustAnchors[0].GenerationID != root.Generation.ID {
		t.Fatalf("bundle chain = %#v, trust = %#v", privateBundle.Chain, privateBundle.TrustAnchors)
	}
	encoded, err := json.Marshal(privateBundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"privateKey"`)) {
		t.Fatalf("private bundle json = %s", encoded)
	}

	publicBundle, err := service.ExportBundle(t.Context(), leaf.ID, domainpki.PurposeDualRoleMTLS, false)
	if err != nil {
		t.Fatal(err)
	}
	defer publicBundle.Clear()
	if publicBundle.PrivateKey != nil || publicBundle.PrivateKeyRef != nil {
		t.Fatal("public bundle includes private material")
	}
	publicJSON, err := json.Marshal(publicBundle)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivateKey := base64.StdEncoding.EncodeToString(privateBundle.PrivateKey.Data)
	if bytes.Contains(publicJSON, []byte(`"privateKey"`)) || bytes.Contains(publicJSON, []byte(encodedPrivateKey)) {
		t.Fatalf("public bundle leaked private material: %s", publicJSON)
	}
	auditJSON, err := json.Marshal(store.AuditRecords())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditJSON, privateBundle.PrivateKey.Data) || bytes.Contains(auditJSON, []byte(encodedPrivateKey)) {
		t.Fatalf("audit records leaked private material: %s", auditJSON)
	}
	var denied, exported, keyAccess bool
	for _, record := range store.AuditRecords() {
		if record.Action == apppki.AuditActionExportAuthorization && record.Outcome == apppki.AuditOutcomeDenied {
			denied = true
		}
		if record.Action == apppki.AuditActionPrivateExport && record.Outcome == apppki.AuditOutcomeSucceeded {
			exported = true
		}
		if record.Action == apppki.AuditActionKeyAccess && record.Details["purpose"] == "private-export" {
			keyAccess = true
		}
	}
	if !denied || !exported || !keyAccess {
		t.Fatalf("audit records missing denial/export/key access: %#v", store.AuditRecords())
	}
	store.AllowPrivateExport(root.Generation.ID)
	if _, err := service.ExportBundle(t.Context(), root.Generation.ID, domainpki.PurposeCustom, true); !errors.Is(err, apppki.ErrPrivateKeyExportDenied) {
		t.Fatalf("root private export policy error = %v", err)
	}
}

func TestExportBundleClearsPrivateMaterialAfterValidationFailure(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	validator := &rejectingBundleValidator{Validator: infrapki.NewValidator()}
	service := newTestServiceWithCrypto(
		t,
		store,
		infrapki.NewBackend(),
		validator,
		fixedClock{now: fixedTestTime},
	)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name: "bundle cleanup root",
		Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IssuerAuthorityID: root.Authority.ID,
		Name:              "bundle-cleanup.test",
		ProfileID:         domainpki.ProfilePQHybridMutual,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.AllowPrivateExport(leaf.ID)
	if _, err := service.ExportBundle(
		t.Context(), leaf.ID, leaf.Purpose, true,
	); err == nil || !strings.Contains(err.Error(), "test bundle validation failed") {
		t.Fatalf("ExportBundle() error = %v, want validator failure", err)
	}
	if len(validator.privateKeyAlias) == 0 {
		t.Fatal("validator did not observe private bundle material")
	}
	for _, value := range validator.privateKeyAlias {
		if value != 0 {
			t.Fatalf("failed bundle retained private material: %v", validator.privateKeyAlias)
		}
	}
}

func TestServiceManagesTrustAndAssignmentActivation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		ID: "authority-assignment-root", CertificateID: "certificate-assignment-root",
		GenerationID: "generation-assignment-root", KeyID: "key-assignment-root",
		Name: "Assignment root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{ID: "trust-assignment", Name: "Assignment trust"})
	if err != nil {
		t.Fatal(err)
	}
	stagedTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		TrustSetID: trustSet.ID, ExpectedRevision: trustSet.Revision,
		GenerationID: "trust-assignment-generation-1", AnchorGenerationIDs: []domainpki.GenerationID{root.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	activeTrust, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		TrustSetID: trustSet.ID, ExpectedRevision: stagedTrust.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		CertificateID: "certificate-assignment-leaf", GenerationID: "generation-assignment-leaf",
		KeyID: "key-assignment-leaf", IssuerAuthorityID: root.Authority.ID,
		Name: "assignment-listener.test", ProfileID: domainpki.ProfileMTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		ID: "assignment-listener", Purpose: domainpki.PurposeMTLSServer,
		ConsumerType: domainpki.ConsumerMeshListener, ConsumerID: "mesh-provider/listener-edge",
		ProfileID: domainpki.ProfileMTLSServer, TrustSetID: activeTrust.TrustSet.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedAssignment, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		AssignmentID: assignment.ID, GenerationID: leaf.ID, ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	activeAssignment, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		AssignmentID: assignment.ID, ExpectedRevision: stagedAssignment.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if activeAssignment.Assignment.ActiveGenerationID != leaf.ID || activeAssignment.ActiveGeneration == nil ||
		activeAssignment.Assignment.ActiveTrustGenerationID != "trust-assignment-generation-1" ||
		activeAssignment.Assignment.State != domainpki.AssignmentStateActive {
		t.Fatalf("ActivateAssignment() = %#v", activeAssignment)
	}
	secondStagedTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		TrustSetID: activeTrust.TrustSet.ID, ExpectedRevision: activeTrust.TrustSet.Revision,
		GenerationID: "trust-assignment-generation-2", AnchorGenerationIDs: []domainpki.GenerationID{root.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondActiveTrust, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		TrustSetID: activeTrust.TrustSet.ID, ExpectedRevision: secondStagedTrust.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondActiveTrust.TrustSet.ActiveGenerationID != "trust-assignment-generation-2" {
		t.Fatalf("second trust activation = %#v", secondActiveTrust)
	}
	inspection, err := service.InspectAssignment(t.Context(), assignment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.TrustSet == nil || inspection.ActiveTrustGeneration == nil || inspection.ActiveGeneration == nil {
		t.Fatalf("InspectAssignment() omitted resolved generations: %#v", inspection)
	}
	if inspection.ActiveTrustGeneration.ID != "trust-assignment-generation-1" {
		t.Fatalf("InspectAssignment() trust generation = %q, want pinned generation 1", inspection.ActiveTrustGeneration.ID)
	}
	assignments, err := service.ListAssignments(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	trustSets, err := service.ListTrustSets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || len(trustSets) != 1 {
		t.Fatalf("assignment/trust inventory = %d/%d, want 1/1", len(assignments), len(trustSets))
	}
	unbindRequest := apppki.UnbindAssignmentRequest{
		IdempotencyKey: "test:assignment-unbind", AssignmentID: assignment.ID,
		ExpectedRevision: activeAssignment.Assignment.Revision,
	}
	retired, err := service.UnbindAssignment(t.Context(), unbindRequest)
	if err != nil {
		t.Fatal(err)
	}
	if retired.State != domainpki.AssignmentStateRetired || retired.ActiveGenerationID != leaf.ID {
		t.Fatalf("UnbindAssignment() = %#v", retired)
	}
	replayedRetirement, err := service.UnbindAssignment(t.Context(), unbindRequest)
	if err != nil || replayedRetirement != retired {
		t.Fatalf("idempotent UnbindAssignment() = %#v, %v; want %#v, nil", replayedRetirement, err, retired)
	}
	if _, err := service.UnbindAssignment(t.Context(), apppki.UnbindAssignmentRequest{
		IdempotencyKey: "test:assignment-unbind-stale", AssignmentID: assignment.ID,
		ExpectedRevision: activeAssignment.Assignment.Revision,
	}); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale UnbindAssignment() error = %v, want revision conflict", err)
	}
	if _, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		ID: "assignment-listener-rebound", Purpose: domainpki.PurposeMTLSServer,
		ConsumerType: domainpki.ConsumerMeshListener, ConsumerID: "mesh-provider/listener-edge",
		ProfileID: domainpki.ProfileMTLSServer, TrustSetID: activeTrust.TrustSet.ID,
	}); err != nil {
		t.Fatalf("BindAssignment() after retirement error = %v", err)
	}

	actions := make(map[apppki.AuditAction]bool)
	for _, record := range store.AuditRecords() {
		actions[record.Action] = true
	}
	for _, action := range []apppki.AuditAction{
		apppki.AuditActionTrustSetCreate, apppki.AuditActionTrustSetStage, apppki.AuditActionTrustSetActivate,
		apppki.AuditActionAssignmentBind, apppki.AuditActionAssignmentStage,
		apppki.AuditActionAssignmentActivate, apppki.AuditActionAssignmentUnbind,
	} {
		if !actions[action] {
			t.Errorf("audit records omitted action %q", action)
		}
	}
}

func TestServiceTracksAuthorityRolloverAcknowledgements(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	racingPersistence := &rolloverRacePersistence{Persistence: store}
	service := newTestServiceWithPersistence(t, racingPersistence, store)
	previous, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:rollover-previous", ID: "authority-rollover-previous",
		CertificateID: "certificate-rollover-previous", GenerationID: "generation-rollover-previous",
		KeyID: "key-rollover-previous", Name: "Rollover previous root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:rollover-replacement", ID: "authority-rollover-replacement",
		CertificateID: "certificate-rollover-replacement", GenerationID: "generation-rollover-replacement",
		KeyID: "key-rollover-replacement", Name: "Rollover replacement root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{
		IdempotencyKey: "test:rollover-trust-create", ID: "trust-rollover", Name: "Rollover trust",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "test:rollover-trust-initial", TrustSetID: trustSet.ID,
		ExpectedRevision: trustSet.Revision, GenerationID: "trustgen-rollover-initial",
		AnchorGenerationIDs: []domainpki.GenerationID{previous.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	activeTrust, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		IdempotencyKey: "test:rollover-trust-activate", TrustSetID: trustSet.ID,
		ExpectedRevision: initialTrust.TrustSet.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, previous.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:rollover-leaf", CertificateID: "certificate-rollover-leaf",
		GenerationID: "generation-rollover-leaf", KeyID: "key-rollover-leaf",
		IssuerAuthorityID: previous.Authority.ID, Name: "rollover-listener.test",
		ProfileID: domainpki.ProfileMTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:rollover-assignment-bind", ID: "assignment-rollover-listener",
		Purpose: domainpki.PurposeMTLSServer, ConsumerType: domainpki.ConsumerMeshListener,
		ConsumerID: "mesh-provider/rollover-listener", ProfileID: domainpki.ProfileMTLSServer,
		TrustSetID: activeTrust.TrustSet.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	stagedAssignment, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "test:rollover-assignment-stage", AssignmentID: assignment.ID,
		GenerationID: leaf.ID, ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "test:rollover-assignment-activate", AssignmentID: assignment.ID,
		ExpectedRevision: stagedAssignment.Assignment.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	overlap, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "test:rollover-trust-overlap", TrustSetID: trustSet.ID,
		ExpectedRevision: activeTrust.TrustSet.Revision, GenerationID: "trustgen-rollover-overlap",
		AnchorGenerationIDs: []domainpki.GenerationID{previous.Generation.ID, replacement.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if overlap.StagedGeneration == nil {
		t.Fatal("StageTrustSet() omitted rollover overlap generation")
	}
	var lateAssignment domainpki.Assignment
	racingPersistence.beforeCreate = func() error {
		bound, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
			IdempotencyKey: "test:rollover-late-assignment-bind", ID: "assignment-rollover-late",
			Purpose: domainpki.PurposeMTLSServer, ConsumerType: domainpki.ConsumerMeshListener,
			ConsumerID: "mesh-provider/rollover-late", ProfileID: domainpki.ProfileMTLSServer,
			TrustSetID: trustSet.ID,
		})
		if err != nil {
			return err
		}
		staged, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
			IdempotencyKey: "test:rollover-late-assignment-stage", AssignmentID: bound.ID,
			GenerationID: leaf.ID, ExpectedRevision: bound.Revision,
		})
		if err != nil {
			return err
		}
		activated, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
			IdempotencyKey: "test:rollover-late-assignment-activate", AssignmentID: bound.ID,
			ExpectedRevision: staged.Assignment.Revision,
		})
		if err != nil {
			return err
		}
		lateAssignment = activated.Assignment
		return nil
	}
	cancelableRequest := apppki.StartAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-cancelable-start", OperationID: "operation-rollover-cancelable",
		PreviousAuthorityID: previous.Authority.ID, ReplacementAuthorityID: replacement.Authority.ID,
		TrustSetID: trustSet.ID, OverlapTrustGenerationID: overlap.StagedGeneration.ID,
		ConsumerTracking: domainpki.RolloverConsumerTrackingAllTracked,
	}
	if _, err := service.StartAuthorityRollover(t.Context(), cancelableRequest); err == nil {
		t.Fatal("StartAuthorityRollover() accepted a stale all-tracked assignment snapshot")
	}
	cancelable, err := service.StartAuthorityRollover(t.Context(), cancelableRequest)
	if err != nil {
		t.Fatal(err)
	}
	startRequest := apppki.StartAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-start", OperationID: "operation-rollover",
		PreviousAuthorityID: previous.Authority.ID, ReplacementAuthorityID: replacement.Authority.ID,
		TrustSetID: trustSet.ID, OverlapTrustGenerationID: overlap.StagedGeneration.ID,
		ConsumerTracking: domainpki.RolloverConsumerTrackingAllTracked,
	}
	if _, err := service.StartAuthorityRollover(t.Context(), startRequest); !errors.Is(
		err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionResourceReserved, ""),
	) {
		t.Fatalf("reserved StartAuthorityRollover() error = %v", err)
	}
	cancelRequest := apppki.CancelAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-cancel", OperationID: cancelable.Operation.ID,
		ExpectedRevision: cancelable.Operation.Revision,
	}
	canceled, err := service.CancelAuthorityRollover(t.Context(), cancelRequest)
	if err != nil {
		t.Fatal(err)
	}
	if canceled.Operation.Status != domainpki.OperationStatusCanceled || canceled.Operation.CompletedAt.IsZero() {
		t.Fatalf("CancelAuthorityRollover() = %#v", canceled)
	}
	if replayedCancellation, err := service.CancelAuthorityRollover(t.Context(), cancelRequest); err != nil ||
		replayedCancellation.Operation.Revision != canceled.Operation.Revision {
		t.Fatalf("idempotent CancelAuthorityRollover() = %#v, %v", replayedCancellation, err)
	}
	if _, err := service.UnbindAssignment(t.Context(), apppki.UnbindAssignmentRequest{
		IdempotencyKey: "test:rollover-late-assignment-unbind", AssignmentID: lateAssignment.ID,
		ExpectedRevision: lateAssignment.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	started, err := service.StartAuthorityRollover(t.Context(), startRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(started.MissingAssignmentIDs, []domainpki.AssignmentID{assignment.ID}) ||
		started.Operation.AuthorityRollover == nil ||
		!slices.Equal(started.Operation.AuthorityRollover.RequiredAssignmentIDs, []domainpki.AssignmentID{assignment.ID}) {
		t.Fatalf("StartAuthorityRollover() = %#v", started)
	}
	if _, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:rollover-reserved-assignment-bind", ID: "assignment-rollover-reserved",
		Purpose: domainpki.PurposeMTLSServer, ConsumerType: domainpki.ConsumerMeshListener,
		ConsumerID: "mesh-provider/rollover-reserved", ProfileID: domainpki.ProfileMTLSServer,
		TrustSetID: trustSet.ID,
	}); !errors.Is(err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionResourceReserved, "")) {
		t.Fatalf("reserved BindAssignment() error = %v", err)
	}
	if _, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		IdempotencyKey: "test:rollover-reserved-overlap-activate", TrustSetID: trustSet.ID,
		ExpectedRevision: overlap.TrustSet.Revision,
	}); !errors.Is(err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionResourceReserved, "")) {
		t.Fatalf("reserved ActivateTrustSet() error = %v", err)
	}
	activateRequest := apppki.ActivateAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-activate", OperationID: started.Operation.ID,
		ExpectedRevision: started.Operation.Revision, ExpectedTrustSetRevision: overlap.TrustSet.Revision,
	}
	if _, err := service.ActivateAuthorityRollover(t.Context(), activateRequest); err == nil {
		t.Fatal("ActivateAuthorityRollover() accepted missing overlap acknowledgements")
	}
	acknowledgeRequest := apppki.AcknowledgeAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-ack", AcknowledgementID: "ack-rollover-listener",
		OperationID: started.Operation.ID, AssignmentID: assignment.ID, EvidenceRef: "provider-receipt:17",
	}
	acknowledged, err := service.AcknowledgeAuthorityRollover(t.Context(), acknowledgeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(acknowledged.MissingAssignmentIDs) != 0 || len(acknowledged.Acknowledgements) != 1 ||
		acknowledged.Acknowledgements[0].ConsumerID != assignment.ConsumerID {
		t.Fatalf("AcknowledgeAuthorityRollover() = %#v", acknowledged)
	}
	replayed, err := service.AcknowledgeAuthorityRollover(t.Context(), acknowledgeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed.Acknowledgements) != 1 || replayed.Acknowledgements[0].ID != acknowledged.Acknowledgements[0].ID {
		t.Fatalf("acknowledgement replay = %#v", replayed)
	}
	duplicate := acknowledgeRequest
	duplicate.IdempotencyKey = "test:rollover-ack-duplicate"
	duplicate.AcknowledgementID = "ack-rollover-listener-duplicate"
	if _, err := service.AcknowledgeAuthorityRollover(t.Context(), duplicate); !errors.Is(err, apppki.ErrAcknowledgementExists) {
		t.Fatalf("duplicate acknowledgement error = %v, want ErrAcknowledgementExists", err)
	}
	staleActivation := activateRequest
	staleActivation.IdempotencyKey = "test:rollover-activate-stale"
	staleActivation.ExpectedTrustSetRevision--
	if _, err := service.ActivateAuthorityRollover(t.Context(), staleActivation); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale ActivateAuthorityRollover() error = %v, want revision conflict", err)
	}
	activated, err := service.ActivateAuthorityRollover(t.Context(), activateRequest)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Operation.AuthorityRollover == nil ||
		activated.Operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingLeafRotation {
		t.Fatalf("ActivateAuthorityRollover() = %#v", activated)
	}
	if replayedActivation, err := service.ActivateAuthorityRollover(t.Context(), activateRequest); err != nil ||
		replayedActivation.Operation.Revision != activated.Operation.Revision {
		t.Fatalf("idempotent ActivateAuthorityRollover() = %#v, %v", replayedActivation, err)
	}
	if _, err := service.CancelAuthorityRollover(t.Context(), apppki.CancelAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-late-cancel", OperationID: activated.Operation.ID,
		ExpectedRevision: activated.Operation.Revision,
	}); !errors.Is(err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionWrongPhase, "")) {
		t.Fatalf("late CancelAuthorityRollover() error = %v", err)
	}
	activeOverlap, err := service.InspectTrustSet(t.Context(), trustSet.ID)
	if err != nil {
		t.Fatal(err)
	}
	finalTrust, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		IdempotencyKey: "test:rollover-trust-final", TrustSetID: trustSet.ID,
		ExpectedRevision: activeOverlap.TrustSet.Revision, GenerationID: "trustgen-rollover-final",
		AnchorGenerationIDs: []domainpki.GenerationID{replacement.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalTrust.StagedGeneration == nil {
		t.Fatal("StageTrustSet() omitted rollover final generation")
	}
	if _, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		IdempotencyKey: "test:rollover-reserved-final-activate", TrustSetID: trustSet.ID,
		ExpectedRevision: finalTrust.TrustSet.Revision,
	}); !errors.Is(err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionResourceReserved, "")) {
		t.Fatalf("reserved final ActivateTrustSet() error = %v", err)
	}
	_, err = service.BeginAuthorityRolloverFinalTrust(
		t.Context(), apppki.BeginAuthorityRolloverFinalTrustRequest{
			IdempotencyKey: "test:rollover-final-before-leaf", OperationID: activated.Operation.ID,
			ExpectedRevision: activated.Operation.Revision, ExpectedTrustSetRevision: finalTrust.TrustSet.Revision,
			FinalTrustGenerationID: finalTrust.StagedGeneration.ID,
		},
	)
	var precondition *apppki.RolloverPreconditionError
	if !errors.As(err, &precondition) || precondition.Reason != apppki.RolloverPreconditionAssignmentsNotRotated {
		t.Fatalf("unrotated leaf error = %v, want assignments-not-rotated precondition", err)
	}

	unlockTestAuthority(t, service, replacement.Authority.ID)
	replacementLeaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:rollover-replacement-leaf", CertificateID: "certificate-rollover-replacement-leaf",
		GenerationID: "generation-rollover-replacement-leaf", KeyID: "key-rollover-replacement-leaf",
		IssuerAuthorityID: replacement.Authority.ID, Name: "rollover-listener.test",
		ProfileID: domainpki.ProfileMTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	activeAssignment, err := service.InspectAssignment(t.Context(), assignment.ID)
	if err != nil {
		t.Fatal(err)
	}
	stagedReplacement, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "test:rollover-replacement-stage", AssignmentID: assignment.ID,
		GenerationID: replacementLeaf.ID, ExpectedRevision: activeAssignment.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey: "test:rollover-replacement-activate", AssignmentID: assignment.ID,
		ExpectedRevision: stagedReplacement.Assignment.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	beginFinalRequest := apppki.BeginAuthorityRolloverFinalTrustRequest{
		IdempotencyKey: "test:rollover-begin-final", OperationID: activated.Operation.ID,
		ExpectedRevision: activated.Operation.Revision, ExpectedTrustSetRevision: finalTrust.TrustSet.Revision,
		FinalTrustGenerationID: finalTrust.StagedGeneration.ID,
	}
	staleBeginFinal := beginFinalRequest
	staleBeginFinal.IdempotencyKey = "test:rollover-begin-final-stale"
	staleBeginFinal.ExpectedTrustSetRevision--
	if _, err := service.BeginAuthorityRolloverFinalTrust(t.Context(), staleBeginFinal); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale BeginAuthorityRolloverFinalTrust() error = %v, want revision conflict", err)
	}
	awaitingFinal, err := service.BeginAuthorityRolloverFinalTrust(t.Context(), beginFinalRequest)
	if err != nil {
		t.Fatal(err)
	}
	completeRequest := apppki.CompleteAuthorityRolloverRequest{
		IdempotencyKey: "test:rollover-complete", OperationID: awaitingFinal.Operation.ID,
		ExpectedRevision: awaitingFinal.Operation.Revision, ExpectedTrustSetRevision: finalTrust.TrustSet.Revision,
	}
	if _, err := service.CompleteAuthorityRollover(t.Context(), completeRequest); err == nil {
		t.Fatal("CompleteAuthorityRollover() accepted missing final acknowledgements")
	}
	finalAcknowledged, err := service.AcknowledgeAuthorityRollover(
		t.Context(), apppki.AcknowledgeAuthorityRolloverRequest{
			IdempotencyKey: "test:rollover-final-ack", AcknowledgementID: "ack-rollover-listener-final",
			OperationID: awaitingFinal.Operation.ID, AssignmentID: assignment.ID,
			EvidenceRef: "provider-receipt:29",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(finalAcknowledged.Acknowledgements) != 2 || len(finalAcknowledged.MissingAssignmentIDs) != 0 {
		t.Fatalf("final acknowledgement = %#v", finalAcknowledged)
	}
	staleCompletion := completeRequest
	staleCompletion.IdempotencyKey = "test:rollover-complete-stale"
	staleCompletion.ExpectedTrustSetRevision--
	if _, err := service.CompleteAuthorityRollover(t.Context(), staleCompletion); !errors.Is(err, apppki.ErrRevisionConflict) {
		t.Fatalf("stale CompleteAuthorityRollover() error = %v, want revision conflict", err)
	}
	assignmentBeforeDrift, err := service.InspectAssignment(t.Context(), assignment.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey: "test:rollover-drift-stage", AssignmentID: assignment.ID,
		GenerationID: leaf.ID, ExpectedRevision: assignmentBeforeDrift.Assignment.Revision,
	})
	if !errors.Is(err, apppki.NewRolloverPreconditionError(apppki.RolloverPreconditionResourceReserved, "")) {
		t.Fatalf("assignment drift reservation error = %v", err)
	}
	completed, err := service.CompleteAuthorityRollover(t.Context(), completeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Operation.Status != domainpki.OperationStatusCompleted ||
		completed.Operation.AuthorityRollover == nil ||
		completed.Operation.AuthorityRollover.Phase != domainpki.AuthorityRolloverPhaseCompleted {
		t.Fatalf("CompleteAuthorityRollover() = %#v", completed)
	}
	if replayedCompletion, err := service.CompleteAuthorityRollover(t.Context(), completeRequest); err != nil ||
		replayedCompletion.Operation.Revision != completed.Operation.Revision {
		t.Fatalf("idempotent CompleteAuthorityRollover() = %#v, %v", replayedCompletion, err)
	}
	retiredPrevious, err := service.InspectAuthority(t.Context(), previous.Authority.ID)
	if err != nil {
		t.Fatal(err)
	}
	activeFinalTrust, err := service.InspectTrustSet(t.Context(), trustSet.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retiredPrevious.Authority.State != domainpki.AuthorityStateRetired ||
		activeFinalTrust.TrustSet.ActiveGenerationID != finalTrust.StagedGeneration.ID ||
		activeFinalTrust.TrustSet.StagedGenerationID != "" {
		t.Fatalf("completed rollover authority/trust = %#v / %#v", retiredPrevious, activeFinalTrust)
	}
	inspected, err := service.InspectOperation(t.Context(), started.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := service.ListOperations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 2 || operations[0].Status != domainpki.OperationStatusCompleted ||
		operations[1].Status != domainpki.OperationStatusCanceled || len(inspected.Acknowledgements) != 2 {
		t.Fatalf("operation inventory = %#v, inspection = %#v", operations, inspected)
	}
}

func TestServiceRejectsUnimplementedAssignmentContracts(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	if _, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		ID: "assignment-policy", Purpose: domainpki.PurposeTLSServer,
		ConsumerType: domainpki.ConsumerService, ConsumerID: "service/api",
		ProfileID: domainpki.ProfileTLSServer, RotationPolicyID: "rotation-default",
	}); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("BindAssignment() rotation policy error = %v", err)
	}

	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{ID: "trust-crl", Name: "CRL trust"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		TrustSetID: trustSet.ID, ExpectedRevision: trustSet.Revision,
		AnchorGenerationIDs: []domainpki.GenerationID{"generation-placeholder"},
		CRLGenerationIDs:    []domainpki.CRLGenerationID{"crl-placeholder"},
	}); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("StageTrustSet() unknown CRL error = %v, want not found", err)
	}
}

func TestServiceMakesTrustMutationsIdempotent(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	request := apppki.CreateTrustSetRequest{IdempotencyKey: "test:trust-idempotent", Name: "Idempotent trust"}
	first, err := service.CreateTrustSet(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateTrustSet(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotent CreateTrustSet() results differ: %#v %#v", first, second)
	}
	trustSets, err := service.ListTrustSets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(trustSets) != 1 {
		t.Fatalf("idempotent CreateTrustSet() persisted %d trust sets, want 1", len(trustSets))
	}
	request.Name = "Different trust"
	if _, err := service.CreateTrustSet(t.Context(), request); !errors.Is(err, apppki.ErrIdempotencyConflict) {
		t.Fatalf("CreateTrustSet() key reuse error = %v, want idempotency conflict", err)
	}
}

func TestServiceRevalidatesTrustMaterialBeforeActivation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	baseService := newTestService(t, store)
	root, err := baseService.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		ID: "authority-revalidate-root", CertificateID: "certificate-revalidate-root",
		GenerationID: "generation-revalidate-root", KeyID: "key-revalidate-root",
		Name: "Revalidation root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked := false
	service := newTestServiceWithPersistence(t, overridingPersistence{
		Persistence: store,
		generationMutator: func(generation domainpki.CertificateGeneration) domainpki.CertificateGeneration {
			if revoked && generation.ID == root.Generation.ID {
				generation.State = domainpki.CertificateStateRevoked
			}
			return generation
		},
	}, store)
	trustSet, err := service.CreateTrustSet(t.Context(), apppki.CreateTrustSetRequest{ID: "trust-revalidate", Name: "Revalidation trust"})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.StageTrustSet(t.Context(), apppki.StageTrustSetRequest{
		TrustSetID: trustSet.ID, ExpectedRevision: trustSet.Revision,
		GenerationID: "trust-revalidate-generation-1", AnchorGenerationIDs: []domainpki.GenerationID{root.Generation.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked = true
	if _, err := service.ActivateTrustSet(t.Context(), apppki.ActivateTrustSetRequest{
		TrustSetID: trustSet.ID, ExpectedRevision: staged.TrustSet.Revision,
	}); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("ActivateTrustSet() revoked anchor error = %v", err)
	}
}

func TestServiceRejectsMismatchedAssignmentGeneration(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		ID: "authority-mismatch-root", CertificateID: "certificate-mismatch-root",
		GenerationID: "generation-mismatch-root", KeyID: "key-mismatch-root",
		Name: "Mismatch root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		CertificateID: "certificate-mismatch-leaf", GenerationID: "generation-mismatch-leaf",
		KeyID: "key-mismatch-leaf", IssuerAuthorityID: root.Authority.ID,
		Name: "mismatch.test", ProfileID: domainpki.ProfileTLSClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		ID: "assignment-mismatch", Purpose: domainpki.PurposeTLSClient,
		ConsumerType: domainpki.ConsumerExternal, ConsumerID: "external:mismatch",
		ProfileID: domainpki.ProfileTLSClient,
	})
	if err == nil {
		t.Fatal("BindAssignment() accepted a peer-trusting purpose without a trust set")
	}
	assignment, err = service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		ID: "assignment-mismatch-server", Purpose: domainpki.PurposeTLSServer,
		ConsumerType: domainpki.ConsumerExternal, ConsumerID: "external:mismatch-server",
		ProfileID: domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		AssignmentID: assignment.ID, GenerationID: leaf.ID, ExpectedRevision: assignment.Revision,
	}); err == nil {
		t.Fatal("StageAssignment() accepted a generation with a mismatched profile and purpose")
	}
}

func TestServiceMakesCertificateIssuanceIdempotent(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:idempotent-root",
		Name:           "Idempotency root",
		Role:           domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	request := apppki.IssueCertificateRequest{
		IdempotencyKey:    "test:idempotent-leaf",
		IssuerAuthorityID: root.Authority.ID,
		Name:              "idempotent.test",
	}
	first, err := service.IssueCertificate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.IssueCertificate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.FingerprintSHA256 != second.FingerprintSHA256 {
		t.Fatalf("idempotent issuance returned different results: first=%q second=%q", first.ID, second.ID)
	}
	request.Name = "different.test"
	if _, err := service.IssueCertificate(t.Context(), request); !errors.Is(err, apppki.ErrIdempotencyConflict) {
		t.Fatalf("IssueCertificate() idempotency mismatch error = %v", err)
	}
	generations, err := service.ListCertificateGenerations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 2 {
		t.Fatalf("idempotent issuance persisted %d generations, want root and one leaf", len(generations))
	}
}

func TestValidateAuthorityIssuanceCompletionBindsAggregatePlan(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	result, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:authority-aggregate-plan", Name: "aggregate plan root",
		Role: domainpki.AuthorityRoleRoot, Labels: map[string]string{"environment": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := result.Generation
	authority := result.Authority
	intent := apppki.IssuanceIntent{
		ID: "issuance-authority-aggregate-plan", IdempotencyKey: "test:authority-aggregate-plan-validation",
		RequestSHA256: strings.Repeat("a", sha256.Size*2), Kind: apppki.IssuanceKindAuthority,
		AuthorityID: authority.ID, CertificateID: generation.CertificateID, GenerationID: generation.ID,
		Generation: generation.Generation, KeyID: generation.KeyID,
		IssuerAuthorityID: generation.IssuerAuthorityID, IssuerGenerationID: generation.IssuerGenerationID,
		SubjectBackendID: generation.BackendID, SubjectBackendVersion: generation.BackendVersion,
		SubjectPackageDigest: generation.BackendPackageDigest, SubjectCapabilityHash: generation.BackendCapabilityHash,
		SigningBackendID: generation.SigningBackendID, SigningBackendVersion: generation.SigningBackendVersion,
		SigningPackageDigest: generation.SigningBackendPackageDigest, SigningCapabilityHash: generation.SigningBackendCapabilityHash,
		ProfileID: generation.ProfileID, CompatibilityTargetID: generation.CompatibilityTargetID,
		CompatibilityVersion: generation.CompatibilityVersion, Purpose: generation.Purpose,
		ExportPolicy: generation.ExportPolicy, KeyEstablishment: generation.KeyEstablishment,
		TLSNamedGroups: generation.TLSNamedGroups, ChainGenerationIDs: generation.ChainGenerationIDs,
		AuthorityPlan: &apppki.AuthorityIssuancePlan{
			Name: authority.Name, Role: authority.Role, Origin: authority.Origin,
			ParentAuthorityID: authority.ParentAuthorityID, State: authority.State,
			ProfileID: authority.ProfileID, SignerRef: authority.SignerRef,
			ExportPolicy: authority.ExportPolicy, CreatedAt: authority.CreatedAt, Labels: authority.Labels,
		},
		Template: generation.Template, Status: apppki.IssuanceStatusPending,
		OwnerToken: "authority-plan-validator", Revision: 1,
		LeaseExpiresAt: authority.CreatedAt.Add(apppki.DefaultIssuanceLease),
		CreatedAt:      authority.CreatedAt, UpdatedAt: authority.CreatedAt,
	}
	material, err := store.LoadKey(t.Context(), result.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKeyPKCS8)
	if err := apppki.ValidateAuthorityIssuanceCompletion(intent, result.Authority, result.Generation, material); err != nil {
		t.Fatalf("ValidateAuthorityIssuanceCompletion() rejected exact aggregate: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*domainpki.Authority)
	}{
		{name: "role", mutate: func(authority *domainpki.Authority) { authority.Role = domainpki.AuthorityRoleSubordinate }},
		{name: "parent", mutate: func(authority *domainpki.Authority) { authority.ParentAuthorityID = "authority-other" }},
		{name: "profile", mutate: func(authority *domainpki.Authority) { authority.ProfileID = domainpki.ProfileSubordinateModern }},
		{name: "export policy", mutate: func(authority *domainpki.Authority) { authority.ExportPolicy = domainpki.ExportPolicyExplicit }},
		{name: "signer reference", mutate: func(authority *domainpki.Authority) { authority.SignerRef = "key-other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := result.Authority.Clone()
			test.mutate(&candidate)
			if err := apppki.ValidateAuthorityIssuanceCompletion(intent, candidate, result.Generation, material); err == nil {
				t.Fatal("ValidateAuthorityIssuanceCompletion() accepted authority aggregate drift")
			}
		})
	}
}

func TestServiceReconcilesStalePendingIssuance(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "reconcile root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	staleAt := fixedTestTime.Add(-2 * time.Minute)
	intent, created, err := store.BeginIssuance(t.Context(), pendingTestIssuance(root, "stale", staleAt, staleAt.Add(time.Minute)))
	if err != nil || !created {
		t.Fatalf("BeginIssuance() created=%t err=%v", created, err)
	}
	reconciled, err := service.ReconcilePendingIssuance(t.Context(), intent.IdempotencyKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != apppki.IssuanceStatusFailed || !strings.Contains(reconciled.Failure, "reconciliation") {
		t.Fatalf("reconciled intent = %#v", reconciled)
	}
	for _, suffix := range []string{"sweep-a", "sweep-b"} {
		if _, created, err := store.BeginIssuance(t.Context(), pendingTestIssuance(root, suffix, staleAt, staleAt.Add(time.Minute))); err != nil || !created {
			t.Fatalf("BeginIssuance(%s) created=%t err=%v", suffix, created, err)
		}
	}
	if _, created, err := store.BeginIssuance(t.Context(), pendingTestIssuance(root, "live", fixedTestTime, fixedTestTime.Add(apppki.DefaultIssuanceLease))); err != nil || !created {
		t.Fatalf("BeginIssuance(live) created=%t err=%v", created, err)
	}
	reconciledBatch, err := service.ReconcilePendingIssuances(t.Context(), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciledBatch) != 2 {
		t.Fatalf("reconciled batch length = %d, want 2", len(reconciledBatch))
	}
}

func pendingTestIssuance(root apppki.CreateAuthorityResult, suffix string, createdAt, leaseExpiresAt time.Time) apppki.IssuanceIntent {
	return apppki.IssuanceIntent{
		ID: domainpki.IssuanceID("issuance-" + suffix), IdempotencyKey: "test:issuance-" + suffix,
		RequestSHA256: strings.Repeat("a", sha256.Size*2), Kind: apppki.IssuanceKindCertificate,
		CertificateID: domainpki.CertificateID("cert-" + suffix), GenerationID: domainpki.GenerationID("certgen-" + suffix),
		KeyID: domainpki.KeyID("key-" + suffix), IssuerAuthorityID: root.Authority.ID, IssuerGenerationID: root.Generation.ID,
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
		OwnerToken: "worker-" + suffix, Revision: 1, LeaseExpiresAt: leaseExpiresAt, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func TestServiceConstructionPropagatesRegistryCancellation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	clock := fixedClock{now: fixedTestTime}
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	backend := infrapki.NewBackend()
	validators, err := apppki.NewStaticValidatorRegistry(map[domainpki.BackendID]apppki.Validator{
		backend.Descriptor().ID: infrapki.NewValidator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := &cancellationAwareBackendRegistry{called: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		<-registry.called
		cancel()
	}()
	_, err = apppki.NewServiceWithCryptoRegistries(
		ctx,
		store,
		registry,
		validators,
		leases,
		store,
		store,
		fixedAuditContext{},
		clock,
		bytes.NewReader(deterministicRandomBytes(42)),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NewServiceWithCryptoRegistries() error = %v, want context cancellation", err)
	}
}

func TestServiceSelectsRequestedCryptoBackend(t *testing.T) {
	t.Parallel()

	builtin := infrapki.NewBackend()
	builtinDescriptor := builtin.Descriptor()
	customDescriptor, err := domainpki.NewBackendDescriptor(domainpki.BackendDescriptorArgs{
		SchemaVersion: builtinDescriptor.SchemaVersion, ID: "provider-test", Version: builtinDescriptor.Version,
		PackageDigest: builtinDescriptor.PackageDigest, KeyAlgorithms: builtinDescriptor.KeyAlgorithms,
		SignatureAlgorithms: builtinDescriptor.SignatureAlgorithms, SupportsCSR: builtinDescriptor.SupportsCSR,
		SupportsImport: builtinDescriptor.SupportsImport, SupportsExport: builtinDescriptor.SupportsExport,
		SupportsCRL: builtinDescriptor.SupportsCRL, SupportsCustom: builtinDescriptor.SupportsCustom,
	})
	if err != nil {
		t.Fatal(err)
	}
	custom := namedBackend{delegate: builtin, descriptor: customDescriptor}
	backends, err := apppki.NewStaticBackendRegistry(builtin, custom)
	if err != nil {
		t.Fatal(err)
	}
	validator := infrapki.NewValidator()
	validators, err := apppki.NewStaticValidatorRegistry(map[domainpki.BackendID]apppki.Validator{
		builtinDescriptor.ID: validator,
		customDescriptor.ID:  validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := pkimemory.NewStore()
	clock := fixedClock{now: fixedTestTime}
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewServiceWithCryptoRegistries(t.Context(), store, backends, validators, leases, store, store, fixedAuditContext{}, clock, bytes.NewReader(deterministicRandomBytes(42)))
	if err != nil {
		t.Fatal(err)
	}
	builtinRoot, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:provider-builtin-root", Name: "provider builtin root", Role: domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, builtinRoot.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey: "test:provider-leaf", IssuerAuthorityID: builtinRoot.Authority.ID,
		Name: "provider.listener.test", BackendID: customDescriptor.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.BackendID != customDescriptor.ID || leaf.SigningBackendID != builtinDescriptor.ID {
		t.Fatalf("leaf backend provenance = subject %q signing %q", leaf.BackendID, leaf.SigningBackendID)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:provider-root", Name: "provider root", Role: domainpki.AuthorityRoleRoot, BackendID: customDescriptor.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if root.Generation.BackendID != customDescriptor.ID || root.Generation.SigningBackendID != customDescriptor.ID {
		t.Fatalf("generation backend provenance = subject %q signing %q, want %q", root.Generation.BackendID, root.Generation.SigningBackendID, customDescriptor.ID)
	}
}

func TestServiceRequiresSigningAuthorization(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "listener.test"})
	if !errors.Is(err, apppki.ErrAuthoritySigningLocked) {
		t.Fatalf("IssueCertificate() error = %v, want ErrAuthoritySigningLocked", err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	if _, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "listener.test"}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceUsesBoundedRevocableSigningLeases(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	clock := &mutableClock{now: fixedTestTime}
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	randomBytes := make([]byte, 8192)
	for index := range randomBytes {
		randomBytes[index] = byte((index+41)%251 + 1)
	}
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), leases, store, store, fixedAuditContext{}, clock, bytes.NewReader(randomBytes))
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "lease root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	if root.Authority.State != domainpki.AuthorityStateLocked {
		t.Fatalf("root authority state = %q, want locked", root.Authority.State)
	}
	issue := func(name string) error {
		_, issueErr := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: name})
		return issueErr
	}
	if err := issue("locked.test"); !errors.Is(err, apppki.ErrAuthoritySigningLocked) {
		t.Fatalf("locked issue error = %v, want ErrAuthoritySigningLocked", err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, apppki.MaximumSigningLeaseDuration+time.Second); err == nil {
		t.Fatal("UnlockAuthoritySigning() accepted an overlong lease")
	}
	lease, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.Sub(lease.GrantedAt) != time.Minute {
		t.Fatalf("signing lease duration = %s, want 1m", lease.ExpiresAt.Sub(lease.GrantedAt))
	}
	renewedLease, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if renewedLease.ExpiresAt.Sub(renewedLease.GrantedAt) != 2*time.Minute {
		t.Fatalf("renewed signing lease duration = %s, want 2m", renewedLease.ExpiresAt.Sub(renewedLease.GrantedAt))
	}
	otherScope := apppki.AuditContext{ActorID: "other-operator", OperationID: "test-operation", CorrelationID: "other-correlation"}
	if _, err := leases.UnlockSigning(t.Context(), root.Authority.ID, time.Minute, otherScope); !errors.Is(err, apppki.ErrAuthoritySigningLeaseOwned) {
		t.Fatalf("other actor UnlockSigning() error = %v, want ErrAuthoritySigningLeaseOwned", err)
	}
	if _, active, err := leases.SigningLease(t.Context(), root.Authority.ID, otherScope); err != nil || active {
		t.Fatalf("other actor SigningLease() active=%t err=%v", active, err)
	}
	if err := leases.LockSigning(t.Context(), root.Authority.ID, otherScope); err == nil {
		t.Fatal("LockSigning() let another actor revoke a lease")
	}
	if err := issue("unlocked.test"); err != nil {
		t.Fatal(err)
	}
	clock.Add(3 * time.Minute)
	if _, err := leases.UnlockSigning(t.Context(), root.Authority.ID, time.Minute, otherScope); err != nil {
		t.Fatalf("other actor could not replace expired signing lease: %v", err)
	}
	if _, active, err := service.AuthoritySigningLease(t.Context(), root.Authority.ID); err != nil || active {
		t.Fatalf("expired AuthoritySigningLease() active=%t err=%v", active, err)
	}
	if err := issue("expired.test"); !errors.Is(err, apppki.ErrAuthoritySigningLocked) {
		t.Fatalf("expired issue error = %v, want ErrAuthoritySigningLocked", err)
	}
	if err := leases.LockSigning(t.Context(), root.Authority.ID, otherScope); err != nil {
		t.Fatalf("other actor could not release its replacement lease: %v", err)
	}
	if _, err := service.UnlockAuthoritySigning(t.Context(), root.Authority.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := service.LockAuthoritySigning(t.Context(), root.Authority.ID); err != nil {
		t.Fatal(err)
	}
	if err := issue("relocked.test"); !errors.Is(err, apppki.ErrAuthoritySigningLocked) {
		t.Fatalf("relocked issue error = %v, want ErrAuthoritySigningLocked", err)
	}
}

func TestServiceRejectsValidityBeyondIssuer(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	serial, err := domainpki.NewSerialNumber([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	template := domainpki.CertificateTemplate{
		SerialNumber:           serial,
		Subject:                domainpki.DistinguishedName{CommonName: "too-long.test"},
		NotBefore:              fixedTestTime,
		NotAfter:               root.Generation.Template.NotAfter.Add(time.Second),
		Key:                    domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256},
		SignatureAlgorithm:     domainpki.SignatureAlgorithmECDSASHA256,
		KeyUsage:               domainpki.KeyUsageDigitalSignature,
		ExtendedKeyUsages:      []domainpki.ExtendedKeyUsage{domainpki.ExtendedKeyUsageServerAuth},
		SubjectKeyIdentifier:   domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier: domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
	_, err = service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "too-long.test", Template: &template})
	if err == nil || !strings.Contains(err.Error(), "contained by issuer validity") && !strings.Contains(err.Error(), "profile issuance window") {
		t.Fatalf("IssueCertificate() error = %v", err)
	}
}

func TestServiceRejectsInactiveOrInvalidSignerGeneration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(domainpki.CertificateGeneration) domainpki.CertificateGeneration
	}{
		{name: "revoked", mutate: func(generation domainpki.CertificateGeneration) domainpki.CertificateGeneration {
			generation.State = domainpki.CertificateStateRevoked
			return generation
		}},
		{name: "not yet valid", mutate: func(generation domainpki.CertificateGeneration) domainpki.CertificateGeneration {
			generation.Template.NotBefore = fixedTestTime.Add(time.Minute)
			generation.Template.NotAfter = generation.Template.NotAfter.Add(time.Minute)
			return generation
		}},
		{name: "expired", mutate: func(generation domainpki.CertificateGeneration) domainpki.CertificateGeneration {
			generation.Template.NotBefore = fixedTestTime.Add(-2 * time.Hour)
			generation.Template.NotAfter = fixedTestTime
			return generation
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := pkimemory.NewStore()
			base := newTestService(t, store)
			root, err := base.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
			if err != nil {
				t.Fatal(err)
			}
			service := newTestServiceWithPersistence(t, overridingPersistence{Persistence: store, generationMutator: test.mutate}, store)
			unlockTestAuthority(t, service, root.Authority.ID)
			if _, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "listener.test"}); err == nil {
				t.Fatal("IssueCertificate() accepted an unusable signer generation")
			}
		})
	}
}

func TestServiceRejectsPrivateKeyThatDoesNotMatchGeneration(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	base := newTestService(t, store)
	root, err := base.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, base, root.Authority.ID)
	leaf, err := base.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "listener.test"})
	if err != nil {
		t.Fatal(err)
	}
	store.AllowPrivateExport(leaf.ID)
	wrongKey, err := infrapki.NewBackend().GenerateKey(t.Context(), "wrong-key", leaf.Template.Key)
	if err != nil {
		t.Fatal(err)
	}
	persistence := overridingPersistence{Persistence: store, loadKeyOverride: &wrongKey}
	service := newTestServiceWithPersistence(t, persistence, store)
	if _, err := service.ExportBundle(t.Context(), leaf.ID, leaf.Purpose, true); err == nil || !strings.Contains(err.Error(), "does not match certificate generation") {
		t.Fatalf("ExportBundle() error = %v, want key mismatch", err)
	}
}

func TestServiceAllowsSubjectAndIssuerKeyAlgorithmsToDiffer(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	serial, err := domainpki.NewSerialNumber([]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	template := domainpki.CertificateTemplate{
		SerialNumber:            serial,
		Subject:                 domainpki.DistinguishedName{CommonName: "ed25519.listener.test"},
		NotBefore:               fixedTestTime,
		NotAfter:                fixedTestTime.Add(time.Hour),
		Key:                     domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmEd25519},
		SignatureAlgorithm:      domainpki.SignatureAlgorithmECDSASHA256,
		SubjectAlternativeNames: domainpki.SubjectAlternativeNames{DNSNames: []string{"ed25519.listener.test"}},
		KeyUsage:                domainpki.KeyUsageDigitalSignature,
		ExtendedKeyUsages:       []domainpki.ExtendedKeyUsage{domainpki.ExtendedKeyUsageServerAuth},
		SubjectKeyIdentifier:    domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier:  domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
	generation, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IssuerAuthorityID: root.Authority.ID,
		Name:              "ed25519.listener.test",
		Template:          &template,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(generation.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("public key type = %T, want ed25519.PublicKey", certificate.PublicKey)
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("signature algorithm = %s, want %s", certificate.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}
}

func TestServiceResolvesDefaultLeafSignatureFromRSAIssuer(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	serial, err := domainpki.NewSerialNumber([]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := domainpki.CertificateTemplate{
		SerialNumber:           serial,
		Subject:                domainpki.DistinguishedName{CommonName: "rsa root"},
		NotBefore:              fixedTestTime.Add(-domainpki.DefaultBackdate),
		NotAfter:               fixedTestTime.Add(365 * 24 * time.Hour),
		Key:                    domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmRSA, RSABits: 2048},
		SignatureAlgorithm:     domainpki.SignatureAlgorithmSHA256WithRSA,
		BasicConstraints:       domainpki.BasicConstraints{Critical: true, IsCA: true},
		KeyUsage:               domainpki.KeyUsageCertificateSign | domainpki.KeyUsageCRLSign | domainpki.KeyUsageDigitalSignature,
		SubjectKeyIdentifier:   domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier: domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "rsa root", Role: domainpki.AuthorityRoleRoot, Template: &rootTemplate})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	leaf, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{IssuerAuthorityID: root.Authority.ID, Name: "rsa-issued.listener.test"})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.SignatureAlgorithm != x509.SHA256WithRSA || leaf.Template.SignatureAlgorithm != domainpki.SignatureAlgorithmSHA256WithRSA {
		t.Fatalf("resolved signature = certificate %s, template %s", certificate.SignatureAlgorithm, leaf.Template.SignatureAlgorithm)
	}
}

func TestServiceRejectsExplicitTemplateThatWeakensProfile(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	serial, err := domainpki.NewSerialNumber([]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	template := domainpki.CertificateTemplate{
		SerialNumber:           serial,
		Subject:                domainpki.DistinguishedName{CommonName: "client-only.test"},
		NotBefore:              fixedTestTime,
		NotAfter:               fixedTestTime.Add(time.Hour),
		Key:                    domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256},
		SignatureAlgorithm:     domainpki.SignatureAlgorithmAuto,
		KeyUsage:               domainpki.KeyUsageDigitalSignature,
		ExtendedKeyUsages:      []domainpki.ExtendedKeyUsage{domainpki.ExtendedKeyUsageClientAuth},
		SubjectKeyIdentifier:   domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier: domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
	_, err = service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IssuerAuthorityID: root.Authority.ID,
		Name:              "client-only.test",
		ProfileID:         domainpki.ProfileTLSServer,
		Template:          &template,
	})
	if err == nil || !strings.Contains(err.Error(), "extended key usage") {
		t.Fatalf("weakened explicit template error = %v", err)
	}
}

func TestServiceEnforcesAuthorityConstraints(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	if _, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name:         "exportable root",
		Role:         domainpki.AuthorityRoleRoot,
		ExportPolicy: domainpki.ExportPolicyExplicit,
	}); err == nil || !strings.Contains(err.Error(), "weakens") {
		t.Fatalf("weakened root export policy error = %v", err)
	}
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, root.Authority.ID)
	subordinate, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name:              "subordinate",
		Role:              domainpki.AuthorityRoleSubordinate,
		ParentAuthorityID: root.Authority.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, subordinate.Authority.ID)
	_, err = service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		Name:              "forbidden nested subordinate",
		Role:              domainpki.AuthorityRoleSubordinate,
		ParentAuthorityID: subordinate.Authority.ID,
	})
	if err == nil || !strings.Contains(err.Error(), "path length") {
		t.Fatalf("nested subordinate error = %v", err)
	}
}

func TestServicePersistsOnlyValidatorDerivedCertificateMetadata(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	backend := misleadingBackend{Backend: infrapki.NewBackend()}
	service := newTestServiceWithBackend(t, store, backend)
	root, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{Name: "root", Role: domainpki.AuthorityRoleRoot})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(root.Generation.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(root.Generation.CertificateDER)
	if root.Generation.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) ||
		!bytes.Equal(root.Generation.PublicKeySPKI, certificate.RawSubjectPublicKeyInfo) ||
		!bytes.Equal(root.Generation.SubjectKeyID, certificate.SubjectKeyId) ||
		!bytes.Equal(root.Generation.AuthorityKeyID, certificate.AuthorityKeyId) {
		t.Fatalf("generation retained untrusted backend metadata: %#v", root.Generation)
	}
	storedKey, err := store.LoadKey(t.Context(), root.Generation.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := (infrapki.NewValidator()).ValidateKey(t.Context(), apppki.KeyValidationRequest{Spec: root.Generation.Template.Key, Material: storedKey}); err != nil {
		t.Fatalf("backend mutation corrupted stored key: %v", err)
	}
}

var fixedTestTime = time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)

func newTestService(t *testing.T, store *pkimemory.Store) apppki.Service {
	t.Helper()
	return newTestServiceWithBackend(t, store, infrapki.NewBackend())
}

func newTestServiceWithBackend(t *testing.T, store *pkimemory.Store, backend apppki.Backend) apppki.Service {
	t.Helper()
	clock := fixedClock{now: fixedTestTime}
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(t.Context(), store, backend, infrapki.NewValidator(), leases, store, store, fixedAuditContext{}, clock, bytes.NewReader(deterministicRandomBytes(0)))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newTestServiceWithRandom(t *testing.T, store *pkimemory.Store, random *switchableReader) apppki.Service {
	t.Helper()
	clock := fixedClock{now: fixedTestTime}
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(t.Context(), store, infrapki.NewBackend(), infrapki.NewValidator(), leases, store, store, fixedAuditContext{}, clock, random)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newTestServiceWithPersistence(t *testing.T, persistence apppki.Persistence, authorization *pkimemory.Store) apppki.Service {
	t.Helper()
	return newTestServiceWithPersistenceAndBackend(
		t, persistence, authorization, infrapki.NewBackend(), fixedClock{now: fixedTestTime},
	)
}

func newTestServiceWithPersistenceAndBackend(
	t *testing.T,
	persistence apppki.Persistence,
	authorization *pkimemory.Store,
	backend apppki.Backend,
	clock apppki.Clock,
) apppki.Service {
	t.Helper()
	return newTestServiceWithCryptoPersistence(
		t, persistence, authorization, backend, infrapki.NewValidator(), clock,
	)
}

func newTestServiceWithCrypto(
	t *testing.T,
	store *pkimemory.Store,
	backend apppki.Backend,
	validator apppki.Validator,
	clock apppki.Clock,
) apppki.Service {
	t.Helper()
	return newTestServiceWithCryptoPersistence(t, store, store, backend, validator, clock)
}

func newTestServiceWithCryptoPersistence(
	t *testing.T,
	persistence apppki.Persistence,
	authorization *pkimemory.Store,
	backend apppki.Backend,
	validator apppki.Validator,
	clock apppki.Clock,
) apppki.Service {
	t.Helper()
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(
		t.Context(), persistence, backend, validator, leases, authorization, authorization,
		fixedAuditContext{}, clock, bytes.NewReader(deterministicRandomBytes(97)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func deterministicRandomBytes(offset int) []byte {
	const (
		randomInputBytes = 8192
		randomCycleBytes = 251
	)
	randomBytes := make([]byte, randomInputBytes)
	for index := range randomBytes {
		randomBytes[index] = byte((index+offset)%randomCycleBytes + 1)
	}
	return randomBytes
}

func unlockTestAuthority(t *testing.T, service apppki.Service, id domainpki.AuthorityID) {
	t.Helper()
	if _, err := service.UnlockAuthoritySigning(t.Context(), id, apppki.DefaultSigningLeaseDuration); err != nil {
		t.Fatal(err)
	}
}
