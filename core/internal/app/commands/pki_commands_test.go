package commands

import (
	"context"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/daemon"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type fakePKIClientFactory struct{ control *fakePKIControlClient }

func (f fakePKIClientFactory) DialRunClient(string) (RunClient, error) {
	return fakePKIRunClient{fakeRunClient: fakeRunClient{}, control: f.control}, nil
}

type fakePKIRunClient struct {
	fakeRunClient
	control *fakePKIControlClient
}

func (c fakePKIRunClient) PKIStatus(ctx context.Context) (apppki.WorkspaceStatus, error) {
	return c.control.PKIStatus(ctx)
}

func (c fakePKIRunClient) InitializePKI(ctx context.Context, scope PKIRequestScope, confirmed bool) (apppki.WorkspaceStatus, error) {
	return c.control.InitializePKI(ctx, scope, confirmed)
}

func (c fakePKIRunClient) ListPKIBackends(ctx context.Context) ([]domainpki.BackendDescriptor, error) {
	return c.control.ListPKIBackends(ctx)
}

func (c fakePKIRunClient) ListPKIProfiles(ctx context.Context) ([]domainpki.Profile, error) {
	return c.control.ListPKIProfiles(ctx)
}

func (c fakePKIRunClient) ListPKIAuthorities(ctx context.Context) ([]domainpki.Authority, error) {
	return c.control.ListPKIAuthorities(ctx)
}

func (c fakePKIRunClient) InspectPKIAuthority(ctx context.Context, id domainpki.AuthorityID) (apppki.AuthorityInspection, error) {
	return c.control.InspectPKIAuthority(ctx, id)
}

func (c fakePKIRunClient) CreatePKIAuthority(ctx context.Context, scope PKIRequestScope, request apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error) {
	return c.control.CreatePKIAuthority(ctx, scope, request)
}

func (c fakePKIRunClient) UnlockPKIAuthority(ctx context.Context, scope PKIRequestScope, id domainpki.AuthorityID, duration time.Duration) (apppki.SigningLease, error) {
	return c.control.UnlockPKIAuthority(ctx, scope, id, duration)
}

func (c fakePKIRunClient) LockPKIAuthority(ctx context.Context, scope PKIRequestScope, id domainpki.AuthorityID) error {
	return c.control.LockPKIAuthority(ctx, scope, id)
}

func (c fakePKIRunClient) ListPKICertificates(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	return c.control.ListPKICertificates(ctx)
}

func (c fakePKIRunClient) InspectPKICertificate(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	return c.control.InspectPKICertificate(ctx, id)
}

func (c fakePKIRunClient) IssuePKICertificate(ctx context.Context, scope PKIRequestScope, request apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	return c.control.IssuePKICertificate(ctx, scope, request)
}

func (c fakePKIRunClient) RenewPKICertificate(ctx context.Context, scope PKIRequestScope, request apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	return c.control.RenewPKICertificate(ctx, scope, request)
}

func (c fakePKIRunClient) RotatePKICertificate(ctx context.Context, scope PKIRequestScope, request apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	return c.control.RotatePKICertificate(ctx, scope, request)
}

func (c fakePKIRunClient) RevokePKICertificate(ctx context.Context, scope PKIRequestScope, request apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error) {
	return c.control.RevokePKICertificate(ctx, scope, request)
}

func (c fakePKIRunClient) InspectPKIRevocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	return c.control.InspectPKIRevocation(ctx, id)
}

func (c fakePKIRunClient) InspectPKIGenerationRevocation(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	return c.control.InspectPKIGenerationRevocation(ctx, id)
}

func (c fakePKIRunClient) ListPKIRevocations(ctx context.Context, authorityID domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	return c.control.ListPKIRevocations(ctx, authorityID)
}

func (c fakePKIRunClient) PublishPKICRL(ctx context.Context, scope PKIRequestScope, request apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error) {
	return c.control.PublishPKICRL(ctx, scope, request)
}

func (c fakePKIRunClient) InspectPKICRL(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	return c.control.InspectPKICRL(ctx, id)
}

func (c fakePKIRunClient) ListPKICRLs(ctx context.Context, authorityID domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	return c.control.ListPKICRLs(ctx, authorityID)
}

func (c fakePKIRunClient) ListPKIAssignments(ctx context.Context) ([]domainpki.Assignment, error) {
	return c.control.ListPKIAssignments(ctx)
}

func (c fakePKIRunClient) InspectPKIAssignment(ctx context.Context, id domainpki.AssignmentID) (apppki.AssignmentInspection, error) {
	return c.control.InspectPKIAssignment(ctx, id)
}

func (c fakePKIRunClient) BindPKIAssignment(ctx context.Context, scope PKIRequestScope, request apppki.BindAssignmentRequest) (domainpki.Assignment, error) {
	return c.control.BindPKIAssignment(ctx, scope, request)
}

func (c fakePKIRunClient) StagePKIAssignment(ctx context.Context, scope PKIRequestScope, request apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error) {
	return c.control.StagePKIAssignment(ctx, scope, request)
}

func (c fakePKIRunClient) ActivatePKIAssignment(ctx context.Context, scope PKIRequestScope, request apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error) {
	return c.control.ActivatePKIAssignment(ctx, scope, request)
}

func (c fakePKIRunClient) UnbindPKIAssignment(ctx context.Context, scope PKIRequestScope, request apppki.UnbindAssignmentRequest) (domainpki.Assignment, error) {
	return c.control.UnbindPKIAssignment(ctx, scope, request)
}

func (c fakePKIRunClient) ListPKITrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	return c.control.ListPKITrustSets(ctx)
}

func (c fakePKIRunClient) InspectPKITrustSet(ctx context.Context, id domainpki.TrustSetID) (apppki.TrustSetInspection, error) {
	return c.control.InspectPKITrustSet(ctx, id)
}

func (c fakePKIRunClient) CreatePKITrustSet(ctx context.Context, scope PKIRequestScope, request apppki.CreateTrustSetRequest) (domainpki.TrustSet, error) {
	return c.control.CreatePKITrustSet(ctx, scope, request)
}

func (c fakePKIRunClient) StagePKITrustSet(ctx context.Context, scope PKIRequestScope, request apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error) {
	return c.control.StagePKITrustSet(ctx, scope, request)
}

func (c fakePKIRunClient) ActivatePKITrustSet(ctx context.Context, scope PKIRequestScope, request apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error) {
	return c.control.ActivatePKITrustSet(ctx, scope, request)
}

type fakePKIControlClient struct {
	initialized     bool
	scope           PKIRequestScope
	confirmed       bool
	unlocks         int
	boundAssignment apppki.BindAssignmentRequest
	stagedTrust     apppki.StageTrustSetRequest
	renewRequest    apppki.RenewCertificateRequest
	rotateRequest   apppki.RotateCertificateRequest
	revokeRequest   apppki.RevokeCertificateRequest
	crlRequest      apppki.PublishCRLRequest
}

func (c *fakePKIControlClient) PKIStatus(context.Context) (apppki.WorkspaceStatus, error) {
	return apppki.WorkspaceStatus{Initialized: c.initialized}, nil
}

func (c *fakePKIControlClient) InitializePKI(_ context.Context, scope PKIRequestScope, confirmed bool) (apppki.WorkspaceStatus, error) {
	c.scope, c.confirmed, c.initialized = scope, confirmed, true
	return apppki.WorkspaceStatus{Initialized: true, ActiveKeyVersion: "master-key-v1", MasterKeyVersions: 1}, nil
}

func (*fakePKIControlClient) ListPKIBackends(context.Context) ([]domainpki.BackendDescriptor, error) {
	return nil, nil
}

func (*fakePKIControlClient) ListPKIProfiles(context.Context) ([]domainpki.Profile, error) {
	return domainpki.BuiltInProfiles(), nil
}

func (*fakePKIControlClient) ListPKIAuthorities(context.Context) ([]domainpki.Authority, error) {
	return nil, nil
}

func (*fakePKIControlClient) InspectPKIAuthority(context.Context, domainpki.AuthorityID) (apppki.AuthorityInspection, error) {
	return apppki.AuthorityInspection{}, nil
}

func (*fakePKIControlClient) CreatePKIAuthority(context.Context, PKIRequestScope, apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error) {
	return apppki.CreateAuthorityResult{}, nil
}

func (c *fakePKIControlClient) UnlockPKIAuthority(_ context.Context, scope PKIRequestScope, id domainpki.AuthorityID, duration time.Duration) (apppki.SigningLease, error) {
	c.scope = scope
	c.unlocks++
	return apppki.SigningLease{AuthorityID: id, GrantedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(duration), ActorID: scope.ActorID, OperationID: scope.OperationID}, nil
}

func (*fakePKIControlClient) LockPKIAuthority(context.Context, PKIRequestScope, domainpki.AuthorityID) error {
	return nil
}

func (*fakePKIControlClient) ListPKICertificates(context.Context) ([]domainpki.CertificateGeneration, error) {
	return nil, nil
}

func (*fakePKIControlClient) InspectPKICertificate(context.Context, domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	return domainpki.CertificateGeneration{}, nil
}

func (*fakePKIControlClient) IssuePKICertificate(context.Context, PKIRequestScope, apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	return domainpki.CertificateGeneration{}, nil
}

func (c *fakePKIControlClient) RenewPKICertificate(_ context.Context, scope PKIRequestScope, request apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	c.scope = scope
	c.renewRequest = request
	return apppki.CertificateLifecycleResult{Generation: domainpki.CertificateGeneration{ID: request.GenerationID, KeyID: "key-existing"}}, nil
}

func (c *fakePKIControlClient) RotatePKICertificate(_ context.Context, scope PKIRequestScope, request apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	c.scope = scope
	c.rotateRequest = request
	return apppki.CertificateLifecycleResult{Generation: domainpki.CertificateGeneration{ID: request.GenerationID, KeyID: request.KeyID}}, nil
}

func (c *fakePKIControlClient) RevokePKICertificate(_ context.Context, scope PKIRequestScope, request apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error) {
	c.scope = scope
	c.revokeRequest = request
	return apppki.CertificateRevocationResult{
		Revocation: domainpki.Revocation{GenerationID: request.GenerationID, Reason: request.Reason},
		Generation: domainpki.CertificateGeneration{ID: request.GenerationID},
	}, nil
}

func (*fakePKIControlClient) InspectPKIRevocation(_ context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	return domainpki.Revocation{ID: id}, nil
}

func (*fakePKIControlClient) InspectPKIGenerationRevocation(_ context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	return domainpki.Revocation{GenerationID: id}, nil
}

func (*fakePKIControlClient) ListPKIRevocations(_ context.Context, authorityID domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	return []domainpki.Revocation{{IssuerAuthorityID: authorityID}}, nil
}

func (c *fakePKIControlClient) PublishPKICRL(_ context.Context, scope PKIRequestScope, request apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error) {
	c.scope = scope
	c.crlRequest = request
	return apppki.CRLPublicationResult{Generation: domainpki.CRLGeneration{
		ID: "crl-command", AuthorityID: request.AuthorityID, Number: 1,
	}}, nil
}

func (*fakePKIControlClient) InspectPKICRL(_ context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	return domainpki.CRLGeneration{ID: id}, nil
}

func (*fakePKIControlClient) ListPKICRLs(_ context.Context, authorityID domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	return []domainpki.CRLGeneration{{ID: "crl-command", AuthorityID: authorityID}}, nil
}

func (*fakePKIControlClient) ListPKIAssignments(context.Context) ([]domainpki.Assignment, error) {
	return nil, nil
}

func (*fakePKIControlClient) InspectPKIAssignment(context.Context, domainpki.AssignmentID) (apppki.AssignmentInspection, error) {
	return apppki.AssignmentInspection{}, nil
}

func (c *fakePKIControlClient) BindPKIAssignment(_ context.Context, scope PKIRequestScope, request apppki.BindAssignmentRequest) (domainpki.Assignment, error) {
	c.scope = scope
	c.boundAssignment = request
	return domainpki.Assignment{ID: request.ID, ConsumerID: request.ConsumerID}, nil
}

func (*fakePKIControlClient) StagePKIAssignment(_ context.Context, _ PKIRequestScope, request apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error) {
	return apppki.AssignmentInspection{Assignment: domainpki.Assignment{ID: request.AssignmentID}}, nil
}

func (*fakePKIControlClient) ActivatePKIAssignment(_ context.Context, _ PKIRequestScope, request apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error) {
	return apppki.AssignmentInspection{Assignment: domainpki.Assignment{ID: request.AssignmentID}}, nil
}

func (*fakePKIControlClient) UnbindPKIAssignment(_ context.Context, _ PKIRequestScope, request apppki.UnbindAssignmentRequest) (domainpki.Assignment, error) {
	return domainpki.Assignment{ID: request.AssignmentID}, nil
}

func (*fakePKIControlClient) ListPKITrustSets(context.Context) ([]domainpki.TrustSet, error) {
	return nil, nil
}

func (*fakePKIControlClient) InspectPKITrustSet(context.Context, domainpki.TrustSetID) (apppki.TrustSetInspection, error) {
	return apppki.TrustSetInspection{}, nil
}

func (*fakePKIControlClient) CreatePKITrustSet(_ context.Context, _ PKIRequestScope, request apppki.CreateTrustSetRequest) (domainpki.TrustSet, error) {
	return domainpki.TrustSet{ID: request.ID, Name: request.Name}, nil
}

func (c *fakePKIControlClient) StagePKITrustSet(_ context.Context, scope PKIRequestScope, request apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error) {
	c.scope = scope
	c.stagedTrust = request
	return apppki.TrustSetInspection{TrustSet: domainpki.TrustSet{ID: request.TrustSetID}}, nil
}

func (*fakePKIControlClient) ActivatePKITrustSet(_ context.Context, _ PKIRequestScope, request apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error) {
	return apppki.TrustSetInspection{TrustSet: domainpki.TrustSet{ID: request.TrustSetID}}, nil
}

func TestPKIInitCommandRequiresAndRecordsConfirmation(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	definition, ok := registry.Find("pki", "init")
	if !ok {
		t.Fatal("pki init command is missing")
	}
	if _, err := definition.Execute(t.Context(), Invocation{Options: map[string]string{"workspace": ".hovel"}, NonInteractive: true}); err == nil {
		t.Fatal("pki init accepted a non-interactive request without --yes")
	}
	result, err := definition.Execute(t.Context(), Invocation{Options: map[string]string{"workspace": ".hovel"}, Flags: map[string]bool{"yes": true}, NonInteractive: true})
	if err != nil {
		t.Fatal(err)
	}
	if !control.confirmed || control.scope.ActorID != defaultPKIActorID || control.scope.CorrelationID == "" {
		t.Fatalf("initialize call confirmed=%t scope=%#v", control.confirmed, control.scope)
	}
	status, ok := result.JSON.(apppki.WorkspaceStatus)
	if !ok || !status.Initialized {
		t.Fatalf("result = %#v", result.JSON)
	}
}

func TestPKIAuthorityUnlockRequiresExplicitApproval(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	definition, _ := registry.Find("pki", "authority", "unlock")
	invocation := Invocation{Positionals: map[string]string{"authority": "authority-test"}, Options: map[string]string{"workspace": ".hovel", "duration": "1m"}}
	if _, err := definition.Execute(t.Context(), invocation); err == nil {
		t.Fatal("authority unlock accepted a request without --approve")
	}
	invocation.Flags = map[string]bool{"approve": true}
	if _, err := definition.Execute(t.Context(), invocation); err != nil {
		t.Fatal(err)
	}
	if control.unlocks != 1 || !control.scope.ApproveSigningLease {
		t.Fatalf("unlock calls=%d scope=%#v", control.unlocks, control.scope)
	}
}

func TestPKICertificateLifecycleCommandsUseTypedRequests(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	renew, ok := registry.Find("pki", "certificate", "renew")
	if !ok {
		t.Fatal("pki certificate renew command is missing")
	}
	base := Invocation{
		Positionals: map[string]string{"generation": "certgen-current"},
		Options: map[string]string{
			"workspace": ".hovel", "generation-id": "certgen-renewed",
			"idempotency-key": "test:renew",
		},
		Flags: map[string]bool{"yes": true}, NonInteractive: true,
	}
	if _, err := renew.Execute(t.Context(), base); err != nil {
		t.Fatal(err)
	}
	if control.renewRequest.SourceGenerationID != "certgen-current" ||
		control.renewRequest.GenerationID != "certgen-renewed" ||
		control.renewRequest.IdempotencyKey != "test:renew" || control.scope.CorrelationID == "" {
		t.Fatalf("RenewPKICertificate() request=%#v scope=%#v", control.renewRequest, control.scope)
	}
	rotate, ok := registry.Find("pki", "certificate", "rotate")
	if !ok {
		t.Fatal("pki certificate rotate command is missing")
	}
	base.Options["generation-id"] = "certgen-rotated"
	base.Options["key-id"] = "key-rotated"
	base.Options["backend"] = "builtin-go-x509"
	base.Options["idempotency-key"] = "test:rotate"
	if _, err := rotate.Execute(t.Context(), base); err != nil {
		t.Fatal(err)
	}
	if control.rotateRequest.SourceGenerationID != "certgen-current" ||
		control.rotateRequest.GenerationID != "certgen-rotated" || control.rotateRequest.KeyID != "key-rotated" ||
		control.rotateRequest.BackendID != "builtin-go-x509" || control.rotateRequest.IdempotencyKey != "test:rotate" {
		t.Fatalf("RotatePKICertificate() request=%#v", control.rotateRequest)
	}
}

func TestPKICertificateRevokeUsesTypedRequest(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	revoke, ok := registry.Find("pki", "certificate", "revoke")
	if !ok {
		t.Fatal("pki certificate revoke command is missing")
	}
	effectiveAt := time.Date(2026, 7, 12, 1, 2, 3, 0, time.UTC)
	invocation := Invocation{
		Positionals: map[string]string{"generation": "certgen-revoked"},
		Options: map[string]string{
			"workspace": ".hovel", "reason": string(domainpki.RevocationReasonKeyCompromise),
			"effective-at": effectiveAt.Format(time.RFC3339), "idempotency-key": "test:revoke",
		},
		Flags: map[string]bool{"yes": true}, NonInteractive: true,
	}
	if _, err := revoke.Execute(t.Context(), invocation); err != nil {
		t.Fatal(err)
	}
	request := control.revokeRequest
	if request.GenerationID != "certgen-revoked" || request.Reason != domainpki.RevocationReasonKeyCompromise ||
		!request.EffectiveAt.Equal(effectiveAt) || request.IdempotencyKey != "test:revoke" || control.scope.CorrelationID == "" {
		t.Fatalf("RevokePKICertificate() request=%#v scope=%#v", request, control.scope)
	}
}

func TestPKICRLPublishUsesTypedRequest(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	publish, ok := registry.Find("pki", "crl", "publish")
	if !ok {
		t.Fatal("pki crl publish command is missing")
	}
	invocation := Invocation{
		Positionals: map[string]string{"authority": "authority-crl"},
		Options: map[string]string{
			"workspace": ".hovel", "issuer-generation": "certgen-crl-issuer",
			"valid-for": "12h", "signature-algorithm": "ecdsa-sha384",
			"idempotency-key": "test:crl-publish",
		},
		Flags: map[string]bool{"yes": true}, NonInteractive: true,
	}
	if _, err := publish.Execute(t.Context(), invocation); err != nil {
		t.Fatal(err)
	}
	request := control.crlRequest
	if request.AuthorityID != "authority-crl" || request.IssuerGenerationID != "certgen-crl-issuer" ||
		request.ValiditySeconds != uint32((12*time.Hour)/time.Second) ||
		request.SignatureAlgorithm != domainpki.SignatureAlgorithmECDSASHA384 ||
		request.IdempotencyKey != "test:crl-publish" || control.scope.CorrelationID == "" {
		t.Fatalf("PublishPKICRL() request=%#v scope=%#v", request, control.scope)
	}
	invocation.Options["valid-for"] = "1.5s"
	if _, err := publish.Execute(t.Context(), invocation); err == nil {
		t.Fatal("pki crl publish accepted a fractional-second validity")
	}
}

func TestPKIAssignmentBindRequiresConfirmationAndUsesTypedRequest(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	definition, ok := registry.Find("pki", "assignment", "bind")
	if !ok {
		t.Fatal("pki assignment bind command is missing")
	}
	invocation := Invocation{
		Positionals: map[string]string{"consumer": "mesh-provider/listener-edge"},
		Options: map[string]string{
			"workspace": ".hovel", "id": "assignment-edge", "consumer-type": "mesh-listener",
			"purpose": "mtls-server", "profile": "mtls-server", "trust-set": "trust-edge",
			"idempotency-key": "test:assignment-bind",
		},
		NonInteractive: true,
	}
	if _, err := definition.Execute(t.Context(), invocation); err == nil {
		t.Fatal("pki assignment bind accepted a non-interactive request without --yes")
	}
	invocation.Flags = map[string]bool{"yes": true}
	if _, err := definition.Execute(t.Context(), invocation); err != nil {
		t.Fatal(err)
	}
	if control.boundAssignment.ID != "assignment-edge" || control.boundAssignment.ConsumerType != domainpki.ConsumerMeshListener ||
		control.boundAssignment.ConsumerID != "mesh-provider/listener-edge" || control.boundAssignment.Purpose != domainpki.PurposeMTLSServer ||
		control.boundAssignment.IdempotencyKey != "test:assignment-bind" ||
		control.scope.CorrelationID == "" {
		t.Fatalf("BindPKIAssignment() request=%#v scope=%#v", control.boundAssignment, control.scope)
	}
}

func TestPKITrustStageParsesBoundedTypedLists(t *testing.T) {
	t.Parallel()

	control := &fakePKIControlClient{}
	registry := HovelRegistry(pkiTestRuntime(t, control))
	definition, ok := registry.Find("pki", "trust", "stage")
	if !ok {
		t.Fatal("pki trust stage command is missing")
	}
	invocation := Invocation{
		Positionals: map[string]string{"trust-set": "trust-edge"},
		Options: map[string]string{
			"workspace": ".hovel", "revision": "2", "generation-id": "trust-generation-2",
			"anchors": "root-old, root-new", "intermediates": "issuer-new", "crls": "crl-new",
			"idempotency-key": "test:trust-stage",
		},
		Flags: map[string]bool{"yes": true}, NonInteractive: true,
	}
	if _, err := definition.Execute(t.Context(), invocation); err != nil {
		t.Fatal(err)
	}
	request := control.stagedTrust
	if request.TrustSetID != "trust-edge" || request.ExpectedRevision != 2 || request.GenerationID != "trust-generation-2" ||
		request.IdempotencyKey != "test:trust-stage" ||
		len(request.AnchorGenerationIDs) != 2 || request.AnchorGenerationIDs[1] != "root-new" ||
		len(request.IntermediateGenerationIDs) != 1 || len(request.CRLGenerationIDs) != 1 {
		t.Fatalf("StagePKITrustSet() request = %#v", request)
	}
	invocation.Options["revision"] = "0"
	if _, err := definition.Execute(t.Context(), invocation); err == nil {
		t.Fatal("pki trust stage accepted revision zero")
	}
}

func pkiTestRuntime(t *testing.T, control *fakePKIControlClient) Runtime {
	t.Helper()
	identity, err := daemon.NewIdentity(daemon.IdentityArgs{
		WorkspacePath: ".hovel", PID: 1234, SocketPath: "/tmp/hovel-pki-test.sock",
		StartedAt: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC), Health: daemon.HealthHealthy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Runtime{
		Daemons: fakePKIDaemonService{status: daemon.Running(identity)},
		Runs:    fakePKIClientFactory{control: control},
	}
}

type fakePKIDaemonService struct{ status daemon.Status }

func (s fakePKIDaemonService) Status(context.Context, services.DaemonStatusRequest) (daemon.Status, error) {
	return s.status, nil
}

var _ PKIControlClient = fakePKIRunClient{}
