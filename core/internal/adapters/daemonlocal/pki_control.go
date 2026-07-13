package daemonlocal

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/adapters/storage/filesystem"
	sqlitestore "github.com/vibepwners/hovel/internal/adapters/storage/sqlite"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

type pkiClock struct{}

func (pkiClock) Now() time.Time {
	return time.Now().UTC()
}

// workspacePKIControl owns one daemon-lifetime PKI service and its master-key
// provider. It opens existing custody lazily and initializes custody only from
// the explicit Initialize call.
type workspacePKIControl struct {
	workspacePath string
	workspaceID   workspace.ID

	mu          sync.Mutex
	active      sync.WaitGroup
	provider    *infrapki.FileMasterKeyProvider
	persistence *sqlitestore.PKIStore
	backends    apppki.BackendRegistry
	validators  apppki.ValidatorRegistry
	service     apppki.Service
	ready       bool
	closed      bool
}

func newWorkspacePKIControl(ctx context.Context, workspacePath string) (apppki.WorkspaceControl, error) {
	backend := infrapki.NewBackend()
	backends, err := apppki.NewStaticBackendRegistry(backend)
	if err != nil {
		return nil, err
	}
	validators, err := apppki.NewStaticValidatorRegistry(map[domainpki.BackendID]apppki.Validator{
		backend.Descriptor().ID: infrapki.NewValidator(),
	})
	if err != nil {
		return nil, err
	}
	return newWorkspacePKIControlWithRegistries(ctx, workspacePath, backends, validators)
}

func newWorkspacePKIControlWithRegistries(
	ctx context.Context,
	workspacePath string,
	backends apppki.BackendRegistry,
	validators apppki.ValidatorRegistry,
) (apppki.WorkspaceControl, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if backends == nil || validators == nil {
		return nil, errors.New("workspace PKI crypto registries are required")
	}
	return &workspacePKIControl{
		workspacePath: workspace.ResolvePath(workspacePath),
		backends:      backends,
		validators:    validators,
	}, nil
}

func (c *workspacePKIControl) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.ready = false
	c.service = apppki.Service{}
	provider := c.provider
	c.provider = nil
	persistence := c.persistence
	c.persistence = nil
	c.mu.Unlock()
	c.active.Wait()
	var closeStoreErr, closeProviderErr error
	if persistence != nil {
		closeStoreErr = persistence.Close()
	}
	if provider != nil {
		closeProviderErr = provider.Close()
	}
	return errors.Join(closeStoreErr, closeProviderErr)
}

func (c *workspacePKIControl) Status(ctx context.Context) apppki.WorkspaceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureServiceLocked(ctx, false); err != nil {
		if errors.Is(err, infrapki.ErrMasterKeysNotInitialized) {
			return apppki.WorkspaceStatus{}
		}
		return apppki.WorkspaceStatus{Error: "workspace PKI is unavailable"}
	}
	version, err := c.provider.ActiveVersion(ctx)
	if err != nil {
		return apppki.WorkspaceStatus{Initialized: true, Error: "workspace PKI custody is unavailable"}
	}
	return apppki.WorkspaceStatus{
		Initialized:       true,
		ActiveKeyVersion:  version,
		MasterKeyVersions: len(c.provider.Versions()),
	}
}

func (c *workspacePKIControl) Initialize(ctx context.Context) (apppki.WorkspaceStatus, error) {
	if _, err := (apppki.ContextAuditContextProvider{}).AuditContext(ctx); err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureServiceLocked(ctx, true); err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	version, err := c.provider.ActiveVersion(ctx)
	if err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	return apppki.WorkspaceStatus{
		Initialized:       true,
		ActiveKeyVersion:  version,
		MasterKeyVersions: len(c.provider.Versions()),
	}, nil
}

func (c *workspacePKIControl) ensureServiceLocked(ctx context.Context, initialize bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.ready {
		return nil
	}
	if c.closed {
		return errors.New("workspace PKI control is closed")
	}
	if c.workspaceID == "" {
		ws, err := (filesystem.NewWorkspaceStore()).LoadWorkspace(ctx, c.workspacePath)
		if err != nil {
			return err
		}
		c.workspacePath = ws.Path
		c.workspaceID = ws.ID
	}
	provider, err := infrapki.OpenFileMasterKeyProvider(ctx, c.workspacePath)
	if errors.Is(err, infrapki.ErrMasterKeysNotInitialized) && initialize {
		provider, err = infrapki.InitializeFileMasterKeyProvider(ctx, c.workspacePath)
		if errors.Is(err, os.ErrExist) {
			provider, err = infrapki.OpenFileMasterKeyProvider(ctx, c.workspacePath)
		}
	}
	if err != nil {
		return err
	}
	protector, err := infrapki.NewEnvelopeProtector(c.workspaceID, provider)
	if err != nil {
		return errors.Join(err, provider.Close())
	}
	persistence, err := sqlitestore.NewPKIStore(c.workspacePath, c.workspaceID, protector)
	if err != nil {
		return errors.Join(err, provider.Close())
	}
	clock := pkiClock{}
	leases, err := apppki.NewSigningLeaseManager(clock, apppki.ContextSigningLeaseApprover{})
	if err != nil {
		return errors.Join(err, provider.Close())
	}
	service, err := apppki.NewServiceWithCryptoRegistries(
		ctx,
		persistence,
		c.backends,
		c.validators,
		leases,
		apppki.ContextExportAuthorizer{},
		persistence,
		apppki.ContextAuditContextProvider{},
		clock,
		rand.Reader,
	)
	if err != nil {
		return errors.Join(err, provider.Close())
	}
	c.provider = provider
	c.persistence = &persistence
	c.service = service
	c.ready = true
	return nil
}

func (c *workspacePKIControl) serviceFor(ctx context.Context) (apppki.Service, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureServiceLocked(ctx, false); err != nil {
		return apppki.Service{}, nil, err
	}
	c.active.Add(1)
	return c.service, c.active.Done, nil
}

func (c *workspacePKIControl) BackendDescriptors(ctx context.Context) ([]domainpki.BackendDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.backends.BackendDescriptors(ctx)
}

func (c *workspacePKIControl) ResolveCredentialOperation(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) (*services.CredentialOperationResolution, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	lease, err := service.ResolveCredentialOperationLease(
		ctx,
		provider,
		descriptor,
		selections,
		scope,
		consumers,
	)
	if err != nil {
		release()
		return nil, err
	}
	workspaceLease, err := newWorkspaceCredentialOperationLease(lease, release)
	if err != nil {
		lease.Close()
		release()
		return nil, err
	}
	resolution, err := services.NewCredentialOperationResolution(workspaceLease)
	if err != nil {
		workspaceLease.Close()
		return nil, err
	}
	return resolution, nil
}

type credentialOperationLease interface {
	BorrowedDeliveries() (domainpki.CredentialOperationDeliveries, error)
	Revalidate(context.Context) error
	Close()
}

type workspaceCredentialOperationLease struct {
	lease   credentialOperationLease
	release func()
	once    sync.Once
}

func newWorkspaceCredentialOperationLease(
	lease credentialOperationLease,
	release func(),
) (*workspaceCredentialOperationLease, error) {
	if lease == nil {
		return nil, errors.New("workspace PKI credential operation lease is required")
	}
	if release == nil {
		return nil, errors.New("workspace PKI credential operation release is required")
	}
	return &workspaceCredentialOperationLease{lease: lease, release: release}, nil
}

func (l *workspaceCredentialOperationLease) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	if l == nil || l.lease == nil {
		return nil, errors.New("workspace PKI credential operation lease is required")
	}
	return l.lease.BorrowedDeliveries()
}

func (l *workspaceCredentialOperationLease) Revalidate(ctx context.Context) error {
	if l == nil || l.lease == nil {
		return errors.New("workspace PKI credential operation lease is required")
	}
	return l.lease.Revalidate(ctx)
}

func (l *workspaceCredentialOperationLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.lease != nil {
			l.lease.Close()
		}
		if l.release != nil {
			l.release()
		}
	})
}

func (c *workspacePKIControl) ListOperations(ctx context.Context) ([]domainpki.Operation, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListOperations(ctx)
}

func (c *workspacePKIControl) ListCredentialStamps(
	ctx context.Context,
) ([]domainpki.CredentialStamp, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return service.ListCredentialStamps(ctx)
}

func (c *workspacePKIControl) InspectCredentialStamp(
	ctx context.Context,
	id domainpki.StampID,
) (domainpki.CredentialStamp, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	defer done()
	return service.InspectCredentialStamp(ctx, id)
}

func (c *workspacePKIControl) ListCredentialExecutions(
	ctx context.Context,
) ([]domainpki.CredentialExecution, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return service.ListCredentialExecutions(ctx)
}

func (c *workspacePKIControl) InspectCredentialExecution(
	ctx context.Context,
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	defer done()
	return service.InspectCredentialExecution(ctx, id)
}

func (c *workspacePKIControl) RecordCredentialExecutionPlan(
	ctx context.Context,
	idempotencyKey string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	defer done()
	return service.RecordCredentialExecutionPlan(ctx, idempotencyKey, execution)
}

func (c *workspacePKIControl) RecordCredentialExecutionTransition(
	ctx context.Context,
	idempotencyKey string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	service, done, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	defer done()
	return service.RecordCredentialExecutionTransition(ctx, idempotencyKey, execution)
}

func (c *workspacePKIControl) InspectOperation(
	ctx context.Context,
	id domainpki.OperationID,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.InspectOperation(ctx, id)
}

func (c *workspacePKIControl) StartAuthorityRollover(
	ctx context.Context,
	request apppki.StartAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.StartAuthorityRollover(ctx, request)
}

func (c *workspacePKIControl) AcknowledgeAuthorityRollover(
	ctx context.Context,
	request apppki.AcknowledgeAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.AcknowledgeAuthorityRollover(ctx, request)
}

func (c *workspacePKIControl) ActivateAuthorityRollover(
	ctx context.Context,
	request apppki.ActivateAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.ActivateAuthorityRollover(ctx, request)
}

func (c *workspacePKIControl) BeginAuthorityRolloverFinalTrust(
	ctx context.Context,
	request apppki.BeginAuthorityRolloverFinalTrustRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.BeginAuthorityRolloverFinalTrust(ctx, request)
}

func (c *workspacePKIControl) CompleteAuthorityRollover(
	ctx context.Context,
	request apppki.CompleteAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.CompleteAuthorityRollover(ctx, request)
}

func (c *workspacePKIControl) CancelAuthorityRollover(
	ctx context.Context,
	request apppki.CancelAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	defer release()
	return service.CancelAuthorityRollover(ctx, request)
}

func (c *workspacePKIControl) ListAuthorities(ctx context.Context) ([]domainpki.Authority, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListAuthorities(ctx)
}

func (c *workspacePKIControl) InspectAuthority(ctx context.Context, id domainpki.AuthorityID) (apppki.AuthorityInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.AuthorityInspection{}, err
	}
	defer release()
	return service.InspectAuthority(ctx, id)
}

func (c *workspacePKIControl) ListCertificateGenerations(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListCertificateGenerations(ctx)
}

func (c *workspacePKIControl) InspectCertificateGeneration(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	defer release()
	return service.InspectCertificateGeneration(ctx, id)
}

func (c *workspacePKIControl) ListAssignments(ctx context.Context) ([]domainpki.Assignment, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListAssignments(ctx)
}

func (c *workspacePKIControl) InspectAssignment(ctx context.Context, id domainpki.AssignmentID) (apppki.AssignmentInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	defer release()
	return service.InspectAssignment(ctx, id)
}

func (c *workspacePKIControl) BindAssignment(ctx context.Context, request apppki.BindAssignmentRequest) (domainpki.Assignment, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	defer release()
	return service.BindAssignment(ctx, request)
}

func (c *workspacePKIControl) StageAssignment(ctx context.Context, request apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	defer release()
	return service.StageAssignment(ctx, request)
}

func (c *workspacePKIControl) ActivateAssignment(ctx context.Context, request apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	defer release()
	return service.ActivateAssignment(ctx, request)
}

func (c *workspacePKIControl) UnbindAssignment(ctx context.Context, request apppki.UnbindAssignmentRequest) (domainpki.Assignment, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	defer release()
	return service.UnbindAssignment(ctx, request)
}

func (c *workspacePKIControl) ListTrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListTrustSets(ctx)
}

func (c *workspacePKIControl) InspectTrustSet(ctx context.Context, id domainpki.TrustSetID) (apppki.TrustSetInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	defer release()
	return service.InspectTrustSet(ctx, id)
}

func (c *workspacePKIControl) CreateTrustSet(ctx context.Context, request apppki.CreateTrustSetRequest) (domainpki.TrustSet, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	defer release()
	return service.CreateTrustSet(ctx, request)
}

func (c *workspacePKIControl) StageTrustSet(ctx context.Context, request apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	defer release()
	return service.StageTrustSet(ctx, request)
}

func (c *workspacePKIControl) ActivateTrustSet(ctx context.Context, request apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	defer release()
	return service.ActivateTrustSet(ctx, request)
}

func (c *workspacePKIControl) CreateAuthority(ctx context.Context, request apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CreateAuthorityResult{}, err
	}
	defer release()
	return service.CreateAuthority(ctx, request)
}

func (c *workspacePKIControl) IssueCertificate(ctx context.Context, request apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	defer release()
	return service.IssueCertificate(ctx, request)
}

func (c *workspacePKIControl) RenewCertificate(ctx context.Context, request apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	defer release()
	return service.RenewCertificate(ctx, request)
}

func (c *workspacePKIControl) RotateCertificate(ctx context.Context, request apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	defer release()
	return service.RotateCertificate(ctx, request)
}

func (c *workspacePKIControl) RevokeCertificate(ctx context.Context, request apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CertificateRevocationResult{}, err
	}
	defer release()
	return service.RevokeCertificate(ctx, request)
}

func (c *workspacePKIControl) InspectRevocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.Revocation{}, err
	}
	defer release()
	return service.InspectRevocation(ctx, id)
}

func (c *workspacePKIControl) InspectGenerationRevocation(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.Revocation{}, err
	}
	defer release()
	return service.InspectGenerationRevocation(ctx, id)
}

func (c *workspacePKIControl) ListAuthorityRevocations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListAuthorityRevocations(ctx, id)
}

func (c *workspacePKIControl) PublishCRL(ctx context.Context, request apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CRLPublicationResult{}, err
	}
	defer release()
	return service.PublishCRL(ctx, request)
}

func (c *workspacePKIControl) InspectCRLPublication(ctx context.Context, id domainpki.CRLPublicationID) (apppki.CRLPublicationIntent, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	defer release()
	return service.InspectCRLPublication(ctx, id)
}

func (c *workspacePKIControl) ListCRLPublications(ctx context.Context, id domainpki.AuthorityID) ([]apppki.CRLPublicationIntent, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListCRLPublications(ctx, id)
}

func (c *workspacePKIControl) InspectCRLGeneration(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.CRLGeneration{}, err
	}
	defer release()
	return service.InspectCRLGeneration(ctx, id)
}

func (c *workspacePKIControl) ListCRLGenerations(ctx context.Context, id domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ListCRLGenerations(ctx, id)
}

func (c *workspacePKIControl) ReconcileCRLPublication(ctx context.Context, request apppki.ReconcileCRLPublicationRequest) (apppki.CRLPublicationIntent, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	defer release()
	return service.ReconcileCRLPublication(ctx, request)
}

func (c *workspacePKIControl) ReconcileCRLPublications(ctx context.Context, request apppki.ReconcileCRLPublicationsRequest) ([]apppki.CRLPublicationIntent, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return service.ReconcileCRLPublications(ctx, request)
}

func (c *workspacePKIControl) UnlockAuthoritySigning(ctx context.Context, id domainpki.AuthorityID, duration time.Duration) (apppki.SigningLease, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.SigningLease{}, err
	}
	defer release()
	return service.UnlockAuthoritySigning(ctx, id, duration)
}

func (c *workspacePKIControl) LockAuthoritySigning(ctx context.Context, id domainpki.AuthorityID) error {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return err
	}
	defer release()
	return service.LockAuthoritySigning(ctx, id)
}

func (c *workspacePKIControl) AuthoritySigningLease(ctx context.Context, id domainpki.AuthorityID) (apppki.SigningLease, bool, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return apppki.SigningLease{}, false, err
	}
	defer release()
	return service.AuthoritySigningLease(ctx, id)
}

func (c *workspacePKIControl) ExportBundle(ctx context.Context, id domainpki.GenerationID, purpose domainpki.Purpose, includePrivate bool) (domainpki.Bundle, error) {
	service, release, err := c.serviceFor(ctx)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	defer release()
	return service.ExportBundle(ctx, id, purpose, includePrivate)
}

var _ apppki.WorkspaceControl = (*workspacePKIControl)(nil)
