package pki

import (
	"context"
	"errors"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

// WorkspaceStatus reports whether the workspace PKI can serve operations.
// It deliberately contains no secret-provider paths or key material.
type WorkspaceStatus struct {
	Initialized       bool   `json:"initialized"`
	ActiveKeyVersion  string `json:"activeKeyVersion,omitempty"`
	MasterKeyVersions int    `json:"masterKeyVersions,omitempty"`
	Error             string `json:"error,omitempty"`
}

// WorkspaceControl is the daemon-facing PKI application boundary. Front ends
// use this interface rather than constructing custody or persistence adapters.
type WorkspaceControl interface {
	Close() error
	Status(context.Context) WorkspaceStatus
	Initialize(context.Context) (WorkspaceStatus, error)
	BackendDescriptors(context.Context) ([]domainpki.BackendDescriptor, error)
	ListAuthorities(context.Context) ([]domainpki.Authority, error)
	InspectAuthority(context.Context, domainpki.AuthorityID) (AuthorityInspection, error)
	ListCertificateGenerations(context.Context) ([]domainpki.CertificateGeneration, error)
	InspectCertificateGeneration(context.Context, domainpki.GenerationID) (domainpki.CertificateGeneration, error)
	ListAssignments(context.Context) ([]domainpki.Assignment, error)
	ListCredentialStamps(context.Context) ([]domainpki.CredentialStamp, error)
	InspectCredentialStamp(context.Context, domainpki.StampID) (domainpki.CredentialStamp, error)
	ListCredentialExecutions(context.Context) ([]domainpki.CredentialExecution, error)
	InspectCredentialExecution(context.Context, domainpki.CredentialExecutionRequestID) (domainpki.CredentialExecution, error)
	InspectAssignment(context.Context, domainpki.AssignmentID) (AssignmentInspection, error)
	BindAssignment(context.Context, BindAssignmentRequest) (domainpki.Assignment, error)
	StageAssignment(context.Context, StageAssignmentRequest) (AssignmentInspection, error)
	ActivateAssignment(context.Context, ActivateAssignmentRequest) (AssignmentInspection, error)
	UnbindAssignment(context.Context, UnbindAssignmentRequest) (domainpki.Assignment, error)
	ListTrustSets(context.Context) ([]domainpki.TrustSet, error)
	InspectTrustSet(context.Context, domainpki.TrustSetID) (TrustSetInspection, error)
	CreateTrustSet(context.Context, CreateTrustSetRequest) (domainpki.TrustSet, error)
	StageTrustSet(context.Context, StageTrustSetRequest) (TrustSetInspection, error)
	ActivateTrustSet(context.Context, ActivateTrustSetRequest) (TrustSetInspection, error)
	CreateAuthority(context.Context, CreateAuthorityRequest) (CreateAuthorityResult, error)
	IssueCertificate(context.Context, IssueCertificateRequest) (domainpki.CertificateGeneration, error)
	RenewCertificate(context.Context, RenewCertificateRequest) (CertificateLifecycleResult, error)
	RotateCertificate(context.Context, RotateCertificateRequest) (CertificateLifecycleResult, error)
	RevokeCertificate(context.Context, RevokeCertificateRequest) (CertificateRevocationResult, error)
	InspectRevocation(context.Context, domainpki.RevocationID) (domainpki.Revocation, error)
	InspectGenerationRevocation(context.Context, domainpki.GenerationID) (domainpki.Revocation, error)
	ListAuthorityRevocations(context.Context, domainpki.AuthorityID) ([]domainpki.Revocation, error)
	PublishCRL(context.Context, PublishCRLRequest) (CRLPublicationResult, error)
	InspectCRLPublication(context.Context, domainpki.CRLPublicationID) (CRLPublicationIntent, error)
	ListCRLPublications(context.Context, domainpki.AuthorityID) ([]CRLPublicationIntent, error)
	InspectCRLGeneration(context.Context, domainpki.CRLGenerationID) (domainpki.CRLGeneration, error)
	ListCRLGenerations(context.Context, domainpki.AuthorityID) ([]domainpki.CRLGeneration, error)
	ReconcileCRLPublication(context.Context, ReconcileCRLPublicationRequest) (CRLPublicationIntent, error)
	ReconcileCRLPublications(context.Context, ReconcileCRLPublicationsRequest) ([]CRLPublicationIntent, error)
	UnlockAuthoritySigning(context.Context, domainpki.AuthorityID, time.Duration) (SigningLease, error)
	LockAuthoritySigning(context.Context, domainpki.AuthorityID) error
	AuthoritySigningLease(context.Context, domainpki.AuthorityID) (SigningLease, bool, error)
	ExportBundle(context.Context, domainpki.GenerationID, domainpki.Purpose, bool) (domainpki.Bundle, error)
}

// OperationControl is the optional daemon capability for durable PKI
// operations. Keeping it separate lets minimal PKI controls omit long-running
// workflows without weakening their contracts with unimplemented methods.
type OperationControl interface {
	ListOperations(context.Context) ([]domainpki.Operation, error)
	InspectOperation(context.Context, domainpki.OperationID) (OperationInspection, error)
	StartAuthorityRollover(context.Context, StartAuthorityRolloverRequest) (OperationInspection, error)
	AcknowledgeAuthorityRollover(context.Context, AcknowledgeAuthorityRolloverRequest) (OperationInspection, error)
	ActivateAuthorityRollover(context.Context, ActivateAuthorityRolloverRequest) (OperationInspection, error)
	BeginAuthorityRolloverFinalTrust(context.Context, BeginAuthorityRolloverFinalTrustRequest) (OperationInspection, error)
	CompleteAuthorityRollover(context.Context, CompleteAuthorityRolloverRequest) (OperationInspection, error)
	CancelAuthorityRollover(context.Context, CancelAuthorityRolloverRequest) (OperationInspection, error)
}

// CredentialExecutionRecorder is the daemon-owned write boundary for
// secret-free provider invocation bookkeeping. Runtime adapters use it around
// provider calls; front ends receive only the list and inspect methods on
// WorkspaceControl.
type CredentialExecutionRecorder interface {
	RecordCredentialExecutionPlan(
		context.Context,
		string,
		domainpki.CredentialExecution,
	) (domainpki.CredentialExecution, error)
	RecordCredentialExecutionTransition(
		context.Context,
		string,
		domainpki.CredentialExecution,
	) (domainpki.CredentialExecution, error)
}

// RequestContext is the authenticated, auditable scope of one front-end call.
// Approval booleans are intentionally narrow instead of a string permission
// bag so callers cannot invent authority by adding an unknown capability.
type RequestContext struct {
	Audit                    AuditContext `json:"audit"`
	ApproveSigningLease      bool         `json:"approveSigningLease,omitempty"`
	ApprovePrivateKeyExport  bool         `json:"approvePrivateKeyExport,omitempty"`
	ApproveCredentialUse     bool         `json:"approveCredentialUse,omitempty"`
	ApproveReconciliation    bool         `json:"approveIssuanceReconciliation,omitempty"`
	ApproveCRLReconciliation bool         `json:"approveCrlPublicationReconciliation,omitempty"`
}

func (r RequestContext) Validate() error {
	return r.Audit.Validate()
}

type requestContextKey struct{}

// WithRequestContext binds authenticated caller identity and explicit
// approvals to an application call.
func WithRequestContext(ctx context.Context, request RequestContext) (context.Context, error) {
	if ctx == nil {
		return nil, errors.New("pki: request context parent is required")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, requestContextKey{}, request), nil
}

func requestContext(ctx context.Context) (RequestContext, error) {
	if ctx == nil {
		return RequestContext{}, errors.New("pki: request context is required")
	}
	request, ok := ctx.Value(requestContextKey{}).(RequestContext)
	if !ok {
		return RequestContext{}, errors.New("pki: authenticated request context is required")
	}
	if err := request.Validate(); err != nil {
		return RequestContext{}, err
	}
	return request, nil
}

// ContextAuditContextProvider resolves the audit scope bound by a front-end
// adapter through WithRequestContext.
type ContextAuditContextProvider struct{}

func (ContextAuditContextProvider) AuditContext(ctx context.Context) (AuditContext, error) {
	request, err := requestContext(ctx)
	if err != nil {
		return AuditContext{}, err
	}
	return request.Audit, nil
}

// ContextSigningLeaseApprover requires an explicit approval on the current
// authenticated request. The resulting lease remains actor/operation scoped.
type ContextSigningLeaseApprover struct{}

func (ContextSigningLeaseApprover) AuthorizeSigningLease(ctx context.Context, _ domainpki.AuthorityID, _ time.Duration, _ AuditContext) error {
	request, err := requestContext(ctx)
	if err != nil {
		return err
	}
	if !request.ApproveSigningLease {
		return errors.New("pki: signing lease requires explicit request approval")
	}
	return nil
}

// ContextExportAuthorizer requires an explicit private-export approval on the
// current authenticated request.
type ContextExportAuthorizer struct{}

func (ContextExportAuthorizer) AuthorizePrivateKeyExport(ctx context.Context, _ domainpki.GenerationID) error {
	request, err := requestContext(ctx)
	if err != nil {
		return err
	}
	if !request.ApprovePrivateKeyExport {
		return errors.New("pki: private-key export requires explicit request approval")
	}
	return nil
}

// ContextCredentialUseAuthorizer requires explicit approval before assignment
// material is delivered into a provider process. This is intentionally
// separate from private-key export because no secret is returned to the
// external control-plane caller.
type ContextCredentialUseAuthorizer struct{}

func (ContextCredentialUseAuthorizer) AuthorizeCredentialUse(
	ctx context.Context,
	_ domainpki.AssignmentID,
) error {
	request, err := requestContext(ctx)
	if err != nil {
		return err
	}
	if !request.ApproveCredentialUse {
		return errors.New("pki: credential use requires explicit request approval")
	}
	return nil
}

func (ContextAuditContextProvider) AuthorizeCredentialUse(
	ctx context.Context,
	assignmentID domainpki.AssignmentID,
) error {
	return (ContextCredentialUseAuthorizer{}).AuthorizeCredentialUse(ctx, assignmentID)
}

func (ContextAuditContextProvider) AuthorizeIssuanceReconciliation(ctx context.Context, _ AuditContext) error {
	request, err := requestContext(ctx)
	if err != nil {
		return err
	}
	if !request.ApproveReconciliation {
		return errors.New("pki: issuance reconciliation requires explicit request approval")
	}
	return nil
}

func (ContextAuditContextProvider) AuthorizeCRLPublicationReconciliation(ctx context.Context, _ AuditContext) error {
	request, err := requestContext(ctx)
	if err != nil {
		return err
	}
	if !request.ApproveCRLReconciliation {
		return errors.New("pki: crl publication reconciliation requires explicit request approval")
	}
	return nil
}
