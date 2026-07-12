package pki_test

import (
	"context"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
)

func TestRequestContextRequiresIdentityAndNarrowApprovals(t *testing.T) {
	t.Parallel()

	audit := apppki.AuditContext{
		ActorID:       "operator-1",
		OperationID:   "pki-operation-1",
		CorrelationID: "request-1",
	}
	ctx, err := apppki.WithRequestContext(t.Context(), apppki.RequestContext{Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	provider := apppki.ContextAuditContextProvider{}
	got, err := provider.AuditContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != audit {
		t.Fatalf("audit context = %#v, want %#v", got, audit)
	}
	if err := (apppki.ContextSigningLeaseApprover{}).AuthorizeSigningLease(ctx, "authority-1", time.Minute, audit); err == nil {
		t.Fatal("signing lease was approved without explicit permission")
	}
	if err := (apppki.ContextExportAuthorizer{}).AuthorizePrivateKeyExport(ctx, "certgen-1"); err == nil {
		t.Fatal("private export was approved without explicit permission")
	}
	if err := (apppki.ContextCredentialUseAuthorizer{}).AuthorizeCredentialUse(ctx, "assignment-1"); err == nil {
		t.Fatal("credential use was approved without explicit permission")
	}
	if err := provider.AuthorizeIssuanceReconciliation(ctx, audit); err == nil {
		t.Fatal("issuance reconciliation was approved without explicit permission")
	}
	if err := provider.AuthorizeCRLPublicationReconciliation(ctx, audit); err == nil {
		t.Fatal("CRL publication reconciliation was approved without explicit permission")
	}

	approved, err := apppki.WithRequestContext(context.Background(), apppki.RequestContext{
		Audit:                    audit,
		ApproveSigningLease:      true,
		ApprovePrivateKeyExport:  true,
		ApproveCredentialUse:     true,
		ApproveReconciliation:    true,
		ApproveCRLReconciliation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (apppki.ContextSigningLeaseApprover{}).AuthorizeSigningLease(approved, "authority-1", time.Minute, audit); err != nil {
		t.Fatalf("approved signing lease: %v", err)
	}
	if err := (apppki.ContextExportAuthorizer{}).AuthorizePrivateKeyExport(approved, "certgen-1"); err != nil {
		t.Fatalf("approved private export: %v", err)
	}
	if err := (apppki.ContextCredentialUseAuthorizer{}).AuthorizeCredentialUse(approved, "assignment-1"); err != nil {
		t.Fatalf("approved credential use: %v", err)
	}
	if err := provider.AuthorizeIssuanceReconciliation(approved, audit); err != nil {
		t.Fatalf("approved issuance reconciliation: %v", err)
	}
	if err := provider.AuthorizeCRLPublicationReconciliation(approved, audit); err != nil {
		t.Fatalf("approved CRL reconciliation: %v", err)
	}
}

func TestRequestContextRejectsMissingOrInvalidIdentity(t *testing.T) {
	t.Parallel()

	var nilParent context.Context
	if _, err := apppki.WithRequestContext(nilParent, apppki.RequestContext{}); err == nil {
		t.Fatal("WithRequestContext() accepted a nil parent")
	}
	if _, err := apppki.WithRequestContext(t.Context(), apppki.RequestContext{}); err == nil {
		t.Fatal("WithRequestContext() accepted an empty audit identity")
	}
	if _, err := (apppki.ContextAuditContextProvider{}).AuditContext(t.Context()); err == nil {
		t.Fatal("AuditContext() accepted a context without authenticated request data")
	}
}
