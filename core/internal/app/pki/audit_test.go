package pki

import (
	"strings"
	"testing"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func TestAuditRecordValidationBoundsUntrustedFields(t *testing.T) {
	t.Parallel()

	valid := AuditRecord{
		ID:            "audit-1",
		Action:        AuditActionKeyAccess,
		Outcome:       AuditOutcomeSucceeded,
		ActorID:       "operator-1",
		OperationID:   "operation-1",
		CorrelationID: "correlation-1",
		ResourceType:  "key",
		ResourceID:    "key-1",
		Details:       map[string]string{"purpose": "certificate-signing"},
		CreatedAt:     time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*AuditRecord)
	}{
		{name: "non-canonical actor", mutate: func(record *AuditRecord) { record.ActorID = " operator-1" }},
		{name: "control character", mutate: func(record *AuditRecord) { record.ResourceID = "key-1\nforged" }},
		{name: "oversized id", mutate: func(record *AuditRecord) { record.OperationID = strings.Repeat("a", maximumAuditIDBytes+1) }},
		{name: "oversized detail value", mutate: func(record *AuditRecord) {
			record.Details = map[string]string{"value": strings.Repeat("a", maximumAuditDetailValueBytes+1)}
		}},
		{name: "too many details", mutate: func(record *AuditRecord) {
			record.Details = make(map[string]string, maximumAuditDetailCount+1)
			for index := range maximumAuditDetailCount + 1 {
				record.Details[string(rune('a'+index))] = "value"
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := valid.Clone()
			test.mutate(&record)
			if err := record.Validate(); err == nil {
				t.Fatal("AuditRecord.Validate() accepted unbounded or non-canonical data")
			}
		})
	}
}

func TestIssuanceCompletionAuditsRejectOrdinaryLifecycleLineage(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	audits := IssuanceCompletionAudits{SigningUse: AuditRecord{
		ID: "audit-signing-use", Action: AuditActionSigningUse, Outcome: AuditOutcomeSucceeded,
		ActorID: "operator-1", OperationID: "operation-1", CorrelationID: "correlation-1",
		ResourceType: auditResourceAuthority, ResourceID: "authority-1",
		Details: map[string]string{
			auditDetailGenerationID:       "certgen-1",
			auditDetailIssuanceKind:       string(IssuanceKindCertificate),
			auditDetailSourceGenerationID: "",
		},
		CreatedAt: createdAt,
	}}
	if err := audits.Validate(IssuanceKindCertificate, "certgen-1", "", "authority-1"); err == nil ||
		!strings.Contains(err.Error(), "cannot identify a lifecycle source") {
		t.Fatalf("IssuanceCompletionAudits.Validate() error = %v, want lifecycle-source rejection", err)
	}
}

func TestIssuanceCompletionAuditsRequireDistinctRecordIDs(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 5, 15, 0, 0, time.UTC)
	signingUse := AuditRecord{
		ID: "audit-shared", Action: AuditActionSigningUse, Outcome: AuditOutcomeSucceeded,
		ActorID: "operator-1", OperationID: "operation-1", CorrelationID: "correlation-1",
		ResourceType: auditResourceAuthority, ResourceID: "authority-1",
		Details: map[string]string{
			auditDetailGenerationID:       "certgen-renewed",
			auditDetailIssuanceKind:       string(IssuanceKindCertificateRenewal),
			auditDetailSourceGenerationID: "certgen-source",
		},
		CreatedAt: createdAt,
	}
	lifecycle := AuditRecord{
		ID: "audit-shared", Action: AuditActionCertificateRenew, Outcome: AuditOutcomeSucceeded,
		ActorID: signingUse.ActorID, OperationID: signingUse.OperationID, CorrelationID: signingUse.CorrelationID,
		ResourceType: auditResourceGeneration, ResourceID: "certgen-renewed",
		Details: map[string]string{auditDetailSourceGenerationID: "certgen-source"}, CreatedAt: createdAt,
	}
	audits := IssuanceCompletionAudits{SigningUse: signingUse, Lifecycle: &lifecycle}
	if err := audits.Validate(
		IssuanceKindCertificateRenewal, "certgen-renewed", "certgen-source", "authority-1",
	); err == nil || !strings.Contains(err.Error(), "ids must be distinct") {
		t.Fatalf("IssuanceCompletionAudits.Validate() error = %v, want duplicate-id rejection", err)
	}
}

func TestIssuanceCompletionAuditsRejectUnexpectedLifecycleDetails(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 5, 20, 0, 0, time.UTC)
	signingUse := AuditRecord{
		ID: "audit-signing", Action: AuditActionSigningUse, Outcome: AuditOutcomeSucceeded,
		ActorID: "operator-1", OperationID: "operation-1", CorrelationID: "correlation-1",
		ResourceType: auditResourceAuthority, ResourceID: "authority-1",
		Details: map[string]string{
			auditDetailGenerationID:       "certgen-renewed",
			auditDetailIssuanceKind:       string(IssuanceKindCertificateRenewal),
			auditDetailSourceGenerationID: "certgen-source",
		},
		CreatedAt: createdAt,
	}
	lifecycle := AuditRecord{
		ID: "audit-lifecycle", Action: AuditActionCertificateRenew, Outcome: AuditOutcomeSucceeded,
		ActorID: signingUse.ActorID, OperationID: signingUse.OperationID, CorrelationID: signingUse.CorrelationID,
		ResourceType: auditResourceGeneration, ResourceID: "certgen-renewed",
		Details: map[string]string{
			auditDetailSourceGenerationID: "certgen-source",
			auditDetailGenerationID:       "certgen-contradictory",
		},
		CreatedAt: createdAt,
	}
	audits := IssuanceCompletionAudits{SigningUse: signingUse, Lifecycle: &lifecycle}
	if err := audits.Validate(
		IssuanceKindCertificateRenewal, "certgen-renewed", "certgen-source", "authority-1",
	); err == nil || !strings.Contains(err.Error(), "unexpected details") {
		t.Fatalf("IssuanceCompletionAudits.Validate() error = %v, want unexpected-detail rejection", err)
	}
}

func TestValidateLifecycleSourceEligibility(t *testing.T) {
	t.Parallel()

	active := domainpki.CertificateGeneration{ID: "certgen-source", State: domainpki.CertificateStateActive}
	if err := ValidateLifecycleSourceEligibility(active); err != nil {
		t.Fatal(err)
	}
	revoked := active
	revoked.State = domainpki.CertificateStateRevoked
	if err := ValidateLifecycleSourceEligibility(revoked); err == nil || !strings.Contains(err.Error(), "while revoked") {
		t.Fatalf("ValidateLifecycleSourceEligibility() error = %v, want revoked rejection", err)
	}
}
