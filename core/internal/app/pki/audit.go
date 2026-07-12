package pki

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	maximumAuditIDBytes          = 256
	maximumAuditResourceBytes    = 512
	maximumAuditDetailCount      = 32
	maximumAuditDetailKeyBytes   = 128
	maximumAuditDetailValueBytes = 1024
)

type AuditAction string

const (
	AuditActionSigningAuthorization       AuditAction = "pki.signing.authorization"
	AuditActionSigningUse                 AuditAction = "pki.signing.use"
	AuditActionKeyAccess                  AuditAction = "pki.key.access"
	AuditActionExportAuthorization        AuditAction = "pki.private_export.authorization"
	AuditActionPrivateExport              AuditAction = "pki.private_export"
	AuditActionAuthorityUnlock            AuditAction = "pki.authority.unlock"
	AuditActionAuthorityLock              AuditAction = "pki.authority.lock"
	AuditActionIssuance                   AuditAction = "pki.issuance"
	AuditActionCertificateRenew           AuditAction = "pki.certificate.renew"
	AuditActionCertificateRotate          AuditAction = "pki.certificate.rotate"
	AuditActionCertificateRevoke          AuditAction = "pki.certificate.revoke"
	AuditActionCRLPublish                 AuditAction = "pki.crl.publish"
	AuditActionAssignmentBind             AuditAction = "pki.assignment.bind"
	AuditActionAssignmentStage            AuditAction = "pki.assignment.stage"
	AuditActionAssignmentActivate         AuditAction = "pki.assignment.activate"
	AuditActionAssignmentUnbind           AuditAction = "pki.assignment.unbind"
	AuditActionTrustSetCreate             AuditAction = "pki.trust.create"
	AuditActionTrustSetStage              AuditAction = "pki.trust.stage"
	AuditActionTrustSetActivate           AuditAction = "pki.trust.activate"
	AuditActionAuthorityRollover          AuditAction = "pki.authority.rollover"
	AuditActionConsumerAcknowledge        AuditAction = "pki.consumer.acknowledge"
	AuditActionCredentialStampPlan        AuditAction = "pki.credential_stamp.plan"
	AuditActionCredentialStampSucceed     AuditAction = "pki.credential_stamp.succeed"
	AuditActionCredentialStampFail        AuditAction = "pki.credential_stamp.fail"
	AuditActionCredentialStampSupersede   AuditAction = "pki.credential_stamp.supersede"
	AuditActionCredentialExecutionPlan    AuditAction = "pki.credential_execution.plan"
	AuditActionCredentialExecutionSucceed AuditAction = "pki.credential_execution.succeed"
	AuditActionCredentialExecutionFail    AuditAction = "pki.credential_execution.fail"
)

type AuditOutcome string

const (
	AuditOutcomeAllowed   AuditOutcome = "allowed"
	AuditOutcomeDenied    AuditOutcome = "denied"
	AuditOutcomeSucceeded AuditOutcome = "succeeded"
	AuditOutcomeFailed    AuditOutcome = "failed"
	AuditOutcomeAttempted AuditOutcome = "attempted"
)

type AuditContext struct {
	ActorID       string
	OperationID   string
	CorrelationID string
}

func (c AuditContext) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "actor id", value: c.ActorID},
		{name: "operation id", value: c.OperationID},
		{name: "correlation id", value: c.CorrelationID},
	} {
		if err := validateCanonicalAuditText(field.value, field.name, maximumAuditIDBytes); err != nil {
			return err
		}
	}
	return nil
}

type AuditContextProvider interface {
	AuditContext(context.Context) (AuditContext, error)
}

type AuditRecord struct {
	ID            string
	Action        AuditAction
	Outcome       AuditOutcome
	ActorID       string
	OperationID   string
	CorrelationID string
	ResourceType  string
	ResourceID    string
	Details       map[string]string
	CreatedAt     time.Time
}

func (r AuditRecord) Clone() AuditRecord {
	result := r
	result.Details = make(map[string]string, len(r.Details))
	for key, value := range r.Details {
		result.Details[key] = value
	}
	return result
}

func (r AuditRecord) Validate() error {
	if err := validateCanonicalAuditText(r.ID, "record id", maximumAuditIDBytes); err != nil {
		return err
	}
	switch r.Action {
	case AuditActionSigningAuthorization, AuditActionSigningUse, AuditActionKeyAccess,
		AuditActionExportAuthorization, AuditActionPrivateExport, AuditActionAuthorityUnlock,
		AuditActionAuthorityLock, AuditActionIssuance, AuditActionCertificateRenew,
		AuditActionCertificateRotate, AuditActionCertificateRevoke, AuditActionCRLPublish, AuditActionAssignmentBind,
		AuditActionAssignmentStage, AuditActionAssignmentActivate, AuditActionAssignmentUnbind,
		AuditActionTrustSetCreate, AuditActionTrustSetStage, AuditActionTrustSetActivate,
		AuditActionAuthorityRollover, AuditActionConsumerAcknowledge,
		AuditActionCredentialStampPlan, AuditActionCredentialStampSucceed,
		AuditActionCredentialStampFail, AuditActionCredentialStampSupersede,
		AuditActionCredentialExecutionPlan, AuditActionCredentialExecutionSucceed,
		AuditActionCredentialExecutionFail:
	default:
		return fmt.Errorf("pki: unsupported audit action %q", r.Action)
	}
	switch r.Outcome {
	case AuditOutcomeAllowed, AuditOutcomeDenied, AuditOutcomeSucceeded, AuditOutcomeFailed, AuditOutcomeAttempted:
	default:
		return fmt.Errorf("pki: unsupported audit outcome %q", r.Outcome)
	}
	if err := (AuditContext{ActorID: r.ActorID, OperationID: r.OperationID, CorrelationID: r.CorrelationID}).Validate(); err != nil {
		return err
	}
	if err := validateCanonicalAuditText(r.ResourceType, "resource type", maximumAuditResourceBytes); err != nil {
		return err
	}
	if err := validateCanonicalAuditText(r.ResourceID, "resource id", maximumAuditResourceBytes); err != nil {
		return err
	}
	if r.CreatedAt.IsZero() {
		return errors.New("pki: audit creation time is required")
	}
	if len(r.Details) > maximumAuditDetailCount {
		return fmt.Errorf("pki: audit details exceed %d entries", maximumAuditDetailCount)
	}
	for key, value := range r.Details {
		if err := validateCanonicalAuditText(key, "detail key", maximumAuditDetailKeyBytes); err != nil {
			return err
		}
		if len(value) > maximumAuditDetailValueBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("pki: audit detail value is not canonical")
		}
	}
	return nil
}

func validateCanonicalAuditText(value, field string, maximumBytes int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("pki: audit %s is required", field)
	}
	if value != strings.TrimSpace(value) || len(value) > maximumBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("pki: audit %s is not canonical", field)
	}
	return nil
}

type AuditSink interface {
	AppendPKIAudit(context.Context, AuditRecord) error
}
