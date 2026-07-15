// Package pki defines Hovel's certificate, authority, assignment, bundle, and
// lifecycle value objects. It contains no storage, UI, RPC, or cryptographic
// implementation dependencies.
package pki

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type AuthorityID string
type CertificateID string
type GenerationID string
type ProfileID string
type AssignmentID string
type ConsumerID string
type TrustSetID string
type TrustSetGenerationID string
type RotationPolicyID string
type BackendID string
type CompatibilityTargetID string
type KeyID string
type BundleID string
type StampID string
type IssuanceID string
type MutationID string
type RevocationID string
type CRLPublicationID string
type OperationID string
type AcknowledgementID string
type CredentialSlotName string
type DeliveryProviderID string
type StampReferenceID string
type CredentialExecutionRequestID string

type CRLGenerationID string

func NewAuthorityID(value string) (AuthorityID, error) {
	return newID[AuthorityID](value, "authority")
}

func NewCertificateID(value string) (CertificateID, error) {
	return newID[CertificateID](value, "certificate")
}

func NewGenerationID(value string) (GenerationID, error) {
	return newID[GenerationID](value, "certificate generation")
}

func NewProfileID(value string) (ProfileID, error) {
	return newID[ProfileID](value, "profile")
}

func NewAssignmentID(value string) (AssignmentID, error) {
	return newID[AssignmentID](value, "assignment")
}

func NewConsumerID(value string) (ConsumerID, error) {
	return newID[ConsumerID](value, "assignment consumer")
}

func NewTrustSetID(value string) (TrustSetID, error) {
	return newID[TrustSetID](value, "trust set")
}

func NewTrustSetGenerationID(value string) (TrustSetGenerationID, error) {
	return newID[TrustSetGenerationID](value, "trust set generation")
}

func NewRotationPolicyID(value string) (RotationPolicyID, error) {
	return newID[RotationPolicyID](value, "rotation policy")
}

func NewBackendID(value string) (BackendID, error) {
	return newID[BackendID](value, "crypto backend")
}

func NewCompatibilityTargetID(value string) (CompatibilityTargetID, error) {
	return newID[CompatibilityTargetID](value, "compatibility target")
}

func NewKeyID(value string) (KeyID, error) {
	return newID[KeyID](value, "key")
}

func NewBundleID(value string) (BundleID, error) {
	return newID[BundleID](value, "bundle")
}

func NewStampID(value string) (StampID, error) {
	return newID[StampID](value, "credential stamp")
}

func NewIssuanceID(value string) (IssuanceID, error) {
	return newID[IssuanceID](value, "issuance")
}

func NewMutationID(value string) (MutationID, error) {
	return newID[MutationID](value, "mutation")
}

func NewRevocationID(value string) (RevocationID, error) {
	return newID[RevocationID](value, "revocation")
}

func NewCRLPublicationID(value string) (CRLPublicationID, error) {
	return newID[CRLPublicationID](value, "crl publication")
}

func NewCRLGenerationID(value string) (CRLGenerationID, error) {
	return newID[CRLGenerationID](value, "crl generation")
}

func NewOperationID(value string) (OperationID, error) {
	return newID[OperationID](value, "operation")
}

func NewAcknowledgementID(value string) (AcknowledgementID, error) {
	return newID[AcknowledgementID](value, "acknowledgement")
}

func NewCredentialSlotName(value string) (CredentialSlotName, error) {
	return newID[CredentialSlotName](value, "credential slot")
}

func NewDeliveryProviderID(value string) (DeliveryProviderID, error) {
	return newID[DeliveryProviderID](value, "credential delivery provider")
}

func NewStampReferenceID(value string) (StampReferenceID, error) {
	return newID[StampReferenceID](value, "credential stamp reference")
}

func NewCredentialExecutionRequestID(value string) (CredentialExecutionRequestID, error) {
	return newID[CredentialExecutionRequestID](value, "credential execution request")
}

func (id AuthorityID) Validate() error           { return validateID(id, "authority") }
func (id CertificateID) Validate() error         { return validateID(id, "certificate") }
func (id GenerationID) Validate() error          { return validateID(id, "certificate generation") }
func (id ProfileID) Validate() error             { return validateID(id, "profile") }
func (id AssignmentID) Validate() error          { return validateID(id, "assignment") }
func (id ConsumerID) Validate() error            { return validateID(id, "assignment consumer") }
func (id TrustSetID) Validate() error            { return validateID(id, "trust set") }
func (id TrustSetGenerationID) Validate() error  { return validateID(id, "trust set generation") }
func (id RotationPolicyID) Validate() error      { return validateID(id, "rotation policy") }
func (id BackendID) Validate() error             { return validateID(id, "crypto backend") }
func (id CompatibilityTargetID) Validate() error { return validateID(id, "compatibility target") }
func (id KeyID) Validate() error                 { return validateID(id, "key") }
func (id BundleID) Validate() error              { return validateID(id, "bundle") }
func (id StampID) Validate() error               { return validateID(id, "credential stamp") }
func (id IssuanceID) Validate() error            { return validateID(id, "issuance") }
func (id MutationID) Validate() error            { return validateID(id, "mutation") }
func (id RevocationID) Validate() error          { return validateID(id, "revocation") }
func (id CRLPublicationID) Validate() error      { return validateID(id, "crl publication") }
func (id CRLGenerationID) Validate() error       { return validateID(id, "crl generation") }
func (id OperationID) Validate() error           { return validateID(id, "operation") }
func (id AcknowledgementID) Validate() error     { return validateID(id, "acknowledgement") }
func (id CredentialSlotName) Validate() error    { return validateID(id, "credential slot") }
func (id DeliveryProviderID) Validate() error    { return validateID(id, "credential delivery provider") }
func (id StampReferenceID) Validate() error      { return validateID(id, "credential stamp reference") }
func (id CredentialExecutionRequestID) Validate() error {
	return validateID(id, "credential execution request")
}

func validateID[T ~string](value T, field string) error {
	normalized, err := newID[T](string(value), field)
	if err != nil {
		return err
	}
	if normalized != value {
		return fmt.Errorf("pki: %s id is not canonical", field)
	}
	return nil
}

func newID[T ~string](value, field string) (T, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("pki: %s id is required", field)
	}
	if len(value) > MaxIDLength {
		return "", fmt.Errorf("pki: %s id exceeds %d bytes", field, MaxIDLength)
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/", r) {
			continue
		}
		return "", fmt.Errorf("pki: %s id contains invalid characters", field)
	}
	return T(value), nil
}

func validateName(value, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("pki: %s is required", field)
	}
	if len(value) > MaxNameLength {
		return "", fmt.Errorf("pki: %s exceeds %d bytes", field, MaxNameLength)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("pki: %s contains control characters", field)
		}
	}
	return value, nil
}

func validateSchemaVersion(value, expected string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("pki: schema version is required")
	}
	if value != expected {
		return fmt.Errorf("pki: unsupported schema version %q", value)
	}
	return nil
}

const (
	MaxIDLength   = 256
	MaxNameLength = 512
)
