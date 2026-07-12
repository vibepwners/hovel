package pki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	MaximumIdempotencyKeyBytes  = 256
	MaximumIssuanceFailureBytes = 1024
	MaximumIssuanceOwnerBytes   = 256
	DefaultIssuanceLease        = 15 * time.Minute
	MaximumPendingIssuanceBatch = 100
	issuanceRequestDigestBytes  = sha256.Size
)

type IssuanceKind string

const (
	IssuanceKindAuthority           IssuanceKind = "authority"
	IssuanceKindCertificate         IssuanceKind = "certificate"
	IssuanceKindCertificateRenewal  IssuanceKind = "certificate-renewal"
	IssuanceKindCertificateRotation IssuanceKind = "certificate-rotation"
)

func (k IssuanceKind) Validate() error {
	switch k {
	case IssuanceKindAuthority, IssuanceKindCertificate, IssuanceKindCertificateRenewal,
		IssuanceKindCertificateRotation:
		return nil
	default:
		return fmt.Errorf("pki: unsupported issuance kind %q", k)
	}
}

// IssuanceCompletionAudits is the atomic audit contract committed with a
// successful issuance result. Every issuance records signing use; lifecycle
// issuance additionally records its strongly typed renewal or rotation event.
type IssuanceCompletionAudits struct {
	SigningUse AuditRecord
	Lifecycle  *AuditRecord
}

// Validate verifies that the audit set exactly matches the issuance kind and
// identifies the generation committed with it.
func (a IssuanceCompletionAudits) Validate(kind IssuanceKind, generationID, sourceGenerationID domainpki.GenerationID, signingAuthorityID domainpki.AuthorityID) error {
	if err := kind.Validate(); err != nil {
		return err
	}
	if err := generationID.Validate(); err != nil {
		return err
	}
	if err := signingAuthorityID.Validate(); err != nil {
		return err
	}
	if err := a.SigningUse.Validate(); err != nil {
		return err
	}
	if a.SigningUse.Action != AuditActionSigningUse || a.SigningUse.Outcome != AuditOutcomeSucceeded {
		return errors.New("pki: issuance completion requires a successful signing-use audit")
	}
	if a.SigningUse.ResourceType != auditResourceAuthority || a.SigningUse.ResourceID != string(signingAuthorityID) {
		return errors.New("pki: signing-use audit must identify an authority")
	}
	if a.SigningUse.Details[auditDetailGenerationID] != string(generationID) ||
		a.SigningUse.Details[auditDetailIssuanceKind] != string(kind) {
		return errors.New("pki: signing-use audit does not identify the issuance result")
	}
	expectedLifecycleAction := AuditAction("")
	switch kind {
	case IssuanceKindAuthority, IssuanceKindCertificate:
		if sourceGenerationID != "" {
			return errors.New("pki: ordinary issuance cannot identify a lifecycle source")
		}
		if _, exists := a.SigningUse.Details[auditDetailSourceGenerationID]; exists {
			return errors.New("pki: ordinary issuance signing audit cannot identify a lifecycle source")
		}
		if len(a.SigningUse.Details) != 2 {
			return errors.New("pki: ordinary issuance signing audit has unexpected details")
		}
		if a.Lifecycle != nil {
			return errors.New("pki: ordinary issuance cannot include a lifecycle audit")
		}
		return nil
	case IssuanceKindCertificateRenewal:
		expectedLifecycleAction = AuditActionCertificateRenew
	case IssuanceKindCertificateRotation:
		expectedLifecycleAction = AuditActionCertificateRotate
	}
	if err := sourceGenerationID.Validate(); err != nil {
		return err
	}
	if a.Lifecycle == nil {
		return errors.New("pki: lifecycle issuance requires a lifecycle audit")
	}
	if a.SigningUse.ID == a.Lifecycle.ID {
		return errors.New("pki: issuance completion audit ids must be distinct")
	}
	if err := a.Lifecycle.Validate(); err != nil {
		return err
	}
	if a.Lifecycle.Action != expectedLifecycleAction || a.Lifecycle.Outcome != AuditOutcomeSucceeded {
		return errors.New("pki: lifecycle audit does not match the issuance kind")
	}
	if a.Lifecycle.ResourceType != auditResourceGeneration || a.Lifecycle.ResourceID != string(generationID) {
		return errors.New("pki: lifecycle audit does not identify the issued generation")
	}
	if a.Lifecycle.Details[auditDetailSourceGenerationID] != string(sourceGenerationID) ||
		a.SigningUse.Details[auditDetailSourceGenerationID] != string(sourceGenerationID) {
		return errors.New("pki: issuance completion audits do not identify the lifecycle source")
	}
	if len(a.SigningUse.Details) != 3 || len(a.Lifecycle.Details) != 1 {
		return errors.New("pki: lifecycle issuance audits have unexpected details")
	}
	if a.SigningUse.ActorID != a.Lifecycle.ActorID ||
		a.SigningUse.OperationID != a.Lifecycle.OperationID ||
		a.SigningUse.CorrelationID != a.Lifecycle.CorrelationID {
		return errors.New("pki: issuance completion audits do not share an audit context")
	}
	return nil
}

// Records returns defensive copies in durable append order.
func (a IssuanceCompletionAudits) Records() []AuditRecord {
	records := []AuditRecord{a.SigningUse.Clone()}
	if a.Lifecycle != nil {
		records = append(records, a.Lifecycle.Clone())
	}
	return records
}

// CompletedAt returns the signing-use timestamp used to close the issuance
// intent.
func (a IssuanceCompletionAudits) CompletedAt() time.Time {
	return a.SigningUse.CreatedAt
}

type IssuanceStatus string

const (
	IssuanceStatusPending   IssuanceStatus = "pending"
	IssuanceStatusCompleted IssuanceStatus = "completed"
	IssuanceStatusFailed    IssuanceStatus = "failed"
)

func (s IssuanceStatus) Validate() error {
	switch s {
	case IssuanceStatusPending, IssuanceStatusCompleted, IssuanceStatusFailed:
		return nil
	default:
		return fmt.Errorf("pki: unsupported issuance status %q", s)
	}
}

// AuthorityIssuancePlan is the immutable authority aggregate projection that
// must be committed with an authority certificate issuance. SignerMode is
// intentionally derived from the validated key material at completion.
type AuthorityIssuancePlan struct {
	Name              string                   `json:"name"`
	Role              domainpki.AuthorityRole  `json:"role"`
	Origin            domainpki.Origin         `json:"origin"`
	ParentAuthorityID domainpki.AuthorityID    `json:"parentAuthorityId,omitempty"`
	State             domainpki.AuthorityState `json:"state"`
	ProfileID         domainpki.ProfileID      `json:"profileId"`
	SignerRef         string                   `json:"signerRef"`
	ExportPolicy      domainpki.ExportPolicy   `json:"exportPolicy"`
	CreatedAt         time.Time                `json:"createdAt"`
	Labels            map[string]string        `json:"labels,omitempty"`
}

func (p AuthorityIssuancePlan) Clone() AuthorityIssuancePlan {
	result := p
	if p.Labels != nil {
		result.Labels = make(map[string]string, len(p.Labels))
		for key, value := range p.Labels {
			result.Labels[key] = value
		}
	}
	return result
}

// IssuanceIntent is the durable, idempotent plan persisted before a backend is
// allowed to create a key or sign a certificate. Generation is assigned by
// Persistence.BeginIssuance when the caller leaves it zero.
type IssuanceIntent struct {
	ID                    domainpki.IssuanceID             `json:"id"`
	IdempotencyKey        string                           `json:"idempotencyKey"`
	RequestSHA256         string                           `json:"requestSha256"`
	Kind                  IssuanceKind                     `json:"kind"`
	AuthorityID           domainpki.AuthorityID            `json:"authorityId,omitempty"`
	CertificateID         domainpki.CertificateID          `json:"certificateId"`
	GenerationID          domainpki.GenerationID           `json:"generationId"`
	SourceGenerationID    domainpki.GenerationID           `json:"sourceGenerationId,omitempty"`
	Generation            uint64                           `json:"generation"`
	KeyID                 domainpki.KeyID                  `json:"keyId"`
	IssuerAuthorityID     domainpki.AuthorityID            `json:"issuerAuthorityId,omitempty"`
	IssuerGenerationID    domainpki.GenerationID           `json:"issuerGenerationId,omitempty"`
	SubjectBackendID      domainpki.BackendID              `json:"subjectBackendId"`
	SubjectBackendVersion string                           `json:"subjectBackendVersion"`
	SubjectPackageDigest  string                           `json:"subjectBackendPackageDigest,omitempty"`
	SubjectCapabilityHash string                           `json:"subjectCapabilityHash"`
	SigningBackendID      domainpki.BackendID              `json:"signingBackendId"`
	SigningBackendVersion string                           `json:"signingBackendVersion"`
	SigningPackageDigest  string                           `json:"signingBackendPackageDigest,omitempty"`
	SigningCapabilityHash string                           `json:"signingCapabilityHash"`
	ProfileID             domainpki.ProfileID              `json:"profileId"`
	CompatibilityTargetID domainpki.CompatibilityTargetID  `json:"compatibilityTargetId"`
	CompatibilityVersion  string                           `json:"compatibilityVersion"`
	Purpose               domainpki.Purpose                `json:"purpose"`
	ExportPolicy          domainpki.ExportPolicy           `json:"exportPolicy"`
	KeyEstablishment      domainpki.KeyEstablishmentPolicy `json:"keyEstablishmentPolicy"`
	TLSNamedGroups        []domainpki.TLSNamedGroup        `json:"tlsNamedGroups,omitempty"`
	ChainGenerationIDs    []domainpki.GenerationID         `json:"chainGenerationIds,omitempty"`
	AuthorityPlan         *AuthorityIssuancePlan           `json:"authorityPlan,omitempty"`
	Template              domainpki.CertificateTemplate    `json:"template"`
	Status                IssuanceStatus                   `json:"status"`
	OwnerToken            string                           `json:"ownerToken"`
	Revision              uint64                           `json:"revision"`
	LeaseExpiresAt        time.Time                        `json:"leaseExpiresAt"`
	ResultGenerationID    domainpki.GenerationID           `json:"resultGenerationId,omitempty"`
	Failure               string                           `json:"failure,omitempty"`
	CreatedAt             time.Time                        `json:"createdAt"`
	UpdatedAt             time.Time                        `json:"updatedAt"`
}

type IssuanceOwnership struct {
	OwnerToken string `json:"ownerToken"`
	Revision   uint64 `json:"revision"`
}

func (i IssuanceIntent) Ownership() IssuanceOwnership {
	return IssuanceOwnership{OwnerToken: i.OwnerToken, Revision: i.Revision}
}

// SigningAuthorityID returns the authority whose key signs this intent. A
// self-signed root uses its newly created authority; every other intent uses
// its persisted issuer authority.
func (i IssuanceIntent) SigningAuthorityID() domainpki.AuthorityID {
	if i.IssuerAuthorityID != "" {
		return i.IssuerAuthorityID
	}
	return i.AuthorityID
}

func (i IssuanceIntent) Clone() IssuanceIntent {
	result := i
	result.Template = i.Template.Clone()
	result.TLSNamedGroups = append([]domainpki.TLSNamedGroup(nil), i.TLSNamedGroups...)
	result.ChainGenerationIDs = append([]domainpki.GenerationID(nil), i.ChainGenerationIDs...)
	if i.AuthorityPlan != nil {
		plan := i.AuthorityPlan.Clone()
		result.AuthorityPlan = &plan
	}
	return result
}

func (i IssuanceIntent) Validate() error {
	if err := i.ID.Validate(); err != nil {
		return err
	}
	if err := validateIdempotencyKey(i.IdempotencyKey); err != nil {
		return err
	}
	digest, err := hex.DecodeString(i.RequestSHA256)
	if err != nil || len(digest) != issuanceRequestDigestBytes || i.RequestSHA256 != strings.ToLower(i.RequestSHA256) {
		return errors.New("pki: issuance request digest must be canonical sha256")
	}
	if err := i.Kind.Validate(); err != nil {
		return err
	}
	if i.AuthorityID != "" {
		if err := i.AuthorityID.Validate(); err != nil {
			return err
		}
	}
	if i.Kind == IssuanceKindAuthority && i.AuthorityID == "" {
		return errors.New("pki: authority issuance requires an authority id")
	}
	if i.Kind != IssuanceKindAuthority && i.AuthorityID != "" {
		return errors.New("pki: certificate issuance cannot own an authority")
	}
	if err := i.CertificateID.Validate(); err != nil {
		return err
	}
	if err := i.GenerationID.Validate(); err != nil {
		return err
	}
	isLifecycle := i.Kind == IssuanceKindCertificateRenewal || i.Kind == IssuanceKindCertificateRotation
	if isLifecycle {
		if err := i.SourceGenerationID.Validate(); err != nil {
			return err
		}
		if i.SourceGenerationID == i.GenerationID {
			return errors.New("pki: lifecycle source and result generations must differ")
		}
	} else if i.SourceGenerationID != "" {
		return errors.New("pki: ordinary issuance cannot identify a lifecycle source")
	}
	if i.Generation == 0 || i.Generation > domainpki.MaximumSequenceNumber {
		return errors.New("pki: issuance generation is outside the supported range")
	}
	if err := i.KeyID.Validate(); err != nil {
		return err
	}
	if i.IssuerAuthorityID != "" {
		if err := i.IssuerAuthorityID.Validate(); err != nil {
			return err
		}
	}
	if (i.IssuerAuthorityID == "") != (i.IssuerGenerationID == "") {
		return errors.New("pki: issuance issuer authority and generation must be specified together")
	}
	if i.IssuerGenerationID != "" {
		if err := i.IssuerGenerationID.Validate(); err != nil {
			return err
		}
	}
	if err := i.SubjectBackendID.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(i.SubjectBackendVersion) == "" || strings.TrimSpace(i.SubjectCapabilityHash) == "" {
		return errors.New("pki: issuance subject backend commitment is required")
	}
	if err := i.SigningBackendID.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(i.SigningBackendVersion) == "" || strings.TrimSpace(i.SigningCapabilityHash) == "" {
		return errors.New("pki: issuance signing backend commitment is required")
	}
	if err := i.ProfileID.Validate(); err != nil {
		return err
	}
	if err := i.CompatibilityTargetID.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(i.CompatibilityVersion) == "" {
		return errors.New("pki: issuance compatibility version is required")
	}
	if err := i.Purpose.Validate(); err != nil {
		return err
	}
	if err := i.ExportPolicy.Validate(); err != nil {
		return err
	}
	if err := domainpki.ValidateKeyEstablishment(i.KeyEstablishment, i.TLSNamedGroups); err != nil {
		return err
	}
	for _, id := range i.ChainGenerationIDs {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if i.Kind == IssuanceKindAuthority {
		if i.AuthorityPlan == nil {
			return errors.New("pki: authority issuance requires a durable authority plan")
		}
		if _, err := plannedAuthority(i, domainpki.SignerModeLocal); err != nil {
			return fmt.Errorf("pki: validate authority issuance plan: %w", err)
		}
	} else if i.AuthorityPlan != nil {
		return errors.New("pki: certificate issuance cannot include an authority plan")
	}
	if err := i.Template.Validate(); err != nil {
		return fmt.Errorf("pki: validate issuance template: %w", err)
	}
	if err := i.Status.Validate(); err != nil {
		return err
	}
	if !validIssuanceOwner(i.OwnerToken) || i.Revision == 0 || i.Revision > domainpki.MaximumSequenceNumber {
		return errors.New("pki: issuance ownership is invalid")
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() || i.UpdatedAt.Before(i.CreatedAt) {
		return errors.New("pki: issuance timestamps are invalid")
	}
	if i.LeaseExpiresAt.IsZero() || i.Status == IssuanceStatusPending && !i.LeaseExpiresAt.After(i.UpdatedAt) {
		return errors.New("pki: issuance ownership lease is invalid")
	}
	switch i.Status {
	case IssuanceStatusPending:
		if i.ResultGenerationID != "" || i.Failure != "" {
			return errors.New("pki: pending issuance cannot have a result or failure")
		}
	case IssuanceStatusCompleted:
		if i.ResultGenerationID != i.GenerationID || i.Failure != "" {
			return errors.New("pki: completed issuance result does not match its plan")
		}
	case IssuanceStatusFailed:
		if i.ResultGenerationID != "" || !validIssuanceFailure(i.Failure) {
			return errors.New("pki: failed issuance requires a canonical failure")
		}
	}
	return nil
}

func plannedAuthority(intent IssuanceIntent, signerMode domainpki.SignerMode) (domainpki.Authority, error) {
	if intent.AuthorityPlan == nil {
		return domainpki.Authority{}, errors.New("pki: authority issuance plan is required")
	}
	plan := intent.AuthorityPlan
	if plan.ParentAuthorityID != intent.IssuerAuthorityID || plan.ProfileID != intent.ProfileID ||
		plan.ExportPolicy != intent.ExportPolicy || plan.SignerRef != string(intent.KeyID) ||
		!plan.CreatedAt.Equal(intent.CreatedAt) || plan.Origin != domainpki.OriginGenerated ||
		plan.State != initialAuthorityState(plan.Role) {
		return domainpki.Authority{}, errors.New("pki: authority issuance plan does not match its durable intent")
	}
	return domainpki.NewAuthority(domainpki.AuthorityArgs{
		ID: intent.AuthorityID, Name: plan.Name, Role: plan.Role, Origin: plan.Origin,
		SignerMode: signerMode, ParentAuthorityID: plan.ParentAuthorityID, State: plan.State,
		ActiveGenerationID: intent.GenerationID, ProfileID: plan.ProfileID, SignerRef: plan.SignerRef,
		ExportPolicy: plan.ExportPolicy, CreatedAt: plan.CreatedAt, UpdatedAt: plan.CreatedAt, Labels: plan.Labels,
	})
}

// ValidateAuthorityIssuanceCompletion binds the complete authority aggregate
// to its durable plan and derives the only dynamic field, signer mode, from
// the validated key material.
func ValidateAuthorityIssuanceCompletion(
	intent IssuanceIntent,
	authority domainpki.Authority,
	generation domainpki.CertificateGeneration,
	material KeyMaterial,
) error {
	if intent.Kind != IssuanceKindAuthority {
		return errors.New("pki: authority completion requires an authority issuance intent")
	}
	if err := ValidateIssuanceCompletion(intent, generation); err != nil {
		return err
	}
	if err := ValidateGenerationKeyBinding(generation, material); err != nil {
		return err
	}
	signerMode := domainpki.SignerModeLocal
	if material.ExternalHandle != nil {
		signerMode = domainpki.SignerModeExternal
	}
	expected, err := plannedAuthority(intent, signerMode)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(authority, expected) {
		return errors.New("pki: authority aggregate does not match its durable issuance plan")
	}
	return nil
}

func ValidateNewIssuanceIntent(intent IssuanceIntent) error {
	if intent.Status != IssuanceStatusPending || intent.ResultGenerationID != "" || intent.Failure != "" || intent.Revision != 1 {
		return errors.New("pki: new issuance intent must be pending")
	}
	validated := intent.Clone()
	if validated.Generation == 0 {
		validated.Generation = 1
	}
	return validated.Validate()
}

func ValidateIssuanceOwnership(intent IssuanceIntent, ownerToken string, revision uint64) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Status != IssuanceStatusPending || intent.OwnerToken != ownerToken || intent.Revision != revision {
		return errors.New("pki: issuance ownership changed")
	}
	return nil
}

func ClaimIssuanceIntent(intent IssuanceIntent, ownerToken string, claimedAt time.Time) (IssuanceIntent, error) {
	if intent.Status != IssuanceStatusPending || claimedAt.UTC().Before(intent.LeaseExpiresAt) {
		return IssuanceIntent{}, errors.New("pki: issuance is not eligible for stale reconciliation")
	}
	if !validIssuanceOwner(ownerToken) {
		return IssuanceIntent{}, errors.New("pki: reconciliation owner token is invalid")
	}
	if intent.Revision >= domainpki.MaximumSequenceNumber {
		return IssuanceIntent{}, errors.New("pki: issuance revision is exhausted")
	}
	result := intent.Clone()
	result.OwnerToken = ownerToken
	result.Revision++
	result.UpdatedAt = claimedAt.UTC()
	result.LeaseExpiresAt = result.UpdatedAt.Add(DefaultIssuanceLease)
	if err := result.Validate(); err != nil {
		return IssuanceIntent{}, err
	}
	return result, nil
}

func ValidateIssuanceCompletion(intent IssuanceIntent, generation domainpki.CertificateGeneration) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Status != IssuanceStatusPending {
		return errors.New("pki: only pending issuance can be completed")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if intent.CertificateID != generation.CertificateID || intent.GenerationID != generation.ID ||
		intent.Generation != generation.Generation || intent.KeyID != generation.KeyID ||
		intent.IssuerAuthorityID != generation.IssuerAuthorityID || intent.ProfileID != generation.ProfileID ||
		intent.CompatibilityTargetID != generation.CompatibilityTargetID ||
		intent.CompatibilityVersion != generation.CompatibilityVersion || intent.Purpose != generation.Purpose ||
		intent.ExportPolicy != generation.ExportPolicy || intent.KeyEstablishment != generation.KeyEstablishment ||
		!slices.Equal(intent.TLSNamedGroups, generation.TLSNamedGroups) ||
		!slices.Equal(intent.ChainGenerationIDs, generation.ChainGenerationIDs) {
		return errors.New("pki: issuance result does not match its durable plan")
	}
	if generation.State != domainpki.CertificateStateActive {
		return errors.New("pki: issued certificate generation must be active")
	}
	if intent.Kind == IssuanceKindAuthority {
		if generation.OwningAuthorityID != intent.AuthorityID {
			return errors.New("pki: authority issuance result does not match its durable owner")
		}
	} else if generation.OwningAuthorityID != "" {
		return errors.New("pki: leaf issuance result cannot own an authority")
	}
	if intent.IssuerGenerationID != generation.IssuerGenerationID {
		return errors.New("pki: issuance result changed its issuer generation")
	}
	if intent.SubjectBackendID != generation.BackendID || intent.SubjectBackendVersion != generation.BackendVersion ||
		intent.SubjectPackageDigest != generation.BackendPackageDigest || intent.SubjectCapabilityHash != generation.BackendCapabilityHash ||
		intent.SigningBackendID != generation.SigningBackendID || intent.SigningBackendVersion != generation.SigningBackendVersion ||
		intent.SigningPackageDigest != generation.SigningBackendPackageDigest || intent.SigningCapabilityHash != generation.SigningBackendCapabilityHash {
		return errors.New("pki: issuance result changed its backend provenance commitments")
	}
	planned := intent.Template.Clone()
	if planned.SignatureAlgorithm == domainpki.SignatureAlgorithmAuto {
		if generation.Template.SignatureAlgorithm == domainpki.SignatureAlgorithmAuto {
			return errors.New("pki: issued signature algorithm was not resolved")
		}
		planned.SignatureAlgorithm = generation.Template.SignatureAlgorithm
	}
	plannedTemplate, err := json.Marshal(planned)
	if err != nil {
		return fmt.Errorf("pki: encode planned issuance template: %w", err)
	}
	resultTemplate, err := json.Marshal(generation.Template)
	if err != nil {
		return fmt.Errorf("pki: encode issued certificate template: %w", err)
	}
	if !bytes.Equal(plannedTemplate, resultTemplate) {
		return errors.New("pki: issued certificate template does not match its durable plan")
	}
	return nil
}

// ValidateLifecycleSourceEligibility verifies mutable source state at the
// first atomic lifecycle commit. Replay validation deliberately does not call
// this function because a completed result remains replayable after its source
// is superseded, expired, or revoked.
func ValidateLifecycleSourceEligibility(source domainpki.CertificateGeneration) error {
	if source.State != domainpki.CertificateStateActive {
		return fmt.Errorf("pki: source certificate generation %q cannot be changed while %s", source.ID, source.State)
	}
	return nil
}

// ValidateLifecycleGenerationTransition verifies the immutable lineage and
// key transition before a renewal or rotation result can be committed.
func ValidateLifecycleGenerationTransition(kind IssuanceKind, source, generation domainpki.CertificateGeneration) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if generation.CertificateID != source.CertificateID ||
		generation.OwningAuthorityID != source.OwningAuthorityID ||
		generation.IssuerAuthorityID != source.IssuerAuthorityID ||
		generation.ProfileID != source.ProfileID ||
		generation.Purpose != source.Purpose ||
		generation.CompatibilityTargetID != source.CompatibilityTargetID ||
		generation.CompatibilityVersion != source.CompatibilityVersion ||
		generation.ExportPolicy != source.ExportPolicy ||
		generation.KeyEstablishment != source.KeyEstablishment ||
		!slices.Equal(generation.TLSNamedGroups, source.TLSNamedGroups) ||
		generation.State != domainpki.CertificateStateActive ||
		generation.Generation <= source.Generation {
		return errors.New("pki: lifecycle result does not preserve the source certificate lineage")
	}
	samePublicKey := bytes.Equal(generation.PublicKeySPKI, source.PublicKeySPKI)
	switch kind {
	case IssuanceKindCertificateRenewal:
		if generation.KeyID != source.KeyID || generation.BackendID != source.BackendID || !samePublicKey {
			return errors.New("pki: renewal did not preserve the source key")
		}
	case IssuanceKindCertificateRotation:
		if generation.KeyID == source.KeyID || samePublicKey {
			return errors.New("pki: rotation did not create a distinct key")
		}
	default:
		return fmt.Errorf("pki: unsupported certificate lifecycle result kind %q", kind)
	}
	return nil
}

func CompleteIssuanceIntent(intent IssuanceIntent, updatedAt time.Time) (IssuanceIntent, error) {
	if intent.Status != IssuanceStatusPending {
		return IssuanceIntent{}, errors.New("pki: only pending issuance can be completed")
	}
	result := intent.Clone()
	result.Status = IssuanceStatusCompleted
	result.ResultGenerationID = result.GenerationID
	result.UpdatedAt = updatedAt.UTC()
	if err := result.Validate(); err != nil {
		return IssuanceIntent{}, err
	}
	return result, nil
}

func FailIssuanceIntent(intent IssuanceIntent, failure string, updatedAt time.Time) (IssuanceIntent, error) {
	if intent.Status != IssuanceStatusPending {
		return IssuanceIntent{}, errors.New("pki: only pending issuance can fail")
	}
	result := intent.Clone()
	result.Status = IssuanceStatusFailed
	result.Failure = strings.TrimSpace(failure)
	result.UpdatedAt = updatedAt.UTC()
	if err := result.Validate(); err != nil {
		return IssuanceIntent{}, err
	}
	return result, nil
}

func validateIdempotencyKey(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > MaximumIdempotencyKeyBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("pki: idempotency key is not canonical")
	}
	return nil
}

func validIssuanceFailure(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= MaximumIssuanceFailureBytes && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validIssuanceOwner(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= MaximumIssuanceOwnerBytes && strings.IndexFunc(value, unicode.IsControl) < 0
}

func issuanceRequestDigest(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
