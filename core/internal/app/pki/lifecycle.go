package pki

import (
	"context"
	"errors"
	"fmt"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type RenewCertificateRequest struct {
	IdempotencyKey     string                         `json:"idempotencyKey"`
	SourceGenerationID domainpki.GenerationID         `json:"sourceGenerationId"`
	GenerationID       domainpki.GenerationID         `json:"generationId,omitempty"`
	Template           *domainpki.CertificateTemplate `json:"template,omitempty"`
}

type RotateCertificateRequest struct {
	IdempotencyKey     string                         `json:"idempotencyKey"`
	SourceGenerationID domainpki.GenerationID         `json:"sourceGenerationId"`
	GenerationID       domainpki.GenerationID         `json:"generationId,omitempty"`
	KeyID              domainpki.KeyID                `json:"keyId,omitempty"`
	BackendID          domainpki.BackendID            `json:"backendId,omitempty"`
	Template           *domainpki.CertificateTemplate `json:"template,omitempty"`
}

type CertificateLifecycleResult struct {
	Kind               IssuanceKind                    `json:"kind"`
	SourceGenerationID domainpki.GenerationID          `json:"sourceGenerationId"`
	Generation         domainpki.CertificateGeneration `json:"generation"`
	KeyReused          bool                            `json:"keyReused"`
}

func (r CertificateLifecycleResult) Validate() error {
	if r.Kind != IssuanceKindCertificateRenewal && r.Kind != IssuanceKindCertificateRotation {
		return fmt.Errorf("pki: unsupported certificate lifecycle result kind %q", r.Kind)
	}
	if err := r.SourceGenerationID.Validate(); err != nil {
		return err
	}
	if err := r.Generation.Validate(); err != nil {
		return err
	}
	if r.Generation.ID == r.SourceGenerationID {
		return errors.New("pki: lifecycle result must create a new certificate generation")
	}
	if r.KeyReused != (r.Kind == IssuanceKindCertificateRenewal) {
		return errors.New("pki: lifecycle result key reuse does not match its kind")
	}
	return nil
}

func (s Service) RenewCertificate(ctx context.Context, request RenewCertificateRequest) (CertificateLifecycleResult, error) {
	normalized, source, template, digest, err := s.prepareRenewal(ctx, request)
	if err != nil {
		return CertificateLifecycleResult{}, err
	}
	generation, err := s.issueCertificate(ctx, IssueCertificateRequest{
		IdempotencyKey: request.IdempotencyKey, CertificateID: source.CertificateID,
		GenerationID: normalized.GenerationID, KeyID: source.KeyID,
		IssuerAuthorityID: source.IssuerAuthorityID, Name: lifecycleCertificateName(source),
		ProfileID: source.ProfileID, BackendID: source.BackendID, Template: template,
	}, certificateIssuanceOptions{
		kind: IssuanceKindCertificateRenewal, reuseKey: true,
		sourceGenerationID: source.ID, sourceGeneration: &source, requestSHA256: digest,
	})
	if err != nil {
		return CertificateLifecycleResult{}, err
	}
	result := CertificateLifecycleResult{
		Kind: IssuanceKindCertificateRenewal, SourceGenerationID: source.ID,
		Generation: generation, KeyReused: true,
	}
	if err := result.Validate(); err != nil {
		return CertificateLifecycleResult{}, err
	}
	if err := validateLifecycleResultAgainstSource(result, source); err != nil {
		return CertificateLifecycleResult{}, err
	}
	return result, nil
}

func (s Service) RotateCertificate(ctx context.Context, request RotateCertificateRequest) (CertificateLifecycleResult, error) {
	normalized, source, template, digest, err := s.prepareRotation(ctx, request)
	if err != nil {
		return CertificateLifecycleResult{}, err
	}
	backendID := normalized.BackendID
	if backendID == "" {
		backendID = source.BackendID
	}
	generation, err := s.issueCertificate(ctx, IssueCertificateRequest{
		IdempotencyKey: request.IdempotencyKey, CertificateID: source.CertificateID,
		GenerationID: normalized.GenerationID, KeyID: normalized.KeyID,
		IssuerAuthorityID: source.IssuerAuthorityID, Name: lifecycleCertificateName(source),
		ProfileID: source.ProfileID, BackendID: backendID, Template: template,
	}, certificateIssuanceOptions{
		kind: IssuanceKindCertificateRotation, sourceGenerationID: source.ID,
		sourceGeneration: &source, requestSHA256: digest,
	})
	if err != nil {
		return CertificateLifecycleResult{}, err
	}
	result := CertificateLifecycleResult{
		Kind: IssuanceKindCertificateRotation, SourceGenerationID: source.ID,
		Generation: generation,
	}
	if err := result.Validate(); err != nil {
		return CertificateLifecycleResult{}, err
	}
	if err := validateLifecycleResultAgainstSource(result, source); err != nil {
		return CertificateLifecycleResult{}, err
	}
	return result, nil
}

func (s Service) prepareRenewal(ctx context.Context, request RenewCertificateRequest) (RenewCertificateRequest, domainpki.CertificateGeneration, *domainpki.CertificateTemplate, string, error) {
	if err := request.SourceGenerationID.Validate(); err != nil {
		return RenewCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	if request.GenerationID != "" {
		if err := request.GenerationID.Validate(); err != nil {
			return RenewCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
	}
	normalized := request
	normalized.IdempotencyKey = ""
	if normalized.Template != nil {
		clone := normalized.Template.Clone()
		if err := clone.Validate(); err != nil {
			return RenewCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
		normalized.Template = &clone
	}
	digest, err := requestDigest(normalized)
	if err != nil {
		return RenewCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	source, err := s.persistence.Generation(ctx, request.SourceGenerationID)
	if err != nil {
		return RenewCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	return normalized, source, normalized.Template, digest, nil
}

func (s Service) prepareRotation(ctx context.Context, request RotateCertificateRequest) (RotateCertificateRequest, domainpki.CertificateGeneration, *domainpki.CertificateTemplate, string, error) {
	if err := request.SourceGenerationID.Validate(); err != nil {
		return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	if request.GenerationID != "" {
		if err := request.GenerationID.Validate(); err != nil {
			return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
	}
	if request.KeyID != "" {
		if err := request.KeyID.Validate(); err != nil {
			return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
	}
	if request.BackendID != "" {
		if err := request.BackendID.Validate(); err != nil {
			return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
	}
	normalized := request
	normalized.IdempotencyKey = ""
	if normalized.Template != nil {
		clone := normalized.Template.Clone()
		if err := clone.Validate(); err != nil {
			return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
		}
		normalized.Template = &clone
	}
	digest, err := requestDigest(normalized)
	if err != nil {
		return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	source, err := s.persistence.Generation(ctx, request.SourceGenerationID)
	if err != nil {
		return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", err
	}
	if request.KeyID == source.KeyID {
		return RotateCertificateRequest{}, domainpki.CertificateGeneration{}, nil, "", errors.New("pki: rotation key id must differ from the source key")
	}
	return normalized, source, normalized.Template, digest, nil
}

func (s Service) lifecycleTemplate(source domainpki.CertificateGeneration, explicit *domainpki.CertificateTemplate, reuseKey bool) (domainpki.CertificateTemplate, error) {
	if explicit != nil {
		return explicit.Clone(), nil
	}
	profile, err := lifecycleProfile(source, source.BackendID, reuseKey)
	if err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	serial, err := s.newSerial()
	if err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	template := source.Template.Clone()
	template.SerialNumber = serial
	template.NotBefore = now.Add(-profile.Backdate)
	template.NotAfter = now.Add(profile.Validity)
	template.SubjectKeyIdentifier = domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic}
	template.AuthorityKeyIdentifier = domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic}
	if reuseKey {
		template.Key.Source = domainpki.KeySourceExisting
		template.Key.Existing = source.KeyID
	} else {
		template.Key.Source = domainpki.KeySourceGenerated
		template.Key.Existing = ""
	}
	if err := template.Validate(); err != nil {
		return domainpki.CertificateTemplate{}, err
	}
	return template, nil
}

// lifecycleProfile reconstructs the immutable issuance policy from the source
// generation instead of consulting a mutable built-in profile definition.
func lifecycleProfile(
	source domainpki.CertificateGeneration,
	backendID domainpki.BackendID,
	reuseKey bool,
) (domainpki.Profile, error) {
	if err := source.Validate(); err != nil {
		return domainpki.Profile{}, err
	}
	if backendID == "" {
		backendID = source.BackendID
	}
	if err := backendID.Validate(); err != nil {
		return domainpki.Profile{}, err
	}
	backdate := source.CreatedAt.Sub(source.Template.NotBefore)
	validity := source.Template.NotAfter.Sub(source.CreatedAt)
	if backdate < 0 || validity <= 0 {
		return domainpki.Profile{}, errors.New("pki: source certificate has an invalid issuance window")
	}
	key := source.Template.Key
	if reuseKey {
		key.Source = domainpki.KeySourceExisting
		key.Existing = source.KeyID
	} else {
		key.Source = domainpki.KeySourceGenerated
		key.Existing = ""
	}
	profile := domainpki.Profile{
		ID: source.ProfileID, Name: string(source.ProfileID),
		Purpose: source.Purpose, Key: key, Signature: source.Template.SignatureAlgorithm,
		Validity: validity, Backdate: backdate, BasicConstraints: source.Template.BasicConstraints,
		KeyUsage:         source.Template.KeyUsage,
		ExtendedKeyUsage: append([]domainpki.ExtendedKeyUsage(nil), source.Template.ExtendedKeyUsages...),
		ExportPolicy:     source.ExportPolicy, Backend: backendID,
		Compatibility: source.CompatibilityTargetID, KeyEstablishment: source.KeyEstablishment,
	}
	if err := profile.Validate(); err != nil {
		return domainpki.Profile{}, fmt.Errorf("pki: validate source lifecycle policy: %w", err)
	}
	return profile, nil
}

func validateLifecycleSource(source domainpki.CertificateGeneration, kind IssuanceKind, request IssueCertificateRequest) error {
	if err := validateLifecycleSourceBase(source, kind, request); err != nil {
		return err
	}
	switch kind {
	case IssuanceKindCertificateRenewal:
		if request.Template == nil || request.Template.Key.Source != domainpki.KeySourceExisting ||
			request.Template.Key.Existing != source.KeyID {
			return errors.New("pki: renewal must preserve the source key and backend")
		}
	case IssuanceKindCertificateRotation:
		if request.Template == nil || request.Template.Key.Source == domainpki.KeySourceExisting {
			return errors.New("pki: rotation must create a distinct key")
		}
	}
	return nil
}

func validateLifecycleSourceBase(source domainpki.CertificateGeneration, kind IssuanceKind, request IssueCertificateRequest) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := ValidateLifecycleSourceEligibility(source); err != nil {
		return err
	}
	if source.OwningAuthorityID != "" || source.Template.BasicConstraints.IsCA {
		return errors.New("pki: authority generations require the authority rollover workflow")
	}
	if source.CertificateID != request.CertificateID || source.IssuerAuthorityID != request.IssuerAuthorityID ||
		source.ProfileID != request.ProfileID {
		return errors.New("pki: lifecycle request does not preserve source certificate identity")
	}
	switch kind {
	case IssuanceKindCertificateRenewal:
		if request.KeyID != source.KeyID || request.BackendID != source.BackendID {
			return errors.New("pki: renewal must preserve the source key and backend")
		}
	case IssuanceKindCertificateRotation:
		if request.KeyID == source.KeyID {
			return errors.New("pki: rotation must create a distinct key")
		}
	default:
		return fmt.Errorf("pki: unsupported lifecycle issuance kind %q", kind)
	}
	return nil
}

func lifecycleCertificateName(source domainpki.CertificateGeneration) string {
	if source.Template.Subject.CommonName != "" {
		return source.Template.Subject.CommonName
	}
	return string(source.CertificateID)
}

func validateLifecycleResultAgainstSource(result CertificateLifecycleResult, source domainpki.CertificateGeneration) error {
	return ValidateLifecycleGenerationTransition(result.Kind, source, result.Generation)
}
