package pki

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type AuthorityArgs struct {
	ID                 AuthorityID
	Name               string
	Role               AuthorityRole
	Origin             Origin
	SignerMode         SignerMode
	ParentAuthorityID  AuthorityID
	State              AuthorityState
	ActiveGenerationID GenerationID
	ProfileID          ProfileID
	SignerRef          string
	ExportPolicy       ExportPolicy
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Labels             map[string]string
}

type Authority struct {
	ID                 AuthorityID       `json:"id"`
	Name               string            `json:"name"`
	Role               AuthorityRole     `json:"role"`
	Origin             Origin            `json:"origin"`
	SignerMode         SignerMode        `json:"signerMode"`
	ParentAuthorityID  AuthorityID       `json:"parentAuthorityId,omitempty"`
	State              AuthorityState    `json:"state"`
	ActiveGenerationID GenerationID      `json:"activeGenerationId,omitempty"`
	ProfileID          ProfileID         `json:"profileId"`
	SignerRef          string            `json:"signerRef,omitempty"`
	ExportPolicy       ExportPolicy      `json:"exportPolicy"`
	CreatedAt          time.Time         `json:"createdAt"`
	UpdatedAt          time.Time         `json:"updatedAt"`
	Labels             map[string]string `json:"labels,omitempty"`
}

func (a Authority) Clone() Authority {
	result := a
	result.Labels = cloneStringMap(a.Labels)
	return result
}

func (a Authority) Validate() error {
	_, err := NewAuthority(AuthorityArgs(a))
	return err
}

func NewAuthority(args AuthorityArgs) (Authority, error) {
	if err := args.ID.Validate(); err != nil {
		return Authority{}, err
	}
	name, err := validateName(args.Name, "authority name")
	if err != nil {
		return Authority{}, err
	}
	if err := args.Role.Validate(); err != nil {
		return Authority{}, err
	}
	if err := args.Origin.Validate(); err != nil {
		return Authority{}, err
	}
	if err := args.SignerMode.Validate(); err != nil {
		return Authority{}, err
	}
	signerRef := strings.TrimSpace(args.SignerRef)
	if args.SignerMode == SignerModeNone && signerRef != "" {
		return Authority{}, errors.New("pki: authority without a signer cannot retain a signer reference")
	}
	if args.SignerMode != SignerModeNone && signerRef == "" {
		return Authority{}, errors.New("pki: local and external authority signers require a signer reference")
	}
	if err := args.State.Validate(); err != nil {
		return Authority{}, err
	}
	if err := args.ExportPolicy.Validate(); err != nil {
		return Authority{}, err
	}
	if args.Role == AuthorityRoleRoot && args.ParentAuthorityID != "" {
		return Authority{}, errors.New("pki: root authority cannot have a parent")
	}
	if args.Role == AuthorityRoleSubordinate && args.ParentAuthorityID == "" {
		return Authority{}, errors.New("pki: subordinate authority requires a parent")
	}
	if args.ParentAuthorityID != "" {
		if err := args.ParentAuthorityID.Validate(); err != nil {
			return Authority{}, err
		}
	}
	if args.ActiveGenerationID != "" {
		if err := args.ActiveGenerationID.Validate(); err != nil {
			return Authority{}, err
		}
	}
	if err := args.ProfileID.Validate(); err != nil {
		return Authority{}, err
	}
	if args.CreatedAt.IsZero() {
		return Authority{}, errors.New("pki: authority creation time is required")
	}
	if args.UpdatedAt.IsZero() {
		args.UpdatedAt = args.CreatedAt
	}
	if args.UpdatedAt.Before(args.CreatedAt) {
		return Authority{}, errors.New("pki: authority update time precedes creation time")
	}
	return Authority{
		ID:                 args.ID,
		Name:               name,
		Role:               args.Role,
		Origin:             args.Origin,
		SignerMode:         args.SignerMode,
		ParentAuthorityID:  args.ParentAuthorityID,
		State:              args.State,
		ActiveGenerationID: args.ActiveGenerationID,
		ProfileID:          args.ProfileID,
		SignerRef:          signerRef,
		ExportPolicy:       args.ExportPolicy,
		CreatedAt:          args.CreatedAt.UTC(),
		UpdatedAt:          args.UpdatedAt.UTC(),
		Labels:             cloneStringMap(args.Labels),
	}, nil
}

type GenerationArgs struct {
	CertificateID                CertificateID
	ID                           GenerationID
	Generation                   uint64
	OwningAuthorityID            AuthorityID
	IssuerAuthorityID            AuthorityID
	IssuerGenerationID           GenerationID
	ProfileID                    ProfileID
	Template                     CertificateTemplate
	BackendID                    BackendID
	BackendVersion               string
	BackendPackageDigest         string
	BackendCapabilityHash        string
	SigningBackendID             BackendID
	SigningBackendVersion        string
	SigningBackendPackageDigest  string
	SigningBackendCapabilityHash string
	CompatibilityTargetID        CompatibilityTargetID
	CompatibilityVersion         string
	Purpose                      Purpose
	ExportPolicy                 ExportPolicy
	KeyEstablishment             KeyEstablishmentPolicy
	TLSNamedGroups               []TLSNamedGroup
	FingerprintSHA256            string
	SubjectKeyID                 []byte
	AuthorityKeyID               []byte
	State                        CertificateState
	KeyID                        KeyID
	CertificateDER               []byte
	PublicKeySPKI                []byte
	ChainGenerationIDs           []GenerationID
	CreatedAt                    time.Time
}

type CertificateGeneration struct {
	CertificateID                CertificateID          `json:"certificateId"`
	ID                           GenerationID           `json:"id"`
	Generation                   uint64                 `json:"generation"`
	OwningAuthorityID            AuthorityID            `json:"owningAuthorityId,omitempty"`
	IssuerAuthorityID            AuthorityID            `json:"issuerAuthorityId,omitempty"`
	IssuerGenerationID           GenerationID           `json:"issuerGenerationId,omitempty"`
	ProfileID                    ProfileID              `json:"profileId"`
	Template                     CertificateTemplate    `json:"template"`
	BackendID                    BackendID              `json:"backendId"`
	BackendVersion               string                 `json:"backendVersion"`
	BackendPackageDigest         string                 `json:"backendPackageDigest,omitempty"`
	BackendCapabilityHash        string                 `json:"backendCapabilityHash"`
	SigningBackendID             BackendID              `json:"signingBackendId"`
	SigningBackendVersion        string                 `json:"signingBackendVersion"`
	SigningBackendPackageDigest  string                 `json:"signingBackendPackageDigest,omitempty"`
	SigningBackendCapabilityHash string                 `json:"signingBackendCapabilityHash"`
	CompatibilityTargetID        CompatibilityTargetID  `json:"compatibilityTargetId"`
	CompatibilityVersion         string                 `json:"compatibilityVersion"`
	Purpose                      Purpose                `json:"purpose"`
	ExportPolicy                 ExportPolicy           `json:"exportPolicy"`
	KeyEstablishment             KeyEstablishmentPolicy `json:"keyEstablishmentPolicy"`
	TLSNamedGroups               []TLSNamedGroup        `json:"tlsNamedGroups,omitempty"`
	FingerprintSHA256            string                 `json:"fingerprintSha256"`
	SubjectKeyID                 []byte                 `json:"subjectKeyId,omitempty"`
	AuthorityKeyID               []byte                 `json:"authorityKeyId,omitempty"`
	State                        CertificateState       `json:"state"`
	KeyID                        KeyID                  `json:"keyId"`
	CertificateDER               []byte                 `json:"certificateDer"`
	PublicKeySPKI                []byte                 `json:"publicKeySpki"`
	ChainGenerationIDs           []GenerationID         `json:"chainGenerationIds,omitempty"`
	CreatedAt                    time.Time              `json:"createdAt"`
}

func (g CertificateGeneration) Clone() CertificateGeneration {
	result := g
	result.Template = cloneTemplate(g.Template)
	result.SubjectKeyID = append([]byte(nil), g.SubjectKeyID...)
	result.AuthorityKeyID = append([]byte(nil), g.AuthorityKeyID...)
	result.CertificateDER = append([]byte(nil), g.CertificateDER...)
	result.PublicKeySPKI = append([]byte(nil), g.PublicKeySPKI...)
	result.ChainGenerationIDs = append([]GenerationID(nil), g.ChainGenerationIDs...)
	result.TLSNamedGroups = append([]TLSNamedGroup(nil), g.TLSNamedGroups...)
	return result
}

func (g CertificateGeneration) Validate() error {
	_, err := NewCertificateGeneration(GenerationArgs(g))
	return err
}

func NewCertificateGeneration(args GenerationArgs) (CertificateGeneration, error) {
	if err := args.CertificateID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.ID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := validateSequenceNumber(args.Generation, "certificate generation number"); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.Template.Validate(); err != nil {
		return CertificateGeneration{}, fmt.Errorf("pki: validate certificate template: %w", err)
	}
	for _, optional := range []struct {
		value AuthorityID
		field string
	}{
		{value: args.OwningAuthorityID, field: "owning authority"},
		{value: args.IssuerAuthorityID, field: "issuer authority"},
	} {
		if optional.value != "" {
			if err := optional.value.Validate(); err != nil {
				return CertificateGeneration{}, fmt.Errorf("pki: validate %s: %w", optional.field, err)
			}
		}
	}
	if args.IssuerGenerationID != "" {
		if err := args.IssuerGenerationID.Validate(); err != nil {
			return CertificateGeneration{}, err
		}
	}
	if err := args.ProfileID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.BackendID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.SigningBackendID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.CompatibilityTargetID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if strings.TrimSpace(args.BackendVersion) == "" || strings.TrimSpace(args.BackendCapabilityHash) == "" ||
		strings.TrimSpace(args.SigningBackendVersion) == "" || strings.TrimSpace(args.SigningBackendCapabilityHash) == "" ||
		strings.TrimSpace(args.CompatibilityVersion) == "" {
		return CertificateGeneration{}, errors.New("pki: backend and compatibility version metadata is required")
	}
	if err := args.Purpose.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.ExportPolicy.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := ValidateKeyEstablishment(args.KeyEstablishment, args.TLSNamedGroups); err != nil {
		return CertificateGeneration{}, err
	}
	if target, ok := BuiltInCompatibilityTarget(args.CompatibilityTargetID); ok {
		if strings.TrimSpace(args.CompatibilityVersion) != target.Version {
			return CertificateGeneration{}, fmt.Errorf("pki: compatibility target %q version does not match built-in version %q", target.ID, target.Version)
		}
		expectedGroups, err := ResolveTLSNamedGroups(target, args.KeyEstablishment)
		if err != nil {
			return CertificateGeneration{}, err
		}
		if !slices.Equal(expectedGroups, args.TLSNamedGroups) {
			return CertificateGeneration{}, errors.New("pki: certificate generation tls named groups do not match compatibility target")
		}
	}
	fingerprint, err := normalizeSHA256Fingerprint(args.FingerprintSHA256, "certificate fingerprint")
	if err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.State.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if err := args.KeyID.Validate(); err != nil {
		return CertificateGeneration{}, err
	}
	if len(args.CertificateDER) == 0 || len(args.PublicKeySPKI) == 0 {
		return CertificateGeneration{}, errors.New("pki: certificate der and public key spki are required")
	}
	if len(args.CertificateDER) > MaximumCertificateDERBytes || len(args.PublicKeySPKI) > MaximumPublicKeyDERBytes {
		return CertificateGeneration{}, errors.New("pki: certificate generation encoded material exceeds size limits")
	}
	if len(args.ChainGenerationIDs) > MaximumBundleChainMembers {
		return CertificateGeneration{}, fmt.Errorf("pki: certificate generation chain exceeds %d entries", MaximumBundleChainMembers)
	}
	seenChainIDs := make(map[GenerationID]struct{}, len(args.ChainGenerationIDs))
	for _, id := range args.ChainGenerationIDs {
		if err := id.Validate(); err != nil {
			return CertificateGeneration{}, err
		}
		if _, ok := seenChainIDs[id]; ok {
			return CertificateGeneration{}, fmt.Errorf("pki: duplicate chain generation id %q", id)
		}
		seenChainIDs[id] = struct{}{}
	}
	if args.CreatedAt.IsZero() {
		return CertificateGeneration{}, errors.New("pki: certificate generation creation time is required")
	}
	return CertificateGeneration{
		CertificateID:                args.CertificateID,
		ID:                           args.ID,
		Generation:                   args.Generation,
		OwningAuthorityID:            args.OwningAuthorityID,
		IssuerAuthorityID:            args.IssuerAuthorityID,
		IssuerGenerationID:           args.IssuerGenerationID,
		ProfileID:                    args.ProfileID,
		Template:                     cloneTemplate(args.Template),
		BackendID:                    args.BackendID,
		BackendVersion:               strings.TrimSpace(args.BackendVersion),
		BackendPackageDigest:         strings.TrimSpace(args.BackendPackageDigest),
		BackendCapabilityHash:        strings.TrimSpace(args.BackendCapabilityHash),
		SigningBackendID:             args.SigningBackendID,
		SigningBackendVersion:        strings.TrimSpace(args.SigningBackendVersion),
		SigningBackendPackageDigest:  strings.TrimSpace(args.SigningBackendPackageDigest),
		SigningBackendCapabilityHash: strings.TrimSpace(args.SigningBackendCapabilityHash),
		CompatibilityTargetID:        args.CompatibilityTargetID,
		CompatibilityVersion:         strings.TrimSpace(args.CompatibilityVersion),
		Purpose:                      args.Purpose,
		ExportPolicy:                 args.ExportPolicy,
		KeyEstablishment:             args.KeyEstablishment,
		TLSNamedGroups:               append([]TLSNamedGroup(nil), args.TLSNamedGroups...),
		FingerprintSHA256:            fingerprint,
		SubjectKeyID:                 append([]byte(nil), args.SubjectKeyID...),
		AuthorityKeyID:               append([]byte(nil), args.AuthorityKeyID...),
		State:                        args.State,
		KeyID:                        args.KeyID,
		CertificateDER:               append([]byte(nil), args.CertificateDER...),
		PublicKeySPKI:                append([]byte(nil), args.PublicKeySPKI...),
		ChainGenerationIDs:           append([]GenerationID(nil), args.ChainGenerationIDs...),
		CreatedAt:                    args.CreatedAt.UTC(),
	}, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneTemplate(template CertificateTemplate) CertificateTemplate {
	result := template
	result.Subject.Country = append([]string(nil), template.Subject.Country...)
	result.Subject.Organization = append([]string(nil), template.Subject.Organization...)
	result.Subject.OrganizationalUnit = append([]string(nil), template.Subject.OrganizationalUnit...)
	result.Subject.Locality = append([]string(nil), template.Subject.Locality...)
	result.Subject.Province = append([]string(nil), template.Subject.Province...)
	result.Subject.StreetAddress = append([]string(nil), template.Subject.StreetAddress...)
	result.Subject.PostalCode = append([]string(nil), template.Subject.PostalCode...)
	result.Subject.ExtraNames = append([]Attribute(nil), template.Subject.ExtraNames...)
	result.SubjectAlternativeNames.DNSNames = append([]string(nil), template.SubjectAlternativeNames.DNSNames...)
	result.SubjectAlternativeNames.IPAddresses = append([]string(nil), template.SubjectAlternativeNames.IPAddresses...)
	result.SubjectAlternativeNames.EmailAddresses = append([]string(nil), template.SubjectAlternativeNames.EmailAddresses...)
	result.SubjectAlternativeNames.URIs = append([]string(nil), template.SubjectAlternativeNames.URIs...)
	result.ExtendedKeyUsages = append([]ExtendedKeyUsage(nil), template.ExtendedKeyUsages...)
	result.UnknownExtendedKeyUsages = append([]OID(nil), template.UnknownExtendedKeyUsages...)
	result.SubjectKeyIdentifier.Value = append([]byte(nil), template.SubjectKeyIdentifier.Value...)
	result.AuthorityKeyIdentifier.Value = append([]byte(nil), template.AuthorityKeyIdentifier.Value...)
	result.PolicyOIDs = append([]OID(nil), template.PolicyOIDs...)
	result.OCSPServers = append([]string(nil), template.OCSPServers...)
	result.IssuingCertificateURLs = append([]string(nil), template.IssuingCertificateURLs...)
	result.CRLDistributionPoints = append([]string(nil), template.CRLDistributionPoints...)
	result.NameConstraints = cloneNameConstraints(template.NameConstraints)
	result.CustomExtensions = make([]CustomExtension, len(template.CustomExtensions))
	for index, extension := range template.CustomExtensions {
		result.CustomExtensions[index] = extension
		result.CustomExtensions[index].DER = append([]byte(nil), extension.DER...)
	}
	return result
}

func cloneNameConstraints(constraints NameConstraints) NameConstraints {
	result := constraints
	result.PermittedDNSDomains = append([]string(nil), constraints.PermittedDNSDomains...)
	result.ExcludedDNSDomains = append([]string(nil), constraints.ExcludedDNSDomains...)
	result.PermittedIPRanges = append([]string(nil), constraints.PermittedIPRanges...)
	result.ExcludedIPRanges = append([]string(nil), constraints.ExcludedIPRanges...)
	result.PermittedEmailAddresses = append([]string(nil), constraints.PermittedEmailAddresses...)
	result.ExcludedEmailAddresses = append([]string(nil), constraints.ExcludedEmailAddresses...)
	result.PermittedURIDomains = append([]string(nil), constraints.PermittedURIDomains...)
	result.ExcludedURIDomains = append([]string(nil), constraints.ExcludedURIDomains...)
	return result
}
