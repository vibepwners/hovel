package pki

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	BundleSchemaV1    = "hovel.pki.bundle/v1"
	EncodingBase64DER = "base64-der"

	MediaTypeCertificate = "application/pkix-cert"
	MediaTypePublicKey   = "application/pkix-keyinfo"
	MediaTypePrivateKey  = "application/pkcs8"
	MediaTypeCRL         = "application/pkix-crl"

	MaximumCertificateDERBytes = 1 << 20
	MaximumPublicKeyDERBytes   = 1 << 20
	MaximumPrivateKeyDERBytes  = 2 << 20
	MaximumCRLDERBytes         = 4 << 20
	MaximumBundleJSONBytes     = 32 << 20
	MaximumBundleBinaryBytes   = 24 << 20
	MaximumBundleChainMembers  = 32
	MaximumBundleCRLMembers    = 32
	MaximumKeyCapabilities     = 64
	MaximumCapabilityBytes     = 256
)

type Binary struct {
	MediaType string `json:"mediaType"`
	Encoding  string `json:"encoding"`
	Data      []byte `json:"data"`
}

func NewBinary(mediaType string, data []byte) (Binary, error) {
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "" {
		return Binary{}, errors.New("pki: binary media type is required")
	}
	if len(data) == 0 {
		return Binary{}, errors.New("pki: binary data is required")
	}
	result := Binary{MediaType: mediaType, Encoding: EncodingBase64DER, Data: append([]byte(nil), data...)}
	if err := validateBinary(result, mediaType, "binary data"); err != nil {
		return Binary{}, err
	}
	return result, nil
}

type CertificateMember struct {
	GenerationID GenerationID `json:"certificateGenerationId"`
	Binary
}

type CRLMember struct {
	GenerationID       CRLGenerationID `json:"crlGenerationId"`
	IssuerGenerationID GenerationID    `json:"issuerCertificateGenerationId"`
	Binary
}

type KeyReference struct {
	KeyID        KeyID     `json:"keyId"`
	ProviderID   string    `json:"providerId"`
	Capabilities []string  `json:"capabilities"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
}

type Fingerprints struct {
	CertificateSHA256 string `json:"certificateSha256"`
	PublicKeySHA256   string `json:"publicKeySha256"`
}

type BundleArgs struct {
	SchemaVersion              string
	ID                         BundleID
	AssignmentID               AssignmentID
	CertificateID              CertificateID
	CertificateGenerationID    GenerationID
	Generation                 uint64
	Purpose                    Purpose
	CompatibilityTargetID      CompatibilityTargetID
	CompatibilityVersion       string
	KeyEstablishmentPolicy     KeyEstablishmentPolicy
	TLSNamedGroups             []TLSNamedGroup
	Certificate                Binary
	PublicKey                  Binary
	PrivateKey                 *Binary
	PrivateKeyRef              *KeyReference
	Chain                      []CertificateMember
	TrustAnchors               []CertificateMember
	CertificateRevocationLists []CRLMember
	Fingerprints               Fingerprints
	NotBefore                  time.Time
	NotAfter                   time.Time
}

type Bundle struct {
	SchemaVersion              string                 `json:"schemaVersion"`
	ID                         BundleID               `json:"bundleId"`
	AssignmentID               AssignmentID           `json:"assignmentId,omitempty"`
	CertificateID              CertificateID          `json:"certificateId"`
	CertificateGenerationID    GenerationID           `json:"certificateGenerationId"`
	Generation                 uint64                 `json:"generation"`
	Purpose                    Purpose                `json:"purpose"`
	CompatibilityTargetID      CompatibilityTargetID  `json:"compatibilityTargetId"`
	CompatibilityVersion       string                 `json:"compatibilityVersion"`
	KeyEstablishmentPolicy     KeyEstablishmentPolicy `json:"keyEstablishmentPolicy"`
	TLSNamedGroups             []TLSNamedGroup        `json:"tlsNamedGroups,omitempty"`
	Certificate                Binary                 `json:"certificate"`
	PublicKey                  Binary                 `json:"publicKey"`
	PrivateKey                 *Binary                `json:"privateKey,omitempty"`
	PrivateKeyRef              *KeyReference          `json:"privateKeyRef,omitempty"`
	Chain                      []CertificateMember    `json:"chain,omitempty"`
	TrustAnchors               []CertificateMember    `json:"trustAnchors,omitempty"`
	CertificateRevocationLists []CRLMember            `json:"certificateRevocationLists,omitempty"`
	Fingerprints               Fingerprints           `json:"fingerprints"`
	NotBefore                  time.Time              `json:"notBefore"`
	NotAfter                   time.Time              `json:"notAfter"`
}

type bundleWire Bundle

// Validate verifies a bundle received from storage, JSON, or a provider. It is
// intentionally equivalent to construction so consumers cannot bypass domain
// invariants by populating exported wire fields directly.
func (b Bundle) Validate() error {
	_, err := NewBundle(bundleArgs(b))
	return err
}

// UnmarshalJSON makes the public wire type fail closed. Provider and control
// clients can still use DecodeBundleJSON when they also want unknown-field and
// trailing-data rejection.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	if b == nil {
		return errors.New("pki: bundle destination is nil")
	}
	if len(data) == 0 || len(data) > MaximumBundleJSONBytes {
		return errors.New("pki: bundle json has an invalid size")
	}
	var wire bundleWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("pki: decode bundle: %w", err)
	}
	validated, err := NewBundle(bundleArgs(Bundle(wire)))
	if err != nil {
		return err
	}
	*b = validated
	return nil
}

// DecodeBundleJSON rejects unknown fields and trailing JSON in addition to the
// domain validation enforced by Bundle.UnmarshalJSON.
func DecodeBundleJSON(data []byte) (Bundle, error) {
	if len(data) == 0 || len(data) > MaximumBundleJSONBytes {
		return Bundle{}, errors.New("pki: bundle json has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire bundleWire
	if err := decoder.Decode(&wire); err != nil {
		return Bundle{}, fmt.Errorf("pki: decode bundle: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Bundle{}, errors.New("pki: bundle contains trailing json data")
	}
	bundle, err := NewBundle(bundleArgs(Bundle(wire)))
	if err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func NewBundle(args BundleArgs) (Bundle, error) {
	if err := validateSchemaVersion(args.SchemaVersion, BundleSchemaV1); err != nil {
		return Bundle{}, err
	}
	if err := args.ID.Validate(); err != nil {
		return Bundle{}, err
	}
	if args.AssignmentID != "" {
		if err := args.AssignmentID.Validate(); err != nil {
			return Bundle{}, err
		}
	}
	if err := args.CertificateID.Validate(); err != nil {
		return Bundle{}, err
	}
	if err := args.CertificateGenerationID.Validate(); err != nil {
		return Bundle{}, err
	}
	if args.Generation == 0 {
		return Bundle{}, errors.New("pki: bundle generation must be positive")
	}
	if err := args.Purpose.Validate(); err != nil {
		return Bundle{}, err
	}
	if err := args.CompatibilityTargetID.Validate(); err != nil {
		return Bundle{}, err
	}
	compatibilityVersion := strings.TrimSpace(args.CompatibilityVersion)
	if compatibilityVersion == "" {
		return Bundle{}, errors.New("pki: compatibility version is required")
	}
	if err := ValidateKeyEstablishment(args.KeyEstablishmentPolicy, args.TLSNamedGroups); err != nil {
		return Bundle{}, err
	}
	if target, ok := BuiltInCompatibilityTarget(args.CompatibilityTargetID); ok {
		if compatibilityVersion != target.Version {
			return Bundle{}, fmt.Errorf("pki: compatibility target %q version %q does not match built-in version %q", target.ID, compatibilityVersion, target.Version)
		}
		expectedGroups, err := ResolveTLSNamedGroups(target, args.KeyEstablishmentPolicy)
		if err != nil {
			return Bundle{}, err
		}
		if !slices.Equal(expectedGroups, args.TLSNamedGroups) {
			return Bundle{}, errors.New("pki: bundle tls named groups do not match the compatibility target and policy")
		}
	}
	if err := validateBinary(args.Certificate, MediaTypeCertificate, "certificate"); err != nil {
		return Bundle{}, err
	}
	if err := validateBinary(args.PublicKey, MediaTypePublicKey, "public key"); err != nil {
		return Bundle{}, err
	}
	if args.PrivateKey != nil && args.PrivateKeyRef != nil {
		return Bundle{}, errors.New("pki: private key and private key reference are mutually exclusive")
	}
	if args.PrivateKey != nil {
		if err := validateBinary(*args.PrivateKey, MediaTypePrivateKey, "private key"); err != nil {
			return Bundle{}, err
		}
	}
	if args.PrivateKeyRef != nil {
		if err := args.PrivateKeyRef.KeyID.Validate(); err != nil {
			return Bundle{}, err
		}
		if strings.TrimSpace(args.PrivateKeyRef.ProviderID) == "" {
			return Bundle{}, errors.New("pki: private key reference provider id is required")
		}
		if len(args.PrivateKeyRef.ProviderID) > MaxIDLength || strings.ContainsAny(args.PrivateKeyRef.ProviderID, "\x00\r\n") {
			return Bundle{}, errors.New("pki: private key reference provider id is not canonical")
		}
		if len(args.PrivateKeyRef.Capabilities) > MaximumKeyCapabilities {
			return Bundle{}, fmt.Errorf("pki: private key reference capabilities exceed %d entries", MaximumKeyCapabilities)
		}
		seenCapabilities := make(map[string]struct{}, len(args.PrivateKeyRef.Capabilities))
		for _, capability := range args.PrivateKeyRef.Capabilities {
			if capability == "" || capability != strings.TrimSpace(capability) || len(capability) > MaximumCapabilityBytes || strings.ContainsAny(capability, "\x00\r\n") {
				return Bundle{}, errors.New("pki: private key reference capability is not canonical")
			}
			if _, exists := seenCapabilities[capability]; exists {
				return Bundle{}, fmt.Errorf("pki: duplicate private key reference capability %q", capability)
			}
			seenCapabilities[capability] = struct{}{}
		}
	}
	certificateFingerprint, err := normalizeSHA256Fingerprint(args.Fingerprints.CertificateSHA256, "certificate fingerprint")
	if err != nil {
		return Bundle{}, err
	}
	publicKeyFingerprint, err := normalizeSHA256Fingerprint(args.Fingerprints.PublicKeySHA256, "public key fingerprint")
	if err != nil {
		return Bundle{}, err
	}
	if args.NotBefore.IsZero() || args.NotAfter.IsZero() || !args.NotAfter.After(args.NotBefore) {
		return Bundle{}, errors.New("pki: valid bundle time bounds are required")
	}
	if err := validateCertificateMembers(args.Chain, args.TrustAnchors, args.CertificateGenerationID); err != nil {
		return Bundle{}, err
	}
	if err := validateCRLMembers(args.CertificateRevocationLists); err != nil {
		return Bundle{}, err
	}
	if err := validateBundleAggregateSize(args); err != nil {
		return Bundle{}, err
	}
	result := Bundle{
		SchemaVersion:              args.SchemaVersion,
		ID:                         args.ID,
		AssignmentID:               args.AssignmentID,
		CertificateID:              args.CertificateID,
		CertificateGenerationID:    args.CertificateGenerationID,
		Generation:                 args.Generation,
		Purpose:                    args.Purpose,
		CompatibilityTargetID:      args.CompatibilityTargetID,
		CompatibilityVersion:       compatibilityVersion,
		KeyEstablishmentPolicy:     args.KeyEstablishmentPolicy,
		TLSNamedGroups:             append([]TLSNamedGroup(nil), args.TLSNamedGroups...),
		Certificate:                cloneBinary(args.Certificate),
		PublicKey:                  cloneBinary(args.PublicKey),
		PrivateKey:                 cloneBinaryPointer(args.PrivateKey),
		PrivateKeyRef:              cloneKeyReference(args.PrivateKeyRef),
		Chain:                      cloneCertificateMembers(args.Chain),
		TrustAnchors:               cloneCertificateMembers(args.TrustAnchors),
		CertificateRevocationLists: cloneCRLMembers(args.CertificateRevocationLists),
		Fingerprints: Fingerprints{
			CertificateSHA256: certificateFingerprint,
			PublicKeySHA256:   publicKeyFingerprint,
		},
		NotBefore: args.NotBefore.UTC(),
		NotAfter:  args.NotAfter.UTC(),
	}
	return result, nil
}

func bundleArgs(bundle Bundle) BundleArgs {
	return BundleArgs(bundle)
}

func (b Bundle) Public() Bundle {
	result := b.Clone()
	result.PrivateKey = nil
	result.PrivateKeyRef = nil
	return result
}

func (b Bundle) Clone() Bundle {
	result := b
	result.Certificate = cloneBinary(b.Certificate)
	result.PublicKey = cloneBinary(b.PublicKey)
	result.PrivateKey = cloneBinaryPointer(b.PrivateKey)
	result.PrivateKeyRef = cloneKeyReference(b.PrivateKeyRef)
	result.Chain = cloneCertificateMembers(b.Chain)
	result.TrustAnchors = cloneCertificateMembers(b.TrustAnchors)
	result.CertificateRevocationLists = cloneCRLMembers(b.CertificateRevocationLists)
	result.TLSNamedGroups = append([]TLSNamedGroup(nil), b.TLSNamedGroups...)
	return result
}

func validateBinary(binary Binary, mediaType, field string) error {
	if binary.MediaType != mediaType || binary.Encoding != EncodingBase64DER || len(binary.Data) == 0 {
		return fmt.Errorf("pki: %s must be non-empty %s encoded as %s", field, mediaType, EncodingBase64DER)
	}
	maximumBytes := MaximumBundleBinaryBytes
	switch mediaType {
	case MediaTypeCertificate:
		maximumBytes = MaximumCertificateDERBytes
	case MediaTypePublicKey:
		maximumBytes = MaximumPublicKeyDERBytes
	case MediaTypePrivateKey:
		maximumBytes = MaximumPrivateKeyDERBytes
	case MediaTypeCRL:
		maximumBytes = MaximumCRLDERBytes
	}
	if len(binary.Data) > maximumBytes {
		return fmt.Errorf("pki: %s exceeds %d bytes", field, maximumBytes)
	}
	return nil
}

func validateCertificateMembers(chain, trust []CertificateMember, leaf GenerationID) error {
	if len(chain)+len(trust) > MaximumBundleChainMembers {
		return fmt.Errorf("pki: bundle certificate members exceed %d entries", MaximumBundleChainMembers)
	}
	seen := map[GenerationID]struct{}{leaf: {}}
	for _, members := range [][]CertificateMember{chain, trust} {
		for _, member := range members {
			if err := member.GenerationID.Validate(); err != nil {
				return err
			}
			if err := validateBinary(member.Binary, MediaTypeCertificate, "certificate member"); err != nil {
				return err
			}
			if _, ok := seen[member.GenerationID]; ok {
				return fmt.Errorf("pki: duplicate certificate generation %q in bundle", member.GenerationID)
			}
			seen[member.GenerationID] = struct{}{}
		}
	}
	return nil
}

func validateCRLMembers(values []CRLMember) error {
	if len(values) > MaximumBundleCRLMembers {
		return fmt.Errorf("pki: bundle crl members exceed %d entries", MaximumBundleCRLMembers)
	}
	seen := make(map[CRLGenerationID]struct{}, len(values))
	for _, member := range values {
		if err := member.GenerationID.Validate(); err != nil {
			return err
		}
		if err := member.IssuerGenerationID.Validate(); err != nil {
			return err
		}
		if _, ok := seen[member.GenerationID]; ok {
			return fmt.Errorf("pki: duplicate crl generation %q in bundle", member.GenerationID)
		}
		seen[member.GenerationID] = struct{}{}
		if err := validateBinary(member.Binary, MediaTypeCRL, "certificate revocation list"); err != nil {
			return err
		}
	}
	return nil
}

func validateBundleAggregateSize(args BundleArgs) error {
	total := 0
	add := func(size int) error {
		if size < 0 || size > MaximumBundleBinaryBytes-total {
			return fmt.Errorf("pki: bundle binary material exceeds %d bytes", MaximumBundleBinaryBytes)
		}
		total += size
		return nil
	}
	for _, size := range []int{len(args.Certificate.Data), len(args.PublicKey.Data)} {
		if err := add(size); err != nil {
			return err
		}
	}
	if args.PrivateKey != nil {
		if err := add(len(args.PrivateKey.Data)); err != nil {
			return err
		}
	}
	for _, member := range args.Chain {
		if err := add(len(member.Data)); err != nil {
			return err
		}
	}
	for _, member := range args.TrustAnchors {
		if err := add(len(member.Data)); err != nil {
			return err
		}
	}
	for _, member := range args.CertificateRevocationLists {
		if err := add(len(member.Data)); err != nil {
			return err
		}
	}
	return nil
}

func normalizeSHA256Fingerprint(value, field string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("pki: %s must be a 32-byte hexadecimal sha-256 digest", field)
	}
	return value, nil
}

func cloneBinary(binary Binary) Binary {
	result := binary
	result.Data = append([]byte(nil), binary.Data...)
	return result
}

func cloneBinaryPointer(binary *Binary) *Binary {
	if binary == nil {
		return nil
	}
	result := cloneBinary(*binary)
	return &result
}

func cloneKeyReference(reference *KeyReference) *KeyReference {
	if reference == nil {
		return nil
	}
	result := *reference
	result.Capabilities = append(make([]string, 0, len(reference.Capabilities)), reference.Capabilities...)
	return &result
}

func cloneCertificateMembers(values []CertificateMember) []CertificateMember {
	result := make([]CertificateMember, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Binary = cloneBinary(value.Binary)
	}
	return result
}

func cloneCRLMembers(values []CRLMember) []CRLMember {
	result := make([]CRLMember, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Binary = cloneBinary(value.Binary)
	}
	return result
}
