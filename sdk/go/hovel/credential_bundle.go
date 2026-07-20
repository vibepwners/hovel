package hovel

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// CredentialBundleSchemaV1 is the portable bundle emitted by Hovel PKI.
	CredentialBundleSchemaV1 = "hovel.pki.bundle/v1"

	CredentialBundleEncodingBase64DER = "base64-der"
	CredentialBundleMediaCertificate  = "application/pkix-cert"
	CredentialBundleMediaPublicKey    = "application/pkix-keyinfo"
	CredentialBundleMediaPrivateKey   = "application/pkcs8"
	CredentialBundleMediaCRL          = "application/pkix-crl"

	CredentialKeyEstablishmentNotApplicable       = "not-applicable"
	CredentialKeyEstablishmentClassicalCompatible = "classical-compatible"
	CredentialKeyEstablishmentHybridPQPreferred   = "hybrid-pq-preferred"
	CredentialKeyEstablishmentHybridPQRequired    = "hybrid-pq-required"

	credentialBundleMaximumJSONBytes        = 32 << 20
	credentialBundleMaximumCertificateBytes = 1 << 20
	credentialBundleMaximumPublicKeyBytes   = 1 << 20
	credentialBundleMaximumPrivateKeyBytes  = 2 << 20
	credentialBundleMaximumCRLBytes         = 4 << 20
	credentialBundleMaximumBinaryBytes      = maximumCredentialBinaryBytes
	credentialBundleMaximumCertificateCount = 32
	credentialBundleMaximumCRLCount         = 32
	redactedCredentialBundle                = "<credential bundle redacted>"
)

// CredentialBundleBinary is one DER member of a portable credential bundle.
// Data uses CredentialBytes so ordinary formatting cannot expose key bytes.
type CredentialBundleBinary struct {
	MediaType string          `json:"mediaType"`
	Encoding  string          `json:"encoding"`
	Data      CredentialBytes `json:"data"`
}

type CredentialBundleCertificate struct {
	GenerationID string `json:"certificateGenerationId"`
	CredentialBundleBinary
}

type CredentialBundleCRL struct {
	GenerationID       string `json:"crlGenerationId"`
	IssuerGenerationID string `json:"issuerCertificateGenerationId"`
	CredentialBundleBinary
}

type CredentialBundleKeyReference struct {
	KeyID        string    `json:"keyId"`
	ProviderID   string    `json:"providerId"`
	Capabilities []string  `json:"capabilities"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
}

type CredentialBundleFingerprints struct {
	CertificateSHA256 string `json:"certificateSha256"`
	PublicKeySHA256   string `json:"publicKeySha256"`
}

// CredentialBundle is the Go provider-side representation of
// hovel.pki.bundle/v1. DecodeCredentialBundleJSON performs strict structural
// validation; ValidateAt additionally verifies its PKIX path and CRLs.
type CredentialBundle struct {
	SchemaVersion              string                        `json:"schemaVersion"`
	ID                         string                        `json:"bundleId"`
	AssignmentID               string                        `json:"assignmentId,omitempty"`
	CertificateID              string                        `json:"certificateId"`
	CertificateGenerationID    string                        `json:"certificateGenerationId"`
	Generation                 uint64                        `json:"generation"`
	Purpose                    CredentialPurpose             `json:"purpose"`
	CompatibilityTargetID      string                        `json:"compatibilityTargetId"`
	CompatibilityVersion       string                        `json:"compatibilityVersion"`
	KeyEstablishmentPolicy     string                        `json:"keyEstablishmentPolicy"`
	TLSNamedGroups             []string                      `json:"tlsNamedGroups,omitempty"`
	Certificate                CredentialBundleBinary        `json:"certificate"`
	PublicKey                  CredentialBundleBinary        `json:"publicKey"`
	PrivateKey                 *CredentialBundleBinary       `json:"privateKey,omitempty"`
	PrivateKeyRef              *CredentialBundleKeyReference `json:"privateKeyRef,omitempty"`
	Chain                      []CredentialBundleCertificate `json:"chain,omitempty"`
	TrustAnchors               []CredentialBundleCertificate `json:"trustAnchors,omitempty"`
	CertificateRevocationLists []CredentialBundleCRL         `json:"certificateRevocationLists,omitempty"`
	Fingerprints               CredentialBundleFingerprints  `json:"fingerprints"`
	NotBefore                  time.Time                     `json:"notBefore"`
	NotAfter                   time.Time                     `json:"notAfter"`
}

func (CredentialBundle) String() string { return redactedCredentialBundle }

func (CredentialBundle) GoString() string { return redactedCredentialBundle }

func (CredentialBundle) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialBundle)
}

// DecodeCredentialBundleJSON rejects unknown fields, trailing data, malformed
// DER members, mismatched fingerprints, and mismatched private keys.
func DecodeCredentialBundleJSON(data []byte) (CredentialBundle, error) {
	if len(data) == 0 || len(data) > credentialBundleMaximumJSONBytes {
		return CredentialBundle{}, errors.New("hovel: credential bundle JSON has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle CredentialBundle
	if err := decoder.Decode(&bundle); err != nil {
		bundle.Clear()
		return CredentialBundle{}, fmt.Errorf("hovel: decode credential bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		bundle.Clear()
		return CredentialBundle{}, errors.New("hovel: credential bundle contains trailing JSON data")
	}
	if err := bundle.Validate(); err != nil {
		bundle.Clear()
		return CredentialBundle{}, err
	}
	return bundle, nil
}

// Validate checks the bundle's stable wire invariants without consulting the
// wall clock. Use ValidateAt before configuring a live TLS endpoint.
func (b CredentialBundle) Validate() error {
	if b.SchemaVersion != CredentialBundleSchemaV1 {
		return fmt.Errorf("hovel: unsupported credential bundle schema %q", b.SchemaVersion)
	}
	for label, value := range map[string]string{
		"bundle id":                 b.ID,
		"certificate id":            b.CertificateID,
		"certificate generation id": b.CertificateGenerationID,
		"compatibility target id":   b.CompatibilityTargetID,
		"compatibility version":     b.CompatibilityVersion,
	} {
		if err := validateCredentialCanonicalText(value, label, maximumCredentialNameBytes); err != nil {
			return err
		}
	}
	if b.AssignmentID != "" {
		if err := validateCredentialCanonicalText(
			b.AssignmentID, "assignment id", maximumCredentialNameBytes,
		); err != nil {
			return err
		}
	}
	if b.Generation == 0 {
		return errors.New("hovel: credential bundle generation must be positive")
	}
	if err := b.Purpose.Validate(); err != nil {
		return err
	}
	if err := validateCredentialKeyEstablishment(
		b.KeyEstablishmentPolicy,
		b.TLSNamedGroups,
	); err != nil {
		return err
	}
	leaf, err := validateCredentialBundleBinary(
		b.Certificate,
		CredentialBundleMediaCertificate,
		"certificate",
	)
	if err != nil {
		return err
	}
	certificate, err := parseCredentialBundleCertificate(leaf, "certificate")
	if err != nil {
		return err
	}
	publicKey, err := validateCredentialBundleBinary(
		b.PublicKey,
		CredentialBundleMediaPublicKey,
		"public key",
	)
	if err != nil {
		return err
	}
	if _, err := x509.ParsePKIXPublicKey(publicKey); err != nil {
		return fmt.Errorf("hovel: parse credential bundle public key: %w", err)
	}
	if !bytes.Equal(publicKey, certificate.RawSubjectPublicKeyInfo) {
		return errors.New("hovel: credential bundle public key does not match its certificate")
	}
	if err := validateCredentialBundleFingerprint(
		b.Fingerprints.CertificateSHA256,
		leaf,
		"certificate",
	); err != nil {
		return err
	}
	if err := validateCredentialBundleFingerprint(
		b.Fingerprints.PublicKeySHA256,
		publicKey,
		"public key",
	); err != nil {
		return err
	}
	if b.PrivateKey != nil && b.PrivateKeyRef != nil {
		return errors.New("hovel: credential bundle contains private bytes and a private reference")
	}
	if b.PrivateKey != nil {
		privateKey, err := validateCredentialBundleBinary(
			*b.PrivateKey,
			CredentialBundleMediaPrivateKey,
			"private key",
		)
		if err != nil {
			return err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("hovel: parse credential bundle private key: %w", err)
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return errors.New("hovel: credential bundle private key cannot sign")
		}
		privatePublic, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil || !bytes.Equal(privatePublic, publicKey) {
			return errors.New("hovel: credential bundle private key does not match its certificate")
		}
	}
	if b.PrivateKeyRef != nil {
		if err := validateCredentialCanonicalText(
			b.PrivateKeyRef.KeyID, "private key id", maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := validateCredentialCanonicalText(
			b.PrivateKeyRef.ProviderID, "private key provider id", maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if len(b.PrivateKeyRef.Capabilities) > maximumCredentialReferenceCapabilities {
			return errors.New("hovel: credential bundle private key capabilities exceed limits")
		}
		seenCapabilities := make(map[string]struct{}, len(b.PrivateKeyRef.Capabilities))
		for _, capability := range b.PrivateKeyRef.Capabilities {
			if err := validateCredentialCanonicalText(
				capability, "private key capability", maximumCredentialIDBytes,
			); err != nil {
				return err
			}
			if _, duplicate := seenCapabilities[capability]; duplicate {
				return errors.New("hovel: credential bundle private key capabilities contain a duplicate")
			}
			seenCapabilities[capability] = struct{}{}
		}
	}
	if b.NotBefore.IsZero() || b.NotAfter.IsZero() || !b.NotAfter.After(b.NotBefore) {
		return errors.New("hovel: credential bundle validity window is invalid")
	}
	if !certificate.NotBefore.Equal(b.NotBefore) || !certificate.NotAfter.Equal(b.NotAfter) {
		return errors.New("hovel: credential bundle validity window does not match its certificate")
	}
	if len(b.Chain)+len(b.TrustAnchors) > credentialBundleMaximumCertificateCount {
		return errors.New("hovel: credential bundle certificate members exceed limits")
	}
	seen := map[string]struct{}{b.CertificateGenerationID: {}}
	for _, group := range [][]CredentialBundleCertificate{b.Chain, b.TrustAnchors} {
		for _, member := range group {
			if err := validateCredentialCanonicalText(
				member.GenerationID, "certificate member generation id", maximumCredentialIDBytes,
			); err != nil {
				return err
			}
			if _, duplicate := seen[member.GenerationID]; duplicate {
				return errors.New("hovel: credential bundle contains a duplicate certificate generation")
			}
			seen[member.GenerationID] = struct{}{}
			memberDER, err := validateCredentialBundleBinary(
				member.CredentialBundleBinary,
				CredentialBundleMediaCertificate,
				"certificate member",
			)
			if err != nil {
				return err
			}
			if _, err := parseCredentialBundleCertificate(memberDER, "certificate member"); err != nil {
				return err
			}
		}
	}
	if len(b.CertificateRevocationLists) > credentialBundleMaximumCRLCount {
		return errors.New("hovel: credential bundle CRL members exceed limits")
	}
	seenCRLs := make(map[string]struct{}, len(b.CertificateRevocationLists))
	for _, member := range b.CertificateRevocationLists {
		if err := validateCredentialCanonicalText(
			member.GenerationID, "CRL generation id", maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := validateCredentialCanonicalText(
			member.IssuerGenerationID, "CRL issuer generation id", maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if _, duplicate := seenCRLs[member.GenerationID]; duplicate {
			return errors.New("hovel: credential bundle contains a duplicate CRL generation")
		}
		seenCRLs[member.GenerationID] = struct{}{}
		crlDER, err := validateCredentialBundleBinary(
			member.CredentialBundleBinary,
			CredentialBundleMediaCRL,
			"certificate revocation list",
		)
		if err != nil {
			return err
		}
		if _, err := x509.ParseRevocationList(crlDER); err != nil {
			return fmt.Errorf("hovel: parse credential bundle CRL: %w", err)
		}
	}
	return validateCredentialBundleAggregateSize(b)
}

// ValidateAt verifies the certificate path, intended EKU, validity, and
// bundled revocation lists at a caller-selected instant.
func (b CredentialBundle) ValidateAt(currentTime time.Time) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if currentTime.IsZero() {
		return errors.New("hovel: credential bundle verification time is required")
	}
	currentTime = currentTime.UTC()
	if currentTime.Before(b.NotBefore) || !currentTime.Before(b.NotAfter) {
		return errors.New("hovel: credential bundle is not currently valid")
	}
	leaf, _ := parseCredentialBundleCertificate(b.Certificate.Data, "certificate")
	chain := make([]*x509.Certificate, 0, len(b.Chain))
	trust := make([]*x509.Certificate, 0, len(b.TrustAnchors))
	certificates := make(map[string]*x509.Certificate, 1+len(b.Chain)+len(b.TrustAnchors))
	certificates[b.CertificateGenerationID] = leaf
	for _, member := range b.Chain {
		certificate, _ := parseCredentialBundleCertificate(member.Data, "chain member")
		chain = append(chain, certificate)
		certificates[member.GenerationID] = certificate
	}
	for _, member := range b.TrustAnchors {
		certificate, _ := parseCredentialBundleCertificate(member.Data, "trust anchor")
		trust = append(trust, certificate)
		certificates[member.GenerationID] = certificate
	}
	if err := verifyCredentialBundlePurpose(leaf, b.Purpose); err != nil {
		return err
	}
	if err := verifyCredentialBundleChainAt(leaf, chain, trust, currentTime, b.Purpose); err != nil {
		return err
	}
	for _, member := range b.CertificateRevocationLists {
		list, _ := x509.ParseRevocationList(member.Data)
		issuer := certificates[member.IssuerGenerationID]
		if issuer == nil {
			return errors.New("hovel: credential bundle CRL references a missing issuer")
		}
		if !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
			return errors.New("hovel: credential bundle CRL issuer does not match its certificate")
		}
		if err := list.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("hovel: verify credential bundle CRL: %w", err)
		}
		if list.ThisUpdate.IsZero() || list.NextUpdate.IsZero() ||
			!list.NextUpdate.After(list.ThisUpdate) || currentTime.Before(list.ThisUpdate) ||
			!currentTime.Before(list.NextUpdate) {
			return errors.New("hovel: credential bundle CRL is not fresh")
		}
		for generationID, certificate := range certificates {
			if generationID == member.IssuerGenerationID ||
				!bytes.Equal(certificate.RawIssuer, issuer.RawSubject) {
				continue
			}
			for _, revoked := range list.RevokedCertificateEntries {
				if revoked.SerialNumber.Cmp(certificate.SerialNumber) == 0 &&
					!revoked.RevocationTime.After(currentTime) {
					return fmt.Errorf(
						"hovel: credential bundle CRL revokes certificate generation %q",
						generationID,
					)
				}
			}
		}
	}
	return nil
}

// TLSServerConfigAt creates a TLS 1.3 server configuration from a verified
// bundle, preserving its exact named-group policy and certificate chain.
func (b CredentialBundle) TLSServerConfigAt(currentTime time.Time) (*tls.Config, error) {
	if err := b.ValidateAt(currentTime); err != nil {
		return nil, err
	}
	switch b.Purpose {
	case CredentialPurposeTLSServer, CredentialPurposeMTLSServer, CredentialPurposeDualRoleMTLS:
	default:
		return nil, fmt.Errorf("hovel: credential purpose %q cannot configure a TLS server", b.Purpose)
	}
	if b.PrivateKey == nil {
		return nil, errors.New("hovel: credential bundle has no server private-key bytes")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(b.PrivateKey.Data)
	if err != nil {
		return nil, fmt.Errorf("hovel: parse TLS server private key: %w", err)
	}
	leaf, _ := x509.ParseCertificate(b.Certificate.Data)
	chain := make([][]byte, 0, 1+len(b.Chain))
	chain = append(chain, append([]byte(nil), b.Certificate.Data...))
	for _, member := range b.Chain {
		chain = append(chain, append([]byte(nil), member.Data...))
	}
	curves, err := credentialBundleTLSCurves(b.TLSNamedGroups)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: chain,
			PrivateKey:  privateKey,
			Leaf:        leaf,
		}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
	if b.Purpose == CredentialPurposeMTLSServer || b.Purpose == CredentialPurposeDualRoleMTLS {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = x509.NewCertPool()
		for _, member := range b.TrustAnchors {
			certificate, _ := x509.ParseCertificate(member.Data)
			config.ClientCAs.AddCert(certificate)
		}
	}
	return config, nil
}

// Clear overwrites all bundle byte members owned by b.
func (b *CredentialBundle) Clear() {
	if b == nil {
		return
	}
	clear(b.Certificate.Data)
	clear(b.PublicKey.Data)
	if b.PrivateKey != nil {
		clear(b.PrivateKey.Data)
	}
	for index := range b.Chain {
		clear(b.Chain[index].Data)
	}
	for index := range b.TrustAnchors {
		clear(b.TrustAnchors[index].Data)
	}
	for index := range b.CertificateRevocationLists {
		clear(b.CertificateRevocationLists[index].Data)
	}
	*b = CredentialBundle{}
}

func validateCredentialBundleBinary(
	binary CredentialBundleBinary,
	mediaType string,
	label string,
) ([]byte, error) {
	maximumBytes := credentialBundleMaximumBinaryBytes
	switch mediaType {
	case CredentialBundleMediaCertificate:
		maximumBytes = credentialBundleMaximumCertificateBytes
	case CredentialBundleMediaPublicKey:
		maximumBytes = credentialBundleMaximumPublicKeyBytes
	case CredentialBundleMediaPrivateKey:
		maximumBytes = credentialBundleMaximumPrivateKeyBytes
	case CredentialBundleMediaCRL:
		maximumBytes = credentialBundleMaximumCRLBytes
	}
	if binary.MediaType != mediaType || binary.Encoding != CredentialBundleEncodingBase64DER ||
		len(binary.Data) == 0 || len(binary.Data) > maximumBytes {
		return nil, fmt.Errorf("hovel: credential bundle %s is invalid", label)
	}
	return binary.Data, nil
}

func validateCredentialBundleAggregateSize(bundle CredentialBundle) error {
	total := 0
	add := func(size int) error {
		if size < 0 || size > credentialBundleMaximumBinaryBytes-total {
			return errors.New("hovel: credential bundle binary material exceeds limits")
		}
		total += size
		return nil
	}
	for _, size := range []int{len(bundle.Certificate.Data), len(bundle.PublicKey.Data)} {
		if err := add(size); err != nil {
			return err
		}
	}
	if bundle.PrivateKey != nil {
		if err := add(len(bundle.PrivateKey.Data)); err != nil {
			return err
		}
	}
	for _, members := range [][]CredentialBundleCertificate{bundle.Chain, bundle.TrustAnchors} {
		for _, member := range members {
			if err := add(len(member.Data)); err != nil {
				return err
			}
		}
	}
	for _, member := range bundle.CertificateRevocationLists {
		if err := add(len(member.Data)); err != nil {
			return err
		}
	}
	return nil
}

func parseCredentialBundleCertificate(data []byte, label string) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("hovel: parse credential bundle %s: %w", label, err)
	}
	if !bytes.Equal(certificate.Raw, data) {
		return nil, fmt.Errorf("hovel: credential bundle %s contains trailing data", label)
	}
	return certificate, nil
}

func validateCredentialBundleFingerprint(value string, data []byte, label string) error {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return fmt.Errorf("hovel: credential bundle %s fingerprint is invalid", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("hovel: credential bundle %s fingerprint is invalid", label)
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(decoded, digest[:]) {
		return fmt.Errorf("hovel: credential bundle %s fingerprint does not match", label)
	}
	return nil
}

func validateCredentialKeyEstablishment(policy string, groups []string) error {
	seen := make(map[string]struct{}, len(groups))
	hybrid := 0
	for _, group := range groups {
		if _, err := credentialBundleTLSCurve(group); err != nil {
			return err
		}
		if _, duplicate := seen[group]; duplicate {
			return fmt.Errorf("hovel: duplicate TLS named group %q", group)
		}
		seen[group] = struct{}{}
		if strings.Contains(group, "mlkem") {
			hybrid++
		}
	}
	switch policy {
	case CredentialKeyEstablishmentNotApplicable:
		if len(groups) != 0 {
			return errors.New("hovel: not-applicable key establishment includes TLS groups")
		}
	case CredentialKeyEstablishmentClassicalCompatible:
		if len(groups) == 0 || hybrid != 0 {
			return errors.New("hovel: classical key establishment requires classical TLS groups")
		}
	case CredentialKeyEstablishmentHybridPQPreferred:
		if hybrid == 0 || hybrid == len(groups) {
			return errors.New("hovel: preferred hybrid key establishment requires hybrid and classical TLS groups")
		}
	case CredentialKeyEstablishmentHybridPQRequired:
		if len(groups) == 0 || hybrid != len(groups) {
			return errors.New("hovel: required hybrid key establishment permits only hybrid TLS groups")
		}
	default:
		return fmt.Errorf("hovel: unsupported key-establishment policy %q", policy)
	}
	return nil
}

func credentialBundleTLSCurves(groups []string) ([]tls.CurveID, error) {
	result := make([]tls.CurveID, 0, len(groups))
	for _, group := range groups {
		curve, err := credentialBundleTLSCurve(group)
		if err != nil {
			return nil, err
		}
		result = append(result, curve)
	}
	return result, nil
}

func credentialBundleTLSCurve(group string) (tls.CurveID, error) {
	switch group {
	case "x25519-mlkem768":
		return tls.X25519MLKEM768, nil
	case "secp256r1-mlkem768":
		return tls.SecP256r1MLKEM768, nil
	case "secp384r1-mlkem1024":
		return tls.SecP384r1MLKEM1024, nil
	case "x25519":
		return tls.X25519, nil
	case "secp256r1":
		return tls.CurveP256, nil
	case "secp384r1":
		return tls.CurveP384, nil
	case "secp521r1":
		return tls.CurveP521, nil
	default:
		return 0, fmt.Errorf("hovel: unsupported TLS named group %q", group)
	}
}

func verifyCredentialBundlePurpose(certificate *x509.Certificate, purpose CredentialPurpose) error {
	requireServer := purpose == CredentialPurposeTLSServer ||
		purpose == CredentialPurposeMTLSServer || purpose == CredentialPurposeDualRoleMTLS
	requireClient := purpose == CredentialPurposeTLSClient ||
		purpose == CredentialPurposeMTLSClient || purpose == CredentialPurposeDualRoleMTLS
	requireCodeSigning := purpose == CredentialPurposeCodeSigning
	server, client, codeSigning := false, false, false
	for _, usage := range certificate.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth
		client = client || usage == x509.ExtKeyUsageClientAuth
		codeSigning = codeSigning || usage == x509.ExtKeyUsageCodeSigning
	}
	if requireServer && !server || requireClient && !client || requireCodeSigning && !codeSigning {
		return fmt.Errorf("hovel: credential bundle certificate usages do not satisfy purpose %q", purpose)
	}
	return nil
}

func verifyCredentialBundleChainAt(
	leaf *x509.Certificate,
	chain []*x509.Certificate,
	trust []*x509.Certificate,
	currentTime time.Time,
	purpose CredentialPurpose,
) error {
	current := leaf
	for _, parent := range chain {
		if !bytes.Equal(current.RawIssuer, parent.RawSubject) {
			return errors.New("hovel: credential bundle chain issuer and subject names do not match")
		}
		if err := current.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("hovel: verify credential bundle chain signature: %w", err)
		}
		current = parent
	}
	roots := x509.NewCertPool()
	if len(trust) == 0 {
		if len(chain) != 0 || !bytes.Equal(current.RawIssuer, current.RawSubject) {
			return errors.New("hovel: credential bundle chain does not terminate in a trust anchor")
		}
		if err := current.CheckSignatureFrom(current); err != nil {
			return fmt.Errorf("hovel: verify credential bundle self-signed certificate: %w", err)
		}
		roots.AddCert(current)
		return verifyCredentialBundlePKIX(leaf, chain, roots, currentTime, purpose)
	}
	terminatesAtTrust := false
	for _, anchor := range trust {
		if err := anchor.CheckSignatureFrom(anchor); err != nil {
			return fmt.Errorf("hovel: verify credential bundle trust anchor: %w", err)
		}
		roots.AddCert(anchor)
		if bytes.Equal(current.Raw, anchor.Raw) ||
			bytes.Equal(current.RawIssuer, anchor.RawSubject) && current.CheckSignatureFrom(anchor) == nil {
			terminatesAtTrust = true
		}
	}
	if !terminatesAtTrust {
		return errors.New("hovel: credential bundle chain does not validate to a supplied trust anchor")
	}
	return verifyCredentialBundlePKIX(leaf, chain, roots, currentTime, purpose)
}

func verifyCredentialBundlePKIX(
	leaf *x509.Certificate,
	chain []*x509.Certificate,
	roots *x509.CertPool,
	currentTime time.Time,
	purpose CredentialPurpose,
) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range chain {
		intermediates.AddCert(certificate)
	}
	for _, usage := range credentialBundleKeyUsages(purpose) {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   currentTime,
			KeyUsages:     []x509.ExtKeyUsage{usage},
		}); err != nil {
			return fmt.Errorf("hovel: verify credential bundle certificate path: %w", err)
		}
	}
	return nil
}

func credentialBundleKeyUsages(purpose CredentialPurpose) []x509.ExtKeyUsage {
	switch purpose {
	case CredentialPurposeTLSServer, CredentialPurposeMTLSServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case CredentialPurposeTLSClient, CredentialPurposeMTLSClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case CredentialPurposeDualRoleMTLS:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case CredentialPurposeCodeSigning:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
}
