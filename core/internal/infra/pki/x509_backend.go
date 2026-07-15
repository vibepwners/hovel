package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const BackendVersion = "1"

const (
	crlReasonUnspecified          = 0
	crlReasonKeyCompromise        = 1
	crlReasonCACompromise         = 2
	crlReasonAffiliationChanged   = 3
	crlReasonSuperseded           = 4
	crlReasonCessationOfOperation = 5
	crlReasonCertificateHold      = 6
	crlReasonPrivilegeWithdrawn   = 9
	crlReasonAACompromise         = 10
)

type Backend struct {
	descriptor domainpki.BackendDescriptor
}

func NewBackend() Backend {
	args := domainpki.BackendDescriptorArgs{
		SchemaVersion: domainpki.BackendSchemaV1,
		ID:            domainpki.BackendBuiltinX509,
		Version:       BackendVersion,
		KeyAlgorithms: []domainpki.KeyAlgorithm{
			domainpki.KeyAlgorithmECDSA,
			domainpki.KeyAlgorithmRSA,
			domainpki.KeyAlgorithmEd25519,
		},
		SignatureAlgorithms: []domainpki.SignatureAlgorithm{
			domainpki.SignatureAlgorithmECDSASHA256,
			domainpki.SignatureAlgorithmECDSASHA384,
			domainpki.SignatureAlgorithmECDSASHA512,
			domainpki.SignatureAlgorithmSHA256WithRSA,
			domainpki.SignatureAlgorithmSHA384WithRSA,
			domainpki.SignatureAlgorithmSHA512WithRSA,
			domainpki.SignatureAlgorithmSHA256WithRSAPSS,
			domainpki.SignatureAlgorithmSHA384WithRSAPSS,
			domainpki.SignatureAlgorithmSHA512WithRSAPSS,
			domainpki.SignatureAlgorithmEd25519,
		},
		SupportsImport: false,
		SupportsExport: true,
		SupportsCRL:    true,
		SupportsCSR:    false,
		SupportsCustom: true,
	}
	descriptor, err := domainpki.NewBackendDescriptor(args)
	if err != nil {
		panic(err)
	}
	return Backend{descriptor: descriptor}
}

func (b Backend) Descriptor() domainpki.BackendDescriptor {
	return b.descriptor.Clone()
}

func (b Backend) GenerateKey(ctx context.Context, id domainpki.KeyID, spec domainpki.KeySpec) (apppki.KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	if id == "" {
		return apppki.KeyMaterial{}, errors.New("pki: key id is required")
	}
	if spec.Source != domainpki.KeySourceGenerated {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: builtin key generation does not support source %q", spec.Source)
	}
	if err := spec.Validate(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	var privateKey crypto.Signer
	var err error
	switch spec.Algorithm {
	case domainpki.KeyAlgorithmECDSA:
		privateKey, err = ecdsa.GenerateKey(curve(spec.Curve), rand.Reader)
	case domainpki.KeyAlgorithmRSA:
		privateKey, err = rsa.GenerateKey(rand.Reader, spec.RSABits)
	case domainpki.KeyAlgorithmEd25519:
		_, key, generateErr := ed25519.GenerateKey(rand.Reader)
		privateKey, err = key, generateErr
	default:
		return apppki.KeyMaterial{}, fmt.Errorf("pki: unsupported key algorithm %q", spec.Algorithm)
	}
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: generate key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: marshal pkcs8 private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: marshal subject public key info: %w", err)
	}
	return apppki.KeyMaterial{
		ID:              id,
		Algorithm:       spec.Algorithm,
		PublicKeySPKI:   publicDER,
		PrivateKeyPKCS8: privateDER,
	}, nil
}

func (b Backend) Issue(ctx context.Context, req apppki.IssueRequest) (apppki.IssuedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuedCertificate{}, err
	}
	if err := req.Template.Validate(); err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: validate certificate template: %w", err)
	}
	if req.Template.BasicConstraints.IsCA && req.Template.SubjectKeyIdentifier.Mode == domainpki.IdentifierModeOmitted {
		return apppki.IssuedCertificate{}, errors.New("pki: builtin x509 backend cannot omit the subject key identifier from a ca certificate")
	}
	if err := req.Signer.Validate(); err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: validate builtin signer: %w", err)
	}
	if req.Signer.ExternalHandle != nil {
		return apppki.IssuedCertificate{}, errors.New("pki: builtin x509 backend cannot use an external signer handle")
	}
	publicKey, err := x509.ParsePKIXPublicKey(req.SubjectPublicKeySPKI)
	if err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: parse subject public key info: %w", err)
	}
	privateKey, err := parseSigner(req.Signer.PrivateKeyPKCS8)
	if err != nil {
		return apppki.IssuedCertificate{}, err
	}
	if err := validateSignerAlgorithm(privateKey, req.Template.SignatureAlgorithm); err != nil {
		return apppki.IssuedCertificate{}, err
	}
	template, err := certificateTemplate(req.Template, req.SubjectPublicKeySPKI)
	if err != nil {
		return apppki.IssuedCertificate{}, err
	}
	parent := template
	if len(req.IssuerCertificateDER) != 0 {
		parent, err = x509.ParseCertificate(req.IssuerCertificateDER)
		if err != nil {
			return apppki.IssuedCertificate{}, fmt.Errorf("pki: parse issuer certificate: %w", err)
		}
	}
	switch req.Template.AuthorityKeyIdentifier.Mode {
	case domainpki.IdentifierModeAutomatic:
		if len(req.IssuerCertificateDER) != 0 {
			template.AuthorityKeyId = append([]byte(nil), parent.SubjectKeyId...)
		} else {
			template.AuthorityKeyId = append([]byte(nil), template.SubjectKeyId...)
		}
	case domainpki.IdentifierModeExplicit:
		parentCopy := *template
		if len(req.IssuerCertificateDER) != 0 {
			parentCopy = *parent
		}
		parentCopy.SubjectKeyId = append([]byte(nil), template.AuthorityKeyId...)
		parent = &parentCopy
	case domainpki.IdentifierModeOmitted:
		parentCopy := *template
		if len(req.IssuerCertificateDER) != 0 {
			parentCopy = *parent
		}
		parentCopy.SubjectKeyId = nil
		parent = &parentCopy
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: create certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: parse issued certificate: %w", err)
	}
	fingerprint := sha256.Sum256(certificateDER)
	return apppki.IssuedCertificate{
		CertificateDER:     certificateDER,
		PublicKeySPKI:      append([]byte(nil), certificate.RawSubjectPublicKeyInfo...),
		FingerprintSHA256:  hex.EncodeToString(fingerprint[:]),
		SubjectKeyID:       append([]byte(nil), certificate.SubjectKeyId...),
		AuthorityKeyID:     append([]byte(nil), certificate.AuthorityKeyId...),
		SignatureAlgorithm: domainSignatureAlgorithm(certificate.SignatureAlgorithm),
	}, nil
}

func (b Backend) IssueCRL(ctx context.Context, req apppki.CRLIssueRequest) (apppki.IssuedCRL, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuedCRL{}, err
	}
	if err := req.Validate(); err != nil {
		return apppki.IssuedCRL{}, err
	}
	if req.Signer.ExternalHandle != nil {
		return apppki.IssuedCRL{}, errors.New("pki: builtin x509 backend cannot issue a crl with an external signer handle")
	}
	issuer, err := x509.ParseCertificate(req.IssuerCertificateDER)
	if err != nil {
		return apppki.IssuedCRL{}, fmt.Errorf("pki: parse crl issuer certificate: %w", err)
	}
	if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return apppki.IssuedCRL{}, errors.New("pki: crl issuer certificate is not authorized for crl signing")
	}
	signer, err := parseSigner(req.Signer.PrivateKeyPKCS8)
	if err != nil {
		return apppki.IssuedCRL{}, err
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return apppki.IssuedCRL{}, fmt.Errorf("pki: marshal crl signer public key: %w", err)
	}
	if !bytes.Equal(publicSPKI, issuer.RawSubjectPublicKeyInfo) {
		return apppki.IssuedCRL{}, errors.New("pki: crl signer does not match issuer certificate")
	}
	entries := make([]x509.RevocationListEntry, 0, len(req.Entries))
	for _, entry := range req.Entries {
		serial, err := entry.SerialNumber.Bytes()
		if err != nil {
			return apppki.IssuedCRL{}, err
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: new(big.Int).SetBytes(serial), RevocationTime: entry.RevokedAt,
			ReasonCode: revocationReasonCode(entry.Reason),
		})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: entries, Number: new(big.Int).SetUint64(req.Number),
		ThisUpdate: req.ThisUpdate, NextUpdate: req.NextUpdate,
		SignatureAlgorithm: signatureAlgorithm(req.SignatureAlgorithm),
	}, issuer, signer)
	if err != nil {
		return apppki.IssuedCRL{}, fmt.Errorf("pki: create certificate revocation list: %w", err)
	}
	fingerprint := sha256.Sum256(crlDER)
	return apppki.IssuedCRL{
		CRLDER: crlDER, FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm: req.SignatureAlgorithm,
	}, nil
}

func revocationReasonCode(reason domainpki.RevocationReason) int {
	switch reason {
	case domainpki.RevocationReasonKeyCompromise:
		return crlReasonKeyCompromise
	case domainpki.RevocationReasonCACompromise:
		return crlReasonCACompromise
	case domainpki.RevocationReasonAffiliationChanged:
		return crlReasonAffiliationChanged
	case domainpki.RevocationReasonSuperseded:
		return crlReasonSuperseded
	case domainpki.RevocationReasonCessationOfOperation:
		return crlReasonCessationOfOperation
	case domainpki.RevocationReasonCertificateHold:
		return crlReasonCertificateHold
	case domainpki.RevocationReasonPrivilegeWithdrawn:
		return crlReasonPrivilegeWithdrawn
	case domainpki.RevocationReasonAACompromise:
		return crlReasonAACompromise
	default:
		return crlReasonUnspecified
	}
}

func curve(value domainpki.EllipticCurve) elliptic.Curve {
	switch value {
	case domainpki.EllipticCurveP384:
		return elliptic.P384()
	case domainpki.EllipticCurveP521:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

func parseSigner(der []byte) (crypto.Signer, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse pkcs8 signer: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pki: private key type %T cannot sign", parsed)
	}
	return signer, nil
}

func validateSignerAlgorithm(signer crypto.Signer, algorithm domainpki.SignatureAlgorithm) error {
	if algorithm == "" || algorithm == domainpki.SignatureAlgorithmAuto {
		return nil
	}
	compatible := false
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		compatible = algorithm == domainpki.SignatureAlgorithmECDSASHA256 ||
			algorithm == domainpki.SignatureAlgorithmECDSASHA384 ||
			algorithm == domainpki.SignatureAlgorithmECDSASHA512
	case *rsa.PublicKey:
		compatible = algorithm == domainpki.SignatureAlgorithmSHA256WithRSA ||
			algorithm == domainpki.SignatureAlgorithmSHA384WithRSA ||
			algorithm == domainpki.SignatureAlgorithmSHA512WithRSA ||
			algorithm == domainpki.SignatureAlgorithmSHA256WithRSAPSS ||
			algorithm == domainpki.SignatureAlgorithmSHA384WithRSAPSS ||
			algorithm == domainpki.SignatureAlgorithmSHA512WithRSAPSS
	case ed25519.PublicKey:
		compatible = algorithm == domainpki.SignatureAlgorithmEd25519
	}
	if !compatible {
		return fmt.Errorf("pki: signature algorithm %q is incompatible with signer key type %T", algorithm, signer.Public())
	}
	return nil
}

func certificateTemplate(template domainpki.CertificateTemplate, spki []byte) (*x509.Certificate, error) {
	serialBytes, err := template.SerialNumber.Bytes()
	if err != nil {
		return nil, err
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() <= 0 {
		return nil, errors.New("pki: serial number must be positive")
	}
	subject, err := distinguishedName(template.Subject)
	if err != nil {
		return nil, err
	}
	ipAddresses, err := parseIPs(template.SubjectAlternativeNames.IPAddresses)
	if err != nil {
		return nil, err
	}
	uris, err := parseURIs(template.SubjectAlternativeNames.URIs)
	if err != nil {
		return nil, err
	}
	permittedRanges, err := parseCIDRs(template.NameConstraints.PermittedIPRanges)
	if err != nil {
		return nil, err
	}
	excludedRanges, err := parseCIDRs(template.NameConstraints.ExcludedIPRanges)
	if err != nil {
		return nil, err
	}
	policyOIDs, err := objectIdentifiers(template.PolicyOIDs)
	if err != nil {
		return nil, err
	}
	unknownEKUs, err := objectIdentifiers(template.UnknownExtendedKeyUsages)
	if err != nil {
		return nil, err
	}
	extraExtensions, err := standardExtensions(template)
	if err != nil {
		return nil, err
	}
	custom, err := customExtensions(template.CustomExtensions)
	if err != nil {
		return nil, err
	}
	extraExtensions = append(extraExtensions, custom...)
	result := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     subject,
		NotBefore:                   template.NotBefore.UTC(),
		NotAfter:                    template.NotAfter.UTC(),
		SignatureAlgorithm:          signatureAlgorithm(template.SignatureAlgorithm),
		KeyUsage:                    keyUsage(template.KeyUsage),
		ExtKeyUsage:                 extendedKeyUsages(template.ExtendedKeyUsages),
		UnknownExtKeyUsage:          unknownEKUs,
		BasicConstraintsValid:       true,
		IsCA:                        template.BasicConstraints.IsCA,
		MaxPathLen:                  x509MaxPathLen(template.BasicConstraints),
		MaxPathLenZero:              template.BasicConstraints.MaxPathLenZero,
		DNSNames:                    append([]string(nil), template.SubjectAlternativeNames.DNSNames...),
		EmailAddresses:              append([]string(nil), template.SubjectAlternativeNames.EmailAddresses...),
		IPAddresses:                 ipAddresses,
		URIs:                        uris,
		SubjectKeyId:                identifier(template.SubjectKeyIdentifier, spki),
		AuthorityKeyId:              explicitIdentifier(template.AuthorityKeyIdentifier),
		OCSPServer:                  append([]string(nil), template.OCSPServers...),
		IssuingCertificateURL:       append([]string(nil), template.IssuingCertificateURLs...),
		CRLDistributionPoints:       append([]string(nil), template.CRLDistributionPoints...),
		PolicyIdentifiers:           policyOIDs,
		PermittedDNSDomainsCritical: template.NameConstraints.Critical,
		PermittedDNSDomains:         append([]string(nil), template.NameConstraints.PermittedDNSDomains...),
		ExcludedDNSDomains:          append([]string(nil), template.NameConstraints.ExcludedDNSDomains...),
		PermittedIPRanges:           permittedRanges,
		ExcludedIPRanges:            excludedRanges,
		PermittedEmailAddresses:     append([]string(nil), template.NameConstraints.PermittedEmailAddresses...),
		ExcludedEmailAddresses:      append([]string(nil), template.NameConstraints.ExcludedEmailAddresses...),
		PermittedURIDomains:         append([]string(nil), template.NameConstraints.PermittedURIDomains...),
		ExcludedURIDomains:          append([]string(nil), template.NameConstraints.ExcludedURIDomains...),
		ExtraExtensions:             extraExtensions,
	}
	return result, nil
}

func x509MaxPathLen(constraints domainpki.BasicConstraints) int {
	if !constraints.IsCA || constraints.MaxPathLen == 0 && !constraints.MaxPathLenZero {
		return -1
	}
	return constraints.MaxPathLen
}

func distinguishedName(name domainpki.DistinguishedName) (pkix.Name, error) {
	result := pkix.Name{
		CommonName:         name.CommonName,
		SerialNumber:       name.SerialNumber,
		Country:            append([]string(nil), name.Country...),
		Organization:       append([]string(nil), name.Organization...),
		OrganizationalUnit: append([]string(nil), name.OrganizationalUnit...),
		Locality:           append([]string(nil), name.Locality...),
		Province:           append([]string(nil), name.Province...),
		StreetAddress:      append([]string(nil), name.StreetAddress...),
		PostalCode:         append([]string(nil), name.PostalCode...),
	}
	for _, attribute := range name.ExtraNames {
		oid, err := objectIdentifier(attribute.OID)
		if err != nil {
			return pkix.Name{}, err
		}
		value, err := distinguishedNameValue(attribute.Value, attribute.StringType)
		if err != nil {
			return pkix.Name{}, fmt.Errorf("pki: encode distinguished name attribute %q: %w", attribute.OID, err)
		}
		result.ExtraNames = append(result.ExtraNames, pkix.AttributeTypeAndValue{Type: oid, Value: value})
	}
	return result, nil
}

func distinguishedNameValue(value string, stringType domainpki.ASN1StringType) (any, error) {
	if stringType == "" {
		return value, nil
	}
	parameter := string(stringType)
	encoded, err := asn1.MarshalWithParams(value, parameter)
	if err != nil {
		return nil, err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func parseIPs(values []string) ([]net.IP, error) {
	result := make([]net.IP, 0, len(values))
	for _, value := range values {
		parsed := net.ParseIP(value)
		if parsed == nil {
			return nil, fmt.Errorf("pki: parse ip address %q", value)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseURIs(values []string) ([]*url.URL, error) {
	result := make([]*url.URL, 0, len(values))
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" {
			return nil, fmt.Errorf("pki: parse uri %q", value)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, parsed, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("pki: parse ip range %q: %w", value, err)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func objectIdentifiers(values []domainpki.OID) ([]asn1.ObjectIdentifier, error) {
	result := make([]asn1.ObjectIdentifier, 0, len(values))
	for _, value := range values {
		parsed, err := objectIdentifier(value)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

func objectIdentifier(value domainpki.OID) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(string(value), ".")
	result := make(asn1.ObjectIdentifier, len(parts))
	for index, part := range parts {
		if _, err := fmt.Sscan(part, &result[index]); err != nil {
			return nil, fmt.Errorf("pki: parse oid %q: %w", value, err)
		}
	}
	return result, nil
}

var (
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionCRLDistribution     = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCRLNumber           = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionCRLReason           = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtensionCertificatePolicy   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
)

type basicConstraintsDER struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func standardExtensions(template domainpki.CertificateTemplate) ([]pkix.Extension, error) {
	value, err := asn1.Marshal(basicConstraintsDER{
		IsCA:       template.BasicConstraints.IsCA,
		MaxPathLen: x509MaxPathLen(template.BasicConstraints),
	})
	if err != nil {
		return nil, fmt.Errorf("pki: marshal basic constraints: %w", err)
	}
	return []pkix.Extension{{
		Id:       oidExtensionBasicConstraints,
		Critical: template.BasicConstraints.Critical,
		Value:    value,
	}}, nil
}

func customExtensions(values []domainpki.CustomExtension) ([]pkix.Extension, error) {
	result := make([]pkix.Extension, 0, len(values))
	for _, value := range values {
		oid, err := objectIdentifier(value.OID)
		if err != nil {
			return nil, err
		}
		result = append(result, pkix.Extension{Id: oid, Critical: value.Critical, Value: append([]byte(nil), value.DER...)})
	}
	return result, nil
}

func identifier(value domainpki.KeyIdentifier, spki []byte) []byte {
	switch value.Mode {
	case domainpki.IdentifierModeExplicit:
		return append([]byte(nil), value.Value...)
	case domainpki.IdentifierModeAutomatic:
		digest := sha256.Sum256(spki)
		return append([]byte(nil), digest[:20]...)
	default:
		return nil
	}
}

func explicitIdentifier(value domainpki.KeyIdentifier) []byte {
	if value.Mode == domainpki.IdentifierModeExplicit {
		return append([]byte(nil), value.Value...)
	}
	return nil
}

func signatureAlgorithm(value domainpki.SignatureAlgorithm) x509.SignatureAlgorithm {
	switch value {
	case domainpki.SignatureAlgorithmECDSASHA256:
		return x509.ECDSAWithSHA256
	case domainpki.SignatureAlgorithmECDSASHA384:
		return x509.ECDSAWithSHA384
	case domainpki.SignatureAlgorithmECDSASHA512:
		return x509.ECDSAWithSHA512
	case domainpki.SignatureAlgorithmSHA256WithRSA:
		return x509.SHA256WithRSA
	case domainpki.SignatureAlgorithmSHA384WithRSA:
		return x509.SHA384WithRSA
	case domainpki.SignatureAlgorithmSHA512WithRSA:
		return x509.SHA512WithRSA
	case domainpki.SignatureAlgorithmSHA256WithRSAPSS:
		return x509.SHA256WithRSAPSS
	case domainpki.SignatureAlgorithmSHA384WithRSAPSS:
		return x509.SHA384WithRSAPSS
	case domainpki.SignatureAlgorithmSHA512WithRSAPSS:
		return x509.SHA512WithRSAPSS
	case domainpki.SignatureAlgorithmEd25519:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func domainSignatureAlgorithm(value x509.SignatureAlgorithm) domainpki.SignatureAlgorithm {
	switch value {
	case x509.ECDSAWithSHA256:
		return domainpki.SignatureAlgorithmECDSASHA256
	case x509.ECDSAWithSHA384:
		return domainpki.SignatureAlgorithmECDSASHA384
	case x509.ECDSAWithSHA512:
		return domainpki.SignatureAlgorithmECDSASHA512
	case x509.SHA256WithRSA:
		return domainpki.SignatureAlgorithmSHA256WithRSA
	case x509.SHA384WithRSA:
		return domainpki.SignatureAlgorithmSHA384WithRSA
	case x509.SHA512WithRSA:
		return domainpki.SignatureAlgorithmSHA512WithRSA
	case x509.SHA256WithRSAPSS:
		return domainpki.SignatureAlgorithmSHA256WithRSAPSS
	case x509.SHA384WithRSAPSS:
		return domainpki.SignatureAlgorithmSHA384WithRSAPSS
	case x509.SHA512WithRSAPSS:
		return domainpki.SignatureAlgorithmSHA512WithRSAPSS
	case x509.PureEd25519:
		return domainpki.SignatureAlgorithmEd25519
	default:
		return ""
	}
}

func keyUsage(value domainpki.KeyUsage) x509.KeyUsage {
	var result x509.KeyUsage
	mapping := []struct {
		domain domainpki.KeyUsage
		x509   x509.KeyUsage
	}{
		{domainpki.KeyUsageDigitalSignature, x509.KeyUsageDigitalSignature},
		{domainpki.KeyUsageContentCommitment, x509.KeyUsageContentCommitment},
		{domainpki.KeyUsageKeyEncipherment, x509.KeyUsageKeyEncipherment},
		{domainpki.KeyUsageDataEncipherment, x509.KeyUsageDataEncipherment},
		{domainpki.KeyUsageKeyAgreement, x509.KeyUsageKeyAgreement},
		{domainpki.KeyUsageCertificateSign, x509.KeyUsageCertSign},
		{domainpki.KeyUsageCRLSign, x509.KeyUsageCRLSign},
		{domainpki.KeyUsageEncipherOnly, x509.KeyUsageEncipherOnly},
		{domainpki.KeyUsageDecipherOnly, x509.KeyUsageDecipherOnly},
	}
	for _, pair := range mapping {
		if value&pair.domain != 0 {
			result |= pair.x509
		}
	}
	return result
}

func extendedKeyUsages(values []domainpki.ExtendedKeyUsage) []x509.ExtKeyUsage {
	result := make([]x509.ExtKeyUsage, 0, len(values))
	for _, value := range values {
		switch value {
		case domainpki.ExtendedKeyUsageAny:
			result = append(result, x509.ExtKeyUsageAny)
		case domainpki.ExtendedKeyUsageServerAuth:
			result = append(result, x509.ExtKeyUsageServerAuth)
		case domainpki.ExtendedKeyUsageClientAuth:
			result = append(result, x509.ExtKeyUsageClientAuth)
		case domainpki.ExtendedKeyUsageCodeSigning:
			result = append(result, x509.ExtKeyUsageCodeSigning)
		case domainpki.ExtendedKeyUsageEmailProtection:
			result = append(result, x509.ExtKeyUsageEmailProtection)
		case domainpki.ExtendedKeyUsageTimeStamping:
			result = append(result, x509.ExtKeyUsageTimeStamping)
		case domainpki.ExtendedKeyUsageOCSPSigning:
			result = append(result, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return result
}

type Validator struct{}

func NewValidator() Validator {
	return Validator{}
}

func (Validator) ValidateKey(ctx context.Context, req apppki.KeyValidationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := req.Spec.Validate(); err != nil {
		return fmt.Errorf("pki: validate expected key specification: %w", err)
	}
	if err := req.Material.Validate(); err != nil {
		return err
	}
	if req.Material.Algorithm != req.Spec.Algorithm {
		return errors.New("pki: generated key algorithm differs from key specification")
	}
	privateKey, err := parseSigner(req.Material.PrivateKeyPKCS8)
	if err != nil {
		return err
	}
	privateSPKI, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("pki: marshal generated private key public half: %w", err)
	}
	if !bytes.Equal(privateSPKI, req.Material.PublicKeySPKI) {
		return errors.New("pki: generated private and public keys do not match")
	}
	publicKey, err := x509.ParsePKIXPublicKey(req.Material.PublicKeySPKI)
	if err != nil {
		return fmt.Errorf("pki: parse generated public key: %w", err)
	}
	return validatePublicKeySpecification(publicKey, req.Spec)
}

func (Validator) ValidateBundle(ctx context.Context, bundle domainpki.Bundle, currentTime time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return VerifyBundleAt(bundle, currentTime)
}

func validatePublicKeySpecification(publicKey any, spec domainpki.KeySpec) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if spec.Algorithm != domainpki.KeyAlgorithmECDSA || key.Curve.Params().Name != string(spec.Curve) {
			return errors.New("pki: generated ecdsa key differs from key specification")
		}
	case *rsa.PublicKey:
		if spec.Algorithm != domainpki.KeyAlgorithmRSA || key.N.BitLen() != spec.RSABits {
			return errors.New("pki: generated rsa key differs from key specification")
		}
	case ed25519.PublicKey:
		if spec.Algorithm != domainpki.KeyAlgorithmEd25519 || len(key) != ed25519.PublicKeySize {
			return errors.New("pki: generated ed25519 key differs from key specification")
		}
	default:
		return fmt.Errorf("pki: unsupported generated public key type %T", publicKey)
	}
	return nil
}

func (v Validator) ValidateIssued(ctx context.Context, req apppki.ValidationRequest) (apppki.IssuedCertificate, error) {
	if err := v.validateIssued(ctx, req); err != nil {
		return apppki.IssuedCertificate{}, err
	}
	certificate, err := x509.ParseCertificate(req.CertificateDER)
	if err != nil {
		return apppki.IssuedCertificate{}, fmt.Errorf("pki: parse validated certificate: %w", err)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return apppki.IssuedCertificate{
		CertificateDER:     append([]byte(nil), certificate.Raw...),
		PublicKeySPKI:      append([]byte(nil), certificate.RawSubjectPublicKeyInfo...),
		FingerprintSHA256:  hex.EncodeToString(fingerprint[:]),
		SubjectKeyID:       append([]byte(nil), certificate.SubjectKeyId...),
		AuthorityKeyID:     append([]byte(nil), certificate.AuthorityKeyId...),
		SignatureAlgorithm: domainSignatureAlgorithm(certificate.SignatureAlgorithm),
	}, nil
}

func (Validator) ValidateCRL(
	ctx context.Context,
	req apppki.CRLValidationRequest,
	encoded []byte,
) (apppki.CRLValidationResult, error) {
	issued, err := validateCRL(ctx, req, encoded)
	if err != nil {
		if ctx.Err() != nil {
			return apppki.CRLValidationResult{}, err
		}
		return apppki.NewRejectedCRLValidation(apppki.CRLValidationRejectionInvalidCRL, err.Error())
	}
	return apppki.NewAcceptedCRLValidation(issued)
}

func validateCRL(ctx context.Context, req apppki.CRLValidationRequest, encoded []byte) (apppki.IssuedCRL, error) {
	if err := ctx.Err(); err != nil {
		return apppki.IssuedCRL{}, err
	}
	if err := req.Validate(); err != nil {
		return apppki.IssuedCRL{}, err
	}
	if len(encoded) == 0 || len(encoded) > domainpki.MaximumCRLDERBytes {
		return apppki.IssuedCRL{}, errors.New("pki: issued crl der is empty or too large")
	}
	issuer, err := x509.ParseCertificate(req.IssuerCertificateDER)
	if err != nil {
		return apppki.IssuedCRL{}, fmt.Errorf("pki: parse validated crl issuer: %w", err)
	}
	if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return apppki.IssuedCRL{}, errors.New("pki: crl issuer is not an authorized certificate authority")
	}
	crl, err := x509.ParseRevocationList(encoded)
	if err != nil {
		return apppki.IssuedCRL{}, fmt.Errorf("pki: parse issued crl: %w", err)
	}
	if crl.CheckSignatureFrom(issuer) != nil || !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return apppki.IssuedCRL{}, errors.New("pki: issued crl does not validate to its issuer")
	}
	if domainSignatureAlgorithm(crl.SignatureAlgorithm) != req.SignatureAlgorithm {
		return apppki.IssuedCRL{}, errors.New("pki: issued crl signature algorithm does not match its request")
	}
	if err := validateCRLExtensions(crl, issuer, req.Number); err != nil {
		return apppki.IssuedCRL{}, err
	}
	if crl.Number == nil || crl.Number.Sign() <= 0 || crl.Number.BitLen() > 63 || crl.Number.Uint64() != req.Number ||
		!crl.ThisUpdate.Equal(req.ThisUpdate) || !crl.NextUpdate.Equal(req.NextUpdate) {
		return apppki.IssuedCRL{}, errors.New("pki: issued crl metadata does not match its request")
	}
	if len(crl.RevokedCertificateEntries) != len(req.Entries) {
		return apppki.IssuedCRL{}, errors.New("pki: issued crl entry count does not match its request")
	}
	for index, expected := range req.Entries {
		actual := crl.RevokedCertificateEntries[index]
		serialBytes, err := expected.SerialNumber.Bytes()
		if err != nil {
			return apppki.IssuedCRL{}, err
		}
		if actual.SerialNumber == nil || actual.SerialNumber.Cmp(new(big.Int).SetBytes(serialBytes)) != 0 ||
			!actual.RevocationTime.Equal(expected.RevokedAt) || actual.ReasonCode != revocationReasonCode(expected.Reason) {
			return apppki.IssuedCRL{}, errors.New("pki: issued crl entries do not match their request")
		}
		if err := validateCRLEntryExtensions(actual, revocationReasonCode(expected.Reason)); err != nil {
			return apppki.IssuedCRL{}, err
		}
	}
	fingerprint := sha256.Sum256(crl.Raw)
	return apppki.IssuedCRL{
		CRLDER: append([]byte(nil), crl.Raw...), FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm: domainSignatureAlgorithm(crl.SignatureAlgorithm),
	}, nil
}

func validateCRLExtensions(crl *x509.RevocationList, issuer *x509.Certificate, expectedNumber uint64) error {
	if len(issuer.SubjectKeyId) == 0 || !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("pki: issued crl authority key identifier does not match its issuer")
	}
	if len(crl.Extensions) != 2 {
		return errors.New("pki: issued crl must contain exactly authority key identifier and crl number extensions")
	}
	seenAuthorityKeyID := false
	seenCRLNumber := false
	for _, extension := range crl.Extensions {
		if extension.Critical {
			return errors.New("pki: issued crl contains an unexpected critical extension")
		}
		switch {
		case extension.Id.Equal(oidExtensionAuthorityKeyID):
			if seenAuthorityKeyID {
				return errors.New("pki: issued crl contains duplicate authority key identifier extensions")
			}
			seenAuthorityKeyID = true
			if err := validateAuthorityKeyIDExtension(extension.Value, issuer.SubjectKeyId); err != nil {
				return err
			}
		case extension.Id.Equal(oidExtensionCRLNumber):
			if seenCRLNumber {
				return errors.New("pki: issued crl contains duplicate crl number extensions")
			}
			seenCRLNumber = true
			if err := validateCRLNumberExtension(extension.Value, expectedNumber); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pki: issued crl contains unsupported extension %s", extension.Id.String())
		}
	}
	if !seenAuthorityKeyID || !seenCRLNumber {
		return errors.New("pki: issued crl is missing a required extension")
	}
	return nil
}

type authorityKeyIdentifierExtension struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

func validateAuthorityKeyIDExtension(encoded, expected []byte) error {
	var value authorityKeyIdentifierExtension
	rest, err := asn1.Unmarshal(encoded, &value)
	if err != nil || len(rest) != 0 || !bytes.Equal(value.KeyIdentifier, expected) {
		return errors.New("pki: issued crl authority key identifier extension is invalid")
	}
	canonical, err := asn1.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("pki: issued crl authority key identifier extension is not canonical der")
	}
	return nil
}

func validateCRLNumberExtension(encoded []byte, expected uint64) error {
	var value *big.Int
	rest, err := asn1.Unmarshal(encoded, &value)
	if err != nil || len(rest) != 0 || value == nil || value.Sign() <= 0 || value.BitLen() > 63 || value.Uint64() != expected {
		return errors.New("pki: issued crl number extension is invalid")
	}
	canonical, err := asn1.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("pki: issued crl number extension is not canonical der")
	}
	return nil
}

func validateCRLEntryExtensions(entry x509.RevocationListEntry, reasonCode int) error {
	if reasonCode == crlReasonUnspecified {
		if len(entry.Extensions) != 0 {
			return errors.New("pki: unspecified crl entry contains unexpected extensions")
		}
		return nil
	}
	if len(entry.Extensions) != 1 || !entry.Extensions[0].Id.Equal(oidExtensionCRLReason) || entry.Extensions[0].Critical {
		return errors.New("pki: crl entry reason extension does not match its request")
	}
	var value asn1.Enumerated
	rest, err := asn1.Unmarshal(entry.Extensions[0].Value, &value)
	if err != nil || len(rest) != 0 || int(value) != reasonCode {
		return errors.New("pki: crl entry reason extension value does not match its request")
	}
	canonical, err := asn1.Marshal(value)
	if err != nil || !bytes.Equal(canonical, entry.Extensions[0].Value) {
		return errors.New("pki: crl entry reason extension is not canonical der")
	}
	return nil
}

func (Validator) validateIssued(ctx context.Context, req apppki.ValidationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := req.Template.Validate(); err != nil {
		return fmt.Errorf("pki: validate expected template: %w", err)
	}
	certificate, err := x509.ParseCertificate(req.CertificateDER)
	if err != nil {
		return fmt.Errorf("pki: parse issued certificate: %w", err)
	}
	if !slices.Equal(certificate.RawSubjectPublicKeyInfo, req.SubjectPublicKeySPKI) {
		return errors.New("pki: issued certificate public key does not match requested key")
	}
	serialBytes, err := req.Template.SerialNumber.Bytes()
	if err != nil {
		return err
	}
	if certificate.SerialNumber.Cmp(new(big.Int).SetBytes(serialBytes)) != 0 {
		return errors.New("pki: issued certificate serial number differs from template")
	}
	if !certificate.NotBefore.Equal(req.Template.NotBefore) || !certificate.NotAfter.Equal(req.Template.NotAfter) {
		return errors.New("pki: issued certificate validity differs from template")
	}
	expectedSubject, err := distinguishedName(req.Template.Subject)
	if err != nil {
		return err
	}
	expectedRawSubject, err := asn1.Marshal(expectedSubject.ToRDNSequence())
	if err != nil {
		return fmt.Errorf("pki: marshal expected subject: %w", err)
	}
	if !bytes.Equal(certificate.RawSubject, expectedRawSubject) {
		return errors.New("pki: issued certificate subject differs from template")
	}
	if certificate.IsCA != req.Template.BasicConstraints.IsCA || certificate.MaxPathLen != x509MaxPathLen(req.Template.BasicConstraints) || certificate.MaxPathLenZero != req.Template.BasicConstraints.MaxPathLenZero {
		return errors.New("pki: issued certificate basic constraints differ from template")
	}
	basicConstraintsExtension, ok := findExtension(certificate.Extensions, oidExtensionBasicConstraints)
	if !ok || basicConstraintsExtension.Critical != req.Template.BasicConstraints.Critical {
		return errors.New("pki: issued certificate basic constraints criticality differs from template")
	}
	expectedBasicConstraints, err := standardExtensions(req.Template)
	if err != nil {
		return err
	}
	if !bytes.Equal(basicConstraintsExtension.Value, expectedBasicConstraints[0].Value) {
		return errors.New("pki: issued certificate basic constraints encoding differs from template")
	}
	if req.Template.SignatureAlgorithm != "" && req.Template.SignatureAlgorithm != domainpki.SignatureAlgorithmAuto && certificate.SignatureAlgorithm != signatureAlgorithm(req.Template.SignatureAlgorithm) {
		return errors.New("pki: issued certificate signature algorithm differs from template")
	}
	if certificate.KeyUsage != keyUsage(req.Template.KeyUsage) {
		return errors.New("pki: issued certificate key usage differs from template")
	}
	if !slices.Equal(certificate.ExtKeyUsage, extendedKeyUsages(req.Template.ExtendedKeyUsages)) || !equalObjectIdentifiers(certificate.UnknownExtKeyUsage, req.Template.UnknownExtendedKeyUsages) {
		return errors.New("pki: issued certificate extended key usage differs from template")
	}
	expectedIPs, err := parseIPs(req.Template.SubjectAlternativeNames.IPAddresses)
	if err != nil {
		return err
	}
	expectedURIs, err := parseURIs(req.Template.SubjectAlternativeNames.URIs)
	if err != nil {
		return err
	}
	if !slices.Equal(certificate.DNSNames, req.Template.SubjectAlternativeNames.DNSNames) ||
		!equalIPs(certificate.IPAddresses, expectedIPs) ||
		!slices.Equal(certificate.EmailAddresses, req.Template.SubjectAlternativeNames.EmailAddresses) ||
		!equalURIs(certificate.URIs, expectedURIs) {
		return errors.New("pki: issued certificate subject alternative names differ from template")
	}
	if !bytes.Equal(certificate.SubjectKeyId, identifier(req.Template.SubjectKeyIdentifier, req.SubjectPublicKeySPKI)) {
		return errors.New("pki: issued certificate subject key identifier differs from template")
	}
	if !equalNameConstraints(certificate, req.Template.NameConstraints) {
		return errors.New("pki: issued certificate name constraints differ from template")
	}
	if !equalObjectIdentifiers(certificate.PolicyIdentifiers, req.Template.PolicyOIDs) {
		return errors.New("pki: issued certificate policy identifiers differ from template")
	}
	if err := validatePolicyExtension(certificate.Extensions, req.Template.PolicyOIDs); err != nil {
		return err
	}
	if !slices.Equal(certificate.OCSPServer, req.Template.OCSPServers) ||
		!slices.Equal(certificate.IssuingCertificateURL, req.Template.IssuingCertificateURLs) ||
		!slices.Equal(certificate.CRLDistributionPoints, req.Template.CRLDistributionPoints) {
		return errors.New("pki: issued certificate authority information differs from template")
	}
	if err := validateAuthorityInfoAccess(certificate.Extensions, req.Template.OCSPServers, req.Template.IssuingCertificateURLs); err != nil {
		return err
	}
	if len(certificate.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("pki: issued certificate contains unhandled critical extensions: %v", certificate.UnhandledCriticalExtensions)
	}
	if err := validateIssuedCustomExtensions(certificate.Extensions, req.Template.CustomExtensions); err != nil {
		return err
	}
	if err := validateIssuedExtensionSet(certificate.Extensions, req.Template); err != nil {
		return err
	}
	var expectedAuthorityKeyID []byte
	if len(req.IssuerCertificateDER) != 0 {
		issuer, parseErr := x509.ParseCertificate(req.IssuerCertificateDER)
		if parseErr != nil {
			return fmt.Errorf("pki: parse issuer certificate: %w", parseErr)
		}
		expectedAuthorityKeyID = authorityKeyIdentifier(req.Template.AuthorityKeyIdentifier, issuer.SubjectKeyId)
		if !bytes.Equal(certificate.RawIssuer, issuer.RawSubject) {
			return errors.New("pki: issued certificate issuer differs from expected issuer subject")
		}
		if checkErr := certificate.CheckSignatureFrom(issuer); checkErr != nil {
			return fmt.Errorf("pki: verify issued certificate signature: %w", checkErr)
		}
	} else {
		expectedAuthorityKeyID = authorityKeyIdentifier(req.Template.AuthorityKeyIdentifier, certificate.SubjectKeyId)
		if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			return errors.New("pki: self-signed certificate issuer differs from its subject")
		}
		if checkErr := certificate.CheckSignatureFrom(certificate); checkErr != nil {
			return fmt.Errorf("pki: verify self-signed certificate: %w", checkErr)
		}
	}
	if !bytes.Equal(certificate.AuthorityKeyId, expectedAuthorityKeyID) {
		return errors.New("pki: issued certificate authority key identifier differs from template")
	}
	return nil
}

func authorityKeyIdentifier(value domainpki.KeyIdentifier, automatic []byte) []byte {
	switch value.Mode {
	case domainpki.IdentifierModeExplicit:
		return value.Value
	case domainpki.IdentifierModeAutomatic:
		return automatic
	default:
		return nil
	}
}

func findExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}
	return pkix.Extension{}, false
}

func equalObjectIdentifiers(actual []asn1.ObjectIdentifier, expected []domainpki.OID) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index, value := range actual {
		if value.String() != string(expected[index]) {
			return false
		}
	}
	return true
}

func equalIPs(actual, expected []net.IP) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if !actual[index].Equal(expected[index]) {
			return false
		}
	}
	return true
}

func equalURIs(actual, expected []*url.URL) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].String() != expected[index].String() {
			return false
		}
	}
	return true
}

func equalIPRanges(actual []*net.IPNet, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		_, expectedRange, err := net.ParseCIDR(expected[index])
		if err != nil || actual[index].String() != expectedRange.String() {
			return false
		}
	}
	return true
}

func equalNameConstraints(certificate *x509.Certificate, expected domainpki.NameConstraints) bool {
	return certificate.PermittedDNSDomainsCritical == expected.Critical &&
		slices.Equal(certificate.PermittedDNSDomains, expected.PermittedDNSDomains) &&
		slices.Equal(certificate.ExcludedDNSDomains, expected.ExcludedDNSDomains) &&
		equalIPRanges(certificate.PermittedIPRanges, expected.PermittedIPRanges) &&
		equalIPRanges(certificate.ExcludedIPRanges, expected.ExcludedIPRanges) &&
		slices.Equal(certificate.PermittedEmailAddresses, expected.PermittedEmailAddresses) &&
		slices.Equal(certificate.ExcludedEmailAddresses, expected.ExcludedEmailAddresses) &&
		slices.Equal(certificate.PermittedURIDomains, expected.PermittedURIDomains) &&
		slices.Equal(certificate.ExcludedURIDomains, expected.ExcludedURIDomains)
}

func validateIssuedCustomExtensions(extensions []pkix.Extension, expected []domainpki.CustomExtension) error {
	for _, custom := range expected {
		oid, err := objectIdentifier(custom.OID)
		if err != nil {
			return err
		}
		actual, ok := findExtension(extensions, oid)
		if !ok || actual.Critical != custom.Critical || !bytes.Equal(actual.Value, custom.DER) {
			return fmt.Errorf("pki: issued custom extension %q differs from template", custom.OID)
		}
	}
	return nil
}

func validatePolicyExtension(extensions []pkix.Extension, expected []domainpki.OID) error {
	if len(expected) == 0 {
		return nil
	}
	extension, ok := findExtension(extensions, oidExtensionCertificatePolicy)
	if !ok {
		return errors.New("pki: issued certificate is missing certificate policies")
	}
	sequences, err := sequenceElements(extension.Value)
	if err != nil {
		return fmt.Errorf("pki: parse certificate policies: %w", err)
	}
	if len(sequences) != len(expected) {
		return errors.New("pki: issued certificate policy count differs from template")
	}
	for index, sequence := range sequences {
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(sequence.Bytes, &oid)
		if err != nil {
			return fmt.Errorf("pki: parse certificate policy: %w", err)
		}
		if len(rest) != 0 {
			return errors.New("pki: certificate policy qualifiers are not allowed by this template contract")
		}
		if oid.String() != string(expected[index]) {
			return errors.New("pki: issued certificate policy differs from template")
		}
	}
	return nil
}

var (
	oidAuthorityInfoAccessOCSP    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func validateAuthorityInfoAccess(extensions []pkix.Extension, expectedOCSP, expectedIssuers []string) error {
	if len(expectedOCSP)+len(expectedIssuers) == 0 {
		return nil
	}
	extension, ok := findExtension(extensions, oidExtensionAuthorityInfoAccess)
	if !ok {
		return errors.New("pki: issued certificate is missing authority information access")
	}
	sequences, err := sequenceElements(extension.Value)
	if err != nil {
		return fmt.Errorf("pki: parse authority information access: %w", err)
	}
	actualOCSP := make([]string, 0, len(expectedOCSP))
	actualIssuers := make([]string, 0, len(expectedIssuers))
	for _, sequence := range sequences {
		var method asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(sequence.Bytes, &method)
		if err != nil {
			return fmt.Errorf("pki: parse authority information access method: %w", err)
		}
		var location asn1.RawValue
		trailing, err := asn1.Unmarshal(rest, &location)
		if err != nil || len(trailing) != 0 || location.Class != asn1.ClassContextSpecific || location.Tag != 6 {
			return errors.New("pki: authority information access location must be a URI")
		}
		switch {
		case method.Equal(oidAuthorityInfoAccessOCSP):
			actualOCSP = append(actualOCSP, string(location.Bytes))
		case method.Equal(oidAuthorityInfoAccessIssuers):
			actualIssuers = append(actualIssuers, string(location.Bytes))
		default:
			return fmt.Errorf("pki: unsupported authority information access method %q", method)
		}
	}
	if !slices.Equal(actualOCSP, expectedOCSP) || !slices.Equal(actualIssuers, expectedIssuers) {
		return errors.New("pki: issued certificate authority information access differs from template")
	}
	return nil
}

func sequenceElements(der []byte) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, errors.New("expected a single der sequence")
	}
	values := make([]asn1.RawValue, 0)
	contents := outer.Bytes
	for len(contents) != 0 {
		var value asn1.RawValue
		contents, err = asn1.Unmarshal(contents, &value)
		if err != nil || value.Class != asn1.ClassUniversal || value.Tag != asn1.TagSequence {
			return nil, errors.New("expected a sequence element")
		}
		values = append(values, value)
	}
	return values, nil
}

func validateIssuedExtensionSet(extensions []pkix.Extension, template domainpki.CertificateTemplate) error {
	expected := map[string]struct{}{oidExtensionBasicConstraints.String(): {}}
	add := func(condition bool, oid asn1.ObjectIdentifier) {
		if condition {
			expected[oid.String()] = struct{}{}
		}
	}
	add(template.KeyUsage != 0, oidExtensionKeyUsage)
	add(len(template.ExtendedKeyUsages)+len(template.UnknownExtendedKeyUsages) != 0, oidExtensionExtendedKeyUsage)
	add(template.SubjectKeyIdentifier.Mode != domainpki.IdentifierModeOmitted, oidExtensionSubjectKeyID)
	add(template.AuthorityKeyIdentifier.Mode != domainpki.IdentifierModeOmitted, oidExtensionAuthorityKeyID)
	add(len(template.SubjectAlternativeNames.DNSNames)+len(template.SubjectAlternativeNames.IPAddresses)+
		len(template.SubjectAlternativeNames.EmailAddresses)+len(template.SubjectAlternativeNames.URIs) != 0, oidExtensionSubjectAltName)
	add(hasNameConstraints(template.NameConstraints), oidExtensionNameConstraints)
	add(len(template.PolicyOIDs) != 0, oidExtensionCertificatePolicy)
	add(len(template.CRLDistributionPoints) != 0, oidExtensionCRLDistribution)
	add(len(template.OCSPServers)+len(template.IssuingCertificateURLs) != 0, oidExtensionAuthorityInfoAccess)
	for _, custom := range template.CustomExtensions {
		expected[string(custom.OID)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		oid := extension.Id.String()
		if _, ok := expected[oid]; !ok {
			return fmt.Errorf("pki: issued certificate contains unexpected extension %q", oid)
		}
		if _, ok := seen[oid]; ok {
			return fmt.Errorf("pki: issued certificate contains duplicate extension %q", oid)
		}
		seen[oid] = struct{}{}
	}
	for oid := range expected {
		if _, ok := seen[oid]; !ok {
			return fmt.Errorf("pki: issued certificate is missing expected extension %q", oid)
		}
	}
	return nil
}

func hasNameConstraints(value domainpki.NameConstraints) bool {
	return len(value.PermittedDNSDomains)+len(value.ExcludedDNSDomains)+
		len(value.PermittedIPRanges)+len(value.ExcludedIPRanges)+
		len(value.PermittedEmailAddresses)+len(value.ExcludedEmailAddresses)+
		len(value.PermittedURIDomains)+len(value.ExcludedURIDomains) != 0
}

var _ apppki.Backend = Backend{}
var _ apppki.Validator = Validator{}
