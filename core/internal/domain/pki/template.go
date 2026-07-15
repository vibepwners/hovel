package pki

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	MaxSerialBytes                       = 20
	MinimumRSAKeyBits                    = 2048
	MaximumRSAKeyBits                    = 16384
	MaximumCustomDERSize                 = 1 << 20
	MaximumOIDBytes                      = 256
	MaximumTemplateStringBytes           = 4096
	MaximumTemplateListElements          = 256
	MaximumCustomExtensions              = 64
	MaximumCustomExtensionAggregateBytes = 4 << 20
	MaximumKeyIdentifierBytes            = 64
)

const (
	oidExtensionSubjectKeyIdentifier   OID = "2.5.29.14"
	oidExtensionKeyUsage               OID = "2.5.29.15"
	oidExtensionSubjectAlternativeName OID = "2.5.29.17"
	oidExtensionBasicConstraints       OID = "2.5.29.19"
	oidExtensionNameConstraints        OID = "2.5.29.30"
	oidExtensionCRLDistributionPoints  OID = "2.5.29.31"
	oidExtensionCertificatePolicies    OID = "2.5.29.32"
	oidExtensionAuthorityKeyIdentifier OID = "2.5.29.35"
	oidExtensionExtendedKeyUsage       OID = "2.5.29.37"
	oidExtensionAuthorityInfoAccess    OID = "1.3.6.1.5.5.7.1.1"

	oidExtendedKeyUsageAny             OID = "2.5.29.37.0"
	oidExtendedKeyUsageServerAuth      OID = "1.3.6.1.5.5.7.3.1"
	oidExtendedKeyUsageClientAuth      OID = "1.3.6.1.5.5.7.3.2"
	oidExtendedKeyUsageCodeSigning     OID = "1.3.6.1.5.5.7.3.3"
	oidExtendedKeyUsageEmailProtection OID = "1.3.6.1.5.5.7.3.4"
	oidExtendedKeyUsageTimeStamping    OID = "1.3.6.1.5.5.7.3.8"
	oidExtendedKeyUsageOCSPSigning     OID = "1.3.6.1.5.5.7.3.9"
)

type SerialNumber string

func NewSerialNumber(value []byte) (SerialNumber, error) {
	for len(value) > 0 && value[0] == 0 {
		value = value[1:]
	}
	if len(value) == 0 {
		return "", errors.New("pki: serial number must be positive")
	}
	if len(value) > MaxSerialBytes {
		return "", fmt.Errorf("pki: serial number exceeds %d bytes", MaxSerialBytes)
	}
	if len(value) == MaxSerialBytes && value[0]&0x80 != 0 {
		return "", fmt.Errorf("pki: serial number requires a sign octet beyond the %d-byte limit", MaxSerialBytes)
	}
	return SerialNumber(hex.EncodeToString(value)), nil
}

func ParseSerialNumber(value string) (SerialNumber, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if value == "" {
		return "", errors.New("pki: serial number is required")
	}
	if len(value)%2 != 0 {
		value = "0" + value
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("pki: parse serial number: %w", err)
	}
	return NewSerialNumber(decoded)
}

func (s SerialNumber) Bytes() ([]byte, error) {
	if s == "" {
		return nil, errors.New("pki: serial number is required")
	}
	decoded, err := hex.DecodeString(string(s))
	if err != nil {
		return nil, fmt.Errorf("pki: decode serial number: %w", err)
	}
	canonical, err := NewSerialNumber(decoded)
	if err != nil {
		return nil, err
	}
	if canonical != s {
		return nil, errors.New("pki: serial number is not canonical")
	}
	return decoded, nil
}

type OID string

func NewOID(value string) (OID, error) {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > MaximumOIDBytes {
		return "", fmt.Errorf("pki: oid must contain between 1 and %d bytes", MaximumOIDBytes)
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("pki: oid %q must contain at least two arcs", value)
	}
	for index, part := range parts {
		if part == "" {
			return "", fmt.Errorf("pki: oid %q contains an empty arc", value)
		}
		if len(part) > 1 && part[0] == '0' {
			return "", fmt.Errorf("pki: oid %q contains a non-canonical arc", value)
		}
		arc, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return "", fmt.Errorf("pki: oid %q contains an invalid arc: %w", value, err)
		}
		if index == 0 && arc > 2 {
			return "", fmt.Errorf("pki: oid %q first arc must be 0, 1, or 2", value)
		}
		if index == 1 && parts[0] != "2" && arc > 39 {
			return "", fmt.Errorf("pki: oid %q second arc exceeds 39", value)
		}
	}
	return OID(value), nil
}

type Attribute struct {
	OID        OID            `json:"oid"`
	Value      string         `json:"value"`
	StringType ASN1StringType `json:"stringType,omitempty"`
}

type DistinguishedName struct {
	CommonName         string      `json:"commonName,omitempty"`
	SerialNumber       string      `json:"serialNumber,omitempty"`
	Country            []string    `json:"country,omitempty"`
	Organization       []string    `json:"organization,omitempty"`
	OrganizationalUnit []string    `json:"organizationalUnit,omitempty"`
	Locality           []string    `json:"locality,omitempty"`
	Province           []string    `json:"province,omitempty"`
	StreetAddress      []string    `json:"streetAddress,omitempty"`
	PostalCode         []string    `json:"postalCode,omitempty"`
	ExtraNames         []Attribute `json:"extraNames,omitempty"`
}

type SubjectAlternativeNames struct {
	DNSNames       []string `json:"dnsNames,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

type NameConstraints struct {
	Critical                bool     `json:"critical"`
	PermittedDNSDomains     []string `json:"permittedDNSDomains,omitempty"`
	ExcludedDNSDomains      []string `json:"excludedDNSDomains,omitempty"`
	PermittedIPRanges       []string `json:"permittedIPRanges,omitempty"`
	ExcludedIPRanges        []string `json:"excludedIPRanges,omitempty"`
	PermittedEmailAddresses []string `json:"permittedEmailAddresses,omitempty"`
	ExcludedEmailAddresses  []string `json:"excludedEmailAddresses,omitempty"`
	PermittedURIDomains     []string `json:"permittedURIDomains,omitempty"`
	ExcludedURIDomains      []string `json:"excludedURIDomains,omitempty"`
}

type KeySpec struct {
	Source    KeySource     `json:"source"`
	Algorithm KeyAlgorithm  `json:"algorithm"`
	Curve     EllipticCurve `json:"curve,omitempty"`
	RSABits   int           `json:"rsaBits,omitempty"`
	Existing  KeyID         `json:"existingKeyId,omitempty"`
}

func (s KeySpec) Validate() error {
	switch s.Source {
	case KeySourceGenerated, KeySourceImported, KeySourceExisting, KeySourceCSR, KeySourceExternal:
	default:
		return fmt.Errorf("pki: unsupported key source %q", s.Source)
	}
	switch s.Algorithm {
	case KeyAlgorithmECDSA:
		switch s.Curve {
		case EllipticCurveP256, EllipticCurveP384, EllipticCurveP521:
		default:
			return fmt.Errorf("pki: unsupported elliptic curve %q", s.Curve)
		}
		if s.RSABits != 0 {
			return errors.New("pki: rsa bits cannot be set for an ecdsa key")
		}
	case KeyAlgorithmRSA:
		if s.RSABits < MinimumRSAKeyBits || s.RSABits > MaximumRSAKeyBits || s.RSABits%256 != 0 {
			return fmt.Errorf("pki: rsa key bits must be a multiple of 256 between %d and %d", MinimumRSAKeyBits, MaximumRSAKeyBits)
		}
		if s.Curve != "" {
			return errors.New("pki: elliptic curve cannot be set for an rsa key")
		}
	case KeyAlgorithmEd25519:
		if s.Curve != "" || s.RSABits != 0 {
			return errors.New("pki: ed25519 does not accept curve or rsa parameters")
		}
	case KeyAlgorithmMLDSA44, KeyAlgorithmMLDSA65, KeyAlgorithmMLDSA87:
		if s.Curve != "" || s.RSABits != 0 {
			return errors.New("pki: ml-dsa does not accept curve or rsa parameters")
		}
	default:
		return fmt.Errorf("pki: unsupported key algorithm %q", s.Algorithm)
	}
	if s.Source == KeySourceExisting && s.Existing == "" {
		return errors.New("pki: existing key id is required")
	}
	if s.Source != KeySourceExisting && s.Existing != "" {
		return errors.New("pki: existing key id is only valid for an existing key source")
	}
	return nil
}

type KeyUsage uint16

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertificateSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

const allKeyUsages = KeyUsageDigitalSignature | KeyUsageContentCommitment |
	KeyUsageKeyEncipherment | KeyUsageDataEncipherment | KeyUsageKeyAgreement |
	KeyUsageCertificateSign | KeyUsageCRLSign | KeyUsageEncipherOnly | KeyUsageDecipherOnly

func (u KeyUsage) Validate() error {
	if u&^allKeyUsages != 0 {
		return fmt.Errorf("pki: key usage contains unsupported bits 0x%x", uint16(u&^allKeyUsages))
	}
	return nil
}

type ExtendedKeyUsage string

const (
	ExtendedKeyUsageAny             ExtendedKeyUsage = "any"
	ExtendedKeyUsageServerAuth      ExtendedKeyUsage = "server-auth"
	ExtendedKeyUsageClientAuth      ExtendedKeyUsage = "client-auth"
	ExtendedKeyUsageCodeSigning     ExtendedKeyUsage = "code-signing"
	ExtendedKeyUsageEmailProtection ExtendedKeyUsage = "email-protection"
	ExtendedKeyUsageTimeStamping    ExtendedKeyUsage = "time-stamping"
	ExtendedKeyUsageOCSPSigning     ExtendedKeyUsage = "ocsp-signing"
)

func (u ExtendedKeyUsage) Validate() error {
	switch u {
	case ExtendedKeyUsageAny, ExtendedKeyUsageServerAuth, ExtendedKeyUsageClientAuth,
		ExtendedKeyUsageCodeSigning, ExtendedKeyUsageEmailProtection,
		ExtendedKeyUsageTimeStamping, ExtendedKeyUsageOCSPSigning:
		return nil
	default:
		return fmt.Errorf("pki: unsupported extended key usage %q", u)
	}
}

type BasicConstraints struct {
	Critical       bool `json:"critical"`
	IsCA           bool `json:"isCA"`
	MaxPathLen     int  `json:"maxPathLen,omitempty"`
	MaxPathLenZero bool `json:"maxPathLenZero,omitempty"`
}

type KeyIdentifier struct {
	Mode  IdentifierMode `json:"mode"`
	Value []byte         `json:"value,omitempty"`
}

func (i KeyIdentifier) Validate(field string) error {
	if len(i.Value) > MaximumKeyIdentifierBytes {
		return fmt.Errorf("pki: %s exceeds %d bytes", field, MaximumKeyIdentifierBytes)
	}
	switch i.Mode {
	case IdentifierModeAutomatic, IdentifierModeOmitted:
		if len(i.Value) != 0 {
			return fmt.Errorf("pki: %s value requires explicit mode", field)
		}
	case IdentifierModeExplicit:
		if len(i.Value) == 0 {
			return fmt.Errorf("pki: explicit %s value is required", field)
		}
	default:
		return fmt.Errorf("pki: unsupported %s mode %q", field, i.Mode)
	}
	return nil
}

type CustomExtension struct {
	OID      OID    `json:"oid"`
	Critical bool   `json:"critical"`
	DER      []byte `json:"der"`
}

type CertificateTemplate struct {
	SerialNumber             SerialNumber            `json:"serialNumber"`
	Subject                  DistinguishedName       `json:"subject"`
	NotBefore                time.Time               `json:"notBefore"`
	NotAfter                 time.Time               `json:"notAfter"`
	Key                      KeySpec                 `json:"key"`
	SignatureAlgorithm       SignatureAlgorithm      `json:"signatureAlgorithm"`
	SubjectAlternativeNames  SubjectAlternativeNames `json:"subjectAlternativeNames"`
	BasicConstraints         BasicConstraints        `json:"basicConstraints"`
	KeyUsage                 KeyUsage                `json:"keyUsage"`
	ExtendedKeyUsages        []ExtendedKeyUsage      `json:"extendedKeyUsages,omitempty"`
	UnknownExtendedKeyUsages []OID                   `json:"unknownExtendedKeyUsages,omitempty"`
	SubjectKeyIdentifier     KeyIdentifier           `json:"subjectKeyIdentifier"`
	AuthorityKeyIdentifier   KeyIdentifier           `json:"authorityKeyIdentifier"`
	NameConstraints          NameConstraints         `json:"nameConstraints"`
	PolicyOIDs               []OID                   `json:"policyOids,omitempty"`
	OCSPServers              []string                `json:"ocspServers,omitempty"`
	IssuingCertificateURLs   []string                `json:"issuingCertificateUrls,omitempty"`
	CRLDistributionPoints    []string                `json:"crlDistributionPoints,omitempty"`
	CustomExtensions         []CustomExtension       `json:"customExtensions,omitempty"`
}

func (t CertificateTemplate) Clone() CertificateTemplate {
	return cloneTemplate(t)
}

func (t CertificateTemplate) Validate() error {
	if _, err := t.SerialNumber.Bytes(); err != nil {
		return err
	}
	if err := validateDistinguishedName(t.Subject); err != nil {
		return err
	}
	if t.NotBefore.IsZero() || t.NotAfter.IsZero() {
		return errors.New("pki: certificate validity is required")
	}
	if !t.NotAfter.After(t.NotBefore) {
		return errors.New("pki: certificate not after must be after not before")
	}
	if t.NotBefore.Nanosecond() != 0 || t.NotAfter.Nanosecond() != 0 {
		return errors.New("pki: certificate validity must use whole-second precision")
	}
	if err := t.Key.Validate(); err != nil {
		return err
	}
	if err := validateSignatureAlgorithm(t.SignatureAlgorithm); err != nil {
		return err
	}
	if err := t.KeyUsage.Validate(); err != nil {
		return err
	}
	if err := validateSANs(t.SubjectAlternativeNames); err != nil {
		return err
	}
	if err := validateBasicConstraints(t.BasicConstraints, t.KeyUsage); err != nil {
		return err
	}
	if err := t.SubjectKeyIdentifier.Validate("subject key identifier"); err != nil {
		return err
	}
	if err := t.AuthorityKeyIdentifier.Validate("authority key identifier"); err != nil {
		return err
	}
	if err := validateExtendedKeyUsages(t.ExtendedKeyUsages, t.UnknownExtendedKeyUsages); err != nil {
		return err
	}
	if len(t.PolicyOIDs) > MaximumTemplateListElements {
		return fmt.Errorf("pki: certificate policy oids exceed %d entries", MaximumTemplateListElements)
	}
	seenPolicyOIDs := make(map[OID]struct{}, len(t.PolicyOIDs))
	for _, oid := range t.PolicyOIDs {
		canonical, err := NewOID(string(oid))
		if err != nil {
			return err
		}
		if _, exists := seenPolicyOIDs[canonical]; exists {
			return fmt.Errorf("pki: duplicate certificate policy oid %q", canonical)
		}
		seenPolicyOIDs[canonical] = struct{}{}
	}
	if err := validateNameConstraints(t.NameConstraints, t.BasicConstraints.IsCA); err != nil {
		return err
	}
	if err := validateURLList("ocsp server", t.OCSPServers); err != nil {
		return err
	}
	if err := validateURLList("issuing certificate url", t.IssuingCertificateURLs); err != nil {
		return err
	}
	if err := validateURLList("crl distribution point", t.CRLDistributionPoints); err != nil {
		return err
	}
	return validateCustomExtensions(t.CustomExtensions)
}

func validateDistinguishedName(name DistinguishedName) error {
	if err := validateBoundedTemplateString("common name", name.CommonName, true); err != nil {
		return err
	}
	if err := validateBoundedTemplateString("subject serial number", name.SerialNumber, true); err != nil {
		return err
	}
	for field, values := range map[string][]string{
		"country": name.Country, "organization": name.Organization,
		"organizational unit": name.OrganizationalUnit, "locality": name.Locality,
		"province": name.Province, "street address": name.StreetAddress, "postal code": name.PostalCode,
	} {
		if err := validateBoundedTemplateStrings(field, values); err != nil {
			return err
		}
	}
	if len(name.ExtraNames) > MaximumTemplateListElements {
		return fmt.Errorf("pki: distinguished name extra attributes exceed %d entries", MaximumTemplateListElements)
	}
	if strings.TrimSpace(name.CommonName) == "" && len(name.ExtraNames) == 0 &&
		len(name.Country) == 0 && len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 && len(name.Locality) == 0 &&
		len(name.Province) == 0 && len(name.StreetAddress) == 0 && len(name.PostalCode) == 0 {
		return errors.New("pki: certificate subject is required")
	}
	for _, attribute := range name.ExtraNames {
		if _, err := NewOID(string(attribute.OID)); err != nil {
			return err
		}
		if strings.TrimSpace(attribute.Value) == "" {
			return errors.New("pki: distinguished name extra attribute value is required")
		}
		if err := validateBoundedTemplateString("distinguished name extra attribute", attribute.Value, false); err != nil {
			return err
		}
		if err := attribute.StringType.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateSignatureAlgorithm(signature SignatureAlgorithm) error {
	if signature == "" || signature == SignatureAlgorithmAuto {
		return nil
	}
	return validateKnownSignatureAlgorithm(signature)
}

func validateSANs(names SubjectAlternativeNames) error {
	total := len(names.DNSNames) + len(names.IPAddresses) + len(names.EmailAddresses) + len(names.URIs)
	if total > MaximumTemplateListElements {
		return fmt.Errorf("pki: subject alternative names exceed %d entries", MaximumTemplateListElements)
	}
	for field, values := range map[string][]string{
		"dns subject alternative name":   names.DNSNames,
		"ip subject alternative name":    names.IPAddresses,
		"email subject alternative name": names.EmailAddresses,
		"uri subject alternative name":   names.URIs,
	} {
		if err := validateBoundedTemplateStrings(field, values); err != nil {
			return err
		}
	}
	for _, value := range names.DNSNames {
		if strings.TrimSpace(value) == "" {
			return errors.New("pki: dns subject alternative name is empty")
		}
	}
	for _, value := range names.IPAddresses {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("pki: invalid ip subject alternative name %q", value)
		}
	}
	for _, value := range names.EmailAddresses {
		if !strings.Contains(value, "@") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("pki: invalid email subject alternative name %q", value)
		}
	}
	for _, value := range names.URIs {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" {
			return fmt.Errorf("pki: invalid uri subject alternative name %q", value)
		}
	}
	return nil
}

func validateBasicConstraints(constraints BasicConstraints, usage KeyUsage) error {
	if constraints.MaxPathLen < 0 {
		return errors.New("pki: maximum path length cannot be negative")
	}
	if !constraints.IsCA && (constraints.MaxPathLen != 0 || constraints.MaxPathLenZero) {
		return errors.New("pki: path length requires a ca certificate")
	}
	if constraints.MaxPathLenZero && constraints.MaxPathLen != 0 {
		return errors.New("pki: explicit zero path length cannot include a nonzero maximum path length")
	}
	if constraints.IsCA && !constraints.Critical {
		return errors.New("pki: ca basic constraints must be critical")
	}
	if constraints.IsCA && usage&KeyUsageCertificateSign == 0 {
		return errors.New("pki: ca certificate requires certificate-sign key usage")
	}
	if !constraints.IsCA && usage&(KeyUsageCertificateSign|KeyUsageCRLSign) != 0 {
		return errors.New("pki: leaf certificate cannot use certificate-sign or crl-sign key usage")
	}
	if usage&(KeyUsageEncipherOnly|KeyUsageDecipherOnly) != 0 && usage&KeyUsageKeyAgreement == 0 {
		return errors.New("pki: encipher-only and decipher-only require key-agreement usage")
	}
	return nil
}

func validateExtendedKeyUsages(known []ExtendedKeyUsage, unknown []OID) error {
	if len(known)+len(unknown) > MaximumTemplateListElements {
		return fmt.Errorf("pki: extended key usages exceed %d entries", MaximumTemplateListElements)
	}
	seen := map[OID]struct{}{}
	for _, usage := range known {
		if err := usage.Validate(); err != nil {
			return err
		}
		oid := extendedKeyUsageOID(usage)
		if _, ok := seen[oid]; ok {
			return fmt.Errorf("pki: duplicate extended key usage %q", usage)
		}
		seen[oid] = struct{}{}
	}
	for _, oid := range unknown {
		canonical, err := NewOID(string(oid))
		if err != nil {
			return err
		}
		if _, ok := seen[canonical]; ok || isKnownExtendedKeyUsageOID(canonical) {
			return fmt.Errorf("pki: duplicate or known extended key usage oid %q", canonical)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func extendedKeyUsageOID(usage ExtendedKeyUsage) OID {
	switch usage {
	case ExtendedKeyUsageAny:
		return oidExtendedKeyUsageAny
	case ExtendedKeyUsageServerAuth:
		return oidExtendedKeyUsageServerAuth
	case ExtendedKeyUsageClientAuth:
		return oidExtendedKeyUsageClientAuth
	case ExtendedKeyUsageCodeSigning:
		return oidExtendedKeyUsageCodeSigning
	case ExtendedKeyUsageEmailProtection:
		return oidExtendedKeyUsageEmailProtection
	case ExtendedKeyUsageTimeStamping:
		return oidExtendedKeyUsageTimeStamping
	case ExtendedKeyUsageOCSPSigning:
		return oidExtendedKeyUsageOCSPSigning
	default:
		return ""
	}
}

func isKnownExtendedKeyUsageOID(oid OID) bool {
	switch oid {
	case oidExtendedKeyUsageAny, oidExtendedKeyUsageServerAuth, oidExtendedKeyUsageClientAuth,
		oidExtendedKeyUsageCodeSigning, oidExtendedKeyUsageEmailProtection,
		oidExtendedKeyUsageTimeStamping, oidExtendedKeyUsageOCSPSigning:
		return true
	default:
		return false
	}
}

func validateNameConstraints(constraints NameConstraints, isCA bool) error {
	total := len(constraints.PermittedDNSDomains) + len(constraints.ExcludedDNSDomains) +
		len(constraints.PermittedIPRanges) + len(constraints.ExcludedIPRanges) +
		len(constraints.PermittedEmailAddresses) + len(constraints.ExcludedEmailAddresses) +
		len(constraints.PermittedURIDomains) + len(constraints.ExcludedURIDomains)
	if total > MaximumTemplateListElements {
		return fmt.Errorf("pki: name constraints exceed %d entries", MaximumTemplateListElements)
	}
	hasConstraints := total > 0
	for field, values := range map[string][]string{
		"permitted dns domain": constraints.PermittedDNSDomains, "excluded dns domain": constraints.ExcludedDNSDomains,
		"permitted ip range": constraints.PermittedIPRanges, "excluded ip range": constraints.ExcludedIPRanges,
		"permitted email address": constraints.PermittedEmailAddresses, "excluded email address": constraints.ExcludedEmailAddresses,
		"permitted uri domain": constraints.PermittedURIDomains, "excluded uri domain": constraints.ExcludedURIDomains,
	} {
		if err := validateBoundedTemplateStrings(field, values); err != nil {
			return err
		}
	}
	if hasConstraints && !isCA {
		return errors.New("pki: name constraints require a ca certificate")
	}
	if hasConstraints && !constraints.Critical {
		return errors.New("pki: name constraints must be critical")
	}
	for _, value := range append(append([]string(nil), constraints.PermittedIPRanges...), constraints.ExcludedIPRanges...) {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("pki: invalid name constraint ip range %q", value)
		}
	}
	return nil
}

func validateURLList(field string, values []string) error {
	if err := validateBoundedTemplateStrings(field, values); err != nil {
		return err
	}
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" {
			return fmt.Errorf("pki: invalid %s %q", field, value)
		}
	}
	return nil
}

func validateCustomExtensions(extensions []CustomExtension) error {
	if len(extensions) > MaximumCustomExtensions {
		return fmt.Errorf("pki: custom extensions exceed %d entries", MaximumCustomExtensions)
	}
	seen := map[OID]struct{}{}
	totalDERBytes := 0
	for _, extension := range extensions {
		oid, err := NewOID(string(extension.OID))
		if err != nil {
			return err
		}
		if isReservedCertificateExtensionOID(oid) {
			return fmt.Errorf("pki: custom extension oid %q has a typed certificate-template field", oid)
		}
		if _, ok := seen[oid]; ok {
			return fmt.Errorf("pki: duplicate custom extension oid %q", oid)
		}
		seen[oid] = struct{}{}
		if len(extension.DER) == 0 {
			return fmt.Errorf("pki: custom extension %q der is required", oid)
		}
		if len(extension.DER) > MaximumCustomDERSize {
			return fmt.Errorf("pki: custom extension %q exceeds %d bytes", oid, MaximumCustomDERSize)
		}
		if len(extension.DER) > MaximumCustomExtensionAggregateBytes-totalDERBytes {
			return fmt.Errorf("pki: custom extension der exceeds %d aggregate bytes", MaximumCustomExtensionAggregateBytes)
		}
		totalDERBytes += len(extension.DER)
	}
	return nil
}

func validateBoundedTemplateStrings(field string, values []string) error {
	if len(values) > MaximumTemplateListElements {
		return fmt.Errorf("pki: %s values exceed %d entries", field, MaximumTemplateListElements)
	}
	for _, value := range values {
		if err := validateBoundedTemplateString(field, value, false); err != nil {
			return err
		}
	}
	return nil
}

func validateBoundedTemplateString(field, value string, allowEmpty bool) error {
	if len(value) > MaximumTemplateStringBytes {
		return fmt.Errorf("pki: %s exceeds %d bytes", field, MaximumTemplateStringBytes)
	}
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return fmt.Errorf("pki: %s is required", field)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("pki: %s contains control characters", field)
	}
	return nil
}

func isReservedCertificateExtensionOID(oid OID) bool {
	switch oid {
	case oidExtensionSubjectKeyIdentifier, oidExtensionKeyUsage,
		oidExtensionSubjectAlternativeName, oidExtensionBasicConstraints,
		oidExtensionNameConstraints, oidExtensionCRLDistributionPoints,
		oidExtensionCertificatePolicies, oidExtensionAuthorityKeyIdentifier,
		oidExtensionExtendedKeyUsage, oidExtensionAuthorityInfoAccess:
		return true
	default:
		return false
	}
}
