package pki

import (
	"errors"
	"fmt"
)

type AuthorityRole string

const (
	AuthorityRoleRoot        AuthorityRole = "root"
	AuthorityRoleSubordinate AuthorityRole = "subordinate"
)

func (r AuthorityRole) Validate() error {
	switch r {
	case AuthorityRoleRoot, AuthorityRoleSubordinate:
		return nil
	default:
		return fmt.Errorf("pki: unsupported authority role %q", r)
	}
}

type Origin string

const (
	OriginGenerated Origin = "generated"
	OriginImported  Origin = "imported"
)

func (o Origin) Validate() error {
	switch o {
	case OriginGenerated, OriginImported:
		return nil
	default:
		return fmt.Errorf("pki: unsupported origin %q", o)
	}
}

type SignerMode string

const (
	SignerModeLocal    SignerMode = "local"
	SignerModeExternal SignerMode = "external"
	SignerModeNone     SignerMode = "none"
)

func (m SignerMode) Validate() error {
	switch m {
	case SignerModeLocal, SignerModeExternal, SignerModeNone:
		return nil
	default:
		return fmt.Errorf("pki: unsupported signer mode %q", m)
	}
}

type AuthorityState string

const (
	AuthorityStatePending     AuthorityState = "pending"
	AuthorityStateActive      AuthorityState = "active"
	AuthorityStateLocked      AuthorityState = "locked"
	AuthorityStateRetiring    AuthorityState = "retiring"
	AuthorityStateRetired     AuthorityState = "retired"
	AuthorityStateCompromised AuthorityState = "compromised"
	AuthorityStateDestroyed   AuthorityState = "destroyed"
)

func (s AuthorityState) Validate() error {
	switch s {
	case AuthorityStatePending, AuthorityStateActive, AuthorityStateLocked,
		AuthorityStateRetiring, AuthorityStateRetired, AuthorityStateCompromised,
		AuthorityStateDestroyed:
		return nil
	default:
		return fmt.Errorf("pki: unsupported authority state %q", s)
	}
}

type CertificateState string

const (
	CertificateStatePending    CertificateState = "pending"
	CertificateStateActive     CertificateState = "active"
	CertificateStateSuperseded CertificateState = "superseded"
	CertificateStateExpired    CertificateState = "expired"
	CertificateStateRevoked    CertificateState = "revoked"
	CertificateStateInvalid    CertificateState = "invalid"
)

func (s CertificateState) Validate() error {
	switch s {
	case CertificateStatePending, CertificateStateActive, CertificateStateSuperseded,
		CertificateStateExpired, CertificateStateRevoked, CertificateStateInvalid:
		return nil
	default:
		return fmt.Errorf("pki: unsupported certificate state %q", s)
	}
}

type Purpose string

const (
	PurposeTLSServer    Purpose = "tls-server"
	PurposeTLSClient    Purpose = "tls-client"
	PurposeMTLSServer   Purpose = "mtls-server"
	PurposeMTLSClient   Purpose = "mtls-client"
	PurposeDualRoleMTLS Purpose = "dual-role-mtls"
	PurposeCodeSigning  Purpose = "code-signing"
	PurposeCustom       Purpose = "custom"
)

func (p Purpose) Validate() error {
	switch p {
	case PurposeTLSServer, PurposeTLSClient, PurposeMTLSServer, PurposeMTLSClient,
		PurposeDualRoleMTLS, PurposeCodeSigning, PurposeCustom:
		return nil
	default:
		return fmt.Errorf("pki: unsupported purpose %q", p)
	}
}

type ExportPolicy string

const (
	ExportPolicyPublicOnly ExportPolicy = "public-only"
	ExportPolicyExplicit   ExportPolicy = "explicit-private-export"
	ExportPolicyNever      ExportPolicy = "never-private-export"
)

func (p ExportPolicy) Validate() error {
	switch p {
	case ExportPolicyPublicOnly, ExportPolicyExplicit, ExportPolicyNever:
		return nil
	default:
		return fmt.Errorf("pki: unsupported export policy %q", p)
	}
}

type KeyAlgorithm string

const (
	KeyAlgorithmECDSA   KeyAlgorithm = "ecdsa"
	KeyAlgorithmRSA     KeyAlgorithm = "rsa"
	KeyAlgorithmEd25519 KeyAlgorithm = "ed25519"
	KeyAlgorithmMLDSA44 KeyAlgorithm = "ml-dsa-44"
	KeyAlgorithmMLDSA65 KeyAlgorithm = "ml-dsa-65"
	KeyAlgorithmMLDSA87 KeyAlgorithm = "ml-dsa-87"
)

type EllipticCurve string

const (
	EllipticCurveP256 EllipticCurve = "P-256"
	EllipticCurveP384 EllipticCurve = "P-384"
	EllipticCurveP521 EllipticCurve = "P-521"
)

type SignatureAlgorithm string

const (
	SignatureAlgorithmAuto             SignatureAlgorithm = "auto"
	SignatureAlgorithmECDSASHA256      SignatureAlgorithm = "ecdsa-sha256"
	SignatureAlgorithmECDSASHA384      SignatureAlgorithm = "ecdsa-sha384"
	SignatureAlgorithmECDSASHA512      SignatureAlgorithm = "ecdsa-sha512"
	SignatureAlgorithmSHA256WithRSA    SignatureAlgorithm = "sha256-rsa"
	SignatureAlgorithmSHA384WithRSA    SignatureAlgorithm = "sha384-rsa"
	SignatureAlgorithmSHA512WithRSA    SignatureAlgorithm = "sha512-rsa"
	SignatureAlgorithmSHA256WithRSAPSS SignatureAlgorithm = "sha256-rsa-pss"
	SignatureAlgorithmSHA384WithRSAPSS SignatureAlgorithm = "sha384-rsa-pss"
	SignatureAlgorithmSHA512WithRSAPSS SignatureAlgorithm = "sha512-rsa-pss"
	SignatureAlgorithmEd25519          SignatureAlgorithm = "ed25519"
	SignatureAlgorithmMLDSA44          SignatureAlgorithm = "ml-dsa-44"
	SignatureAlgorithmMLDSA65          SignatureAlgorithm = "ml-dsa-65"
	SignatureAlgorithmMLDSA87          SignatureAlgorithm = "ml-dsa-87"
)

// Validate rejects automatic or unset signature selection at boundaries that
// require a concrete, durable algorithm commitment.
func (a SignatureAlgorithm) Validate() error {
	if a == "" || a == SignatureAlgorithmAuto {
		return errors.New("pki: concrete signature algorithm is required")
	}
	return validateKnownSignatureAlgorithm(a)
}

func (a SignatureAlgorithm) CompatibleWith(key KeyAlgorithm) bool {
	if a == "" || a == SignatureAlgorithmAuto {
		return true
	}
	switch key {
	case KeyAlgorithmECDSA:
		return a == SignatureAlgorithmECDSASHA256 || a == SignatureAlgorithmECDSASHA384 || a == SignatureAlgorithmECDSASHA512
	case KeyAlgorithmRSA:
		return a == SignatureAlgorithmSHA256WithRSA || a == SignatureAlgorithmSHA384WithRSA || a == SignatureAlgorithmSHA512WithRSA ||
			a == SignatureAlgorithmSHA256WithRSAPSS || a == SignatureAlgorithmSHA384WithRSAPSS || a == SignatureAlgorithmSHA512WithRSAPSS
	case KeyAlgorithmEd25519:
		return a == SignatureAlgorithmEd25519
	case KeyAlgorithmMLDSA44:
		return a == SignatureAlgorithmMLDSA44
	case KeyAlgorithmMLDSA65:
		return a == SignatureAlgorithmMLDSA65
	case KeyAlgorithmMLDSA87:
		return a == SignatureAlgorithmMLDSA87
	default:
		return false
	}
}

// DefaultSignatureAlgorithm returns the deterministic algorithm Hovel uses
// when a caller requests automatic selection for a concrete key spec.
func DefaultSignatureAlgorithm(key KeySpec) (SignatureAlgorithm, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	switch key.Algorithm {
	case KeyAlgorithmECDSA:
		switch key.Curve {
		case EllipticCurveP256:
			return SignatureAlgorithmECDSASHA256, nil
		case EllipticCurveP384:
			return SignatureAlgorithmECDSASHA384, nil
		case EllipticCurveP521:
			return SignatureAlgorithmECDSASHA512, nil
		default:
			return "", fmt.Errorf("pki: unsupported elliptic curve %q", key.Curve)
		}
	case KeyAlgorithmRSA:
		return SignatureAlgorithmSHA256WithRSA, nil
	case KeyAlgorithmEd25519:
		return SignatureAlgorithmEd25519, nil
	case KeyAlgorithmMLDSA44:
		return SignatureAlgorithmMLDSA44, nil
	case KeyAlgorithmMLDSA65:
		return SignatureAlgorithmMLDSA65, nil
	case KeyAlgorithmMLDSA87:
		return SignatureAlgorithmMLDSA87, nil
	default:
		return "", fmt.Errorf("pki: unsupported key algorithm %q", key.Algorithm)
	}
}

type KeySource string

const (
	KeySourceGenerated KeySource = "generated"
	KeySourceImported  KeySource = "imported"
	KeySourceExisting  KeySource = "existing"
	KeySourceCSR       KeySource = "csr"
	KeySourceExternal  KeySource = "external"
)

type IdentifierMode string

const (
	IdentifierModeAutomatic IdentifierMode = "automatic"
	IdentifierModeExplicit  IdentifierMode = "explicit"
	IdentifierModeOmitted   IdentifierMode = "omitted"
)

// ASN1StringType selects the DER string encoding for a distinguished-name
// attribute. The empty value delegates the choice to the crypto backend.
type ASN1StringType string

const (
	ASN1StringTypeUTF8      ASN1StringType = "utf8"
	ASN1StringTypePrintable ASN1StringType = "printable"
	ASN1StringTypeIA5       ASN1StringType = "ia5"
)

func (t ASN1StringType) Validate() error {
	switch t {
	case "", ASN1StringTypeUTF8, ASN1StringTypePrintable, ASN1StringTypeIA5:
		return nil
	default:
		return fmt.Errorf("pki: unsupported asn.1 string type %q", t)
	}
}

// KeyEstablishmentPolicy describes the TLS key-exchange guarantee expected by
// a credential consumer. It is independent of the certificate signature
// algorithm: hybrid ML-KEM protects session key establishment, not identity
// signatures.
type KeyEstablishmentPolicy string

const (
	KeyEstablishmentNotApplicable       KeyEstablishmentPolicy = "not-applicable"
	KeyEstablishmentClassicalCompatible KeyEstablishmentPolicy = "classical-compatible"
	KeyEstablishmentHybridPQPreferred   KeyEstablishmentPolicy = "hybrid-pq-preferred"
	KeyEstablishmentHybridPQRequired    KeyEstablishmentPolicy = "hybrid-pq-required"
)

func (p KeyEstablishmentPolicy) Validate() error {
	switch p {
	case KeyEstablishmentNotApplicable, KeyEstablishmentClassicalCompatible,
		KeyEstablishmentHybridPQPreferred, KeyEstablishmentHybridPQRequired:
		return nil
	default:
		return fmt.Errorf("pki: unsupported key establishment policy %q", p)
	}
}

type TLSNamedGroup string

const (
	TLSNamedGroupX25519MLKEM768 TLSNamedGroup = "x25519-mlkem768"
	TLSNamedGroupP256MLKEM768   TLSNamedGroup = "secp256r1-mlkem768"
	TLSNamedGroupP384MLKEM1024  TLSNamedGroup = "secp384r1-mlkem1024"
	TLSNamedGroupX25519         TLSNamedGroup = "x25519"
	TLSNamedGroupP256           TLSNamedGroup = "secp256r1"
	TLSNamedGroupP384           TLSNamedGroup = "secp384r1"
	TLSNamedGroupP521           TLSNamedGroup = "secp521r1"
)

func (g TLSNamedGroup) Validate() error {
	switch g {
	case TLSNamedGroupX25519MLKEM768, TLSNamedGroupP256MLKEM768,
		TLSNamedGroupP384MLKEM1024, TLSNamedGroupX25519,
		TLSNamedGroupP256, TLSNamedGroupP384, TLSNamedGroupP521:
		return nil
	default:
		return fmt.Errorf("pki: unsupported tls named group %q", g)
	}
}

func (g TLSNamedGroup) IsHybridPostQuantum() bool {
	switch g {
	case TLSNamedGroupX25519MLKEM768, TLSNamedGroupP256MLKEM768, TLSNamedGroupP384MLKEM1024:
		return true
	default:
		return false
	}
}
