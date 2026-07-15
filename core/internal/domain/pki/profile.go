package pki

import (
	"fmt"
	"time"
)

const (
	DefaultBackdate            = 5 * time.Minute
	DefaultRootValidity        = 10 * 365 * 24 * time.Hour
	DefaultSubordinateValidity = 3 * 365 * 24 * time.Hour
	DefaultLeafValidity        = 30 * 24 * time.Hour
)

const (
	ProfileRootModern        ProfileID = "root-modern"
	ProfileSubordinateModern ProfileID = "subordinate-modern"
	ProfileTLSServer         ProfileID = "tls-server"
	ProfileTLSClient         ProfileID = "tls-client"
	ProfileMTLSServer        ProfileID = "mtls-server"
	ProfileMTLSClient        ProfileID = "mtls-client"
	ProfileDualRoleMTLS      ProfileID = "dual-role-mtls"
	ProfileLegacyRSAServer   ProfileID = "legacy-rsa-server"
	ProfileLegacyRSAClient   ProfileID = "legacy-rsa-client"
	ProfilePQHybridServer    ProfileID = "pq-hybrid-tls-server"
	ProfilePQHybridClient    ProfileID = "pq-hybrid-tls-client"
	ProfilePQHybridMutual    ProfileID = "pq-hybrid-dual-role-mtls"
)

type Profile struct {
	ID               ProfileID              `json:"id"`
	Name             string                 `json:"name"`
	Purpose          Purpose                `json:"purpose"`
	AuthorityRole    AuthorityRole          `json:"authorityRole,omitempty"`
	Key              KeySpec                `json:"key"`
	Signature        SignatureAlgorithm     `json:"signatureAlgorithm"`
	Validity         time.Duration          `json:"validity"`
	Backdate         time.Duration          `json:"backdate"`
	BasicConstraints BasicConstraints       `json:"basicConstraints"`
	KeyUsage         KeyUsage               `json:"keyUsage"`
	ExtendedKeyUsage []ExtendedKeyUsage     `json:"extendedKeyUsage,omitempty"`
	ExportPolicy     ExportPolicy           `json:"exportPolicy"`
	Backend          BackendID              `json:"backendId"`
	Compatibility    CompatibilityTargetID  `json:"compatibilityTargetId"`
	KeyEstablishment KeyEstablishmentPolicy `json:"keyEstablishmentPolicy"`
}

func (p Profile) Validate() error {
	if err := p.ID.Validate(); err != nil {
		return err
	}
	if _, err := validateName(p.Name, "profile name"); err != nil {
		return err
	}
	if err := p.Purpose.Validate(); err != nil {
		return err
	}
	if p.AuthorityRole != "" {
		if err := p.AuthorityRole.Validate(); err != nil {
			return err
		}
	}
	if err := p.Key.Validate(); err != nil {
		return err
	}
	if err := validateSignatureAlgorithm(p.Signature); err != nil {
		return err
	}
	if p.Validity <= 0 {
		return fmt.Errorf("pki: profile validity must be positive")
	}
	if p.Backdate < 0 {
		return fmt.Errorf("pki: profile backdate cannot be negative")
	}
	if err := validateBasicConstraints(p.BasicConstraints, p.KeyUsage); err != nil {
		return err
	}
	if err := validateExtendedKeyUsages(p.ExtendedKeyUsage, nil); err != nil {
		return err
	}
	if err := p.ExportPolicy.Validate(); err != nil {
		return err
	}
	if err := p.Backend.Validate(); err != nil {
		return err
	}
	if err := p.Compatibility.Validate(); err != nil {
		return err
	}
	if err := p.KeyEstablishment.Validate(); err != nil {
		return err
	}
	if target, ok := BuiltInCompatibilityTarget(p.Compatibility); ok {
		if !target.SupportsKey(p.Key.Algorithm) || !target.SupportsSignature(p.Signature) {
			return fmt.Errorf("pki: compatibility target %q does not support profile algorithms", target.ID)
		}
		if _, err := ResolveTLSNamedGroups(target, p.KeyEstablishment); err != nil {
			return err
		}
	}
	return nil
}

func BuiltInProfiles() []Profile {
	builtin := BackendBuiltinX509
	ecdsa := KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: EllipticCurveP256}
	rsa := KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmRSA, RSABits: 2048}
	caUsage := KeyUsageCertificateSign | KeyUsageCRLSign | KeyUsageDigitalSignature
	ecdsaUsage := KeyUsageDigitalSignature
	rsaUsage := KeyUsageDigitalSignature | KeyUsageKeyEncipherment
	leaf := func(id ProfileID, name string, purpose Purpose, key KeySpec, usage KeyUsage, extended []ExtendedKeyUsage, compatibility CompatibilityTargetID, establishment KeyEstablishmentPolicy) Profile {
		return Profile{
			ID: id, Name: name, Purpose: purpose, Key: key,
			Signature: SignatureAlgorithmAuto, Validity: DefaultLeafValidity,
			Backdate: DefaultBackdate, KeyUsage: usage,
			ExtendedKeyUsage: append([]ExtendedKeyUsage(nil), extended...),
			ExportPolicy:     ExportPolicyExplicit, Backend: builtin,
			Compatibility: compatibility, KeyEstablishment: establishment,
		}
	}
	return []Profile{
		{
			ID: ProfileRootModern, Name: "Modern root authority", Purpose: PurposeCustom,
			AuthorityRole: AuthorityRoleRoot, Key: ecdsa, Signature: SignatureAlgorithmECDSASHA256,
			Validity: DefaultRootValidity, Backdate: DefaultBackdate,
			BasicConstraints: BasicConstraints{Critical: true, IsCA: true}, KeyUsage: caUsage,
			ExportPolicy: ExportPolicyNever, Backend: builtin,
			Compatibility: CompatibilityPortableX509, KeyEstablishment: KeyEstablishmentNotApplicable,
		},
		{
			ID: ProfileSubordinateModern, Name: "Modern subordinate authority", Purpose: PurposeCustom,
			AuthorityRole: AuthorityRoleSubordinate, Key: ecdsa, Signature: SignatureAlgorithmAuto,
			Validity: DefaultSubordinateValidity, Backdate: DefaultBackdate,
			BasicConstraints: BasicConstraints{Critical: true, IsCA: true, MaxPathLenZero: true}, KeyUsage: caUsage,
			ExportPolicy: ExportPolicyNever, Backend: builtin,
			Compatibility: CompatibilityPortableX509, KeyEstablishment: KeyEstablishmentNotApplicable,
		},
		leaf(ProfileTLSServer, "TLS server", PurposeTLSServer, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileTLSClient, "TLS client", PurposeTLSClient, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageClientAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileMTLSServer, "Mutual TLS server", PurposeMTLSServer, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileMTLSClient, "Mutual TLS client", PurposeMTLSClient, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageClientAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileDualRoleMTLS, "Dual-role mutual TLS", PurposeDualRoleMTLS, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth, ExtendedKeyUsageClientAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileLegacyRSAServer, "Legacy RSA TLS server", PurposeTLSServer, rsa, rsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfileLegacyRSAClient, "Legacy RSA TLS client", PurposeTLSClient, rsa, rsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageClientAuth}, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		leaf(ProfilePQHybridServer, "Post-quantum hybrid TLS server", PurposeTLSServer, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth}, CompatibilityGo126PQHybrid, KeyEstablishmentHybridPQRequired),
		leaf(ProfilePQHybridClient, "Post-quantum hybrid TLS client", PurposeTLSClient, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageClientAuth}, CompatibilityGo126PQHybrid, KeyEstablishmentHybridPQRequired),
		leaf(ProfilePQHybridMutual, "Post-quantum hybrid mutual TLS", PurposeDualRoleMTLS, ecdsa, ecdsaUsage, []ExtendedKeyUsage{ExtendedKeyUsageServerAuth, ExtendedKeyUsageClientAuth}, CompatibilityGo126PQHybrid, KeyEstablishmentHybridPQRequired),
	}
}

func BuiltInProfile(id ProfileID) (Profile, bool) {
	for _, profile := range BuiltInProfiles() {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}
