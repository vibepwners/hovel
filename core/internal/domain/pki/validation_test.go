package pki

import (
	"strings"
	"testing"
	"time"
)

func TestTypedIDConstructorsAndValidation(t *testing.T) {
	t.Parallel()

	constructors := []struct {
		name string
		make func(string) error
	}{
		{name: "authority", make: func(value string) error { _, err := NewAuthorityID(value); return err }},
		{name: "certificate", make: func(value string) error { _, err := NewCertificateID(value); return err }},
		{name: "generation", make: func(value string) error { _, err := NewGenerationID(value); return err }},
		{name: "profile", make: func(value string) error { _, err := NewProfileID(value); return err }},
		{name: "assignment", make: func(value string) error { _, err := NewAssignmentID(value); return err }},
		{name: "consumer", make: func(value string) error { _, err := NewConsumerID(value); return err }},
		{name: "trust set", make: func(value string) error { _, err := NewTrustSetID(value); return err }},
		{name: "trust set generation", make: func(value string) error { _, err := NewTrustSetGenerationID(value); return err }},
		{name: "rotation policy", make: func(value string) error { _, err := NewRotationPolicyID(value); return err }},
		{name: "backend", make: func(value string) error { _, err := NewBackendID(value); return err }},
		{name: "compatibility", make: func(value string) error { _, err := NewCompatibilityTargetID(value); return err }},
		{name: "key", make: func(value string) error { _, err := NewKeyID(value); return err }},
		{name: "bundle", make: func(value string) error { _, err := NewBundleID(value); return err }},
		{name: "stamp", make: func(value string) error { _, err := NewStampID(value); return err }},
		{name: "issuance", make: func(value string) error { _, err := NewIssuanceID(value); return err }},
		{name: "revocation", make: func(value string) error { _, err := NewRevocationID(value); return err }},
		{name: "crl generation", make: func(value string) error { _, err := NewCRLGenerationID(value); return err }},
		{name: "operation", make: func(value string) error { _, err := NewOperationID(value); return err }},
		{name: "acknowledgement", make: func(value string) error { _, err := NewAcknowledgementID(value); return err }},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			if err := constructor.make("valid-id"); err != nil {
				t.Fatal(err)
			}
			if err := constructor.make("invalid id"); err == nil {
				t.Fatal("constructor accepted invalid id")
			}
		})
	}
}

func TestEnumsRejectUnknownValues(t *testing.T) {
	t.Parallel()

	validations := []struct {
		name     string
		validate func() error
	}{
		{name: "authority role", validate: func() error { return AuthorityRole("unknown").Validate() }},
		{name: "origin", validate: func() error { return Origin("unknown").Validate() }},
		{name: "signer mode", validate: func() error { return SignerMode("unknown").Validate() }},
		{name: "authority state", validate: func() error { return AuthorityState("unknown").Validate() }},
		{name: "certificate state", validate: func() error { return CertificateState("unknown").Validate() }},
		{name: "revocation reason", validate: func() error { return RevocationReason("unknown").Validate() }},
		{name: "purpose", validate: func() error { return Purpose("unknown").Validate() }},
		{name: "export policy", validate: func() error { return ExportPolicy("unknown").Validate() }},
		{name: "asn1 string", validate: func() error { return ASN1StringType("unknown").Validate() }},
		{name: "key establishment", validate: func() error { return KeyEstablishmentPolicy("unknown").Validate() }},
		{name: "tls named group", validate: func() error { return TLSNamedGroup("unknown").Validate() }},
	}
	for _, validation := range validations {
		t.Run(validation.name, func(t *testing.T) {
			if err := validation.validate(); err == nil {
				t.Fatal("validation accepted unknown enum value")
			}
		})
	}
	if TLSNamedGroupX25519.IsHybridPostQuantum() {
		t.Fatal("classical X25519 group reported as hybrid post-quantum")
	}
}

func TestSignatureAlgorithmsMatchKeyAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		signature SignatureAlgorithm
		key       KeyAlgorithm
		want      bool
	}{
		{name: "unset delegates selection", key: KeyAlgorithmECDSA, want: true},
		{name: "automatic delegates selection", signature: SignatureAlgorithmAuto, key: KeyAlgorithmRSA, want: true},
		{name: "ecdsa p256", signature: SignatureAlgorithmECDSASHA256, key: KeyAlgorithmECDSA, want: true},
		{name: "ecdsa p384", signature: SignatureAlgorithmECDSASHA384, key: KeyAlgorithmECDSA, want: true},
		{name: "ecdsa p521", signature: SignatureAlgorithmECDSASHA512, key: KeyAlgorithmECDSA, want: true},
		{name: "rsa pkcs1 sha256", signature: SignatureAlgorithmSHA256WithRSA, key: KeyAlgorithmRSA, want: true},
		{name: "rsa pkcs1 sha384", signature: SignatureAlgorithmSHA384WithRSA, key: KeyAlgorithmRSA, want: true},
		{name: "rsa pkcs1 sha512", signature: SignatureAlgorithmSHA512WithRSA, key: KeyAlgorithmRSA, want: true},
		{name: "rsa pss sha256", signature: SignatureAlgorithmSHA256WithRSAPSS, key: KeyAlgorithmRSA, want: true},
		{name: "rsa pss sha384", signature: SignatureAlgorithmSHA384WithRSAPSS, key: KeyAlgorithmRSA, want: true},
		{name: "rsa pss sha512", signature: SignatureAlgorithmSHA512WithRSAPSS, key: KeyAlgorithmRSA, want: true},
		{name: "ed25519", signature: SignatureAlgorithmEd25519, key: KeyAlgorithmEd25519, want: true},
		{name: "ml dsa 44", signature: SignatureAlgorithmMLDSA44, key: KeyAlgorithmMLDSA44, want: true},
		{name: "ml dsa 65", signature: SignatureAlgorithmMLDSA65, key: KeyAlgorithmMLDSA65, want: true},
		{name: "ml dsa 87", signature: SignatureAlgorithmMLDSA87, key: KeyAlgorithmMLDSA87, want: true},
		{name: "algorithm mismatch", signature: SignatureAlgorithmEd25519, key: KeyAlgorithmECDSA},
		{name: "unknown key", signature: SignatureAlgorithmECDSASHA256, key: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.signature.CompatibleWith(test.key); got != test.want {
				t.Fatalf("SignatureAlgorithm(%q).CompatibleWith(%q) = %v, want %v", test.signature, test.key, got, test.want)
			}
		})
	}
}

func TestDefaultSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  KeySpec
		want SignatureAlgorithm
	}{
		{name: "ecdsa p256", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: EllipticCurveP256}, want: SignatureAlgorithmECDSASHA256},
		{name: "ecdsa p384", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: EllipticCurveP384}, want: SignatureAlgorithmECDSASHA384},
		{name: "ecdsa p521", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: EllipticCurveP521}, want: SignatureAlgorithmECDSASHA512},
		{name: "rsa", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmRSA, RSABits: MinimumRSAKeyBits}, want: SignatureAlgorithmSHA256WithRSA},
		{name: "ed25519", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmEd25519}, want: SignatureAlgorithmEd25519},
		{name: "ml dsa 44", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmMLDSA44}, want: SignatureAlgorithmMLDSA44},
		{name: "ml dsa 65", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmMLDSA65}, want: SignatureAlgorithmMLDSA65},
		{name: "ml dsa 87", key: KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmMLDSA87}, want: SignatureAlgorithmMLDSA87},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := DefaultSignatureAlgorithm(test.key)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("DefaultSignatureAlgorithm(%#v) = %q, want %q", test.key, got, test.want)
			}
		})
	}

	if _, err := DefaultSignatureAlgorithm(KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: "unknown"}); err == nil {
		t.Fatal("DefaultSignatureAlgorithm() accepted an invalid key specification")
	}
}

func TestAuthoritySignerModeIsATaggedUnion(t *testing.T) {
	t.Parallel()

	base := AuthorityArgs{
		ID: "authority-signer", Name: "Signer authority", Role: AuthorityRoleRoot,
		Origin: OriginGenerated, SignerMode: SignerModeLocal, State: AuthorityStateActive,
		ActiveGenerationID: "certgen-signer", ProfileID: ProfileRootModern,
		SignerRef: "key-signer", ExportPolicy: ExportPolicyNever, CreatedAt: time.Now().UTC(),
	}
	if _, err := NewAuthority(base); err != nil {
		t.Fatal(err)
	}
	missing := base
	missing.SignerRef = ""
	if _, err := NewAuthority(missing); err == nil {
		t.Fatal("NewAuthority() accepted a local signer without a reference")
	}
	none := base
	none.SignerMode = SignerModeNone
	if _, err := NewAuthority(none); err == nil {
		t.Fatal("NewAuthority() accepted signer mode none with a reference")
	}
	none.SignerRef = ""
	if _, err := NewAuthority(none); err != nil {
		t.Fatalf("NewAuthority() rejected signer mode none without a reference: %v", err)
	}
	external := base
	external.SignerMode = SignerModeExternal
	if _, err := NewAuthority(external); err != nil {
		t.Fatalf("NewAuthority() rejected an external signer reference: %v", err)
	}
}

func TestProfileValidationRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	valid, ok := BuiltInProfile(ProfileTLSServer)
	if !ok {
		t.Fatal("built-in TLS server profile is unavailable")
	}
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{name: "id", mutate: func(profile *Profile) { profile.ID = "bad id" }},
		{name: "name", mutate: func(profile *Profile) { profile.Name = " " }},
		{name: "purpose", mutate: func(profile *Profile) { profile.Purpose = "unknown" }},
		{name: "authority role", mutate: func(profile *Profile) { profile.AuthorityRole = "unknown" }},
		{name: "key", mutate: func(profile *Profile) { profile.Key.Curve = "unknown" }},
		{name: "signature", mutate: func(profile *Profile) { profile.Signature = "unknown" }},
		{name: "validity", mutate: func(profile *Profile) { profile.Validity = 0 }},
		{name: "backdate", mutate: func(profile *Profile) { profile.Backdate = -time.Second }},
		{name: "basic constraints", mutate: func(profile *Profile) {
			profile.BasicConstraints.IsCA = true
		}},
		{name: "extended key usage", mutate: func(profile *Profile) {
			profile.ExtendedKeyUsage = []ExtendedKeyUsage{"unknown"}
		}},
		{name: "export policy", mutate: func(profile *Profile) { profile.ExportPolicy = "unknown" }},
		{name: "backend", mutate: func(profile *Profile) { profile.Backend = "bad id" }},
		{name: "compatibility", mutate: func(profile *Profile) { profile.Compatibility = "bad id" }},
		{name: "key establishment", mutate: func(profile *Profile) { profile.KeyEstablishment = "unknown" }},
		{name: "incompatible algorithm", mutate: func(profile *Profile) {
			profile.Key = KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmMLDSA44}
			profile.Signature = SignatureAlgorithmMLDSA44
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			candidate.ExtendedKeyUsage = append([]ExtendedKeyUsage(nil), valid.ExtendedKeyUsage...)
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Profile.Validate() error = nil, want error")
			}
		})
	}

	if _, ok := BuiltInProfile("unknown"); ok {
		t.Fatal("BuiltInProfile() found an unknown profile")
	}
}

func TestBackendDescriptorValidationAndCopies(t *testing.T) {
	t.Parallel()

	valid := BackendDescriptorArgs{
		SchemaVersion:       BackendSchemaV1,
		ID:                  "backend-1",
		Version:             "1.0",
		KeyAlgorithms:       []KeyAlgorithm{KeyAlgorithmECDSA},
		SignatureAlgorithms: []SignatureAlgorithm{SignatureAlgorithmECDSASHA256},
	}
	descriptor, err := NewBackendDescriptor(valid)
	if err != nil {
		t.Fatal(err)
	}
	clone := descriptor.Clone()
	clone.KeyAlgorithms[0] = KeyAlgorithmRSA
	clone.SignatureAlgorithms[0] = SignatureAlgorithmSHA256WithRSA
	if descriptor.KeyAlgorithms[0] != KeyAlgorithmECDSA || descriptor.SignatureAlgorithms[0] != SignatureAlgorithmECDSASHA256 {
		t.Fatal("BackendDescriptor.Clone() aliased algorithm slices")
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	tampered := descriptor.Clone()
	tampered.SupportsCRL = true
	if err := tampered.Validate(); err == nil {
		t.Fatal("BackendDescriptor.Validate() accepted capabilities that do not match the commitment")
	}
	tests := []struct {
		name   string
		mutate func(*BackendDescriptorArgs)
	}{
		{name: "schema", mutate: func(args *BackendDescriptorArgs) { args.SchemaVersion = "v2" }},
		{name: "id", mutate: func(args *BackendDescriptorArgs) { args.ID = "bad id" }},
		{name: "version", mutate: func(args *BackendDescriptorArgs) { args.Version = " " }},
		{name: "keys", mutate: func(args *BackendDescriptorArgs) { args.KeyAlgorithms = nil }},
		{name: "signatures", mutate: func(args *BackendDescriptorArgs) { args.SignatureAlgorithms = nil }},
		{name: "duplicate key", mutate: func(args *BackendDescriptorArgs) {
			args.KeyAlgorithms = []KeyAlgorithm{KeyAlgorithmECDSA, KeyAlgorithmECDSA}
		}},
		{name: "unknown key", mutate: func(args *BackendDescriptorArgs) { args.KeyAlgorithms = []KeyAlgorithm{"unknown"} }},
		{name: "duplicate signature", mutate: func(args *BackendDescriptorArgs) {
			args.SignatureAlgorithms = []SignatureAlgorithm{SignatureAlgorithmECDSASHA256, SignatureAlgorithmECDSASHA256}
		}},
		{name: "unknown signature", mutate: func(args *BackendDescriptorArgs) {
			args.SignatureAlgorithms = []SignatureAlgorithm{"unknown"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := valid
			test.mutate(&args)
			if _, err := NewBackendDescriptor(args); err == nil {
				t.Fatal("NewBackendDescriptor() accepted invalid input")
			}
		})
	}
}

func TestBundleRejectsInvalidMembersAndMetadata(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name   string
		mutate func(*BundleArgs)
	}{
		{name: "schema", mutate: func(args *BundleArgs) { args.SchemaVersion = "v2" }},
		{name: "bundle id", mutate: func(args *BundleArgs) { args.ID = "bad id" }},
		{name: "generation number", mutate: func(args *BundleArgs) { args.Generation = 0 }},
		{name: "purpose", mutate: func(args *BundleArgs) { args.Purpose = "unknown" }},
		{name: "compatibility", mutate: func(args *BundleArgs) { args.CompatibilityTargetID = "bad id" }},
		{name: "compatibility version", mutate: func(args *BundleArgs) { args.CompatibilityVersion = " " }},
		{name: "key establishment", mutate: func(args *BundleArgs) { args.KeyEstablishmentPolicy = "unknown" }},
		{name: "contradictory required hybrid policy", mutate: func(args *BundleArgs) { args.KeyEstablishmentPolicy = KeyEstablishmentHybridPQRequired }},
		{name: "certificate media type", mutate: func(args *BundleArgs) { args.Certificate.MediaType = MediaTypePublicKey }},
		{name: "private key and reference", mutate: func(args *BundleArgs) { args.PrivateKeyRef = &KeyReference{KeyID: "key-1", ProviderID: "provider"} }},
		{name: "certificate fingerprint", mutate: func(args *BundleArgs) { args.Fingerprints.CertificateSHA256 = "abc" }},
		{name: "public key fingerprint", mutate: func(args *BundleArgs) { args.Fingerprints.PublicKeySHA256 = "xyz" }},
		{name: "validity", mutate: func(args *BundleArgs) { args.NotAfter = args.NotBefore }},
		{name: "duplicate certificate member", mutate: func(args *BundleArgs) {
			args.Chain = []CertificateMember{{GenerationID: args.CertificateGenerationID, Binary: args.Certificate}}
		}},
		{name: "invalid crl id", mutate: func(args *BundleArgs) {
			args.CertificateRevocationLists = []CRLMember{{GenerationID: "bad id", IssuerGenerationID: "certgen-validation", Binary: mustTestBinary(t, MediaTypeCRL)}}
		}},
		{name: "invalid crl issuer id", mutate: func(args *BundleArgs) {
			args.CertificateRevocationLists = []CRLMember{{GenerationID: "crl-1", IssuerGenerationID: "bad id", Binary: mustTestBinary(t, MediaTypeCRL)}}
		}},
		{name: "invalid crl media type", mutate: func(args *BundleArgs) {
			args.CertificateRevocationLists = []CRLMember{{GenerationID: "crl-1", IssuerGenerationID: "certgen-validation", Binary: args.Certificate}}
		}},
		{name: "duplicate crl", mutate: func(args *BundleArgs) {
			crl := CRLMember{GenerationID: "crl-1", IssuerGenerationID: "certgen-validation", Binary: mustTestBinary(t, MediaTypeCRL)}
			args.CertificateRevocationLists = []CRLMember{crl, crl}
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			args := validTestBundleArgs(t)
			test.mutate(&args)
			if _, err := NewBundle(args); err == nil {
				t.Fatal("NewBundle() accepted invalid input")
			}
		})
	}
}

func validTestBundleArgs(t *testing.T) BundleArgs {
	t.Helper()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	privateKey := mustTestBinary(t, MediaTypePrivateKey)
	return BundleArgs{
		SchemaVersion:           BundleSchemaV1,
		ID:                      "bundle-validation",
		CertificateID:           "cert-validation",
		CertificateGenerationID: "certgen-validation",
		Generation:              1,
		Purpose:                 PurposeTLSServer,
		CompatibilityTargetID:   CompatibilityPortableX509,
		CompatibilityVersion:    CompatibilityPortableVersion,
		KeyEstablishmentPolicy:  KeyEstablishmentClassicalCompatible,
		TLSNamedGroups:          resolvedTestTLSGroups(t, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		Certificate:             mustTestBinary(t, MediaTypeCertificate),
		PublicKey:               mustTestBinary(t, MediaTypePublicKey),
		PrivateKey:              &privateKey,
		Fingerprints: Fingerprints{
			CertificateSHA256: strings.Repeat("a", 64),
			PublicKeySHA256:   strings.Repeat("b", 64),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}
}

func resolvedTestTLSGroups(t *testing.T, id CompatibilityTargetID, policy KeyEstablishmentPolicy) []TLSNamedGroup {
	t.Helper()
	target, ok := BuiltInCompatibilityTarget(id)
	if !ok {
		t.Fatalf("compatibility target %q not found", id)
	}
	groups, err := ResolveTLSNamedGroups(target, policy)
	if err != nil {
		t.Fatal(err)
	}
	return groups
}

func mustTestBinary(t *testing.T, mediaType string) Binary {
	t.Helper()
	binary, err := NewBinary(mediaType, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	return binary
}
