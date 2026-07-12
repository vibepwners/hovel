package pki

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTypedIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "simple", input: "authority-01J", valid: true},
		{name: "provider scoped", input: "mesh:provider/listener", valid: true},
		{name: "trimmed", input: "  cert-1  ", valid: true},
		{name: "empty", input: "  ", valid: false},
		{name: "spaces", input: "cert one", valid: false},
		{name: "control", input: "cert\none", valid: false},
		{name: "too long", input: strings.Repeat("a", MaxIDLength+1), valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			id, err := NewCertificateID(test.input)
			if test.valid && err != nil {
				t.Fatalf("NewCertificateID() error = %v", err)
			}
			if !test.valid && err == nil {
				t.Fatalf("NewCertificateID() = %q, want error", id)
			}
		})
	}
	if err := CertificateID(" cert-1 ").Validate(); err == nil {
		t.Fatal("directly constructed non-canonical id passed validation")
	}
}

func TestSerialNumber(t *testing.T) {
	t.Parallel()

	serial, err := ParseSerialNumber("0x00010203")
	if err != nil {
		t.Fatal(err)
	}
	if serial != "010203" {
		t.Fatalf("serial = %q, want 010203", serial)
	}
	decoded, err := serial.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "\x01\x02\x03" {
		t.Fatalf("serial bytes = %x, want 010203", decoded)
	}
	if _, err := NewSerialNumber(make([]byte, MaxSerialBytes+1)); err == nil {
		t.Fatal("NewSerialNumber() accepted an oversized serial")
	}
	if _, err := NewSerialNumber([]byte{0}); err == nil {
		t.Fatal("NewSerialNumber() accepted zero")
	}
	if _, err := SerialNumber("00").Bytes(); err == nil {
		t.Fatal("directly constructed zero serial passed validation")
	}
	highBitSerial := make([]byte, MaxSerialBytes)
	highBitSerial[0] = 0x80
	if _, err := NewSerialNumber(highBitSerial); err == nil {
		t.Fatal("NewSerialNumber() accepted a value requiring a 21st sign octet")
	}
}

func TestBuiltInProfilesValidate(t *testing.T) {
	t.Parallel()

	profiles := BuiltInProfiles()
	if len(profiles) != 12 {
		t.Fatalf("profile count = %d, want 12", len(profiles))
	}
	seen := map[ProfileID]struct{}{}
	for _, profile := range profiles {
		if err := profile.Validate(); err != nil {
			t.Fatalf("profile %q: %v", profile.ID, err)
		}
		if _, ok := seen[profile.ID]; ok {
			t.Fatalf("duplicate profile %q", profile.ID)
		}
		seen[profile.ID] = struct{}{}
	}
	quantum, ok := BuiltInProfile(ProfilePQHybridMutual)
	if !ok || quantum.KeyEstablishment != KeyEstablishmentHybridPQRequired || quantum.Compatibility != CompatibilityGo126PQHybrid {
		t.Fatalf("post-quantum hybrid profile = %#v", quantum)
	}
	target, ok := BuiltInCompatibilityTarget(quantum.Compatibility)
	if !ok || !target.SupportsHybridPostQuantumTLS() {
		t.Fatalf("post-quantum hybrid compatibility target = %#v", target)
	}
}

func TestCertificateTemplateValidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	serial, err := NewSerialNumber([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	valid := CertificateTemplate{
		SerialNumber: serial,
		Subject: DistinguishedName{
			CommonName: "listener.test",
		},
		NotBefore:          now,
		NotAfter:           now.Add(time.Hour),
		Key:                KeySpec{Source: KeySourceGenerated, Algorithm: KeyAlgorithmECDSA, Curve: EllipticCurveP256},
		SignatureAlgorithm: SignatureAlgorithmECDSASHA256,
		SubjectAlternativeNames: SubjectAlternativeNames{
			DNSNames:    []string{"listener.test"},
			IPAddresses: []string{"127.0.0.1"},
			URIs:        []string{"spiffe://hovel/listener"},
		},
		KeyUsage:               KeyUsageDigitalSignature,
		ExtendedKeyUsages:      []ExtendedKeyUsage{ExtendedKeyUsageServerAuth},
		SubjectKeyIdentifier:   KeyIdentifier{Mode: IdentifierModeAutomatic},
		AuthorityKeyIdentifier: KeyIdentifier{Mode: IdentifierModeAutomatic},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid template: %v", err)
	}
	existingKey := cloneTemplate(valid)
	existingKey.Key.Source = KeySourceExisting
	existingKey.Key.Existing = "key-existing"
	if err := existingKey.Validate(); err != nil {
		t.Fatalf("valid existing-key template: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CertificateTemplate)
	}{
		{name: "zero serial", mutate: func(template *CertificateTemplate) { template.SerialNumber = "" }},
		{name: "reversed validity", mutate: func(template *CertificateTemplate) { template.NotAfter = template.NotBefore }},
		{name: "subsecond validity", mutate: func(template *CertificateTemplate) { template.NotBefore = template.NotBefore.Add(time.Nanosecond) }},
		{name: "bad san ip", mutate: func(template *CertificateTemplate) {
			template.SubjectAlternativeNames.IPAddresses = []string{"999.1.1.1"}
		}},
		{name: "unknown signature algorithm", mutate: func(template *CertificateTemplate) { template.SignatureAlgorithm = SignatureAlgorithm("md5-rsa") }},
		{name: "unknown distinguished name string type", mutate: func(template *CertificateTemplate) {
			template.Subject.ExtraNames = []Attribute{{OID: "1.2.3", Value: "value", StringType: ASN1StringType("teletex")}}
		}},
		{name: "leaf cert sign", mutate: func(template *CertificateTemplate) { template.KeyUsage |= KeyUsageCertificateSign }},
		{name: "duplicate eku", mutate: func(template *CertificateTemplate) {
			template.ExtendedKeyUsages = []ExtendedKeyUsage{ExtendedKeyUsageServerAuth, ExtendedKeyUsageServerAuth}
		}},
		{name: "known eku repeated as unknown oid", mutate: func(template *CertificateTemplate) {
			template.UnknownExtendedKeyUsages = []OID{oidExtendedKeyUsageServerAuth}
		}},
		{name: "leaf name constraints", mutate: func(template *CertificateTemplate) { template.NameConstraints.PermittedDNSDomains = []string{".test"} }},
		{name: "duplicate extension", mutate: func(template *CertificateTemplate) {
			template.CustomExtensions = []CustomExtension{{OID: "1.2.3", DER: []byte{5, 0}}, {OID: "1.2.3", DER: []byte{5, 0}}}
		}},
		{name: "custom extension collides with typed field", mutate: func(template *CertificateTemplate) {
			template.CustomExtensions = []CustomExtension{{OID: oidExtensionBasicConstraints, DER: []byte{5, 0}}}
		}},
		{name: "subject unicode control", mutate: func(template *CertificateTemplate) {
			template.Subject.CommonName = "listener\u0085test"
		}},
		{name: "duplicate policy oid", mutate: func(template *CertificateTemplate) {
			template.PolicyOIDs = []OID{"1.2.3", "1.2.3"}
		}},
		{name: "existing id on generated key", mutate: func(template *CertificateTemplate) {
			template.Key.Existing = "unexpected-key"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := cloneTemplate(valid)
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("CertificateTemplate.Validate() error = nil, want error")
			}
		})
	}
}

func TestBundleJSONAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	certificate, err := NewBinary(MediaTypeCertificate, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := NewBinary(MediaTypePublicKey, []byte{4, 5, 6})
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := NewBinary(MediaTypePrivateKey, []byte{7, 8, 9})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	bundle, err := NewBundle(BundleArgs{
		SchemaVersion:           BundleSchemaV1,
		ID:                      "bundle-1",
		CertificateID:           "cert-1",
		CertificateGenerationID: "certgen-1",
		Generation:              1,
		Purpose:                 PurposeTLSServer,
		CompatibilityTargetID:   CompatibilityPortableX509,
		CompatibilityVersion:    CompatibilityPortableVersion,
		KeyEstablishmentPolicy:  KeyEstablishmentClassicalCompatible,
		TLSNamedGroups:          resolvedTestTLSGroups(t, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		Certificate:             certificate,
		PublicKey:               publicKey,
		PrivateKey:              &privateKey,
		Fingerprints: Fingerprints{
			CertificateSHA256: strings.Repeat("a", 64),
			PublicKeySHA256:   strings.Repeat("b", 64),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey.Data[0] = 0
	if bundle.PrivateKey == nil || bundle.PrivateKey.Data[0] != 7 {
		t.Fatal("bundle retained caller-owned private key bytes")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"encoding":"base64-der"`) || !strings.Contains(string(encoded), `"data":"AQID"`) {
		t.Fatalf("bundle json = %s", encoded)
	}
	decoded, err := DecodeBundleJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	invalidJSON := strings.Replace(string(encoded), `"generation":1`, `"generation":0`, 1)
	if err := json.Unmarshal([]byte(invalidJSON), &decoded); err == nil {
		t.Fatal("json.Unmarshal() accepted an invalid bundle")
	}
	unknownJSON := strings.Replace(string(encoded), `"schemaVersion"`, `"unknown":true,"schemaVersion"`, 1)
	if _, err := DecodeBundleJSON([]byte(unknownJSON)); err == nil {
		t.Fatal("DecodeBundleJSON() accepted an unknown field")
	}
	if _, err := DecodeBundleJSON(append(encoded, []byte(` {}`)...)); err == nil {
		t.Fatal("DecodeBundleJSON() accepted trailing json")
	}
	public := bundle.Public()
	if public.PrivateKey != nil || public.PrivateKeyRef != nil {
		t.Fatal("Bundle.Public() retained private material")
	}
	public.Certificate.Data[0] = 0
	if bundle.Certificate.Data[0] != 1 {
		t.Fatal("Bundle.Public() aliased certificate bytes")
	}

	keyRef := KeyReference{KeyID: "key-1", ProviderID: "keystore", Capabilities: []string{"sign-certificate"}}
	if _, err := NewBundle(BundleArgs{
		SchemaVersion:           BundleSchemaV1,
		ID:                      "bundle-2",
		CertificateID:           "cert-1",
		CertificateGenerationID: "certgen-1",
		Generation:              1,
		Purpose:                 PurposeTLSServer,
		CompatibilityTargetID:   CompatibilityPortableX509,
		CompatibilityVersion:    CompatibilityPortableVersion,
		KeyEstablishmentPolicy:  KeyEstablishmentClassicalCompatible,
		TLSNamedGroups:          resolvedTestTLSGroups(t, CompatibilityPortableX509, KeyEstablishmentClassicalCompatible),
		Certificate:             certificate,
		PublicKey:               publicKey,
		PrivateKey:              &privateKey,
		PrivateKeyRef:           &keyRef,
		Fingerprints:            bundle.Fingerprints,
		NotBefore:               now,
		NotAfter:                now.Add(time.Hour),
	}); err == nil {
		t.Fatal("NewBundle() accepted private key and reference together")
	}
}

func TestHybridPreferredTLSGroupsPreservePreferenceAndFallback(t *testing.T) {
	t.Parallel()

	target, ok := BuiltInCompatibilityTarget(CompatibilityGo126PQHybrid)
	if !ok {
		t.Fatal("Go hybrid compatibility target is unavailable")
	}
	groups, err := ResolveTLSNamedGroups(target, KeyEstablishmentHybridPQPreferred)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) < 2 || !groups[0].IsHybridPostQuantum() || groups[len(groups)-1].IsHybridPostQuantum() {
		t.Fatalf("hybrid-preferred groups = %v, want hybrid-first with classical fallback", groups)
	}
	if err := ValidateKeyEstablishment(KeyEstablishmentHybridPQPreferred, []TLSNamedGroup{TLSNamedGroupX25519MLKEM768}); err == nil {
		t.Fatal("hybrid-pq-preferred accepted no classical fallback")
	}
	custom, err := NewCompatibilityTarget(CompatibilityTargetArgs{
		SchemaVersion:       CompatibilityTargetSchemaV1,
		ID:                  "preference-order",
		Version:             "1",
		KeyAlgorithms:       []KeyAlgorithm{KeyAlgorithmECDSA},
		SignatureAlgorithms: []SignatureAlgorithm{SignatureAlgorithmECDSASHA256},
		TLSNamedGroups:      []TLSNamedGroup{TLSNamedGroupP521, TLSNamedGroupX25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	if custom.TLSNamedGroups[0] != TLSNamedGroupP521 {
		t.Fatalf("compatibility target reordered preferences: %v", custom.TLSNamedGroups)
	}
}

func FuzzSerialNumberRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{{1}, {0, 1}, {0x7f}, {0x80}, make([]byte, MaxSerialBytes+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		serial, err := NewSerialNumber(value)
		if err != nil {
			return
		}
		decoded, err := serial.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := NewSerialNumber(decoded)
		if err != nil || roundTrip != serial {
			t.Fatalf("serial round trip = %q, %v; want %q", roundTrip, err, serial)
		}
	})
}

func FuzzOIDValidation(f *testing.F) {
	for _, seed := range []string{"1.2.840.113549", "2.5.29.19", "01.2", "1..2", "3.1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		oid, err := NewOID(value)
		if err != nil {
			return
		}
		if string(oid) != strings.TrimSpace(value) {
			t.Fatalf("oid = %q, want canonical input %q", oid, value)
		}
	})
}
