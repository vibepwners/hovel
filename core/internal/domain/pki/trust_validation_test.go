package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestValidateTrustSetGenerationMaterialRequiresCurrentCertificatesAndCRLs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	root := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-root",
		generationID:  "certgen-root",
		authorityID:   "authority-root",
		profileID:     ProfileRootModern,
		role:          AuthorityRoleRoot,
		notBefore:     now.Add(-time.Hour),
		notAfter:      now.Add(2 * time.Hour),
	})
	crl := newTrustTestCRL(t, root, now)
	trust, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-current", TrustSetID: "trust-current", Generation: 1,
		AnchorGenerationIDs: []GenerationID{root.ID},
		CRLGenerationIDs:    []CRLGenerationID{crl.ID},
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	material := TrustMaterial{Certificates: []CertificateGeneration{root}, CRLs: []CRLGeneration{crl}}
	if err := ValidateTrustSetGenerationMaterial(trust, material, now); err != nil {
		t.Fatalf("valid trust material: %v", err)
	}

	tests := []struct {
		name string
		now  time.Time
		want string
	}{
		{name: "certificate not yet valid", now: root.Template.NotBefore.Add(-time.Second), want: "not currently valid"},
		{name: "certificate expired", now: root.Template.NotAfter, want: "not currently valid"},
		{name: "crl expired", now: crl.NextUpdate, want: "crl generation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateTrustSetGenerationMaterial(trust, material, test.now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateTrustSetGenerationMaterial() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateTrustSetGenerationMaterialRejectsInvalidInventory(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	root := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-inventory-root", generationID: "certgen-inventory-root",
		authorityID: "authority-inventory-root", profileID: ProfileRootModern,
		role: AuthorityRoleRoot, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	crl := newTrustTestCRL(t, root, now)
	trust, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-inventory", TrustSetID: "trust-inventory", Generation: 1,
		AnchorGenerationIDs: []GenerationID{root.ID}, CRLGenerationIDs: []CRLGenerationID{crl.ID},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	validMaterial := TrustMaterial{Certificates: []CertificateGeneration{root}, CRLs: []CRLGeneration{crl}}

	invalidTrust := trust.Clone()
	invalidTrust.ID = "bad id"
	if err := ValidateTrustSetGenerationMaterial(invalidTrust, validMaterial, now); err == nil {
		t.Fatal("ValidateTrustSetGenerationMaterial() accepted an invalid trust generation")
	}
	for _, invalidTime := range []time.Time{
		{},
		now.In(time.FixedZone("noncanonical", int(time.Hour/time.Second))),
	} {
		if err := ValidateTrustSetGenerationMaterial(trust, validMaterial, invalidTime); err == nil {
			t.Fatalf("ValidateTrustSetGenerationMaterial() accepted time %v", invalidTime)
		}
	}

	otherRoot := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-inventory-other", generationID: "certgen-inventory-other",
		authorityID: "authority-inventory-other", profileID: ProfileRootModern,
		role: AuthorityRoleRoot, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	leaf := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-inventory-leaf", generationID: "certgen-inventory-leaf",
		authorityID: "authority-inventory-leaf", profileID: ProfileTLSServer,
		issuerAuthorityID: root.OwningAuthorityID, issuerGenerationID: root.ID,
		chainGenerationIDs: []GenerationID{root.ID}, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	invalidCertificate := root.Clone()
	invalidCertificate.ID = "bad id"
	unusableCertificate := root.Clone()
	unusableCertificate.State = CertificateStateRevoked

	certificateTests := []struct {
		name      string
		trust     TrustSetGeneration
		material  []CertificateGeneration
		wantError string
	}{
		{name: "invalid certificate", trust: trust, material: []CertificateGeneration{invalidCertificate}, wantError: "validate trust certificate"},
		{name: "unreferenced certificate", trust: trust, material: []CertificateGeneration{root, otherRoot}, wantError: "unreferenced"},
		{name: "duplicate certificate", trust: trust, material: []CertificateGeneration{root, root}, wantError: "duplicate"},
		{name: "incomplete certificate inventory", trust: trust, wantError: "incomplete"},
		{name: "unusable certificate", trust: trust, material: []CertificateGeneration{unusableCertificate}, wantError: "not usable"},
	}
	leafTrust, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-inventory-leaf", TrustSetID: "trust-inventory-leaf", Generation: 1,
		AnchorGenerationIDs: []GenerationID{leaf.ID}, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateTests = append(certificateTests, struct {
		name      string
		trust     TrustSetGeneration
		material  []CertificateGeneration
		wantError string
	}{name: "non ca certificate", trust: leafTrust, material: []CertificateGeneration{leaf}, wantError: "not a certificate authority"})
	for _, test := range certificateTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateTrustSetGenerationMaterial(test.trust, TrustMaterial{Certificates: test.material, CRLs: validMaterial.CRLs}, now)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateTrustSetGenerationMaterial() error = %v, want %q", err, test.wantError)
			}
		})
	}

	invalidCRL := crl.Clone()
	invalidCRL.ID = "bad id"
	unreferencedCRL := crl.Clone()
	unreferencedCRL.ID = "crlgen-unreferenced"
	wrongIssuerCRL := crl.Clone()
	wrongIssuerCRL.IssuerGenerationID = otherRoot.ID
	crlTests := []struct {
		name      string
		material  []CRLGeneration
		wantError string
	}{
		{name: "invalid crl", material: []CRLGeneration{invalidCRL}, wantError: "validate trust crl"},
		{name: "unreferenced crl", material: []CRLGeneration{crl, unreferencedCRL}, wantError: "unreferenced"},
		{name: "duplicate crl", material: []CRLGeneration{crl, crl}, wantError: "duplicate"},
		{name: "wrong crl issuer", material: []CRLGeneration{wrongIssuerCRL}, wantError: "issuer is not in"},
		{name: "incomplete crl inventory", wantError: "incomplete"},
	}
	for _, test := range crlTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateTrustSetGenerationMaterial(trust, TrustMaterial{Certificates: validMaterial.Certificates, CRLs: test.material}, now)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateTrustSetGenerationMaterial() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestValidateAuthorityRolloverOverlapMaterialProvesSubordinateChain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	root := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-root",
		generationID:  "certgen-root",
		authorityID:   "authority-root",
		profileID:     ProfileRootModern,
		role:          AuthorityRoleRoot,
		notBefore:     now.Add(-time.Hour),
		notAfter:      now.Add(time.Hour),
	})
	previous := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID:      "certificate-previous",
		generationID:       "certgen-previous",
		authorityID:        "authority-previous",
		profileID:          ProfileSubordinateModern,
		role:               AuthorityRoleSubordinate,
		issuerAuthorityID:  root.OwningAuthorityID,
		issuerGenerationID: root.ID,
		chainGenerationIDs: []GenerationID{root.ID},
		notBefore:          now.Add(-time.Hour),
		notAfter:           now.Add(time.Hour),
	})
	replacement := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID:      "certificate-replacement",
		generationID:       "certgen-replacement",
		authorityID:        "authority-replacement",
		profileID:          ProfileSubordinateModern,
		role:               AuthorityRoleSubordinate,
		issuerAuthorityID:  root.OwningAuthorityID,
		issuerGenerationID: root.ID,
		chainGenerationIDs: []GenerationID{root.ID},
		notBefore:          now.Add(-time.Hour),
		notAfter:           now.Add(time.Hour),
	})
	previousAuthority := newTrustTestAuthority(t, previous, AuthorityRoleSubordinate, root.OwningAuthorityID, now)
	replacementAuthority := newTrustTestAuthority(t, replacement, AuthorityRoleSubordinate, root.OwningAuthorityID, now)
	trust, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-overlap", TrustSetID: "trust-rollover", Generation: 1,
		AnchorGenerationIDs: []GenerationID{root.ID},
		IntermediateGenerationIDs: []GenerationID{
			previous.ID,
			replacement.ID,
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	material := TrustMaterial{Certificates: []CertificateGeneration{root, previous, replacement}}
	if err := ValidateAuthorityRolloverOverlapMaterial(
		trust, previousAuthority, replacementAuthority, previous, replacement, material, now,
	); err != nil {
		t.Fatalf("valid subordinate rollover chain: %v", err)
	}

	wrongIssuer := replacement.Clone()
	wrongIssuer.IssuerAuthorityID = "authority-unrelated"
	material.Certificates[2] = wrongIssuer
	err = ValidateAuthorityRolloverOverlapMaterial(
		trust, previousAuthority, replacementAuthority, previous, wrongIssuer, material, now,
	)
	if err == nil || !strings.Contains(err.Error(), "parent chain") {
		t.Fatalf("wrong issuer error = %v", err)
	}
}

func TestValidateAuthorityRolloverFinalMaterial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	root := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-final-root", generationID: "certgen-final-root",
		authorityID: "authority-final-root", profileID: ProfileRootModern,
		role: AuthorityRoleRoot, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	previous := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-final-previous", generationID: "certgen-final-previous",
		authorityID: "authority-final-previous", profileID: ProfileSubordinateModern,
		role: AuthorityRoleSubordinate, issuerAuthorityID: root.OwningAuthorityID,
		issuerGenerationID: root.ID, chainGenerationIDs: []GenerationID{root.ID},
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	replacement := newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-final-replacement", generationID: "certgen-final-replacement",
		authorityID: "authority-final-replacement", profileID: ProfileSubordinateModern,
		role: AuthorityRoleSubordinate, issuerAuthorityID: root.OwningAuthorityID,
		issuerGenerationID: root.ID, chainGenerationIDs: []GenerationID{root.ID},
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	previousAuthority := newTrustTestAuthority(t, previous, AuthorityRoleSubordinate, root.OwningAuthorityID, now)
	replacementAuthority := newTrustTestAuthority(t, replacement, AuthorityRoleSubordinate, root.OwningAuthorityID, now)
	trust, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-final", TrustSetID: "trust-final", Generation: 1,
		AnchorGenerationIDs:       []GenerationID{root.ID},
		IntermediateGenerationIDs: []GenerationID{replacement.ID},
		CreatedAt:                 now,
	})
	if err != nil {
		t.Fatal(err)
	}
	material := TrustMaterial{Certificates: []CertificateGeneration{root, replacement}}
	if err := ValidateAuthorityRolloverFinalMaterial(
		trust, previousAuthority, replacementAuthority, previous, replacement, material, now,
	); err != nil {
		t.Fatalf("ValidateAuthorityRolloverFinalMaterial() error = %v", err)
	}

	invalidPrevious := previous.Clone()
	invalidPrevious.ID = "bad id"
	err = ValidateAuthorityRolloverFinalMaterial(
		trust, previousAuthority, replacementAuthority, invalidPrevious, replacement, material, now,
	)
	if err == nil || !strings.Contains(err.Error(), "previous rollover") {
		t.Fatalf("invalid previous generation error = %v", err)
	}

	wrongReplacement := replacement.Clone()
	wrongReplacement.OwningAuthorityID = previousAuthority.ID
	err = ValidateAuthorityRolloverFinalMaterial(
		trust, previousAuthority, replacementAuthority, previous, wrongReplacement, material, now,
	)
	if err == nil {
		t.Fatal("ValidateAuthorityRolloverFinalMaterial() accepted a mismatched replacement generation")
	}
}

type trustTestGenerationArgs struct {
	certificateID      CertificateID
	generationID       GenerationID
	authorityID        AuthorityID
	profileID          ProfileID
	role               AuthorityRole
	issuerAuthorityID  AuthorityID
	issuerGenerationID GenerationID
	chainGenerationIDs []GenerationID
	notBefore          time.Time
	notAfter           time.Time
}

func newTrustTestGeneration(t *testing.T, args trustTestGenerationArgs) CertificateGeneration {
	t.Helper()

	serial, err := NewSerialNumber([]byte{byte(len(args.generationID))})
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte("certificate:" + args.generationID)
	fingerprint := sha256.Sum256(encoded)
	profile, ok := BuiltInProfile(args.profileID)
	if !ok {
		t.Fatalf("profile %q not found", args.profileID)
	}
	target, ok := BuiltInCompatibilityTarget(profile.Compatibility)
	if !ok {
		t.Fatalf("compatibility target %q not found", profile.Compatibility)
	}
	tlsNamedGroups, err := ResolveTLSNamedGroups(target, profile.KeyEstablishment)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := NewCertificateGeneration(GenerationArgs{
		CertificateID: args.certificateID, ID: args.generationID, Generation: 1,
		OwningAuthorityID: args.authorityID, IssuerAuthorityID: args.issuerAuthorityID,
		IssuerGenerationID: args.issuerGenerationID, ProfileID: args.profileID,
		Template: CertificateTemplate{
			SerialNumber: serial, Subject: DistinguishedName{CommonName: string(args.authorityID)},
			NotBefore: args.notBefore, NotAfter: args.notAfter, Key: profile.Key,
			SignatureAlgorithm: profile.Signature, BasicConstraints: profile.BasicConstraints,
			KeyUsage:               profile.KeyUsage,
			SubjectKeyIdentifier:   KeyIdentifier{Mode: IdentifierModeAutomatic},
			AuthorityKeyIdentifier: KeyIdentifier{Mode: IdentifierModeAutomatic},
		},
		BackendID: BackendBuiltinX509, BackendVersion: "1",
		BackendCapabilityHash: strings.Repeat("a", sha256.Size*2),
		SigningBackendID:      BackendBuiltinX509, SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("b", sha256.Size*2),
		CompatibilityTargetID:        CompatibilityPortableX509,
		CompatibilityVersion:         CompatibilityPortableVersion,
		Purpose:                      profile.Purpose, ExportPolicy: profile.ExportPolicy,
		KeyEstablishment: profile.KeyEstablishment, TLSNamedGroups: tlsNamedGroups,
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]), State: CertificateStateActive,
		KeyID: "key-" + KeyID(args.generationID), CertificateDER: encoded, PublicKeySPKI: []byte("public-key"),
		ChainGenerationIDs: args.chainGenerationIDs, CreatedAt: args.notBefore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if args.role != profile.AuthorityRole {
		t.Fatalf("profile %q role = %q, want %q", args.profileID, profile.AuthorityRole, args.role)
	}
	return generation
}

func newTrustTestAuthority(
	t *testing.T,
	generation CertificateGeneration,
	role AuthorityRole,
	parentID AuthorityID,
	now time.Time,
) Authority {
	t.Helper()

	authority, err := NewAuthority(AuthorityArgs{
		ID: generation.OwningAuthorityID, Name: string(generation.OwningAuthorityID), Role: role,
		Origin: OriginGenerated, SignerMode: SignerModeLocal, ParentAuthorityID: parentID,
		State: AuthorityStateActive, ActiveGenerationID: generation.ID, ProfileID: generation.ProfileID,
		SignerRef: string(generation.KeyID), ExportPolicy: generation.ExportPolicy,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func newTrustTestCRL(t *testing.T, issuer CertificateGeneration, now time.Time) CRLGeneration {
	t.Helper()

	encoded := []byte("crl:" + issuer.ID)
	fingerprint := sha256.Sum256(encoded)
	crl, err := NewCRLGeneration(CRLGenerationArgs{
		ID: "crlgen-current", AuthorityID: issuer.OwningAuthorityID, IssuerGenerationID: issuer.ID,
		Number: 1, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		SigningBackendID: BackendBuiltinX509, SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("c", sha256.Size*2),
		SignatureAlgorithm:           issuer.Template.SignatureAlgorithm,
		FingerprintSHA256:            hex.EncodeToString(fingerprint[:]), CRLDER: encoded, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return crl
}
