package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func TestBackendDescriptorAndKeyGeneration(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	descriptor := backend.Descriptor()
	if descriptor.ID != "builtin-x509" || descriptor.Version != BackendVersion {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	if descriptor.CapabilityHash == "" || !descriptor.SupportsKey(domainpki.KeyAlgorithmECDSA) || !descriptor.SupportsKey(domainpki.KeyAlgorithmRSA) || !descriptor.SupportsKey(domainpki.KeyAlgorithmEd25519) {
		t.Fatalf("descriptor does not advertise expected capabilities: %#v", descriptor)
	}

	tests := []struct {
		name string
		spec domainpki.KeySpec
	}{
		{name: "ecdsa p256", spec: domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256}},
		{name: "rsa 2048", spec: domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmRSA, RSABits: 2048}},
		{name: "ed25519", spec: domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmEd25519}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			material, err := backend.GenerateKey(t.Context(), domainpki.KeyID("key-1"), test.spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := material.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := validator.ValidateKey(t.Context(), apppki.KeyValidationRequest{Spec: test.spec, Material: material}); err != nil {
				t.Fatal(err)
			}
			privateKey, err := x509.ParsePKCS8PrivateKey(material.PrivateKeyPKCS8)
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			publicKey, err := x509.ParsePKIXPublicKey(material.PublicKeySPKI)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			signer, ok := privateKey.(crypto.Signer)
			if !ok {
				t.Fatalf("private key type %T does not implement crypto.Signer", privateKey)
			}
			privateSPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			if string(privateSPKI) != string(material.PublicKeySPKI) || publicKey == nil {
				t.Fatal("public and private key material do not match")
			}
		})
	}
}

func TestValidatorRejectsMismatchedKeyPair(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	spec := domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256}
	first, err := backend.GenerateKey(t.Context(), "key-first", spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.GenerateKey(t.Context(), "key-second", spec)
	if err != nil {
		t.Fatal(err)
	}
	first.PrivateKeyPKCS8 = second.PrivateKeyPKCS8
	if err := validator.ValidateKey(t.Context(), apppki.KeyValidationRequest{Spec: spec, Material: first}); err == nil {
		t.Fatal("ValidateKey() accepted unrelated public and private keys")
	}
}

func TestIssueRootSubordinateAndLeaf(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)

	rootKey := generateTestKey(t, backend, "key-root")
	rootTemplate := testTemplate(t, now, 1, "Hovel test root", true, nil)
	rootIssued := issueTestCertificate(t, backend, validator, rootTemplate, rootKey, nil, apppki.KeyMaterial{})
	root, err := x509.ParseCertificate(rootIssued.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || len(root.SubjectKeyId) == 0 || string(root.SubjectKeyId) != string(root.AuthorityKeyId) {
		t.Fatalf("unexpected root identifiers: ski=%x aki=%x", root.SubjectKeyId, root.AuthorityKeyId)
	}

	subordinateKey := generateTestKey(t, backend, "key-subordinate")
	subordinateTemplate := testTemplate(t, now.Add(time.Minute), 2, "Hovel test subordinate", true, nil)
	subordinateTemplate.BasicConstraints.MaxPathLenZero = true
	subordinateIssued := issueTestCertificate(t, backend, validator, subordinateTemplate, subordinateKey, rootIssued.CertificateDER, rootKey)
	subordinate, err := x509.ParseCertificate(subordinateIssued.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := subordinate.CheckSignatureFrom(root); err != nil {
		t.Fatalf("subordinate signature: %v", err)
	}

	leafKey := generateTestKey(t, backend, "key-leaf")
	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	leafTemplate := testTemplate(t, now.Add(2*time.Minute), 3, "listener.test", false, []string{"listener.test"})
	leafTemplate.BasicConstraints.Critical = false
	leafTemplate.SubjectAlternativeNames.IPAddresses = []string{"127.0.0.1"}
	leafTemplate.ExtendedKeyUsages = []domainpki.ExtendedKeyUsage{domainpki.ExtendedKeyUsageServerAuth, domainpki.ExtendedKeyUsageClientAuth}
	attributeOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	leafTemplate.Subject.ExtraNames = []domainpki.Attribute{{OID: domainpki.OID(attributeOID.String()), Value: "printable", StringType: domainpki.ASN1StringTypePrintable}}
	leafTemplate.CustomExtensions = []domainpki.CustomExtension{{OID: domainpki.OID(customOID.String()), DER: []byte{5, 0}}}
	leafIssued := issueTestCertificate(t, backend, validator, leafTemplate, leafKey, subordinateIssued.CertificateDER, subordinateKey)
	leaf, err := x509.ParseCertificate(leafIssued.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(subordinate); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	if len(leaf.Extensions) == 0 || !hasExtension(leaf.Extensions, customOID) {
		t.Fatal("issued leaf is missing custom extension")
	}
	if extension, ok := findExtension(leaf.Extensions, oidExtensionBasicConstraints); !ok || extension.Critical {
		t.Fatalf("basic constraints extension = %#v, want non-critical", extension)
	}
	if tag := subjectAttributeTag(t, leaf.RawSubject, attributeOID); tag != asn1.TagPrintableString {
		t.Fatalf("distinguished name attribute tag = %d, want PrintableString", tag)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(subordinate)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "listener.test", CurrentTime: now.Add(3 * time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		t.Fatalf("verify leaf chain: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 3 {
		t.Fatalf("verified chains = %#v", chains)
	}

	verificationTime := now.Add(3 * time.Minute)
	verifyMutualTLS(t, root, subordinate, leafIssued, leafKey, verificationTime)
	verifyBundleCRLSemantics(t, testQuantumBundle(t, leafIssued, subordinate, root), subordinate, subordinateKey, leaf)
}

func TestBackendIssuesAndValidatorChecksCRL(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	issuerKey := generateTestKey(t, backend, "key-crl-issuer")
	issuerTemplate := testTemplate(t, now.Add(-time.Hour), 1, "CRL issuer", true, nil)
	issuerTemplate.NotAfter = now.Add(48 * time.Hour)
	issuer := issueTestCertificate(t, backend, validator, issuerTemplate, issuerKey, nil, apppki.KeyMaterial{})
	serial, err := domainpki.NewSerialNumber([]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	request := apppki.CRLIssueRequest{
		Number: 3, ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour),
		SignatureAlgorithm: domainpki.SignatureAlgorithmECDSASHA256,
		Entries: []apppki.CRLEntry{{
			RevocationID: "revocation-crl-test", SerialNumber: serial,
			RevokedAt: now.Add(-time.Minute), Reason: domainpki.RevocationReasonKeyCompromise,
		}},
		IssuerCertificateDER: issuer.CertificateDER, Signer: issuerKey,
	}
	issued, err := backend.IssueCRL(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	validationRequest := request.ValidationRequest()
	validation, err := validator.ValidateCRL(t.Context(), validationRequest, issued.CRLDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(); err != nil || validation.Accepted == nil {
		t.Fatalf("ValidateCRL() = %#v, %v", validation, err)
	}
	validated := validation.Accepted
	if validated.FingerprintSHA256 != issued.FingerprintSHA256 ||
		validated.SignatureAlgorithm != request.SignatureAlgorithm || !bytes.Equal(validated.CRLDER, issued.CRLDER) {
		t.Fatal("validated CRL does not match backend output")
	}
	tampered := append([]byte(nil), issued.CRLDER...)
	tampered[len(tampered)-1] ^= 0xff
	requireCRLValidationRejected(t, validator, validationRequest, tampered)
	issuerCertificate, err := x509.ParseCertificate(issuer.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := parseSigner(issuerKey.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	serialBytes, err := serial.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	unsupportedExtensionCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber: new(big.Int).SetBytes(serialBytes), RevocationTime: now.Add(-time.Minute), ReasonCode: crlReasonKeyCompromise,
		}},
		Number: new(big.Int).SetUint64(request.Number), ThisUpdate: request.ThisUpdate, NextUpdate: request.NextUpdate,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: []byte{0x05, 0x00}}},
	}, issuerCertificate, signer)
	if err != nil {
		t.Fatal(err)
	}
	requireCRLValidationRejected(t, validator, validationRequest, unsupportedExtensionCRL)
	malformedNumber, err := asn1.Marshal(new(big.Int).SetUint64(request.Number))
	if err != nil {
		t.Fatal(err)
	}
	malformedNumber = append(malformedNumber, 0x00)
	malformedNumberCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber: new(big.Int).SetBytes(serialBytes), RevocationTime: now.Add(-time.Minute), ReasonCode: crlReasonKeyCompromise,
		}},
		Number: new(big.Int).SetUint64(request.Number), ThisUpdate: request.ThisUpdate, NextUpdate: request.NextUpdate,
		ExtraExtensions: []pkix.Extension{{Id: oidExtensionCRLNumber, Value: malformedNumber}},
	}, issuerCertificate, signer)
	if err != nil {
		t.Fatal(err)
	}
	requireCRLValidationRejected(t, validator, validationRequest, malformedNumberCRL)
	malformedReason, err := asn1.Marshal(asn1.Enumerated(crlReasonKeyCompromise))
	if err != nil {
		t.Fatal(err)
	}
	malformedReason = append(malformedReason, 0x00)
	if err := validateCRLEntryExtensions(x509.RevocationListEntry{
		Extensions: []pkix.Extension{{Id: oidExtensionCRLReason, Value: malformedReason}},
	}, crlReasonKeyCompromise); err == nil {
		t.Fatal("validateCRLEntryExtensions() accepted non-canonical reason DER")
	}
	malformedAuthorityKeyID, err := asn1.Marshal(struct {
		KeyIdentifier []byte `asn1:"optional,tag:0"`
		Unexpected    int
	}{KeyIdentifier: issuerCertificate.SubjectKeyId, Unexpected: 1})
	if err != nil {
		t.Fatal(err)
	}
	malformedAuthorityKeyIDCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber: new(big.Int).SetBytes(serialBytes), RevocationTime: now.Add(-time.Minute), ReasonCode: crlReasonKeyCompromise,
		}},
		Number: new(big.Int).SetUint64(request.Number), ThisUpdate: request.ThisUpdate, NextUpdate: request.NextUpdate,
		ExtraExtensions: []pkix.Extension{{Id: oidExtensionAuthorityKeyID, Value: malformedAuthorityKeyID}},
	}, issuerCertificate, signer)
	if err != nil {
		t.Fatal(err)
	}
	requireCRLValidationRejected(t, validator, validationRequest, malformedAuthorityKeyIDCRL)

	for _, test := range []struct {
		name     string
		isCA     bool
		keyUsage x509.KeyUsage
	}{
		{
			name: "not a ca", isCA: false, keyUsage: x509.KeyUsageDigitalSignature,
		},
		{
			name: "no crl sign usage", isCA: true,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			unauthorizedDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: big.NewInt(9), Subject: issuerCertificate.Subject,
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
				KeyUsage: test.keyUsage, BasicConstraintsValid: true, IsCA: test.isCA,
				SubjectKeyId: issuerCertificate.SubjectKeyId,
			}, &x509.Certificate{
				SerialNumber: big.NewInt(9), Subject: issuerCertificate.Subject,
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
				KeyUsage: test.keyUsage, BasicConstraintsValid: true, IsCA: test.isCA,
				SubjectKeyId: issuerCertificate.SubjectKeyId,
			}, issuerCertificate.PublicKey, signer)
			if err != nil {
				t.Fatal(err)
			}
			unauthorizedRequest := validationRequest.Clone()
			unauthorizedRequest.IssuerCertificateDER = unauthorizedDER
			requireCRLValidationRejected(t, validator, unauthorizedRequest, issued.CRLDER)
		})
	}
}

func TestBackendHonorsSupportedKeyIdentifierModes(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	rootKey := generateTestKey(t, backend, "key-identifier-root")
	rootTemplate := testTemplate(t, now, 1, "identifier root", true, nil)
	root := issueTestCertificate(t, backend, validator, rootTemplate, rootKey, nil, apppki.KeyMaterial{})

	tests := []struct {
		name string
		ski  domainpki.KeyIdentifier
		aki  domainpki.KeyIdentifier
	}{
		{
			name: "explicit",
			ski:  domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeExplicit, Value: []byte{1, 2, 3, 4}},
			aki:  domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeExplicit, Value: []byte{5, 6, 7, 8}},
		},
		{
			name: "omitted",
			ski:  domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeOmitted},
			aki:  domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeOmitted},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leafKey := generateTestKey(t, backend, domainpki.KeyID("key-identifier-"+test.name))
			template := testTemplate(t, now.Add(time.Minute), byte(index+2), test.name+".test", false, []string{test.name + ".test"})
			template.SubjectKeyIdentifier = test.ski
			template.AuthorityKeyIdentifier = test.aki
			issued := issueTestCertificate(t, backend, validator, template, leafKey, root.CertificateDER, rootKey)
			certificate := mustParseCertificate(t, issued.CertificateDER)
			if test.name == "omitted" && (len(certificate.SubjectKeyId) != 0 || len(certificate.AuthorityKeyId) != 0) {
				t.Fatalf("omitted identifiers = ski %x aki %x", certificate.SubjectKeyId, certificate.AuthorityKeyId)
			}
		})
	}

	unsupported := testTemplate(t, now, 9, "omitted ca", true, nil)
	unsupported.SubjectKeyIdentifier = domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeOmitted}
	if _, err := backend.Issue(t.Context(), apppki.IssueRequest{Template: unsupported, SubjectPublicKeySPKI: rootKey.PublicKeySPKI, Signer: rootKey}); err == nil {
		t.Fatal("Backend.Issue() accepted an unimplementable omitted ca subject key identifier")
	}
}

func generateTestKey(t *testing.T, backend Backend, id domainpki.KeyID) apppki.KeyMaterial {
	t.Helper()
	material, err := backend.GenerateKey(t.Context(), id, domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256})
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func testTemplate(t *testing.T, now time.Time, serialByte byte, commonName string, isCA bool, dnsNames []string) domainpki.CertificateTemplate {
	t.Helper()
	serial, err := domainpki.NewSerialNumber([]byte{serialByte})
	if err != nil {
		t.Fatal(err)
	}
	usage := domainpki.KeyUsageDigitalSignature
	if isCA {
		usage |= domainpki.KeyUsageCertificateSign | domainpki.KeyUsageCRLSign
	}
	return domainpki.CertificateTemplate{
		SerialNumber: serial,
		Subject: domainpki.DistinguishedName{
			CommonName:   commonName,
			Organization: []string{"Hovel tests"},
		},
		NotBefore:          now,
		NotAfter:           now.Add(24 * time.Hour),
		Key:                domainpki.KeySpec{Source: domainpki.KeySourceGenerated, Algorithm: domainpki.KeyAlgorithmECDSA, Curve: domainpki.EllipticCurveP256},
		SignatureAlgorithm: domainpki.SignatureAlgorithmECDSASHA256,
		SubjectAlternativeNames: domainpki.SubjectAlternativeNames{
			DNSNames: dnsNames,
		},
		BasicConstraints:       domainpki.BasicConstraints{Critical: true, IsCA: isCA},
		KeyUsage:               usage,
		SubjectKeyIdentifier:   domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
		AuthorityKeyIdentifier: domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeAutomatic},
	}
}

func issueTestCertificate(t *testing.T, backend Backend, validator Validator, template domainpki.CertificateTemplate, key apppki.KeyMaterial, issuerDER []byte, signer apppki.KeyMaterial) apppki.IssuedCertificate {
	t.Helper()
	if signer.ID == "" {
		signer = key
	}
	issued, err := backend.Issue(t.Context(), apppki.IssueRequest{
		Template:             template,
		SubjectPublicKeySPKI: key.PublicKeySPKI,
		IssuerCertificateDER: issuerDER,
		Signer:               signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ValidateIssued(t.Context(), apppki.ValidationRequest{
		Template:             template,
		CertificateDER:       issued.CertificateDER,
		SubjectPublicKeySPKI: key.PublicKeySPKI,
		IssuerCertificateDER: issuerDER,
	}); err != nil {
		t.Fatal(err)
	}
	return issued
}

func hasExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func subjectAttributeTag(t *testing.T, rawSubject []byte, target asn1.ObjectIdentifier) int {
	t.Helper()
	var subject asn1.RawValue
	if rest, err := asn1.Unmarshal(rawSubject, &subject); err != nil || len(rest) != 0 || subject.Tag != asn1.TagSequence {
		t.Fatalf("parse subject sequence: rest=%x err=%v tag=%d", rest, err, subject.Tag)
	}
	sets := subject.Bytes
	for len(sets) != 0 {
		var set asn1.RawValue
		var err error
		sets, err = asn1.Unmarshal(sets, &set)
		if err != nil || set.Tag != asn1.TagSet {
			t.Fatalf("parse relative distinguished name: err=%v tag=%d", err, set.Tag)
		}
		attributes := set.Bytes
		for len(attributes) != 0 {
			var sequence asn1.RawValue
			attributes, err = asn1.Unmarshal(attributes, &sequence)
			if err != nil || sequence.Tag != asn1.TagSequence {
				t.Fatalf("parse attribute sequence: err=%v tag=%d", err, sequence.Tag)
			}
			var oid asn1.ObjectIdentifier
			valueBytes, err := asn1.Unmarshal(sequence.Bytes, &oid)
			if err != nil {
				t.Fatal(err)
			}
			var value asn1.RawValue
			if rest, err := asn1.Unmarshal(valueBytes, &value); err != nil || len(rest) != 0 {
				t.Fatalf("parse attribute value: rest=%x err=%v", rest, err)
			}
			if oid.Equal(target) {
				return value.Tag
			}
		}
	}
	t.Fatalf("subject attribute %s not found", target)
	return 0
}

func verifyMutualTLS(
	t *testing.T,
	root, subordinate *x509.Certificate,
	leaf apppki.IssuedCertificate,
	key apppki.KeyMaterial,
	verificationTime time.Time,
) {
	t.Helper()
	certificate := tls.Certificate{Certificate: [][]byte{leaf.CertificateDER, subordinate.Raw, root.Raw}, PrivateKey: parseTestPrivateKey(t, key.PrivateKeyPKCS8), Leaf: mustParseCertificate(t, leaf.CertificateDER)}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	bundle := testQuantumBundle(t, leaf, subordinate, root)
	curves, err := TLSCurvePreferencesForBundleAt(bundle, verificationTime)
	if err != nil {
		t.Fatal(err)
	}
	privateBinary, err := domainpki.NewBinary(domainpki.MediaTypePrivateKey, key.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	privateBundle := bundle.Clone()
	privateBundle.PrivateKey = &privateBinary
	if err := VerifyBundleAt(privateBundle, verificationTime); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleAt(privateBundle, privateBundle.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("VerifyBundleAt() accepted an expired PKIX path")
	}
	encodedBundle, err := json.Marshal(privateBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerifyBundleJSON(encodedBundle, privateBundle.NotBefore.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tamperedFingerprint := bundle.Clone()
	tamperedFingerprint.Fingerprints.CertificateSHA256 = strings.Repeat("0", sha256.Size*2)
	if err := VerifyBundleAt(tamperedFingerprint, verificationTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted a false certificate fingerprint")
	}
	otherKey := generateTestKey(t, NewBackend(), "key-bundle-mismatch")
	mismatchedPrivate, err := domainpki.NewBinary(domainpki.MediaTypePrivateKey, otherKey.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	privateBundle.PrivateKey = &mismatchedPrivate
	if err := VerifyBundleAt(privateBundle, verificationTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted a mismatched private key")
	}
	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        rootPool,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), curves...),
		Time:             func() time.Time { return verificationTime },
	}
	clientConfig := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		RootCAs:          rootPool,
		ServerName:       "listener.test",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), curves...),
		Time:             func() time.Time { return verificationTime },
	}
	serverSide, clientSide := net.Pipe()
	defer func() {
		if err := clientSide.Close(); err != nil {
			t.Errorf("close client pipe: %v", err)
		}
		if err := serverSide.Close(); err != nil {
			t.Errorf("close server pipe: %v", err)
		}
	}()
	server := tls.Server(serverSide, serverConfig)
	client := tls.Client(clientSide, clientConfig)
	errCh := make(chan error, 2)
	go func() { errCh <- server.HandshakeContext(t.Context()) }()
	go func() { errCh <- client.HandshakeContext(t.Context()) }()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("mutual tls handshake: %v", err)
		}
	}
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()
	if !clientState.HandshakeComplete || !serverState.HandshakeComplete || len(serverState.VerifiedChains) == 0 {
		t.Fatal("mutual tls handshake did not verify both peers")
	}
	if clientState.CurveID != serverState.CurveID || !IsHybridPostQuantumTLSCurve(clientState.CurveID) {
		t.Fatalf("tls key exchange = client %s, server %s; want hybrid post-quantum", clientState.CurveID, serverState.CurveID)
	}
	verifyEncryptedExchange(t, server, client, []byte("server-to-client"))
	verifyEncryptedExchange(t, client, server, []byte("client-to-server"))
	verifyClassicalPeerRejected(t, certificate, rootPool, curves, verificationTime)
}

func verifyBundleCRLSemantics(t *testing.T, bundle domainpki.Bundle, issuer *x509.Certificate, issuerKey apppki.KeyMaterial, leaf *x509.Certificate) {
	t.Helper()
	currentTime := leaf.NotBefore.Add(time.Minute)
	privateKey := parseTestPrivateKey(t, issuerKey.PrivateKeyPKCS8)
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("issuer private key type %T does not implement crypto.Signer", privateKey)
	}
	makeCRL := func(thisUpdate, nextUpdate time.Time, revoked []x509.RevocationListEntry) domainpki.Binary {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
			RevokedCertificateEntries: revoked,
		}, issuer, signer)
		if err != nil {
			t.Fatal(err)
		}
		binary, err := domainpki.NewBinary(domainpki.MediaTypeCRL, der)
		if err != nil {
			t.Fatal(err)
		}
		return binary
	}
	validCRL := makeCRL(currentTime.Add(-time.Minute), currentTime.Add(time.Hour), nil)
	withCRL := bundle.Clone()
	withCRL.CertificateRevocationLists = []domainpki.CRLMember{{
		GenerationID: "crl-valid", IssuerGenerationID: "certgen-pq-subordinate", Binary: validCRL,
	}}
	if err := VerifyBundleAt(withCRL, currentTime); err != nil {
		t.Fatalf("valid CRL bundle: %v", err)
	}

	stale := withCRL.Clone()
	stale.CertificateRevocationLists[0].Binary = makeCRL(currentTime.Add(-2*time.Hour), currentTime.Add(-time.Hour), nil)
	if err := VerifyBundleAt(stale, currentTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted a stale CRL")
	}
	revoked := withCRL.Clone()
	revoked.CertificateRevocationLists[0].Binary = makeCRL(currentTime.Add(-time.Minute), currentTime.Add(time.Hour), []x509.RevocationListEntry{{
		SerialNumber: leaf.SerialNumber, RevocationTime: currentTime.Add(-time.Second),
	}})
	if err := VerifyBundleAt(revoked, currentTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted a CRL that revokes the leaf")
	}
	wrongIssuer := withCRL.Clone()
	wrongIssuer.CertificateRevocationLists[0].IssuerGenerationID = "certgen-pq-root"
	if err := VerifyBundleAt(wrongIssuer, currentTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted a CRL bound to the wrong generation")
	}

	badAnchorDER := append([]byte(nil), bundle.TrustAnchors[0].Data...)
	badAnchorDER[len(badAnchorDER)-1] ^= 0xff
	badAnchor, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, badAnchorDER)
	if err != nil {
		t.Fatal(err)
	}
	badTrust := bundle.Clone()
	badTrust.TrustAnchors = append(badTrust.TrustAnchors, domainpki.CertificateMember{GenerationID: "certgen-bad-anchor", Binary: badAnchor})
	if err := VerifyBundleAt(badTrust, currentTime); err == nil {
		t.Fatal("VerifyBundleAt() accepted an invalid trailing trust anchor")
	}
}

func testQuantumBundle(t *testing.T, leaf apppki.IssuedCertificate, subordinate, root *x509.Certificate) domainpki.Bundle {
	t.Helper()
	certificate := mustParseCertificate(t, leaf.CertificateDER)
	certificateBinary, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBinary, err := domainpki.NewBinary(domainpki.MediaTypePublicKey, leaf.PublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	subordinateBinary, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, subordinate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	rootBinary, err := domainpki.NewBinary(domainpki.MediaTypeCertificate, root.Raw)
	if err != nil {
		t.Fatal(err)
	}
	target, ok := domainpki.BuiltInCompatibilityTarget(domainpki.CompatibilityGo126PQHybrid)
	if !ok {
		t.Fatal("Go hybrid post-quantum compatibility target is unavailable")
	}
	groups, err := domainpki.ResolveTLSNamedGroups(target, domainpki.KeyEstablishmentHybridPQRequired)
	if err != nil {
		t.Fatal(err)
	}
	publicFingerprint := sha256.Sum256(leaf.PublicKeySPKI)
	bundle, err := domainpki.NewBundle(domainpki.BundleArgs{
		SchemaVersion:           domainpki.BundleSchemaV1,
		ID:                      "bundle-pq-test",
		CertificateID:           "cert-pq-test",
		CertificateGenerationID: "certgen-pq-test",
		Generation:              1,
		Purpose:                 domainpki.PurposeDualRoleMTLS,
		CompatibilityTargetID:   target.ID,
		CompatibilityVersion:    target.Version,
		KeyEstablishmentPolicy:  domainpki.KeyEstablishmentHybridPQRequired,
		TLSNamedGroups:          groups,
		Certificate:             certificateBinary,
		PublicKey:               publicKeyBinary,
		Chain:                   []domainpki.CertificateMember{{GenerationID: "certgen-pq-subordinate", Binary: subordinateBinary}},
		TrustAnchors:            []domainpki.CertificateMember{{GenerationID: "certgen-pq-root", Binary: rootBinary}},
		Fingerprints: domainpki.Fingerprints{
			CertificateSHA256: leaf.FingerprintSHA256,
			PublicKeySHA256:   hex.EncodeToString(publicFingerprint[:]),
		},
		NotBefore: certificate.NotBefore,
		NotAfter:  certificate.NotAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func verifyClassicalPeerRejected(
	t *testing.T,
	certificate tls.Certificate,
	rootPool *x509.CertPool,
	required []tls.CurveID,
	verificationTime time.Time,
) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	defer func() {
		if err := clientSide.Close(); err != nil {
			t.Errorf("close incompatible client pipe: %v", err)
		}
		if err := serverSide.Close(); err != nil {
			t.Errorf("close incompatible server pipe: %v", err)
		}
	}()
	server := tls.Server(serverSide, &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), required...),
		Time:             func() time.Time { return verificationTime },
	})
	client := tls.Client(clientSide, &tls.Config{
		RootCAs:          rootPool,
		ServerName:       "listener.test",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		Time:             func() time.Time { return verificationTime },
	})
	errCh := make(chan error, 2)
	go func() { errCh <- server.HandshakeContext(t.Context()) }()
	go func() { errCh <- client.HandshakeContext(t.Context()) }()
	for range 2 {
		if err := <-errCh; err == nil {
			t.Fatal("classical-only peer negotiated with a required-hybrid endpoint")
		}
	}
}

func verifyEncryptedExchange(t *testing.T, writer io.Writer, reader io.Reader, payload []byte) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		written, err := writer.Write(payload)
		if err == nil && written != len(payload) {
			err = io.ErrShortWrite
		}
		errCh <- err
	}()
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, actual); err != nil {
		t.Fatalf("read encrypted tls payload: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write encrypted tls payload: %v", err)
	}
	if string(actual) != string(payload) {
		t.Fatalf("encrypted tls payload = %q, want %q", actual, payload)
	}
}

func parseTestPrivateKey(t *testing.T, der []byte) any {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustParseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestValidatorRejectsMismatchedPublicKey(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	key := generateTestKey(t, backend, "key-1")
	otherKey := generateTestKey(t, backend, "key-2")
	template := testTemplate(t, now, 1, "root", true, nil)
	issued, err := backend.Issue(t.Context(), apppki.IssueRequest{Template: template, SubjectPublicKeySPKI: key.PublicKeySPKI, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	_, err = validator.ValidateIssued(t.Context(), apppki.ValidationRequest{Template: template, CertificateDER: issued.CertificateDER, SubjectPublicKeySPKI: otherKey.PublicKeySPKI})
	if err == nil {
		t.Fatal("ValidateIssued() accepted a mismatched public key")
	}
	digest := sha256.Sum256(issued.CertificateDER)
	if issued.FingerprintSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("fingerprint = %q", issued.FingerprintSHA256)
	}
}

func TestValidatorRejectsSignedCertificateWithWrongIssuerName(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	issuerKey := generateTestKey(t, backend, "key-issuer-name")
	issuerTemplate := testTemplate(t, now, 1, "expected issuer", true, nil)
	issuerIssued := issueTestCertificate(t, backend, validator, issuerTemplate, issuerKey, nil, apppki.KeyMaterial{})
	issuer := mustParseCertificate(t, issuerIssued.CertificateDER)
	wrongIssuer := *issuer
	wrongIssuer.RawSubject = nil
	wrongIssuer.Subject = pkix.Name{CommonName: "different issuer", Organization: []string{"Hovel tests"}}

	leafKey := generateTestKey(t, backend, "key-wrong-issuer-leaf")
	leafTemplate := testTemplate(t, now.Add(time.Minute), 2, "wrong-issuer.test", false, []string{"wrong-issuer.test"})
	leafX509Template, err := certificateTemplate(leafTemplate, leafKey.PublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	leafPublicKey, err := x509.ParsePKIXPublicKey(leafKey.PublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	issuerSigner, err := parseSigner(issuerKey.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, leafX509Template, &wrongIssuer, leafPublicKey, issuerSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ValidateIssued(t.Context(), apppki.ValidationRequest{
		Template:             leafTemplate,
		CertificateDER:       certificateDER,
		SubjectPublicKeySPKI: leafKey.PublicKeySPKI,
		IssuerCertificateDER: issuerIssued.CertificateDER,
	}); err == nil {
		t.Fatal("ValidateIssued() accepted a certificate with the wrong issuer name")
	}
}

func TestValidatorRejectsSemanticMismatches(t *testing.T) {
	t.Parallel()

	backend := NewBackend()
	validator := NewValidator()
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	key := generateTestKey(t, backend, "key-semantic")
	template := testTemplate(t, now, 9, "semantic root", true, nil)
	issued := issueTestCertificate(t, backend, validator, template, key, nil, apppki.KeyMaterial{})
	tests := []struct {
		name   string
		mutate func(*domainpki.CertificateTemplate)
	}{
		{name: "subject", mutate: func(value *domainpki.CertificateTemplate) { value.Subject.Organization = []string{"different"} }},
		{name: "basic constraints criticality", mutate: func(value *domainpki.CertificateTemplate) { value.BasicConstraints.Critical = false }},
		{name: "signature algorithm", mutate: func(value *domainpki.CertificateTemplate) {
			value.SignatureAlgorithm = domainpki.SignatureAlgorithmECDSASHA384
		}},
		{name: "subject key identifier", mutate: func(value *domainpki.CertificateTemplate) {
			value.SubjectKeyIdentifier = domainpki.KeyIdentifier{Mode: domainpki.IdentifierModeExplicit, Value: []byte{1, 2, 3}}
		}},
		{name: "policy", mutate: func(value *domainpki.CertificateTemplate) { value.PolicyOIDs = []domainpki.OID{"1.2.3.4"} }},
		{name: "custom extension", mutate: func(value *domainpki.CertificateTemplate) {
			value.CustomExtensions = []domainpki.CustomExtension{{OID: "1.2.3.5", DER: []byte{5, 0}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := template.Clone()
			test.mutate(&expected)
			_, err := validator.ValidateIssued(t.Context(), apppki.ValidationRequest{
				Template:             expected,
				CertificateDER:       issued.CertificateDER,
				SubjectPublicKeySPKI: key.PublicKeySPKI,
			})
			if err == nil {
				t.Fatal("ValidateIssued() accepted semantically different output")
			}
		})
	}
}

func requireCRLValidationRejected(
	t *testing.T,
	validator Validator,
	request apppki.CRLValidationRequest,
	encoded []byte,
) {
	t.Helper()
	result, err := validator.ValidateCRL(t.Context(), request, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.Decision != apppki.CRLValidationDecisionRejected || result.Rejection == nil {
		t.Fatalf("ValidateCRL() = %#v, want typed rejection", result)
	}
}
