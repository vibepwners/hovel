package hovel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCredentialBundleConfiguresVerifiedTLSServer(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, root := testCredentialBundle(t, now)
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCredentialBundleJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := decoded.TLSServerConfigAt(now)
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 ||
		len(serverConfig.CurvePreferences) != 2 ||
		serverConfig.CurvePreferences[0] != tls.X25519 {
		t.Fatalf("TLS server config = %#v", serverConfig)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	server := tls.Server(serverSide, serverConfig)
	client := tls.Client(clientSide, &tls.Config{
		RootCAs:    roots,
		ServerName: "squatter.mesh.test",
		MinVersion: tls.VersionTLS13,
	})
	errors := make(chan error, 2)
	go func() { errors <- server.HandshakeContext(t.Context()) }()
	go func() { errors <- client.HandshakeContext(t.Context()) }()
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
	}
	privateAlias := decoded.PrivateKey.Data
	decoded.Clear()
	if !bytes.Equal(privateAlias, make([]byte, len(privateAlias))) {
		t.Fatal("CredentialBundle.Clear() did not clear private-key bytes")
	}
}

func TestCredentialBundleDecodeFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, _ := testCredentialBundle(t, now)
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	certificate := wire["certificate"].(map[string]any)
	certificate["unknown"] = true
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialBundleJSON(encoded); err == nil {
		t.Fatal("DecodeCredentialBundleJSON() accepted an unknown nested field")
	}

	badKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badPKCS8, err := x509.MarshalPKCS8PrivateKey(badKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle.PrivateKey.Data = badPKCS8
	encoded, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialBundleJSON(encoded); err == nil {
		t.Fatal("DecodeCredentialBundleJSON() accepted a mismatched private key")
	}
}

func TestCredentialBundleValidateAtEnforcesPurposeAndTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, _ := testCredentialBundle(t, now)
	bundle.Purpose = CredentialPurposeDualRoleMTLS
	if err := bundle.ValidateAt(now); err == nil {
		t.Fatal("CredentialBundle.ValidateAt() accepted a dual-role certificate without client authentication usage")
	}

	bundle, _ = testCredentialBundle(t, now)
	bundle.TrustAnchors = []CredentialBundleCertificate{{
		GenerationID: "generation-untrusted-leaf",
		CredentialBundleBinary: CredentialBundleBinary{
			MediaType: CredentialBundleMediaCertificate,
			Encoding:  CredentialBundleEncodingBase64DER,
			Data:      append(CredentialBytes(nil), bundle.Certificate.Data...),
		},
	}}
	if err := bundle.ValidateAt(now); err == nil {
		t.Fatal("CredentialBundle.ValidateAt() accepted a non-self-signed trust anchor")
	}
}

func testCredentialBundle(
	t *testing.T,
	now time.Time,
) (CredentialBundle, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Hovel test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "squatter.mesh.test"},
		DNSNames:     []string{"squatter.mesh.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateDigest := sha256.Sum256(leafDER)
	publicDigest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return CredentialBundle{
		SchemaVersion:           CredentialBundleSchemaV1,
		ID:                      "bundle-test",
		AssignmentID:            "assignment-test",
		CertificateID:           "certificate-test",
		CertificateGenerationID: "generation-leaf",
		Generation:              1,
		Purpose:                 CredentialPurposeTLSServer,
		CompatibilityTargetID:   "portable-x509",
		CompatibilityVersion:    "1",
		KeyEstablishmentPolicy:  CredentialKeyEstablishmentClassicalCompatible,
		TLSNamedGroups:          []string{"x25519", "secp256r1"},
		Certificate: CredentialBundleBinary{
			MediaType: CredentialBundleMediaCertificate,
			Encoding:  CredentialBundleEncodingBase64DER,
			Data:      leafDER,
		},
		PublicKey: CredentialBundleBinary{
			MediaType: CredentialBundleMediaPublicKey,
			Encoding:  CredentialBundleEncodingBase64DER,
			Data:      leaf.RawSubjectPublicKeyInfo,
		},
		PrivateKey: &CredentialBundleBinary{
			MediaType: CredentialBundleMediaPrivateKey,
			Encoding:  CredentialBundleEncodingBase64DER,
			Data:      privateKey,
		},
		TrustAnchors: []CredentialBundleCertificate{{
			GenerationID: "generation-root",
			CredentialBundleBinary: CredentialBundleBinary{
				MediaType: CredentialBundleMediaCertificate,
				Encoding:  CredentialBundleEncodingBase64DER,
				Data:      rootDER,
			},
		}},
		Fingerprints: CredentialBundleFingerprints{
			CertificateSHA256: hex.EncodeToString(certificateDigest[:]),
			PublicKeySHA256:   hex.EncodeToString(publicDigest[:]),
		},
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, root
}
