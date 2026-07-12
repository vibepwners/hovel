package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCRLGenerationValidationAndClone(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	encoded := []byte("crl")
	fingerprint := sha256.Sum256(encoded)
	args := CRLGenerationArgs{
		ID: "crlgen-test", AuthorityID: "authority-test", IssuerGenerationID: "certgen-authority-test",
		Number: 7, ThisUpdate: createdAt, NextUpdate: createdAt.Add(24 * time.Hour),
		RevocationIDs:    []RevocationID{"revocation-a", "revocation-b"},
		SigningBackendID: "builtin-x509", SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("a", 64),
		SignatureAlgorithm:           SignatureAlgorithmECDSASHA256,
		FingerprintSHA256:            hex.EncodeToString(fingerprint[:]), CRLDER: encoded, CreatedAt: createdAt,
	}
	generation, err := NewCRLGeneration(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := generation.Validate(); err != nil {
		t.Fatal(err)
	}
	if !generation.FreshAt(createdAt) || generation.FreshAt(generation.NextUpdate) {
		t.Fatal("CRLGeneration.FreshAt() did not enforce the half-open freshness window")
	}
	args.RevocationIDs[0] = "revocation-mutated"
	args.CRLDER[0] = 'X'
	clone := generation.Clone()
	clone.RevocationIDs[0] = "revocation-clone"
	clone.CRLDER[0] = 'Y'
	if generation.RevocationIDs[0] != "revocation-a" || string(generation.CRLDER) != "crl" {
		t.Fatal("CRLGeneration did not defensively copy mutable fields")
	}
}

func TestCRLGenerationRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	encoded := []byte("crl")
	fingerprint := sha256.Sum256(encoded)
	valid := CRLGenerationArgs{
		ID: "crlgen-test", AuthorityID: "authority-test", IssuerGenerationID: "certgen-authority-test",
		Number: 1, ThisUpdate: createdAt, NextUpdate: createdAt.Add(time.Hour),
		SigningBackendID: "builtin-x509", SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("a", 64),
		SignatureAlgorithm:           SignatureAlgorithmECDSASHA256,
		FingerprintSHA256:            hex.EncodeToString(fingerprint[:]), CRLDER: encoded, CreatedAt: createdAt,
	}
	tests := []struct {
		name   string
		mutate func(*CRLGenerationArgs)
	}{
		{name: "zero number", mutate: func(args *CRLGenerationArgs) { args.Number = 0 }},
		{name: "short validity", mutate: func(args *CRLGenerationArgs) { args.NextUpdate = args.ThisUpdate.Add(time.Minute) }},
		{name: "long validity", mutate: func(args *CRLGenerationArgs) { args.NextUpdate = args.ThisUpdate.Add(MaximumCRLValidity + time.Second) }},
		{name: "unsorted revocations", mutate: func(args *CRLGenerationArgs) { args.RevocationIDs = []RevocationID{"revocation-b", "revocation-a"} }},
		{name: "duplicate revocations", mutate: func(args *CRLGenerationArgs) { args.RevocationIDs = []RevocationID{"revocation-a", "revocation-a"} }},
		{name: "empty der", mutate: func(args *CRLGenerationArgs) { args.CRLDER = nil }},
		{name: "fingerprint mismatch", mutate: func(args *CRLGenerationArgs) { args.FingerprintSHA256 = strings.Repeat("b", 64) }},
		{name: "expired before creation", mutate: func(args *CRLGenerationArgs) { args.CreatedAt = args.NextUpdate }},
		{name: "automatic signature", mutate: func(args *CRLGenerationArgs) { args.SignatureAlgorithm = SignatureAlgorithmAuto }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if _, err := NewCRLGeneration(candidate); err == nil {
				t.Fatal("NewCRLGeneration() accepted an invalid contract")
			}
		})
	}
}
