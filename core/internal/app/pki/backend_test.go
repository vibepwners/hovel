package pki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type testValidator struct{}

func (testValidator) ValidateKey(context.Context, KeyValidationRequest) error { return nil }
func (testValidator) ValidateIssued(context.Context, ValidationRequest) (IssuedCertificate, error) {
	return IssuedCertificate{}, nil
}
func (testValidator) ValidateBundle(context.Context, domainpki.Bundle, time.Time) error { return nil }

func TestExternalKeyHandleIsAValidatedNonExportableAlternative(t *testing.T) {
	t.Parallel()

	material := KeyMaterial{
		ID:            "key-external",
		Algorithm:     domainpki.KeyAlgorithmECDSA,
		PublicKeySPKI: []byte{1, 2, 3},
		ExternalHandle: &ExternalKeyHandle{
			BackendID:    "pkcs11-test",
			Handle:       "pkcs11:token=hovel;object=issuer",
			Capabilities: []string{"sign-certificate", "sign-crl"},
		},
	}
	if err := material.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := material.Clone()
	clone.ExternalHandle.Capabilities[0] = "changed"
	if material.ExternalHandle.Capabilities[0] != "sign-certificate" {
		t.Fatal("KeyMaterial.Clone() aliased external key capabilities")
	}

	both := material.Clone()
	both.PrivateKeyPKCS8 = []byte{4, 5, 6}
	if err := both.Validate(); err == nil {
		t.Fatal("KeyMaterial.Validate() accepted both local and external private-key custody")
	}
	neither := material.Clone()
	neither.ExternalHandle = nil
	if err := neither.Validate(); err == nil {
		t.Fatal("KeyMaterial.Validate() accepted no private-key custody")
	}
}

func TestStaticValidatorRegistrySelectsByBackend(t *testing.T) {
	t.Parallel()

	registry, err := NewStaticValidatorRegistry(map[domainpki.BackendID]Validator{
		domainpki.BackendBuiltinX509: testValidator{},
		"provider-custom":            testValidator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveValidator(t.Context(), "provider-custom"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveValidator(t.Context(), "provider-missing"); err == nil {
		t.Fatal("ResolveValidator() accepted an unregistered backend")
	}
}

func TestCRLValidationResultMakesDecisionsExplicit(t *testing.T) {
	t.Parallel()

	encoded := []byte{1, 2, 3}
	digest := sha256.Sum256(encoded)
	accepted, err := NewAcceptedCRLValidation(IssuedCRL{
		CRLDER: encoded, FingerprintSHA256: hex.EncodeToString(digest[:]),
		SignatureAlgorithm: domainpki.SignatureAlgorithmECDSASHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Decision != CRLValidationDecisionAccepted || accepted.Accepted == nil || accepted.Rejection != nil {
		t.Fatalf("accepted validation = %#v", accepted)
	}
	rejected, err := NewRejectedCRLValidation(
		CRLValidationRejectionInvalidCRL,
		"signature does not match the issuer",
	)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Decision != CRLValidationDecisionRejected || rejected.Accepted != nil || rejected.Rejection == nil {
		t.Fatalf("rejected validation = %#v", rejected)
	}
	invalid := accepted.Clone()
	invalid.Rejection = rejected.Rejection
	if err := invalid.Validate(); err == nil {
		t.Fatal("CRLValidationResult.Validate() accepted contradictory result fields")
	}
}
