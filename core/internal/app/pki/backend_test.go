package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

type recordingKeyValidator struct {
	err            error
	privateKeyView []byte
}

func (v *recordingKeyValidator) ValidateKey(_ context.Context, request KeyValidationRequest) error {
	v.privateKeyView = request.Material.PrivateKeyPKCS8
	return v.err
}

func (*recordingKeyValidator) ValidateIssued(context.Context, ValidationRequest) (IssuedCertificate, error) {
	return IssuedCertificate{}, nil
}

func (*recordingKeyValidator) ValidateBundle(context.Context, domainpki.Bundle, time.Time) error {
	return nil
}

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

func TestKeyMaterialClearOverwritesOwnedBytes(t *testing.T) {
	t.Parallel()

	publicKey := []byte{1, 2, 3}
	privateKey := []byte{4, 5, 6}
	material := KeyMaterial{
		ID:              "key-clear",
		Algorithm:       domainpki.KeyAlgorithmEd25519,
		PublicKeySPKI:   publicKey,
		PrivateKeyPKCS8: privateKey,
	}

	material.Clear()

	if !allBytesZero(publicKey) || !allBytesZero(privateKey) {
		t.Fatal("KeyMaterial.Clear() did not overwrite owned byte slices")
	}
	if material.ID != "" || material.Algorithm != "" ||
		material.PublicKeySPKI != nil || material.PrivateKeyPKCS8 != nil ||
		material.ExternalHandle != nil {
		t.Fatalf("KeyMaterial.Clear() retained state: %#v", material)
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

func TestValidateKeyMaterialClearsValidationCopyOnFailure(t *testing.T) {
	t.Parallel()

	validationErr := errors.New("validation failed")
	validator := &recordingKeyValidator{err: validationErr}
	privateKey := []byte{4, 5, 6}
	material := KeyMaterial{
		ID:              "key-validation-failure",
		Algorithm:       domainpki.KeyAlgorithmEd25519,
		PublicKeySPKI:   []byte{1, 2, 3},
		PrivateKeyPKCS8: append([]byte(nil), privateKey...),
	}

	if _, err := ValidateKeyMaterial(
		t.Context(),
		validator,
		domainpki.KeySpec{Algorithm: domainpki.KeyAlgorithmEd25519},
		material,
	); !errors.Is(err, validationErr) {
		t.Fatalf("ValidateKeyMaterial() error = %v, want %v", err, validationErr)
	}
	if !allBytesZero(validator.privateKeyView) {
		t.Fatal("ValidateKeyMaterial() retained private-key bytes after validation failure")
	}
	if !bytes.Equal(material.PrivateKeyPKCS8, privateKey) {
		t.Fatal("ValidateKeyMaterial() cleared caller-owned private-key bytes")
	}
}

func TestValidateKeyMaterialTransfersOwnedCopyOnSuccess(t *testing.T) {
	t.Parallel()

	validator := &recordingKeyValidator{}
	material := KeyMaterial{
		ID:              "key-validation-success",
		Algorithm:       domainpki.KeyAlgorithmEd25519,
		PublicKeySPKI:   []byte{1, 2, 3},
		PrivateKeyPKCS8: []byte{4, 5, 6},
	}

	validated, err := ValidateKeyMaterial(
		t.Context(),
		validator,
		domainpki.KeySpec{Algorithm: domainpki.KeyAlgorithmEd25519},
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.Clear()
	if !allBytesZero(validator.privateKeyView) {
		t.Fatal("ValidateKeyMaterial() retained the validator's borrowed private-key copy")
	}
	got := validated.Material()
	defer got.Clear()
	if !bytes.Equal(got.PrivateKeyPKCS8, material.PrivateKeyPKCS8) {
		t.Fatalf("validated private key = %v, want %v", got.PrivateKeyPKCS8, material.PrivateKeyPKCS8)
	}
	got.PrivateKeyPKCS8[0] ^= 0xff
	second := validated.Material()
	defer second.Clear()
	if bytes.Equal(got.PrivateKeyPKCS8, second.PrivateKeyPKCS8) {
		t.Fatal("ValidatedKeyMaterial.Material() returned an aliased private-key slice")
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

func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
