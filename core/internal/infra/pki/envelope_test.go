package pki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

type fixedMasterKeyProvider struct {
	key MasterKey
}

func (p fixedMasterKeyProvider) ActiveMasterKey(context.Context) (string, MasterKey, error) {
	return "test-v1", p.key, nil
}

func (p fixedMasterKeyProvider) MasterKey(_ context.Context, version string) (MasterKey, error) {
	if version != "test-v1" {
		return MasterKey{}, errors.New("unknown test master-key version")
	}
	return p.key, nil
}

func TestEnvelopeProtectorRoundTripAndAuthentication(t *testing.T) {
	t.Parallel()

	key, err := NewMasterKey(bytes.Repeat([]byte{0x42}, MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	workspaceA, err := workspace.NewID("workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewEnvelopeProtector(workspaceA, fixedMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	material := apppki.KeyMaterial{
		ID:              "key-1",
		Algorithm:       domainpki.KeyAlgorithmEd25519,
		PublicKeySPKI:   []byte{1, 2, 3},
		PrivateKeyPKCS8: []byte{4, 5, 6},
	}
	protected, err := protector.Seal(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains encoded plaintext key material")
	}
	secondEnvelope, err := protector.Seal(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(protected.Nonce, secondEnvelope.Nonce) {
		t.Fatal("independent key envelopes reused an AES-GCM nonce")
	}
	opened, err := protector.Open(t.Context(), protected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.PublicKeySPKI, material.PublicKeySPKI) || !bytes.Equal(opened.PrivateKeyPKCS8, material.PrivateKeyPKCS8) {
		t.Fatalf("opened key = %#v, want %#v", opened, material)
	}

	tampered := protected.Clone()
	tampered.Ciphertext[0] ^= 0xff
	if _, err := protector.Open(t.Context(), tampered); err == nil {
		t.Fatal("Open() accepted tampered ciphertext")
	}
	tampered = protected.Clone()
	tampered.KeyID = "key-2"
	if _, err := protector.Open(t.Context(), tampered); err == nil {
		t.Fatal("Open() accepted changed associated metadata")
	}
	tampered = protected.Clone()
	tampered.KeyVersion = "test-v2"
	if _, err := protector.Open(t.Context(), tampered); err == nil {
		t.Fatal("Open() accepted changed master-key version metadata")
	}
	workspaceB, err := workspace.NewID("workspace-b")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace, err := NewEnvelopeProtector(workspaceB, fixedMasterKeyProvider{key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherWorkspace.Open(t.Context(), protected); err == nil {
		t.Fatal("Open() accepted an envelope from another workspace")
	}
}

func TestNewMasterKeyRequiresAES256Key(t *testing.T) {
	t.Parallel()

	if _, err := NewMasterKey(make([]byte, MasterKeySize-1)); err == nil {
		t.Fatal("NewMasterKey() accepted a short key")
	}
}

func TestProtectedKeyMaterialRejectsInvalidEnvelopeSizes(t *testing.T) {
	t.Parallel()

	valid := apppki.ProtectedKeyMaterial{
		SchemaVersion: apppki.KeyEnvelopeSchemaV1,
		Cipher:        apppki.KeyEnvelopeAES256GCM,
		KeyVersion:    "test-v1",
		KeyID:         "key-envelope-sizes",
		Algorithm:     domainpki.KeyAlgorithmEd25519,
		Nonce:         make([]byte, apppki.KeyEnvelopeAESGCMNonceBytes),
		Ciphertext:    make([]byte, apppki.KeyEnvelopeAESGCMTagBytes+1),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalidNonce := valid.Clone()
	invalidNonce.Nonce = invalidNonce.Nonce[:len(invalidNonce.Nonce)-1]
	if err := invalidNonce.Validate(); err == nil {
		t.Fatal("ProtectedKeyMaterial.Validate() accepted a short nonce")
	}
	invalidTag := valid.Clone()
	invalidTag.Ciphertext = invalidTag.Ciphertext[:apppki.KeyEnvelopeAESGCMTagBytes]
	if err := invalidTag.Validate(); err == nil {
		t.Fatal("ProtectedKeyMaterial.Validate() accepted tag-only ciphertext")
	}
	oversized := valid.Clone()
	oversized.Ciphertext = make([]byte, apppki.MaximumKeyEnvelopeCiphertextBytes+1)
	if err := oversized.Validate(); err == nil {
		t.Fatal("ProtectedKeyMaterial.Validate() accepted oversized ciphertext")
	}
}
