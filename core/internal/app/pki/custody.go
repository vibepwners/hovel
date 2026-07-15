package pki

import (
	"context"
	"errors"
	"strings"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const (
	KeyEnvelopeSchemaV1               = "hovel.pki.key-envelope/v1"
	KeyEnvelopeAES256GCM              = "aes-256-gcm"
	KeyEnvelopeAESGCMNonceBytes       = 12
	KeyEnvelopeAESGCMTagBytes         = 16
	MaximumKeyEnvelopeCiphertextBytes = 2 << 20
	MaxKeyVersionLength               = 128
	MetadataAuthenticationSchemaV1    = "hovel.pki.metadata-authentication/v1"
	MetadataAuthenticationHMACSHA256  = "hmac-sha256"
	MetadataAuthenticationTagBytes    = 32
)

type ProtectedKeyMaterial struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Cipher        string                 `json:"cipher"`
	KeyVersion    string                 `json:"keyVersion"`
	KeyID         domainpki.KeyID        `json:"keyId"`
	Algorithm     domainpki.KeyAlgorithm `json:"algorithm"`
	Nonce         []byte                 `json:"nonce"`
	Ciphertext    []byte                 `json:"ciphertext"`
}

func (m ProtectedKeyMaterial) Clone() ProtectedKeyMaterial {
	result := m
	result.Nonce = append([]byte(nil), m.Nonce...)
	result.Ciphertext = append([]byte(nil), m.Ciphertext...)
	return result
}

func (m ProtectedKeyMaterial) Validate() error {
	if m.SchemaVersion != KeyEnvelopeSchemaV1 {
		return errors.New("pki: unsupported key envelope schema version")
	}
	if m.Cipher != KeyEnvelopeAES256GCM {
		return errors.New("pki: unsupported key envelope cipher")
	}
	if err := ValidateKeyVersion(m.KeyVersion); err != nil {
		return err
	}
	if err := m.KeyID.Validate(); err != nil {
		return err
	}
	switch m.Algorithm {
	case domainpki.KeyAlgorithmECDSA, domainpki.KeyAlgorithmRSA, domainpki.KeyAlgorithmEd25519,
		domainpki.KeyAlgorithmMLDSA44, domainpki.KeyAlgorithmMLDSA65, domainpki.KeyAlgorithmMLDSA87:
	default:
		return errors.New("pki: unsupported key envelope algorithm")
	}
	if len(m.Nonce) != KeyEnvelopeAESGCMNonceBytes {
		return errors.New("pki: key envelope nonce has an invalid size")
	}
	if len(m.Ciphertext) <= KeyEnvelopeAESGCMTagBytes || len(m.Ciphertext) > MaximumKeyEnvelopeCiphertextBytes {
		return errors.New("pki: key envelope ciphertext has an invalid size")
	}
	return nil
}

func ValidateKeyVersion(value string) error {
	keyVersion := strings.TrimSpace(value)
	if keyVersion == "" {
		return errors.New("pki: key envelope master-key version is required")
	}
	if keyVersion != value || len(keyVersion) > MaxKeyVersionLength || strings.ContainsAny(keyVersion, "\x00\r\n") {
		return errors.New("pki: key envelope master-key version is not canonical")
	}
	return nil
}

type KeyProtector interface {
	WorkspaceID() workspace.ID
	ActiveKeyVersion(context.Context) (string, error)
	Seal(context.Context, KeyMaterial) (ProtectedKeyMaterial, error)
	SealWithVersion(context.Context, KeyMaterial, string) (ProtectedKeyMaterial, error)
	Open(context.Context, ProtectedKeyMaterial) (KeyMaterial, error)
	AuthenticateMetadata(context.Context, []byte) (ProtectedMetadata, error)
	AuthenticateMetadataWithVersion(context.Context, []byte, string) (ProtectedMetadata, error)
	VerifyMetadata(context.Context, []byte, ProtectedMetadata) error
	WithStableKeyEpoch(context.Context, func() error) error
}

type ProtectedMetadata struct {
	SchemaVersion string `json:"schemaVersion"`
	Algorithm     string `json:"algorithm"`
	KeyVersion    string `json:"keyVersion"`
	Tag           []byte `json:"tag"`
}

func (m ProtectedMetadata) Clone() ProtectedMetadata {
	result := m
	result.Tag = append([]byte(nil), m.Tag...)
	return result
}

func (m ProtectedMetadata) Validate() error {
	if m.SchemaVersion != MetadataAuthenticationSchemaV1 {
		return errors.New("pki: unsupported metadata authentication schema version")
	}
	if m.Algorithm != MetadataAuthenticationHMACSHA256 {
		return errors.New("pki: unsupported metadata authentication algorithm")
	}
	if err := ValidateKeyVersion(m.KeyVersion); err != nil {
		return err
	}
	if len(m.Tag) != MetadataAuthenticationTagBytes {
		return errors.New("pki: metadata authentication tag has an invalid size")
	}
	return nil
}
