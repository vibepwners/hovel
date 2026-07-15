package pki

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const MasterKeySize = 32

const metadataAuthenticationContext = "hovel.pki.metadata-authentication-key/v1"

type MasterKey [MasterKeySize]byte

func NewMasterKey(value []byte) (MasterKey, error) {
	if len(value) != MasterKeySize {
		return MasterKey{}, fmt.Errorf("pki: workspace master key must be %d bytes", MasterKeySize)
	}
	var result MasterKey
	copy(result[:], value)
	return result, nil
}

// Clear overwrites this owned master-key value. Because MasterKey is an array,
// callers must clear every value copy they create.
func (k *MasterKey) Clear() {
	if k == nil {
		return
	}
	clear(k[:])
}

type MasterKeyProvider interface {
	ActiveMasterKey(context.Context) (string, MasterKey, error)
	MasterKey(context.Context, string) (MasterKey, error)
}

type StableMasterKeyProvider interface {
	MasterKeyProvider
	WithStableKeyEpoch(context.Context, func() error) error
}

type EnvelopeProtector struct {
	workspaceID     workspace.ID
	workspaceDigest string
	provider        MasterKeyProvider
}

func NewEnvelopeProtector(workspaceID workspace.ID, provider MasterKeyProvider) (EnvelopeProtector, error) {
	if _, err := workspace.NewID(workspaceID.String()); err != nil {
		return EnvelopeProtector{}, err
	}
	if provider == nil {
		return EnvelopeProtector{}, errors.New("pki: workspace id and master-key provider are required")
	}
	digest := sha256.Sum256([]byte(workspaceID.String()))
	return EnvelopeProtector{
		workspaceID:     workspaceID,
		workspaceDigest: hex.EncodeToString(digest[:]),
		provider:        provider,
	}, nil
}

func (p EnvelopeProtector) WorkspaceID() workspace.ID {
	return p.workspaceID
}

func (p EnvelopeProtector) WithStableKeyEpoch(ctx context.Context, operation func() error) error {
	if operation == nil {
		return errors.New("pki: stable key-epoch operation is required")
	}
	if provider, ok := p.provider.(StableMasterKeyProvider); ok {
		return provider.WithStableKeyEpoch(ctx, operation)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (p EnvelopeProtector) ActiveKeyVersion(ctx context.Context) (string, error) {
	version, key, err := p.provider.ActiveMasterKey(ctx)
	defer key.Clear()
	if err != nil {
		return "", fmt.Errorf("pki: load active workspace master key: %w", err)
	}
	if err := apppki.ValidateKeyVersion(version); err != nil {
		return "", err
	}
	return version, nil
}

func (p EnvelopeProtector) Seal(ctx context.Context, material apppki.KeyMaterial) (apppki.ProtectedKeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	if err := material.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	keyVersion, key, err := p.provider.ActiveMasterKey(ctx)
	defer key.Clear()
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: load active workspace master key: %w", err)
	}
	return p.sealWithKey(material, keyVersion, key)
}

func (p EnvelopeProtector) SealWithVersion(ctx context.Context, material apppki.KeyMaterial, keyVersion string) (apppki.ProtectedKeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	if err := material.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	if err := apppki.ValidateKeyVersion(keyVersion); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	key, err := p.provider.MasterKey(ctx, keyVersion)
	defer key.Clear()
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: load workspace master key version %q: %w", keyVersion, err)
	}
	return p.sealWithKey(material, keyVersion, key)
}

func (p EnvelopeProtector) sealWithKey(material apppki.KeyMaterial, keyVersion string, key MasterKey) (apppki.ProtectedKeyMaterial, error) {
	defer key.Clear()
	if err := apppki.ValidateKeyVersion(keyVersion); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: create key-envelope block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: create key-envelope cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, randomErr := rand.Read(nonce)
	if randomErr != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: generate key-envelope nonce: %w", randomErr)
	}
	plaintext, err := json.Marshal(material)
	if err != nil {
		return apppki.ProtectedKeyMaterial{}, fmt.Errorf("pki: encode key material: %w", err)
	}
	defer clear(plaintext)
	protected := apppki.ProtectedKeyMaterial{
		SchemaVersion: apppki.KeyEnvelopeSchemaV1,
		Cipher:        apppki.KeyEnvelopeAES256GCM,
		KeyVersion:    keyVersion,
		KeyID:         material.ID,
		Algorithm:     material.Algorithm,
		Nonce:         nonce,
	}
	protected.Ciphertext = aead.Seal(nil, protected.Nonce, plaintext, p.additionalData(protected))
	if err := protected.Validate(); err != nil {
		return apppki.ProtectedKeyMaterial{}, err
	}
	return protected, nil
}

func (p EnvelopeProtector) Open(ctx context.Context, protected apppki.ProtectedKeyMaterial) (apppki.KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	if err := protected.Validate(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	key, err := p.provider.MasterKey(ctx, protected.KeyVersion)
	defer key.Clear()
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: load workspace master key version %q: %w", protected.KeyVersion, err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: create key-envelope block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: create key-envelope cipher: %w", err)
	}
	if len(protected.Nonce) != aead.NonceSize() {
		return apppki.KeyMaterial{}, errors.New("pki: key-envelope nonce has an invalid size")
	}
	plaintext, err := aead.Open(nil, protected.Nonce, protected.Ciphertext, p.additionalData(protected))
	if err != nil {
		return apppki.KeyMaterial{}, errors.New("pki: decrypt key envelope")
	}
	defer clear(plaintext)
	var material apppki.KeyMaterial
	defer material.Clear()
	if err := json.Unmarshal(plaintext, &material); err != nil {
		return apppki.KeyMaterial{}, fmt.Errorf("pki: decode key material: %w", err)
	}
	if err := material.Validate(); err != nil {
		return apppki.KeyMaterial{}, err
	}
	if material.ID != protected.KeyID || material.Algorithm != protected.Algorithm {
		return apppki.KeyMaterial{}, errors.New("pki: decrypted key material does not match envelope metadata")
	}
	return material.Clone(), nil
}

func (p EnvelopeProtector) AuthenticateMetadata(ctx context.Context, data []byte) (apppki.ProtectedMetadata, error) {
	if err := ctx.Err(); err != nil {
		return apppki.ProtectedMetadata{}, err
	}
	version, key, err := p.provider.ActiveMasterKey(ctx)
	if err != nil {
		key.Clear()
		return apppki.ProtectedMetadata{}, fmt.Errorf("pki: load active workspace master key: %w", err)
	}
	return p.authenticateMetadataWithOwnedKey(data, version, &key)
}

func (p EnvelopeProtector) AuthenticateMetadataWithVersion(ctx context.Context, data []byte, version string) (apppki.ProtectedMetadata, error) {
	if err := ctx.Err(); err != nil {
		return apppki.ProtectedMetadata{}, err
	}
	if err := apppki.ValidateKeyVersion(version); err != nil {
		return apppki.ProtectedMetadata{}, err
	}
	key, err := p.provider.MasterKey(ctx, version)
	if err != nil {
		key.Clear()
		return apppki.ProtectedMetadata{}, fmt.Errorf("pki: load workspace master key version %q: %w", version, err)
	}
	return p.authenticateMetadataWithOwnedKey(data, version, &key)
}

func (p EnvelopeProtector) VerifyMetadata(ctx context.Context, data []byte, protected apppki.ProtectedMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := protected.Validate(); err != nil {
		return err
	}
	key, err := p.provider.MasterKey(ctx, protected.KeyVersion)
	if err != nil {
		key.Clear()
		return fmt.Errorf("pki: load workspace master key version %q: %w", protected.KeyVersion, err)
	}
	expected, err := p.authenticateMetadataWithOwnedKey(data, protected.KeyVersion, &key)
	if err != nil {
		return err
	}
	defer clear(expected.Tag)
	if !hmac.Equal(expected.Tag, protected.Tag) {
		return errors.New("pki: verify authenticated metadata")
	}
	return nil
}

// authenticateMetadataWithOwnedKey consumes key and clears the caller-owned
// value before returning on every path.
func (p EnvelopeProtector) authenticateMetadataWithOwnedKey(
	data []byte,
	version string,
	key *MasterKey,
) (apppki.ProtectedMetadata, error) {
	if key == nil {
		return apppki.ProtectedMetadata{}, errors.New("pki: metadata authentication master key is required")
	}
	defer key.Clear()
	if len(data) == 0 {
		return apppki.ProtectedMetadata{}, errors.New("pki: metadata authentication input is required")
	}
	if err := apppki.ValidateKeyVersion(version); err != nil {
		return apppki.ProtectedMetadata{}, err
	}
	derivation := hmac.New(sha256.New, key[:])
	_, _ = derivation.Write([]byte(metadataAuthenticationContext))
	_, _ = derivation.Write([]byte{0})
	_, _ = derivation.Write([]byte(p.workspaceDigest))
	derivedKey := derivation.Sum(nil)
	defer clear(derivedKey)
	mac := hmac.New(sha256.New, derivedKey)
	_, _ = mac.Write(data)
	protected := apppki.ProtectedMetadata{
		SchemaVersion: apppki.MetadataAuthenticationSchemaV1,
		Algorithm:     apppki.MetadataAuthenticationHMACSHA256,
		KeyVersion:    version,
		Tag:           mac.Sum(nil),
	}
	if err := protected.Validate(); err != nil {
		return apppki.ProtectedMetadata{}, err
	}
	return protected, nil
}

func (p EnvelopeProtector) additionalData(protected apppki.ProtectedKeyMaterial) []byte {
	return []byte(strings.Join([]string{
		protected.SchemaVersion,
		protected.Cipher,
		protected.KeyVersion,
		p.workspaceDigest,
		string(protected.KeyID),
		string(protected.Algorithm),
	}, "\x00"))
}

var _ apppki.KeyProtector = EnvelopeProtector{}
