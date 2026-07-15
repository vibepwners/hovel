package pki

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const (
	RecoveryEnvelopeSchemaV1     = "hovel.pki.recovery-envelope/v1"
	RecoveryPayloadSchemaV1      = "hovel.pki.recovery-payload/v1"
	RecoveryKDFArgon2id          = "argon2id"
	RecoveryCipherAES256GCM      = "aes-256-gcm"
	recoveryArgon2Version        = argon2.Version
	recoveryArgon2Time           = 3
	recoveryArgon2MemoryKiB      = 64 * 1024
	recoveryArgon2Parallelism    = 2
	recoverySaltBytes            = 16
	recoveryKeyBytes             = 32
	minimumRecoveryPassphrase    = 12
	maximumRecoveryPassphrase    = 1024
	minimumRecoveryArgon2Time    = 1
	maximumRecoveryArgon2Time    = 10
	minimumRecoveryMemoryKiB     = 19 * 1024
	maximumRecoveryMemoryKiB     = 256 * 1024
	minimumRecoveryParallelism   = 1
	maximumRecoveryParallelism   = 16
	maximumRecoveryEnvelopeBytes = 2 << 20
)

type recoveryEnvelope struct {
	SchemaVersion string `json:"schemaVersion"`
	KDF           string `json:"kdf"`
	KDFVersion    int    `json:"kdfVersion"`
	Time          uint32 `json:"time"`
	MemoryKiB     uint32 `json:"memoryKiB"`
	Parallelism   uint8  `json:"parallelism"`
	Salt          []byte `json:"salt"`
	Cipher        string `json:"cipher"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
}

type recoveryPayload struct {
	SchemaVersion string         `json:"schemaVersion"`
	WorkspaceID   string         `json:"workspaceId"`
	MasterKeys    fileMasterKeys `json:"masterKeys"`
}

func (p *FileMasterKeyProvider) ExportRecovery(ctx context.Context, workspaceID workspace.ID, passphrase []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := workspace.NewID(workspaceID.String()); err != nil {
		return nil, err
	}
	if err := validateRecoveryPassphrase(passphrase); err != nil {
		return nil, err
	}
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("pki: file master-key provider is closed")
	}
	masterKeys := p.snapshotLocked()
	p.mu.RUnlock()
	payload := recoveryPayload{SchemaVersion: RecoveryPayloadSchemaV1, WorkspaceID: workspaceID.String(), MasterKeys: masterKeys}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("pki: encode recovery payload: %w", err)
	}
	defer clear(plaintext)
	envelope := recoveryEnvelope{
		SchemaVersion: RecoveryEnvelopeSchemaV1,
		KDF:           RecoveryKDFArgon2id,
		KDFVersion:    recoveryArgon2Version,
		Time:          recoveryArgon2Time,
		MemoryKiB:     recoveryArgon2MemoryKiB,
		Parallelism:   recoveryArgon2Parallelism,
		Salt:          make([]byte, recoverySaltBytes),
		Cipher:        RecoveryCipherAES256GCM,
	}
	if _, err := rand.Read(envelope.Salt); err != nil {
		return nil, fmt.Errorf("pki: generate recovery salt: %w", err)
	}
	key := argon2.IDKey(passphrase, envelope.Salt, envelope.Time, envelope.MemoryKiB, envelope.Parallelism, recoveryKeyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pki: create recovery block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pki: create recovery cipher: %w", err)
	}
	envelope.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(envelope.Nonce); err != nil {
		return nil, fmt.Errorf("pki: generate recovery nonce: %w", err)
	}
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, plaintext, recoveryAdditionalData(envelope))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("pki: encode recovery envelope: %w", err)
	}
	if len(encoded) > maximumRecoveryEnvelopeBytes {
		clear(encoded)
		return nil, errors.New("pki: recovery envelope exceeds the maximum size")
	}
	return encoded, nil
}

func RestoreFileMasterKeyProvider(ctx context.Context, workspacePath string, workspaceID workspace.ID, encoded, passphrase []byte) (*FileMasterKeyProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := workspace.NewID(workspaceID.String()); err != nil {
		return nil, err
	}
	if err := validateRecoveryPassphrase(passphrase); err != nil {
		return nil, err
	}
	envelope, err := decodeRecoveryEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, envelope.Salt, envelope.Time, envelope.MemoryKiB, envelope.Parallelism, recoveryKeyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pki: create recovery block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pki: create recovery cipher: %w", err)
	}
	if len(envelope.Nonce) != aead.NonceSize() {
		return nil, errors.New("pki: recovery nonce has an invalid size")
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, recoveryAdditionalData(envelope))
	if err != nil {
		return nil, errors.New("pki: decrypt recovery envelope")
	}
	defer clear(plaintext)
	payload, err := decodeRecoveryPayload(plaintext)
	if err != nil {
		return nil, err
	}
	if payload.WorkspaceID != workspaceID.String() {
		return nil, errors.New("pki: recovery payload belongs to a different workspace")
	}
	path := filepath.Join(workspace.ResolvePath(workspacePath), MasterKeyRelativePath)
	if err := ensureSecretDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	provider, err := providerFromFile(path, payload.MasterKeys)
	if err != nil {
		return nil, err
	}
	committed, err := provider.persistLocked(masterKeyPersistCreate)
	if err != nil {
		if committed {
			return provider, err
		}
		provider.clearLocked()
		return nil, err
	}
	return provider, nil
}

func (p *FileMasterKeyProvider) snapshotLocked() fileMasterKeys {
	keys := make(map[string]string, len(p.keys))
	for version, key := range p.keys {
		keys[version] = encodeMasterKey(key)
	}
	return fileMasterKeys{SchemaVersion: FileMasterKeySchemaV1, ActiveVersion: p.active, Keys: keys}
}

func encodeMasterKey(key MasterKey) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func decodeRecoveryEnvelope(encoded []byte) (recoveryEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > maximumRecoveryEnvelopeBytes {
		return recoveryEnvelope{}, errors.New("pki: recovery envelope has an invalid size")
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), maximumRecoveryEnvelopeBytes+1))
	decoder.DisallowUnknownFields()
	var envelope recoveryEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return recoveryEnvelope{}, fmt.Errorf("pki: decode recovery envelope: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryEnvelope{}, errors.New("pki: recovery envelope contains trailing data")
	}
	if err := envelope.validate(); err != nil {
		return recoveryEnvelope{}, err
	}
	return envelope, nil
}

func (e recoveryEnvelope) validate() error {
	if e.SchemaVersion != RecoveryEnvelopeSchemaV1 || e.KDF != RecoveryKDFArgon2id || e.KDFVersion != recoveryArgon2Version || e.Cipher != RecoveryCipherAES256GCM {
		return errors.New("pki: unsupported recovery envelope parameters")
	}
	if e.Time < minimumRecoveryArgon2Time || e.Time > maximumRecoveryArgon2Time ||
		e.MemoryKiB < minimumRecoveryMemoryKiB || e.MemoryKiB > maximumRecoveryMemoryKiB ||
		e.Parallelism < minimumRecoveryParallelism || e.Parallelism > maximumRecoveryParallelism {
		return errors.New("pki: recovery kdf parameters are outside safe bounds")
	}
	if len(e.Salt) != recoverySaltBytes || len(e.Nonce) != apppki.KeyEnvelopeAESGCMNonceBytes ||
		len(e.Ciphertext) <= apppki.KeyEnvelopeAESGCMTagBytes || len(e.Ciphertext) > maximumRecoveryEnvelopeBytes {
		return errors.New("pki: recovery envelope cryptographic material has an invalid size")
	}
	return nil
}

func decodeRecoveryPayload(encoded []byte) (recoveryPayload, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var payload recoveryPayload
	if err := decoder.Decode(&payload); err != nil {
		return recoveryPayload{}, fmt.Errorf("pki: decode recovery payload: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryPayload{}, errors.New("pki: recovery payload contains trailing data")
	}
	if payload.SchemaVersion != RecoveryPayloadSchemaV1 {
		return recoveryPayload{}, errors.New("pki: unsupported recovery payload schema")
	}
	if _, err := workspace.NewID(payload.WorkspaceID); err != nil {
		return recoveryPayload{}, err
	}
	provider, err := providerFromFile("validation-only", payload.MasterKeys)
	if err != nil {
		return recoveryPayload{}, err
	}
	if err := provider.Close(); err != nil {
		return recoveryPayload{}, err
	}
	return payload, nil
}

func recoveryAdditionalData(envelope recoveryEnvelope) []byte {
	buffer := make([]byte, 0, 256)
	buffer = appendLengthPrefixed(buffer, envelope.SchemaVersion)
	buffer = appendLengthPrefixed(buffer, envelope.KDF)
	var integers [17]byte
	binary.BigEndian.PutUint32(integers[0:4], uint32(envelope.KDFVersion))
	binary.BigEndian.PutUint32(integers[4:8], envelope.Time)
	binary.BigEndian.PutUint32(integers[8:12], envelope.MemoryKiB)
	integers[12] = envelope.Parallelism
	binary.BigEndian.PutUint32(integers[13:17], uint32(len(envelope.Salt)))
	buffer = append(buffer, integers[:]...)
	buffer = append(buffer, envelope.Salt...)
	buffer = appendLengthPrefixed(buffer, envelope.Cipher)
	return buffer
}

func appendLengthPrefixed(destination []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func validateRecoveryPassphrase(passphrase []byte) error {
	if len(passphrase) < minimumRecoveryPassphrase || len(passphrase) > maximumRecoveryPassphrase {
		return fmt.Errorf("pki: recovery passphrase must contain between %d and %d bytes", minimumRecoveryPassphrase, maximumRecoveryPassphrase)
	}
	if len(bytes.TrimSpace(passphrase)) == 0 {
		return errors.New("pki: recovery passphrase cannot be whitespace")
	}
	return nil
}
