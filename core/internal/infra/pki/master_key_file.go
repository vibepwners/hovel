package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const (
	FileMasterKeySchemaV1       = "hovel.pki.file-master-keys/v1"
	MasterKeyRelativePath       = "secrets/pki-master-keys.json"
	masterKeyVersionRandomBytes = 16
	maximumMasterKeyVersions    = 1024
	maximumMasterKeyFileBytes   = 1 << 20
	masterKeyVersionPrefix      = "mk-"
	masterKeyVersionRetries     = 8
)

var ErrMasterKeysNotInitialized = errors.New("pki: workspace master keys are not initialized")

type masterKeyPersistMode uint8

const (
	masterKeyPersistCreate masterKeyPersistMode = iota + 1
	masterKeyPersistReplace
)

type fileMasterKeys struct {
	SchemaVersion string            `json:"schemaVersion"`
	ActiveVersion string            `json:"activeVersion"`
	Keys          map[string]string `json:"keys"`
}

type FileMasterKeyProvider struct {
	maintenanceMu sync.RWMutex
	mu            sync.RWMutex
	path          string
	active        string
	keys          map[string]MasterKey
	closed        bool
}

func InitializeFileMasterKeyProvider(ctx context.Context, workspacePath string) (*FileMasterKeyProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(workspace.ResolvePath(workspacePath), MasterKeyRelativePath)
	if err := ensureSecretDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	version, key, err := generateMasterKeyVersion()
	if err != nil {
		return nil, err
	}
	provider := &FileMasterKeyProvider{path: path, active: version, keys: map[string]MasterKey{version: key}}
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

func OpenFileMasterKeyProvider(ctx context.Context, workspacePath string) (*FileMasterKeyProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(workspace.ResolvePath(workspacePath), MasterKeyRelativePath)
	if err := validateSecretDirectory(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMasterKeysNotInitialized
		}
		return nil, err
	}
	fileHandle, info, err := openSecretFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMasterKeysNotInitialized
		}
		return nil, err
	}
	defer func() {
		if err := fileHandle.Close(); err != nil {
			log.Printf("pki: close workspace master-key file: %v", err)
		}
	}()
	if !info.Mode().IsRegular() {
		return nil, errors.New("pki: workspace master-key path must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maximumMasterKeyFileBytes {
		return nil, errors.New("pki: workspace master-key file has an invalid size")
	}
	encoded, err := io.ReadAll(io.LimitReader(fileHandle, maximumMasterKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximumMasterKeyFileBytes {
		clear(encoded)
		return nil, errors.New("pki: workspace master-key file has an invalid size")
	}
	file, err := decodeFileMasterKeys(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return providerFromFile(path, file)
}

func providerFromFile(path string, file fileMasterKeys) (*FileMasterKeyProvider, error) {
	if file.SchemaVersion != FileMasterKeySchemaV1 || len(file.Keys) == 0 || len(file.Keys) > maximumMasterKeyVersions {
		return nil, errors.New("pki: unsupported or empty workspace master-key file")
	}
	if err := apppki.ValidateKeyVersion(file.ActiveVersion); err != nil {
		return nil, err
	}
	keys := make(map[string]MasterKey, len(file.Keys))
	loaded := false
	defer func() {
		if !loaded {
			clearMasterKeyMap(keys)
		}
	}()
	for version, encodedKey := range file.Keys {
		if err := apppki.ValidateKeyVersion(version); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
		if err != nil {
			return nil, fmt.Errorf("pki: decode workspace master key %q: %w", version, err)
		}
		key, err := NewMasterKey(raw)
		clear(raw)
		if err != nil {
			return nil, err
		}
		keys[version] = key
	}
	if _, ok := keys[file.ActiveVersion]; !ok {
		return nil, errors.New("pki: active workspace master-key version is unavailable")
	}
	loaded = true
	return &FileMasterKeyProvider{path: path, active: file.ActiveVersion, keys: keys}, nil
}

func (p *FileMasterKeyProvider) ActiveMasterKey(ctx context.Context) (string, MasterKey, error) {
	if err := ctx.Err(); err != nil {
		return "", MasterKey{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return "", MasterKey{}, errors.New("pki: file master-key provider is closed")
	}
	key, ok := p.keys[p.active]
	if !ok {
		return "", MasterKey{}, errors.New("pki: active workspace master key is unavailable")
	}
	return p.active, key, nil
}

// ActiveVersion reports the active key epoch without copying key material.
func (p *FileMasterKeyProvider) ActiveVersion(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return "", errors.New("pki: file master-key provider is closed")
	}
	if _, ok := p.keys[p.active]; !ok {
		return "", errors.New("pki: active workspace master key is unavailable")
	}
	return p.active, nil
}

func (p *FileMasterKeyProvider) WithStableKeyEpoch(ctx context.Context, operation func() error) error {
	if operation == nil {
		return errors.New("pki: stable key-epoch operation is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.maintenanceMu.RLock()
	defer p.maintenanceMu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (p *FileMasterKeyProvider) MasterKey(ctx context.Context, version string) (MasterKey, error) {
	if err := ctx.Err(); err != nil {
		return MasterKey{}, err
	}
	if err := apppki.ValidateKeyVersion(version); err != nil {
		return MasterKey{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return MasterKey{}, errors.New("pki: file master-key provider is closed")
	}
	key, ok := p.keys[version]
	if !ok {
		return MasterKey{}, errors.New("pki: workspace master-key version is unavailable")
	}
	return key, nil
}

func (p *FileMasterKeyProvider) rotate(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", errors.New("pki: file master-key provider is closed")
	}
	version, key, err := p.generateUniqueMasterKeyVersionLocked()
	if err != nil {
		return "", err
	}
	previous := p.active
	p.keys[version] = key
	p.active = version
	committed, err := p.persistLocked(masterKeyPersistReplace)
	if err != nil && !committed {
		p.keys[version] = MasterKey{}
		delete(p.keys, version)
		clear(key[:])
		p.active = previous
		return "", err
	}
	return version, err
}

func (p *FileMasterKeyProvider) retire(ctx context.Context, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := apppki.ValidateKeyVersion(version); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("pki: file master-key provider is closed")
	}
	if version == p.active {
		return errors.New("pki: active workspace master key cannot be retired")
	}
	key, ok := p.keys[version]
	if !ok {
		return errors.New("pki: workspace master-key version is unavailable")
	}
	p.keys[version] = MasterKey{}
	delete(p.keys, version)
	committed, err := p.persistLocked(masterKeyPersistReplace)
	if err != nil && !committed {
		p.keys[version] = key
		return err
	}
	clear(key[:])
	return err
}

func (p *FileMasterKeyProvider) Versions() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	versions := make([]string, 0, len(p.keys))
	for version := range p.keys {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions
}

func (p *FileMasterKeyProvider) WorkspacePath() string {
	if p == nil {
		return ""
	}
	return filepath.Dir(filepath.Dir(p.path))
}

func (p *FileMasterKeyProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.clearLocked()
	p.closed = true
	return nil
}

func (p *FileMasterKeyProvider) persistLocked(mode masterKeyPersistMode) (committed bool, resultErr error) {
	if mode != masterKeyPersistCreate && mode != masterKeyPersistReplace {
		return false, errors.New("pki: invalid master-key persistence mode")
	}
	file := p.snapshotLocked()
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return false, fmt.Errorf("pki: encode workspace master keys: %w", err)
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	temporary, err := os.CreateTemp(filepath.Dir(p.path), ".pki-master-keys-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("pki: remove temporary master-key file: %w", err))
		}
	}()
	if err := secureSecretTempFile(temporary); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(encoded); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if mode == masterKeyPersistCreate {
		if err := os.Link(temporaryPath, p.path); err != nil {
			return false, fmt.Errorf("pki: initialize file master-key provider: %w", err)
		}
	} else if err := os.Rename(temporaryPath, p.path); err != nil {
		return false, err
	}
	committed = true
	directory, err := os.Open(filepath.Dir(p.path))
	if err != nil {
		return true, fmt.Errorf("pki: sync workspace master-key directory after commit: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return true, fmt.Errorf("pki: sync workspace master-key directory after commit: %w", err)
	}
	return true, nil
}

func (p *FileMasterKeyProvider) clearLocked() {
	clearMasterKeyMap(p.keys)
	p.keys = nil
	p.active = ""
}

func clearMasterKeyMap(keys map[string]MasterKey) {
	for version := range keys {
		keys[version] = MasterKey{}
		delete(keys, version)
	}
}

func (p *FileMasterKeyProvider) generateUniqueMasterKeyVersionLocked() (string, MasterKey, error) {
	if len(p.keys) >= maximumMasterKeyVersions {
		return "", MasterKey{}, errors.New("pki: workspace master-key version limit reached")
	}
	for range masterKeyVersionRetries {
		version, key, err := generateMasterKeyVersion()
		if err != nil {
			return "", MasterKey{}, err
		}
		if _, exists := p.keys[version]; !exists {
			return version, key, nil
		}
		clear(key[:])
	}
	return "", MasterKey{}, errors.New("pki: failed to generate a unique master-key version")
}

func generateMasterKeyVersion() (string, MasterKey, error) {
	versionBytes := make([]byte, masterKeyVersionRandomBytes)
	if _, err := rand.Read(versionBytes); err != nil {
		return "", MasterKey{}, fmt.Errorf("pki: generate master-key version: %w", err)
	}
	version := masterKeyVersionPrefix + hex.EncodeToString(versionBytes)
	clear(versionBytes)
	var key MasterKey
	if _, err := rand.Read(key[:]); err != nil {
		return "", MasterKey{}, fmt.Errorf("pki: generate workspace master key: %w", err)
	}
	return version, key, nil
}

func decodeFileMasterKeys(encoded []byte) (fileMasterKeys, error) {
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), maximumMasterKeyFileBytes+1))
	decoder.DisallowUnknownFields()
	var file fileMasterKeys
	if err := decoder.Decode(&file); err != nil {
		return fileMasterKeys{}, fmt.Errorf("pki: decode workspace master keys: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fileMasterKeys{}, errors.New("pki: workspace master-key file contains trailing data")
	}
	if file.SchemaVersion != FileMasterKeySchemaV1 || len(file.Keys) == 0 || len(file.Keys) > maximumMasterKeyVersions {
		return fileMasterKeys{}, errors.New("pki: unsupported or empty workspace master-key file")
	}
	if err := apppki.ValidateKeyVersion(file.ActiveVersion); err != nil {
		return fileMasterKeys{}, err
	}
	return file, nil
}

var _ MasterKeyProvider = (*FileMasterKeyProvider)(nil)
var _ StableMasterKeyProvider = (*FileMasterKeyProvider)(nil)
