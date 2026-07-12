package pki

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/vibepwners/hovel/internal/domain/workspace"
)

type MasterKeyRewrapper interface {
	WorkspaceID() workspace.ID
	WorkspacePath() string
	RewrapKeys(context.Context) (int, error)
	ReferencedMasterKeyVersions(context.Context) ([]string, error)
}

type MasterKeyRotationResult struct {
	ActiveVersion   string
	RewrappedKeys   int
	RetiredVersions []string
}

type MasterKeyRotationCoordinator struct {
	provider  *FileMasterKeyProvider
	rewrapper MasterKeyRewrapper
}

func NewMasterKeyRotationCoordinator(provider *FileMasterKeyProvider, rewrapper MasterKeyRewrapper) (MasterKeyRotationCoordinator, error) {
	if provider == nil || rewrapper == nil {
		return MasterKeyRotationCoordinator{}, errors.New("pki: master-key provider and rewrapper are required")
	}
	if _, err := workspace.NewID(rewrapper.WorkspaceID().String()); err != nil {
		return MasterKeyRotationCoordinator{}, fmt.Errorf("pki: invalid rewrapper workspace identity: %w", err)
	}
	if filepath.Clean(provider.WorkspacePath()) != filepath.Clean(rewrapper.WorkspacePath()) {
		return MasterKeyRotationCoordinator{}, errors.New("pki: master-key provider and rewrapper belong to different workspaces")
	}
	return MasterKeyRotationCoordinator{provider: provider, rewrapper: rewrapper}, nil
}

// RotateAndRewrap creates a new active master key, transactionally rewraps all
// stored key and metadata records, verifies the resulting references, and only
// then retires superseded versions. A failure always retains every key version
// that may still be referenced.
func (c MasterKeyRotationCoordinator) RotateAndRewrap(ctx context.Context) (MasterKeyRotationResult, error) {
	c.provider.maintenanceMu.Lock()
	defer c.provider.maintenanceMu.Unlock()
	version, err := c.provider.rotate(ctx)
	if err != nil {
		return MasterKeyRotationResult{ActiveVersion: version}, err
	}
	return c.convergeLocked(ctx, version)
}

// ConvergeActive repairs an interrupted rotation without creating another key.
func (c MasterKeyRotationCoordinator) ConvergeActive(ctx context.Context) (MasterKeyRotationResult, error) {
	c.provider.maintenanceMu.Lock()
	defer c.provider.maintenanceMu.Unlock()
	version, key, err := c.provider.ActiveMasterKey(ctx)
	clear(key[:])
	if err != nil {
		return MasterKeyRotationResult{}, err
	}
	return c.convergeLocked(ctx, version)
}

func (c MasterKeyRotationCoordinator) convergeLocked(ctx context.Context, targetVersion string) (MasterKeyRotationResult, error) {
	rewrapped, err := c.rewrapper.RewrapKeys(ctx)
	if err != nil {
		return MasterKeyRotationResult{ActiveVersion: targetVersion}, fmt.Errorf("pki: rewrap records with active master key: %w", err)
	}
	referenced, err := c.rewrapper.ReferencedMasterKeyVersions(ctx)
	if err != nil {
		return MasterKeyRotationResult{ActiveVersion: targetVersion, RewrappedKeys: rewrapped}, fmt.Errorf("pki: verify master-key references after rewrap: %w", err)
	}
	for _, version := range referenced {
		if version != targetVersion {
			return MasterKeyRotationResult{ActiveVersion: targetVersion, RewrappedKeys: rewrapped}, fmt.Errorf("pki: record still references superseded master-key version %q", version)
		}
	}
	result := MasterKeyRotationResult{ActiveVersion: targetVersion, RewrappedKeys: rewrapped}
	for _, version := range c.provider.Versions() {
		if version == targetVersion {
			continue
		}
		if err := c.provider.retire(ctx, version); err != nil {
			return result, fmt.Errorf("pki: retire superseded master-key version %q: %w", version, err)
		}
		result.RetiredVersions = append(result.RetiredVersions, version)
	}
	return result, nil
}
