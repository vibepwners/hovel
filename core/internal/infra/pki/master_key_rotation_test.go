package pki

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/domain/workspace"
)

const keyEpochTestTimeout = time.Second

type testMasterKeyRewrapper struct {
	provider   *FileMasterKeyProvider
	references []string
	rewrapped  int
	err        error
	called     chan struct{}
}

func (r *testMasterKeyRewrapper) WorkspaceID() workspace.ID {
	id, err := workspace.NewID("workspace-master-key-rotation-test")
	if err != nil {
		panic(err)
	}
	return id
}

func (r *testMasterKeyRewrapper) WorkspacePath() string {
	return r.provider.WorkspacePath()
}

func (r *testMasterKeyRewrapper) RewrapKeys(ctx context.Context) (int, error) {
	if r.called != nil {
		close(r.called)
		r.called = nil
	}
	if r.err != nil {
		return 0, r.err
	}
	version, key, err := r.provider.ActiveMasterKey(ctx)
	clear(key[:])
	if err != nil {
		return 0, err
	}
	r.references = []string{version}
	return r.rewrapped, nil
}

func TestMasterKeyRotationWaitsForStableKeyEpochWriters(t *testing.T) {
	t.Parallel()

	provider, err := InitializeFileMasterKeyProvider(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Error(err)
		}
	}()
	writerStarted := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- provider.WithStableKeyEpoch(t.Context(), func() error {
			close(writerStarted)
			<-releaseWriter
			return nil
		})
	}()
	<-writerStarted
	rewrapCalled := make(chan struct{})
	rewrapper := &testMasterKeyRewrapper{provider: provider, called: rewrapCalled}
	coordinator, err := NewMasterKeyRotationCoordinator(provider, rewrapper)
	if err != nil {
		t.Fatal(err)
	}
	rotationDone := make(chan error, 1)
	go func() {
		_, rotateErr := coordinator.RotateAndRewrap(t.Context())
		rotationDone <- rotateErr
	}()
	select {
	case <-rewrapCalled:
		t.Fatal("rotation entered rewrap while a stable key-epoch writer was active")
	case <-time.After(keyEpochTestTimeout / 10):
	}
	close(releaseWriter)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-rotationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(keyEpochTestTimeout):
		t.Fatal("rotation did not continue after stable key-epoch writer completed")
	}
}

func (r *testMasterKeyRewrapper) ReferencedMasterKeyVersions(context.Context) ([]string, error) {
	return append([]string(nil), r.references...), nil
}

func TestMasterKeyRotationCoordinatorRetiresOnlyAfterVerifiedRewrap(t *testing.T) {
	t.Parallel()

	provider, err := InitializeFileMasterKeyProvider(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Error(err)
		}
	}()
	oldVersion, oldKey, err := provider.ActiveMasterKey(t.Context())
	clear(oldKey[:])
	if err != nil {
		t.Fatal(err)
	}
	rewrapper := &testMasterKeyRewrapper{provider: provider, rewrapped: 3}
	coordinator, err := NewMasterKeyRotationCoordinator(provider, rewrapper)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.RotateAndRewrap(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.ActiveVersion == oldVersion || result.RewrappedKeys != 3 || len(result.RetiredVersions) != 1 || result.RetiredVersions[0] != oldVersion {
		t.Fatalf("RotateAndRewrap() = %#v", result)
	}
	if _, err := provider.MasterKey(t.Context(), oldVersion); err == nil {
		t.Fatal("RotateAndRewrap() retained a verified superseded key")
	}
}

func TestMasterKeyRotationCoordinatorRetainsKeysOnRewrapFailure(t *testing.T) {
	t.Parallel()

	provider, err := InitializeFileMasterKeyProvider(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Error(err)
		}
	}()
	oldVersion, oldKey, err := provider.ActiveMasterKey(t.Context())
	clear(oldKey[:])
	if err != nil {
		t.Fatal(err)
	}
	rewrapper := &testMasterKeyRewrapper{provider: provider, err: errors.New("injected rewrap failure")}
	coordinator, err := NewMasterKeyRotationCoordinator(provider, rewrapper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RotateAndRewrap(t.Context()); err == nil {
		t.Fatal("RotateAndRewrap() accepted a failed rewrap")
	}
	if len(provider.Versions()) != 2 {
		t.Fatalf("versions after failed rewrap = %v, want old and new", provider.Versions())
	}
	retained, err := provider.MasterKey(t.Context(), oldVersion)
	clear(retained[:])
	if err != nil {
		t.Fatalf("old key was retired after failed rewrap: %v", err)
	}
	rewrapper.err = nil
	if _, err := coordinator.ConvergeActive(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(provider.Versions()) != 1 {
		t.Fatalf("versions after convergence = %v, want active only", provider.Versions())
	}
}
