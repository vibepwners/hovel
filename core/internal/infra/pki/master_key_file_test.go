package pki

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpenFileMasterKeyProviderHasNoInitializationSideEffects(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	_, err := OpenFileMasterKeyProvider(t.Context(), workspacePath)
	if !errors.Is(err, ErrMasterKeysNotInitialized) {
		t.Fatalf("OpenFileMasterKeyProvider() error = %v, want ErrMasterKeysNotInitialized", err)
	}
	secretDirectory := filepath.Join(workspacePath, filepath.Dir(MasterKeyRelativePath))
	if _, err := os.Lstat(secretDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenFileMasterKeyProvider() created %q or returned unexpected stat error: %v", secretDirectory, err)
	}
}

func TestInitializeFileMasterKeyProviderIsAtomicAcrossCallers(t *testing.T) {
	t.Parallel()

	const callerCount = 8
	workspacePath := t.TempDir()
	type initializationResult struct {
		provider *FileMasterKeyProvider
		err      error
	}
	results := make(chan initializationResult, callerCount)
	var ready sync.WaitGroup
	ready.Add(callerCount)
	start := make(chan struct{})
	for range callerCount {
		go func() {
			ready.Done()
			<-start
			provider, err := InitializeFileMasterKeyProvider(context.Background(), workspacePath)
			results <- initializationResult{provider: provider, err: err}
		}()
	}
	ready.Wait()
	close(start)

	successes := 0
	for range callerCount {
		result := <-results
		if result.err == nil {
			successes++
			if result.provider == nil {
				t.Fatal("successful initialization returned a nil provider")
			}
			if closeErr := result.provider.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			continue
		}
		if result.provider != nil {
			if closeErr := result.provider.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if !errors.Is(result.err, os.ErrExist) {
			t.Errorf("initialization error = %v, want os.ErrExist", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful initializations = %d, want 1", successes)
	}

	reopened, err := OpenFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileMasterKeyProviderLifecycle(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() initialized a missing provider")
	}
	provider, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second initialization error = %v, want os.ErrExist", err)
	}
	firstVersion, firstKey, err := provider.ActiveMasterKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	activeVersion, err := provider.ActiveVersion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if activeVersion != firstVersion {
		t.Fatalf("ActiveVersion() = %q, want %q", activeVersion, firstVersion)
	}
	secondVersion, err := provider.rotate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if secondVersion == firstVersion {
		t.Fatal("Rotate() reused a master-key version")
	}
	activeVersion, err = provider.ActiveVersion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if activeVersion != secondVersion {
		t.Fatalf("ActiveVersion() after rotation = %q, want %q", activeVersion, secondVersion)
	}
	if len(provider.Versions()) != 2 {
		t.Fatalf("master-key versions = %v, want two", provider.Versions())
	}
	loadedFirst, err := provider.MasterKey(t.Context(), firstVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedFirst[:], firstKey[:]) {
		t.Fatal("historical master key changed after rotation")
	}
	if err := provider.retire(t.Context(), secondVersion); err == nil {
		t.Fatal("Retire() retired the active master key")
	}
	if err := provider.retire(t.Context(), firstVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.MasterKey(t.Context(), firstVersion); err == nil {
		t.Fatal("retired master key remained available")
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	activeVersion, err = reopened.ActiveVersion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if activeVersion != secondVersion || len(reopened.Versions()) != 1 {
		t.Fatalf("reopened provider active=%q versions=%v", activeVersion, reopened.Versions())
	}

}

func TestFileMasterKeyProviderRejectsCorruptFiles(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	provider, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspacePath, MasterKeyRelativePath)
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"hovel.pki.file-master-keys/v1"} trailing`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() accepted corrupt data")
	}
}
