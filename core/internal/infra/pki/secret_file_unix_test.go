//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenFileMasterKeyProviderRejectsGroupReadableFile(t *testing.T) {
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
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() accepted a group-readable master-key file")
	}
}

func TestOpenFileMasterKeyProviderRejectsGroupAccessibleDirectory(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	provider, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(workspacePath, filepath.Dir(MasterKeyRelativePath))
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() accepted a group-accessible secrets directory")
	}
}
