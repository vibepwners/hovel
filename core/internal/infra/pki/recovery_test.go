package pki

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vibepwners/hovel/internal/domain/workspace"
)

func TestFileMasterKeyRecoveryRoundTrip(t *testing.T) {
	workspaceID, err := workspace.NewID("workspace-recovery")
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := t.TempDir()
	source, err := InitializeFileMasterKeyProvider(t.Context(), sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	firstVersion, firstKey, err := source.ActiveMasterKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	secondVersion, err := source.rotate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	recovery, err := source.ExportRecovery(t.Context(), workspaceID, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(recovery, firstKey[:]) || bytes.Contains(recovery, []byte(base64.StdEncoding.EncodeToString(firstKey[:]))) {
		t.Fatal("recovery envelope contains plaintext master-key material")
	}

	restorePath := t.TempDir()
	restored, err := RestoreFileMasterKeyProvider(t.Context(), restorePath, workspaceID, recovery, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := restored.Close(); err != nil {
			t.Error(err)
		}
	}()
	if got := restored.Versions(); len(got) != 2 || !slices.Contains(got, firstVersion) || !slices.Contains(got, secondVersion) {
		t.Fatalf("restored versions = %v, want %q and %q", got, firstVersion, secondVersion)
	}
	restoredFirst, err := restored.MasterKey(t.Context(), firstVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredFirst[:], firstKey[:]) {
		t.Fatal("restored historical master key differs from source")
	}
	if _, err := RestoreFileMasterKeyProvider(t.Context(), restorePath, workspaceID, recovery, passphrase); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second restore error = %v, want os.ErrExist", err)
	}
}

func TestFileMasterKeyRecoveryFailsClosed(t *testing.T) {
	workspaceID, err := workspace.NewID("workspace-recovery-failures")
	if err != nil {
		t.Fatal(err)
	}
	source, err := InitializeFileMasterKeyProvider(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	passphrase := []byte("correct horse battery staple")
	recovery, err := source.ExportRecovery(t.Context(), workspaceID, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	wrongPasswordPath := t.TempDir()
	if _, err := RestoreFileMasterKeyProvider(t.Context(), wrongPasswordPath, workspaceID, recovery, []byte("incorrect passphrase")); err == nil {
		t.Fatal("RestoreFileMasterKeyProvider() accepted an incorrect passphrase")
	}
	assertRecoveryDidNotCreateSecrets(t, wrongPasswordPath)

	otherWorkspaceID, err := workspace.NewID("workspace-other")
	if err != nil {
		t.Fatal(err)
	}
	wrongWorkspacePath := t.TempDir()
	if _, err := RestoreFileMasterKeyProvider(t.Context(), wrongWorkspacePath, otherWorkspaceID, recovery, passphrase); err == nil {
		t.Fatal("RestoreFileMasterKeyProvider() accepted another workspace id")
	}
	assertRecoveryDidNotCreateSecrets(t, wrongWorkspacePath)

	var envelope recoveryEnvelope
	if err := json.Unmarshal(recovery, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.MemoryKiB = maximumRecoveryMemoryKiB + 1
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreFileMasterKeyProvider(t.Context(), t.TempDir(), workspaceID, tampered, passphrase); err == nil {
		t.Fatal("RestoreFileMasterKeyProvider() accepted unsafe kdf parameters")
	}

	if _, err := source.ExportRecovery(t.Context(), workspaceID, []byte("too-short")); err == nil {
		t.Fatal("ExportRecovery() accepted a short recovery passphrase")
	}
}

func assertRecoveryDidNotCreateSecrets(t *testing.T, workspacePath string) {
	t.Helper()
	secretDirectory := filepath.Join(workspacePath, filepath.Dir(MasterKeyRelativePath))
	if _, err := os.Lstat(secretDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery created %q or returned unexpected stat error: %v", secretDirectory, err)
	}
}
