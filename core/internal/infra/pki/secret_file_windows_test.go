//go:build windows

package pki

import (
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateWindowsOwnerOnlyDACL(t *testing.T) {
	t.Parallel()

	const ownerString = "S-1-5-21-1-2-3-1001"
	owner, err := windows.StringToSid(ownerString)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		sddl      string
		directory bool
		wantErr   bool
	}{
		{
			name: "owner-only file",
			sddl: "D:P(A;;FA;;;" + ownerString + ")",
		},
		{
			name:      "owner-only directory",
			sddl:      "D:P(A;OICI;FA;;;" + ownerString + ")",
			directory: true,
		},
		{
			name:    "unprotected DACL",
			sddl:    "D:(A;;FA;;;" + ownerString + ")",
			wantErr: true,
		},
		{
			name:    "different principal",
			sddl:    "D:P(A;;FA;;;WD)",
			wantErr: true,
		},
		{
			name:    "additional principal",
			sddl:    "D:P(A;;FA;;;" + ownerString + ")(A;;FR;;;WD)",
			wantErr: true,
		},
		{
			name:    "incomplete owner access",
			sddl:    "D:P(A;;FR;;;" + ownerString + ")",
			wantErr: true,
		},
		{
			name:    "inherited owner entry",
			sddl:    "D:P(A;ID;FA;;;" + ownerString + ")",
			wantErr: true,
		},
		{
			name:      "directory entry without child inheritance",
			sddl:      "D:P(A;;FA;;;" + ownerString + ")",
			directory: true,
			wantErr:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateWindowsOwnerOnlyDACL(descriptor, owner, test.directory)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("validateWindowsOwnerOnlyDACL() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestValidateSecretDirectoryUsesWindowsDACL(t *testing.T) {
	t.Parallel()

	path := t.TempDir()
	if err := setWindowsOwnerOnlyDACL(path, true); err != nil {
		t.Fatal(err)
	}
	if err := validateSecretDirectory(path); err != nil {
		t.Fatalf("validateSecretDirectory() rejected a protected owner-only DACL: %v", err)
	}
}

func TestOpenFileMasterKeyProviderRejectsWindowsFileDACLForOtherPrincipal(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	provider, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	owner := currentWindowsTestUserSID(t)
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsTestDACL(t, filepath.Join(workspacePath, MasterKeyRelativePath), false, owner, world)
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() accepted a master-key DACL for another principal")
	}
}

func TestOpenFileMasterKeyProviderRejectsWindowsDirectoryDACLForOtherPrincipal(t *testing.T) {
	t.Parallel()

	workspacePath := t.TempDir()
	provider, err := InitializeFileMasterKeyProvider(t.Context(), workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	owner := currentWindowsTestUserSID(t)
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(workspacePath, filepath.Dir(MasterKeyRelativePath))
	setWindowsTestDACL(t, directory, true, owner, world)
	if _, err := OpenFileMasterKeyProvider(t.Context(), workspacePath); err == nil {
		t.Fatal("OpenFileMasterKeyProvider() accepted a secrets-directory DACL for another principal")
	}
}

func currentWindowsTestUserSID(t *testing.T) *windows.SID {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if currentUser == nil || currentUser.User.Sid == nil {
		t.Fatal("current Windows principal is unavailable")
	}
	return currentUser.User.Sid
}

func setWindowsTestDACL(t *testing.T, path string, directory bool, principals ...*windows.SID) {
	t.Helper()

	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(principals))
	var pinner runtime.Pinner
	defer pinner.Unpin()
	for _, principal := range principals {
		pinner.Pin(principal)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(principal),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}
