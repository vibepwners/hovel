//go:build windows

package pki

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsFileDeleteChild windows.ACCESS_MASK = 0x00000040
	windowsFileAllAccess                       = windows.STANDARD_RIGHTS_REQUIRED |
		windows.SYNCHRONIZE |
		windows.FILE_READ_DATA |
		windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.FILE_READ_EA |
		windows.FILE_WRITE_EA |
		windows.FILE_EXECUTE |
		windowsFileDeleteChild |
		windows.FILE_READ_ATTRIBUTES |
		windows.FILE_WRITE_ATTRIBUTES
)

func openSecretFile(path string) (*os.File, os.FileInfo, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	closeHandle := func(cause error) (*os.File, os.FileInfo, error) {
		return nil, nil, errors.Join(cause, windows.CloseHandle(handle))
	}
	if err := validateWindowsSecretHandle(handle, false, true); err != nil {
		return closeHandle(err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return closeHandle(errors.New("pki: open workspace master-key file"))
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	return file, info, nil
}

func secureSecretTempFile(file *os.File) error {
	handle := windows.Handle(file.Fd())
	if err := validateWindowsSecretHandle(handle, false, false); err != nil {
		return err
	}
	if err := setWindowsOwnerOnlyDACL(file.Name(), false); err != nil {
		return err
	}
	return validateWindowsSecretHandle(handle, false, true)
}

func ensureSecretDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	handle, err := openWindowsSecretDirectory(path)
	if err != nil {
		return err
	}
	if err := validateWindowsSecretHandle(handle, true, false); err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	if err := setWindowsOwnerOnlyDACL(path, true); err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	return errors.Join(validateWindowsSecretHandle(handle, true, true), windows.CloseHandle(handle))
}

func validateSecretDirectory(path string) error {
	handle, err := openWindowsSecretDirectory(path)
	if err != nil {
		return err
	}
	return errors.Join(validateWindowsSecretHandle(handle, true, true), windows.CloseHandle(handle))
}

func openWindowsSecretDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func validateWindowsSecretHandle(handle windows.Handle, directory, requireRestrictedDACL bool) error {
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return err
	}
	if identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("pki: workspace secret path must not be a Windows reparse point")
	}
	isDirectory := identity.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		return errors.New("pki: workspace secret path has an unexpected file type")
	}
	if !directory && identity.NumberOfLinks != 1 {
		return errors.New("pki: workspace master-key file must have exactly one hard link")
	}

	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION)
	if requireRestrictedDACL {
		securityInformation |= windows.DACL_SECURITY_INFORMATION
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInformation)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if owner == nil || currentUser == nil || !windows.EqualSid(owner, currentUser.User.Sid) {
		return errors.New("pki: workspace secret path is owned by another principal")
	}
	if !requireRestrictedDACL {
		return nil
	}
	return validateWindowsOwnerOnlyDACL(descriptor, currentUser.User.Sid, directory)
}

func setWindowsOwnerOnlyDACL(path string, directory bool) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if currentUser == nil || currentUser.User.Sid == nil {
		return errors.New("pki: current Windows principal is unavailable")
	}

	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var pinner runtime.Pinner
	pinner.Pin(currentUser.User.Sid)
	defer pinner.Unpin()
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func validateWindowsOwnerOnlyDACL(
	descriptor *windows.SECURITY_DESCRIPTOR,
	owner *windows.SID,
	directory bool,
) error {
	invalidDACL := errors.New("pki: workspace secret path must have a protected owner-only DACL")
	if descriptor == nil || owner == nil {
		return invalidDACL
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return invalidDACL
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return invalidDACL
	}
	if dacl == nil || defaulted || dacl.AceCount != 1 {
		return invalidDACL
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return invalidDACL
	}
	wantFlags := uint8(windows.NO_INHERITANCE)
	if directory {
		wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceFlags != wantFlags {
		return invalidDACL
	}
	if ace.Mask&windows.GENERIC_ALL == 0 && ace.Mask&windowsFileAllAccess != windowsFileAllAccess {
		return invalidDACL
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.IsValid() || !windows.EqualSid(aceSID, owner) {
		return invalidDACL
	}
	return nil
}
