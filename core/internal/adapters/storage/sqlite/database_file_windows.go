//go:build windows

package sqlite

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openDatabaseFileNoFollow(path string) (*os.File, error) {
	return openWindowsDatabaseFile(path, windows.OPEN_ALWAYS)
}

func openWindowsDatabaseFile(path string, disposition uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsHandle(handle, false); err != nil {
		return nil, errors.Join(err, windows.CloseHandle(handle))
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(errors.New("sqlite database file handle is invalid"), windows.CloseHandle(handle))
	}
	return file, nil
}

func validateDatabaseFileSecurity(os.FileInfo) error { return nil }

func validateDatabaseDirectorySecurity(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	return errors.Join(validateWindowsHandle(handle, true), windows.CloseHandle(handle))
}

func validateWindowsHandle(handle windows.Handle, directory bool) error {
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return err
	}
	if identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("sqlite path must not be a Windows reparse point")
	}
	isDirectory := identity.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		return errors.New("sqlite path has an unexpected file type")
	}
	if !directory && identity.NumberOfLinks != 1 {
		return errors.New("sqlite database file must have exactly one hard link")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
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
		return errors.New("sqlite path must be owned by the current principal")
	}
	return nil
}
