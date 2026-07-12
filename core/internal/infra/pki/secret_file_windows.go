//go:build windows

package pki

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
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
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return closeHandle(err)
	}
	if identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		identity.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || identity.NumberOfLinks != 1 {
		return closeHandle(errors.New("pki: workspace master-key file attributes or link count are unsafe"))
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return closeHandle(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return closeHandle(err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return closeHandle(err)
	}
	if owner == nil || currentUser == nil || !windows.EqualSid(owner, currentUser.User.Sid) {
		return closeHandle(errors.New("pki: workspace master-key file is owned by another principal"))
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

func validateSecretFilePermissions(os.FileInfo) error {
	// Windows ownership and reparse/link checks are performed on the open
	// handle above; os.FileMode does not faithfully represent the file DACL.
	return nil
}
