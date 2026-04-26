package workspace

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
)

const DefaultPath = ".hovel"

type ID string

func NewID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("workspace id is required")
	}
	return ID(value), nil
}

func (id ID) String() string {
	return string(id)
}

type Name string

func NewName(value string) (Name, error) {
	if value != strings.TrimSpace(value) || value == "" {
		return "", errors.New("workspace name is required")
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", errors.New("workspace name contains invalid characters")
	}
	if strings.Contains(value, "..") {
		return "", errors.New("workspace name must not contain path traversal")
	}
	return Name(value), nil
}

func (name Name) String() string {
	return string(name)
}

type Workspace struct {
	ID   ID
	Name Name
	Path string
}

func New(id ID, name Name, path string) (Workspace, error) {
	if id == "" {
		return Workspace{}, errors.New("workspace id is required")
	}
	if name == "" {
		return Workspace{}, errors.New("workspace name is required")
	}
	path = ResolvePath(path)
	if path == "." || path == "" {
		return Workspace{}, errors.New("workspace path is required")
	}
	return Workspace{
		ID:   id,
		Name: name,
		Path: path,
	}, nil
}

func ResolvePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultPath
	}
	return filepath.Clean(value)
}
