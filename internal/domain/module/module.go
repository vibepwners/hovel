package module

import (
	"errors"
	"strings"
)

// ID is a non-empty string value object identifying a module instance.
type ID string

// NewID creates an ID, rejecting empty or whitespace-only values.
func NewID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("module id is required")
	}
	return ID(value), nil
}

func (id ID) String() string {
	return string(id)
}

// Name is a validated module name matching [a-z0-9][a-z0-9-]* with no trailing hyphen.
type Name string

// NewName creates a Name.
// Valid names start with a lowercase letter or digit, contain only lowercase
// letters, digits, and hyphens, and must not start or end with a hyphen.
func NewName(value string) (Name, error) {
	if value == "" || strings.TrimSpace(value) == "" {
		return "", errors.New("module name is required")
	}
	if value[0] == '-' {
		return "", errors.New("module name must not start with a hyphen")
	}
	if value[len(value)-1] == '-' {
		return "", errors.New("module name must not end with a hyphen")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", errors.New("module name must contain only lowercase letters, digits, and hyphens")
	}
	return Name(value), nil
}

func (name Name) String() string {
	return string(name)
}

// Version is a non-empty, trimmed version string.
type Version string

// NewVersion creates a Version, rejecting empty or whitespace-only values.
func NewVersion(value string) (Version, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("module version is required")
	}
	return Version(value), nil
}

func (v Version) String() string {
	return string(v)
}

// Type is one of the recognized module type values from the domain model.
type Type string

var validTypes = map[string]struct{}{
	"survey":           {},
	"exploit":          {},
	"payload_provider": {},
	"transport":        {},
	"access":           {},
	"deliver":          {},
	"payload":          {},
	"post_action":      {},
	"cleanup":          {},
	"transform":        {},
	"provider":         {},
	"chain":            {},
	"utility":          {},
	"service_client":   {},
}

// NewType creates a Type, rejecting unknown or empty values.
func NewType(value string) (Type, error) {
	if value == "" {
		return "", errors.New("module type is required")
	}
	if _, ok := validTypes[value]; !ok {
		return "", errors.New("module type is not valid: " + value)
	}
	return Type(value), nil
}

func (t Type) String() string {
	return string(t)
}

// Descriptor holds the validated identity fields for a module.
type Descriptor struct {
	ID      ID
	Name    Name
	Version Version
	Type    Type
}

// New creates a Descriptor, requiring all fields to be non-zero validated values.
func New(id ID, name Name, version Version, typ Type) (Descriptor, error) {
	if id == "" {
		return Descriptor{}, errors.New("module id is required")
	}
	if name == "" {
		return Descriptor{}, errors.New("module name is required")
	}
	if version == "" {
		return Descriptor{}, errors.New("module version is required")
	}
	if typ == "" {
		return Descriptor{}, errors.New("module type is required")
	}
	return Descriptor{
		ID:      id,
		Name:    name,
		Version: version,
		Type:    typ,
	}, nil
}
