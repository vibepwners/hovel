package module

import (
	"errors"
	"strings"
)

// ModuleID is a non-empty string value object identifying a module instance.
type ModuleID string

// NewModuleID creates a ModuleID, rejecting empty or whitespace-only values.
func NewModuleID(value string) (ModuleID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("module id is required")
	}
	return ModuleID(value), nil
}

func (id ModuleID) String() string {
	return string(id)
}

// ModuleName is a validated name that must match [a-z0-9][a-z0-9-]* with no trailing hyphen.
type ModuleName string

// NewModuleName creates a ModuleName.
// Valid names start with a lowercase letter or digit, contain only lowercase
// letters, digits, and hyphens, and must not start or end with a hyphen.
func NewModuleName(value string) (ModuleName, error) {
	if value == "" || strings.TrimSpace(value) == "" {
		return "", errors.New("module name is required")
	}
	if len(value) == 0 {
		return "", errors.New("module name is required")
	}
	// Must not start with a hyphen
	if value[0] == '-' {
		return "", errors.New("module name must not start with a hyphen")
	}
	// Must not end with a hyphen
	if value[len(value)-1] == '-' {
		return "", errors.New("module name must not end with a hyphen")
	}
	// All characters must be lowercase letters, digits, or hyphens
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", errors.New("module name must contain only lowercase letters, digits, and hyphens")
	}
	return ModuleName(value), nil
}

func (name ModuleName) String() string {
	return string(name)
}

// ModuleVersion is a non-empty, trimmed version string.
type ModuleVersion string

// NewModuleVersion creates a ModuleVersion, rejecting empty or whitespace-only values.
func NewModuleVersion(value string) (ModuleVersion, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("module version is required")
	}
	return ModuleVersion(value), nil
}

func (v ModuleVersion) String() string {
	return string(v)
}

// ModuleType is one of the recognized module type values from the domain model.
type ModuleType string

var validModuleTypes = map[string]struct{}{
	"survey":         {},
	"transport":      {},
	"access":         {},
	"deliver":        {},
	"payload":        {},
	"post_action":    {},
	"cleanup":        {},
	"transform":      {},
	"provider":       {},
	"chain":          {},
	"utility":        {},
	"service_client": {},
}

// NewModuleType creates a ModuleType, rejecting unknown or empty values.
func NewModuleType(value string) (ModuleType, error) {
	if value == "" {
		return "", errors.New("module type is required")
	}
	if _, ok := validModuleTypes[value]; !ok {
		return "", errors.New("module type is not valid: " + value)
	}
	return ModuleType(value), nil
}

func (t ModuleType) String() string {
	return string(t)
}

// Descriptor holds the validated identity fields for a module.
type Descriptor struct {
	ID      ModuleID
	Name    ModuleName
	Version ModuleVersion
	Type    ModuleType
}

// New creates a Descriptor, requiring all fields to be non-zero validated values.
func New(id ModuleID, name ModuleName, version ModuleVersion, typ ModuleType) (Descriptor, error) {
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
