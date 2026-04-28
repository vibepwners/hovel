package service

import (
	"errors"
	"strings"
)

// ServiceID is a non-empty string value object identifying a service instance.
type ServiceID string

// NewServiceID creates a ServiceID, rejecting empty or whitespace-only values.
func NewServiceID(value string) (ServiceID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("service id is required")
	}
	return ServiceID(value), nil
}

func (id ServiceID) String() string {
	return string(id)
}

// ServiceName is a validated name that must match [a-z0-9][a-z0-9-]* with no trailing hyphen.
type ServiceName string

// NewServiceName creates a ServiceName.
// Valid names start with a lowercase letter or digit, contain only lowercase
// letters, digits, and hyphens, and must not start or end with a hyphen.
func NewServiceName(value string) (ServiceName, error) {
	if value == "" || strings.TrimSpace(value) == "" {
		return "", errors.New("service name is required")
	}
	// Must not start with a hyphen
	if value[0] == '-' {
		return "", errors.New("service name must not start with a hyphen")
	}
	// Must not end with a hyphen
	if value[len(value)-1] == '-' {
		return "", errors.New("service name must not end with a hyphen")
	}
	// All characters must be lowercase letters, digits, or hyphens
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", errors.New("service name must contain only lowercase letters, digits, and hyphens")
	}
	return ServiceName(value), nil
}

func (name ServiceName) String() string {
	return string(name)
}

// ServiceVersion is a non-empty, trimmed version string.
type ServiceVersion string

// NewServiceVersion creates a ServiceVersion, rejecting empty or whitespace-only values.
func NewServiceVersion(value string) (ServiceVersion, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("service version is required")
	}
	return ServiceVersion(value), nil
}

func (v ServiceVersion) String() string {
	return string(v)
}

// ServiceType is one of the recognized service type values from the domain model.
type ServiceType string

var validServiceTypes = map[string]struct{}{
	"payload_provider":  {},
	"listener":          {},
	"session_broker":    {},
	"credential_broker": {},
	"artifact_server":   {},
	"callback_listener": {},
	"inventory_sync":    {},
	"generic":           {},
}

// NewServiceType creates a ServiceType, rejecting unknown or empty values.
func NewServiceType(value string) (ServiceType, error) {
	if value == "" {
		return "", errors.New("service type is required")
	}
	if _, ok := validServiceTypes[value]; !ok {
		return "", errors.New("service type is not valid: " + value)
	}
	return ServiceType(value), nil
}

func (t ServiceType) String() string {
	return string(t)
}

// Descriptor holds the validated identity fields for a service.
type Descriptor struct {
	ID      ServiceID
	Name    ServiceName
	Version ServiceVersion
	Type    ServiceType
}

// New creates a Descriptor, requiring all fields to be non-zero validated values.
func New(id ServiceID, name ServiceName, version ServiceVersion, typ ServiceType) (Descriptor, error) {
	if id == "" {
		return Descriptor{}, errors.New("service id is required")
	}
	if name == "" {
		return Descriptor{}, errors.New("service name is required")
	}
	if version == "" {
		return Descriptor{}, errors.New("service version is required")
	}
	if typ == "" {
		return Descriptor{}, errors.New("service type is required")
	}
	return Descriptor{
		ID:      id,
		Name:    name,
		Version: version,
		Type:    typ,
	}, nil
}
