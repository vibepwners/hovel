package descriptor

import (
	"encoding/json"
	"errors"

	"github.com/Vibe-Pwners/hovel/internal/domain/module"
	"github.com/Vibe-Pwners/hovel/internal/domain/service"
)

// rawDescriptor is the JSON wire format shared by both module and service descriptors.
type rawDescriptor struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   rawMetadata     `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
}

type rawMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type rawModuleSpec struct {
	ModuleType string `json:"moduleType"`
}

const expectedAPIVersion = "hovel.dev/v1alpha1"

// ValidateModuleDescriptor parses JSON bytes and returns a module.Descriptor.
// Returns error if JSON is malformed, required fields are missing, or values fail domain validation.
func ValidateModuleDescriptor(data []byte) (module.Descriptor, error) {
	var raw rawDescriptor
	if err := json.Unmarshal(data, &raw); err != nil {
		return module.Descriptor{}, err
	}

	if raw.APIVersion != expectedAPIVersion {
		return module.Descriptor{}, errors.New("invalid apiVersion: must be " + expectedAPIVersion)
	}

	if raw.Kind != "Module" {
		return module.Descriptor{}, errors.New("invalid kind: must be Module")
	}

	if raw.Metadata.Name == "" {
		return module.Descriptor{}, errors.New("metadata.name is required")
	}

	if raw.Metadata.Version == "" {
		return module.Descriptor{}, errors.New("metadata.version is required")
	}

	var spec rawModuleSpec
	if raw.Spec != nil {
		if err := json.Unmarshal(raw.Spec, &spec); err != nil {
			return module.Descriptor{}, err
		}
	}

	if spec.ModuleType == "" {
		return module.Descriptor{}, errors.New("spec.moduleType is required")
	}

	name, err := module.NewModuleName(raw.Metadata.Name)
	if err != nil {
		return module.Descriptor{}, err
	}

	version, err := module.NewModuleVersion(raw.Metadata.Version)
	if err != nil {
		return module.Descriptor{}, err
	}

	modType, err := module.NewModuleType(spec.ModuleType)
	if err != nil {
		return module.Descriptor{}, err
	}

	id, err := module.NewModuleID(raw.Metadata.Name + "@" + raw.Metadata.Version)
	if err != nil {
		return module.Descriptor{}, err
	}

	return module.New(id, name, version, modType)
}

// ValidateServiceDescriptor parses JSON bytes and returns a service.Descriptor.
// Returns error if JSON is malformed, required fields are missing, or values fail domain validation.
func ValidateServiceDescriptor(data []byte) (service.Descriptor, error) {
	var raw rawDescriptor
	if err := json.Unmarshal(data, &raw); err != nil {
		return service.Descriptor{}, err
	}

	if raw.APIVersion != expectedAPIVersion {
		return service.Descriptor{}, errors.New("invalid apiVersion: must be " + expectedAPIVersion)
	}

	if raw.Kind != "Service" {
		return service.Descriptor{}, errors.New("invalid kind: must be Service")
	}

	if raw.Metadata.Name == "" {
		return service.Descriptor{}, errors.New("metadata.name is required")
	}

	if raw.Metadata.Version == "" {
		return service.Descriptor{}, errors.New("metadata.version is required")
	}

	// We need to detect the presence of the "lifecycle" key even when it is an
	// empty object, so we unmarshal the spec into a raw map first.
	var specMap map[string]json.RawMessage
	if raw.Spec != nil {
		if err := json.Unmarshal(raw.Spec, &specMap); err != nil {
			return service.Descriptor{}, err
		}
	}

	serviceTypeRaw, hasServiceType := specMap["serviceType"]
	if !hasServiceType {
		return service.Descriptor{}, errors.New("spec.serviceType is required")
	}

	var serviceTypeStr string
	if err := json.Unmarshal(serviceTypeRaw, &serviceTypeStr); err != nil {
		return service.Descriptor{}, err
	}
	if serviceTypeStr == "" {
		return service.Descriptor{}, errors.New("spec.serviceType is required")
	}

	if _, hasLifecycle := specMap["lifecycle"]; !hasLifecycle {
		return service.Descriptor{}, errors.New("spec.lifecycle is required")
	}

	name, err := service.NewServiceName(raw.Metadata.Name)
	if err != nil {
		return service.Descriptor{}, err
	}

	version, err := service.NewServiceVersion(raw.Metadata.Version)
	if err != nil {
		return service.Descriptor{}, err
	}

	svcType, err := service.NewServiceType(serviceTypeStr)
	if err != nil {
		return service.Descriptor{}, err
	}

	id, err := service.NewServiceID(raw.Metadata.Name + "@" + raw.Metadata.Version)
	if err != nil {
		return service.Descriptor{}, err
	}

	return service.New(id, name, version, svcType)
}
