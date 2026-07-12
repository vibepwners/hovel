package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	BackendSchemaV1              = "hovel.pki.backend/v1"
	BackendBuiltinX509 BackendID = "builtin-x509"
)

type BackendDescriptorArgs struct {
	SchemaVersion       string
	ID                  BackendID
	Version             string
	PackageDigest       string
	KeyAlgorithms       []KeyAlgorithm
	SignatureAlgorithms []SignatureAlgorithm
	SupportsImport      bool
	SupportsExport      bool
	SupportsCRL         bool
	SupportsCSR         bool
	SupportsCustom      bool
}

type BackendDescriptor struct {
	SchemaVersion       string               `json:"schemaVersion"`
	ID                  BackendID            `json:"id"`
	Version             string               `json:"version"`
	PackageDigest       string               `json:"packageDigest,omitempty"`
	CapabilityHash      string               `json:"capabilityHash"`
	KeyAlgorithms       []KeyAlgorithm       `json:"keyAlgorithms"`
	SignatureAlgorithms []SignatureAlgorithm `json:"signatureAlgorithms"`
	SupportsImport      bool                 `json:"supportsImport"`
	SupportsExport      bool                 `json:"supportsExport"`
	SupportsCRL         bool                 `json:"supportsCrl"`
	SupportsCSR         bool                 `json:"supportsCsr"`
	SupportsCustom      bool                 `json:"supportsCustomExtensions"`
}

func (d BackendDescriptor) Clone() BackendDescriptor {
	result := d
	result.KeyAlgorithms = append([]KeyAlgorithm(nil), d.KeyAlgorithms...)
	result.SignatureAlgorithms = append([]SignatureAlgorithm(nil), d.SignatureAlgorithms...)
	return result
}

func NewBackendDescriptor(args BackendDescriptorArgs) (BackendDescriptor, error) {
	if err := validateSchemaVersion(args.SchemaVersion, BackendSchemaV1); err != nil {
		return BackendDescriptor{}, err
	}
	if err := args.ID.Validate(); err != nil {
		return BackendDescriptor{}, err
	}
	args.Version = strings.TrimSpace(args.Version)
	if args.Version == "" {
		return BackendDescriptor{}, errors.New("pki: crypto backend version is required")
	}
	if len(args.KeyAlgorithms) == 0 || len(args.SignatureAlgorithms) == 0 {
		return BackendDescriptor{}, errors.New("pki: crypto backend algorithms are required")
	}
	keys, err := uniqueKeyAlgorithms(args.KeyAlgorithms)
	if err != nil {
		return BackendDescriptor{}, err
	}
	signatures, err := uniqueSignatureAlgorithms(args.SignatureAlgorithms)
	if err != nil {
		return BackendDescriptor{}, err
	}
	descriptor := BackendDescriptor{
		SchemaVersion:       args.SchemaVersion,
		ID:                  args.ID,
		Version:             args.Version,
		PackageDigest:       strings.TrimSpace(args.PackageDigest),
		KeyAlgorithms:       keys,
		SignatureAlgorithms: signatures,
		SupportsImport:      args.SupportsImport,
		SupportsExport:      args.SupportsExport,
		SupportsCRL:         args.SupportsCRL,
		SupportsCSR:         args.SupportsCSR,
		SupportsCustom:      args.SupportsCustom,
	}
	capabilityHash, err := descriptor.computeCapabilityHash()
	if err != nil {
		return BackendDescriptor{}, err
	}
	descriptor.CapabilityHash = capabilityHash
	return descriptor, nil
}

func (d BackendDescriptor) Validate() error {
	rebuilt, err := NewBackendDescriptor(BackendDescriptorArgs{
		SchemaVersion: d.SchemaVersion, ID: d.ID, Version: d.Version, PackageDigest: d.PackageDigest,
		KeyAlgorithms: d.KeyAlgorithms, SignatureAlgorithms: d.SignatureAlgorithms,
		SupportsImport: d.SupportsImport, SupportsExport: d.SupportsExport, SupportsCRL: d.SupportsCRL,
		SupportsCSR: d.SupportsCSR, SupportsCustom: d.SupportsCustom,
	})
	if err != nil {
		return err
	}
	if d.CapabilityHash != rebuilt.CapabilityHash {
		return errors.New("pki: crypto backend capability hash does not match descriptor")
	}
	return nil
}

func (d BackendDescriptor) computeCapabilityHash() (string, error) {
	commitment := struct {
		SchemaVersion       string
		ID                  BackendID
		Version             string
		PackageDigest       string
		KeyAlgorithms       []KeyAlgorithm
		SignatureAlgorithms []SignatureAlgorithm
		SupportsImport      bool
		SupportsExport      bool
		SupportsCRL         bool
		SupportsCSR         bool
		SupportsCustom      bool
	}{
		SchemaVersion: d.SchemaVersion, ID: d.ID, Version: d.Version, PackageDigest: d.PackageDigest,
		KeyAlgorithms: d.KeyAlgorithms, SignatureAlgorithms: d.SignatureAlgorithms,
		SupportsImport: d.SupportsImport, SupportsExport: d.SupportsExport, SupportsCRL: d.SupportsCRL,
		SupportsCSR: d.SupportsCSR, SupportsCustom: d.SupportsCustom,
	}
	encoded, err := json.Marshal(commitment)
	if err != nil {
		return "", fmt.Errorf("pki: encode crypto backend capability commitment: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (d BackendDescriptor) SupportsKey(algorithm KeyAlgorithm) bool {
	for _, candidate := range d.KeyAlgorithms {
		if candidate == algorithm {
			return true
		}
	}
	return false
}

func (d BackendDescriptor) SupportsSignature(algorithm SignatureAlgorithm) bool {
	if algorithm == "" || algorithm == SignatureAlgorithmAuto {
		return true
	}
	for _, candidate := range d.SignatureAlgorithms {
		if candidate == algorithm {
			return true
		}
	}
	return false
}

func uniqueKeyAlgorithms(values []KeyAlgorithm) ([]KeyAlgorithm, error) {
	seen := map[KeyAlgorithm]struct{}{}
	result := make([]KeyAlgorithm, 0, len(values))
	for _, value := range values {
		switch value {
		case KeyAlgorithmECDSA, KeyAlgorithmRSA, KeyAlgorithmEd25519,
			KeyAlgorithmMLDSA44, KeyAlgorithmMLDSA65, KeyAlgorithmMLDSA87:
		default:
			return nil, fmt.Errorf("pki: unsupported key algorithm %q", value)
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("pki: duplicate key algorithm %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func uniqueSignatureAlgorithms(values []SignatureAlgorithm) ([]SignatureAlgorithm, error) {
	seen := map[SignatureAlgorithm]struct{}{}
	result := make([]SignatureAlgorithm, 0, len(values))
	for _, value := range values {
		if err := validateKnownSignatureAlgorithm(value); err != nil {
			return nil, err
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("pki: duplicate signature algorithm %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func validateKnownSignatureAlgorithm(value SignatureAlgorithm) error {
	switch value {
	case SignatureAlgorithmECDSASHA256, SignatureAlgorithmECDSASHA384,
		SignatureAlgorithmECDSASHA512, SignatureAlgorithmSHA256WithRSA,
		SignatureAlgorithmSHA384WithRSA, SignatureAlgorithmSHA512WithRSA,
		SignatureAlgorithmSHA256WithRSAPSS, SignatureAlgorithmSHA384WithRSAPSS,
		SignatureAlgorithmSHA512WithRSAPSS, SignatureAlgorithmEd25519:
		return nil
	case SignatureAlgorithmMLDSA44, SignatureAlgorithmMLDSA65, SignatureAlgorithmMLDSA87:
		return nil
	default:
		return fmt.Errorf("pki: unsupported signature algorithm %q", value)
	}
}
