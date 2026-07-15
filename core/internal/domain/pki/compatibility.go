package pki

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	CompatibilityPortableX509    CompatibilityTargetID = "portable-x509"
	CompatibilityGo126PQHybrid   CompatibilityTargetID = "go-1.26-pq-hybrid"
	CompatibilityTargetSchemaV1                        = "hovel.pki.compatibility-target/v1"
	CompatibilityPortableVersion                       = "1"
	CompatibilityGo126Version                          = "1.26.5"
)

type CompatibilityTargetArgs struct {
	SchemaVersion            string
	ID                       CompatibilityTargetID
	Version                  string
	KeyAlgorithms            []KeyAlgorithm
	SignatureAlgorithms      []SignatureAlgorithm
	TLSNamedGroups           []TLSNamedGroup
	SupportsCustomExtensions bool
}

type CompatibilityTarget struct {
	SchemaVersion            string                `json:"schemaVersion"`
	ID                       CompatibilityTargetID `json:"id"`
	Version                  string                `json:"version"`
	KeyAlgorithms            []KeyAlgorithm        `json:"keyAlgorithms"`
	SignatureAlgorithms      []SignatureAlgorithm  `json:"signatureAlgorithms"`
	TLSNamedGroups           []TLSNamedGroup       `json:"tlsNamedGroups,omitempty"`
	SupportsCustomExtensions bool                  `json:"supportsCustomExtensions"`
}

func NewCompatibilityTarget(args CompatibilityTargetArgs) (CompatibilityTarget, error) {
	if err := validateSchemaVersion(args.SchemaVersion, CompatibilityTargetSchemaV1); err != nil {
		return CompatibilityTarget{}, err
	}
	if err := args.ID.Validate(); err != nil {
		return CompatibilityTarget{}, err
	}
	version := strings.TrimSpace(args.Version)
	if version == "" {
		return CompatibilityTarget{}, errors.New("pki: compatibility target version is required")
	}
	keys, err := uniqueKeyAlgorithms(args.KeyAlgorithms)
	if err != nil {
		return CompatibilityTarget{}, err
	}
	signatures, err := uniqueSignatureAlgorithms(args.SignatureAlgorithms)
	if err != nil {
		return CompatibilityTarget{}, err
	}
	groups := append([]TLSNamedGroup(nil), args.TLSNamedGroups...)
	seenGroups := make(map[TLSNamedGroup]struct{}, len(groups))
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return CompatibilityTarget{}, err
		}
		if _, ok := seenGroups[group]; ok {
			return CompatibilityTarget{}, fmt.Errorf("pki: duplicate tls named group %q", group)
		}
		seenGroups[group] = struct{}{}
	}
	return CompatibilityTarget{
		SchemaVersion:            args.SchemaVersion,
		ID:                       args.ID,
		Version:                  version,
		KeyAlgorithms:            keys,
		SignatureAlgorithms:      signatures,
		TLSNamedGroups:           groups,
		SupportsCustomExtensions: args.SupportsCustomExtensions,
	}, nil
}

func (t CompatibilityTarget) Clone() CompatibilityTarget {
	result := t
	result.KeyAlgorithms = append([]KeyAlgorithm(nil), t.KeyAlgorithms...)
	result.SignatureAlgorithms = append([]SignatureAlgorithm(nil), t.SignatureAlgorithms...)
	result.TLSNamedGroups = append([]TLSNamedGroup(nil), t.TLSNamedGroups...)
	return result
}

func (t CompatibilityTarget) SupportsKey(algorithm KeyAlgorithm) bool {
	return slices.Contains(t.KeyAlgorithms, algorithm)
}

func (t CompatibilityTarget) SupportsSignature(algorithm SignatureAlgorithm) bool {
	return algorithm == "" || algorithm == SignatureAlgorithmAuto || slices.Contains(t.SignatureAlgorithms, algorithm)
}

func (t CompatibilityTarget) SupportsHybridPostQuantumTLS() bool {
	for _, group := range t.TLSNamedGroups {
		if group.IsHybridPostQuantum() {
			return true
		}
	}
	return false
}

func ValidateKeyEstablishment(policy KeyEstablishmentPolicy, groups []TLSNamedGroup) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	seen := make(map[TLSNamedGroup]struct{}, len(groups))
	hybridCount := 0
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return err
		}
		if _, ok := seen[group]; ok {
			return fmt.Errorf("pki: duplicate resolved tls named group %q", group)
		}
		seen[group] = struct{}{}
		if group.IsHybridPostQuantum() {
			hybridCount++
		}
	}
	switch policy {
	case KeyEstablishmentNotApplicable:
		if len(groups) != 0 {
			return errors.New("pki: not-applicable key establishment cannot include tls named groups")
		}
	case KeyEstablishmentClassicalCompatible:
		if len(groups) == 0 || hybridCount != 0 {
			return errors.New("pki: classical-compatible key establishment requires only classical tls named groups")
		}
	case KeyEstablishmentHybridPQPreferred:
		if hybridCount == 0 || hybridCount == len(groups) {
			return errors.New("pki: hybrid-pq-preferred key establishment requires hybrid and classical tls named groups")
		}
	case KeyEstablishmentHybridPQRequired:
		if len(groups) == 0 || hybridCount != len(groups) {
			return errors.New("pki: hybrid-pq-required key establishment permits only hybrid tls named groups")
		}
	}
	return nil
}

func ResolveTLSNamedGroups(target CompatibilityTarget, policy KeyEstablishmentPolicy) ([]TLSNamedGroup, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	groups := make([]TLSNamedGroup, 0, len(target.TLSNamedGroups))
	for _, group := range target.TLSNamedGroups {
		switch policy {
		case KeyEstablishmentNotApplicable:
			continue
		case KeyEstablishmentClassicalCompatible:
			if group.IsHybridPostQuantum() {
				continue
			}
		case KeyEstablishmentHybridPQRequired:
			if !group.IsHybridPostQuantum() {
				continue
			}
		}
		groups = append(groups, group)
	}
	if err := ValidateKeyEstablishment(policy, groups); err != nil {
		return nil, fmt.Errorf("pki: resolve compatibility target %q: %w", target.ID, err)
	}
	return groups, nil
}

func BuiltInCompatibilityTargets() []CompatibilityTarget {
	classicalKeys := []KeyAlgorithm{KeyAlgorithmECDSA, KeyAlgorithmRSA, KeyAlgorithmEd25519}
	classicalSignatures := []SignatureAlgorithm{
		SignatureAlgorithmECDSASHA256,
		SignatureAlgorithmECDSASHA384,
		SignatureAlgorithmECDSASHA512,
		SignatureAlgorithmSHA256WithRSA,
		SignatureAlgorithmSHA384WithRSA,
		SignatureAlgorithmSHA512WithRSA,
		SignatureAlgorithmSHA256WithRSAPSS,
		SignatureAlgorithmSHA384WithRSAPSS,
		SignatureAlgorithmSHA512WithRSAPSS,
		SignatureAlgorithmEd25519,
	}
	portable, err := NewCompatibilityTarget(CompatibilityTargetArgs{
		SchemaVersion:            CompatibilityTargetSchemaV1,
		ID:                       CompatibilityPortableX509,
		Version:                  CompatibilityPortableVersion,
		KeyAlgorithms:            classicalKeys,
		SignatureAlgorithms:      classicalSignatures,
		TLSNamedGroups:           []TLSNamedGroup{TLSNamedGroupX25519, TLSNamedGroupP256, TLSNamedGroupP384, TLSNamedGroupP521},
		SupportsCustomExtensions: true,
	})
	if err != nil {
		panic(err)
	}
	go126, err := NewCompatibilityTarget(CompatibilityTargetArgs{
		SchemaVersion:       CompatibilityTargetSchemaV1,
		ID:                  CompatibilityGo126PQHybrid,
		Version:             CompatibilityGo126Version,
		KeyAlgorithms:       classicalKeys,
		SignatureAlgorithms: classicalSignatures,
		TLSNamedGroups: []TLSNamedGroup{
			TLSNamedGroupX25519MLKEM768,
			TLSNamedGroupP256MLKEM768,
			TLSNamedGroupP384MLKEM1024,
			TLSNamedGroupX25519,
			TLSNamedGroupP256,
			TLSNamedGroupP384,
		},
		SupportsCustomExtensions: true,
	})
	if err != nil {
		panic(err)
	}
	return []CompatibilityTarget{portable, go126}
}

func BuiltInCompatibilityTarget(id CompatibilityTargetID) (CompatibilityTarget, bool) {
	for _, target := range BuiltInCompatibilityTargets() {
		if target.ID == id {
			return target.Clone(), true
		}
	}
	return CompatibilityTarget{}, false
}
