package hovel

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CredentialDeliverySchemaV1 is the versioned provider credential-delivery
// descriptor understood by Hovel.
const CredentialDeliverySchemaV1 = "hovel.pki.credential-delivery/v1"

const (
	maximumCredentialBinaryBytes            = 24 << 20
	maximumCredentialExecutionFiles         = 64
	maximumCredentialReferenceCapabilities  = 64
	maximumCredentialStampDigests           = 128
	maximumCredentialStampPreconditionBytes = 1 << 20
	maximumCredentialReceiptBytes           = maximumCredentialStampPreconditionBytes
	maximumCredentialProviderTargetBytes    = 1 << 20
	maximumCredentialIDBytes                = 256
	maximumCredentialNameBytes              = 512
	maximumCredentialPathBytes              = 4096
	maximumCredentialEncodingBytes          = 256
	maximumCredentialReferenceList          = 32
)

type CredentialDeliveryCapability string

const (
	CredentialDeliveryNone          CredentialDeliveryCapability = "none"
	CredentialDeliveryRuntime       CredentialDeliveryCapability = "runtime"
	CredentialDeliveryFiles         CredentialDeliveryCapability = "files"
	CredentialDeliveryStampStandard CredentialDeliveryCapability = "stamp-standard"
	CredentialDeliveryStampAdvanced CredentialDeliveryCapability = "stamp-advanced"
)

type CredentialPurpose string

const (
	CredentialPurposeTLSServer    CredentialPurpose = "tls-server"
	CredentialPurposeTLSClient    CredentialPurpose = "tls-client"
	CredentialPurposeMTLSServer   CredentialPurpose = "mtls-server"
	CredentialPurposeMTLSClient   CredentialPurpose = "mtls-client"
	CredentialPurposeDualRoleMTLS CredentialPurpose = "dual-role-mtls"
	CredentialPurposeCodeSigning  CredentialPurpose = "code-signing"
	CredentialPurposeCustom       CredentialPurpose = "custom"
)

type CredentialEndpointRole string

const (
	CredentialEndpointServer        CredentialEndpointRole = "server"
	CredentialEndpointClient        CredentialEndpointRole = "client"
	CredentialEndpointDual          CredentialEndpointRole = "dual"
	CredentialEndpointNotApplicable CredentialEndpointRole = "not-applicable"
)

type CredentialConsumerType string

const (
	CredentialConsumerMeshProvider  CredentialConsumerType = "mesh-provider"
	CredentialConsumerMeshListener  CredentialConsumerType = "mesh-listener"
	CredentialConsumerListeningPost CredentialConsumerType = "listening-post"
	CredentialConsumerMeshNode      CredentialConsumerType = "mesh-node"
	CredentialConsumerImplant       CredentialConsumerType = "implant"
	CredentialConsumerStager        CredentialConsumerType = "stager"
	CredentialConsumerPayload       CredentialConsumerType = "payload"
	CredentialConsumerC2Service     CredentialConsumerType = "c2-service"
	CredentialConsumerService       CredentialConsumerType = "service"
	CredentialConsumerExternal      CredentialConsumerType = "external"
)

type CredentialProjection string

const (
	CredentialProjectionBundle           CredentialProjection = "bundle"
	CredentialProjectionCertificateDER   CredentialProjection = "certificate-der"
	CredentialProjectionPrivateKeyPKCS8  CredentialProjection = "private-key-pkcs8"
	CredentialProjectionPublicKeySPKI    CredentialProjection = "public-key-spki"
	CredentialProjectionSignerReference  CredentialProjection = "signer-reference"
	CredentialProjectionChainDER         CredentialProjection = "chain-der"
	CredentialProjectionTrustDER         CredentialProjection = "trust-der"
	CredentialProjectionCRLDER           CredentialProjection = "crl-der"
	CredentialProjectionProviderEncoding CredentialProjection = "provider-encoding"
	CredentialProjectionLiteralReference CredentialProjection = "literal-reference"
)

type CredentialMaterialForm string

const (
	CredentialMaterialPublic           CredentialMaterialForm = "public"
	CredentialMaterialPrivateReference CredentialMaterialForm = "private-reference"
	CredentialMaterialPrivateBytes     CredentialMaterialForm = "private-bytes"
)

type CredentialPrivateMaterialPolicy string

const (
	CredentialPrivateMaterialForbidden CredentialPrivateMaterialPolicy = "forbidden"
	CredentialPrivateMaterialAllowed   CredentialPrivateMaterialPolicy = "allowed"
	CredentialPrivateMaterialRequired  CredentialPrivateMaterialPolicy = "required"
)

type CredentialStampRemainderPolicy string

const (
	CredentialStampRemainderPreserve     CredentialStampRemainderPolicy = "preserve"
	CredentialStampRemainderZeroFill     CredentialStampRemainderPolicy = "zero-fill"
	CredentialStampRemainderRequireExact CredentialStampRemainderPolicy = "require-exact"
)

type CredentialStampTargetKind string

const (
	CredentialStampTargetNamedSlot       CredentialStampTargetKind = "named-slot"
	CredentialStampTargetFileOffset      CredentialStampTargetKind = "file-offset"
	CredentialStampTargetVirtualAddress  CredentialStampTargetKind = "virtual-address"
	CredentialStampTargetSymbol          CredentialStampTargetKind = "symbol"
	CredentialStampTargetMarker          CredentialStampTargetKind = "marker"
	CredentialStampTargetBytePattern     CredentialStampTargetKind = "byte-pattern"
	CredentialStampTargetProviderDefined CredentialStampTargetKind = "provider-defined"
)

type CredentialStampAddressSpace string

const (
	CredentialStampAddressFile       CredentialStampAddressSpace = "file"
	CredentialStampAddressELFVirtual CredentialStampAddressSpace = "elf-virtual-address"
	CredentialStampAddressPERVA      CredentialStampAddressSpace = "pe-rva"
	CredentialStampAddressMachOVM    CredentialStampAddressSpace = "macho-vm-address"
)

// CredentialCanonicalUint64 carries an unsigned offset or address as a
// canonical base-10 string. String encoding preserves the complete uint64
// range through JSON clients that use IEEE-754 numbers.
type CredentialCanonicalUint64 string

type CredentialStampPreconditionKind string

const (
	CredentialStampPreconditionNone   CredentialStampPreconditionKind = "none"
	CredentialStampPreconditionBytes  CredentialStampPreconditionKind = "bytes"
	CredentialStampPreconditionSHA256 CredentialStampPreconditionKind = "sha256"
)

// CredentialStampPrecondition prevents a provider from writing to an
// unexpected artifact location. Exactly one variant is active for Kind.
type CredentialStampPrecondition struct {
	Kind   CredentialStampPreconditionKind `json:"kind"`
	Bytes  []byte                          `json:"bytes,omitempty"`
	SHA256 string                          `json:"sha256,omitempty"`
	Length CredentialCanonicalUint64       `json:"length,omitempty"`
}

type CredentialNamedSlotTarget struct {
	Name string `json:"name"`
}

type CredentialFileOffsetTarget struct {
	Offset          CredentialCanonicalUint64      `json:"offset"`
	MaximumLength   CredentialCanonicalUint64      `json:"maximumLength"`
	Alignment       CredentialCanonicalUint64      `json:"alignment"`
	RemainderPolicy CredentialStampRemainderPolicy `json:"remainderPolicy"`
	Precondition    CredentialStampPrecondition    `json:"precondition"`
}

type CredentialVirtualAddressTarget struct {
	Address         CredentialCanonicalUint64      `json:"address"`
	AddressSpace    CredentialStampAddressSpace    `json:"addressSpace"`
	ImageBase       CredentialCanonicalUint64      `json:"imageBase,omitempty"`
	MaximumLength   CredentialCanonicalUint64      `json:"maximumLength"`
	Alignment       CredentialCanonicalUint64      `json:"alignment"`
	RemainderPolicy CredentialStampRemainderPolicy `json:"remainderPolicy"`
	Precondition    CredentialStampPrecondition    `json:"precondition"`
}

type CredentialSymbolTarget struct {
	Name            string                         `json:"name"`
	Section         string                         `json:"section,omitempty"`
	MaximumLength   CredentialCanonicalUint64      `json:"maximumLength"`
	RemainderPolicy CredentialStampRemainderPolicy `json:"remainderPolicy"`
	Precondition    CredentialStampPrecondition    `json:"precondition"`
}

type CredentialMarkerTarget struct {
	Marker          []byte                         `json:"marker"`
	Occurrence      uint32                         `json:"occurrence"`
	MaximumLength   CredentialCanonicalUint64      `json:"maximumLength"`
	RemainderPolicy CredentialStampRemainderPolicy `json:"remainderPolicy"`
	Precondition    CredentialStampPrecondition    `json:"precondition"`
}

type CredentialBytePatternTarget struct {
	Pattern         []byte                         `json:"pattern"`
	Mask            []byte                         `json:"mask"`
	Occurrence      uint32                         `json:"occurrence"`
	MaximumLength   CredentialCanonicalUint64      `json:"maximumLength"`
	RemainderPolicy CredentialStampRemainderPolicy `json:"remainderPolicy"`
	Precondition    CredentialStampPrecondition    `json:"precondition"`
}

type CredentialProviderDefinedTarget struct {
	ProviderID    string         `json:"providerId"`
	SchemaVersion string         `json:"schemaVersion"`
	Value         map[string]any `json:"value"`
}

// CredentialStampTarget is a tagged union. Set Kind and exactly one matching
// variant. Hovel rejects inactive or contradictory variants before invoking a
// provider.
type CredentialStampTarget struct {
	Kind            CredentialStampTargetKind        `json:"kind"`
	NamedSlot       *CredentialNamedSlotTarget       `json:"namedSlot,omitempty"`
	FileOffset      *CredentialFileOffsetTarget      `json:"fileOffset,omitempty"`
	VirtualAddress  *CredentialVirtualAddressTarget  `json:"virtualAddress,omitempty"`
	Symbol          *CredentialSymbolTarget          `json:"symbol,omitempty"`
	Marker          *CredentialMarkerTarget          `json:"marker,omitempty"`
	BytePattern     *CredentialBytePatternTarget     `json:"bytePattern,omitempty"`
	ProviderDefined *CredentialProviderDefinedTarget `json:"providerDefined,omitempty"`
}

// CredentialMaterialReference identifies immutable PKI material without
// carrying its secret bytes in a persisted plan.
type CredentialMaterialReference struct {
	Projection           CredentialProjection   `json:"projection"`
	Form                 CredentialMaterialForm `json:"form"`
	BundleID             string                 `json:"bundleId,omitempty"`
	GenerationID         string                 `json:"generationId,omitempty"`
	GenerationIDs        []string               `json:"generationIds,omitempty"`
	TrustSetGenerationID string                 `json:"trustSetGenerationId,omitempty"`
	CRLGenerationIDs     []string               `json:"crlGenerationIds,omitempty"`
}

type CredentialProviderEncodingMaterial struct {
	ProviderID    string                      `json:"providerId"`
	SchemaVersion string                      `json:"schemaVersion"`
	Form          CredentialMaterialForm      `json:"form"`
	Source        CredentialMaterialReference `json:"source"`
}

type CredentialLiteralMaterialReference struct {
	Reference string                 `json:"reference"`
	SHA256    string                 `json:"sha256"`
	Form      CredentialMaterialForm `json:"form"`
}

// CredentialStampMaterial is a tagged reference union. It intentionally does
// not contain resolved private bytes; those belong only in an authorized,
// short-lived provider invocation contract.
type CredentialStampMaterial struct {
	Projection       CredentialProjection                `json:"projection"`
	Credential       *CredentialMaterialReference        `json:"credential,omitempty"`
	ProviderEncoding *CredentialProviderEncodingMaterial `json:"providerEncoding,omitempty"`
	LiteralReference *CredentialLiteralMaterialReference `json:"literalReference,omitempty"`
}

type ResolvedCredentialMetadata struct {
	BundleVersion         string                 `json:"bundleVersion"`
	Purpose               CredentialPurpose      `json:"purpose"`
	ConsumerType          CredentialConsumerType `json:"consumerType"`
	ProfileID             string                 `json:"profileId"`
	CompatibilityTargetID string                 `json:"compatibilityTargetId"`
}

// CredentialStampRequest is the provider-independent, descriptor-validated
// stamping contract. Standard providers use a named slot; advanced providers
// may use any target kind they advertise.
type CredentialStampRequest struct {
	AssignmentID string                       `json:"assignmentId"`
	Capability   CredentialDeliveryCapability `json:"capability"`
	SlotName     string                       `json:"slotName"`
	Target       CredentialStampTarget        `json:"target"`
	Material     CredentialStampMaterial      `json:"material"`
	EncodedBytes uint64                       `json:"encodedBytes"`
	Credential   ResolvedCredentialMetadata   `json:"credential"`
}

// CredentialSlot describes one strict provider-defined credential consumer.
// Providers advertise only slots they actually consume.
type CredentialSlot struct {
	Name                         string                          `json:"name"`
	Purpose                      CredentialPurpose               `json:"purpose"`
	EndpointRole                 CredentialEndpointRole          `json:"endpointRole"`
	ConsumerType                 CredentialConsumerType          `json:"consumerType"`
	AcceptedBundleVersions       []string                        `json:"acceptedBundleVersions"`
	AcceptedProfiles             []string                        `json:"acceptedProfiles"`
	AcceptedCompatibilityTargets []string                        `json:"acceptedCompatibilityTargets"`
	AcceptedProjections          []CredentialProjection          `json:"acceptedProjections"`
	AcceptedMaterialForms        []CredentialMaterialForm        `json:"acceptedMaterialForms"`
	MaximumEncodedBytes          uint64                          `json:"maximumEncodedBytes"`
	RemainderPolicy              CredentialStampRemainderPolicy  `json:"remainderPolicy"`
	PrivateMaterial              CredentialPrivateMaterialPolicy `json:"privateMaterial"`
}

type CredentialProviderTargetSchema struct {
	ProviderID    string         `json:"providerId"`
	SchemaVersion string         `json:"schemaVersion"`
	JSONSchema    map[string]any `json:"jsonSchema"`
}

type CredentialProviderEncodingSchema struct {
	ProviderID                string                   `json:"providerId"`
	SchemaVersion             string                   `json:"schemaVersion"`
	AcceptedSourceProjections []CredentialProjection   `json:"acceptedSourceProjections"`
	AcceptedSourceForms       []CredentialMaterialForm `json:"acceptedSourceForms"`
	OutputForms               []CredentialMaterialForm `json:"outputForms"`
}

// CredentialDeliveryDescriptor advertises optional credential resolution and
// stamping capabilities. A provider is not required to implement every mode.
type CredentialDeliveryDescriptor struct {
	SchemaVersion           string                             `json:"schemaVersion"`
	Slots                   []CredentialSlot                   `json:"credentialSlots,omitempty"`
	Capabilities            []CredentialDeliveryCapability     `json:"deliveryCapabilities"`
	StampTargetKinds        []CredentialStampTargetKind        `json:"stampTargetKinds,omitempty"`
	AddressSpaces           []CredentialStampAddressSpace      `json:"addressSpaces,omitempty"`
	ProviderTargetSchemas   []CredentialProviderTargetSchema   `json:"providerTargetSchemas,omitempty"`
	ProviderEncodingSchemas []CredentialProviderEncodingSchema `json:"providerEncodingSchemas,omitempty"`
}

func (c CredentialDeliveryCapability) Validate() error {
	switch c {
	case CredentialDeliveryNone, CredentialDeliveryRuntime, CredentialDeliveryFiles,
		CredentialDeliveryStampStandard, CredentialDeliveryStampAdvanced:
		return nil
	default:
		return fmt.Errorf("unsupported credential delivery capability %q", c)
	}
}

func (p CredentialPurpose) Validate() error {
	switch p {
	case CredentialPurposeTLSServer, CredentialPurposeTLSClient,
		CredentialPurposeMTLSServer, CredentialPurposeMTLSClient,
		CredentialPurposeDualRoleMTLS, CredentialPurposeCodeSigning,
		CredentialPurposeCustom:
		return nil
	default:
		return fmt.Errorf("unsupported credential purpose %q", p)
	}
}

func (c CredentialConsumerType) Validate() error {
	switch c {
	case CredentialConsumerMeshProvider, CredentialConsumerMeshListener,
		CredentialConsumerListeningPost, CredentialConsumerMeshNode,
		CredentialConsumerImplant, CredentialConsumerStager,
		CredentialConsumerPayload, CredentialConsumerC2Service,
		CredentialConsumerService, CredentialConsumerExternal:
		return nil
	default:
		return fmt.Errorf("unsupported credential consumer type %q", c)
	}
}

func (p CredentialProjection) Validate() error {
	switch p {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionSignerReference, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER,
		CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return nil
	default:
		return fmt.Errorf("unsupported credential projection %q", p)
	}
}

func (f CredentialMaterialForm) Validate() error {
	switch f {
	case CredentialMaterialPublic, CredentialMaterialPrivateReference,
		CredentialMaterialPrivateBytes:
		return nil
	default:
		return fmt.Errorf("unsupported credential material form %q", f)
	}
}

func (p CredentialStampRemainderPolicy) Validate() error {
	switch p {
	case CredentialStampRemainderPreserve, CredentialStampRemainderZeroFill,
		CredentialStampRemainderRequireExact:
		return nil
	default:
		return fmt.Errorf("unsupported credential stamp remainder policy %q", p)
	}
}

func (v CredentialCanonicalUint64) Uint64() (uint64, error) {
	value := string(v)
	if value == "" || value != strings.TrimSpace(value) {
		return 0, fmt.Errorf("%q is not a canonical uint64", value)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%q is not a canonical uint64", value)
	}
	return parsed, nil
}

type credentialStampPreconditionWire CredentialStampPrecondition

func (p CredentialStampPrecondition) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(credentialStampPreconditionWire(p))
}

func (p *CredentialStampPrecondition) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("credential stamp precondition destination is nil")
	}
	var wire credentialStampPreconditionWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode credential stamp precondition: %w", err)
	}
	allowed := ""
	switch wire.Kind {
	case CredentialStampPreconditionNone:
	case CredentialStampPreconditionBytes:
		allowed = "bytes"
	case CredentialStampPreconditionSHA256:
		allowed = "sha256,length"
	default:
		return fmt.Errorf("unsupported credential stamp precondition kind %q", wire.Kind)
	}
	if err := rejectInactiveCredentialJSONFields(
		data,
		allowed,
		[]string{"bytes", "sha256", "length"},
		"credential stamp precondition",
	); err != nil {
		return err
	}
	result := CredentialStampPrecondition(wire)
	if err := result.Validate(); err != nil {
		return err
	}
	result.Bytes = append([]byte(nil), result.Bytes...)
	*p = result
	return nil
}

func (p CredentialStampPrecondition) Validate() error {
	switch p.Kind {
	case CredentialStampPreconditionNone:
		if len(p.Bytes) != 0 || p.SHA256 != "" || p.Length != "" {
			return errors.New("empty credential stamp precondition contains comparison material")
		}
	case CredentialStampPreconditionBytes:
		if len(p.Bytes) == 0 || len(p.Bytes) > maximumCredentialStampPreconditionBytes ||
			p.SHA256 != "" || p.Length != "" {
			return errors.New("credential byte stamp precondition is invalid")
		}
	case CredentialStampPreconditionSHA256:
		if len(p.Bytes) != 0 {
			return errors.New("credential hash stamp precondition contains literal bytes")
		}
		length, err := p.Length.Uint64()
		if err != nil || length == 0 || length > maximumCredentialBinaryBytes {
			return errors.New("credential stamp precondition hash length is invalid")
		}
		if err := validateCredentialSHA256(p.SHA256, "credential stamp precondition"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported credential stamp precondition kind %q", p.Kind)
	}
	return nil
}

type credentialStampTargetWire CredentialStampTarget

func (t CredentialStampTarget) MarshalJSON() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(credentialStampTargetWire(t))
}

func (t *CredentialStampTarget) UnmarshalJSON(data []byte) error {
	if t == nil {
		return errors.New("credential stamp target destination is nil")
	}
	var wire credentialStampTargetWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode credential stamp target: %w", err)
	}
	active, err := credentialStampTargetJSONField(wire.Kind)
	if err != nil {
		return err
	}
	if err := rejectInactiveCredentialJSONFields(
		data,
		active,
		[]string{
			"namedSlot", "fileOffset", "virtualAddress", "symbol",
			"marker", "bytePattern", "providerDefined",
		},
		"credential stamp target",
	); err != nil {
		return err
	}
	result := CredentialStampTarget(wire)
	if err := result.Validate(); err != nil {
		return err
	}
	*t = result
	return nil
}

func (t CredentialStampTarget) Validate() error {
	if _, err := credentialStampTargetJSONField(t.Kind); err != nil {
		return err
	}
	if credentialStampTargetVariantCount(t) != 1 {
		return errors.New("credential stamp target must contain exactly one tagged variant")
	}
	switch t.Kind {
	case CredentialStampTargetNamedSlot:
		if t.NamedSlot == nil {
			return errors.New("credential named-slot stamp target is missing")
		}
		return validateCredentialCanonicalText(
			t.NamedSlot.Name,
			"credential stamp slot name",
			maximumCredentialIDBytes,
		)
	case CredentialStampTargetFileOffset:
		if t.FileOffset == nil {
			return errors.New("credential file-offset stamp target is missing")
		}
		return validateCredentialPositionTarget(
			t.FileOffset.Offset,
			"",
			t.FileOffset.MaximumLength,
			t.FileOffset.Alignment,
			t.FileOffset.RemainderPolicy,
			t.FileOffset.Precondition,
			CredentialStampAddressFile,
		)
	case CredentialStampTargetVirtualAddress:
		if t.VirtualAddress == nil {
			return errors.New("credential virtual-address stamp target is missing")
		}
		if err := validateCredentialStampAddressSpace(t.VirtualAddress.AddressSpace); err != nil {
			return err
		}
		if t.VirtualAddress.AddressSpace == CredentialStampAddressFile {
			return errors.New("credential virtual-address target cannot use file address space")
		}
		return validateCredentialPositionTarget(
			t.VirtualAddress.Address,
			t.VirtualAddress.ImageBase,
			t.VirtualAddress.MaximumLength,
			t.VirtualAddress.Alignment,
			t.VirtualAddress.RemainderPolicy,
			t.VirtualAddress.Precondition,
			t.VirtualAddress.AddressSpace,
		)
	case CredentialStampTargetSymbol:
		if t.Symbol == nil {
			return errors.New("credential symbol stamp target is missing")
		}
		if err := validateCredentialCanonicalText(
			t.Symbol.Name,
			"credential stamp symbol name",
			maximumCredentialNameBytes,
		); err != nil {
			return err
		}
		if t.Symbol.Section != "" {
			if err := validateCredentialCanonicalText(
				t.Symbol.Section,
				"credential stamp symbol section",
				maximumCredentialNameBytes,
			); err != nil {
				return err
			}
		}
		_, err := validateCredentialBoundedTarget(
			t.Symbol.MaximumLength,
			t.Symbol.RemainderPolicy,
			t.Symbol.Precondition,
		)
		return err
	case CredentialStampTargetMarker:
		if t.Marker == nil || len(t.Marker.Marker) == 0 ||
			len(t.Marker.Marker) > maximumCredentialStampPreconditionBytes {
			return errors.New("credential marker stamp target is invalid")
		}
		_, err := validateCredentialBoundedTarget(
			t.Marker.MaximumLength,
			t.Marker.RemainderPolicy,
			t.Marker.Precondition,
		)
		return err
	case CredentialStampTargetBytePattern:
		if t.BytePattern == nil || len(t.BytePattern.Pattern) == 0 ||
			len(t.BytePattern.Pattern) != len(t.BytePattern.Mask) ||
			len(t.BytePattern.Pattern) > maximumCredentialStampPreconditionBytes ||
			credentialBytesAllZero(t.BytePattern.Mask) {
			return errors.New("credential byte-pattern stamp target is invalid")
		}
		_, err := validateCredentialBoundedTarget(
			t.BytePattern.MaximumLength,
			t.BytePattern.RemainderPolicy,
			t.BytePattern.Precondition,
		)
		return err
	case CredentialStampTargetProviderDefined:
		if t.ProviderDefined == nil {
			return errors.New("credential provider-defined stamp target is missing")
		}
		if err := validateCredentialCanonicalText(
			t.ProviderDefined.ProviderID,
			"credential provider-defined target provider id",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := validateCredentialCanonicalText(
			t.ProviderDefined.SchemaVersion,
			"credential provider-defined target schema version",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if t.ProviderDefined.Value == nil {
			return errors.New("credential provider-defined target value is required")
		}
		encoded, err := json.Marshal(t.ProviderDefined.Value)
		if err != nil || len(encoded) > maximumCredentialProviderTargetBytes {
			return errors.New("credential provider-defined target value is invalid")
		}
	}
	return nil
}

type credentialMaterialReferenceWire CredentialMaterialReference

func (r CredentialMaterialReference) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(credentialMaterialReferenceWire(r))
}

func (r *CredentialMaterialReference) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("credential material reference destination is nil")
	}
	var wire credentialMaterialReferenceWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode credential material reference: %w", err)
	}
	active, err := credentialMaterialReferenceJSONField(wire.Projection)
	if err != nil {
		return err
	}
	if err := rejectInactiveCredentialJSONFields(
		data,
		active,
		[]string{
			"bundleId", "generationId", "generationIds",
			"trustSetGenerationId", "crlGenerationIds",
		},
		"credential material reference",
	); err != nil {
		return err
	}
	result := CredentialMaterialReference(wire)
	if err := result.Validate(); err != nil {
		return err
	}
	result.GenerationIDs = append([]string(nil), result.GenerationIDs...)
	result.CRLGenerationIDs = append([]string(nil), result.CRLGenerationIDs...)
	*r = result
	return nil
}

func (r CredentialMaterialReference) Validate() error {
	if err := r.Projection.Validate(); err != nil {
		return err
	}
	if credentialMaterialReferenceVariantCount(r) != 1 {
		return errors.New("credential material must contain exactly one tagged reference")
	}
	if err := r.Form.Validate(); err != nil {
		return err
	}
	switch r.Projection {
	case CredentialProjectionBundle:
		return validateCredentialCanonicalText(
			r.BundleID,
			"credential bundle id",
			maximumCredentialIDBytes,
		)
	case CredentialProjectionCertificateDER, CredentialProjectionPublicKeySPKI:
		if r.Form != CredentialMaterialPublic {
			return errors.New("public credential projection requires public material")
		}
		return validateCredentialCanonicalText(
			r.GenerationID,
			"credential generation id",
			maximumCredentialIDBytes,
		)
	case CredentialProjectionPrivateKeyPKCS8:
		if r.Form != CredentialMaterialPrivateBytes {
			return errors.New("private-key projection requires private bytes")
		}
		return validateCredentialCanonicalText(
			r.GenerationID,
			"credential generation id",
			maximumCredentialIDBytes,
		)
	case CredentialProjectionSignerReference:
		if r.Form != CredentialMaterialPrivateReference {
			return errors.New("signer projection requires a private reference")
		}
		return validateCredentialCanonicalText(
			r.GenerationID,
			"credential generation id",
			maximumCredentialIDBytes,
		)
	case CredentialProjectionChainDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("credential chain requires public material")
		}
		return validateCredentialReferenceList(r.GenerationIDs, "credential chain generation ids")
	case CredentialProjectionTrustDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("credential trust material requires public material")
		}
		return validateCredentialCanonicalText(
			r.TrustSetGenerationID,
			"credential trust-set generation id",
			maximumCredentialIDBytes,
		)
	case CredentialProjectionCRLDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("credential CRL material requires public material")
		}
		return validateCredentialReferenceList(r.CRLGenerationIDs, "credential CRL generation ids")
	case CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return errors.New("credential material reference cannot contain provider or literal material")
	}
	return nil
}

type credentialStampMaterialWire CredentialStampMaterial

func (m CredentialStampMaterial) MarshalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(credentialStampMaterialWire(m))
}

func (m *CredentialStampMaterial) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("credential stamp material destination is nil")
	}
	var wire credentialStampMaterialWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode credential stamp material: %w", err)
	}
	active, err := credentialStampMaterialJSONField(wire.Projection)
	if err != nil {
		return err
	}
	if err := rejectInactiveCredentialJSONFields(
		data,
		active,
		[]string{"credential", "providerEncoding", "literalReference"},
		"credential stamp material",
	); err != nil {
		return err
	}
	result := CredentialStampMaterial(wire)
	if err := result.Validate(); err != nil {
		return err
	}
	*m = result
	return nil
}

func (m CredentialStampMaterial) Validate() error {
	if err := m.Projection.Validate(); err != nil {
		return err
	}
	if credentialStampMaterialVariantCount(m) != 1 {
		return errors.New("credential stamp material must contain exactly one tagged reference")
	}
	switch m.Projection {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionSignerReference, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER:
		if m.Credential == nil || m.Credential.Projection != m.Projection {
			return errors.New("credential stamp material projection does not match its reference")
		}
		return m.Credential.Validate()
	case CredentialProjectionProviderEncoding:
		if m.ProviderEncoding == nil {
			return errors.New("credential provider-encoding material is missing")
		}
		if err := validateCredentialCanonicalText(
			m.ProviderEncoding.ProviderID,
			"credential provider-encoding provider id",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := validateCredentialCanonicalText(
			m.ProviderEncoding.SchemaVersion,
			"credential provider-encoding schema version",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := m.ProviderEncoding.Form.Validate(); err != nil {
			return err
		}
		return m.ProviderEncoding.Source.Validate()
	case CredentialProjectionLiteralReference:
		if m.LiteralReference == nil {
			return errors.New("credential literal material reference is missing")
		}
		if err := validateCredentialCanonicalText(
			m.LiteralReference.Reference,
			"credential literal material reference",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if err := m.LiteralReference.Form.Validate(); err != nil {
			return err
		}
		return validateCredentialSHA256(
			m.LiteralReference.SHA256,
			"credential literal material",
		)
	}
	return nil
}

func (m CredentialStampMaterial) Form() (CredentialMaterialForm, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	switch m.Projection {
	case CredentialProjectionProviderEncoding:
		return m.ProviderEncoding.Form, nil
	case CredentialProjectionLiteralReference:
		return m.LiteralReference.Form, nil
	default:
		return m.Credential.Form, nil
	}
}

func (m ResolvedCredentialMetadata) Validate() error {
	if err := validateCredentialCanonicalText(
		m.BundleVersion,
		"resolved credential bundle version",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := m.Purpose.Validate(); err != nil {
		return err
	}
	if err := m.ConsumerType.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		m.ProfileID,
		"resolved credential profile id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	return validateCredentialCanonicalText(
		m.CompatibilityTargetID,
		"resolved credential compatibility target id",
		maximumCredentialIDBytes,
	)
}

func (r CredentialStampRequest) Validate() error {
	if err := validateCredentialCanonicalText(
		r.AssignmentID,
		"credential stamp assignment id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Capability.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		r.SlotName,
		"credential stamp slot name",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if err := r.Material.Validate(); err != nil {
		return err
	}
	if r.EncodedBytes == 0 || r.EncodedBytes > maximumCredentialBinaryBytes {
		return errors.New("credential stamp encoded byte count is invalid")
	}
	return r.Credential.Validate()
}

func validateCredentialProjectionForm(
	projection CredentialProjection,
	form CredentialMaterialForm,
) error {
	if err := projection.Validate(); err != nil {
		return err
	}
	if err := form.Validate(); err != nil {
		return err
	}
	switch projection {
	case CredentialProjectionCertificateDER, CredentialProjectionPublicKeySPKI,
		CredentialProjectionChainDER, CredentialProjectionTrustDER,
		CredentialProjectionCRLDER:
		if form != CredentialMaterialPublic {
			return errors.New("public credential projection requires public material")
		}
	case CredentialProjectionPrivateKeyPKCS8:
		if form != CredentialMaterialPrivateBytes {
			return errors.New("private-key projection requires private bytes")
		}
	case CredentialProjectionSignerReference:
		if form != CredentialMaterialPrivateReference {
			return errors.New("signer projection requires a private reference")
		}
	}
	return nil
}

func validateCredentialCanonicalText(value, label string, maximum int) error {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
		len(value) > maximum || !utf8.ValidString(value) {
		return fmt.Errorf("%s is invalid or noncanonical", label)
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("%s contains control characters", label)
		}
	}
	return nil
}

func validateCredentialSHA256(value, label string) error {
	if len(value) != 64 || value != strings.ToLower(value) {
		return fmt.Errorf("%s sha256 is invalid or noncanonical", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s sha256 is invalid or noncanonical", label)
	}
	return nil
}

func validateCredentialStampAddressSpace(value CredentialStampAddressSpace) error {
	switch value {
	case CredentialStampAddressFile, CredentialStampAddressELFVirtual,
		CredentialStampAddressPERVA, CredentialStampAddressMachOVM:
		return nil
	default:
		return fmt.Errorf("unsupported credential stamp address space %q", value)
	}
}

func validateCredentialPositionTarget(
	position CredentialCanonicalUint64,
	imageBase CredentialCanonicalUint64,
	maximumLength CredentialCanonicalUint64,
	alignment CredentialCanonicalUint64,
	remainderPolicy CredentialStampRemainderPolicy,
	precondition CredentialStampPrecondition,
	addressSpace CredentialStampAddressSpace,
) error {
	positionValue, err := position.Uint64()
	if err != nil {
		return err
	}
	var imageBaseValue uint64
	if imageBase != "" {
		imageBaseValue, err = imageBase.Uint64()
		if err != nil {
			return err
		}
	}
	align, err := alignment.Uint64()
	if err != nil || align == 0 || align&(align-1) != 0 {
		return errors.New("credential stamp target alignment must be a nonzero power of two")
	}
	if positionValue%align != 0 {
		return errors.New("credential stamp target position does not satisfy its alignment")
	}
	maximum, err := validateCredentialBoundedTarget(
		maximumLength,
		remainderPolicy,
		precondition,
	)
	if err != nil {
		return err
	}
	if positionValue > math.MaxUint64-maximum {
		return errors.New("credential stamp target position and maximum length overflow uint64")
	}
	if imageBase != "" {
		switch addressSpace {
		case CredentialStampAddressPERVA:
			if imageBaseValue > math.MaxUint64-positionValue ||
				imageBaseValue+positionValue > math.MaxUint64-maximum {
				return errors.New("credential stamp image base, address, and length overflow uint64")
			}
		case CredentialStampAddressELFVirtual, CredentialStampAddressMachOVM:
			if positionValue < imageBaseValue {
				return errors.New("credential virtual address precedes its image base")
			}
		}
	}
	return nil
}

func validateCredentialBoundedTarget(
	maximumLength CredentialCanonicalUint64,
	remainderPolicy CredentialStampRemainderPolicy,
	precondition CredentialStampPrecondition,
) (uint64, error) {
	maximum, err := maximumLength.Uint64()
	if err != nil || maximum == 0 || maximum > maximumCredentialBinaryBytes {
		return 0, errors.New("credential stamp target maximum length is invalid")
	}
	if err := remainderPolicy.Validate(); err != nil {
		return 0, err
	}
	if err := precondition.Validate(); err != nil {
		return 0, err
	}
	if precondition.Kind == CredentialStampPreconditionBytes &&
		uint64(len(precondition.Bytes)) > maximum {
		return 0, errors.New("credential stamp precondition exceeds target maximum length")
	}
	if precondition.Kind == CredentialStampPreconditionSHA256 {
		length, err := precondition.Length.Uint64()
		if err != nil || length > maximum {
			return 0, errors.New("credential stamp hash precondition exceeds target maximum length")
		}
	}
	return maximum, nil
}

func credentialBytesAllZero(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}

func credentialStampTargetVariantCount(target CredentialStampTarget) int {
	count := 0
	for _, present := range []bool{
		target.NamedSlot != nil,
		target.FileOffset != nil,
		target.VirtualAddress != nil,
		target.Symbol != nil,
		target.Marker != nil,
		target.BytePattern != nil,
		target.ProviderDefined != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func credentialStampTargetJSONField(kind CredentialStampTargetKind) (string, error) {
	switch kind {
	case CredentialStampTargetNamedSlot:
		return "namedSlot", nil
	case CredentialStampTargetFileOffset:
		return "fileOffset", nil
	case CredentialStampTargetVirtualAddress:
		return "virtualAddress", nil
	case CredentialStampTargetSymbol:
		return "symbol", nil
	case CredentialStampTargetMarker:
		return "marker", nil
	case CredentialStampTargetBytePattern:
		return "bytePattern", nil
	case CredentialStampTargetProviderDefined:
		return "providerDefined", nil
	default:
		return "", fmt.Errorf("unsupported credential stamp target kind %q", kind)
	}
}

func credentialMaterialReferenceVariantCount(reference CredentialMaterialReference) int {
	count := 0
	for _, present := range []bool{
		reference.BundleID != "",
		reference.GenerationID != "",
		len(reference.GenerationIDs) != 0,
		reference.TrustSetGenerationID != "",
		len(reference.CRLGenerationIDs) != 0,
	} {
		if present {
			count++
		}
	}
	return count
}

func credentialMaterialReferenceJSONField(projection CredentialProjection) (string, error) {
	switch projection {
	case CredentialProjectionBundle:
		return "bundleId", nil
	case CredentialProjectionCertificateDER, CredentialProjectionPrivateKeyPKCS8,
		CredentialProjectionPublicKeySPKI, CredentialProjectionSignerReference:
		return "generationId", nil
	case CredentialProjectionChainDER:
		return "generationIds", nil
	case CredentialProjectionTrustDER:
		return "trustSetGenerationId", nil
	case CredentialProjectionCRLDER:
		return "crlGenerationIds", nil
	case CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return "", errors.New("credential material reference cannot contain provider or literal material")
	default:
		return "", fmt.Errorf("unsupported credential projection %q", projection)
	}
}

func credentialStampMaterialVariantCount(material CredentialStampMaterial) int {
	count := 0
	for _, present := range []bool{
		material.Credential != nil,
		material.ProviderEncoding != nil,
		material.LiteralReference != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func credentialStampMaterialJSONField(projection CredentialProjection) (string, error) {
	switch projection {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionSignerReference, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER:
		return "credential", nil
	case CredentialProjectionProviderEncoding:
		return "providerEncoding", nil
	case CredentialProjectionLiteralReference:
		return "literalReference", nil
	default:
		return "", fmt.Errorf("unsupported credential projection %q", projection)
	}
}

func rejectInactiveCredentialJSONFields(
	data []byte,
	allowed string,
	variants []string,
	label string,
) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode %s fields: %w", label, err)
	}
	allowedFields := make(map[string]struct{})
	for _, field := range strings.Split(allowed, ",") {
		if field != "" {
			allowedFields[field] = struct{}{}
		}
	}
	for _, variant := range variants {
		if _, present := fields[variant]; !present {
			continue
		}
		if _, active := allowedFields[variant]; !active {
			return fmt.Errorf("%s contains inactive variant field %q", label, variant)
		}
	}
	return nil
}

func validateCredentialReferenceList(values []string, label string) error {
	if len(values) == 0 || len(values) > maximumCredentialReferenceList {
		return fmt.Errorf("%s is empty or exceeds limits", label)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateCredentialCanonicalText(value, label, maximumCredentialIDBytes); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%s contains a duplicate", label)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// CredentialDescriber is implemented by modules that advertise credential
// delivery independently of Mesh. A module may implement this interface, a
// Mesh surface, or both.
type CredentialDescriber interface {
	Module
	DescribeCredentialDelivery() (CredentialDeliveryDescriptor, error)
}
