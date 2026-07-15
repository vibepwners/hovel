package pki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	CredentialDeliverySchemaV1      = "hovel.pki.credential-delivery/v1"
	MaximumCredentialSlots          = 256
	MaximumCredentialSlotValues     = 64
	MaximumProviderSchemas          = 64
	MaximumCredentialDescriptorJSON = 4 << 20
	MaximumStampContractJSON        = 2 << 20
	MaximumStampPreconditionBytes   = 1 << 20
	MaximumProviderTargetBytes      = 1 << 20
)

// DeliveryCapability is an optional provider-side credential consumption mode.
type DeliveryCapability string

const (
	DeliveryCapabilityNone          DeliveryCapability = "none"
	DeliveryCapabilityRuntime       DeliveryCapability = "runtime"
	DeliveryCapabilityFiles         DeliveryCapability = "files"
	DeliveryCapabilityStampStandard DeliveryCapability = "stamp-standard"
	DeliveryCapabilityStampAdvanced DeliveryCapability = "stamp-advanced"
)

func (c DeliveryCapability) Validate() error {
	switch c {
	case DeliveryCapabilityNone, DeliveryCapabilityRuntime, DeliveryCapabilityFiles,
		DeliveryCapabilityStampStandard, DeliveryCapabilityStampAdvanced:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential delivery capability %q", c)
	}
}

// CredentialProjection identifies one typed view of a resolved bundle.
type CredentialProjection string

const (
	CredentialProjectionBundle           CredentialProjection = "bundle"
	CredentialProjectionCertificateDER   CredentialProjection = "certificate-der"
	CredentialProjectionPrivateKeyPKCS8  CredentialProjection = "private-key-pkcs8"
	CredentialProjectionPublicKeySPKI    CredentialProjection = "public-key-spki"
	CredentialProjectionChainDER         CredentialProjection = "chain-der"
	CredentialProjectionTrustDER         CredentialProjection = "trust-der"
	CredentialProjectionCRLDER           CredentialProjection = "crl-der"
	CredentialProjectionSignerReference  CredentialProjection = "signer-reference"
	CredentialProjectionProviderEncoding CredentialProjection = "provider-encoding"
	CredentialProjectionLiteralReference CredentialProjection = "literal-reference"
)

func (p CredentialProjection) Validate() error {
	switch p {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionChainDER, CredentialProjectionTrustDER,
		CredentialProjectionCRLDER, CredentialProjectionSignerReference,
		CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential projection %q", p)
	}
}

type CredentialEndpointRole string

const (
	CredentialEndpointServer        CredentialEndpointRole = "server"
	CredentialEndpointClient        CredentialEndpointRole = "client"
	CredentialEndpointDual          CredentialEndpointRole = "dual"
	CredentialEndpointNotApplicable CredentialEndpointRole = "not-applicable"
)

func (r CredentialEndpointRole) Validate() error {
	switch r {
	case CredentialEndpointServer, CredentialEndpointClient, CredentialEndpointDual,
		CredentialEndpointNotApplicable:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential endpoint role %q", r)
	}
}

type PrivateMaterialPolicy string

const (
	PrivateMaterialForbidden PrivateMaterialPolicy = "forbidden"
	PrivateMaterialAllowed   PrivateMaterialPolicy = "allowed"
	PrivateMaterialRequired  PrivateMaterialPolicy = "required"
)

func (p PrivateMaterialPolicy) Validate() error {
	switch p {
	case PrivateMaterialForbidden, PrivateMaterialAllowed, PrivateMaterialRequired:
		return nil
	default:
		return fmt.Errorf("pki: unsupported private material policy %q", p)
	}
}

// StampRemainderPolicy defines what happens to unused capacity after writing
// encoded material into a bounded standard slot or advanced target.
type StampRemainderPolicy string

const (
	StampRemainderPreserve     StampRemainderPolicy = "preserve"
	StampRemainderZeroFill     StampRemainderPolicy = "zero-fill"
	StampRemainderRequireExact StampRemainderPolicy = "require-exact"
)

func (p StampRemainderPolicy) Validate() error {
	switch p {
	case StampRemainderPreserve, StampRemainderZeroFill, StampRemainderRequireExact:
		return nil
	default:
		return fmt.Errorf("pki: unsupported stamp remainder policy %q", p)
	}
}

type CredentialSlot struct {
	Name                         CredentialSlotName       `json:"name"`
	Purpose                      Purpose                  `json:"purpose"`
	EndpointRole                 CredentialEndpointRole   `json:"endpointRole"`
	ConsumerType                 ConsumerType             `json:"consumerType"`
	AcceptedBundleVersions       []string                 `json:"acceptedBundleVersions"`
	AcceptedProfiles             []ProfileID              `json:"acceptedProfiles"`
	AcceptedCompatibilityTargets []CompatibilityTargetID  `json:"acceptedCompatibilityTargets"`
	AcceptedProjections          []CredentialProjection   `json:"acceptedProjections"`
	AcceptedMaterialForms        []CredentialMaterialForm `json:"acceptedMaterialForms"`
	MaximumEncodedBytes          uint64                   `json:"maximumEncodedBytes"`
	RemainderPolicy              StampRemainderPolicy     `json:"remainderPolicy"`
	PrivateMaterial              PrivateMaterialPolicy    `json:"privateMaterial"`
}

type CredentialSlotArgs CredentialSlot

func NewCredentialSlot(args CredentialSlotArgs) (CredentialSlot, error) {
	slot := CredentialSlot(args)
	if err := slot.Validate(); err != nil {
		return CredentialSlot{}, err
	}
	return slot.Clone(), nil
}

func (s CredentialSlot) Clone() CredentialSlot {
	result := s
	result.AcceptedBundleVersions = append([]string(nil), s.AcceptedBundleVersions...)
	result.AcceptedProfiles = append([]ProfileID(nil), s.AcceptedProfiles...)
	result.AcceptedCompatibilityTargets = append([]CompatibilityTargetID(nil), s.AcceptedCompatibilityTargets...)
	result.AcceptedProjections = append([]CredentialProjection(nil), s.AcceptedProjections...)
	result.AcceptedMaterialForms = append([]CredentialMaterialForm(nil), s.AcceptedMaterialForms...)
	return result
}

func (s CredentialSlot) Validate() error {
	if err := s.Name.Validate(); err != nil {
		return err
	}
	if err := s.Purpose.Validate(); err != nil {
		return err
	}
	if err := s.EndpointRole.Validate(); err != nil {
		return err
	}
	if err := s.ConsumerType.Validate(); err != nil {
		return err
	}
	if err := validatePurposeEndpointRole(s.Purpose, s.EndpointRole); err != nil {
		return err
	}
	if len(s.AcceptedBundleVersions) == 0 ||
		len(s.AcceptedBundleVersions) > MaximumCredentialSlotValues ||
		!slices.Contains(s.AcceptedBundleVersions, BundleSchemaV1) ||
		hasDuplicateStrings(s.AcceptedBundleVersions) {
		return errors.New("pki: credential slot requires unique bundle versions including bundle v1")
	}
	for _, version := range s.AcceptedBundleVersions {
		if err := validateCanonicalContractText(version, "bundle version", MaxIDLength); err != nil {
			return err
		}
	}
	if len(s.AcceptedProfiles) == 0 || len(s.AcceptedProfiles) > MaximumCredentialSlotValues ||
		hasDuplicateProfileIDs(s.AcceptedProfiles) {
		return errors.New("pki: credential slot requires unique accepted profiles")
	}
	for _, id := range s.AcceptedProfiles {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if len(s.AcceptedCompatibilityTargets) == 0 ||
		len(s.AcceptedCompatibilityTargets) > MaximumCredentialSlotValues ||
		hasDuplicateCompatibilityTargetIDs(s.AcceptedCompatibilityTargets) {
		return errors.New("pki: credential slot requires unique compatibility targets")
	}
	for _, id := range s.AcceptedCompatibilityTargets {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if len(s.AcceptedProjections) == 0 || len(s.AcceptedProjections) > MaximumCredentialSlotValues ||
		hasDuplicateCredentialProjections(s.AcceptedProjections) {
		return errors.New("pki: credential slot requires unique projections")
	}
	for _, projection := range s.AcceptedProjections {
		if err := projection.Validate(); err != nil {
			return err
		}
	}
	if len(s.AcceptedMaterialForms) == 0 ||
		len(s.AcceptedMaterialForms) > MaximumCredentialSlotValues ||
		hasDuplicateCredentialMaterialForms(s.AcceptedMaterialForms) {
		return errors.New("pki: credential slot requires unique material forms")
	}
	for _, form := range s.AcceptedMaterialForms {
		if err := form.Validate(); err != nil {
			return err
		}
	}
	if s.MaximumEncodedBytes == 0 || s.MaximumEncodedBytes > MaximumBundleJSONBytes {
		return errors.New("pki: credential slot encoded-size limit is invalid")
	}
	if err := s.RemainderPolicy.Validate(); err != nil {
		return err
	}
	if err := s.PrivateMaterial.Validate(); err != nil {
		return err
	}
	alwaysPrivate := slices.Contains(s.AcceptedProjections, CredentialProjectionPrivateKeyPKCS8) ||
		slices.Contains(s.AcceptedProjections, CredentialProjectionSignerReference)
	canCarryPrivate := alwaysPrivate ||
		slices.Contains(s.AcceptedProjections, CredentialProjectionBundle) ||
		slices.Contains(s.AcceptedProjections, CredentialProjectionProviderEncoding) ||
		slices.Contains(s.AcceptedProjections, CredentialProjectionLiteralReference)
	if (s.PrivateMaterial == PrivateMaterialForbidden && alwaysPrivate) ||
		(s.PrivateMaterial == PrivateMaterialRequired && !canCarryPrivate) {
		return errors.New("pki: credential slot private-material policy contradicts its projections")
	}
	privateReference := slices.Contains(s.AcceptedMaterialForms, CredentialMaterialPrivateReference)
	privateBytes := slices.Contains(s.AcceptedMaterialForms, CredentialMaterialPrivateBytes)
	switch s.PrivateMaterial {
	case PrivateMaterialForbidden:
		if privateReference || privateBytes {
			return errors.New("pki: forbidden private-material policy advertises private forms")
		}
	case PrivateMaterialRequired:
		if slices.Contains(s.AcceptedMaterialForms, CredentialMaterialPublic) ||
			(!privateReference && !privateBytes) {
			return errors.New("pki: required private-material policy advertises public forms")
		}
	}
	return nil
}

type CredentialDeliveryDescriptor struct {
	SchemaVersion           string                   `json:"schemaVersion"`
	Slots                   []CredentialSlot         `json:"credentialSlots,omitempty"`
	Capabilities            []DeliveryCapability     `json:"deliveryCapabilities"`
	StampTargetKinds        []StampTargetKind        `json:"stampTargetKinds,omitempty"`
	AddressSpaces           []StampAddressSpace      `json:"addressSpaces,omitempty"`
	ProviderTargetSchemas   []ProviderTargetSchema   `json:"providerTargetSchemas,omitempty"`
	ProviderEncodingSchemas []ProviderEncodingSchema `json:"providerEncodingSchemas,omitempty"`
}

type CredentialDeliveryDescriptorArgs CredentialDeliveryDescriptor

func NewCredentialDeliveryDescriptor(
	args CredentialDeliveryDescriptorArgs,
) (CredentialDeliveryDescriptor, error) {
	descriptor := CredentialDeliveryDescriptor(args)
	if err := descriptor.Validate(); err != nil {
		return CredentialDeliveryDescriptor{}, err
	}
	return descriptor.Clone(), nil
}

type credentialDeliveryDescriptorWire CredentialDeliveryDescriptor

func (d *CredentialDeliveryDescriptor) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("pki: credential delivery descriptor destination is nil")
	}
	var wire credentialDeliveryDescriptorWire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialDescriptorJSON, &wire, "credential delivery descriptor",
	); err != nil {
		return err
	}
	validated, err := NewCredentialDeliveryDescriptor(
		CredentialDeliveryDescriptorArgs(wire),
	)
	if err != nil {
		return err
	}
	*d = validated
	return nil
}

func DecodeCredentialDeliveryDescriptorJSON(data []byte) (CredentialDeliveryDescriptor, error) {
	var descriptor CredentialDeliveryDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return CredentialDeliveryDescriptor{}, err
	}
	return descriptor.Clone(), nil
}

func (d CredentialDeliveryDescriptor) Clone() CredentialDeliveryDescriptor {
	result := d
	result.Slots = make([]CredentialSlot, len(d.Slots))
	for i := range d.Slots {
		result.Slots[i] = d.Slots[i].Clone()
	}
	result.Capabilities = append([]DeliveryCapability(nil), d.Capabilities...)
	result.StampTargetKinds = append([]StampTargetKind(nil), d.StampTargetKinds...)
	result.AddressSpaces = append([]StampAddressSpace(nil), d.AddressSpaces...)
	result.ProviderTargetSchemas = make([]ProviderTargetSchema, len(d.ProviderTargetSchemas))
	for i, schema := range d.ProviderTargetSchemas {
		result.ProviderTargetSchemas[i] = schema.Clone()
	}
	result.ProviderEncodingSchemas = make([]ProviderEncodingSchema, len(d.ProviderEncodingSchemas))
	for i, schema := range d.ProviderEncodingSchemas {
		result.ProviderEncodingSchemas[i] = schema.Clone()
	}
	return result
}

// DigestSHA256 returns the canonical descriptor identity used to bind
// provider discovery to later credential execution requests.
func (d CredentialDeliveryDescriptor) DigestSHA256() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("pki: encode credential delivery descriptor digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (d CredentialDeliveryDescriptor) Validate() error {
	if d.SchemaVersion != CredentialDeliverySchemaV1 {
		return fmt.Errorf("pki: unsupported credential delivery schema %q", d.SchemaVersion)
	}
	if len(d.Slots) > MaximumCredentialSlots {
		return fmt.Errorf("pki: credential delivery descriptor exceeds %d slots", MaximumCredentialSlots)
	}
	seenSlots := make(map[CredentialSlotName]struct{}, len(d.Slots))
	for _, slot := range d.Slots {
		if err := slot.Validate(); err != nil {
			return err
		}
		if _, duplicate := seenSlots[slot.Name]; duplicate {
			return fmt.Errorf("pki: duplicate credential slot %q", slot.Name)
		}
		seenSlots[slot.Name] = struct{}{}
	}
	if len(d.Capabilities) == 0 || hasDuplicateDeliveryCapabilities(d.Capabilities) {
		return errors.New("pki: credential delivery capabilities must be unique and non-empty")
	}
	for _, capability := range d.Capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
	}
	if slices.Contains(d.Capabilities, DeliveryCapabilityNone) && len(d.Capabilities) != 1 {
		return errors.New("pki: none delivery capability cannot be combined with other capabilities")
	}
	if err := validateStampDescriptorCapabilities(d); err != nil {
		return err
	}
	if err := validateProviderEncodingSchemas(d.ProviderEncodingSchemas); err != nil {
		return err
	}
	if err := validateProviderEncodingDescriptor(d); err != nil {
		return err
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("pki: encode credential delivery descriptor: %w", err)
	}
	if len(encoded) > MaximumCredentialDescriptorJSON {
		return errors.New("pki: credential delivery descriptor exceeds its encoded-size limit")
	}
	return nil
}

func (d CredentialDeliveryDescriptor) ValidateTarget(target StampTarget) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if !slices.Contains(d.StampTargetKinds, target.Kind) {
		return fmt.Errorf("pki: provider does not advertise stamp target kind %q", target.Kind)
	}
	switch target.Kind {
	case StampTargetNamedSlot:
		if _, ok := d.credentialSlot(target.NamedSlot.Name); !ok {
			return fmt.Errorf("pki: provider does not advertise credential slot %q", target.NamedSlot.Name)
		}
	case StampTargetFileOffset:
		if !slices.Contains(d.AddressSpaces, StampAddressSpaceFile) {
			return errors.New("pki: provider does not advertise file-offset addressing")
		}
	case StampTargetVirtualAddress:
		if !slices.Contains(d.AddressSpaces, target.VirtualAddress.AddressSpace) {
			return fmt.Errorf("pki: provider does not advertise address space %q", target.VirtualAddress.AddressSpace)
		}
	case StampTargetProviderDefined:
		if !slices.ContainsFunc(d.ProviderTargetSchemas, func(schema ProviderTargetSchema) bool {
			return schema.ProviderID == target.ProviderDefined.ProviderID &&
				schema.SchemaVersion == target.ProviderDefined.SchemaVersion
		}) {
			return errors.New("pki: provider-defined target does not match an advertised schema")
		}
	}
	return nil
}

func (d CredentialDeliveryDescriptor) ValidateMaterial(
	slotName CredentialSlotName,
	material StampMaterial,
	encodedBytes uint64,
) error {
	if err := d.Validate(); err != nil {
		return err
	}
	slot, ok := d.credentialSlot(slotName)
	if !ok {
		return fmt.Errorf("pki: provider does not advertise credential slot %q", slotName)
	}
	if err := material.Validate(); err != nil {
		return err
	}
	if !slices.Contains(slot.AcceptedProjections, material.Projection) {
		return fmt.Errorf("pki: credential slot %q does not accept projection %q", slotName, material.Projection)
	}
	if encodedBytes == 0 || encodedBytes > slot.MaximumEncodedBytes {
		return fmt.Errorf("pki: credential material exceeds slot %q encoded-size limit", slotName)
	}
	form, err := material.Form()
	if err != nil {
		return err
	}
	if slot.PrivateMaterial == PrivateMaterialForbidden && form.IsPrivate() {
		return fmt.Errorf("pki: credential slot %q forbids private material", slotName)
	}
	if slot.PrivateMaterial == PrivateMaterialRequired && !form.IsPrivate() {
		return fmt.Errorf("pki: credential slot %q requires private material", slotName)
	}
	if !slices.Contains(slot.AcceptedMaterialForms, form) {
		return fmt.Errorf("pki: credential slot %q does not accept material form %q", slotName, form)
	}
	if material.ProviderEncoding != nil {
		schema, ok := d.providerEncodingSchema(
			material.ProviderEncoding.ProviderID,
			material.ProviderEncoding.SchemaVersion,
		)
		if !ok {
			return errors.New("pki: provider encoding does not match an advertised schema")
		}
		if !slices.Contains(
			schema.AcceptedSourceProjections, material.ProviderEncoding.Source.Projection,
		) || !slices.Contains(schema.AcceptedSourceForms, material.ProviderEncoding.Source.Form) ||
			!slices.Contains(schema.OutputForms, material.ProviderEncoding.Form) {
			return errors.New("pki: provider encoding source or output form is not advertised")
		}
	}
	return nil
}

type ResolvedCredentialMetadata struct {
	BundleVersion         string                `json:"bundleVersion"`
	Purpose               Purpose               `json:"purpose"`
	ConsumerType          ConsumerType          `json:"consumerType"`
	ProfileID             ProfileID             `json:"profileId"`
	CompatibilityTargetID CompatibilityTargetID `json:"compatibilityTargetId"`
}

type resolvedCredentialMetadataWire ResolvedCredentialMetadata

func (m *ResolvedCredentialMetadata) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("pki: resolved credential metadata destination is nil")
	}
	var wire resolvedCredentialMetadataWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "resolved credential metadata",
	); err != nil {
		return err
	}
	metadata := ResolvedCredentialMetadata(wire)
	if err := metadata.Validate(); err != nil {
		return err
	}
	*m = metadata
	return nil
}

func (m ResolvedCredentialMetadata) Validate() error {
	if err := validateCanonicalContractText(m.BundleVersion, "bundle version", MaxIDLength); err != nil {
		return err
	}
	if err := m.Purpose.Validate(); err != nil {
		return err
	}
	if err := m.ConsumerType.Validate(); err != nil {
		return err
	}
	if err := m.ProfileID.Validate(); err != nil {
		return err
	}
	return m.CompatibilityTargetID.Validate()
}

type CredentialStampRequest struct {
	AssignmentID AssignmentID               `json:"assignmentId"`
	Capability   DeliveryCapability         `json:"capability"`
	SlotName     CredentialSlotName         `json:"slotName"`
	Target       StampTarget                `json:"target"`
	Material     StampMaterial              `json:"material"`
	EncodedBytes uint64                     `json:"encodedBytes"`
	Credential   ResolvedCredentialMetadata `json:"credential"`
}

type credentialStampRequestWire CredentialStampRequest

func (r *CredentialStampRequest) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential stamp request destination is nil")
	}
	var wire credentialStampRequestWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "credential stamp request",
	); err != nil {
		return err
	}
	request := CredentialStampRequest(wire)
	if err := request.Validate(); err != nil {
		return err
	}
	*r = request.Clone()
	return nil
}

// Validate verifies the request's intrinsic wire contract. Provider-specific
// capability, slot, schema, and target compatibility are checked by
// CredentialDeliveryDescriptor.ValidateStampRequest.
func (r CredentialStampRequest) Validate() error {
	if err := r.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := r.Capability.Validate(); err != nil {
		return err
	}
	if err := r.SlotName.Validate(); err != nil {
		return err
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if err := r.Material.Validate(); err != nil {
		return err
	}
	if r.EncodedBytes == 0 || r.EncodedBytes > MaximumBundleBinaryBytes {
		return errors.New("pki: credential stamp request encoded byte count is invalid")
	}
	if err := r.Credential.Validate(); err != nil {
		return err
	}
	return nil
}

func (r CredentialStampRequest) Clone() CredentialStampRequest {
	result := r
	result.Target = r.Target.Clone()
	result.Material = r.Material.Clone()
	return result
}

func (d CredentialDeliveryDescriptor) ValidateStampRequest(request CredentialStampRequest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if request.Capability != DeliveryCapabilityStampStandard &&
		request.Capability != DeliveryCapabilityStampAdvanced {
		return errors.New("pki: credential stamp request requires a stamping capability")
	}
	if !slices.Contains(d.Capabilities, request.Capability) {
		return fmt.Errorf("pki: provider does not advertise capability %q", request.Capability)
	}
	if err := request.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := request.SlotName.Validate(); err != nil {
		return err
	}
	if request.Capability == DeliveryCapabilityStampStandard &&
		request.Target.Kind != StampTargetNamedSlot {
		return errors.New("pki: standard stamp request requires a named-slot target")
	}
	if request.Target.Kind == StampTargetNamedSlot &&
		(request.Target.NamedSlot == nil || request.Target.NamedSlot.Name != request.SlotName) {
		return errors.New("pki: stamp request target does not match its credential slot")
	}
	if err := d.ValidateTarget(request.Target); err != nil {
		return err
	}
	if err := d.ValidateMaterial(request.SlotName, request.Material, request.EncodedBytes); err != nil {
		return err
	}
	slot, _ := d.credentialSlot(request.SlotName)
	if err := request.Credential.Validate(); err != nil {
		return err
	}
	if !slices.Contains(slot.AcceptedBundleVersions, request.Credential.BundleVersion) ||
		!slices.Contains(slot.AcceptedProfiles, request.Credential.ProfileID) ||
		!slices.Contains(
			slot.AcceptedCompatibilityTargets, request.Credential.CompatibilityTargetID,
		) || slot.Purpose != request.Credential.Purpose ||
		slot.ConsumerType != request.Credential.ConsumerType {
		return errors.New("pki: resolved credential metadata is incompatible with its slot")
	}
	if slot.RemainderPolicy == StampRemainderRequireExact &&
		request.EncodedBytes != slot.MaximumEncodedBytes {
		return errors.New("pki: encoded material does not exactly fill its credential slot")
	}
	maximum, policy, bounded, err := stampTargetCapacity(request.Target)
	if err != nil {
		return err
	}
	if bounded && (request.EncodedBytes > maximum ||
		(policy == StampRemainderRequireExact && request.EncodedBytes != maximum)) {
		return errors.New("pki: encoded material does not satisfy the stamp target capacity")
	}
	return nil
}

func (d CredentialDeliveryDescriptor) credentialSlot(
	name CredentialSlotName,
) (CredentialSlot, bool) {
	for _, slot := range d.Slots {
		if slot.Name == name {
			return slot.Clone(), true
		}
	}
	return CredentialSlot{}, false
}

func (d CredentialDeliveryDescriptor) providerEncodingSchema(
	providerID DeliveryProviderID,
	version string,
) (ProviderEncodingSchema, bool) {
	for _, schema := range d.ProviderEncodingSchemas {
		if schema.ProviderID == providerID && schema.SchemaVersion == version {
			return schema.Clone(), true
		}
	}
	return ProviderEncodingSchema{}, false
}

// CanonicalUint64 is a base-10 string on the wire so addresses and offsets
// round-trip through clients whose numeric type cannot represent every uint64.
type CanonicalUint64 string

func NewCanonicalUint64(value uint64) CanonicalUint64 {
	return CanonicalUint64(strconv.FormatUint(value, 10))
}

func ParseCanonicalUint64(value string) (CanonicalUint64, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("pki: %q is not a canonical uint64", value)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return "", fmt.Errorf("pki: %q is not a canonical uint64", value)
	}
	return CanonicalUint64(value), nil
}

func (v CanonicalUint64) Validate() error {
	_, err := ParseCanonicalUint64(string(v))
	return err
}

func (v CanonicalUint64) Uint64() (uint64, error) {
	if err := v.Validate(); err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(v), 10, 64)
}

type StampTargetKind string

const (
	StampTargetNamedSlot       StampTargetKind = "named-slot"
	StampTargetFileOffset      StampTargetKind = "file-offset"
	StampTargetVirtualAddress  StampTargetKind = "virtual-address"
	StampTargetSymbol          StampTargetKind = "symbol"
	StampTargetMarker          StampTargetKind = "marker"
	StampTargetBytePattern     StampTargetKind = "byte-pattern"
	StampTargetProviderDefined StampTargetKind = "provider-defined"
)

func (k StampTargetKind) Validate() error {
	switch k {
	case StampTargetNamedSlot, StampTargetFileOffset, StampTargetVirtualAddress,
		StampTargetSymbol, StampTargetMarker, StampTargetBytePattern,
		StampTargetProviderDefined:
		return nil
	default:
		return fmt.Errorf("pki: unsupported stamp target kind %q", k)
	}
}

type StampAddressSpace string

const (
	StampAddressSpaceFile       StampAddressSpace = "file"
	StampAddressSpaceELFVirtual StampAddressSpace = "elf-virtual-address"
	StampAddressSpacePERVA      StampAddressSpace = "pe-rva"
	StampAddressSpaceMachOVM    StampAddressSpace = "macho-vm-address"
)

func (s StampAddressSpace) Validate() error {
	switch s {
	case StampAddressSpaceFile, StampAddressSpaceELFVirtual,
		StampAddressSpacePERVA, StampAddressSpaceMachOVM:
		return nil
	default:
		return fmt.Errorf("pki: unsupported stamp address space %q", s)
	}
}

type StampPreconditionKind string

const (
	StampPreconditionNone   StampPreconditionKind = "none"
	StampPreconditionBytes  StampPreconditionKind = "bytes"
	StampPreconditionSHA256 StampPreconditionKind = "sha256"
)

type StampPrecondition struct {
	Kind   StampPreconditionKind `json:"kind"`
	Bytes  []byte                `json:"bytes,omitempty"`
	SHA256 string                `json:"sha256,omitempty"`
	Length CanonicalUint64       `json:"length,omitempty"`
}

type stampPreconditionWire StampPrecondition

func (p *StampPrecondition) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("pki: stamp precondition destination is nil")
	}
	var wire stampPreconditionWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "stamp precondition",
	); err != nil {
		return err
	}
	precondition := StampPrecondition(wire)
	allowed := []string(nil)
	switch precondition.Kind {
	case StampPreconditionNone:
	case StampPreconditionBytes:
		allowed = []string{"bytes"}
	case StampPreconditionSHA256:
		allowed = []string{"sha256", "length"}
	default:
		return fmt.Errorf("pki: unsupported stamp precondition kind %q", precondition.Kind)
	}
	if err := rejectDisallowedVariantJSONFields(
		data, allowed, []string{"bytes", "sha256", "length"}, "stamp precondition",
	); err != nil {
		return err
	}
	if err := precondition.Validate(); err != nil {
		return err
	}
	*p = precondition.Clone()
	return nil
}

func (p StampPrecondition) Clone() StampPrecondition {
	result := p
	result.Bytes = append([]byte(nil), p.Bytes...)
	return result
}

func (p StampPrecondition) Validate() error {
	switch p.Kind {
	case StampPreconditionNone:
		if len(p.Bytes) != 0 || p.SHA256 != "" || p.Length != "" {
			return errors.New("pki: empty stamp precondition contains comparison material")
		}
	case StampPreconditionBytes:
		if len(p.Bytes) == 0 || len(p.Bytes) > MaximumStampPreconditionBytes ||
			p.SHA256 != "" || p.Length != "" {
			return errors.New("pki: byte stamp precondition is invalid")
		}
	case StampPreconditionSHA256:
		if len(p.Bytes) != 0 {
			return errors.New("pki: hash stamp precondition contains literal bytes")
		}
		length, err := p.Length.Uint64()
		if err != nil || length == 0 || length > MaximumBundleBinaryBytes {
			return errors.New("pki: stamp precondition hash length is invalid")
		}
		normalized, err := normalizeSHA256Fingerprint(p.SHA256, "stamp precondition")
		if err != nil || normalized != p.SHA256 {
			return errors.New("pki: stamp precondition sha256 is invalid or noncanonical")
		}
	default:
		return fmt.Errorf("pki: unsupported stamp precondition kind %q", p.Kind)
	}
	return nil
}

type NamedSlotTarget struct {
	Name CredentialSlotName `json:"name"`
}

type FileOffsetTarget struct {
	Offset          CanonicalUint64      `json:"offset"`
	MaximumLength   CanonicalUint64      `json:"maximumLength"`
	Alignment       CanonicalUint64      `json:"alignment"`
	RemainderPolicy StampRemainderPolicy `json:"remainderPolicy"`
	Precondition    StampPrecondition    `json:"precondition"`
}

type VirtualAddressTarget struct {
	Address         CanonicalUint64      `json:"address"`
	AddressSpace    StampAddressSpace    `json:"addressSpace"`
	ImageBase       CanonicalUint64      `json:"imageBase,omitempty"`
	MaximumLength   CanonicalUint64      `json:"maximumLength"`
	Alignment       CanonicalUint64      `json:"alignment"`
	RemainderPolicy StampRemainderPolicy `json:"remainderPolicy"`
	Precondition    StampPrecondition    `json:"precondition"`
}

type SymbolTarget struct {
	Name            string               `json:"name"`
	Section         string               `json:"section,omitempty"`
	MaximumLength   CanonicalUint64      `json:"maximumLength"`
	RemainderPolicy StampRemainderPolicy `json:"remainderPolicy"`
	Precondition    StampPrecondition    `json:"precondition"`
}

type MarkerTarget struct {
	Marker          []byte               `json:"marker"`
	Occurrence      uint32               `json:"occurrence"`
	MaximumLength   CanonicalUint64      `json:"maximumLength"`
	RemainderPolicy StampRemainderPolicy `json:"remainderPolicy"`
	Precondition    StampPrecondition    `json:"precondition"`
}

type BytePatternTarget struct {
	Pattern         []byte               `json:"pattern"`
	Mask            []byte               `json:"mask"`
	Occurrence      uint32               `json:"occurrence"`
	MaximumLength   CanonicalUint64      `json:"maximumLength"`
	RemainderPolicy StampRemainderPolicy `json:"remainderPolicy"`
	Precondition    StampPrecondition    `json:"precondition"`
}

type ProviderDefinedTarget struct {
	ProviderID    DeliveryProviderID `json:"providerId"`
	SchemaVersion string             `json:"schemaVersion"`
	Value         json.RawMessage    `json:"value"`
}

type ProviderTargetSchema struct {
	ProviderID    DeliveryProviderID `json:"providerId"`
	SchemaVersion string             `json:"schemaVersion"`
	JSONSchema    json.RawMessage    `json:"jsonSchema"`
}

func (s ProviderTargetSchema) Clone() ProviderTargetSchema {
	result := s
	result.JSONSchema = append(json.RawMessage(nil), s.JSONSchema...)
	return result
}

type StampTarget struct {
	Kind            StampTargetKind        `json:"kind"`
	NamedSlot       *NamedSlotTarget       `json:"namedSlot,omitempty"`
	FileOffset      *FileOffsetTarget      `json:"fileOffset,omitempty"`
	VirtualAddress  *VirtualAddressTarget  `json:"virtualAddress,omitempty"`
	Symbol          *SymbolTarget          `json:"symbol,omitempty"`
	Marker          *MarkerTarget          `json:"marker,omitempty"`
	BytePattern     *BytePatternTarget     `json:"bytePattern,omitempty"`
	ProviderDefined *ProviderDefinedTarget `json:"providerDefined,omitempty"`
}

type stampTargetWire StampTarget

func (t *StampTarget) UnmarshalJSON(data []byte) error {
	if t == nil {
		return errors.New("pki: stamp target destination is nil")
	}
	var wire stampTargetWire
	if err := strictDecodeJSONObject(data, MaximumStampContractJSON, &wire, "stamp target"); err != nil {
		return err
	}
	target := StampTarget(wire)
	activeField, err := stampTargetVariantJSONField(target.Kind)
	if err != nil {
		return err
	}
	if err := rejectInactiveVariantJSONFields(
		data, activeField,
		[]string{"namedSlot", "fileOffset", "virtualAddress", "symbol", "marker", "bytePattern", "providerDefined"},
		"stamp target",
	); err != nil {
		return err
	}
	validated, err := newStampTarget(target)
	if err != nil {
		return err
	}
	*t = validated
	return nil
}

func DecodeStampTargetJSON(data []byte) (StampTarget, error) {
	var target StampTarget
	if err := json.Unmarshal(data, &target); err != nil {
		return StampTarget{}, err
	}
	return target.Clone(), nil
}

func NewNamedSlotStampTarget(target NamedSlotTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetNamedSlot, NamedSlot: &target})
}

func NewFileOffsetStampTarget(target FileOffsetTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetFileOffset, FileOffset: &target})
}

func NewVirtualAddressStampTarget(target VirtualAddressTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetVirtualAddress, VirtualAddress: &target})
}

func NewSymbolStampTarget(target SymbolTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetSymbol, Symbol: &target})
}

func NewMarkerStampTarget(target MarkerTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetMarker, Marker: &target})
}

func NewBytePatternStampTarget(target BytePatternTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetBytePattern, BytePattern: &target})
}

func NewProviderDefinedStampTarget(target ProviderDefinedTarget) (StampTarget, error) {
	return newStampTarget(StampTarget{Kind: StampTargetProviderDefined, ProviderDefined: &target})
}

func newStampTarget(target StampTarget) (StampTarget, error) {
	if err := target.Validate(); err != nil {
		return StampTarget{}, err
	}
	return target.Clone(), nil
}

func (t StampTarget) Clone() StampTarget {
	result := t
	if t.NamedSlot != nil {
		value := *t.NamedSlot
		result.NamedSlot = &value
	}
	if t.FileOffset != nil {
		value := *t.FileOffset
		value.Precondition = t.FileOffset.Precondition.Clone()
		result.FileOffset = &value
	}
	if t.VirtualAddress != nil {
		value := *t.VirtualAddress
		value.Precondition = t.VirtualAddress.Precondition.Clone()
		result.VirtualAddress = &value
	}
	if t.Symbol != nil {
		value := *t.Symbol
		value.Precondition = t.Symbol.Precondition.Clone()
		result.Symbol = &value
	}
	if t.Marker != nil {
		value := *t.Marker
		value.Marker = append([]byte(nil), t.Marker.Marker...)
		value.Precondition = t.Marker.Precondition.Clone()
		result.Marker = &value
	}
	if t.BytePattern != nil {
		value := *t.BytePattern
		value.Pattern = append([]byte(nil), t.BytePattern.Pattern...)
		value.Mask = append([]byte(nil), t.BytePattern.Mask...)
		value.Precondition = t.BytePattern.Precondition.Clone()
		result.BytePattern = &value
	}
	if t.ProviderDefined != nil {
		value := *t.ProviderDefined
		value.Value = append(json.RawMessage(nil), t.ProviderDefined.Value...)
		result.ProviderDefined = &value
	}
	return result
}

func (t StampTarget) Validate() error {
	if err := t.Kind.Validate(); err != nil {
		return err
	}
	if stampTargetVariantCount(t) != 1 {
		return errors.New("pki: stamp target must contain exactly one tagged variant")
	}
	switch t.Kind {
	case StampTargetNamedSlot:
		if t.NamedSlot == nil || t.NamedSlot.Name.Validate() != nil {
			return errors.New("pki: named-slot stamp target is invalid")
		}
	case StampTargetFileOffset:
		if t.FileOffset == nil {
			return errors.New("pki: file-offset stamp target is missing")
		}
		return validatePositionTarget(
			t.FileOffset.Offset, "", t.FileOffset.MaximumLength,
			t.FileOffset.Alignment, t.FileOffset.RemainderPolicy,
			t.FileOffset.Precondition, StampAddressSpaceFile,
		)
	case StampTargetVirtualAddress:
		if t.VirtualAddress == nil {
			return errors.New("pki: virtual-address stamp target is missing")
		}
		if err := t.VirtualAddress.AddressSpace.Validate(); err != nil {
			return err
		}
		if t.VirtualAddress.AddressSpace == StampAddressSpaceFile {
			return errors.New("pki: virtual-address target cannot use the file address space")
		}
		return validatePositionTarget(
			t.VirtualAddress.Address, t.VirtualAddress.ImageBase,
			t.VirtualAddress.MaximumLength, t.VirtualAddress.Alignment,
			t.VirtualAddress.RemainderPolicy, t.VirtualAddress.Precondition,
			t.VirtualAddress.AddressSpace,
		)
	case StampTargetSymbol:
		if t.Symbol == nil {
			return errors.New("pki: symbol stamp target is invalid")
		}
		if err := validateCanonicalContractText(
			t.Symbol.Name, "stamp symbol name", MaxNameLength,
		); err != nil {
			return err
		}
		if t.Symbol.Section != "" {
			if err := validateCanonicalContractText(
				t.Symbol.Section, "stamp symbol section", MaxNameLength,
			); err != nil {
				return err
			}
		}
		_, err := validateBoundedTarget(
			t.Symbol.MaximumLength, t.Symbol.RemainderPolicy, t.Symbol.Precondition,
		)
		return err
	case StampTargetMarker:
		if t.Marker == nil || len(t.Marker.Marker) == 0 ||
			len(t.Marker.Marker) > MaximumStampPreconditionBytes {
			return errors.New("pki: marker stamp target is invalid")
		}
		_, err := validateBoundedTarget(
			t.Marker.MaximumLength, t.Marker.RemainderPolicy, t.Marker.Precondition,
		)
		return err
	case StampTargetBytePattern:
		if t.BytePattern == nil || len(t.BytePattern.Pattern) == 0 ||
			len(t.BytePattern.Pattern) != len(t.BytePattern.Mask) ||
			len(t.BytePattern.Pattern) > MaximumStampPreconditionBytes ||
			allBytesZero(t.BytePattern.Mask) {
			return errors.New("pki: byte-pattern stamp target is invalid")
		}
		_, err := validateBoundedTarget(
			t.BytePattern.MaximumLength, t.BytePattern.RemainderPolicy,
			t.BytePattern.Precondition,
		)
		return err
	case StampTargetProviderDefined:
		if t.ProviderDefined == nil {
			return errors.New("pki: provider-defined stamp target is missing")
		}
		return validateProviderEnvelope(
			t.ProviderDefined.ProviderID, t.ProviderDefined.SchemaVersion,
			t.ProviderDefined.Value, "provider-defined stamp target",
		)
	}
	return nil
}

type CredentialMaterialReference struct {
	Projection           CredentialProjection   `json:"projection"`
	Form                 CredentialMaterialForm `json:"form"`
	BundleID             BundleID               `json:"bundleId,omitempty"`
	GenerationID         GenerationID           `json:"generationId,omitempty"`
	GenerationIDs        []GenerationID         `json:"generationIds,omitempty"`
	TrustSetGenerationID TrustSetGenerationID   `json:"trustSetGenerationId,omitempty"`
	CRLGenerationIDs     []CRLGenerationID      `json:"crlGenerationIds,omitempty"`
}

type credentialMaterialReferenceWire CredentialMaterialReference

func (r *CredentialMaterialReference) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential material reference destination is nil")
	}
	var wire credentialMaterialReferenceWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "credential material reference",
	); err != nil {
		return err
	}
	reference := CredentialMaterialReference(wire)
	active, err := credentialMaterialReferenceJSONField(reference.Projection)
	if err != nil {
		return err
	}
	if err := rejectInactiveVariantJSONFields(
		data, active,
		[]string{"bundleId", "generationId", "generationIds", "trustSetGenerationId", "crlGenerationIds"},
		"credential material reference",
	); err != nil {
		return err
	}
	if err := reference.Validate(); err != nil {
		return err
	}
	*r = reference.Clone()
	return nil
}

// CredentialMaterialForm states how the resolved operation presents private
// material. This cannot be inferred from projections such as bundle or
// provider-encoding, which may contain public data, private bytes, or an
// opaque signer reference.
type CredentialMaterialForm string

const (
	CredentialMaterialPublic           CredentialMaterialForm = "public"
	CredentialMaterialPrivateReference CredentialMaterialForm = "private-reference"
	CredentialMaterialPrivateBytes     CredentialMaterialForm = "private-bytes"
)

func (f CredentialMaterialForm) Validate() error {
	switch f {
	case CredentialMaterialPublic, CredentialMaterialPrivateReference,
		CredentialMaterialPrivateBytes:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential material form %q", f)
	}
}

func (f CredentialMaterialForm) IsPrivate() bool {
	return f == CredentialMaterialPrivateReference || f == CredentialMaterialPrivateBytes
}

func (r CredentialMaterialReference) Clone() CredentialMaterialReference {
	result := r
	result.GenerationIDs = append([]GenerationID(nil), r.GenerationIDs...)
	result.CRLGenerationIDs = append([]CRLGenerationID(nil), r.CRLGenerationIDs...)
	return result
}

func (r CredentialMaterialReference) Validate() error {
	if err := r.Projection.Validate(); err != nil {
		return err
	}
	if credentialMaterialReferenceVariantCount(r) != 1 {
		return errors.New("pki: credential material must contain exactly one tagged reference")
	}
	if err := r.Form.Validate(); err != nil {
		return err
	}
	switch r.Projection {
	case CredentialProjectionBundle:
		return r.BundleID.Validate()
	case CredentialProjectionCertificateDER, CredentialProjectionPublicKeySPKI:
		if r.Form != CredentialMaterialPublic {
			return errors.New("pki: public credential projection has a private material form")
		}
		return r.GenerationID.Validate()
	case CredentialProjectionPrivateKeyPKCS8:
		if r.Form != CredentialMaterialPrivateBytes {
			return errors.New("pki: private-key projection requires private bytes")
		}
		return r.GenerationID.Validate()
	case CredentialProjectionSignerReference:
		if r.Form != CredentialMaterialPrivateReference {
			return errors.New("pki: signer projection requires a private reference")
		}
		return r.GenerationID.Validate()
	case CredentialProjectionChainDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("pki: certificate chain has a private material form")
		}
		return validateGenerationIDList(r.GenerationIDs, "stamp chain")
	case CredentialProjectionTrustDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("pki: trust material has a private material form")
		}
		return r.TrustSetGenerationID.Validate()
	case CredentialProjectionCRLDER:
		if r.Form != CredentialMaterialPublic {
			return errors.New("pki: crl material has a private material form")
		}
		return validateCRLGenerationIDList(r.CRLGenerationIDs)
	case CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return errors.New("pki: credential material reference cannot contain provider or literal material")
	}
	return nil
}

type ProviderEncodingMaterial struct {
	ProviderID    DeliveryProviderID          `json:"providerId"`
	SchemaVersion string                      `json:"schemaVersion"`
	Form          CredentialMaterialForm      `json:"form"`
	Source        CredentialMaterialReference `json:"source"`
}

type ProviderEncodingSchema struct {
	ProviderID                DeliveryProviderID       `json:"providerId"`
	SchemaVersion             string                   `json:"schemaVersion"`
	AcceptedSourceProjections []CredentialProjection   `json:"acceptedSourceProjections"`
	AcceptedSourceForms       []CredentialMaterialForm `json:"acceptedSourceForms"`
	OutputForms               []CredentialMaterialForm `json:"outputForms"`
}

func (s ProviderEncodingSchema) Clone() ProviderEncodingSchema {
	result := s
	result.AcceptedSourceProjections = append(
		[]CredentialProjection(nil), s.AcceptedSourceProjections...,
	)
	result.AcceptedSourceForms = append(
		[]CredentialMaterialForm(nil), s.AcceptedSourceForms...,
	)
	result.OutputForms = append([]CredentialMaterialForm(nil), s.OutputForms...)
	return result
}

type LiteralMaterialReference struct {
	Reference StampReferenceID       `json:"reference"`
	SHA256    string                 `json:"sha256"`
	Form      CredentialMaterialForm `json:"form"`
}

type StampMaterial struct {
	Projection       CredentialProjection         `json:"projection"`
	Credential       *CredentialMaterialReference `json:"credential,omitempty"`
	ProviderEncoding *ProviderEncodingMaterial    `json:"providerEncoding,omitempty"`
	LiteralReference *LiteralMaterialReference    `json:"literalReference,omitempty"`
}

type stampMaterialWire StampMaterial

func (m *StampMaterial) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("pki: stamp material destination is nil")
	}
	var wire stampMaterialWire
	if err := strictDecodeJSONObject(data, MaximumStampContractJSON, &wire, "stamp material"); err != nil {
		return err
	}
	material := StampMaterial(wire)
	activeField, err := stampMaterialVariantJSONField(material.Projection)
	if err != nil {
		return err
	}
	if err := rejectInactiveVariantJSONFields(
		data, activeField,
		[]string{"credential", "providerEncoding", "literalReference"},
		"stamp material",
	); err != nil {
		return err
	}
	validated, err := newStampMaterial(material)
	if err != nil {
		return err
	}
	*m = validated
	return nil
}

func DecodeStampMaterialJSON(data []byte) (StampMaterial, error) {
	var material StampMaterial
	if err := json.Unmarshal(data, &material); err != nil {
		return StampMaterial{}, err
	}
	return material.Clone(), nil
}

func NewCredentialStampMaterial(reference CredentialMaterialReference) (StampMaterial, error) {
	material := StampMaterial{Projection: reference.Projection, Credential: &reference}
	return newStampMaterial(material)
}

func NewProviderEncodingStampMaterial(
	providerEncoding ProviderEncodingMaterial,
) (StampMaterial, error) {
	material := StampMaterial{
		Projection: CredentialProjectionProviderEncoding, ProviderEncoding: &providerEncoding,
	}
	return newStampMaterial(material)
}

func NewLiteralReferenceStampMaterial(
	reference LiteralMaterialReference,
) (StampMaterial, error) {
	material := StampMaterial{
		Projection: CredentialProjectionLiteralReference, LiteralReference: &reference,
	}
	return newStampMaterial(material)
}

func newStampMaterial(material StampMaterial) (StampMaterial, error) {
	if err := material.Validate(); err != nil {
		return StampMaterial{}, err
	}
	return material.Clone(), nil
}

func (m StampMaterial) Clone() StampMaterial {
	result := m
	if m.Credential != nil {
		value := m.Credential.Clone()
		result.Credential = &value
	}
	if m.ProviderEncoding != nil {
		value := *m.ProviderEncoding
		value.Source = m.ProviderEncoding.Source.Clone()
		result.ProviderEncoding = &value
	}
	if m.LiteralReference != nil {
		value := *m.LiteralReference
		result.LiteralReference = &value
	}
	return result
}

func (m StampMaterial) Validate() error {
	if err := m.Projection.Validate(); err != nil {
		return err
	}
	if stampMaterialVariantCount(m) != 1 {
		return errors.New("pki: stamp material must contain exactly one tagged reference")
	}
	switch m.Projection {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionSignerReference, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER:
		if m.Credential == nil || m.Credential.Projection != m.Projection {
			return errors.New("pki: stamp material projection does not match its credential reference")
		}
		return m.Credential.Validate()
	case CredentialProjectionProviderEncoding:
		if m.ProviderEncoding == nil {
			return errors.New("pki: provider encoding material is missing")
		}
		if err := m.ProviderEncoding.ProviderID.Validate(); err != nil {
			return err
		}
		if err := validateProviderSchemaVersion(
			m.ProviderEncoding.SchemaVersion, "provider encoding",
		); err != nil {
			return err
		}
		if err := m.ProviderEncoding.Form.Validate(); err != nil {
			return err
		}
		return m.ProviderEncoding.Source.Validate()
	case CredentialProjectionLiteralReference:
		if m.LiteralReference == nil {
			return errors.New("pki: literal material reference is missing")
		}
		if err := m.LiteralReference.Reference.Validate(); err != nil {
			return err
		}
		if err := m.LiteralReference.Form.Validate(); err != nil {
			return err
		}
		normalized, err := normalizeSHA256Fingerprint(m.LiteralReference.SHA256, "literal material")
		if err != nil || normalized != m.LiteralReference.SHA256 {
			return errors.New("pki: literal material sha256 is invalid or noncanonical")
		}
		return nil
	}
	return nil
}

func (m StampMaterial) Form() (CredentialMaterialForm, error) {
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

func validateStampDescriptorCapabilities(d CredentialDeliveryDescriptor) error {
	advanced := slices.Contains(d.Capabilities, DeliveryCapabilityStampAdvanced)
	standard := slices.Contains(d.Capabilities, DeliveryCapabilityStampStandard)
	if slices.Contains(d.Capabilities, DeliveryCapabilityNone) {
		if len(d.Slots) != 0 || len(d.StampTargetKinds) != 0 ||
			len(d.AddressSpaces) != 0 || len(d.ProviderTargetSchemas) != 0 ||
			len(d.ProviderEncodingSchemas) != 0 {
			return errors.New("pki: none delivery capability cannot declare credential delivery metadata")
		}
		return nil
	}
	if len(d.Slots) == 0 {
		return errors.New("pki: credential delivery capability requires at least one credential slot")
	}
	if len(d.StampTargetKinds) == 0 {
		if len(d.AddressSpaces) != 0 || len(d.ProviderTargetSchemas) != 0 || advanced || standard {
			return errors.New("pki: stamping capability requires declared target kinds")
		}
		return nil
	}
	if !advanced && !standard {
		return errors.New("pki: declared stamp targets require a stamping capability")
	}
	if hasDuplicateStampTargetKinds(d.StampTargetKinds) {
		return errors.New("pki: stamp target kinds must be unique")
	}
	for _, kind := range d.StampTargetKinds {
		if err := kind.Validate(); err != nil {
			return err
		}
	}
	if standard && !slices.Contains(d.StampTargetKinds, StampTargetNamedSlot) {
		return errors.New("pki: standard stamping requires named-slot targets")
	}
	if !advanced && slices.ContainsFunc(d.StampTargetKinds, func(kind StampTargetKind) bool {
		return kind != StampTargetNamedSlot
	}) {
		return errors.New("pki: advanced stamp targets require the advanced capability")
	}
	if hasDuplicateAddressSpaces(d.AddressSpaces) {
		return errors.New("pki: stamp address spaces must be unique")
	}
	for _, addressSpace := range d.AddressSpaces {
		if err := addressSpace.Validate(); err != nil {
			return err
		}
	}
	fileOffset := slices.Contains(d.StampTargetKinds, StampTargetFileOffset)
	virtualAddress := slices.Contains(d.StampTargetKinds, StampTargetVirtualAddress)
	fileAddressSpace := slices.Contains(d.AddressSpaces, StampAddressSpaceFile)
	virtualAddressSpace := slices.ContainsFunc(d.AddressSpaces, func(space StampAddressSpace) bool {
		return space != StampAddressSpaceFile
	})
	if fileOffset != fileAddressSpace || virtualAddress != virtualAddressSpace {
		return errors.New("pki: positional stamp targets require their corresponding address spaces")
	}
	seenSchemas := make(map[string]struct{}, len(d.ProviderTargetSchemas))
	if len(d.ProviderTargetSchemas) > MaximumProviderSchemas {
		return errors.New("pki: provider target schemas exceed the descriptor limit")
	}
	for _, schema := range d.ProviderTargetSchemas {
		if err := validateProviderEnvelope(
			schema.ProviderID, schema.SchemaVersion, schema.JSONSchema, "provider target schema",
		); err != nil {
			return err
		}
		key := string(schema.ProviderID) + "\x00" + schema.SchemaVersion
		if _, duplicate := seenSchemas[key]; duplicate {
			return errors.New("pki: duplicate provider target schema")
		}
		seenSchemas[key] = struct{}{}
	}
	if len(d.ProviderTargetSchemas) != 0 &&
		!slices.Contains(d.StampTargetKinds, StampTargetProviderDefined) {
		return errors.New("pki: provider target schemas require provider-defined targets")
	}
	if slices.Contains(d.StampTargetKinds, StampTargetProviderDefined) &&
		len(d.ProviderTargetSchemas) == 0 {
		return errors.New("pki: provider-defined targets require a declared schema")
	}
	return nil
}

func validateProviderEncodingSchemas(schemas []ProviderEncodingSchema) error {
	if len(schemas) > MaximumProviderSchemas {
		return errors.New("pki: provider encoding schemas exceed the descriptor limit")
	}
	seen := make(map[string]struct{}, len(schemas))
	for _, schema := range schemas {
		if err := schema.ProviderID.Validate(); err != nil {
			return err
		}
		if err := validateProviderSchemaVersion(schema.SchemaVersion, "provider encoding"); err != nil {
			return err
		}
		if len(schema.AcceptedSourceProjections) == 0 ||
			len(schema.AcceptedSourceProjections) > MaximumCredentialSlotValues ||
			hasDuplicateCredentialProjections(schema.AcceptedSourceProjections) {
			return errors.New("pki: provider encoding requires unique bounded source projections")
		}
		for _, projection := range schema.AcceptedSourceProjections {
			if err := projection.Validate(); err != nil {
				return err
			}
			if projection == CredentialProjectionProviderEncoding ||
				projection == CredentialProjectionLiteralReference {
				return errors.New("pki: provider encoding source projection cannot be provider or literal material")
			}
		}
		if err := validateCredentialMaterialForms(
			schema.AcceptedSourceForms, "provider encoding source",
		); err != nil {
			return err
		}
		if err := validateCredentialMaterialForms(
			schema.OutputForms, "provider encoding output",
		); err != nil {
			return err
		}
		key := string(schema.ProviderID) + "\x00" + schema.SchemaVersion
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: duplicate provider encoding schema")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateCredentialMaterialForms(values []CredentialMaterialForm, label string) error {
	if len(values) == 0 || len(values) > MaximumCredentialSlotValues ||
		hasDuplicateCredentialMaterialForms(values) {
		return fmt.Errorf("pki: %s forms must be unique, bounded, and non-empty", label)
	}
	for _, form := range values {
		if err := form.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateProviderEncodingDescriptor(d CredentialDeliveryDescriptor) error {
	acceptingSlots := make([]CredentialSlot, 0, len(d.Slots))
	for _, slot := range d.Slots {
		if slices.Contains(slot.AcceptedProjections, CredentialProjectionProviderEncoding) {
			acceptingSlots = append(acceptingSlots, slot)
		}
	}
	if (len(acceptingSlots) == 0) != (len(d.ProviderEncodingSchemas) == 0) {
		return errors.New("pki: provider-encoding projections and schemas must be declared together")
	}
	compatible := func(slot CredentialSlot, schema ProviderEncodingSchema) bool {
		return slices.ContainsFunc(schema.OutputForms, func(form CredentialMaterialForm) bool {
			return slices.Contains(slot.AcceptedMaterialForms, form)
		})
	}
	for _, slot := range acceptingSlots {
		if !slices.ContainsFunc(d.ProviderEncodingSchemas, func(schema ProviderEncodingSchema) bool {
			return compatible(slot, schema)
		}) {
			return fmt.Errorf("pki: provider-encoding slot %q has no compatible schema", slot.Name)
		}
	}
	for _, schema := range d.ProviderEncodingSchemas {
		if !slices.ContainsFunc(acceptingSlots, func(slot CredentialSlot) bool {
			return compatible(slot, schema)
		}) {
			return fmt.Errorf(
				"pki: provider encoding schema %q/%q is not usable by a slot",
				schema.ProviderID, schema.SchemaVersion,
			)
		}
	}
	return nil
}

func validateProviderSchemaVersion(value, label string) error {
	return validateCanonicalContractText(value, label+" schema version", MaxIDLength)
}

func validatePurposeEndpointRole(purpose Purpose, role CredentialEndpointRole) error {
	var expected CredentialEndpointRole
	switch purpose {
	case PurposeTLSServer, PurposeMTLSServer:
		expected = CredentialEndpointServer
	case PurposeTLSClient, PurposeMTLSClient:
		expected = CredentialEndpointClient
	case PurposeDualRoleMTLS:
		expected = CredentialEndpointDual
	case PurposeCodeSigning, PurposeCustom:
		expected = CredentialEndpointNotApplicable
	default:
		return fmt.Errorf("pki: unsupported credential slot purpose %q", purpose)
	}
	if role != expected {
		return fmt.Errorf("pki: credential endpoint role %q does not match purpose %q", role, purpose)
	}
	return nil
}

func validateCanonicalContractText(value, label string, maximum int) error {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
		len(value) > maximum || !utf8.ValidString(value) {
		return fmt.Errorf("pki: %s is invalid or noncanonical", label)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("pki: %s contains control characters", label)
		}
	}
	return nil
}

func validatePositionTarget(
	position CanonicalUint64,
	imageBase CanonicalUint64,
	maximumLength CanonicalUint64,
	alignment CanonicalUint64,
	remainderPolicy StampRemainderPolicy,
	precondition StampPrecondition,
	addressSpace StampAddressSpace,
) error {
	positionValue, err := position.Uint64()
	if err != nil {
		return err
	}
	var imageBaseValue uint64
	if imageBase != "" {
		var err error
		imageBaseValue, err = imageBase.Uint64()
		if err != nil {
			return err
		}
	}
	align, err := alignment.Uint64()
	if err != nil {
		return err
	}
	if align == 0 || align&(align-1) != 0 {
		return errors.New("pki: stamp target alignment must be a nonzero power of two")
	}
	if positionValue%align != 0 {
		return errors.New("pki: stamp target position does not satisfy its alignment")
	}
	maximum, err := validateBoundedTarget(maximumLength, remainderPolicy, precondition)
	if err != nil {
		return err
	}
	if positionValue > math.MaxUint64-maximum {
		return errors.New("pki: stamp target position and maximum length overflow uint64")
	}
	if imageBase != "" {
		switch addressSpace {
		case StampAddressSpacePERVA:
			if imageBaseValue > math.MaxUint64-positionValue ||
				imageBaseValue+positionValue > math.MaxUint64-maximum {
				return errors.New("pki: image base, relative address, and maximum length overflow uint64")
			}
		case StampAddressSpaceELFVirtual, StampAddressSpaceMachOVM:
			if positionValue < imageBaseValue {
				return errors.New("pki: virtual address precedes its image base")
			}
		}
	}
	return nil
}

func validateBoundedTarget(
	maximumLength CanonicalUint64,
	remainderPolicy StampRemainderPolicy,
	precondition StampPrecondition,
) (uint64, error) {
	maximum, err := maximumLength.Uint64()
	if err != nil {
		return 0, err
	}
	if maximum == 0 || maximum > MaximumBundleBinaryBytes {
		return 0, errors.New("pki: stamp target maximum length is invalid")
	}
	if err := remainderPolicy.Validate(); err != nil {
		return 0, err
	}
	if err := precondition.Validate(); err != nil {
		return 0, err
	}
	if precondition.Kind == StampPreconditionBytes && uint64(len(precondition.Bytes)) > maximum {
		return 0, errors.New("pki: stamp precondition exceeds the target maximum length")
	}
	if precondition.Kind == StampPreconditionSHA256 {
		length, err := precondition.Length.Uint64()
		if err != nil {
			return 0, err
		}
		if length > maximum {
			return 0, errors.New("pki: stamp precondition hash length exceeds the target maximum length")
		}
	}
	return maximum, nil
}

func stampTargetCapacity(
	target StampTarget,
) (uint64, StampRemainderPolicy, bool, error) {
	switch target.Kind {
	case StampTargetFileOffset:
		maximum, err := target.FileOffset.MaximumLength.Uint64()
		return maximum, target.FileOffset.RemainderPolicy, true, err
	case StampTargetVirtualAddress:
		maximum, err := target.VirtualAddress.MaximumLength.Uint64()
		return maximum, target.VirtualAddress.RemainderPolicy, true, err
	case StampTargetSymbol:
		maximum, err := target.Symbol.MaximumLength.Uint64()
		return maximum, target.Symbol.RemainderPolicy, true, err
	case StampTargetMarker:
		maximum, err := target.Marker.MaximumLength.Uint64()
		return maximum, target.Marker.RemainderPolicy, true, err
	case StampTargetBytePattern:
		maximum, err := target.BytePattern.MaximumLength.Uint64()
		return maximum, target.BytePattern.RemainderPolicy, true, err
	case StampTargetNamedSlot, StampTargetProviderDefined:
		return 0, "", false, nil
	default:
		return 0, "", false, fmt.Errorf("pki: unsupported stamp target kind %q", target.Kind)
	}
}

func allBytesZero(values []byte) bool {
	return !slices.ContainsFunc(values, func(value byte) bool { return value != 0 })
}

func validateProviderEnvelope(
	providerID DeliveryProviderID,
	schemaVersion string,
	value json.RawMessage,
	label string,
) error {
	if err := providerID.Validate(); err != nil {
		return err
	}
	if err := validateProviderSchemaVersion(schemaVersion, label); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > MaximumProviderTargetBytes || !json.Valid(value) {
		return fmt.Errorf("pki: %s value is invalid", label)
	}
	if err := validateUniqueJSONObject(value, label); err != nil {
		return err
	}
	return nil
}

func strictDecodeJSONObject(data []byte, maximum int, destination any, label string) error {
	if len(data) == 0 || len(data) > maximum {
		return fmt.Errorf("pki: %s json has an invalid size", label)
	}
	if err := validateUniqueJSONObject(data, label); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("pki: decode %s: %w", label, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("pki: %s contains trailing json data", label)
	}
	return nil
}

func validateUniqueJSONObject(data []byte, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	object, err := consumeUniqueJSONValue(decoder)
	if err != nil {
		return fmt.Errorf("pki: %s value is invalid: %w", label, err)
	}
	if !object {
		return fmt.Errorf("pki: %s value must be a JSON object", label)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("pki: %s contains trailing json data", label)
		}
		return fmt.Errorf("pki: %s value is invalid: %w", label, err)
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("json object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return false, fmt.Errorf("duplicate json object key %q", key)
			}
			seen[key] = struct{}{}
			if _, err := consumeUniqueJSONValue(decoder); err != nil {
				return false, err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return false, errors.New("json object is not closed")
		}
		return true, nil
	case '[':
		for decoder.More() {
			if _, err := consumeUniqueJSONValue(decoder); err != nil {
				return false, err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return false, errors.New("json array is not closed")
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected json delimiter %q", delimiter)
	}
}

func rejectInactiveVariantJSONFields(
	data []byte,
	active string,
	variants []string,
	label string,
) error {
	return rejectDisallowedVariantJSONFields(data, []string{active}, variants, label)
}

func rejectDisallowedVariantJSONFields(
	data []byte,
	allowed []string,
	variants []string,
	label string,
) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("pki: decode %s fields: %w", label, err)
	}
	for _, variant := range variants {
		if _, present := fields[variant]; present && !slices.Contains(allowed, variant) {
			return fmt.Errorf("pki: %s contains inactive variant field %q", label, variant)
		}
	}
	return nil
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
		return "", errors.New("pki: credential material reference cannot contain provider or literal material")
	default:
		return "", fmt.Errorf("pki: unsupported credential projection %q", projection)
	}
}

func stampTargetVariantJSONField(kind StampTargetKind) (string, error) {
	switch kind {
	case StampTargetNamedSlot:
		return "namedSlot", nil
	case StampTargetFileOffset:
		return "fileOffset", nil
	case StampTargetVirtualAddress:
		return "virtualAddress", nil
	case StampTargetSymbol:
		return "symbol", nil
	case StampTargetMarker:
		return "marker", nil
	case StampTargetBytePattern:
		return "bytePattern", nil
	case StampTargetProviderDefined:
		return "providerDefined", nil
	default:
		return "", fmt.Errorf("pki: unsupported stamp target kind %q", kind)
	}
}

func stampMaterialVariantJSONField(projection CredentialProjection) (string, error) {
	switch projection {
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionChainDER, CredentialProjectionTrustDER,
		CredentialProjectionCRLDER, CredentialProjectionSignerReference:
		return "credential", nil
	case CredentialProjectionProviderEncoding:
		return "providerEncoding", nil
	case CredentialProjectionLiteralReference:
		return "literalReference", nil
	default:
		return "", fmt.Errorf("pki: unsupported credential projection %q", projection)
	}
}

func stampTargetVariantCount(target StampTarget) int {
	count := 0
	for _, present := range []bool{
		target.NamedSlot != nil, target.FileOffset != nil,
		target.VirtualAddress != nil, target.Symbol != nil, target.Marker != nil,
		target.BytePattern != nil, target.ProviderDefined != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func stampMaterialVariantCount(material StampMaterial) int {
	count := 0
	for _, present := range []bool{
		material.Credential != nil, material.ProviderEncoding != nil,
		material.LiteralReference != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func credentialMaterialReferenceVariantCount(reference CredentialMaterialReference) int {
	count := 0
	for _, present := range []bool{
		reference.BundleID != "", reference.GenerationID != "",
		len(reference.GenerationIDs) != 0, reference.TrustSetGenerationID != "",
		len(reference.CRLGenerationIDs) != 0,
	} {
		if present {
			count++
		}
	}
	return count
}

func validateGenerationIDList(ids []GenerationID, label string) error {
	if len(ids) == 0 || len(ids) > MaximumBundleChainMembers {
		return fmt.Errorf("pki: %s generation ids are empty or exceed limits", label)
	}
	seen := make(map[GenerationID]struct{}, len(ids))
	for _, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("pki: %s generation ids contain a duplicate", label)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateCRLGenerationIDList(ids []CRLGenerationID) error {
	if len(ids) == 0 || len(ids) > MaximumBundleCRLMembers {
		return errors.New("pki: stamp crl generation ids are empty or exceed limits")
	}
	seen := make(map[CRLGenerationID]struct{}, len(ids))
	for _, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("pki: stamp crl generation ids contain a duplicate")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return true
		}
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateProfileIDs(values []ProfileID) bool {
	seen := make(map[ProfileID]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateCompatibilityTargetIDs(values []CompatibilityTargetID) bool {
	seen := make(map[CompatibilityTargetID]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateCredentialProjections(values []CredentialProjection) bool {
	seen := make(map[CredentialProjection]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateCredentialMaterialForms(values []CredentialMaterialForm) bool {
	seen := make(map[CredentialMaterialForm]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateDeliveryCapabilities(values []DeliveryCapability) bool {
	seen := make(map[DeliveryCapability]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateStampTargetKinds(values []StampTargetKind) bool {
	seen := make(map[StampTargetKind]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func hasDuplicateAddressSpaces(values []StampAddressSpace) bool {
	seen := make(map[StampAddressSpace]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
