package hovel

// CredentialDeliverySchemaV1 is the versioned provider credential-delivery
// descriptor understood by Hovel.
const CredentialDeliverySchemaV1 = "hovel.pki.credential-delivery/v1"

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

// CredentialDescriber is implemented by modules that advertise credential
// delivery independently of Mesh. A module may implement this interface, a
// Mesh surface, or both.
type CredentialDescriber interface {
	Module
	DescribeCredentialDelivery() (CredentialDeliveryDescriptor, error)
}
