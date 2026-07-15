package pki

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonicalUint64(t *testing.T) {
	t.Parallel()

	maximum := NewCanonicalUint64(math.MaxUint64)
	if maximum != "18446744073709551615" {
		t.Fatalf("NewCanonicalUint64(MaxUint64) = %q", maximum)
	}
	value, err := maximum.Uint64()
	if err != nil {
		t.Fatal(err)
	}
	if value != math.MaxUint64 {
		t.Fatalf("CanonicalUint64.Uint64() = %d, want %d", value, uint64(math.MaxUint64))
	}

	for _, input := range []string{"", " 1", "1 ", "+1", "01", "-1", "18446744073709551616"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseCanonicalUint64(input); err == nil {
				t.Fatalf("ParseCanonicalUint64(%q) accepted a noncanonical value", input)
			}
		})
	}
}

func TestCredentialDeliveryDescriptor(t *testing.T) {
	t.Parallel()

	standard := validCredentialDeliveryDescriptor()
	if err := standard.Validate(); err != nil {
		t.Fatalf("valid standard descriptor: %v", err)
	}

	advanced := validCredentialDeliveryDescriptor()
	advanced.Capabilities = []DeliveryCapability{DeliveryCapabilityRuntime, DeliveryCapabilityStampAdvanced}
	advanced.StampTargetKinds = []StampTargetKind{
		StampTargetNamedSlot,
		StampTargetFileOffset,
		StampTargetVirtualAddress,
		StampTargetProviderDefined,
	}
	advanced.AddressSpaces = []StampAddressSpace{StampAddressSpaceFile, StampAddressSpacePERVA}
	advanced.ProviderTargetSchemas = []ProviderTargetSchema{{
		ProviderID:    "mbedtls-image",
		SchemaVersion: "v1",
		JSONSchema:    json.RawMessage(`{"type":"object"}`),
	}}
	if err := advanced.Validate(); err != nil {
		t.Fatalf("valid advanced descriptor: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialDeliveryDescriptor)
	}{
		{name: "unknown schema", mutate: func(value *CredentialDeliveryDescriptor) { value.SchemaVersion = "v2" }},
		{name: "duplicate slot", mutate: func(value *CredentialDeliveryDescriptor) { value.Slots = append(value.Slots, value.Slots[0]) }},
		{name: "duplicate capability", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = append(value.Capabilities, DeliveryCapabilityStampStandard)
		}},
		{name: "none mixed", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = append(value.Capabilities, DeliveryCapabilityNone)
		}},
		{name: "none with metadata", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = []DeliveryCapability{DeliveryCapabilityNone}
		}},
		{name: "missing slots", mutate: func(value *CredentialDeliveryDescriptor) { value.Slots = nil }},
		{name: "targets without capability", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = []DeliveryCapability{DeliveryCapabilityRuntime}
		}},
		{name: "standard missing named slot", mutate: func(value *CredentialDeliveryDescriptor) {
			value.StampTargetKinds = []StampTargetKind{StampTargetFileOffset}
		}},
		{name: "advanced target without advanced capability", mutate: func(value *CredentialDeliveryDescriptor) {
			value.StampTargetKinds = append(value.StampTargetKinds, StampTargetFileOffset)
		}},
		{name: "address spaces without virtual target", mutate: func(value *CredentialDeliveryDescriptor) {
			value.AddressSpaces = []StampAddressSpace{StampAddressSpacePERVA}
		}},
		{name: "virtual target without address spaces", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = []DeliveryCapability{DeliveryCapabilityStampAdvanced}
			value.StampTargetKinds = []StampTargetKind{StampTargetVirtualAddress}
		}},
		{name: "provider target without schema", mutate: func(value *CredentialDeliveryDescriptor) {
			value.Capabilities = []DeliveryCapability{DeliveryCapabilityStampAdvanced}
			value.StampTargetKinds = []StampTargetKind{StampTargetProviderDefined}
		}},
		{name: "schema without provider target", mutate: func(value *CredentialDeliveryDescriptor) {
			value.ProviderTargetSchemas = []ProviderTargetSchema{{ProviderID: "provider", SchemaVersion: "v1", JSONSchema: json.RawMessage(`{}`)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := standard.Clone()
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("CredentialDeliveryDescriptor.Validate() accepted an invalid contract")
			}
		})
	}
}

func TestCredentialSlotRejectsContradictoryPrivateMaterialPolicy(t *testing.T) {
	t.Parallel()

	slot := validCredentialSlot()
	slot.PrivateMaterial = PrivateMaterialForbidden
	slot.AcceptedProjections = append(slot.AcceptedProjections, CredentialProjectionPrivateKeyPKCS8)
	if err := slot.Validate(); err == nil {
		t.Fatal("CredentialSlot.Validate() accepted private material under a forbidden policy")
	}

	slot = validCredentialSlot()
	slot.PrivateMaterial = PrivateMaterialRequired
	slot.AcceptedMaterialForms = []CredentialMaterialForm{
		CredentialMaterialPrivateReference, CredentialMaterialPrivateBytes,
	}
	if err := slot.Validate(); err != nil {
		t.Fatalf("CredentialSlot.Validate() rejected a required private bundle: %v", err)
	}

	slot.AcceptedProjections = []CredentialProjection{CredentialProjectionCertificateDER}
	if err := slot.Validate(); err == nil {
		t.Fatal("CredentialSlot.Validate() accepted a required private policy without a private projection")
	}
}

func TestCredentialSlotPurposeRoleAndBounds(t *testing.T) {
	t.Parallel()

	slot := validCredentialSlot()
	slot.EndpointRole = CredentialEndpointClient
	if err := slot.Validate(); err == nil {
		t.Fatal("CredentialSlot.Validate() accepted a client role for a server purpose")
	}

	slot = validCredentialSlot()
	slot.AcceptedProfiles = make([]ProfileID, MaximumCredentialSlotValues+1)
	for i := range slot.AcceptedProfiles {
		slot.AcceptedProfiles[i] = ProfileID("profile-" + NewCanonicalUint64(uint64(i)))
	}
	if err := slot.Validate(); err == nil {
		t.Fatal("CredentialSlot.Validate() accepted an unbounded profile list")
	}
}

func TestCredentialDeliveryDescriptorValidatesRequests(t *testing.T) {
	t.Parallel()

	descriptor := validCredentialDeliveryDescriptor()
	namedTarget, err := NewNamedSlotStampTarget(NamedSlotTarget{Name: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	if err := descriptor.ValidateTarget(namedTarget); err != nil {
		t.Fatalf("ValidateTarget(named slot) error = %v", err)
	}
	fileTarget, err := NewFileOffsetStampTarget(FileOffsetTarget{
		Offset: "0", MaximumLength: "16", Alignment: "1",
		RemainderPolicy: StampRemainderPreserve,
		Precondition:    StampPrecondition{Kind: StampPreconditionNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := descriptor.ValidateTarget(fileTarget); err == nil {
		t.Fatal("ValidateTarget() accepted an unadvertised file-offset target")
	}

	privateBundle := credentialStampMaterial(CredentialMaterialReference{
		Projection: CredentialProjectionBundle, Form: CredentialMaterialPrivateBytes, BundleID: "bundle-1",
	})
	if err := descriptor.ValidateMaterial("tls-server", privateBundle, 1024); err != nil {
		t.Fatalf("ValidateMaterial(private bundle) error = %v", err)
	}
	forbidden := descriptor.Clone()
	forbidden.Slots[0].PrivateMaterial = PrivateMaterialForbidden
	forbidden.Slots[0].AcceptedMaterialForms = []CredentialMaterialForm{CredentialMaterialPublic}
	if err := forbidden.ValidateMaterial("tls-server", privateBundle, 1024); err == nil {
		t.Fatal("ValidateMaterial() accepted private bytes for a forbidden slot")
	}
	if err := descriptor.ValidateMaterial("tls-server", privateBundle, MaximumBundleJSONBytes+1); err == nil {
		t.Fatal("ValidateMaterial() accepted oversized encoded material")
	}

	request := CredentialStampRequest{
		AssignmentID: "assignment-1",
		Capability:   DeliveryCapabilityStampStandard,
		SlotName:     "tls-server",
		Target:       namedTarget,
		Material:     privateBundle,
		EncodedBytes: 1024,
		Credential: ResolvedCredentialMetadata{
			BundleVersion: BundleSchemaV1, Purpose: PurposeTLSServer,
			ConsumerType: ConsumerMeshListener, ProfileID: ProfileTLSServer,
			CompatibilityTargetID: CompatibilityPortableX509,
		},
	}
	if err := descriptor.ValidateStampRequest(request); err != nil {
		t.Fatalf("ValidateStampRequest() error = %v", err)
	}
	mismatchedTarget, err := NewNamedSlotStampTarget(NamedSlotTarget{Name: "other-slot"})
	if err != nil {
		t.Fatal(err)
	}
	request.Target = mismatchedTarget
	if err := descriptor.ValidateStampRequest(request); err == nil {
		t.Fatal("ValidateStampRequest() accepted a mismatched named slot")
	}
	request.Target = namedTarget
	request.Credential.ProfileID = ProfileTLSClient
	if err := descriptor.ValidateStampRequest(request); err == nil {
		t.Fatal("ValidateStampRequest() accepted incompatible resolved metadata")
	}

	advanced := descriptor.Clone()
	advanced.Capabilities = []DeliveryCapability{DeliveryCapabilityStampAdvanced}
	advanced.StampTargetKinds = []StampTargetKind{StampTargetFileOffset}
	advanced.AddressSpaces = []StampAddressSpace{StampAddressSpaceFile}
	request.Capability = DeliveryCapabilityStampAdvanced
	request.Target, err = NewFileOffsetStampTarget(FileOffsetTarget{
		Offset: "0", MaximumLength: "16", Alignment: "1",
		RemainderPolicy: StampRemainderRequireExact,
		Precondition:    StampPrecondition{Kind: StampPreconditionNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Credential.ProfileID = ProfileTLSServer
	request.EncodedBytes = 15
	if err := advanced.ValidateStampRequest(request); err == nil {
		t.Fatal("ValidateStampRequest() ignored require-exact target capacity")
	}
	request.EncodedBytes = 16
	if err := advanced.ValidateStampRequest(request); err != nil {
		t.Fatalf("ValidateStampRequest(exact advanced target) error = %v", err)
	}

	encoded := descriptor.Clone()
	encoded.Slots[0].AcceptedProjections = []CredentialProjection{CredentialProjectionProviderEncoding}
	encoded.ProviderEncodingSchemas = []ProviderEncodingSchema{{
		ProviderID: "mbedtls-image", SchemaVersion: "v1",
		AcceptedSourceProjections: []CredentialProjection{CredentialProjectionCertificateDER},
		AcceptedSourceForms:       []CredentialMaterialForm{CredentialMaterialPublic},
		OutputForms:               []CredentialMaterialForm{CredentialMaterialPublic},
	}}
	providerMaterial := StampMaterial{
		Projection: CredentialProjectionProviderEncoding,
		ProviderEncoding: &ProviderEncodingMaterial{
			ProviderID: "mbedtls-image", SchemaVersion: "v1", Form: CredentialMaterialPublic,
			Source: CredentialMaterialReference{
				Projection:   CredentialProjectionCertificateDER,
				Form:         CredentialMaterialPublic,
				GenerationID: "generation-1",
			},
		},
	}
	if err := encoded.ValidateMaterial("tls-server", providerMaterial, 1024); err != nil {
		t.Fatalf("ValidateMaterial(provider encoding) error = %v", err)
	}
	encoded.ProviderEncodingSchemas[0].SchemaVersion = "v2"
	if err := encoded.ValidateMaterial("tls-server", providerMaterial, 1024); err == nil {
		t.Fatal("ValidateMaterial() accepted an unadvertised provider encoding")
	}
}

func TestStampTargets(t *testing.T) {
	t.Parallel()

	valid := []StampTarget{
		{Kind: StampTargetNamedSlot, NamedSlot: &NamedSlotTarget{Name: "tls-server"}},
		{Kind: StampTargetFileOffset, FileOffset: &FileOffsetTarget{
			Offset: "8", MaximumLength: "16", Alignment: "8",
			RemainderPolicy: StampRemainderZeroFill,
			Precondition:    StampPrecondition{Kind: StampPreconditionBytes, Bytes: []byte{1, 2}},
		}},
		{Kind: StampTargetVirtualAddress, VirtualAddress: &VirtualAddressTarget{
			Address: "4096", AddressSpace: StampAddressSpacePERVA, ImageBase: "4194304",
			MaximumLength: "32", Alignment: "16", RemainderPolicy: StampRemainderRequireExact,
			Precondition: StampPrecondition{Kind: StampPreconditionNone},
		}},
		{Kind: StampTargetSymbol, Symbol: &SymbolTarget{
			Name: "hovel_tls_bundle", Section: ".data", MaximumLength: "1024",
			RemainderPolicy: StampRemainderPreserve,
			Precondition: StampPrecondition{
				Kind: StampPreconditionSHA256, SHA256: strings.Repeat("a", 64), Length: "1024",
			},
		}},
		{Kind: StampTargetMarker, Marker: &MarkerTarget{
			Marker: []byte("HOVEL_TLS_SLOT"), MaximumLength: "1024",
			RemainderPolicy: StampRemainderZeroFill,
			Precondition:    StampPrecondition{Kind: StampPreconditionNone},
		}},
		{Kind: StampTargetBytePattern, BytePattern: &BytePatternTarget{
			Pattern: []byte{0xaa, 0xbb}, Mask: []byte{0xff, 0xf0}, MaximumLength: "1024",
			RemainderPolicy: StampRemainderPreserve,
			Precondition:    StampPrecondition{Kind: StampPreconditionNone},
		}},
		{Kind: StampTargetProviderDefined, ProviderDefined: &ProviderDefinedTarget{
			ProviderID: "mbedtls-image", SchemaVersion: "v1", Value: json.RawMessage(`{"region":"config"}`),
		}},
	}
	for _, target := range valid {
		if err := target.Validate(); err != nil {
			t.Errorf("StampTarget(%q).Validate() error = %v", target.Kind, err)
		}
	}

	invalid := []StampTarget{
		{Kind: StampTargetNamedSlot},
		{Kind: StampTargetNamedSlot, NamedSlot: &NamedSlotTarget{Name: "tls-server"}, Symbol: &SymbolTarget{}},
		{Kind: StampTargetFileOffset, FileOffset: &FileOffsetTarget{Offset: "3", MaximumLength: "8", Alignment: "2", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetFileOffset, FileOffset: &FileOffsetTarget{Offset: "18446744073709551615", MaximumLength: "1", Alignment: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetFileOffset, FileOffset: &FileOffsetTarget{Offset: "0", MaximumLength: "1", Alignment: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionBytes, Bytes: []byte{1, 2}}}},
		{Kind: StampTargetSymbol, Symbol: &SymbolTarget{Name: "symbol", Section: " .data", MaximumLength: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetBytePattern, BytePattern: &BytePatternTarget{Pattern: []byte{1}, Mask: []byte{0}, MaximumLength: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetProviderDefined, ProviderDefined: &ProviderDefinedTarget{ProviderID: "provider", SchemaVersion: "v1", Value: json.RawMessage(`[]`)}},
		{Kind: StampTargetProviderDefined, ProviderDefined: &ProviderDefinedTarget{ProviderID: "provider", SchemaVersion: "v1", Value: json.RawMessage(`{"outer":{"key":1,"key":2}}`)}},
		{Kind: StampTargetVirtualAddress, VirtualAddress: &VirtualAddressTarget{Address: "0", AddressSpace: StampAddressSpaceFile, MaximumLength: "1", Alignment: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetVirtualAddress, VirtualAddress: &VirtualAddressTarget{Address: "1", AddressSpace: StampAddressSpacePERVA, ImageBase: "18446744073709551615", MaximumLength: "1", Alignment: "1", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionNone}}},
		{Kind: StampTargetSymbol, Symbol: &SymbolTarget{Name: "symbol", MaximumLength: "8", RemainderPolicy: StampRemainderPreserve, Precondition: StampPrecondition{Kind: StampPreconditionSHA256, SHA256: strings.Repeat("a", 64)}}},
	}
	for i, target := range invalid {
		if err := target.Validate(); err == nil {
			t.Errorf("invalid StampTarget[%d] passed validation", i)
		}
	}
}

func TestDeliveryJSONFailsClosed(t *testing.T) {
	t.Parallel()

	target, err := NewNamedSlotStampTarget(NamedSlotTarget{Name: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	encodedTarget, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	decodedTarget, err := DecodeStampTargetJSON(encodedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if decodedTarget.NamedSlot == nil || decodedTarget.NamedSlot.Name != "tls-server" {
		t.Fatalf("decoded target = %#v", decodedTarget)
	}

	invalidTargets := []string{
		`{"kind":"named-slot","namedSlot":{"name":"tls-server"},"unknown":true}`,
		`{"kind":"named-slot","namedSlot":{"name":"tls-server"},"symbol":null}`,
		`{"kind":"provider-defined","providerDefined":{"providerId":"provider","schemaVersion":"v1","value":{"key":1,"key":2}}}`,
		`{"kind":"file-offset","fileOffset":{"offset":"0","maximumLength":"8","alignment":"1","remainderPolicy":"preserve","precondition":{"kind":"bytes","bytes":"AQ==","sha256":null}}}`,
	}
	for _, data := range invalidTargets {
		if _, err := DecodeStampTargetJSON([]byte(data)); err == nil {
			t.Errorf("DecodeStampTargetJSON() accepted %s", data)
		}
	}

	material := credentialStampMaterial(CredentialMaterialReference{
		Projection:   CredentialProjectionCertificateDER,
		Form:         CredentialMaterialPublic,
		GenerationID: "generation-1",
	})
	encodedMaterial, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStampMaterialJSON(encodedMaterial); err != nil {
		t.Fatalf("DecodeStampMaterialJSON() error = %v", err)
	}
	if _, err := DecodeStampMaterialJSON([]byte(
		`{"projection":"certificate-der","credential":{"projection":"certificate-der","form":"public","generationId":"generation-1"},"literalReference":null}`,
	)); err == nil {
		t.Fatal("DecodeStampMaterialJSON() accepted an inactive null variant")
	}
	if _, err := DecodeStampMaterialJSON([]byte(
		`{"projection":"certificate-der","credential":{"projection":"certificate-der","form":"public","generationId":"generation-1","generationIds":null}}`,
	)); err == nil {
		t.Fatal("DecodeStampMaterialJSON() accepted a nested inactive null variant")
	}

	descriptorJSON, err := json.Marshal(validCredentialDeliveryDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialDeliveryDescriptorJSON(descriptorJSON); err != nil {
		t.Fatalf("DecodeCredentialDeliveryDescriptorJSON() error = %v", err)
	}
	if _, err := DecodeCredentialDeliveryDescriptorJSON([]byte(
		`{"schemaVersion":"hovel.pki.delivery/v1","credentialSlots":[{"name":"tls-server","purpose":"tls-server","endpointRole":"server","consumerType":"mesh-listener","acceptedBundleVersions":["hovel.pki.bundle/v1"],"acceptedProfiles":["tls-server"],"acceptedCompatibilityTargets":["portable-x509"],"acceptedProjections":["bundle"],"acceptedMaterialForms":["public"],"maximumEncodedBytes":32,"remainderPolicy":"preserve","privateMaterial":"allowed","unknown":true}],"deliveryCapabilities":["stamp-standard"],"stampTargetKinds":["named-slot"]}`,
	)); err == nil {
		t.Fatal("DecodeCredentialDeliveryDescriptorJSON() accepted a nested unknown field")
	}
}

func TestStampMaterials(t *testing.T) {
	t.Parallel()

	valid := []StampMaterial{
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionBundle, Form: CredentialMaterialPrivateBytes, BundleID: "bundle-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionCertificateDER, Form: CredentialMaterialPublic, GenerationID: "generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionPrivateKeyPKCS8, Form: CredentialMaterialPrivateBytes, GenerationID: "generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionPublicKeySPKI, Form: CredentialMaterialPublic, GenerationID: "generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionSignerReference, Form: CredentialMaterialPrivateReference, GenerationID: "generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionChainDER, Form: CredentialMaterialPublic,
			GenerationIDs: []GenerationID{"generation-1", "generation-2"},
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionTrustDER, Form: CredentialMaterialPublic, TrustSetGenerationID: "trust-generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionCRLDER, Form: CredentialMaterialPublic, CRLGenerationIDs: []CRLGenerationID{"crl-generation-1"},
		}),
		{Projection: CredentialProjectionProviderEncoding, ProviderEncoding: &ProviderEncodingMaterial{
			ProviderID: "mbedtls-image", SchemaVersion: "v1", Form: CredentialMaterialPublic,
			Source: CredentialMaterialReference{
				Projection: CredentialProjectionCertificateDER, Form: CredentialMaterialPublic, GenerationID: "generation-1",
			},
		}},
		{Projection: CredentialProjectionLiteralReference, LiteralReference: &LiteralMaterialReference{
			Reference: "secret-store/material-1", SHA256: strings.Repeat("b", 64),
			Form: CredentialMaterialPrivateBytes,
		}},
	}
	for _, material := range valid {
		if err := material.Validate(); err != nil {
			t.Errorf("StampMaterial(%q).Validate() error = %v", material.Projection, err)
		}
	}

	invalid := []StampMaterial{
		{Projection: CredentialProjectionBundle},
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionBundle, Form: CredentialMaterialPublic,
			BundleID: "bundle-1", GenerationID: "generation-1",
		}),
		credentialStampMaterial(CredentialMaterialReference{
			Projection: CredentialProjectionChainDER, Form: CredentialMaterialPublic,
			GenerationIDs: []GenerationID{"generation-1", "generation-1"},
		}),
		{Projection: CredentialProjectionProviderEncoding, ProviderEncoding: &ProviderEncodingMaterial{
			ProviderID: "provider", SchemaVersion: "v1", Form: CredentialMaterialPublic,
			Source: CredentialMaterialReference{
				Projection: CredentialProjectionProviderEncoding, Form: CredentialMaterialPublic, BundleID: "bundle-1",
			},
		}},
		{Projection: CredentialProjectionLiteralReference, LiteralReference: &LiteralMaterialReference{Reference: "reference-1", SHA256: "not-a-hash"}},
	}
	for i, material := range invalid {
		if err := material.Validate(); err == nil {
			t.Errorf("invalid StampMaterial[%d] passed validation", i)
		}
	}
}

func TestDeliveryContractClonesDefensively(t *testing.T) {
	t.Parallel()

	descriptor := validCredentialDeliveryDescriptor()
	descriptor.ProviderTargetSchemas = []ProviderTargetSchema{{
		ProviderID: "provider", SchemaVersion: "v1", JSONSchema: json.RawMessage(`{"type":"object"}`),
	}}
	clone := descriptor.Clone()
	clone.Slots[0].AcceptedBundleVersions[0] = "changed"
	clone.Capabilities[0] = DeliveryCapabilityNone
	clone.ProviderTargetSchemas[0].JSONSchema[0] = '['
	if descriptor.Slots[0].AcceptedBundleVersions[0] != BundleSchemaV1 ||
		descriptor.Capabilities[0] != DeliveryCapabilityStampStandard ||
		descriptor.ProviderTargetSchemas[0].JSONSchema[0] != '{' {
		t.Fatal("CredentialDeliveryDescriptor.Clone() aliased mutable state")
	}

	target := StampTarget{Kind: StampTargetBytePattern, BytePattern: &BytePatternTarget{
		Pattern: []byte{1}, Mask: []byte{0xff}, MaximumLength: "2",
		RemainderPolicy: StampRemainderPreserve,
		Precondition:    StampPrecondition{Kind: StampPreconditionBytes, Bytes: []byte{2}},
	}}
	targetClone := target.Clone()
	targetClone.BytePattern.Pattern[0] = 3
	targetClone.BytePattern.Precondition.Bytes[0] = 4
	if target.BytePattern.Pattern[0] != 1 || target.BytePattern.Precondition.Bytes[0] != 2 {
		t.Fatal("StampTarget.Clone() aliased mutable state")
	}

	material := credentialStampMaterial(CredentialMaterialReference{
		Projection: CredentialProjectionChainDER, Form: CredentialMaterialPublic,
		GenerationIDs: []GenerationID{"generation-1"},
	})
	materialClone := material.Clone()
	materialClone.Credential.GenerationIDs[0] = "generation-2"
	if material.Credential.GenerationIDs[0] != "generation-1" {
		t.Fatal("StampMaterial.Clone() aliased mutable state")
	}
}

func validCredentialDeliveryDescriptor() CredentialDeliveryDescriptor {
	return CredentialDeliveryDescriptor{
		SchemaVersion:    CredentialDeliverySchemaV1,
		Slots:            []CredentialSlot{validCredentialSlot()},
		Capabilities:     []DeliveryCapability{DeliveryCapabilityStampStandard},
		StampTargetKinds: []StampTargetKind{StampTargetNamedSlot},
	}
}

func validCredentialSlot() CredentialSlot {
	return CredentialSlot{
		Name:                         "tls-server",
		Purpose:                      PurposeTLSServer,
		EndpointRole:                 CredentialEndpointServer,
		ConsumerType:                 ConsumerMeshListener,
		AcceptedBundleVersions:       []string{BundleSchemaV1},
		AcceptedProfiles:             []ProfileID{ProfileTLSServer},
		AcceptedCompatibilityTargets: []CompatibilityTargetID{CompatibilityPortableX509},
		AcceptedProjections:          []CredentialProjection{CredentialProjectionBundle},
		AcceptedMaterialForms: []CredentialMaterialForm{
			CredentialMaterialPublic,
			CredentialMaterialPrivateReference,
			CredentialMaterialPrivateBytes,
		},
		MaximumEncodedBytes: MaximumBundleJSONBytes,
		RemainderPolicy:     StampRemainderPreserve,
		PrivateMaterial:     PrivateMaterialAllowed,
	}
}

func credentialStampMaterial(reference CredentialMaterialReference) StampMaterial {
	return StampMaterial{Projection: reference.Projection, Credential: &reference}
}
