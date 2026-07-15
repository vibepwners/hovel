from __future__ import annotations

import base64
import json
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

CREDENTIAL_DELIVERY_SCHEMA_V1 = "hovel.pki.credential-delivery/v1"
_CREDENTIAL_RPC_DESCRIBE_METHOD = "credential.describe"
_MAXIMUM_CREDENTIAL_BINARY_BYTES = 24 << 20
_MAXIMUM_CREDENTIAL_EXECUTION_FILES = 64
_MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES = 64
_MAXIMUM_CREDENTIAL_STAMP_DIGESTS = 128
_MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES = 1 << 20
_MAXIMUM_CREDENTIAL_RECEIPT_BYTES = _MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES
_MAXIMUM_CREDENTIAL_PROVIDER_TARGET_BYTES = 1 << 20
_MAXIMUM_CREDENTIAL_ID_BYTES = 256
_MAXIMUM_CREDENTIAL_NAME_BYTES = 512
_MAXIMUM_CREDENTIAL_PATH_BYTES = 4096
_MAXIMUM_CREDENTIAL_ENCODING_BYTES = 256
_MAXIMUM_CREDENTIAL_REFERENCE_LIST = 32
_MAXIMUM_UINT32 = (1 << 32) - 1
_MAXIMUM_UINT64 = (1 << 64) - 1
_SHA256_HEX_BYTES = 64
_SHA256_BYTES = 32
_INTEGER_BOUNDS = {
    "encodedBytes": (1, _MAXIMUM_CREDENTIAL_BINARY_BYTES),
    "maximumEncodedBytes": (1, _MAXIMUM_CREDENTIAL_BINARY_BYTES),
    "occurrence": (0, _MAXIMUM_UINT32),
    "size": (1, _MAXIMUM_CREDENTIAL_BINARY_BYTES),
}


class CredentialDeliveryCapability(StrEnum):
    NONE = "none"
    RUNTIME = "runtime"
    FILES = "files"
    STAMP_STANDARD = "stamp-standard"
    STAMP_ADVANCED = "stamp-advanced"


class CredentialPurpose(StrEnum):
    TLS_SERVER = "tls-server"
    TLS_CLIENT = "tls-client"
    MTLS_SERVER = "mtls-server"
    MTLS_CLIENT = "mtls-client"
    DUAL_ROLE_MTLS = "dual-role-mtls"
    CODE_SIGNING = "code-signing"
    CUSTOM = "custom"


class CredentialEndpointRole(StrEnum):
    SERVER = "server"
    CLIENT = "client"
    DUAL = "dual"
    NOT_APPLICABLE = "not-applicable"


class CredentialConsumerType(StrEnum):
    MESH_PROVIDER = "mesh-provider"
    MESH_LISTENER = "mesh-listener"
    LISTENING_POST = "listening-post"
    MESH_NODE = "mesh-node"
    IMPLANT = "implant"
    STAGER = "stager"
    PAYLOAD = "payload"
    C2_SERVICE = "c2-service"
    SERVICE = "service"
    EXTERNAL = "external"


class CredentialProjection(StrEnum):
    BUNDLE = "bundle"
    CERTIFICATE_DER = "certificate-der"
    PRIVATE_KEY_PKCS8 = "private-key-pkcs8"
    PUBLIC_KEY_SPKI = "public-key-spki"
    SIGNER_REFERENCE = "signer-reference"
    CHAIN_DER = "chain-der"
    TRUST_DER = "trust-der"
    CRL_DER = "crl-der"
    PROVIDER_ENCODING = "provider-encoding"
    LITERAL_REFERENCE = "literal-reference"


class CredentialMaterialForm(StrEnum):
    PUBLIC = "public"
    PRIVATE_REFERENCE = "private-reference"
    PRIVATE_BYTES = "private-bytes"


class CredentialPrivateMaterialPolicy(StrEnum):
    FORBIDDEN = "forbidden"
    ALLOWED = "allowed"
    REQUIRED = "required"


class CredentialStampRemainderPolicy(StrEnum):
    PRESERVE = "preserve"
    ZERO_FILL = "zero-fill"
    REQUIRE_EXACT = "require-exact"


class CredentialStampTargetKind(StrEnum):
    NAMED_SLOT = "named-slot"
    FILE_OFFSET = "file-offset"
    VIRTUAL_ADDRESS = "virtual-address"
    SYMBOL = "symbol"
    MARKER = "marker"
    BYTE_PATTERN = "byte-pattern"
    PROVIDER_DEFINED = "provider-defined"


class CredentialStampAddressSpace(StrEnum):
    FILE = "file"
    ELF_VIRTUAL_ADDRESS = "elf-virtual-address"
    PE_RVA = "pe-rva"
    MACHO_VM_ADDRESS = "macho-vm-address"


class CredentialStampPreconditionKind(StrEnum):
    NONE = "none"
    BYTES = "bytes"
    SHA256 = "sha256"


@dataclass(frozen=True)
class CredentialStampPrecondition:
    kind: CredentialStampPreconditionKind
    bytes_value: bytes = field(default=b"", repr=False)
    sha256: str = ""
    length: str = ""

    def validate(self) -> None:
        """Reject contradictory or out-of-bounds precondition variants."""
        _validate_credential_stamp_precondition(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        out: dict[str, Any] = {"kind": self.kind.value}
        if self.bytes_value:
            out["bytes"] = base64.b64encode(self.bytes_value).decode("ascii")
        if self.sha256:
            out["sha256"] = self.sha256
        if self.length:
            out["length"] = self.length
        return out


@dataclass(frozen=True)
class CredentialNamedSlotTarget:
    name: str

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {"kind": CredentialStampTargetKind.NAMED_SLOT.value, "namedSlot": {"name": self.name}}


@dataclass(frozen=True)
class CredentialFileOffsetTarget:
    offset: str
    maximum_length: str
    alignment: str
    remainder_policy: CredentialStampRemainderPolicy
    precondition: CredentialStampPrecondition

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": CredentialStampTargetKind.FILE_OFFSET.value,
            "fileOffset": {
                "offset": self.offset,
                "maximumLength": self.maximum_length,
                "alignment": self.alignment,
                "remainderPolicy": self.remainder_policy.value,
                "precondition": self.precondition.to_rpc(),
            },
        }


@dataclass(frozen=True)
class CredentialVirtualAddressTarget:
    address: str
    address_space: CredentialStampAddressSpace
    maximum_length: str
    alignment: str
    remainder_policy: CredentialStampRemainderPolicy
    precondition: CredentialStampPrecondition
    image_base: str = ""

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        target: dict[str, Any] = {
            "address": self.address,
            "addressSpace": self.address_space.value,
            "maximumLength": self.maximum_length,
            "alignment": self.alignment,
            "remainderPolicy": self.remainder_policy.value,
            "precondition": self.precondition.to_rpc(),
        }
        if self.image_base:
            target["imageBase"] = self.image_base
        return {"kind": CredentialStampTargetKind.VIRTUAL_ADDRESS.value, "virtualAddress": target}


@dataclass(frozen=True)
class CredentialSymbolTarget:
    name: str
    maximum_length: str
    remainder_policy: CredentialStampRemainderPolicy
    precondition: CredentialStampPrecondition
    section: str = ""

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        target: dict[str, Any] = {
            "name": self.name,
            "maximumLength": self.maximum_length,
            "remainderPolicy": self.remainder_policy.value,
            "precondition": self.precondition.to_rpc(),
        }
        if self.section:
            target["section"] = self.section
        return {"kind": CredentialStampTargetKind.SYMBOL.value, "symbol": target}


@dataclass(frozen=True)
class CredentialMarkerTarget:
    marker: bytes = field(repr=False)
    occurrence: int = 0
    maximum_length: str = ""
    remainder_policy: CredentialStampRemainderPolicy = CredentialStampRemainderPolicy.PRESERVE
    precondition: CredentialStampPrecondition = CredentialStampPrecondition(CredentialStampPreconditionKind.NONE)

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": CredentialStampTargetKind.MARKER.value,
            "marker": {
                "marker": base64.b64encode(self.marker).decode("ascii"),
                "occurrence": self.occurrence,
                "maximumLength": self.maximum_length,
                "remainderPolicy": self.remainder_policy.value,
                "precondition": self.precondition.to_rpc(),
            },
        }


@dataclass(frozen=True)
class CredentialBytePatternTarget:
    pattern: bytes = field(repr=False)
    mask: bytes = field(repr=False)
    occurrence: int = 0
    maximum_length: str = ""
    remainder_policy: CredentialStampRemainderPolicy = CredentialStampRemainderPolicy.PRESERVE
    precondition: CredentialStampPrecondition = CredentialStampPrecondition(CredentialStampPreconditionKind.NONE)

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": CredentialStampTargetKind.BYTE_PATTERN.value,
            "bytePattern": {
                "pattern": base64.b64encode(self.pattern).decode("ascii"),
                "mask": base64.b64encode(self.mask).decode("ascii"),
                "occurrence": self.occurrence,
                "maximumLength": self.maximum_length,
                "remainderPolicy": self.remainder_policy.value,
                "precondition": self.precondition.to_rpc(),
            },
        }


@dataclass(frozen=True)
class CredentialProviderDefinedTarget:
    provider_id: str
    schema_version: str
    value: dict[str, Any]

    def validate(self) -> None:
        _validate_credential_stamp_target(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": CredentialStampTargetKind.PROVIDER_DEFINED.value,
            "providerDefined": {
                "providerId": self.provider_id,
                "schemaVersion": self.schema_version,
                "value": dict(self.value),
            },
        }


type CredentialStampTarget = (
    CredentialNamedSlotTarget
    | CredentialFileOffsetTarget
    | CredentialVirtualAddressTarget
    | CredentialSymbolTarget
    | CredentialMarkerTarget
    | CredentialBytePatternTarget
    | CredentialProviderDefinedTarget
)


@dataclass(frozen=True)
class CredentialMaterialReference:
    projection: CredentialProjection
    form: CredentialMaterialForm
    bundle_id: str = ""
    generation_id: str = ""
    generation_ids: list[str] = field(default_factory=list)
    trust_set_generation_id: str = ""
    crl_generation_ids: list[str] = field(default_factory=list)

    def validate(self) -> None:
        """Reject contradictory reference variants and invalid projection forms."""
        _validate_credential_material_reference(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        out: dict[str, Any] = {"projection": self.projection.value, "form": self.form.value}
        if self.bundle_id:
            out["bundleId"] = self.bundle_id
        if self.generation_id:
            out["generationId"] = self.generation_id
        if self.generation_ids:
            out["generationIds"] = list(self.generation_ids)
        if self.trust_set_generation_id:
            out["trustSetGenerationId"] = self.trust_set_generation_id
        if self.crl_generation_ids:
            out["crlGenerationIds"] = list(self.crl_generation_ids)
        return out


@dataclass(frozen=True)
class CredentialReferencedStampMaterial:
    credential: CredentialMaterialReference

    def validate(self) -> None:
        _validate_credential_stamp_material(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {"projection": self.credential.projection.value, "credential": self.credential.to_rpc()}


@dataclass(frozen=True)
class CredentialProviderEncodingStampMaterial:
    provider_id: str
    schema_version: str
    form: CredentialMaterialForm
    source: CredentialMaterialReference

    def validate(self) -> None:
        _validate_credential_stamp_material(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "projection": CredentialProjection.PROVIDER_ENCODING.value,
            "providerEncoding": {
                "providerId": self.provider_id,
                "schemaVersion": self.schema_version,
                "form": self.form.value,
                "source": self.source.to_rpc(),
            },
        }


@dataclass(frozen=True)
class CredentialLiteralStampMaterial:
    reference: str
    sha256: str
    form: CredentialMaterialForm

    def validate(self) -> None:
        _validate_credential_stamp_material(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "projection": CredentialProjection.LITERAL_REFERENCE.value,
            "literalReference": {"reference": self.reference, "sha256": self.sha256, "form": self.form.value},
        }


type CredentialStampMaterial = (
    CredentialReferencedStampMaterial | CredentialProviderEncodingStampMaterial | CredentialLiteralStampMaterial
)


@dataclass(frozen=True)
class ResolvedCredentialMetadata:
    bundle_version: str
    purpose: CredentialPurpose
    consumer_type: CredentialConsumerType
    profile_id: str
    compatibility_target_id: str

    def validate(self) -> None:
        _validate_resolved_credential_metadata(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "bundleVersion": self.bundle_version,
            "purpose": self.purpose.value,
            "consumerType": self.consumer_type.value,
            "profileId": self.profile_id,
            "compatibilityTargetId": self.compatibility_target_id,
        }


@dataclass(frozen=True)
class CredentialStampRequest:
    assignment_id: str
    capability: CredentialDeliveryCapability
    slot_name: str
    target: CredentialStampTarget
    material: CredentialStampMaterial
    encoded_bytes: int
    credential: ResolvedCredentialMetadata

    def validate(self) -> None:
        """Validate the complete typed stamp request before a protocol boundary."""
        _validate_credential_stamp_request(self)

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "assignmentId": self.assignment_id,
            "capability": self.capability.value,
            "slotName": self.slot_name,
            "target": self.target.to_rpc(),
            "material": self.material.to_rpc(),
            "encodedBytes": self.encoded_bytes,
            "credential": self.credential.to_rpc(),
        }


@dataclass(frozen=True)
class CredentialSlot:
    name: str
    purpose: CredentialPurpose
    endpoint_role: CredentialEndpointRole
    consumer_type: CredentialConsumerType
    accepted_bundle_versions: list[str]
    accepted_profiles: list[str]
    accepted_compatibility_targets: list[str]
    accepted_projections: list[CredentialProjection]
    accepted_material_forms: list[CredentialMaterialForm]
    maximum_encoded_bytes: int
    remainder_policy: CredentialStampRemainderPolicy
    private_material: CredentialPrivateMaterialPolicy

    def to_rpc(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "purpose": self.purpose.value,
            "endpointRole": self.endpoint_role.value,
            "consumerType": self.consumer_type.value,
            "acceptedBundleVersions": list(self.accepted_bundle_versions),
            "acceptedProfiles": list(self.accepted_profiles),
            "acceptedCompatibilityTargets": list(self.accepted_compatibility_targets),
            "acceptedProjections": [value.value for value in self.accepted_projections],
            "acceptedMaterialForms": [value.value for value in self.accepted_material_forms],
            "maximumEncodedBytes": self.maximum_encoded_bytes,
            "remainderPolicy": self.remainder_policy.value,
            "privateMaterial": self.private_material.value,
        }


@dataclass(frozen=True)
class CredentialProviderTargetSchema:
    provider_id: str
    schema_version: str
    json_schema: dict[str, Any]

    def to_rpc(self) -> dict[str, Any]:
        return {
            "providerId": self.provider_id,
            "schemaVersion": self.schema_version,
            "jsonSchema": dict(self.json_schema),
        }


@dataclass(frozen=True)
class CredentialProviderEncodingSchema:
    provider_id: str
    schema_version: str
    accepted_source_projections: list[CredentialProjection]
    accepted_source_forms: list[CredentialMaterialForm]
    output_forms: list[CredentialMaterialForm]

    def to_rpc(self) -> dict[str, Any]:
        return {
            "providerId": self.provider_id,
            "schemaVersion": self.schema_version,
            "acceptedSourceProjections": [value.value for value in self.accepted_source_projections],
            "acceptedSourceForms": [value.value for value in self.accepted_source_forms],
            "outputForms": [value.value for value in self.output_forms],
        }


@dataclass(frozen=True)
class CredentialDeliveryDescriptor:
    capabilities: list[CredentialDeliveryCapability]
    slots: list[CredentialSlot] = field(default_factory=list)
    stamp_target_kinds: list[CredentialStampTargetKind] = field(default_factory=list)
    address_spaces: list[CredentialStampAddressSpace] = field(default_factory=list)
    provider_target_schemas: list[CredentialProviderTargetSchema] = field(default_factory=list)
    provider_encoding_schemas: list[CredentialProviderEncodingSchema] = field(default_factory=list)
    schema_version: str = CREDENTIAL_DELIVERY_SCHEMA_V1

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "deliveryCapabilities": [value.value for value in self.capabilities],
        }
        if self.slots:
            out["credentialSlots"] = [slot.to_rpc() for slot in self.slots]
        if self.stamp_target_kinds:
            out["stampTargetKinds"] = [value.value for value in self.stamp_target_kinds]
        if self.address_spaces:
            out["addressSpaces"] = [value.value for value in self.address_spaces]
        if self.provider_target_schemas:
            out["providerTargetSchemas"] = [schema.to_rpc() for schema in self.provider_target_schemas]
        if self.provider_encoding_schemas:
            out["providerEncodingSchemas"] = [schema.to_rpc() for schema in self.provider_encoding_schemas]
        return out


def credential_stamp_request_from_rpc(value: dict[str, Any]) -> CredentialStampRequest:
    """Decode one daemon-validated stamp request into typed SDK values."""
    request = CredentialStampRequest(
        assignment_id=_required_str(value, "assignmentId"),
        capability=CredentialDeliveryCapability(_required_str(value, "capability")),
        slot_name=_required_str(value, "slotName"),
        target=_credential_stamp_target_from_rpc(_required_mapping(value, "target")),
        material=_credential_stamp_material_from_rpc(_required_mapping(value, "material")),
        encoded_bytes=_required_int(value, "encodedBytes"),
        credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
    )
    _validate_credential_stamp_request(request)
    return request


def _credential_stamp_target_from_rpc(value: dict[str, Any]) -> CredentialStampTarget:
    kind = CredentialStampTargetKind(_required_str(value, "kind"))
    active_field = {
        CredentialStampTargetKind.NAMED_SLOT: "namedSlot",
        CredentialStampTargetKind.FILE_OFFSET: "fileOffset",
        CredentialStampTargetKind.VIRTUAL_ADDRESS: "virtualAddress",
        CredentialStampTargetKind.SYMBOL: "symbol",
        CredentialStampTargetKind.MARKER: "marker",
        CredentialStampTargetKind.BYTE_PATTERN: "bytePattern",
        CredentialStampTargetKind.PROVIDER_DEFINED: "providerDefined",
    }[kind]
    _reject_inactive_fields(
        value,
        allowed={active_field},
        variants={
            "namedSlot",
            "fileOffset",
            "virtualAddress",
            "symbol",
            "marker",
            "bytePattern",
            "providerDefined",
        },
        label="credential stamp target",
    )
    if kind is CredentialStampTargetKind.NAMED_SLOT:
        target = _required_mapping(value, "namedSlot")
        result: CredentialStampTarget = CredentialNamedSlotTarget(name=_required_str(target, "name"))
    elif kind is CredentialStampTargetKind.FILE_OFFSET:
        target = _required_mapping(value, "fileOffset")
        result = CredentialFileOffsetTarget(
            offset=_required_str(target, "offset"),
            maximum_length=_required_str(target, "maximumLength"),
            alignment=_required_str(target, "alignment"),
            remainder_policy=CredentialStampRemainderPolicy(_required_str(target, "remainderPolicy")),
            precondition=_credential_precondition_from_rpc(_required_mapping(target, "precondition")),
        )
    elif kind is CredentialStampTargetKind.VIRTUAL_ADDRESS:
        target = _required_mapping(value, "virtualAddress")
        result = CredentialVirtualAddressTarget(
            address=_required_str(target, "address"),
            address_space=CredentialStampAddressSpace(_required_str(target, "addressSpace")),
            image_base=_optional_str(target, "imageBase"),
            maximum_length=_required_str(target, "maximumLength"),
            alignment=_required_str(target, "alignment"),
            remainder_policy=CredentialStampRemainderPolicy(_required_str(target, "remainderPolicy")),
            precondition=_credential_precondition_from_rpc(_required_mapping(target, "precondition")),
        )
    elif kind is CredentialStampTargetKind.SYMBOL:
        target = _required_mapping(value, "symbol")
        result = CredentialSymbolTarget(
            name=_required_str(target, "name"),
            section=_optional_str(target, "section"),
            maximum_length=_required_str(target, "maximumLength"),
            remainder_policy=CredentialStampRemainderPolicy(_required_str(target, "remainderPolicy")),
            precondition=_credential_precondition_from_rpc(_required_mapping(target, "precondition")),
        )
    elif kind is CredentialStampTargetKind.MARKER:
        target = _required_mapping(value, "marker")
        result = CredentialMarkerTarget(
            marker=_required_bytes(target, "marker"),
            occurrence=_required_int(target, "occurrence"),
            maximum_length=_required_str(target, "maximumLength"),
            remainder_policy=CredentialStampRemainderPolicy(_required_str(target, "remainderPolicy")),
            precondition=_credential_precondition_from_rpc(_required_mapping(target, "precondition")),
        )
    elif kind is CredentialStampTargetKind.BYTE_PATTERN:
        target = _required_mapping(value, "bytePattern")
        result = CredentialBytePatternTarget(
            pattern=_required_bytes(target, "pattern"),
            mask=_required_bytes(target, "mask"),
            occurrence=_required_int(target, "occurrence"),
            maximum_length=_required_str(target, "maximumLength"),
            remainder_policy=CredentialStampRemainderPolicy(_required_str(target, "remainderPolicy")),
            precondition=_credential_precondition_from_rpc(_required_mapping(target, "precondition")),
        )
    else:
        target = _required_mapping(value, "providerDefined")
        result = CredentialProviderDefinedTarget(
            provider_id=_required_str(target, "providerId"),
            schema_version=_required_str(target, "schemaVersion"),
            value=dict(_required_mapping(target, "value")),
        )
    _validate_credential_stamp_target(result)
    return result


def _credential_precondition_from_rpc(value: dict[str, Any]) -> CredentialStampPrecondition:
    kind = CredentialStampPreconditionKind(_required_str(value, "kind"))
    allowed = {
        CredentialStampPreconditionKind.NONE: set(),
        CredentialStampPreconditionKind.BYTES: {"bytes"},
        CredentialStampPreconditionKind.SHA256: {"sha256", "length"},
    }[kind]
    _reject_inactive_fields(
        value,
        allowed=allowed,
        variants={"bytes", "sha256", "length"},
        label="credential stamp precondition",
    )
    precondition = CredentialStampPrecondition(
        kind=kind,
        bytes_value=_optional_bytes(value, "bytes"),
        sha256=_optional_str(value, "sha256"),
        length=_optional_str(value, "length"),
    )
    _validate_credential_stamp_precondition(precondition)
    return precondition


def _credential_stamp_material_from_rpc(value: dict[str, Any]) -> CredentialStampMaterial:
    projection = CredentialProjection(_required_str(value, "projection"))
    if projection is CredentialProjection.PROVIDER_ENCODING:
        active_field = "providerEncoding"
    elif projection is CredentialProjection.LITERAL_REFERENCE:
        active_field = "literalReference"
    else:
        active_field = "credential"
    _reject_inactive_fields(
        value,
        allowed={active_field},
        variants={"credential", "providerEncoding", "literalReference"},
        label="credential stamp material",
    )
    if projection is CredentialProjection.PROVIDER_ENCODING:
        material = _required_mapping(value, "providerEncoding")
        result: CredentialStampMaterial = CredentialProviderEncodingStampMaterial(
            provider_id=_required_str(material, "providerId"),
            schema_version=_required_str(material, "schemaVersion"),
            form=CredentialMaterialForm(_required_str(material, "form")),
            source=_credential_material_reference_from_rpc(_required_mapping(material, "source")),
        )
    elif projection is CredentialProjection.LITERAL_REFERENCE:
        material = _required_mapping(value, "literalReference")
        result = CredentialLiteralStampMaterial(
            reference=_required_str(material, "reference"),
            sha256=_required_str(material, "sha256"),
            form=CredentialMaterialForm(_required_str(material, "form")),
        )
    else:
        reference = _credential_material_reference_from_rpc(_required_mapping(value, "credential"))
        if reference.projection is not projection:
            raise ValueError("credential material projection does not match its reference")
        result = CredentialReferencedStampMaterial(reference)
    _validate_credential_stamp_material(result)
    return result


def _credential_material_reference_from_rpc(value: dict[str, Any]) -> CredentialMaterialReference:
    projection = CredentialProjection(_required_str(value, "projection"))
    active_field = {
        CredentialProjection.BUNDLE: "bundleId",
        CredentialProjection.CERTIFICATE_DER: "generationId",
        CredentialProjection.PRIVATE_KEY_PKCS8: "generationId",
        CredentialProjection.PUBLIC_KEY_SPKI: "generationId",
        CredentialProjection.SIGNER_REFERENCE: "generationId",
        CredentialProjection.CHAIN_DER: "generationIds",
        CredentialProjection.TRUST_DER: "trustSetGenerationId",
        CredentialProjection.CRL_DER: "crlGenerationIds",
    }.get(projection)
    if active_field is None:
        raise ValueError("credential material reference cannot contain provider or literal material")
    _reject_inactive_fields(
        value,
        allowed={active_field},
        variants={
            "bundleId",
            "generationId",
            "generationIds",
            "trustSetGenerationId",
            "crlGenerationIds",
        },
        label="credential material reference",
    )
    reference = CredentialMaterialReference(
        projection=projection,
        form=CredentialMaterialForm(_required_str(value, "form")),
        bundle_id=_optional_str(value, "bundleId"),
        generation_id=_optional_str(value, "generationId"),
        generation_ids=_string_list(value, "generationIds"),
        trust_set_generation_id=_optional_str(value, "trustSetGenerationId"),
        crl_generation_ids=_string_list(value, "crlGenerationIds"),
    )
    _validate_credential_material_reference(reference)
    return reference


def _resolved_credential_metadata_from_rpc(value: dict[str, Any]) -> ResolvedCredentialMetadata:
    metadata = ResolvedCredentialMetadata(
        bundle_version=_required_str(value, "bundleVersion"),
        purpose=CredentialPurpose(_required_str(value, "purpose")),
        consumer_type=CredentialConsumerType(_required_str(value, "consumerType")),
        profile_id=_required_str(value, "profileId"),
        compatibility_target_id=_required_str(value, "compatibilityTargetId"),
    )
    _validate_resolved_credential_metadata(metadata)
    return metadata


def _validate_credential_stamp_request(request: CredentialStampRequest) -> None:
    _validate_canonical_text(request.assignment_id, "credential stamp assignment id", _MAXIMUM_CREDENTIAL_ID_BYTES)
    if not isinstance(request.capability, CredentialDeliveryCapability):
        raise TypeError("credential stamp capability must be a CredentialDeliveryCapability")
    _validate_canonical_text(request.slot_name, "credential stamp slot name", _MAXIMUM_CREDENTIAL_ID_BYTES)
    _validate_credential_stamp_target(request.target)
    _validate_credential_stamp_material(request.material)
    if (
        isinstance(request.encoded_bytes, bool)
        or not isinstance(request.encoded_bytes, int)
        or not 1 <= request.encoded_bytes <= _MAXIMUM_CREDENTIAL_BINARY_BYTES
    ):
        raise ValueError("credential stamp encoded byte count is invalid")
    _validate_resolved_credential_metadata(request.credential)


def _validate_credential_stamp_precondition(precondition: CredentialStampPrecondition) -> None:
    if not isinstance(precondition.kind, CredentialStampPreconditionKind):
        raise TypeError("credential stamp precondition kind is invalid")
    if not isinstance(precondition.bytes_value, bytes):
        raise TypeError("credential stamp precondition bytes must be bytes")
    if precondition.kind is CredentialStampPreconditionKind.NONE:
        if precondition.bytes_value or precondition.sha256 or precondition.length:
            raise ValueError("empty credential stamp precondition contains comparison material")
        return
    if precondition.kind is CredentialStampPreconditionKind.BYTES:
        if (
            not 1 <= len(precondition.bytes_value) <= _MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES
            or precondition.sha256
            or precondition.length
        ):
            raise ValueError("credential byte stamp precondition is invalid")
        return
    if precondition.bytes_value:
        raise ValueError("credential hash stamp precondition contains literal bytes")
    length = _parse_canonical_uint64(precondition.length, "credential stamp precondition length")
    if not 1 <= length <= _MAXIMUM_CREDENTIAL_BINARY_BYTES:
        raise ValueError("credential stamp precondition hash length is invalid")
    _validate_sha256(precondition.sha256, "credential stamp precondition")


def _validate_credential_stamp_target(target: CredentialStampTarget) -> None:
    if isinstance(target, CredentialNamedSlotTarget):
        _validate_canonical_text(target.name, "credential stamp slot name", _MAXIMUM_CREDENTIAL_ID_BYTES)
    elif isinstance(target, (CredentialFileOffsetTarget, CredentialVirtualAddressTarget)):
        _validate_credential_position_target(target)
    elif isinstance(target, CredentialSymbolTarget):
        _validate_credential_symbol_target(target)
    elif isinstance(target, CredentialMarkerTarget):
        _validate_credential_marker_target(target)
    elif isinstance(target, CredentialBytePatternTarget):
        _validate_credential_byte_pattern_target(target)
    elif isinstance(target, CredentialProviderDefinedTarget):
        _validate_credential_provider_defined_target(target)
    else:
        raise TypeError("credential stamp target has an unsupported variant")


def _validate_credential_position_target(
    target: CredentialFileOffsetTarget | CredentialVirtualAddressTarget,
) -> None:
    position, image_base, address_space = _credential_position_fields(target)
    position_value = _parse_canonical_uint64(position, "credential stamp target position")
    image_base_value = _parse_canonical_uint64(image_base, "credential stamp target image base") if image_base else 0
    alignment_value = _parse_canonical_uint64(target.alignment, "credential stamp target alignment")
    if alignment_value == 0 or alignment_value & (alignment_value - 1):
        raise ValueError("credential stamp target alignment must be a nonzero power of two")
    if position_value % alignment_value:
        raise ValueError("credential stamp target position does not satisfy its alignment")
    maximum = _validate_credential_bounded_target(
        target.maximum_length,
        target.remainder_policy,
        target.precondition,
    )
    _validate_credential_position_bounds(
        position_value,
        image_base_value,
        maximum,
        image_base,
        address_space,
    )


def _credential_position_fields(
    target: CredentialFileOffsetTarget | CredentialVirtualAddressTarget,
) -> tuple[str, str, CredentialStampAddressSpace]:
    if isinstance(target, CredentialFileOffsetTarget):
        return target.offset, "", CredentialStampAddressSpace.FILE
    if not isinstance(target.address_space, CredentialStampAddressSpace):
        raise TypeError("credential virtual-address target address space is invalid")
    if target.address_space is CredentialStampAddressSpace.FILE:
        raise ValueError("credential virtual-address target cannot use file address space")
    return target.address, target.image_base, target.address_space


def _validate_credential_position_bounds(
    position: int,
    image_base: int,
    maximum: int,
    raw_image_base: str,
    address_space: CredentialStampAddressSpace,
) -> None:
    if position > _MAXIMUM_UINT64 - maximum:
        raise ValueError("credential stamp target position and maximum length overflow uint64")
    if raw_image_base:
        if address_space is CredentialStampAddressSpace.PE_RVA:
            if image_base > _MAXIMUM_UINT64 - position:
                raise ValueError("credential stamp image base, address, and length overflow uint64")
            if image_base + position > _MAXIMUM_UINT64 - maximum:
                raise ValueError("credential stamp image base, address, and length overflow uint64")
        elif (
            address_space
            in {
                CredentialStampAddressSpace.ELF_VIRTUAL_ADDRESS,
                CredentialStampAddressSpace.MACHO_VM_ADDRESS,
            }
            and position < image_base
        ):
            raise ValueError("credential virtual address precedes its image base")


def _validate_credential_symbol_target(target: CredentialSymbolTarget) -> None:
    _validate_canonical_text(target.name, "credential stamp symbol name", _MAXIMUM_CREDENTIAL_NAME_BYTES)
    if target.section:
        _validate_canonical_text(
            target.section,
            "credential stamp symbol section",
            _MAXIMUM_CREDENTIAL_NAME_BYTES,
        )
    _validate_credential_bounded_target(
        target.maximum_length,
        target.remainder_policy,
        target.precondition,
    )


def _validate_credential_marker_target(target: CredentialMarkerTarget) -> None:
    if (
        not isinstance(target.marker, bytes)
        or not 1 <= len(target.marker) <= _MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES
    ):
        raise ValueError("credential marker stamp target is invalid")
    _validate_credential_occurrence(target.occurrence)
    _validate_credential_bounded_target(
        target.maximum_length,
        target.remainder_policy,
        target.precondition,
    )


def _validate_credential_byte_pattern_target(target: CredentialBytePatternTarget) -> None:
    if (
        not isinstance(target.pattern, bytes)
        or not isinstance(target.mask, bytes)
        or not target.pattern
        or len(target.pattern) != len(target.mask)
        or len(target.pattern) > _MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES
        or not any(target.mask)
    ):
        raise ValueError("credential byte-pattern stamp target is invalid")
    _validate_credential_occurrence(target.occurrence)
    _validate_credential_bounded_target(
        target.maximum_length,
        target.remainder_policy,
        target.precondition,
    )


def _validate_credential_provider_defined_target(target: CredentialProviderDefinedTarget) -> None:
    _validate_canonical_text(
        target.provider_id,
        "credential provider-defined target provider id",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )
    _validate_canonical_text(
        target.schema_version,
        "credential provider-defined target schema version",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )
    if not isinstance(target.value, dict):
        raise TypeError("credential provider-defined target value must be an object")
    try:
        encoded = json.dumps(target.value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("credential provider-defined target value is invalid") from error
    if len(encoded) > _MAXIMUM_CREDENTIAL_PROVIDER_TARGET_BYTES:
        raise ValueError("credential provider-defined target value is invalid")


def _validate_credential_bounded_target(
    maximum_length: str,
    remainder_policy: CredentialStampRemainderPolicy,
    precondition: CredentialStampPrecondition,
) -> int:
    maximum = _parse_canonical_uint64(maximum_length, "credential stamp target maximum length")
    if not 1 <= maximum <= _MAXIMUM_CREDENTIAL_BINARY_BYTES:
        raise ValueError("credential stamp target maximum length is invalid")
    if not isinstance(remainder_policy, CredentialStampRemainderPolicy):
        raise TypeError("credential stamp remainder policy is invalid")
    _validate_credential_stamp_precondition(precondition)
    if precondition.kind is CredentialStampPreconditionKind.BYTES and len(precondition.bytes_value) > maximum:
        raise ValueError("credential stamp precondition exceeds target maximum length")
    if precondition.kind is CredentialStampPreconditionKind.SHA256:
        length = _parse_canonical_uint64(precondition.length, "credential stamp precondition length")
        if length > maximum:
            raise ValueError("credential stamp hash precondition exceeds target maximum length")
    return maximum


def _validate_credential_occurrence(occurrence: int) -> None:
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or not 0 <= occurrence <= _MAXIMUM_UINT32:
        raise ValueError("credential stamp occurrence is invalid")


def _validate_credential_material_reference(reference: CredentialMaterialReference) -> None:
    projection = reference.projection
    if not isinstance(projection, CredentialProjection):
        raise TypeError("credential material projection is invalid")
    _validate_projection_form(projection, reference.form)
    variants = [
        bool(reference.bundle_id),
        bool(reference.generation_id),
        bool(reference.generation_ids),
        bool(reference.trust_set_generation_id),
        bool(reference.crl_generation_ids),
    ]
    if sum(variants) != 1:
        raise ValueError("credential material must contain exactly one tagged reference")
    if projection is CredentialProjection.BUNDLE:
        _validate_canonical_text(reference.bundle_id, "credential bundle id", _MAXIMUM_CREDENTIAL_ID_BYTES)
    elif projection in {
        CredentialProjection.CERTIFICATE_DER,
        CredentialProjection.PRIVATE_KEY_PKCS8,
        CredentialProjection.PUBLIC_KEY_SPKI,
        CredentialProjection.SIGNER_REFERENCE,
    }:
        _validate_canonical_text(
            reference.generation_id,
            "credential generation id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
    elif projection is CredentialProjection.CHAIN_DER:
        _validate_reference_list(reference.generation_ids, "credential chain generation ids")
    elif projection is CredentialProjection.TRUST_DER:
        _validate_canonical_text(
            reference.trust_set_generation_id,
            "credential trust-set generation id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
    elif projection is CredentialProjection.CRL_DER:
        _validate_reference_list(reference.crl_generation_ids, "credential CRL generation ids")
    else:
        raise ValueError("credential material reference cannot contain provider or literal material")


def _validate_credential_stamp_material(material: CredentialStampMaterial) -> None:
    if isinstance(material, CredentialReferencedStampMaterial):
        _validate_credential_material_reference(material.credential)
        return
    if isinstance(material, CredentialProviderEncodingStampMaterial):
        _validate_canonical_text(
            material.provider_id,
            "credential provider-encoding provider id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        _validate_canonical_text(
            material.schema_version,
            "credential provider-encoding schema version",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(material.form, CredentialMaterialForm):
            raise TypeError("credential provider-encoding form is invalid")
        _validate_credential_material_reference(material.source)
        return
    if isinstance(material, CredentialLiteralStampMaterial):
        _validate_canonical_text(
            material.reference,
            "credential literal material reference",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(material.form, CredentialMaterialForm):
            raise TypeError("credential literal material form is invalid")
        _validate_sha256(material.sha256, "credential literal material")
        return
    raise TypeError("credential stamp material has an unsupported variant")


def _credential_stamp_material_projection_and_form(
    material: CredentialStampMaterial,
) -> tuple[CredentialProjection, CredentialMaterialForm]:
    _validate_credential_stamp_material(material)
    if isinstance(material, CredentialReferencedStampMaterial):
        return material.credential.projection, material.credential.form
    if isinstance(material, CredentialProviderEncodingStampMaterial):
        return CredentialProjection.PROVIDER_ENCODING, material.form
    return CredentialProjection.LITERAL_REFERENCE, material.form


def _validate_resolved_credential_metadata(metadata: ResolvedCredentialMetadata) -> None:
    _validate_canonical_text(
        metadata.bundle_version,
        "resolved credential bundle version",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )
    if not isinstance(metadata.purpose, CredentialPurpose):
        raise TypeError("resolved credential purpose is invalid")
    if not isinstance(metadata.consumer_type, CredentialConsumerType):
        raise TypeError("resolved credential consumer type is invalid")
    _validate_canonical_text(metadata.profile_id, "resolved credential profile id", _MAXIMUM_CREDENTIAL_ID_BYTES)
    _validate_canonical_text(
        metadata.compatibility_target_id,
        "resolved credential compatibility target id",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )


def _validate_projection_form(projection: CredentialProjection, form: CredentialMaterialForm) -> None:
    if not isinstance(projection, CredentialProjection) or not isinstance(form, CredentialMaterialForm):
        raise TypeError("credential projection or material form is invalid")
    if (
        projection
        in {
            CredentialProjection.CERTIFICATE_DER,
            CredentialProjection.PUBLIC_KEY_SPKI,
            CredentialProjection.CHAIN_DER,
            CredentialProjection.TRUST_DER,
            CredentialProjection.CRL_DER,
        }
        and form is not CredentialMaterialForm.PUBLIC
    ):
        raise ValueError("public credential projection requires public material")
    if projection is CredentialProjection.PRIVATE_KEY_PKCS8 and form is not CredentialMaterialForm.PRIVATE_BYTES:
        raise ValueError("private-key projection requires private bytes")
    if projection is CredentialProjection.SIGNER_REFERENCE and form is not CredentialMaterialForm.PRIVATE_REFERENCE:
        raise ValueError("signer projection requires a private reference")


def _validate_canonical_text(value: str, label: str, maximum_bytes: int) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} is invalid or noncanonical") from error
    if not value.strip() or value != value.strip() or len(encoded) > maximum_bytes:
        raise ValueError(f"{label} is invalid or noncanonical")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"{label} contains control characters")


def _validate_sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_BYTES or value != value.lower():
        raise ValueError(f"{label} sha256 is invalid or noncanonical")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} sha256 is invalid or noncanonical") from error
    if len(decoded) != _SHA256_BYTES:
        raise ValueError(f"{label} sha256 is invalid or noncanonical")


def _parse_canonical_uint64(value: str, label: str) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        raise ValueError(f"{label} is not a canonical uint64")
    parsed = int(value)
    if parsed > _MAXIMUM_UINT64 or str(parsed) != value:
        raise ValueError(f"{label} is not a canonical uint64")
    return parsed


def _validate_reference_list(values: list[str], label: str) -> None:
    if not isinstance(values, list) or not 1 <= len(values) <= _MAXIMUM_CREDENTIAL_REFERENCE_LIST:
        raise ValueError(f"{label} is empty or exceeds limits")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains a duplicate")
    for value in values:
        _validate_canonical_text(value, label, _MAXIMUM_CREDENTIAL_ID_BYTES)


def _reject_inactive_fields(
    value: dict[str, Any],
    *,
    allowed: set[str],
    variants: set[str],
    label: str,
) -> None:
    inactive = sorted((set(value) & variants) - allowed)
    if inactive:
        raise ValueError(f"{label} contains inactive variant field {inactive[0]!r}")


def _required_mapping(value: dict[str, Any], field_name: str) -> dict[str, Any]:
    field = value.get(field_name)
    if not isinstance(field, dict):
        raise TypeError(f"{field_name} must be an object")
    return field


def _required_str(value: dict[str, Any], field_name: str) -> str:
    field = value.get(field_name)
    if not isinstance(field, str) or not field.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return field


def _optional_str(value: dict[str, Any], field_name: str) -> str:
    field = value.get(field_name, "")
    if not isinstance(field, str):
        raise TypeError(f"{field_name} must be a string")
    return field


def _required_int(value: dict[str, Any], field_name: str) -> int:
    field = value.get(field_name)
    if isinstance(field, bool) or not isinstance(field, int):
        raise TypeError(f"{field_name} must be an integer")
    bounds = _INTEGER_BOUNDS.get(field_name)
    if bounds is not None:
        minimum, maximum = bounds
        if field < minimum or field > maximum:
            raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return field


def _optional_bytes(value: dict[str, Any], field_name: str) -> bytes:
    field = value.get(field_name)
    if field is None:
        return b""
    if not isinstance(field, str):
        raise TypeError(f"{field_name} must be base64")
    try:
        decoded = base64.b64decode(field, validate=True)
    except ValueError as error:
        raise ValueError(f"{field_name} must be canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != field:
        raise ValueError(f"{field_name} must be canonical base64")
    return decoded


def _required_bytes(value: dict[str, Any], field_name: str) -> bytes:
    result = _optional_bytes(value, field_name)
    if not result:
        raise ValueError(f"{field_name} must not be empty")
    return result


def _string_list(value: dict[str, Any], field_name: str) -> list[str]:
    field = value.get(field_name, [])
    if not isinstance(field, list) or not all(isinstance(item, str) for item in field):
        raise ValueError(f"{field_name} must be a string list")
    return list(field)
