from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

CREDENTIAL_DELIVERY_SCHEMA_V1 = "hovel.pki.credential-delivery/v1"
_CREDENTIAL_RPC_DESCRIBE_METHOD = "credential.describe"
_MAXIMUM_CREDENTIAL_BINARY_BYTES = 24 << 20
_MAXIMUM_UINT32 = (1 << 32) - 1
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
        return {"kind": CredentialStampTargetKind.NAMED_SLOT.value, "namedSlot": {"name": self.name}}


@dataclass(frozen=True)
class CredentialFileOffsetTarget:
    offset: str
    maximum_length: str
    alignment: str
    remainder_policy: CredentialStampRemainderPolicy
    precondition: CredentialStampPrecondition

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
        return {"projection": self.credential.projection.value, "credential": self.credential.to_rpc()}


@dataclass(frozen=True)
class CredentialProviderEncodingStampMaterial:
    provider_id: str
    schema_version: str
    form: CredentialMaterialForm
    source: CredentialMaterialReference

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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

    def to_rpc(self) -> dict[str, Any]:
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
    return CredentialStampRequest(
        assignment_id=_required_str(value, "assignmentId"),
        capability=CredentialDeliveryCapability(_required_str(value, "capability")),
        slot_name=_required_str(value, "slotName"),
        target=_credential_stamp_target_from_rpc(_required_mapping(value, "target")),
        material=_credential_stamp_material_from_rpc(_required_mapping(value, "material")),
        encoded_bytes=_required_int(value, "encodedBytes"),
        credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
    )


def _credential_stamp_target_from_rpc(value: dict[str, Any]) -> CredentialStampTarget:
    kind = CredentialStampTargetKind(_required_str(value, "kind"))
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
    return result


def _credential_precondition_from_rpc(value: dict[str, Any]) -> CredentialStampPrecondition:
    return CredentialStampPrecondition(
        kind=CredentialStampPreconditionKind(_required_str(value, "kind")),
        bytes_value=_optional_bytes(value, "bytes"),
        sha256=_optional_str(value, "sha256"),
        length=_optional_str(value, "length"),
    )


def _credential_stamp_material_from_rpc(value: dict[str, Any]) -> CredentialStampMaterial:
    projection = CredentialProjection(_required_str(value, "projection"))
    if projection is CredentialProjection.PROVIDER_ENCODING:
        material = _required_mapping(value, "providerEncoding")
        return CredentialProviderEncodingStampMaterial(
            provider_id=_required_str(material, "providerId"),
            schema_version=_required_str(material, "schemaVersion"),
            form=CredentialMaterialForm(_required_str(material, "form")),
            source=_credential_material_reference_from_rpc(_required_mapping(material, "source")),
        )
    if projection is CredentialProjection.LITERAL_REFERENCE:
        material = _required_mapping(value, "literalReference")
        return CredentialLiteralStampMaterial(
            reference=_required_str(material, "reference"),
            sha256=_required_str(material, "sha256"),
            form=CredentialMaterialForm(_required_str(material, "form")),
        )
    reference = _credential_material_reference_from_rpc(_required_mapping(value, "credential"))
    if reference.projection is not projection:
        raise ValueError("credential material projection does not match its reference")
    return CredentialReferencedStampMaterial(reference)


def _credential_material_reference_from_rpc(value: dict[str, Any]) -> CredentialMaterialReference:
    return CredentialMaterialReference(
        projection=CredentialProjection(_required_str(value, "projection")),
        form=CredentialMaterialForm(_required_str(value, "form")),
        bundle_id=_optional_str(value, "bundleId"),
        generation_id=_optional_str(value, "generationId"),
        generation_ids=_string_list(value, "generationIds"),
        trust_set_generation_id=_optional_str(value, "trustSetGenerationId"),
        crl_generation_ids=_string_list(value, "crlGenerationIds"),
    )


def _resolved_credential_metadata_from_rpc(value: dict[str, Any]) -> ResolvedCredentialMetadata:
    return ResolvedCredentialMetadata(
        bundle_version=_required_str(value, "bundleVersion"),
        purpose=CredentialPurpose(_required_str(value, "purpose")),
        consumer_type=CredentialConsumerType(_required_str(value, "consumerType")),
        profile_id=_required_str(value, "profileId"),
        compatibility_target_id=_required_str(value, "compatibilityTargetId"),
    )


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
