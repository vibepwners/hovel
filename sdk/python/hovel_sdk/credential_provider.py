"""Typed, optional credential provider execution contracts."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hovel_sdk.credential_delivery import (
    _MAXIMUM_CREDENTIAL_BINARY_BYTES,
    _MAXIMUM_CREDENTIAL_ENCODING_BYTES,
    _MAXIMUM_CREDENTIAL_EXECUTION_FILES,
    _MAXIMUM_CREDENTIAL_ID_BYTES,
    _MAXIMUM_CREDENTIAL_NAME_BYTES,
    _MAXIMUM_CREDENTIAL_PATH_BYTES,
    _MAXIMUM_CREDENTIAL_RECEIPT_BYTES,
    _MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES,
    _MAXIMUM_CREDENTIAL_STAMP_DIGESTS,
    CredentialMaterialForm,
    CredentialProjection,
    CredentialStampRequest,
    CredentialStampTarget,
    ResolvedCredentialMetadata,
    _credential_stamp_material_projection_and_form,
    _optional_str,
    _parse_canonical_uint64,
    _required_bytes,
    _required_int,
    _required_mapping,
    _required_str,
    _resolved_credential_metadata_from_rpc,
    _validate_canonical_text,
    _validate_credential_stamp_request,
    _validate_credential_stamp_target,
    _validate_projection_form,
    _validate_resolved_credential_metadata,
    _validate_sha256,
    credential_stamp_request_from_rpc,
)

CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1 = "hovel.pki.provider-execution/v1"
CREDENTIAL_ENCODING_RAW = "raw"

_CREDENTIAL_RPC_RUNTIME_METHOD = "credential.runtime"
_CREDENTIAL_RPC_FILES_METHOD = "credential.files"
_CREDENTIAL_RPC_ENCODE_METHOD = "credential.encode"
_CREDENTIAL_RPC_STAMP_METHOD = "credential.stamp"
_CREDENTIAL_RPC_PREFIX = "credential."


@dataclass(frozen=True)
class CredentialOperationScope:
    operation_id: str = ""
    run_id: str = ""
    chain_id: str = ""
    throw_id: str = ""
    target: str = ""
    listener_id: str = ""
    node_id: str = ""

    def validate(self) -> None:
        for label, value in (
            ("operation id", self.operation_id),
            ("run id", self.run_id),
            ("chain id", self.chain_id),
            ("throw id", self.throw_id),
            ("target", self.target),
            ("listener id", self.listener_id),
            ("node id", self.node_id),
        ):
            if value:
                _validate_canonical_text(value, f"credential operation {label}", _MAXIMUM_CREDENTIAL_ID_BYTES)

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialOperationScope:
        scope = cls(
            operation_id=_optional_str(value, "operationId"),
            run_id=_optional_str(value, "runId"),
            chain_id=_optional_str(value, "chainId"),
            throw_id=_optional_str(value, "throwId"),
            target=_optional_str(value, "target"),
            listener_id=_optional_str(value, "listenerId"),
            node_id=_optional_str(value, "nodeId"),
        )
        scope.validate()
        return scope


@dataclass(frozen=True)
class CredentialProviderTarget:
    module_id: str
    provider_id: str
    provider_version: str
    descriptor_sha256: str

    def validate(self) -> None:
        _validate_canonical_text(self.module_id, "credential provider module id", _MAXIMUM_CREDENTIAL_ID_BYTES)
        _validate_canonical_text(self.provider_id, "credential provider provider id", _MAXIMUM_CREDENTIAL_ID_BYTES)
        _validate_canonical_text(
            self.provider_version,
            "credential provider provider version",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        _validate_sha256(self.descriptor_sha256, "credential provider descriptor")

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialProviderTarget:
        target = cls(
            module_id=_required_str(value, "moduleId"),
            provider_id=_required_str(value, "providerId"),
            provider_version=_required_str(value, "providerVersion"),
            descriptor_sha256=_required_str(value, "descriptorSha256"),
        )
        target.validate()
        return target


class CredentialBytes:
    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("credential bytes must be bytes")
        if not 1 <= len(value) <= _MAXIMUM_CREDENTIAL_BINARY_BYTES:
            raise ValueError("credential bytes must be non-empty and bounded")
        self.__value = value

    @property
    def value(self) -> bytes:
        return self.__value

    def __repr__(self) -> str:
        return "<credential bytes redacted>"

    @classmethod
    def from_rpc(cls, value: dict[str, Any], field_name: str) -> CredentialBytes:
        return cls(_required_bytes(value, field_name))

    def to_rpc(self) -> str:
        return base64.b64encode(self.value).decode("ascii")


class CredentialProtectedPath:
    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        _validate_canonical_text(value, "credential protected path", _MAXIMUM_CREDENTIAL_PATH_BYTES)
        self.__value = value

    @property
    def value(self) -> str:
        return self.__value

    def reveal(self) -> str:
        """Reveal the path for an explicit filesystem-boundary operation."""
        return self.__value

    def __repr__(self) -> str:
        return "<credential secret redacted>"

    def __str__(self) -> str:
        return "<credential secret redacted>"


class CredentialSecretReference:
    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        _validate_canonical_text(value, "credential secret reference", _MAXIMUM_CREDENTIAL_ID_BYTES)
        self.__value = value

    @property
    def value(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "<credential secret redacted>"


@dataclass(frozen=True)
class CredentialScopedReference:
    provider_id: str
    reference: CredentialSecretReference
    capabilities: list[str] = field(default_factory=list)

    def validate(self) -> None:
        _validate_canonical_text(
            self.provider_id,
            "credential reference provider id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(self.reference, CredentialSecretReference):
            raise TypeError("credential scoped reference requires a secret reference")
        if (
            not isinstance(self.capabilities, list)
            or len(self.capabilities) > _MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES
        ):
            raise ValueError("credential reference capabilities exceed limits")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("credential reference capabilities contain a duplicate")
        for capability in self.capabilities:
            _validate_canonical_text(
                capability,
                "credential reference capability",
                _MAXIMUM_CREDENTIAL_ID_BYTES,
            )

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialScopedReference:
        capabilities = value.get("capabilities", [])
        if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
            raise ValueError("capabilities must be a string list")
        reference = cls(
            provider_id=_required_str(value, "providerId"),
            reference=CredentialSecretReference(_required_str(value, "reference")),
            capabilities=list(capabilities),
        )
        reference.validate()
        return reference


@dataclass(frozen=True)
class ResolvedCredentialMaterial:
    projection: CredentialProjection
    form: CredentialMaterialForm
    encoding: str
    sha256: str
    value: CredentialBytes | CredentialScopedReference

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_projection_form(self.projection, self.form)
        _validate_canonical_text(
            self.encoding,
            "credential material encoding",
            _MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )
        _validate_sha256(self.sha256, "credential material")
        if self.form == CredentialMaterialForm.PRIVATE_REFERENCE:
            if not isinstance(self.value, CredentialScopedReference):
                raise TypeError("private-reference material requires a scoped reference")
            self.value.validate()
            return
        if not isinstance(self.value, CredentialBytes):
            raise TypeError(f"{self.form.value} material requires credential bytes")
        _validate_digest(self.value.value, self.sha256, "credential material")

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> ResolvedCredentialMaterial:
        has_data = "data" in value
        has_reference = "reference" in value
        if has_data == has_reference:
            raise ValueError("resolved credential material requires exactly one data or reference variant")
        return cls(
            projection=CredentialProjection(_required_str(value, "projection")),
            form=CredentialMaterialForm(_required_str(value, "form")),
            encoding=_required_str(value, "encoding"),
            sha256=_required_str(value, "sha256"),
            value=(
                CredentialBytes.from_rpc(value, "data")
                if has_data
                else CredentialScopedReference.from_rpc(_required_mapping(value, "reference"))
            ),
        )


@dataclass(frozen=True)
class CredentialRuntimeRequest:
    request_id: str
    provider: CredentialProviderTarget
    assignment_id: str
    slot_name: str
    credential: ResolvedCredentialMetadata
    material: ResolvedCredentialMaterial
    scope: CredentialOperationScope
    schema_version: str = CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1

    def validate(self) -> None:
        _validate_execution_envelope(self.schema_version, self.request_id)
        self.provider.validate()
        _validate_delivery_inputs(
            self.assignment_id,
            self.slot_name,
            self.credential,
            self.scope,
        )
        self.material.validate()

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialRuntimeRequest:
        _require_execution_schema(value)
        request = cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            assignment_id=_required_str(value, "assignmentId"),
            slot_name=_required_str(value, "slotName"),
            credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
            material=ResolvedCredentialMaterial.from_rpc(_required_mapping(value, "material")),
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )
        request.validate()
        return request


@dataclass(frozen=True)
class CredentialFile:
    projection: CredentialProjection
    form: CredentialMaterialForm
    encoding: str
    media_type: str
    path: CredentialProtectedPath
    sha256: str = ""
    size: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.path, CredentialProtectedPath):
            raise TypeError("credential file path must be a CredentialProtectedPath")

    def validate(self) -> None:
        _validate_projection_form(self.projection, self.form)
        _validate_canonical_text(self.encoding, "credential file encoding", _MAXIMUM_CREDENTIAL_ENCODING_BYTES)
        _validate_canonical_text(self.media_type, "credential file media type", _MAXIMUM_CREDENTIAL_ID_BYTES)
        if not isinstance(self.path, CredentialProtectedPath):
            raise TypeError("credential file path must be a CredentialProtectedPath")
        _validate_sha256(self.sha256, "credential file")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 1 <= self.size <= _MAXIMUM_CREDENTIAL_BINARY_BYTES
        ):
            raise ValueError("credential file size is invalid")

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialFile:
        credential_file = cls(
            projection=CredentialProjection(_required_str(value, "projection")),
            form=CredentialMaterialForm(_required_str(value, "form")),
            encoding=_required_str(value, "encoding"),
            media_type=_required_str(value, "mediaType"),
            path=CredentialProtectedPath(_required_str(value, "path")),
            sha256=_required_str(value, "sha256"),
            size=_required_int(value, "size"),
        )
        credential_file.validate()
        return credential_file


@dataclass(frozen=True)
class CredentialFilesRequest:
    request_id: str
    provider: CredentialProviderTarget
    assignment_id: str
    slot_name: str
    credential: ResolvedCredentialMetadata
    files: list[CredentialFile]
    scope: CredentialOperationScope
    schema_version: str = CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1

    def validate(self) -> None:
        _validate_execution_envelope(self.schema_version, self.request_id)
        self.provider.validate()
        _validate_delivery_inputs(
            self.assignment_id,
            self.slot_name,
            self.credential,
            self.scope,
        )
        if not 1 <= len(self.files) <= _MAXIMUM_CREDENTIAL_EXECUTION_FILES:
            raise ValueError("credential files request is empty or exceeds limits")
        paths: set[str] = set()
        for credential_file in self.files:
            credential_file.validate()
            path = credential_file.path.reveal()
            if path in paths:
                raise ValueError("credential files request contains a duplicate path")
            paths.add(path)

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialFilesRequest:
        _require_execution_schema(value)
        files = value.get("files")
        if not isinstance(files, list):
            raise TypeError("files must be an array")
        request = cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            assignment_id=_required_str(value, "assignmentId"),
            slot_name=_required_str(value, "slotName"),
            credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
            files=[CredentialFile.from_rpc(_as_mapping(item, "files item")) for item in files],
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )
        request.validate()
        return request


@dataclass(frozen=True)
class CredentialDeliveryReceipt:
    request_id: str
    provider_reference: str = ""
    receipt_sha256: str = ""

    def validate(self) -> None:
        _validate_canonical_text(
            self.request_id,
            "credential delivery receipt request id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if self.provider_reference:
            _validate_canonical_text(
                self.provider_reference,
                "credential provider reference",
                _MAXIMUM_CREDENTIAL_ID_BYTES,
            )
        if self.receipt_sha256:
            _validate_sha256(self.receipt_sha256, "credential delivery receipt")

    def validate_for(self, request_id: str) -> None:
        self.validate()
        if self.request_id != request_id:
            raise ValueError("credential delivery receipt request id does not match its request")

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        out: dict[str, Any] = {"requestId": self.request_id}
        if self.provider_reference:
            out["providerReference"] = self.provider_reference
        if self.receipt_sha256:
            out["receiptSha256"] = self.receipt_sha256
        return out


@dataclass(frozen=True)
class CredentialEncodingRequest:
    request_id: str
    provider: CredentialProviderTarget
    provider_id: str
    provider_schema: str
    output_form: CredentialMaterialForm
    maximum_encoded_bytes: int
    source: ResolvedCredentialMaterial
    scope: CredentialOperationScope
    schema_version: str = CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1

    def validate(self) -> None:
        _validate_execution_envelope(self.schema_version, self.request_id)
        self.provider.validate()
        _validate_canonical_text(
            self.provider_id,
            "credential encoding provider id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if self.provider_id != self.provider.provider_id:
            raise ValueError("credential encoding provider does not match its invocation target")
        _validate_canonical_text(
            self.provider_schema,
            "credential provider schema",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(self.output_form, CredentialMaterialForm):
            raise TypeError("credential encoding output form is invalid")
        if (
            isinstance(self.maximum_encoded_bytes, bool)
            or not isinstance(self.maximum_encoded_bytes, int)
            or not 1 <= self.maximum_encoded_bytes <= _MAXIMUM_CREDENTIAL_BINARY_BYTES
        ):
            raise ValueError("credential encoding output bound is invalid")
        self.source.validate()
        self.scope.validate()

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialEncodingRequest:
        _require_execution_schema(value)
        request = cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            provider_id=_required_str(value, "providerId"),
            provider_schema=_required_str(value, "providerSchema"),
            output_form=CredentialMaterialForm(_required_str(value, "outputForm")),
            maximum_encoded_bytes=_required_int(value, "maximumEncodedBytes"),
            source=ResolvedCredentialMaterial.from_rpc(_required_mapping(value, "source")),
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )
        request.validate()
        return request


@dataclass(frozen=True)
class CredentialEncodingResult:
    request_id: str
    form: CredentialMaterialForm
    encoding: str
    sha256: str
    data: bytes = field(repr=False)

    def validate(self) -> None:
        _validate_canonical_text(
            self.request_id,
            "credential encoding result request id",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(self.form, CredentialMaterialForm):
            raise TypeError("credential encoding result form is invalid")
        _validate_canonical_text(self.encoding, "credential encoding", _MAXIMUM_CREDENTIAL_ENCODING_BYTES)
        if not isinstance(self.data, bytes) or not 1 <= len(self.data) <= _MAXIMUM_CREDENTIAL_BINARY_BYTES:
            raise ValueError("encoded credential data is empty or exceeds limits")
        _validate_digest(self.data, self.sha256, "encoded credential")

    def validate_for(self, request: CredentialEncodingRequest) -> None:
        request.validate()
        self.validate()
        if (
            self.request_id != request.request_id
            or self.form is not request.output_form
            or len(self.data) > request.maximum_encoded_bytes
        ):
            raise ValueError("credential encoding result does not match its request")

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {
            "requestId": self.request_id,
            "form": self.form.value,
            "encoding": self.encoding,
            "sha256": self.sha256,
            "data": base64.b64encode(self.data).decode("ascii"),
        }


@dataclass(frozen=True)
class CredentialArtifactInput:
    artifact_id: str
    sha256: str
    encoding: str
    content: CredentialBytes | CredentialProtectedPath

    def __post_init__(self) -> None:
        if not isinstance(self.content, (CredentialBytes, CredentialProtectedPath)):
            raise TypeError("credential artifact content must be data or a protected path")

    def validate(self) -> None:
        _validate_canonical_text(self.artifact_id, "credential stamp input id", _MAXIMUM_CREDENTIAL_ID_BYTES)
        _validate_sha256(self.sha256, "credential stamp input")
        _validate_canonical_text(
            self.encoding,
            "credential artifact encoding",
            _MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )
        if isinstance(self.content, CredentialBytes):
            _validate_digest(self.content.value, self.sha256, "credential stamp input")
        elif not isinstance(self.content, CredentialProtectedPath):
            raise TypeError("credential artifact content must be data or a protected path")

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialArtifactInput:
        has_data = "data" in value
        has_path = "path" in value
        if has_data == has_path:
            raise ValueError("credential artifact input requires exactly one data or path variant")
        artifact = cls(
            artifact_id=_required_str(value, "id"),
            sha256=_required_str(value, "sha256"),
            encoding=_required_str(value, "encoding"),
            content=(
                CredentialBytes.from_rpc(value, "data")
                if has_data
                else CredentialProtectedPath(_required_str(value, "path"))
            ),
        )
        artifact.validate()
        return artifact


@dataclass(frozen=True)
class CredentialArtifactOutput:
    name: str
    encoding: str
    content: CredentialBytes | CredentialProtectedPath

    def __post_init__(self) -> None:
        if not isinstance(self.content, (CredentialBytes, CredentialProtectedPath)):
            raise TypeError("credential artifact content must be data or a protected path")

    def validate(self) -> None:
        _validate_canonical_text(self.name, "credential artifact output name", _MAXIMUM_CREDENTIAL_NAME_BYTES)
        _validate_canonical_text(
            self.encoding,
            "credential artifact encoding",
            _MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )
        if not isinstance(self.content, (CredentialBytes, CredentialProtectedPath)):
            raise TypeError("credential artifact content must be data or a protected path")

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        out: dict[str, Any] = {"name": self.name, "encoding": self.encoding}
        if isinstance(self.content, CredentialBytes):
            out["data"] = self.content.to_rpc()
        else:
            out["path"] = self.content.reveal()
        return out


@dataclass(frozen=True)
class CredentialDeploymentOutput:
    reference: str
    receipt: bytes = field(repr=False)

    def validate(self) -> None:
        _validate_canonical_text(
            self.reference,
            "credential deployment reference",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        if not isinstance(self.receipt, bytes) or not 1 <= len(self.receipt) <= _MAXIMUM_CREDENTIAL_RECEIPT_BYTES:
            raise ValueError("credential deployment receipt is empty or exceeds limits")

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {"reference": self.reference, "receipt": base64.b64encode(self.receipt).decode("ascii")}


type CredentialStampOutput = CredentialArtifactOutput | CredentialDeploymentOutput


@dataclass(frozen=True)
class CredentialStampedMaterialDigest:
    projection: CredentialProjection
    reference: str
    sha256: str

    def validate(self) -> None:
        if not isinstance(self.projection, CredentialProjection):
            raise TypeError("credential stamped material projection is invalid")
        _validate_canonical_text(
            self.reference,
            "credential stamped material reference",
            _MAXIMUM_CREDENTIAL_ID_BYTES,
        )
        _validate_sha256(self.sha256, "credential stamped material")

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialStampedMaterialDigest:
        digest = cls(
            projection=CredentialProjection(_required_str(value, "projection")),
            reference=_required_str(value, "reference"),
            sha256=_required_str(value, "sha256"),
        )
        digest.validate()
        return digest

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        return {"projection": self.projection.value, "reference": self.reference, "sha256": self.sha256}


class CredentialStampTargetResolution(StrEnum):
    UNCHANGED = "unchanged"
    TRANSLATED = "translated"


@dataclass(frozen=True)
class CredentialStampExecutionRequest:
    stamp_id: str
    provider: CredentialProviderTarget
    request: CredentialStampRequest
    input: CredentialArtifactInput
    material: ResolvedCredentialMaterial
    expected_digests: list[CredentialStampedMaterialDigest]
    scope: CredentialOperationScope
    schema_version: str = CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1

    def validate(self) -> None:
        if self.schema_version != CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1:
            raise ValueError(f"unsupported credential provider execution schema {self.schema_version!r}")
        self.provider.validate()
        _validate_canonical_text(self.stamp_id, "credential stamp id", _MAXIMUM_CREDENTIAL_ID_BYTES)
        _validate_credential_stamp_request(self.request)
        self.input.validate()
        self.material.validate()
        projection, form = _credential_stamp_material_projection_and_form(self.request.material)
        if self.material.projection is not projection or self.material.form is not form:
            raise ValueError("resolved credential material does not match the stamp request")
        _validate_stamped_material_digests(self.expected_digests)
        self.scope.validate()

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialStampExecutionRequest:
        _require_execution_schema(value)
        raw_digests = value.get("expectedDigests")
        if not isinstance(raw_digests, list):
            raise TypeError("expectedDigests must be an array")
        request = cls(
            stamp_id=_required_str(value, "stampId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            request=credential_stamp_request_from_rpc(_required_mapping(value, "request")),
            input=CredentialArtifactInput.from_rpc(_required_mapping(value, "input")),
            material=ResolvedCredentialMaterial.from_rpc(_required_mapping(value, "resolvedMaterial")),
            expected_digests=[
                CredentialStampedMaterialDigest.from_rpc(_as_mapping(item, "expectedDigests item"))
                for item in raw_digests
            ],
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )
        request.validate()
        return request


@dataclass(frozen=True)
class CredentialStampExecutionResult:
    stamp_id: str
    output: CredentialStampOutput
    target_resolution: CredentialStampTargetResolution
    resolved_target: CredentialStampTarget
    bytes_written: str
    material_digests: list[CredentialStampedMaterialDigest]

    def __post_init__(self) -> None:
        if not isinstance(self.output, (CredentialArtifactOutput, CredentialDeploymentOutput)):
            raise TypeError("credential stamp output must be an artifact or deployment")

    def validate(self) -> None:
        _validate_canonical_text(self.stamp_id, "credential stamp result id", _MAXIMUM_CREDENTIAL_ID_BYTES)
        if isinstance(self.output, (CredentialArtifactOutput, CredentialDeploymentOutput)):
            self.output.validate()
        else:
            raise TypeError("credential stamp output must be an artifact or deployment")
        if not isinstance(self.target_resolution, CredentialStampTargetResolution):
            raise TypeError("credential stamp target resolution is invalid")
        _validate_credential_stamp_target(self.resolved_target)
        bytes_written = _parse_canonical_uint64(self.bytes_written, "credential stamp result bytes written")
        if not 1 <= bytes_written <= _MAXIMUM_CREDENTIAL_BINARY_BYTES:
            raise ValueError("credential stamp result bytes written is invalid")
        _validate_stamped_material_digests(self.material_digests)

    def validate_for(self, request: CredentialStampExecutionRequest) -> None:
        request.validate()
        self.validate()
        if self.stamp_id != request.stamp_id:
            raise ValueError("credential stamp result id does not match its request")
        if int(self.bytes_written) != request.request.encoded_bytes:
            raise ValueError("credential stamp result byte count does not match its request")
        if (
            self.target_resolution is CredentialStampTargetResolution.UNCHANGED
            and self.resolved_target != request.request.target
        ):
            raise ValueError("unchanged credential stamp target does not match its request")
        if _stamped_material_digest_map(self.material_digests) != _stamped_material_digest_map(
            request.expected_digests
        ):
            raise ValueError("credential stamp result material digests do not match its request")

    def to_rpc(self) -> dict[str, Any]:
        self.validate()
        if isinstance(self.output, CredentialArtifactOutput):
            output_key = "artifact"
        elif isinstance(self.output, CredentialDeploymentOutput):
            output_key = "deployment"
        else:
            raise TypeError("credential stamp output must be an artifact or deployment")
        return {
            "stampId": self.stamp_id,
            "output": {output_key: self.output.to_rpc()},
            "targetResolution": self.target_resolution.value,
            "resolvedTarget": self.resolved_target.to_rpc(),
            "bytesWritten": self.bytes_written,
            "materialDigests": [digest.to_rpc() for digest in self.material_digests],
        }


def _validate_execution_envelope(schema_version: str, request_id: str) -> None:
    if schema_version != CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1:
        raise ValueError(f"unsupported credential provider execution schema {schema_version!r}")
    _validate_canonical_text(
        request_id,
        "credential provider request id",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )


def _validate_delivery_inputs(
    assignment_id: str,
    slot_name: str,
    credential: ResolvedCredentialMetadata,
    scope: CredentialOperationScope,
) -> None:
    _validate_canonical_text(
        assignment_id,
        "credential assignment id",
        _MAXIMUM_CREDENTIAL_ID_BYTES,
    )
    _validate_canonical_text(slot_name, "credential slot name", _MAXIMUM_CREDENTIAL_ID_BYTES)
    _validate_resolved_credential_metadata(credential)
    scope.validate()


def _validate_digest(data: bytes, value: str, label: str) -> None:
    _validate_sha256(value, label)
    if hashlib.sha256(data).hexdigest() != value:
        raise ValueError(f"{label} sha256 does not match its bytes")


def _validate_stamped_material_digests(digests: list[CredentialStampedMaterialDigest]) -> None:
    if not isinstance(digests, list) or not 1 <= len(digests) <= _MAXIMUM_CREDENTIAL_STAMP_DIGESTS:
        raise ValueError("credential stamped material digests are empty or exceed limits")
    seen: set[tuple[CredentialProjection, str]] = set()
    for digest in digests:
        if not isinstance(digest, CredentialStampedMaterialDigest):
            raise TypeError("credential stamped material digest is invalid")
        digest.validate()
        key = (digest.projection, digest.reference)
        if key in seen:
            raise ValueError("credential stamped material digests contain a duplicate")
        seen.add(key)


def _stamped_material_digest_map(
    digests: list[CredentialStampedMaterialDigest],
) -> dict[tuple[CredentialProjection, str], str]:
    return {(digest.projection, digest.reference): digest.sha256 for digest in digests}


def _require_execution_schema(value: dict[str, Any]) -> None:
    schema = _required_str(value, "schemaVersion")
    if schema != CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1:
        raise ValueError(f"unsupported credential provider execution schema {schema!r}")


def _as_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value
