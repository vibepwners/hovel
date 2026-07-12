"""Typed, optional credential provider execution contracts."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hovel_sdk.credential_delivery import (
    CredentialMaterialForm,
    CredentialProjection,
    CredentialStampRequest,
    CredentialStampTarget,
    ResolvedCredentialMetadata,
    _optional_str,
    _required_bytes,
    _required_int,
    _required_mapping,
    _required_str,
    _resolved_credential_metadata_from_rpc,
    credential_stamp_request_from_rpc,
)

CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1 = "hovel.pki.provider-execution/v1"

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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialOperationScope:
        return cls(
            operation_id=_optional_str(value, "operationId"),
            run_id=_optional_str(value, "runId"),
            chain_id=_optional_str(value, "chainId"),
            throw_id=_optional_str(value, "throwId"),
            target=_optional_str(value, "target"),
            listener_id=_optional_str(value, "listenerId"),
            node_id=_optional_str(value, "nodeId"),
        )


@dataclass(frozen=True)
class CredentialProviderTarget:
    module_id: str
    provider_id: str
    provider_version: str
    descriptor_sha256: str

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialProviderTarget:
        return cls(
            module_id=_required_str(value, "moduleId"),
            provider_id=_required_str(value, "providerId"),
            provider_version=_required_str(value, "providerVersion"),
            descriptor_sha256=_required_str(value, "descriptorSha256"),
        )


class CredentialBytes:
    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise ValueError("credential bytes must be non-empty bytes")
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
        if not isinstance(value, str) or not value.strip():
            raise ValueError("credential protected path must be a non-empty string")
        self.__value = value

    @property
    def value(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "<credential secret redacted>"


class CredentialSecretReference:
    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("credential secret reference must be a non-empty string")
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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialScopedReference:
        capabilities = value.get("capabilities", [])
        if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
            raise ValueError("capabilities must be a string list")
        return cls(
            provider_id=_required_str(value, "providerId"),
            reference=CredentialSecretReference(_required_str(value, "reference")),
            capabilities=list(capabilities),
        )


@dataclass(frozen=True)
class ResolvedCredentialMaterial:
    projection: CredentialProjection
    form: CredentialMaterialForm
    encoding: str
    sha256: str
    value: CredentialBytes | CredentialScopedReference

    def __post_init__(self) -> None:
        if self.form == CredentialMaterialForm.PRIVATE_REFERENCE:
            if not isinstance(self.value, CredentialScopedReference):
                raise TypeError("private-reference material requires a scoped reference")
            return
        if not isinstance(self.value, CredentialBytes):
            raise TypeError(f"{self.form.value} material requires credential bytes")

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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialRuntimeRequest:
        _require_execution_schema(value)
        return cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            assignment_id=_required_str(value, "assignmentId"),
            slot_name=_required_str(value, "slotName"),
            credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
            material=ResolvedCredentialMaterial.from_rpc(_required_mapping(value, "material")),
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )


@dataclass(frozen=True)
class CredentialFile:
    projection: CredentialProjection
    form: CredentialMaterialForm
    media_type: str
    path: str = field(repr=False)
    sha256: str = ""
    size: int = 0

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialFile:
        return cls(
            projection=CredentialProjection(_required_str(value, "projection")),
            form=CredentialMaterialForm(_required_str(value, "form")),
            media_type=_required_str(value, "mediaType"),
            path=_required_str(value, "path"),
            sha256=_required_str(value, "sha256"),
            size=_required_int(value, "size"),
        )


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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialFilesRequest:
        _require_execution_schema(value)
        files = value.get("files")
        if not isinstance(files, list):
            raise TypeError("files must be an array")
        return cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            assignment_id=_required_str(value, "assignmentId"),
            slot_name=_required_str(value, "slotName"),
            credential=_resolved_credential_metadata_from_rpc(_required_mapping(value, "credential")),
            files=[CredentialFile.from_rpc(_as_mapping(item, "files item")) for item in files],
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )


@dataclass(frozen=True)
class CredentialDeliveryReceipt:
    request_id: str
    provider_reference: str = ""
    receipt_sha256: str = ""

    def to_rpc(self) -> dict[str, Any]:
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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialEncodingRequest:
        _require_execution_schema(value)
        return cls(
            request_id=_required_str(value, "requestId"),
            provider=CredentialProviderTarget.from_rpc(_required_mapping(value, "provider")),
            provider_id=_required_str(value, "providerId"),
            provider_schema=_required_str(value, "providerSchema"),
            output_form=CredentialMaterialForm(_required_str(value, "outputForm")),
            maximum_encoded_bytes=_required_int(value, "maximumEncodedBytes"),
            source=ResolvedCredentialMaterial.from_rpc(_required_mapping(value, "source")),
            scope=CredentialOperationScope.from_rpc(_required_mapping(value, "scope")),
        )


@dataclass(frozen=True)
class CredentialEncodingResult:
    request_id: str
    form: CredentialMaterialForm
    encoding: str
    sha256: str
    data: bytes = field(repr=False)

    def to_rpc(self) -> dict[str, Any]:
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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialArtifactInput:
        has_data = "data" in value
        has_path = "path" in value
        if has_data == has_path:
            raise ValueError("credential artifact input requires exactly one data or path variant")
        return cls(
            artifact_id=_required_str(value, "id"),
            sha256=_required_str(value, "sha256"),
            encoding=_required_str(value, "encoding"),
            content=(
                CredentialBytes.from_rpc(value, "data")
                if has_data
                else CredentialProtectedPath(_required_str(value, "path"))
            ),
        )


@dataclass(frozen=True)
class CredentialArtifactOutput:
    name: str
    encoding: str
    content: CredentialBytes | CredentialProtectedPath

    def __post_init__(self) -> None:
        if not isinstance(self.content, (CredentialBytes, CredentialProtectedPath)):
            raise TypeError("credential artifact content must be data or a protected path")

    def to_rpc(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "encoding": self.encoding}
        if isinstance(self.content, CredentialBytes):
            out["data"] = self.content.to_rpc()
        else:
            out["path"] = self.content.value
        return out


@dataclass(frozen=True)
class CredentialDeploymentOutput:
    reference: str
    receipt: bytes = field(repr=False)

    def to_rpc(self) -> dict[str, Any]:
        return {"reference": self.reference, "receipt": base64.b64encode(self.receipt).decode("ascii")}


type CredentialStampOutput = CredentialArtifactOutput | CredentialDeploymentOutput


@dataclass(frozen=True)
class CredentialStampedMaterialDigest:
    projection: CredentialProjection
    reference: str
    sha256: str

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialStampedMaterialDigest:
        return cls(
            projection=CredentialProjection(_required_str(value, "projection")),
            reference=_required_str(value, "reference"),
            sha256=_required_str(value, "sha256"),
        )

    def to_rpc(self) -> dict[str, Any]:
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

    @classmethod
    def from_rpc(cls, value: dict[str, Any]) -> CredentialStampExecutionRequest:
        _require_execution_schema(value)
        raw_digests = value.get("expectedDigests")
        if not isinstance(raw_digests, list):
            raise TypeError("expectedDigests must be an array")
        return cls(
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

    def to_rpc(self) -> dict[str, Any]:
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


def _require_execution_schema(value: dict[str, Any]) -> None:
    schema = _required_str(value, "schemaVersion")
    if schema != CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1:
        raise ValueError(f"unsupported credential provider execution schema {schema!r}")


def _as_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value
