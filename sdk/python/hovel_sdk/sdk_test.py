import asyncio
import base64
import io
import logging
import tempfile
import threading
import unittest
from dataclasses import asdict
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, cast

import pytest

from hovel_sdk import (
    CREDENTIAL_DELIVERY_SCHEMA_V1,
    CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
    MESH_LISTENER_DEPLOYMENT_SEPARATE,
    MESH_LISTENER_MANAGEMENT_PROVIDER,
    MESH_LISTENER_STATE_ACTIVE,
    MESH_LISTENER_STATE_STOPPED,
    MESH_TARGET_DESTINATION,
    MESH_TARGET_NODE,
    MESH_TARGET_ROUTE,
    MESH_TASK_COMMAND,
    MESH_TASK_STREAM,
    MESH_TASK_SURVEY,
    MESH_TASK_UPLOAD_EXECUTE,
    AgentHint,
    Artifact,
    Context,
    CredentialArtifactInput,
    CredentialArtifactOutput,
    CredentialBytePatternTarget,
    CredentialBytes,
    CredentialConsumerType,
    CredentialDeliveryCapability,
    CredentialDeliveryDescriptor,
    CredentialDeliveryReceipt,
    CredentialEncodingRequest,
    CredentialEncodingResult,
    CredentialEndpointRole,
    CredentialFile,
    CredentialFilesRequest,
    CredentialMaterialForm,
    CredentialMaterialReference,
    CredentialNamedSlotTarget,
    CredentialPrivateMaterialPolicy,
    CredentialProjection,
    CredentialProtectedPath,
    CredentialPurpose,
    CredentialReferencedStampMaterial,
    CredentialRuntimeRequest,
    CredentialScopedReference,
    CredentialSecretReference,
    CredentialSlot,
    CredentialStampExecutionRequest,
    CredentialStampExecutionResult,
    CredentialStampPrecondition,
    CredentialStampPreconditionKind,
    CredentialStampRemainderPolicy,
    CredentialStampRequest,
    CredentialStampTargetKind,
    CredentialStampTargetResolution,
    HovelModule,
    InstalledPayload,
    LineShellSession,
    MeshBeacon,
    MeshBeaconRequest,
    MeshDescribeRequest,
    MeshDescriptor,
    MeshEvent,
    MeshLink,
    MeshListener,
    MeshListenerListRequest,
    MeshListenerSpec,
    MeshListenerStartRequest,
    MeshListenerStopRequest,
    MeshNode,
    MeshRoute,
    MeshStreamRequest,
    MeshTaskRequest,
    MeshTaskResult,
    MeshTaskSpec,
    MeshTopology,
    MeshTopologyRequest,
    MeshTrigger,
    PayloadProviderRecord,
    Requirement,
    ResolvedCredentialMaterial,
    ResolvedCredentialMetadata,
    Result,
    SessionRef,
    setup_logging,
)
from hovel_sdk.credential_delivery import _required_int
from hovel_sdk.framing import (
    MAX_FRAME_BYTES,
    FrameError,
    MessageWriter,
    encode_message,
    read_message,
    write_message,
)
from hovel_sdk.server import JSONRPCServer
from hovel_sdk.session import SessionManager, SessionOpenOptions, SessionScope
from hovel_sdk.testing import ModuleRPC, RPCError, drive_module


def test_advanced_credential_stamp_contract_uses_canonical_wire_types() -> None:
    request = CredentialStampRequest(
        assignment_id="assignment-1",
        capability=CredentialDeliveryCapability.STAMP_ADVANCED,
        slot_name="tls-server",
        target=CredentialBytePatternTarget(
            pattern=b"\xaa\xbb",
            mask=b"\xff\x0f",
            occurrence=1,
            maximum_length="18446744073709551615",
            remainder_policy=CredentialStampRemainderPolicy.ZERO_FILL,
            precondition=CredentialStampPrecondition(
                kind=CredentialStampPreconditionKind.SHA256,
                sha256="0" * 64,
                length="2",
            ),
        ),
        material=CredentialReferencedStampMaterial(
            CredentialMaterialReference(
                projection=CredentialProjection.BUNDLE,
                form=CredentialMaterialForm.PRIVATE_BYTES,
                bundle_id="bundle-1",
            )
        ),
        encoded_bytes=4096,
        credential=ResolvedCredentialMetadata(
            bundle_version="hovel.pki.bundle/v1",
            purpose=CredentialPurpose.TLS_SERVER,
            consumer_type=CredentialConsumerType.MESH_PROVIDER,
            profile_id="tls-server",
            compatibility_target_id="mbedtls-3",
        ),
    )

    wire = request.to_rpc()
    assert wire["target"]["bytePattern"]["maximumLength"] == "18446744073709551615"
    assert base64.b64decode(wire["target"]["bytePattern"]["pattern"]) == b"\xaa\xbb"
    assert wire["material"]["credential"]["bundleId"] == "bundle-1"
    assert wire["credential"]["compatibilityTargetId"] == "mbedtls-3"


def test_credential_provider_secrets_are_redacted_from_repr() -> None:
    material = ResolvedCredentialMaterial(
        projection=CredentialProjection.SIGNER_REFERENCE,
        form=CredentialMaterialForm.PRIVATE_REFERENCE,
        encoding="provider-reference",
        sha256="a" * 64,
        value=CredentialScopedReference(
            provider_id="hsm",
            reference=CredentialSecretReference("capability-secret"),
        ),
    )
    protected_file = CredentialFile(
        projection=CredentialProjection.PRIVATE_KEY_PKCS8,
        form=CredentialMaterialForm.PRIVATE_BYTES,
        media_type="application/pkcs8",
        path="/secret/private-key.der",
        sha256="b" * 64,
        size=32,
    )
    artifact = CredentialArtifactInput(
        artifact_id="artifact-1",
        sha256="c" * 64,
        encoding="raw",
        content=CredentialProtectedPath("/secret/input.bin"),
    )
    diagnostic = repr((material, protected_file, artifact))
    for secret in ("capability-secret", "/secret/private-key.der", "/secret/input.bin"):
        assert secret not in diagnostic
        assert secret not in repr(asdict(material))
        assert secret not in repr(asdict(artifact))


def test_credential_base64_rejects_noncanonical_pad_bits() -> None:
    value = {
        "projection": "bundle",
        "form": "private-bytes",
        "encoding": "raw",
        "sha256": "0" * 64,
        "data": "Zh==",
    }

    with pytest.raises(ValueError, match="canonical base64"):
        ResolvedCredentialMaterial.from_rpc(value)


def test_resolved_credential_material_rejects_invalid_union_states() -> None:
    variants: list[dict[str, Any]] = [
        {},
        {
            "data": base64.b64encode(b"private-bundle").decode("ascii"),
            "reference": {"providerId": "hsm", "reference": "secret-reference"},
        },
    ]
    for variant in variants:
        value: dict[str, Any] = {
            "projection": "bundle",
            "form": "private-bytes",
            "encoding": "hovel-bundle-json",
            "sha256": "0" * 64,
            **variant,
        }

        with pytest.raises(ValueError, match="exactly one data or reference"):
            ResolvedCredentialMaterial.from_rpc(value)


def test_resolved_credential_material_binds_form_to_variant() -> None:
    value = {
        "projection": "signer-reference",
        "form": "private-reference",
        "encoding": "provider-reference",
        "sha256": "0" * 64,
        "data": base64.b64encode(b"not-a-reference").decode("ascii"),
    }

    with pytest.raises(TypeError, match="requires a scoped reference"):
        ResolvedCredentialMaterial.from_rpc(value)


def test_credential_artifact_input_rejects_invalid_union_states() -> None:
    variants: list[dict[str, Any]] = [
        {},
        {
            "data": base64.b64encode(b"artifact").decode("ascii"),
            "path": "/protected/artifact.bin",
        },
    ]
    for variant in variants:
        value = {
            "id": "artifact-1",
            "sha256": "0" * 64,
            "encoding": "raw",
            **variant,
        }

        with pytest.raises(ValueError, match="exactly one data or path"):
            CredentialArtifactInput.from_rpc(value)


def test_credential_artifact_output_serializes_exactly_one_variant() -> None:
    data_output = CredentialArtifactOutput(
        name="data.bin",
        encoding="raw",
        content=CredentialBytes(b"artifact"),
    ).to_rpc()
    path_output = CredentialArtifactOutput(
        name="path.bin",
        encoding="protected-path",
        content=CredentialProtectedPath("/protected/artifact.bin"),
    ).to_rpc()

    assert set(data_output) == {"name", "encoding", "data"}
    assert set(path_output) == {"name", "encoding", "path"}


def test_credential_stamp_result_rejects_unknown_output_variant() -> None:
    with pytest.raises(TypeError, match="artifact or deployment"):
        CredentialStampExecutionResult(
            stamp_id="stamp-1",
            output=cast("Any", object()),
            target_resolution=CredentialStampTargetResolution.UNCHANGED,
            resolved_target=CredentialNamedSlotTarget(name="tls-server"),
            bytes_written="1",
            material_digests=[],
        )


def test_session_manager_does_not_track_failed_open() -> None:
    class FailingSession:
        def __init__(self) -> None:
            self.close_calls = 0

        @property
        def closed(self) -> bool:
            return False

        async def open(self) -> None:
            raise RuntimeError("open failed")

        async def write(self, _data: bytes) -> None:
            pass

        async def read(self, wait: float | None = None) -> bytes:
            _ = wait
            return b""

        async def close(self, reason: str = "closed") -> None:
            _ = reason
            self.close_calls += 1

    async def exercise() -> None:
        manager = SessionManager()
        session = FailingSession()
        with pytest.raises(RuntimeError, match=r"^open failed$"):
            await manager.open(
                session,
                scope=SessionScope(run_id="run-1", module_id="mod", target="target"),
                options=SessionOpenOptions(),
            )

        assert manager.refs_for_run("run-1") == []
        await manager.close_all(reason="test")
        assert session.close_calls == 0

    asyncio.run(exercise())


def test_mesh_task_result_deduplicates_opened_sessions() -> None:
    def session_ref(session_id: str) -> SessionRef:
        return SessionRef(
            id=session_id,
            run_id="run-1",
            module_id="mesh-module",
            target="target-1",
        )

    result = MeshTaskResult(sessions=[session_ref("session-1")]).to_rpc(
        sessions=[
            session_ref("session-1"),
            session_ref("session-2"),
            session_ref("session-2"),
        ]
    )

    assert [session["id"] for session in result["sessions"]] == ["session-1", "session-2"]


def test_mesh_requests_reject_mismatched_wire_types() -> None:
    malformed: list[dict[str, Any]] = [
        {},
        {"kind": False},
        {"kind": " "},
        {"kind": MESH_TASK_COMMAND, "runId": 7},
        {"kind": MESH_TASK_COMMAND, "destinationPort": "445"},
        {"kind": MESH_TASK_COMMAND, "destinationPort": 65_536},
        {"kind": MESH_TASK_COMMAND, "args": ["whoami", 1]},
        {"kind": MESH_TASK_COMMAND, "route": "relay-1"},
        {"kind": MESH_TASK_COMMAND, "route": {}},
        {"kind": MESH_TASK_COMMAND, "route": {"nodes": ["relay-1", 2]}},
        {"kind": MESH_TASK_COMMAND, "config": []},
    ]
    for value in malformed:
        with pytest.raises((TypeError, ValueError)):
            MeshTaskRequest.from_rpc(value)

    request = MeshTaskRequest.from_rpc(
        {
            "kind": MESH_TASK_COMMAND,
            "destinationPort": 65_535,
            "route": {"nodes": ["relay-1"], "attributes": {"extension": {"x": 1}}},
            "config": {"extension": {"x": 1}},
        }
    )
    assert request.destination_port == 65_535
    assert request.config == {"extension": {"x": 1}}
    assert request.route == MeshRoute(nodes=["relay-1"], attributes={"extension": {"x": 1}})
    assert not MeshTopologyRequest.from_rpc({"includeRoutes": "false"}).include_routes


def test_credential_integer_contract_bounds() -> None:
    maximum_binary_bytes = 24 << 20
    cases = {
        "encodedBytes": (1, maximum_binary_bytes),
        "maximumEncodedBytes": (1, maximum_binary_bytes),
        "size": (1, maximum_binary_bytes),
        "occurrence": (0, (1 << 32) - 1),
    }
    for field_name, (minimum, maximum) in cases.items():
        assert _required_int({field_name: minimum}, field_name) == minimum
        assert _required_int({field_name: maximum}, field_name) == maximum
        for invalid in (minimum - 1, maximum + 1):
            with pytest.raises(ValueError, match=field_name):
                _required_int({field_name: invalid}, field_name)
        invalid_wire_values: tuple[Any, ...] = (True, 1.5, "1")
        for invalid in invalid_wire_values:
            with pytest.raises(TypeError, match=field_name):
                _required_int({field_name: invalid}, field_name)


class EchoModule(HovelModule):
    name = "echo"
    version = "v0.0.0-test"
    module_type = "survey"
    global_config: ClassVar[tuple[Requirement, ...]] = (Requirement("operator.confirmed_lab", "bool"),)
    target_config: ClassVar[tuple[Requirement, ...]] = (Requirement("target.host", "host"),)

    def run(self, ctx: Context) -> Result:
        ctx.log.info("echo running", extra={"target": ctx.target})
        return Result.ok({"target": ctx.target}, summary="echo done")


class ContextModule(HovelModule):
    name = "context-module"
    version = "v0.0.0-test"
    module_type = "survey"
    discovery_context: ClassVar[dict[str, Any]] = {"summary": "Find SMB exposure", "keywords": ["ms17-010"]}
    planning_context: ClassVar[dict[str, Any]] = {"risk": {"level": "low"}}

    def run(self, _ctx: Context) -> Result:
        return Result.ok({})


class TestShell(LineShellSession):
    async def handle_command(self, command: str) -> str:
        if command == "whoami":
            return "mock-user"
        return f"unknown command: {command}"


class SessionModule(HovelModule):
    name = "session-echo"
    version = "v0.0.0-test"
    module_type = "exploit"

    async def run(self, ctx: Context) -> Result:
        session = await ctx.open_session(
            TestShell(prompt="mock$ "),
            name="mock shell",
            capabilities=("read", "write", "exec", "close"),
        )
        return Result.ok({"sessionId": session.id}, summary="session opened")


class StepModule(HovelModule):
    name = "step-module"
    version = "v0.0.0-test"
    module_type = "payload_provider"

    def describe_steps(self) -> dict[str, Any]:
        return {
            "steps": [
                {
                    "id": "squatter.connect_smb",
                    "kind": "session.connector",
                    "configSchema": {"type": "object"},
                    "requires": [
                        {
                            "type": "PayloadInstance",
                            "schemaVersion": "v1",
                            "attributes": {"provider": "squatter", "transport": "smb-named-pipe"},
                            "states": ["installed", "disconnected", "installed_unconnected"],
                        },
                        {
                            "type": "CredentialCapability",
                            "schemaVersion": "v1",
                            "attributes": {"protocol": "smb"},
                            "states": ["active"],
                        },
                    ],
                    "produces": [
                        {
                            "type": "SessionRef",
                            "schemaVersion": "v1",
                            "attributes": {"provider": "squatter", "transport": "smb-named-pipe"},
                        }
                    ],
                    "prepare": {"materializes": []},
                }
            ]
        }

    def prepare_step(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "plannedOutputs": [
                {
                    "id": "cap_credential_6mb8pq",
                    "type": "CredentialCapability",
                    "schemaVersion": "v1",
                    "state": "planned",
                    "producerStepId": request["stepId"],
                    "attributes": {
                        "protocol": "smb",
                        "username": "m7q4z92d",
                        "password": "plain-high-entropy-password",
                        "sensitive": True,
                    },
                }
            ],
            "preparedValues": {
                "username": {"value": "m7q4z92d", "editable": True},
                "password": {"value": "plain-high-entropy-password", "editable": True},
            },
            "operatorSummary": {"targetSideArtifacts": ["local admin user m7q4z92d"], "warnings": []},
        }

    def execute_step(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "succeeded",
            "capabilities": [
                {
                    "id": "cap_session_q8m2v4",
                    "type": "SessionRef",
                    "schemaVersion": "v1",
                    "state": "connected",
                    "producerStepId": request["stepId"],
                    "attributes": {"provider": "squatter", "transport": "smb-named-pipe"},
                }
            ],
            "evidence": [
                {
                    "id": "ev_connected",
                    "level": "info",
                    "kind": "session.connected",
                    "sourceStepId": request["stepId"],
                    "message": "connected",
                }
            ],
        }

    def cleanup_step(self, _request: dict[str, Any]) -> dict[str, Any]:
        return {"status": "cleanup_verified"}

    def run(self, _ctx: Context) -> Result:
        return Result.ok(summary="not used")


class MeshModule(HovelModule):
    name = "mesh-module"
    version = "v0.0.0-test"
    module_type = "exploit"

    def describe_credential_delivery(self) -> CredentialDeliveryDescriptor:
        descriptor = self.describe_mesh(MeshDescribeRequest()).credential_delivery
        assert descriptor is not None
        return descriptor

    def describe_mesh(self, _request: MeshDescribeRequest) -> MeshDescriptor:
        return MeshDescriptor(
            name="lab mesh",
            version="v0.1.0",
            summary="Node operations plane for lab routing.",
            capabilities=["mesh.node", "mesh.route", "mesh.destination", "mesh.beacon", "mesh.trigger"],
            topology=self.mesh_topology(MeshTopologyRequest(root="controller", include_routes=True)),
            tasks=[
                MeshTaskSpec(
                    kind=MESH_TASK_SURVEY,
                    summary="Survey one mesh node.",
                    read_only=True,
                    target_scopes=[MESH_TARGET_NODE],
                ),
                MeshTaskSpec(
                    kind=MESH_TASK_COMMAND,
                    summary="Run a provider-owned command task.",
                    target_scopes=[MESH_TARGET_NODE, MESH_TARGET_ROUTE, MESH_TARGET_DESTINATION],
                ),
                MeshTaskSpec(
                    kind=MESH_TASK_UPLOAD_EXECUTE,
                    summary="Upload and execute through a node-owned delivery path.",
                    destructive=True,
                    target_scopes=[MESH_TARGET_DESTINATION],
                ),
                MeshTaskSpec(
                    kind=MESH_TASK_STREAM,
                    summary="Open a routed protocol flow.",
                    opens_stream=True,
                    target_scopes=[MESH_TARGET_ROUTE, MESH_TARGET_DESTINATION],
                ),
            ],
            listener_types=[
                MeshListenerSpec(
                    kind="https",
                    summary="HTTPS rendezvous listener",
                    deployments=[MESH_LISTENER_DEPLOYMENT_SEPARATE],
                    management_modes=[MESH_LISTENER_MANAGEMENT_PROVIDER],
                    protocols=["https"],
                    config_schema={"type": "object"},
                )
            ],
            triggers=[
                MeshTrigger(
                    id="trigger-beacon-late",
                    kind="beacon.stale",
                    node_id="leaf-1",
                    action_kind=MESH_TASK_SURVEY,
                )
            ],
            credential_delivery=CredentialDeliveryDescriptor(
                capabilities=[
                    CredentialDeliveryCapability.RUNTIME,
                    CredentialDeliveryCapability.STAMP_STANDARD,
                ],
                slots=[
                    CredentialSlot(
                        name="control-plane-mtls",
                        purpose=CredentialPurpose.MTLS_SERVER,
                        endpoint_role=CredentialEndpointRole.SERVER,
                        consumer_type=CredentialConsumerType.MESH_LISTENER,
                        accepted_bundle_versions=["hovel.pki.bundle/v1"],
                        accepted_profiles=["mtls-server"],
                        accepted_compatibility_targets=["portable-x509"],
                        accepted_projections=[CredentialProjection.BUNDLE],
                        accepted_material_forms=[CredentialMaterialForm.PRIVATE_BYTES],
                        maximum_encoded_bytes=16 * 1024,
                        remainder_policy=CredentialStampRemainderPolicy.PRESERVE,
                        private_material=CredentialPrivateMaterialPolicy.ALLOWED,
                    )
                ],
                stamp_target_kinds=[CredentialStampTargetKind.NAMED_SLOT],
            ),
        )

    def mesh_topology(self, _request: MeshTopologyRequest) -> MeshTopology:
        return MeshTopology(
            root="controller",
            nodes=[
                MeshNode(id="controller", kind="controller", state="online"),
                MeshNode(id="relay-1", parent_id="controller", kind="relay", state="online"),
                MeshNode(id="leaf-1", parent_id="relay-1", kind="agent", state="online"),
            ],
            links=[
                MeshLink(id="controller-relay-1", source="controller", target="relay-1", state="up"),
                MeshLink(id="relay-1-leaf-1", source="relay-1", target="leaf-1", state="up"),
            ],
            routes=[
                MeshRoute(
                    id="route-leaf-1",
                    nodes=["controller", "relay-1", "leaf-1"],
                    links=["controller-relay-1", "relay-1-leaf-1"],
                )
            ],
        )

    def list_mesh_beacons(self, request: MeshBeaconRequest) -> list[MeshBeacon]:
        node_id = request.node_id or "leaf-1"
        return [
            MeshBeacon(
                id="beacon-1",
                node_id=node_id,
                state="online",
                transport="relay",
                remote_addr="10.10.0.5:4444",
                interval_seconds=30,
            )
        ]

    def list_mesh_listeners(self, request: MeshListenerListRequest) -> list[MeshListener]:
        return [
            MeshListener(
                id=request.listener_id or "listener-primary",
                name="primary HTTPS listener",
                kind="https",
                state=MESH_LISTENER_STATE_ACTIVE,
                deployment=MESH_LISTENER_DEPLOYMENT_SEPARATE,
                management=MESH_LISTENER_MANAGEMENT_PROVIDER,
                addresses=["https://127.0.0.1:8443"],
                protocols=["https"],
            )
        ]

    def start_mesh_listener(self, request: MeshListenerStartRequest) -> MeshListener:
        return MeshListener(
            id=request.listener_id,
            name=request.name,
            kind=request.kind,
            state=MESH_LISTENER_STATE_ACTIVE,
            deployment=request.deployment,
            management=request.management,
            addresses=["https://127.0.0.1:8443"],
            protocols=["https"],
        )

    def stop_mesh_listener(self, request: MeshListenerStopRequest) -> MeshListener:
        return MeshListener(
            id=request.listener_id,
            state=MESH_LISTENER_STATE_STOPPED,
            deployment=MESH_LISTENER_DEPLOYMENT_SEPARATE,
            management=MESH_LISTENER_MANAGEMENT_PROVIDER,
        )

    def load_runtime_credential(self, request: CredentialRuntimeRequest) -> CredentialDeliveryReceipt:
        return CredentialDeliveryReceipt(request_id=request.request_id, provider_reference="runtime-loaded")

    def load_credential_files(self, request: CredentialFilesRequest) -> CredentialDeliveryReceipt:
        return CredentialDeliveryReceipt(request_id=request.request_id, provider_reference="files-loaded")

    def encode_credential_material(self, request: CredentialEncodingRequest) -> CredentialEncodingResult:
        return CredentialEncodingResult(
            request_id=request.request_id,
            form=request.output_form,
            encoding="provider-test",
            sha256="1" * 64,
            data=b"encoded",
        )

    def stamp_credential(self, request: CredentialStampExecutionRequest) -> CredentialStampExecutionResult:
        return CredentialStampExecutionResult(
            stamp_id=request.stamp_id,
            output=CredentialArtifactOutput(
                name="stamped.bin",
                encoding="raw",
                content=CredentialBytes(b"stamped"),
            ),
            target_resolution=CredentialStampTargetResolution.UNCHANGED,
            resolved_target=request.request.target,
            bytes_written=str(request.request.encoded_bytes),
            material_digests=list(request.expected_digests),
        )

    def run_mesh_task(self, ctx: Context, request: MeshTaskRequest) -> MeshTaskResult:
        return MeshTaskResult(
            task_id=request.task_id,
            status="succeeded",
            summary=f"{request.kind} completed",
            node_id=request.node_id,
            route=request.route,
            destination_host=request.destination_host,
            destination_port=request.destination_port,
            protocol=request.protocol,
            outputs={
                "args": request.args,
                "config": request.config,
                "contextRunId": ctx.run_id,
                "contextModuleId": ctx.module_id,
                "contextTarget": ctx.target,
            },
            beacons=self.list_mesh_beacons(MeshBeaconRequest(node_id=request.node_id)),
        )

    async def open_mesh_stream(self, ctx: Context, request: MeshStreamRequest) -> SessionRef:
        return await ctx.open_session(
            TestShell(prompt="mesh$ "),
            name=f"stream to {request.destination_host}:{request.destination_port}",
            kind="stream",
            transport="mesh-route",
            capabilities=("read", "write", "close"),
        )

    def run(self, _ctx: Context) -> Result:
        return Result.ok(summary="not used")


class AgentAwareModule(HovelModule):
    name = "agent-aware"
    version = "v0.0.0-test"
    module_type = "survey"

    def run(self, ctx: Context) -> Result:
        if ctx.agent is None:
            return Result.ok({"agentPresent": False}, summary="agent absent")
        return Result.ok(
            {
                "agentPresent": True,
                "entityId": ctx.agent.entity.id,
                "entityKind": ctx.agent.entity.kind,
                "phase": ctx.agent.phase,
            },
            summary="agent present",
        ).with_agent_hints(
            AgentHint(
                phase="execute",
                audience="assistant",
                risk="low",
                text="Prefer read-only inspection before changing state.",
                provenance={"moduleId": "agent-aware@v0.0.0-test"},
            )
        )


class _FragmentingStream:
    def __init__(self) -> None:
        self._buffer = io.BytesIO()

    def write(self, data: bytes) -> int:
        midpoint = max(1, len(data) // 2)
        first = self._buffer.write(data[:midpoint])
        threading.Event().wait(0.001)
        second = self._buffer.write(data[midpoint:])
        return first + second

    def flush(self) -> None:
        return

    def getvalue(self) -> bytes:
        return self._buffer.getvalue()


def _write_many_messages(writer: MessageWriter, prefix: str) -> None:
    for index in range(25):
        writer.write(
            {
                "jsonrpc": "2.0",
                "method": "module/log",
                "params": {"message": f"{prefix}-{index}"},
            }
        )


def _read_all_messages(stream: BinaryIO) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    while True:
        message = read_message(stream)
        if message is None:
            return messages
        messages.append(message)


class SDKTest(unittest.TestCase):
    def test_lsp_framing_round_trips_json_rpc(self) -> None:
        message = {"jsonrpc": "2.0", "id": 1, "method": "handshake"}
        stream = io.BytesIO(encode_message(message))
        self.assertEqual(read_message(stream), message)

    def test_mesh_required_fields_are_serialized_when_empty(self) -> None:
        self.assertEqual(MeshRoute(nodes=[]).to_rpc()["nodes"], [])
        self.assertEqual(MeshEvent(kind="").to_rpc()["kind"], "")

    def test_read_message_rejects_oversized_frame_before_body_read(self) -> None:
        stream = io.BytesIO(f"Content-Length: {MAX_FRAME_BYTES + 1}\r\n\r\n".encode())
        try:
            read_message(stream)
        except FrameError as exc:
            self.assertIn("exceeds maximum", str(exc))
        else:
            self.fail("expected oversized frame to be rejected")

    def test_write_message_uses_content_length(self) -> None:
        stream = io.BytesIO()
        write_message(stream, {"ok": True})
        self.assertTrue(stream.getvalue().startswith(b"Content-Length: "))

    def test_message_writer_serializes_concurrent_frames(self) -> None:
        stream = _FragmentingStream()
        writer = MessageWriter(cast("BinaryIO", stream))

        threads = [threading.Thread(target=_write_many_messages, args=(writer, prefix)) for prefix in ("a", "b", "c")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        read_stream = io.BytesIO(stream.getvalue())
        messages = _read_all_messages(read_stream)

        self.assertEqual(len(messages), 75)
        self.assertEqual(
            sorted(message["params"]["message"] for message in messages),
            sorted(f"{prefix}-{index}" for prefix in ("a", "b", "c") for index in range(25)),
        )

    def test_server_executes_module_and_emits_log_notification(self) -> None:
        stdin = io.BytesIO(
            encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "execute",
                    "params": {"runId": "run-1", "moduleId": "echo", "target": "mock://target"},
                }
            )
            + encode_message({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
        )
        stdout = io.BytesIO()

        JSONRPCServer(EchoModule(), stdin, stdout).serve_forever()

        messages: list[dict[str, Any]] = []
        stdout.seek(0)
        while True:
            message = read_message(stdout)
            if message is None:
                break
            messages.append(message)
        self.assertEqual(messages[0]["method"], "module/log")
        self.assertEqual(messages[1]["result"]["summary"], "echo done")
        self.assertEqual(messages[2]["result"]["status"], "ok")

    def test_schema_returns_module_declared_requirements(self) -> None:
        stdin = io.BytesIO(encode_message({"jsonrpc": "2.0", "id": 1, "method": "schema"}))
        stdout = io.BytesIO()

        JSONRPCServer(EchoModule(), stdin, stdout).serve_forever()

        stdout.seek(0)
        message = read_message(stdout)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message["result"]["chainConfig"][0]["key"], "operator.confirmed_lab")
        self.assertEqual(message["result"]["targetConfig"][0]["type"], "host")

    def test_context_fields_are_optional_and_opt_in(self) -> None:
        self.assertNotIn("discoveryContext", EchoModule().info())
        self.assertNotIn("planningContext", EchoModule().module_schema())
        self.assertEqual(ContextModule().info()["discoveryContext"]["keywords"], ["ms17-010"])
        self.assertEqual(ContextModule().module_schema()["planningContext"]["risk"]["level"], "low")

    def test_execute_exposes_optional_agent_context(self) -> None:
        without_agent = io.BytesIO(
            encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "execute",
                    "params": {"runId": "run-1", "moduleId": "agent-aware", "target": "mock://target"},
                }
            )
        )
        stdout = io.BytesIO()
        JSONRPCServer(AgentAwareModule(), without_agent, stdout).serve_forever()
        stdout.seek(0)
        message = read_message(stdout)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message["result"]["outputs"], {"agentPresent": False})
        self.assertNotIn("agentHints", message["result"])

        with_agent = io.BytesIO(
            encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "execute",
                    "params": {
                        "runId": "run-2",
                        "moduleId": "agent-aware",
                        "target": "mock://target",
                        "agentContext": {
                            "schema": "hovel.agent_context.v1",
                            "entity": {
                                "id": "entity-mcp",
                                "kind": "mcp",
                                "displayName": "Codex",
                                "agent": True,
                            },
                            "operation": "redteam-lab",
                            "chain": "alpha",
                            "planId": "plan-1",
                            "planHash": "hash-1",
                            "approvalState": "pending",
                            "phase": "execute",
                            "resources": ["hovel://throw-plan/plan-1"],
                        },
                    },
                }
            )
        )
        stdout = io.BytesIO()
        JSONRPCServer(AgentAwareModule(), with_agent, stdout).serve_forever()
        stdout.seek(0)
        message = read_message(stdout)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message["result"]["outputs"]["entityId"], "entity-mcp")
        self.assertEqual(message["result"]["outputs"]["entityKind"], "mcp")
        self.assertEqual(message["result"]["agentHints"][0]["schema"], "hovel.agent_hint.v1")
        self.assertEqual(message["result"]["agentHints"][0]["provenance"]["moduleId"], "agent-aware@v0.0.0-test")

    def test_step_contract_methods_dispatch_over_json_rpc(self) -> None:
        stdin = io.BytesIO(
            encode_message({"jsonrpc": "2.0", "id": 1, "method": "step.describe"})
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "step.prepare",
                    "params": {"preparedPlanId": "prep-1", "stepId": "windows.credential.create_local_admin"},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "step.execute",
                    "params": {"runId": "run-1", "stepId": "squatter.connect_smb"},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "step.cleanup",
                    "params": {"runId": "run-1", "stepId": "squatter.cleanup_smb"},
                }
            )
        )
        stdout = io.BytesIO()

        JSONRPCServer(StepModule(), stdin, stdout).serve_forever()

        messages: list[dict[str, Any]] = []
        stdout.seek(0)
        while True:
            message = read_message(stdout)
            if message is None:
                break
            messages.append(message)

        self.assertEqual(messages[0]["result"]["steps"][0]["id"], "squatter.connect_smb")
        self.assertEqual(
            messages[1]["result"]["preparedValues"]["password"]["value"],
            "plain-high-entropy-password",
        )
        self.assertEqual(messages[2]["result"]["status"], "succeeded")
        self.assertEqual(messages[3]["result"]["status"], "cleanup_verified")

    def test_mesh_methods_dispatch_over_json_rpc(self) -> None:
        route = {"id": "route-leaf-1", "nodes": ["controller", "relay-1", "leaf-1"]}
        stdin = io.BytesIO(
            encode_message({"jsonrpc": "2.0", "id": 1, "method": "mesh.describe"})
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "mesh.topology",
                    "params": {"root": "controller", "includeRoutes": True},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "mesh.beacons",
                    "params": {"nodeId": "leaf-1"},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "mesh.task",
                    "params": {
                        "runId": "run-mesh-1",
                        "taskId": "task-1",
                        "kind": MESH_TASK_COMMAND,
                        "nodeId": "relay-1",
                        "route": route,
                        "destinationHost": "10.10.0.99",
                        "destinationPort": 445,
                        "protocol": "tcp",
                        "config": {"command": "whoami"},
                        "args": ["--read-only"],
                    },
                }
            )
        )
        stdout = io.BytesIO()

        JSONRPCServer(MeshModule(), stdin, stdout).serve_forever()

        messages: list[dict[str, Any]] = []
        stdout.seek(0)
        while True:
            message = read_message(stdout)
            if message is None:
                break
            messages.append(message)

        describe = next(message for message in messages if message.get("id") == 1)
        self.assertEqual(describe["result"]["name"], "lab mesh")
        self.assertEqual(describe["result"]["tasks"][2]["targetScopes"], [MESH_TARGET_DESTINATION])
        self.assertEqual(
            describe["result"]["credentialDelivery"]["deliveryCapabilities"],
            ["runtime", "stamp-standard"],
        )
        topology = next(message for message in messages if message.get("id") == 2)
        self.assertEqual(topology["result"]["routes"][0]["nodes"], ["controller", "relay-1", "leaf-1"])
        beacons = next(message for message in messages if message.get("id") == 3)
        self.assertEqual(beacons["result"]["beacons"][0]["nodeId"], "leaf-1")
        task = next(message for message in messages if message.get("id") == 4)
        self.assertEqual(task["result"]["destinationHost"], "10.10.0.99")
        self.assertEqual(task["result"]["route"]["id"], "route-leaf-1")
        self.assertEqual(task["result"]["outputs"]["config"]["command"], "whoami")

    def test_mesh_context_defaults_blank_scope_fields(self) -> None:
        with ModuleRPC(MeshModule()) as rpc:
            result = rpc.call(
                "mesh.task",
                {
                    "runId": " ",
                    "moduleId": " ",
                    "target": " ",
                    "destinationHost": "10.10.0.99",
                    "kind": MESH_TASK_SURVEY,
                },
            )

        outputs = result["outputs"]
        self.assertEqual(outputs["contextRunId"], "mesh")
        self.assertEqual(outputs["contextModuleId"], "mesh-module@v0.0.0-test")
        self.assertEqual(outputs["contextTarget"], "10.10.0.99")

    def test_credential_provider_methods_dispatch_over_json_rpc(self) -> None:
        credential = {
            "bundleVersion": "hovel.pki.bundle/v1",
            "purpose": "mtls-server",
            "consumerType": "mesh-listener",
            "profileId": "mtls-server",
            "compatibilityTargetId": "portable-x509",
        }
        material = {
            "projection": "bundle",
            "form": "private-bytes",
            "encoding": "hovel-bundle-json",
            "sha256": "0" * 64,
            "data": base64.b64encode(b"private-bundle").decode(),
        }
        provider = {
            "moduleId": "mesh-module",
            "providerId": "mesh-module",
            "providerVersion": "v1.0.0",
            "descriptorSha256": "4" * 64,
        }
        with ModuleRPC(MeshModule()) as rpc:
            descriptor = rpc.call("credential.describe")
            runtime = rpc.call(
                "credential.runtime",
                {
                    "schemaVersion": CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
                    "provider": provider,
                    "requestId": "delivery-runtime-1",
                    "assignmentId": "assignment-1",
                    "slotName": "control-plane-mtls",
                    "credential": credential,
                    "material": material,
                    "scope": {"listenerId": "listener-primary"},
                },
            )
            files = rpc.call(
                "credential.files",
                {
                    "schemaVersion": CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
                    "provider": provider,
                    "requestId": "delivery-files-1",
                    "assignmentId": "assignment-1",
                    "slotName": "control-plane-mtls",
                    "credential": credential,
                    "files": [
                        {
                            "projection": "certificate-der",
                            "form": "public",
                            "mediaType": "application/pkix-cert",
                            "path": "/provider-input/certificate.der",
                            "sha256": "1" * 64,
                            "size": 512,
                        }
                    ],
                    "scope": {},
                },
            )
            encoded = rpc.call(
                "credential.encode",
                {
                    "schemaVersion": CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
                    "provider": provider,
                    "requestId": "encoding-1",
                    "providerId": "mesh-module",
                    "providerSchema": "v1",
                    "outputForm": "private-bytes",
                    "maximumEncodedBytes": 4096,
                    "source": material,
                    "scope": {},
                },
            )
            stamped = rpc.call(
                "credential.stamp",
                {
                    "schemaVersion": CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1,
                    "provider": provider,
                    "stampId": "credential-stamp-1",
                    "request": {
                        "assignmentId": "assignment-1",
                        "capability": "stamp-standard",
                        "slotName": "control-plane-mtls",
                        "target": {
                            "kind": "named-slot",
                            "namedSlot": {"name": "control-plane-mtls"},
                        },
                        "material": {
                            "projection": "bundle",
                            "credential": {
                                "projection": "bundle",
                                "form": "private-bytes",
                                "bundleId": "bundle-1",
                            },
                        },
                        "encodedBytes": 14,
                        "credential": credential,
                    },
                    "input": {
                        "id": "artifact-1",
                        "sha256": "3" * 64,
                        "encoding": "raw",
                        "data": base64.b64encode(b"input").decode(),
                    },
                    "resolvedMaterial": material,
                    "expectedDigests": [{"projection": "bundle", "reference": "bundle-1", "sha256": "2" * 64}],
                    "scope": {"runId": "run-1"},
                },
            )

        self.assertEqual(descriptor["schemaVersion"], CREDENTIAL_DELIVERY_SCHEMA_V1)

        self.assertEqual(runtime, {"requestId": "delivery-runtime-1", "providerReference": "runtime-loaded"})
        self.assertNotIn("material", runtime)
        self.assertEqual(files["providerReference"], "files-loaded")
        self.assertEqual(base64.b64decode(encoded["data"]), b"encoded")
        self.assertEqual(stamped["stampId"], "credential-stamp-1")
        self.assertEqual(stamped["bytesWritten"], "14")
        self.assertEqual(base64.b64decode(stamped["output"]["artifact"]["data"]), b"stamped")

    def test_mesh_listener_lifecycle_dispatches_over_json_rpc(self) -> None:
        with ModuleRPC(MeshModule()) as rpc:
            listed = rpc.call(
                "mesh.listeners",
                {"listenerId": "  listener-primary  ", "state": "  active  "},
            )
            started = rpc.call(
                "mesh.listener.start",
                {
                    "listenerId": "  listener-web  ",
                    "name": "web-controlled listener",
                    "kind": "https",
                    "deployment": "  separate  ",
                    "management": "  provider  ",
                    "config": {"token": "write-only-secret"},
                },
            )
            stopped = rpc.call("mesh.listener.stop", {"listenerId": "listener-web"})

        self.assertEqual(listed["listeners"][0]["id"], "listener-primary")
        self.assertEqual(started["id"], "listener-web")
        self.assertEqual(started["state"], "active")
        self.assertEqual(started["deployment"], "separate")
        self.assertEqual(started["management"], "provider")
        self.assertNotIn("config", started)
        self.assertEqual(stopped["state"], "stopped")

    def test_mesh_listener_rejects_malformed_or_echoed_config(self) -> None:
        with ModuleRPC(MeshModule()) as rpc, pytest.raises(RPCError, match="config must be an object"):
            rpc.call(
                "mesh.listener.start",
                {"listenerId": "listener-web", "config": "write-only-secret"},
            )

        class LeakyMeshModule(MeshModule):
            def start_mesh_listener(self, request: MeshListenerStartRequest) -> MeshListener:
                return cast(
                    "MeshListener",
                    {"id": request.listener_id, "config": {"token": "leaked-secret"}},
                )

        with (
            ModuleRPC(LeakyMeshModule()) as rpc,
            pytest.raises(RPCError, match="results must not include config"),
        ):
            rpc.call("mesh.listener.start", {"listenerId": "listener-web"})

    def test_mesh_listener_rejects_blank_ids_before_provider_invocation(self) -> None:
        class CountingMeshModule(MeshModule):
            def __init__(self) -> None:
                self.lifecycle_calls = 0

            def start_mesh_listener(self, request: MeshListenerStartRequest) -> MeshListener:
                self.lifecycle_calls += 1
                return super().start_mesh_listener(request)

            def stop_mesh_listener(self, request: MeshListenerStopRequest) -> MeshListener:
                self.lifecycle_calls += 1
                return super().stop_mesh_listener(request)

        module = CountingMeshModule()
        with ModuleRPC(module) as rpc:
            with pytest.raises(RPCError, match="listenerId is required"):
                rpc.call("mesh.listener.start", {"listenerId": "  "})
            with pytest.raises(RPCError, match="listenerId is required"):
                rpc.call("mesh.listener.stop", {})

        self.assertEqual(module.lifecycle_calls, 0)

    def test_artifact_helpers_emit_inline_and_file_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loot.txt"
            path.write_text("loot", encoding="utf-8")

            result = Result.ok(
                artifacts=[
                    Artifact.inline("transcript.txt", "text/plain", "inline bytes"),
                    Artifact.text("notes.txt", b"operator notes"),
                    Artifact.json("summary.json", {"ok": True, "count": 2}),
                    Artifact.file(path, kind="text/plain"),
                ]
            )
            artifacts = result.to_rpc()["artifacts"]

        self.assertEqual(artifacts[0], {"name": "transcript.txt", "kind": "text/plain", "data": "inline bytes"})
        self.assertEqual(artifacts[1], {"name": "notes.txt", "kind": "text/plain", "data": "operator notes"})
        self.assertEqual(
            artifacts[2],
            {"name": "summary.json", "kind": "application/json", "data": '{"count":2,"ok":true}'},
        )
        self.assertEqual(artifacts[3], {"name": "loot.txt", "kind": "text/plain", "path": str(path)})

    def test_result_serializes_installed_payload_descriptors(self) -> None:
        result = Result.ok(summary="installed").with_installed_payloads(
            InstalledPayload(
                provider="squatter",
                payload_id="squatter/windows/x86/windows-7/tcp-bind/pe-exe",
                payload_version="v0.1.0",
                target="192.168.122.142",
                state="installed",
                transport="tcp-bind",
                endpoint="192.168.122.142:9101",
                instance_key="squatter:tcp-bind:192.168.122.142:9101",
                stamp_id="svc123",
                supports_reconnect=True,
                supports_multiple_sessions=True,
                reconnect=PayloadProviderRecord(
                    provider_id="squatter",
                    schema="squatter.tcp_bind.reconnect",
                    schema_version="v1",
                    descriptor={
                        "transport": "tcp-bind",
                        "host": "192.168.122.142",
                        "port": 9101,
                    },
                ),
                cleanup=PayloadProviderRecord(
                    provider_id="ms17-010",
                    schema="ms17_010.smb_service.cleanup",
                    schema_version="v1",
                    descriptor={
                        "remotePath": r"C:\Windows\Temp\svc123.exe",
                        "serviceName": "svc123",
                    },
                ),
                metadata={"launch_method": "ms17-010-smb-service"},
            )
        )

        installed = result.to_rpc()["installedPayloads"][0]
        self.assertEqual(installed["provider"], "squatter")
        self.assertEqual(
            installed["payloadId"],
            "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
        )
        self.assertEqual(installed["reconnect"]["providerId"], "squatter")
        self.assertEqual(installed["reconnect"]["schemaVersion"], "v1")
        self.assertEqual(installed["reconnect"]["descriptor"]["port"], 9101)
        self.assertEqual(installed["cleanup"]["providerId"], "ms17-010")
        self.assertEqual(installed["cleanup"]["descriptor"]["serviceName"], "svc123")

    def test_async_module_can_open_and_drive_shell_session(self) -> None:
        stdin = io.BytesIO(
            encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "execute",
                    "params": {"runId": "run-1", "moduleId": "session-echo", "target": "mock://target"},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "session/read",
                    "params": {"sessionId": "run-1-session-1", "timeoutMs": 100},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/write",
                    "params": {"sessionId": "run-1-session-1", "data": base64.b64encode(b"whoami\n").decode()},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "session/read",
                    "params": {"sessionId": "run-1-session-1", "timeoutMs": 100},
                }
            )
            + encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "shutdown",
                }
            ),
        )
        stdout = io.BytesIO()

        JSONRPCServer(SessionModule(), stdin, stdout).serve_forever()

        messages: list[dict[str, Any]] = []
        stdout.seek(0)
        while True:
            message = read_message(stdout)
            if message is None:
                break
            messages.append(message)

        execute = next(message for message in messages if message.get("id") == 1)
        self.assertEqual(execute["result"]["sessions"][0]["id"], "run-1-session-1")
        prompt = next(message for message in messages if message.get("id") == 2)
        self.assertEqual(base64.b64decode(prompt["result"]["data"]), b"mock$ ")
        output = next(message for message in messages if message.get("id") == 4)
        self.assertEqual(base64.b64decode(output["result"]["data"]), b"mock-user\n")

    def test_logging_handler_forwards_extra_fields(self) -> None:
        emitted: list[dict[str, Any]] = []
        handler = setup_logging(emitted.append)
        try:
            logger = logging.getLogger("test.hovel")
            logger.info("hello %s", "world", extra={"answer": 42})
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertEqual(emitted[0]["message"], "hello world")
        self.assertEqual(emitted[0]["fields"]["answer"], 42)

    def test_module_rpc_helper_executes_and_collects_notifications(self) -> None:
        with ModuleRPC(EchoModule()) as rpc:
            handshake = rpc.call("handshake")
            result = rpc.call(
                "execute",
                {"runId": "run-1", "moduleId": "echo", "target": "mock://target"},
            )

            self.assertEqual(handshake["name"], "echo")
            self.assertEqual(result["summary"], "echo done")
            self.assertEqual(rpc.notifications[0]["method"], "module/log")
            self.assertEqual(rpc.notifications[0]["params"]["fields"]["target"], "mock://target")

    def test_handshake_requires_identity_and_type(self) -> None:
        class MissingVersionModule(HovelModule):
            name = "missing-version"
            module_type = "survey"

            def run(self, _ctx: Context) -> Result:
                return Result.ok({})

        with ModuleRPC(MissingVersionModule()) as rpc:
            try:
                rpc.call("handshake")
            except RPCError as exc:
                self.assertIn("module handshake version is required", str(exc))
            else:
                self.fail("handshake succeeded, want missing version error")

    def test_module_rpc_helper_drives_session_round_trip(self) -> None:
        with ModuleRPC(SessionModule()) as rpc:
            execute = rpc.call(
                "execute",
                {"runId": "run-1", "moduleId": "session-echo", "target": "mock://target"},
            )
            self.assertEqual(execute["sessions"][0]["id"], "run-1-session-1")

            prompt = rpc.call("session/read", {"sessionId": "run-1-session-1", "timeoutMs": 100})
            rpc.call(
                "session/write",
                {"sessionId": "run-1-session-1", "data": base64.b64encode(b"whoami\n").decode()},
            )
            output = rpc.call("session/read", {"sessionId": "run-1-session-1", "timeoutMs": 100})

            self.assertEqual(base64.b64decode(prompt["data"]), b"mock$ ")
            self.assertEqual(base64.b64decode(output["data"]), b"mock-user\n")

    def test_module_rpc_helper_drives_step_methods(self) -> None:
        with ModuleRPC(StepModule()) as rpc:
            describe = rpc.call("step.describe")
            prepared = rpc.call(
                "step.prepare",
                {"preparedPlanId": "prep-1", "stepId": "windows.credential.create_local_admin"},
            )
            executed = rpc.call("step.execute", {"runId": "run-1", "stepId": "squatter.connect_smb"})

            self.assertEqual(describe["steps"][0]["id"], "squatter.connect_smb")
            self.assertEqual(prepared["preparedValues"]["username"]["value"], "m7q4z92d")
            self.assertEqual(executed["capabilities"][0]["type"], "SessionRef")

    def test_module_rpc_helper_drives_mesh_stream_session(self) -> None:
        with ModuleRPC(MeshModule()) as rpc:
            session = rpc.call(
                "mesh.open_stream",
                {
                    "runId": "run-mesh-1",
                    "nodeId": "relay-1",
                    "route": {"id": "route-leaf-1", "nodes": ["controller", "relay-1", "leaf-1"]},
                    "destinationHost": "10.10.0.99",
                    "destinationPort": 445,
                    "protocol": "tcp",
                },
            )
            self.assertEqual(session["kind"], "stream")
            self.assertEqual(session["transport"], "mesh-route")

            prompt = rpc.call("session/read", {"sessionId": "run-mesh-1-session-1", "timeoutMs": 100})
            rpc.call(
                "session/write",
                {"sessionId": "run-mesh-1-session-1", "data": base64.b64encode(b"whoami\n").decode()},
            )
            output = rpc.call("session/read", {"sessionId": "run-mesh-1-session-1", "timeoutMs": 100})

            self.assertEqual(base64.b64decode(prompt["data"]), b"mesh$ ")
            self.assertEqual(base64.b64decode(output["data"]), b"mock-user\n")

    def test_module_rpc_helper_raises_on_rpc_error(self) -> None:
        with ModuleRPC(EchoModule()) as rpc:
            try:
                rpc.call("does.not.exist")
            except RPCError as exc:
                self.assertIn("unknown method", str(exc))
            else:
                self.fail("expected RPCError")

    def test_drive_module_runs_script_and_returns_notifications(self) -> None:
        def script(rpc: ModuleRPC) -> None:
            rpc.call("execute", {"runId": "run-1", "moduleId": "echo", "target": "mock://target"})

        notifications = drive_module(EchoModule(), script)

        self.assertEqual(notifications[0]["method"], "module/log")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
