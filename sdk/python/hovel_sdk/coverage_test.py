# mypy: disable-error-code="arg-type,attr-defined,unused-ignore"

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import threading
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from hovel_sdk import credential_delivery, credential_provider
from hovel_sdk.context import AgentContext, AgentEntity, Context
from hovel_sdk.framing import MAX_FRAME_BYTES, FrameError, MessageWriter, encode_message, read_message, write_message
from hovel_sdk.logging import setup_logging
from hovel_sdk.mesh import (
    MeshDescriptor,
    MeshTaskResult,
    MeshTopology,
    _bool_value,
    _dict_value,
    _optional_dict,
    _optional_string,
    _string_list,
)
from hovel_sdk.mesh_bridge import (
    MeshBridgeCapability,
    MeshBridgeEndpoint,
    MeshBridgeNetwork,
    _authenticate_udp,
    _numeric_socket_endpoint,
    connect_mesh_bridge,
)
from hovel_sdk.module import HovelModule
from hovel_sdk.payload import (
    PayloadArtifactV1,
    PayloadContent,
    PayloadLoadContract,
    PayloadProviderDescriptor,
    PayloadTarget,
    PayloadVariant,
)
from hovel_sdk.result import AgentHint, Artifact, Finding, InstalledPayload, PayloadProviderRecord, Result
from hovel_sdk.server import (
    JSONRPCServer,
    _merge_rpc_sessions,
    _mesh_listener_lifecycle_to_rpc,
    _validate_handshake_info,
    serve,
)
from hovel_sdk.session import LineShellSession, Session, SessionManager, SessionRef
from hovel_sdk.testing import ModuleRPC, RPCError, _BytePipe


def test_context_fallbacks_and_missing_session_runtime() -> None:
    assert AgentEntity.from_rpc(None) == AgentEntity()
    assert AgentContext.from_rpc(None) is None
    assert AgentContext.from_rpc({"resources": "invalid"}) == AgentContext()

    context = Context("run", "module", "target", {"value": 1}, {"value": 3, "last": 4}, {"value": 2})
    assert context.input("value") == 1
    assert Context("r", "m", "t", target_config={"value": 2}).input("value") == 2
    assert context.input("last") == 4
    assert context.input("missing", 5) == 5
    with pytest.raises(RuntimeError, match="session support is not available"):
        asyncio.run(context.open_session(object()))  # type: ignore[arg-type]


def test_invalid_frames() -> None:
    cases = [
        (b"Content-Length: 2\r\n\r\n{", "truncated frame body"),
        (b"Other: 1\r\n\r\n", "missing Content-Length"),
        (b"\r\nOther: 1\r\n\r\n", "missing Content-Length"),
        (b"Content-Length: nope\r\n\r\n", "invalid Content-Length"),
        (b"Content-Length: -1\r\n\r\n", "invalid Content-Length"),
        (f"Content-Length: {MAX_FRAME_BYTES + 1}\r\n\r\n".encode(), "exceeds maximum"),
        (b"Content-Length: 1\r\n\r\n[", "invalid JSON frame body"),
        (b"Content-Length: 2\r\n\r\n[]", "must be an object"),
        (b"Content-Length: 1", "truncated frame header"),
    ]
    for frame, message in cases:
        with pytest.raises(FrameError, match=message):
            read_message(io.BytesIO(frame))


def test_empty_frames_and_writers() -> None:
    assert read_message(io.BytesIO()) is None
    stream = io.BytesIO()
    write_message(stream, {"ok": True})
    MessageWriter(stream).write({"second": True})
    stream.seek(0)
    assert read_message(stream) == {"ok": True}
    assert read_message(stream) == {"second": True}


def test_default_logging_and_exception_fields() -> None:
    handler = setup_logging()
    try:
        logging.getLogger("coverage").info("discarded")
    finally:
        logging.getLogger().removeHandler(handler)

    emitted: list[dict[str, object]] = []
    handler = setup_logging(emitted.append)
    try:
        try:
            _raise_failure()
        except ValueError:
            logging.getLogger("coverage").exception("caught", extra={"public": 1, "_private": 2})
    finally:
        logging.getLogger().removeHandler(handler)
    assert emitted[0]["fields"] == {"public": 1}
    assert "ValueError: failure" in str(emitted[0]["exception"])


def _raise_failure() -> None:
    raise ValueError("failure")


def test_result_optional_wire_shapes() -> None:
    hint = AgentHint("run", "operator", "low", "text", applies_to={"id": "1"})
    assert hint.to_rpc()["appliesTo"] == {"id": "1"}
    assert "provenance" not in hint.to_rpc()
    assert Artifact.inline("invalid", "text/plain", b"\xff").data == "�"

    record = PayloadProviderRecord("schema", {"key": "value"}, "provider", "v1")
    installed = InstalledPayload(
        "provider",
        "payload",
        "target",
        "active",
        payload_version="1",
        target_id="target-id",
        transport="tcp",
        endpoint="endpoint",
        instance_key="instance",
        stamp_id="stamp",
        supports_reconnect=True,
        supports_multiple_sessions=True,
        reconnect=record,
        cleanup=record,
        metadata={"key": "value"},
    )
    wire = installed.to_rpc()
    assert wire["supportsReconnect"] is True
    assert wire["supportsMultipleSessions"] is True
    assert wire["cleanup"] == record.to_rpc()
    assert Result.failed("failed", findings=[Finding("finding")]).status == "failed"
    assert Finding("finding").to_rpc() == {"title": "finding", "severity": "info", "detail": ""}

    empty_record = PayloadProviderRecord()
    assert empty_record.to_rpc() == {}
    minimal = InstalledPayload("provider", "payload", "target", "active")
    assert minimal.to_rpc() == {"provider": "provider", "payloadId": "payload", "target": "target", "state": "active"}


class _MinimalModule(HovelModule):
    def run(self, _ctx: Context) -> Result:
        return Result.ok()


def test_module_default_contract_methods() -> None:
    module = _MinimalModule()
    assert module.describe_steps() == {"steps": []}
    calls: list[Callable[[], object]] = [
        lambda: module.prepare_step({}),
        lambda: module.execute_step({}),
        lambda: module.cleanup_step({}),
        module.describe_payloads,
        lambda: module.resolve_payload_v1({}),
        lambda: module.generate_payload_v1({}),
        lambda: module.read_payload_artifact({}),
        lambda: module.prepare_payload_listener({}),
        lambda: module.connect_payload({}),
        lambda: module.inspect_payload({}),
        lambda: module.cleanup_installed_payload({}),
        lambda: module.describe_mesh(None),  # type: ignore[arg-type]
        lambda: module.mesh_topology(None),  # type: ignore[arg-type]
        lambda: module.list_mesh_beacons(None),  # type: ignore[arg-type]
        lambda: module.list_mesh_listeners(None),  # type: ignore[arg-type]
        lambda: module.start_mesh_listener(None),  # type: ignore[arg-type]
        lambda: module.stop_mesh_listener(None),  # type: ignore[arg-type]
        lambda: module.run_mesh_task(None, None),  # type: ignore[arg-type]
        lambda: module.open_mesh_stream(None, None),  # type: ignore[arg-type]
        lambda: module.load_runtime_credential(None),  # type: ignore[arg-type]
        module.describe_credential_delivery,
        lambda: module.load_credential_files(None),  # type: ignore[arg-type]
        lambda: module.encode_credential_material(None),  # type: ignore[arg-type]
        lambda: module.stamp_credential(None),  # type: ignore[arg-type]
        lambda: HovelModule.run(module, None),  # type: ignore[arg-type]
    ]
    for call in calls:
        with pytest.raises(NotImplementedError):
            call()


def test_mesh_bridge_capability_rejects_invalid_values() -> None:
    for value in [None, "not-canonical", " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]:
        error = TypeError if value is None else ValueError
        with pytest.raises(error):
            MeshBridgeCapability(value)  # type: ignore[arg-type]


def test_mesh_bridge_endpoint_validation_edges() -> None:
    capability = MeshBridgeCapability("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    invalid_rpc = [
        {"localHost": 1, "localPort": 1, "localNetwork": "tcp", "capability": capability.value},
        {"localHost": "127.0.0.1", "localPort": True, "localNetwork": "tcp", "capability": capability.value},
        {"localHost": "127.0.0.1", "localPort": 1, "localNetwork": 1, "capability": capability.value},
        {"localHost": "127.0.0.1", "localPort": 1, "localNetwork": "tcp", "capability": 1},
    ]
    for value in invalid_rpc:
        with pytest.raises(TypeError):
            MeshBridgeEndpoint.from_rpc(value)
    with pytest.raises(ValueError, match="canonical"):
        MeshBridgeEndpoint(" 127.0.0.1", 1, MeshBridgeNetwork.TCP, capability)
    ipv6 = MeshBridgeEndpoint("::1", 1, MeshBridgeNetwork.TCP, capability)
    assert _numeric_socket_endpoint(ipv6)[1] == ("::1", 1, 0, 0)
    with pytest.raises(TypeError, match="endpoint"):
        connect_mesh_bridge(object())  # type: ignore[arg-type]

    class _ShortSocket:
        def send(self, data: bytes) -> int:
            return len(data) - 1

    with pytest.raises(OSError, match="truncated"):
        _authenticate_udp(_ShortSocket(), b"secret")  # type: ignore[arg-type]


class _WireValue:
    def to_rpc(self) -> dict[str, bool]:
        return {"covered": True}


def test_mesh_optional_serialization_and_conversion_edges() -> None:
    wire = _WireValue()
    assert MeshTopology().to_rpc() == {}
    topology = MeshTopology(root="root", nodes=[wire], links=[wire], routes=[wire])  # type: ignore[list-item]
    assert topology.to_rpc()["routes"] == [{"covered": True}]
    descriptor = MeshDescriptor(
        topology=wire,  # type: ignore[arg-type]
        tasks=[wire],  # type: ignore[list-item]
        listener_types=[wire],  # type: ignore[list-item]
        triggers=[wire],  # type: ignore[list-item]
        credential_delivery=wire,  # type: ignore[arg-type]
    )
    assert descriptor.to_rpc()["credentialDelivery"] == {"covered": True}
    assert MeshDescriptor().to_rpc() == {}

    result = MeshTaskResult.succeeded("done")
    assert result.status == "succeeded"
    full = MeshTaskResult(
        status="succeeded",
        summary="done",
        findings=[Finding("finding")],
        artifacts=[Artifact.text("artifact", "data")],
        events=[wire],  # type: ignore[list-item]
        agent_hints=[{"hint": True}],
    ).to_rpc()
    assert full["findings"][0]["title"] == "finding"
    assert full["events"] == [{"covered": True}]
    assert full["agentHints"] == [{"hint": True}]

    assert _dict_value({"key": "value"}) == {"key": "value"}
    assert _dict_value(None) == {}
    assert _optional_dict({}, "key") == {}
    with pytest.raises(TypeError, match="must be an object"):
        _optional_dict({"key": 1}, "key")
    assert _optional_string({}, "key") == ""
    with pytest.raises(TypeError, match="must be a string"):
        _optional_string({"key": 1}, "key")
    true_value: object = True
    assert _bool_value(true_value) is True
    assert _bool_value("true") is False
    assert _string_list(None) == []
    assert _string_list(["one", 2]) == ["one"]


def test_byte_pipe_close_and_unbounded_read_contract() -> None:
    closed = _BytePipe()
    closed.close()
    with pytest.raises(ValueError, match="closed pipe"):
        closed.write(b"data")
    assert closed.read(1) == b""

    pipe = _BytePipe()
    received: list[bytes] = []
    reader = threading.Thread(target=lambda: received.append(pipe.read()))
    reader.start()
    pipe.write(b"complete")
    pipe.close()
    reader.join(timeout=1)
    assert received == [b"complete"]


def _detached_rpc(*responses: dict[str, object]) -> ModuleRPC:
    rpc = ModuleRPC.__new__(ModuleRPC)
    rpc.notifications = []
    rpc._stdin = _BytePipe()  # noqa: SLF001
    rpc._stdout = io.BytesIO(b"".join(encode_message(item) for item in responses))  # type: ignore[assignment]  # noqa: SLF001
    rpc._next_id = 0  # noqa: SLF001
    rpc._closed = False  # noqa: SLF001
    return rpc


def test_module_rpc_response_validation_edges() -> None:
    rpc = _detached_rpc()
    rpc._closed = True  # noqa: SLF001
    with pytest.raises(RuntimeError, match="closed"):
        rpc.call("method")
    rpc.close()

    with pytest.raises(RuntimeError, match="exited"):
        _detached_rpc().call("method")
    with pytest.raises(RuntimeError, match="unexpected response id"):
        _detached_rpc({"id": 2, "result": {}}).call("method")
    with pytest.raises(RPCError, match="bad"):
        _detached_rpc({"id": 1, "error": {"message": "bad"}}).call("method")
    with pytest.raises(RPCError, match="bad"):
        _detached_rpc({"id": 1, "error": "bad"}).call("method")
    assert _detached_rpc({"method": "notice"}, {"id": 1, "result": 7}).call("method") == {"value": 7}


class _CoverageShell(LineShellSession):
    async def handle_command(self, command: str) -> str | bytes | None:
        if command == "bytes":
            return b"bytes"
        if command == "newline":
            return b"newline\n"
        if command == "close":
            await self.close()
            return None
        return None


def test_session_protocol_defaults_raise() -> None:
    instance = object()
    assert Session.closed.fget is not None
    with pytest.raises(NotImplementedError):
        Session.closed.fget(instance)
    for operation in [
        Session.open(instance),
        Session.write(instance, b"data"),
        Session.read(instance),
        Session.close(instance),
    ]:
        with pytest.raises(NotImplementedError):
            asyncio.run(operation)


def test_line_shell_and_session_manager_edges() -> None:
    async def exercise() -> None:
        shell = _CoverageShell(echo=True)
        await shell.open()
        assert await shell.read() == b"$ "
        await shell.write(b"\nbytes\nnewline\nclose\nignored\n")
        assert await shell.read() == b"\nbytes\nnewline\nclose\nignored\n"
        assert await shell.read() == b"$ "
        assert await shell.read() == b"bytes\n"
        assert await shell.read() == b"$ "
        assert await shell.read() == b"newline\n"
        assert await shell.read() == b"$ "
        assert await shell.read() == b""
        await shell.write(b"ignored after close")
        await shell.close()
        assert await shell.read(wait=0.001) == b""

        base_shell = LineShellSession()
        with pytest.raises(NotImplementedError):
            await base_shell.handle_command("unsupported")
        await base_shell._handle_line("exit")  # noqa: SLF001
        assert base_shell.closed

        events: list[dict[str, object]] = []
        manager = SessionManager(events.append)
        registry = manager.for_run(run_id="run", module_id="module", target="target")
        managed_shell = _CoverageShell()
        ref = await registry.open(managed_shell)
        await managed_shell.close()
        assert await manager.read(ref.id) == b"$ "
        assert manager.refs_for_run("run")[0].state == "closed"
        await manager.close_rpc({"sessionId": ref.id, "reason": "done"})
        assert events[-1]["event"] == "session.closed"
        with pytest.raises(ValueError, match="unknown session"):
            await manager.read("missing")

        quiet = SessionManager()
        quiet_ref = await quiet.for_run(run_id="quiet", module_id="module", target="target").open(_CoverageShell())
        await quiet.close(quiet_ref.id)

    asyncio.run(exercise())


class _ServerModule(_MinimalModule):
    name = "coverage"
    version = "1.0.0"
    module_type = "survey"

    def __init__(self) -> None:
        self.mesh_result: dict[str, object] = {}

    def run_mesh_task(self, _ctx: Context, _request: object) -> dict[str, object]:  # type: ignore[override]
        return dict(self.mesh_result)

    def describe_payloads(self) -> PayloadProviderDescriptor:
        return _payload_descriptor()

    def resolve_payload_v1(self, _request: dict[str, object]) -> PayloadVariant:  # type: ignore[override]
        return _payload_descriptor().payloads[0]

    def generate_payload_v1(self, _request: dict[str, object]) -> PayloadArtifactV1:  # type: ignore[override]
        return PayloadArtifactV1(
            "agent",
            "primary",
            _payload_descriptor().payloads[0],
            "application/octet-stream",
            3,
            "abc",
            PayloadContent(inline_encoding="base64", inline_data="YWJj"),
            {"test.dev/key": True},
        )

    def read_payload_artifact(self, request: dict[str, object]) -> dict[str, object]:  # type: ignore[override]
        return request

    def prepare_payload_listener(self, request: dict[str, object]) -> dict[str, object]:  # type: ignore[override]
        return request

    def connect_payload(self, request: dict[str, object]) -> dict[str, object]:  # type: ignore[override]
        return request

    def inspect_payload(self, request: dict[str, object]) -> dict[str, object]:  # type: ignore[override]
        return request

    def cleanup_installed_payload(self, request: dict[str, object]) -> dict[str, object]:  # type: ignore[override]
        return request


def _payload_descriptor() -> PayloadProviderDescriptor:
    return PayloadProviderDescriptor(
        "coverage",
        "1.0.0",
        ("describe", "generate"),
        (
            PayloadVariant(
                "agent-linux",
                "Agent",
                "1.0.0",
                "agent",
                "elf",
                PayloadTarget("linux", "amd64", abi="gnu", endianness="little", minimum_os="5.4"),
                PayloadLoadContract("process", "main", "pie", ("libc",)),
                ("mesh.task",),
                {"test.dev/key": True},
            ),
        ),
        {"test.dev/provider": True},
    )


def test_payload_v1_wire_shapes_and_dispatch() -> None:
    descriptor = _payload_descriptor()
    assert descriptor.to_rpc()["payloads"][0]["target"]["minimumOs"] == "5.4"
    server = JSONRPCServer(_ServerModule(), io.BytesIO(), io.BytesIO())
    for method in (
        "payload.describe",
        "payload.resolve",
        "payload.generate",
        "payload.artifact.read",
        "payload.listener.prepare",
        "payload.connect",
        "payload.inspect",
        "payload.cleanup",
    ):
        assert server._dispatch(method, {"value": True})  # noqa: SLF001
    with pytest.raises(ValueError, match="unknown method"):
        server._dispatch("payload.unknown", {})  # noqa: SLF001
    server._loop.close()  # noqa: SLF001

    assert PayloadTarget("linux", "amd64").to_rpc() == {"os": "linux", "arch": "amd64"}
    assert PayloadLoadContract("process").to_rpc() == {"executionModel": "process"}
    assert PayloadProviderDescriptor("p", "1", ("describe",)).to_rpc()["providerId"] == "p"
    minimal_variant = PayloadVariant(
        "id", "name", "1", "agent", "elf", PayloadTarget("linux", "amd64"), PayloadLoadContract("process")
    )
    assert "capabilities" not in minimal_variant.to_rpc()
    assert "extensions" not in minimal_variant.to_rpc()
    minimal_artifact = PayloadArtifactV1(
        "name", "primary", minimal_variant, "application/octet-stream", 1, "abc", PayloadContent(artifact_id="a")
    )
    assert "extensions" not in minimal_artifact.to_rpc()
    assert PayloadContent(artifact_id="a").to_rpc() == {"artifact": {"id": "a"}}
    assert PayloadContent(stream_handle="s").to_rpc() == {"stream": {"handle": "s"}}
    with pytest.raises(ValueError, match="exactly one"):
        PayloadContent().to_rpc()


def test_server_loop_and_dispatch_errors() -> None:
    messages = b"".join(
        [
            encode_message({"jsonrpc": "2.0"}),
            encode_message({"jsonrpc": "2.0", "method": "other"}),
            encode_message({"jsonrpc": "2.0", "method": "cancel"}),
            encode_message({"jsonrpc": "2.0", "id": 1, "method": "shutdown"}),
        ]
    )
    output = io.BytesIO()
    JSONRPCServer(_ServerModule(), io.BytesIO(messages), output).serve_forever()
    output.seek(0)
    assert read_message(output)["method"] == "module/log"  # type: ignore[index]
    assert read_message(output) == {"id": 1, "jsonrpc": "2.0", "result": {"status": "ok"}}

    server = JSONRPCServer(_ServerModule(), io.BytesIO(), io.BytesIO())
    response = server._handle_request({"id": 1, "method": 3})  # noqa: SLF001
    assert response["error"]["code"] == -32600
    for method in ["step.unknown", "mesh.unknown", "mesh.listener.unknown", "credential.unknown"]:
        with pytest.raises(ValueError, match="unknown method"):
            server._dispatch(method, {})  # noqa: SLF001

    async def session_dispatch() -> None:
        ref = await server._sessions.for_run(run_id="run", module_id="module", target="target").open(  # noqa: SLF001
            _CoverageShell()
        )
        assert await server._dispatch_session("session/close", {"sessionId": ref.id}) == {  # noqa: SLF001
            "status": "ok"
        }
        with pytest.raises(ValueError, match="unknown method"):
            await server._dispatch_session("session/unknown", {})  # noqa: SLF001
        with pytest.raises(ValueError, match="unknown method"):
            await server._dispatch_mesh_listener("mesh.listener.unknown", {})  # noqa: SLF001

    asyncio.run(session_dispatch())
    server._loop.close()  # noqa: SLF001


def test_server_mesh_result_and_validation_edges() -> None:
    module = _ServerModule()
    server = JSONRPCServer(module, io.BytesIO(), io.BytesIO())

    async def mesh_results() -> None:
        request = {"kind": "command"}
        module.mesh_result = {}
        assert (await server._run_mesh_task(request))["status"] == "succeeded"  # noqa: SLF001
        module.mesh_result = {"status": " "}
        assert (await server._run_mesh_task(request))["status"] == "succeeded"  # noqa: SLF001
        module.mesh_result = {"status": 3}
        assert (await server._run_mesh_task(request))["status"] == 3  # noqa: SLF001

    asyncio.run(mesh_results())
    params = server._mesh_context_params({"destinationHost": "", "nodeId": "node"})  # noqa: SLF001
    assert params["target"] == "node"
    assert server._mesh_context_params({"moduleId": "explicit"})["moduleId"] == "explicit"  # noqa: SLF001
    server._loop.close()  # noqa: SLF001

    with pytest.raises(ValueError, match="result id is required"):
        _mesh_listener_lifecycle_to_rpc("requested", {})
    with pytest.raises(ValueError, match="does not match"):
        _mesh_listener_lifecycle_to_rpc("requested", {"id": "different"})
    with pytest.raises(ValueError, match="moduleType"):
        _validate_handshake_info({"name": "name", "version": "1", "moduleType": "invalid"})

    ref = SessionRef("session", "run", "module", "target")
    empty: dict[str, object] = {}
    _merge_rpc_sessions(empty, [])
    assert empty == {}
    _merge_rpc_sessions(empty, [ref])
    assert empty["sessions"] == [ref.to_rpc()]
    _merge_rpc_sessions(empty, [ref])
    assert empty["sessions"] == [ref.to_rpc()]


def test_serve_translates_frame_errors() -> None:
    with pytest.raises(SystemExit) as caught:
        serve(_ServerModule(), io.BytesIO(b"invalid"), io.BytesIO())
    assert caught.value.code == 2


def test_credential_provider_value_validation_edges() -> None:
    provider = credential_provider
    with pytest.raises(TypeError, match="must be bytes"):
        provider.CredentialBytes("secret")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty"):
        provider.CredentialBytes(b"")
    secret = provider.CredentialBytes(b"secret")
    assert repr(secret) == "<credential bytes redacted>"
    reference = provider.CredentialSecretReference("secret-reference")
    assert reference.value == "secret-reference"

    invalid_references = [
        provider.CredentialScopedReference("provider", object()),  # type: ignore[arg-type]
        provider.CredentialScopedReference("provider", reference, capabilities="read"),  # type: ignore[arg-type]
        provider.CredentialScopedReference("provider", reference, capabilities=["read", "read"]),
        provider.CredentialScopedReference("provider", reference, capabilities=[" invalid"]),
    ]
    for invalid in invalid_references:
        with pytest.raises((TypeError, ValueError)):
            invalid.validate()
    for capabilities in ["read", ["read", 1]]:
        with pytest.raises(ValueError, match="string list"):
            provider.CredentialScopedReference.from_rpc(
                {"providerId": "provider", "reference": "reference", "capabilities": capabilities}
            )
    assert provider.CredentialScopedReference.from_rpc(
        {"providerId": "provider", "reference": "reference", "capabilities": ["read"]}
    ).capabilities == ["read"]

    with pytest.raises(TypeError, match="requires credential bytes"):
        provider.ResolvedCredentialMaterial(
            provider.CredentialProjection.BUNDLE,
            provider.CredentialMaterialForm.PUBLIC,
            "raw",
            "0" * 64,
            object(),  # type: ignore[arg-type]
        ).validate()
    with pytest.raises(TypeError, match="path"):
        provider.CredentialFile(
            provider.CredentialProjection.BUNDLE,
            provider.CredentialMaterialForm.PUBLIC,
            "raw",
            "application/octet-stream",
            object(),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="content"):
        provider.CredentialArtifactInput("artifact", "0" * 64, "raw", object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="content"):
        provider.CredentialArtifactOutput("artifact", "raw", object())  # type: ignore[arg-type]


def test_credential_provider_result_and_helper_edges() -> None:
    provider = credential_provider
    receipt = provider.CredentialDeliveryReceipt("request", "reference", "0" * 64)
    assert receipt.to_rpc()["receiptSha256"] == "0" * 64
    deployment = provider.CredentialDeploymentOutput("reference", b"receipt")
    assert deployment.to_rpc()["receipt"]
    with pytest.raises(ValueError, match="receipt"):
        provider.CredentialDeploymentOutput("reference", b"").validate()

    invalid_digest = provider.CredentialStampedMaterialDigest(  # type: ignore[arg-type]
        "bundle", "reference", "0" * 64
    )
    with pytest.raises(TypeError, match="projection"):
        invalid_digest.validate()
    digest = provider.CredentialStampedMaterialDigest(provider.CredentialProjection.BUNDLE, "reference", "0" * 64)
    with pytest.raises(ValueError, match="empty"):
        provider._validate_stamped_material_digests([])  # noqa: SLF001
    with pytest.raises(TypeError, match="digest is invalid"):
        provider._validate_stamped_material_digests([object()])  # type: ignore[list-item]  # noqa: SLF001
    with pytest.raises(ValueError, match="duplicate"):
        provider._validate_stamped_material_digests([digest, digest])  # noqa: SLF001
    with pytest.raises(ValueError, match="unsupported"):
        provider._validate_execution_envelope("unknown", "request")  # noqa: SLF001
    with pytest.raises(ValueError, match="unsupported"):
        provider._require_execution_schema({"schemaVersion": "unknown"})  # noqa: SLF001
    with pytest.raises(TypeError, match="must be an object"):
        provider._as_mapping([], "value")  # noqa: SLF001


def _provider_contract_values() -> tuple[object, object, object, object]:
    provider = credential_provider
    delivery = credential_delivery
    target = provider.CredentialProviderTarget("module", "provider", "1", "0" * 64)
    metadata = delivery.ResolvedCredentialMetadata(
        "bundle-v1",
        delivery.CredentialPurpose.TLS_SERVER,
        delivery.CredentialConsumerType.SERVICE,
        "profile",
        "target",
    )
    scope = provider.CredentialOperationScope(operation_id="operation")
    data = b"material"
    material = provider.ResolvedCredentialMaterial(
        delivery.CredentialProjection.BUNDLE,
        delivery.CredentialMaterialForm.PUBLIC,
        "raw",
        hashlib.sha256(data).hexdigest(),
        provider.CredentialBytes(data),
    )
    return target, metadata, scope, material


def test_credential_provider_request_invariant_edges() -> None:  # noqa: PLR0915
    provider = credential_provider
    delivery = credential_delivery
    target, metadata, scope, material = _provider_contract_values()
    path = provider.CredentialProtectedPath("/credential")
    credential_file = provider.CredentialFile(
        delivery.CredentialProjection.BUNDLE,
        delivery.CredentialMaterialForm.PUBLIC,
        "raw",
        "application/octet-stream",
        path,
        "0" * 64,
        1,
    )

    corrupted_file = object.__new__(provider.CredentialFile)
    for key, value in credential_file.__dict__.items():
        object.__setattr__(corrupted_file, key, value)
    object.__setattr__(corrupted_file, "path", object())
    with pytest.raises(TypeError, match="path"):
        corrupted_file.validate()
    object.__setattr__(corrupted_file, "path", path)
    object.__setattr__(corrupted_file, "size", 0)
    with pytest.raises(ValueError, match="size"):
        corrupted_file.validate()

    base_files = provider.CredentialFilesRequest(
        "request",
        target,
        "assignment",
        "slot",
        metadata,
        [],
        scope,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="empty"):
        base_files.validate()
    with pytest.raises(TypeError, match="array"):
        provider.CredentialFilesRequest.from_rpc(
            {"schemaVersion": provider.CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1, "files": None}
        )
    duplicate_files = provider.CredentialFilesRequest(
        "request",
        target,
        "assignment",
        "slot",
        metadata,
        [credential_file, credential_file],
        scope,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="duplicate path"):
        duplicate_files.validate()

    encoding = provider.CredentialEncodingRequest(
        "request",
        target,  # type: ignore[arg-type]
        "different",
        "schema",
        delivery.CredentialMaterialForm.PUBLIC,
        10,
        material,  # type: ignore[arg-type]
        scope,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="does not match"):
        encoding.validate()
    object.__setattr__(encoding, "provider_id", "provider")
    object.__setattr__(encoding, "output_form", object())
    with pytest.raises(TypeError, match="output form"):
        encoding.validate()
    object.__setattr__(encoding, "output_form", delivery.CredentialMaterialForm.PUBLIC)
    object.__setattr__(encoding, "maximum_encoded_bytes", 0)
    with pytest.raises(ValueError, match="output bound"):
        encoding.validate()

    result = provider.CredentialEncodingResult("request", delivery.CredentialMaterialForm.PUBLIC, "raw", "0" * 64, b"x")
    object.__setattr__(result, "form", object())
    with pytest.raises(TypeError, match="result form"):
        result.validate()
    object.__setattr__(result, "form", delivery.CredentialMaterialForm.PUBLIC)
    object.__setattr__(result, "data", b"")
    with pytest.raises(ValueError, match="data is empty"):
        result.validate()

    artifact = provider.CredentialArtifactInput("artifact", "0" * 64, "raw", provider.CredentialBytes(b"x"))
    object.__setattr__(artifact, "content", object())
    with pytest.raises(TypeError, match="content"):
        artifact.validate()
    output = provider.CredentialArtifactOutput("artifact", "raw", provider.CredentialBytes(b"x"))
    object.__setattr__(output, "content", object())
    with pytest.raises(TypeError, match="content"):
        output.validate()

    stamp = object.__new__(provider.CredentialStampExecutionRequest)
    object.__setattr__(stamp, "schema_version", "unknown")
    with pytest.raises(ValueError, match="unsupported"):
        stamp.validate()
    with pytest.raises(TypeError, match="expectedDigests"):
        provider.CredentialStampExecutionRequest.from_rpc(
            {"schemaVersion": provider.CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1, "expectedDigests": None}
        )


def test_credential_provider_stamp_result_edges() -> None:
    provider = credential_provider
    delivery = credential_delivery
    target, metadata, scope, material = _provider_contract_values()
    receipt_only = provider.CredentialDeliveryReceipt("request", receipt_sha256="0" * 64)
    assert receipt_only.to_rpc()["receiptSha256"] == "0" * 64
    provider.CredentialArtifactInput(
        "artifact", "0" * 64, "raw", provider.CredentialProtectedPath("/credential")
    ).validate()

    named_target = delivery.CredentialNamedSlotTarget("slot")
    stamp_material = delivery.CredentialReferencedStampMaterial(
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.BUNDLE,
            delivery.CredentialMaterialForm.PUBLIC,
            bundle_id="bundle",
        )
    )
    request = delivery.CredentialStampRequest(
        "assignment",
        delivery.CredentialDeliveryCapability.STAMP_STANDARD,
        "slot",
        named_target,
        stamp_material,
        len(b"material"),
        metadata,  # type: ignore[arg-type]
    )
    digest = provider.CredentialStampedMaterialDigest(delivery.CredentialProjection.BUNDLE, "bundle", "0" * 64)
    artifact_input = provider.CredentialArtifactInput(
        "artifact", hashlib.sha256(b"material").hexdigest(), "raw", provider.CredentialBytes(b"material")
    )
    execution = provider.CredentialStampExecutionRequest(
        "stamp",
        target,  # type: ignore[arg-type]
        request,
        artifact_input,
        material,  # type: ignore[arg-type]
        [digest],
        scope,  # type: ignore[arg-type]
    )
    mismatched_material = provider.ResolvedCredentialMaterial(
        delivery.CredentialProjection.CERTIFICATE_DER,
        delivery.CredentialMaterialForm.PUBLIC,
        "raw",
        hashlib.sha256(b"material").hexdigest(),
        provider.CredentialBytes(b"material"),
    )
    object.__setattr__(execution, "material", mismatched_material)
    with pytest.raises(ValueError, match="does not match the stamp request"):
        execution.validate()

    deployment = provider.CredentialDeploymentOutput("reference", b"receipt")
    result = provider.CredentialStampExecutionResult(
        "stamp",
        deployment,
        provider.CredentialStampTargetResolution.TRANSLATED,
        named_target,
        "1",
        [digest],
    )
    assert result.to_rpc()["output"]["deployment"]
    artifact_result = provider.CredentialStampExecutionResult(
        "stamp",
        provider.CredentialArtifactOutput("artifact", "raw", provider.CredentialBytes(b"x")),
        provider.CredentialStampTargetResolution.TRANSLATED,
        named_target,
        "1",
        [digest],
    )
    assert artifact_result.to_rpc()["output"]["artifact"]

    invalid = object.__new__(provider.CredentialStampExecutionResult)
    for key, value in result.__dict__.items():
        object.__setattr__(invalid, key, value)
    object.__setattr__(invalid, "output", object())
    with pytest.raises(TypeError, match="output"):
        invalid.validate()
    object.__setattr__(invalid, "output", deployment)
    object.__setattr__(invalid, "target_resolution", object())
    with pytest.raises(TypeError, match="resolution"):
        invalid.validate()
    object.__setattr__(invalid, "target_resolution", provider.CredentialStampTargetResolution.TRANSLATED)
    object.__setattr__(invalid, "bytes_written", "0")
    with pytest.raises(ValueError, match="bytes written"):
        invalid.validate()
    object.__setattr__(invalid, "bytes_written", "1")
    object.__setattr__(invalid, "stamp_id", "different")
    fake_request = SimpleNamespace(
        stamp_id="stamp",
        request=SimpleNamespace(encoded_bytes=1, target=named_target),
        expected_digests=[digest],
        validate=lambda: None,
    )
    with pytest.raises(ValueError, match="id does not match"):
        invalid.validate_for(fake_request)  # type: ignore[arg-type]
    object.__setattr__(invalid, "output", object())
    with pytest.raises(TypeError, match="output"):
        invalid.to_rpc()


def test_credential_delivery_serializes_all_target_variants() -> None:
    delivery = credential_delivery
    none = delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.NONE)
    bytes_precondition = delivery.CredentialStampPrecondition(
        delivery.CredentialStampPreconditionKind.BYTES, bytes_value=b"expected"
    )
    sha_precondition = delivery.CredentialStampPrecondition(
        delivery.CredentialStampPreconditionKind.SHA256, sha256="0" * 64, length="8"
    )
    assert bytes_precondition.to_rpc()["bytes"]
    assert sha_precondition.to_rpc()["length"] == "8"

    targets = [
        delivery.CredentialNamedSlotTarget("slot"),
        delivery.CredentialFileOffsetTarget("1", "64", "1", delivery.CredentialStampRemainderPolicy.PRESERVE, none),
        delivery.CredentialVirtualAddressTarget(
            "1",
            delivery.CredentialStampAddressSpace.PE_RVA,
            "64",
            "1",
            delivery.CredentialStampRemainderPolicy.ZERO_FILL,
            none,
            image_base="4096",
        ),
        delivery.CredentialSymbolTarget(
            "symbol", "64", delivery.CredentialStampRemainderPolicy.PRESERVE, none, section=".data"
        ),
        delivery.CredentialMarkerTarget(b"marker", maximum_length="64", precondition=none),
        delivery.CredentialBytePatternTarget(b"pattern", b"\xff" * 7, maximum_length="64", precondition=none),
        delivery.CredentialProviderDefinedTarget("provider", "v1", {"target": True}),
    ]
    kinds = [target.to_rpc()["kind"] for target in targets]
    assert kinds == [kind.value for kind in delivery.CredentialStampTargetKind]


def test_credential_delivery_serializes_material_and_descriptor_variants() -> None:
    delivery = credential_delivery
    references = [
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.BUNDLE,
            delivery.CredentialMaterialForm.PUBLIC,
            bundle_id="bundle",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.CERTIFICATE_DER,
            delivery.CredentialMaterialForm.PUBLIC,
            generation_id="generation",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.PRIVATE_KEY_PKCS8,
            delivery.CredentialMaterialForm.PRIVATE_BYTES,
            generation_id="generation",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.PUBLIC_KEY_SPKI,
            delivery.CredentialMaterialForm.PUBLIC,
            generation_id="generation",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.SIGNER_REFERENCE,
            delivery.CredentialMaterialForm.PRIVATE_REFERENCE,
            generation_id="generation",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.CHAIN_DER,
            delivery.CredentialMaterialForm.PUBLIC,
            generation_ids=["generation"],
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.TRUST_DER,
            delivery.CredentialMaterialForm.PUBLIC,
            trust_set_generation_id="trust",
        ),
        delivery.CredentialMaterialReference(
            delivery.CredentialProjection.CRL_DER,
            delivery.CredentialMaterialForm.PUBLIC,
            crl_generation_ids=["crl"],
        ),
    ]
    for reference in references:
        assert reference.to_rpc()["projection"] == reference.projection.value
    assert delivery.CredentialReferencedStampMaterial(references[0]).to_rpc()["credential"]
    assert delivery.CredentialProviderEncodingStampMaterial(
        "provider", "v1", delivery.CredentialMaterialForm.PUBLIC, references[0]
    ).to_rpc()["providerEncoding"]
    assert delivery.CredentialLiteralStampMaterial(
        "reference", "0" * 64, delivery.CredentialMaterialForm.PRIVATE_REFERENCE
    ).to_rpc()["literalReference"]

    slot = delivery.CredentialSlot(
        "slot",
        delivery.CredentialPurpose.TLS_SERVER,
        delivery.CredentialEndpointRole.SERVER,
        delivery.CredentialConsumerType.SERVICE,
        ["bundle-v1"],
        ["profile"],
        ["target"],
        [delivery.CredentialProjection.BUNDLE],
        [delivery.CredentialMaterialForm.PUBLIC],
        1024,
        delivery.CredentialStampRemainderPolicy.PRESERVE,
        delivery.CredentialPrivateMaterialPolicy.FORBIDDEN,
    )
    target_schema = delivery.CredentialProviderTargetSchema("provider", "v1", {"type": "object"})
    encoding_schema = delivery.CredentialProviderEncodingSchema(
        "provider",
        "v1",
        [delivery.CredentialProjection.BUNDLE],
        [delivery.CredentialMaterialForm.PUBLIC],
        [delivery.CredentialMaterialForm.PUBLIC],
    )
    descriptor = delivery.CredentialDeliveryDescriptor(
        [delivery.CredentialDeliveryCapability.STAMP_STANDARD],
        [slot],
        [delivery.CredentialStampTargetKind.NAMED_SLOT],
        [delivery.CredentialStampAddressSpace.FILE],
        [target_schema],
        [encoding_schema],
    )
    wire = descriptor.to_rpc()
    assert wire["credentialSlots"][0]["name"] == "slot"
    assert wire["providerTargetSchemas"][0]["providerId"] == "provider"


def test_credential_delivery_decodes_every_wire_variant() -> None:
    delivery = credential_delivery
    none = delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.NONE)
    targets = [
        delivery.CredentialNamedSlotTarget("slot"),
        delivery.CredentialFileOffsetTarget("1", "8", "1", delivery.CredentialStampRemainderPolicy.PRESERVE, none),
        delivery.CredentialVirtualAddressTarget(
            "1",
            delivery.CredentialStampAddressSpace.PE_RVA,
            "8",
            "1",
            delivery.CredentialStampRemainderPolicy.PRESERVE,
            none,
        ),
        delivery.CredentialSymbolTarget("symbol", "8", delivery.CredentialStampRemainderPolicy.PRESERVE, none),
        delivery.CredentialMarkerTarget(b"marker", maximum_length="8", precondition=none),
        delivery.CredentialBytePatternTarget(b"x", b"\xff", maximum_length="8", precondition=none),
        delivery.CredentialProviderDefinedTarget("provider", "v1", {"value": True}),
    ]
    for target in targets:
        assert delivery._credential_stamp_target_from_rpc(target.to_rpc()) == target  # noqa: SLF001

    preconditions = [
        none,
        delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.BYTES, bytes_value=b"x"),
        delivery.CredentialStampPrecondition(
            delivery.CredentialStampPreconditionKind.SHA256, sha256="0" * 64, length="1"
        ),
    ]
    for precondition in preconditions:
        assert delivery._credential_precondition_from_rpc(precondition.to_rpc()) == precondition  # noqa: SLF001

    reference = delivery.CredentialMaterialReference(
        delivery.CredentialProjection.BUNDLE, delivery.CredentialMaterialForm.PUBLIC, bundle_id="bundle"
    )
    materials = [
        delivery.CredentialReferencedStampMaterial(reference),
        delivery.CredentialProviderEncodingStampMaterial(
            "provider", "v1", delivery.CredentialMaterialForm.PUBLIC, reference
        ),
        delivery.CredentialLiteralStampMaterial(
            "reference", "0" * 64, delivery.CredentialMaterialForm.PRIVATE_REFERENCE
        ),
    ]
    for material in materials:
        assert delivery._credential_stamp_material_from_rpc(material.to_rpc()) == material  # noqa: SLF001
    with pytest.raises(ValueError, match="cannot contain"):
        delivery._credential_material_reference_from_rpc(  # noqa: SLF001
            {
                "projection": delivery.CredentialProjection.PROVIDER_ENCODING.value,
                "form": delivery.CredentialMaterialForm.PUBLIC.value,
            }
        )
    with pytest.raises(ValueError, match="does not match"):
        delivery._credential_stamp_material_from_rpc(  # noqa: SLF001
            {
                "projection": delivery.CredentialProjection.BUNDLE.value,
                "credential": {
                    "projection": delivery.CredentialProjection.CERTIFICATE_DER.value,
                    "form": delivery.CredentialMaterialForm.PUBLIC.value,
                    "generationId": "generation",
                },
            }
        )


def test_credential_delivery_defensive_validation_edges() -> None:
    delivery = credential_delivery
    none = delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.NONE)
    bytes_condition = delivery.CredentialStampPrecondition(
        delivery.CredentialStampPreconditionKind.BYTES, bytes_value=b"xx"
    )
    sha_condition = delivery.CredentialStampPrecondition(
        delivery.CredentialStampPreconditionKind.SHA256, sha256="0" * 64, length="2"
    )

    invalid_preconditions = [
        delivery.CredentialStampPrecondition("none"),  # type: ignore[arg-type]
        delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.NONE, bytes_value="x"),  # type: ignore[arg-type]
        delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.NONE, sha256="0" * 64),
        delivery.CredentialStampPrecondition(delivery.CredentialStampPreconditionKind.BYTES),
        delivery.CredentialStampPrecondition(
            delivery.CredentialStampPreconditionKind.SHA256, bytes_value=b"x", sha256="0" * 64, length="1"
        ),
        delivery.CredentialStampPrecondition(
            delivery.CredentialStampPreconditionKind.SHA256, sha256="0" * 64, length="0"
        ),
    ]
    for precondition in invalid_preconditions:
        with pytest.raises((TypeError, ValueError)):
            precondition.validate()
    with pytest.raises(TypeError, match="unsupported variant"):
        delivery._validate_credential_stamp_target(object())  # type: ignore[arg-type]  # noqa: SLF001

    invalid_targets = [
        delivery.CredentialFileOffsetTarget("1", "8", "3", delivery.CredentialStampRemainderPolicy.PRESERVE, none),
        delivery.CredentialFileOffsetTarget("3", "8", "2", delivery.CredentialStampRemainderPolicy.PRESERVE, none),
        delivery.CredentialVirtualAddressTarget(
            "1",
            delivery.CredentialStampAddressSpace.FILE,
            "8",
            "1",
            delivery.CredentialStampRemainderPolicy.PRESERVE,
            none,
        ),
        delivery.CredentialMarkerTarget(b"", maximum_length="8", precondition=none),
        delivery.CredentialBytePatternTarget(b"x", b"\x00", maximum_length="8", precondition=none),
        delivery.CredentialProviderDefinedTarget("provider", "v1", []),  # type: ignore[arg-type]
    ]
    for target in invalid_targets:
        with pytest.raises((TypeError, ValueError)):
            target.validate()

    virtual = delivery.CredentialVirtualAddressTarget(
        "1",
        delivery.CredentialStampAddressSpace.PE_RVA,
        "8",
        "1",
        delivery.CredentialStampRemainderPolicy.PRESERVE,
        none,
    )
    object.__setattr__(virtual, "address_space", object())
    with pytest.raises(TypeError, match="address space"):
        virtual.validate()
    bounded_target = delivery._validate_credential_bounded_target  # noqa: SLF001
    with pytest.raises(ValueError, match="maximum length"):
        bounded_target("0", delivery.CredentialStampRemainderPolicy.PRESERVE, none)
    with pytest.raises(TypeError, match="remainder policy"):
        bounded_target("8", object(), none)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exceeds"):
        bounded_target("1", delivery.CredentialStampRemainderPolicy.PRESERVE, bytes_condition)
    with pytest.raises(ValueError, match="exceeds"):
        bounded_target("1", delivery.CredentialStampRemainderPolicy.PRESERVE, sha_condition)
    true_value: object = True
    with pytest.raises(ValueError, match="occurrence"):
        delivery._validate_credential_occurrence(true_value)  # type: ignore[arg-type]  # noqa: SLF001


def test_credential_delivery_primitive_validation_edges() -> None:
    delivery = credential_delivery
    with pytest.raises(TypeError, match="projection"):
        delivery._validate_projection_form("bundle", delivery.CredentialMaterialForm.PUBLIC)  # type: ignore[arg-type]  # noqa: SLF001
    invalid_forms = [
        (delivery.CredentialProjection.CERTIFICATE_DER, delivery.CredentialMaterialForm.PRIVATE_BYTES),
        (delivery.CredentialProjection.PRIVATE_KEY_PKCS8, delivery.CredentialMaterialForm.PUBLIC),
        (delivery.CredentialProjection.SIGNER_REFERENCE, delivery.CredentialMaterialForm.PUBLIC),
    ]
    for projection, form in invalid_forms:
        with pytest.raises(ValueError, match="requires"):
            delivery._validate_projection_form(projection, form)  # noqa: SLF001
    for value in [1, " ", "a\x00b", "\ud800"]:
        with pytest.raises((TypeError, ValueError)):
            delivery._validate_canonical_text(value, "value", 8)  # type: ignore[arg-type]  # noqa: SLF001
    for value in ["A" * 64, "g" * 64]:
        with pytest.raises(ValueError, match="sha256"):
            delivery._validate_sha256(value, "value")  # noqa: SLF001
    for value in ["", "01", str(1 << 64)]:
        with pytest.raises(ValueError, match="uint64"):
            delivery._parse_canonical_uint64(value, "value")  # noqa: SLF001
    for values in [[], ["same", "same"]]:
        with pytest.raises(ValueError, match=r"empty|duplicate"):
            delivery._validate_reference_list(values, "values")  # noqa: SLF001
    with pytest.raises(TypeError, match="object"):
        delivery._required_mapping({}, "field")  # noqa: SLF001
    with pytest.raises(ValueError, match="non-empty"):
        delivery._required_str({}, "field")  # noqa: SLF001
    with pytest.raises(TypeError, match="string"):
        delivery._optional_str({"field": 1}, "field")  # noqa: SLF001
    assert delivery._optional_bytes({}, "field") == b""  # noqa: SLF001
    with pytest.raises(TypeError, match="base64"):
        delivery._optional_bytes({"field": 1}, "field")  # noqa: SLF001
    with pytest.raises(ValueError, match="canonical base64"):
        delivery._optional_bytes({"field": "!"}, "field")  # noqa: SLF001
    with pytest.raises(ValueError, match="not be empty"):
        delivery._required_bytes({}, "field")  # noqa: SLF001
    with pytest.raises(ValueError, match="string list"):
        delivery._string_list({"field": [1]}, "field")  # noqa: SLF001


def test_credential_delivery_remaining_boundary_edges() -> None:  # noqa: PLR0915
    delivery = credential_delivery
    assert delivery.CredentialDeliveryDescriptor([]).to_rpc()["deliveryCapabilities"] == []

    _, metadata, _, _ = _provider_contract_values()
    request = delivery.CredentialStampRequest(
        "assignment",
        delivery.CredentialDeliveryCapability.STAMP_STANDARD,
        "slot",
        delivery.CredentialNamedSlotTarget("slot"),
        delivery.CredentialReferencedStampMaterial(
            delivery.CredentialMaterialReference(
                delivery.CredentialProjection.BUNDLE,
                delivery.CredentialMaterialForm.PUBLIC,
                bundle_id="bundle",
            )
        ),
        1,
        metadata,  # type: ignore[arg-type]
    )
    object.__setattr__(request, "capability", object())
    with pytest.raises(TypeError, match="capability"):
        request.validate()
    object.__setattr__(request, "capability", delivery.CredentialDeliveryCapability.STAMP_STANDARD)
    object.__setattr__(request, "encoded_bytes", 0)
    with pytest.raises(ValueError, match="encoded byte"):
        request.validate()

    maximum = (1 << 64) - 1
    with pytest.raises(ValueError, match="overflow"):
        delivery._validate_credential_position_bounds(  # noqa: SLF001
            maximum, 0, 1, "", delivery.CredentialStampAddressSpace.FILE
        )
    with pytest.raises(ValueError, match="overflow"):
        delivery._validate_credential_position_bounds(  # noqa: SLF001
            1, maximum, 1, str(maximum), delivery.CredentialStampAddressSpace.PE_RVA
        )
    with pytest.raises(ValueError, match="overflow"):
        delivery._validate_credential_position_bounds(  # noqa: SLF001
            1, maximum - 1, 1, str(maximum - 1), delivery.CredentialStampAddressSpace.PE_RVA
        )
    delivery._validate_credential_position_bounds(  # noqa: SLF001
        2, 1, 1, "1", delivery.CredentialStampAddressSpace.ELF_VIRTUAL_ADDRESS
    )
    with pytest.raises(ValueError, match="precedes"):
        delivery._validate_credential_position_bounds(  # noqa: SLF001
            1, 2, 1, "2", delivery.CredentialStampAddressSpace.ELF_VIRTUAL_ADDRESS
        )

    unserializable = delivery.CredentialProviderDefinedTarget("provider", "v1", {"bad": {1}})
    with pytest.raises(ValueError, match="value is invalid"):
        unserializable.validate()
    oversized = delivery.CredentialProviderDefinedTarget("provider", "v1", {"value": "x" * ((1 << 20) + 1)})
    with pytest.raises(ValueError, match="value is invalid"):
        oversized.validate()

    invalid_reference = delivery.CredentialMaterialReference(  # type: ignore[arg-type]
        "bundle", delivery.CredentialMaterialForm.PUBLIC, bundle_id="bundle"
    )
    with pytest.raises(TypeError, match="projection"):
        invalid_reference.validate()
    empty_reference = delivery.CredentialMaterialReference(
        delivery.CredentialProjection.BUNDLE, delivery.CredentialMaterialForm.PUBLIC
    )
    with pytest.raises(ValueError, match="exactly one"):
        empty_reference.validate()
    provider_reference = delivery.CredentialMaterialReference(
        delivery.CredentialProjection.PROVIDER_ENCODING,
        delivery.CredentialMaterialForm.PUBLIC,
        bundle_id="bundle",
    )
    with pytest.raises(ValueError, match="cannot contain"):
        provider_reference.validate()

    source = delivery.CredentialMaterialReference(
        delivery.CredentialProjection.BUNDLE,
        delivery.CredentialMaterialForm.PUBLIC,
        bundle_id="bundle",
    )
    provider_material = delivery.CredentialProviderEncodingStampMaterial(
        "provider", "v1", delivery.CredentialMaterialForm.PUBLIC, source
    )
    literal_material = delivery.CredentialLiteralStampMaterial(
        "reference", "0" * 64, delivery.CredentialMaterialForm.PRIVATE_REFERENCE
    )
    object.__setattr__(provider_material, "form", object())
    with pytest.raises(TypeError, match="form"):
        provider_material.validate()
    object.__setattr__(literal_material, "form", object())
    with pytest.raises(TypeError, match="form"):
        literal_material.validate()
    with pytest.raises(TypeError, match="unsupported variant"):
        delivery._validate_credential_stamp_material(object())  # type: ignore[arg-type]  # noqa: SLF001

    valid_provider_material = delivery.CredentialProviderEncodingStampMaterial(
        "provider", "v1", delivery.CredentialMaterialForm.PUBLIC, source
    )
    valid_literal_material = delivery.CredentialLiteralStampMaterial(
        "reference", "0" * 64, delivery.CredentialMaterialForm.PRIVATE_REFERENCE
    )
    assert delivery._credential_stamp_material_projection_and_form(valid_provider_material)[0] is (  # noqa: SLF001
        delivery.CredentialProjection.PROVIDER_ENCODING
    )
    assert delivery._credential_stamp_material_projection_and_form(valid_literal_material)[0] is (  # noqa: SLF001
        delivery.CredentialProjection.LITERAL_REFERENCE
    )

    invalid_metadata = delivery.ResolvedCredentialMetadata(
        "bundle",
        object(),
        delivery.CredentialConsumerType.SERVICE,
        "profile",
        "target",  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError, match="purpose"):
        invalid_metadata.validate()
    object.__setattr__(invalid_metadata, "purpose", delivery.CredentialPurpose.TLS_SERVER)
    object.__setattr__(invalid_metadata, "consumer_type", object())
    with pytest.raises(TypeError, match="consumer type"):
        invalid_metadata.validate()
    assert delivery._required_int({"unbounded": 1}, "unbounded") == 1  # noqa: SLF001


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
