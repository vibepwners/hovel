import asyncio
import base64
import io
import logging
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, cast

import pytest

from hovel_sdk import (
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
    Result,
    SessionRef,
    setup_logging,
)
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
    request = MeshTaskRequest.from_rpc(
        {
            "runId": 7,
            "kind": False,
            "destinationPort": "445",
            "args": ["whoami", 1, True],
            "route": {"nodes": ["relay-1", 2]},
        }
    )

    assert request.run_id == ""
    assert request.kind == ""
    assert request.destination_port == 0
    assert request.args == ["whoami"]
    assert request.route == MeshRoute(nodes=["relay-1"])
    assert not MeshTopologyRequest.from_rpc({"includeRoutes": "false"}).include_routes


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
