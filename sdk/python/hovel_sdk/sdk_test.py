import base64
import io
import logging
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar

from hovel_sdk import Artifact, Context, HovelModule, LineShellSession, Requirement, Result, setup_logging
from hovel_sdk.framing import encode_message, read_message, write_message
from hovel_sdk.server import JSONRPCServer


class EchoModule(HovelModule):
    name = "echo"
    module_type = "survey"
    global_config: ClassVar[tuple[Requirement, ...]] = (Requirement("operator.confirmed_lab", "bool"),)
    target_config: ClassVar[tuple[Requirement, ...]] = (Requirement("target.host", "host"),)

    def run(self, ctx: Context) -> Result:
        ctx.log.info("echo running", extra={"target": ctx.target})
        return Result.ok({"target": ctx.target}, summary="echo done")


class TestShell(LineShellSession):
    async def handle_command(self, command: str) -> str:
        if command == "whoami":
            return "mock-user"
        return f"unknown command: {command}"


class SessionModule(HovelModule):
    name = "session-echo"
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


class SDKTest(unittest.TestCase):
    def test_lsp_framing_round_trips_json_rpc(self) -> None:
        message = {"jsonrpc": "2.0", "id": 1, "method": "handshake"}
        stream = io.BytesIO(encode_message(message))
        self.assertEqual(read_message(stream), message)

    def test_write_message_uses_content_length(self) -> None:
        stream = io.BytesIO()
        write_message(stream, {"ok": True})
        self.assertTrue(stream.getvalue().startswith(b"Content-Length: "))

    def test_server_executes_module_and_emits_log_notification(self) -> None:
        stdin = io.BytesIO(
            encode_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "execute",
                "params": {"runId": "run-1", "moduleId": "echo", "target": "mock://target"},
            })
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

    def test_step_contract_methods_dispatch_over_json_rpc(self) -> None:
        stdin = io.BytesIO(
            encode_message({"jsonrpc": "2.0", "id": 1, "method": "step.describe"})
            + encode_message({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "step.prepare",
                "params": {"preparedPlanId": "prep-1", "stepId": "windows.credential.create_local_admin"},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "step.execute",
                "params": {"runId": "run-1", "stepId": "squatter.connect_smb"},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "step.cleanup",
                "params": {"runId": "run-1", "stepId": "squatter.cleanup_smb"},
            })
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

    def test_artifact_helpers_emit_inline_and_file_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loot.txt"
            path.write_text("loot", encoding="utf-8")

            result = Result.ok(artifacts=[
                Artifact.inline("transcript.txt", "text/plain", "inline bytes"),
                Artifact.text("notes.txt", b"operator notes"),
                Artifact.json("summary.json", {"ok": True, "count": 2}),
                Artifact.file(path, kind="text/plain"),
            ])
            artifacts = result.to_rpc()["artifacts"]

        self.assertEqual(artifacts[0], {"name": "transcript.txt", "kind": "text/plain", "data": "inline bytes"})
        self.assertEqual(artifacts[1], {"name": "notes.txt", "kind": "text/plain", "data": "operator notes"})
        self.assertEqual(
            artifacts[2],
            {"name": "summary.json", "kind": "application/json", "data": '{"count":2,"ok":true}'},
        )
        self.assertEqual(artifacts[3], {"name": "loot.txt", "kind": "text/plain", "path": str(path)})

    def test_async_module_can_open_and_drive_shell_session(self) -> None:
        stdin = io.BytesIO(
            encode_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "execute",
                "params": {"runId": "run-1", "moduleId": "session-echo", "target": "mock://target"},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/read",
                "params": {"sessionId": "run-1-session-1", "timeoutMs": 100},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/write",
                "params": {"sessionId": "run-1-session-1", "data": base64.b64encode(b"whoami\n").decode()},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "session/read",
                "params": {"sessionId": "run-1-session-1", "timeoutMs": 100},
            })
            + encode_message({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "shutdown",
            }),
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


if __name__ == "__main__":
    unittest.main()
