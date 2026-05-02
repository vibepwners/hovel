import io
import logging
import unittest
from typing import Any, ClassVar

from hovel_sdk import Context, HovelModule, Requirement, Result, setup_logging
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
