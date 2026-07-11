#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path


REGISTER_RE = re.compile(
    r"registerUnary\[[^\n]+\]\(mux,\s*(?P<method>\"[^\"]+\"|[A-Za-z_]\w*)\s*,"
)
STRING_CONST_RE = re.compile(
    r'^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<value>[^"]+)"',
    re.MULTILINE,
)
SERVICE_PREFIX = "/hovel.daemon.v1.DaemonService/"
ARGS = sys.argv[1:]


class DaemonRPCOpenAPITest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        if len(ARGS) != 3:
            raise AssertionError(
                "usage: daemon_rpc_openapi_test.py OPENAPI_JSON DAEMONRPC_GO DOC_HTML"
            )
        self.openapi_path = Path(ARGS[0])
        self.daemonrpc_path = Path(ARGS[1])
        self.doc_path = Path(ARGS[2])
        with self.openapi_path.open("r", encoding="utf-8") as handle:
            self.openapi = json.load(handle)
        self.daemonrpc_source = self.daemonrpc_path.read_text(encoding="utf-8")
        self.doc_html = self.doc_path.read_text(encoding="utf-8")

    def registered_methods(self) -> list[str]:
        string_constants = {
            match.group("name"): match.group("value")
            for match in STRING_CONST_RE.finditer(self.daemonrpc_source)
        }
        methods = []
        for match in REGISTER_RE.finditer(self.daemonrpc_source):
            token = match.group("method")
            if token.startswith('"'):
                methods.append(json.loads(token))
                continue
            if token not in string_constants:
                raise AssertionError(f"unresolved RPC method constant: {token}")
            methods.append(string_constants[token])
        return methods

    def test_openapi_paths_match_registered_daemon_rpc_methods(self) -> None:
        registered = self.registered_methods()
        self.assertGreater(len(registered), 10)

        paths = self.openapi.get("paths", {})
        documented = sorted(path.removeprefix(SERVICE_PREFIX) for path in paths)
        self.assertEqual(documented, sorted(registered))

        for method in registered:
            with self.subTest(method=method):
                path = SERVICE_PREFIX + method
                operation = paths[path]["post"]
                self.assertEqual(operation["operationId"], method)
                request_body = self.resolve_ref(operation["requestBody"])
                self.assertIn("application/json", request_body["content"])
                self.assertIn("200", operation["responses"])
                success = self.resolve_ref(operation["responses"]["200"])
                self.assertIn("application/json", success["content"])

    def test_contract_declares_stability_and_standard_shape(self) -> None:
        self.assertEqual(self.openapi["openapi"], "3.1.0")
        self.assertEqual(self.openapi["info"]["title"], "Hovel Daemon RPC")
        self.assertEqual(self.openapi["x-hovel-stability"], "stable")
        self.assertEqual(self.openapi["x-hovel-service"], "hovel.daemon.v1.DaemonService")

    def test_human_docs_link_contract_and_name_every_method(self) -> None:
        self.assertIn("reference/daemon-rpc.openapi.json", self.doc_html)
        for method in self.registered_methods():
            with self.subTest(method=method):
                self.assertIn(method, self.doc_html)

    def resolve_ref(self, node: object) -> object:
        if not isinstance(node, dict) or "$ref" not in node:
            return node
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise AssertionError(f"unsupported OpenAPI ref: {ref!r}")
        current: object = self.openapi
        for part in ref.removeprefix("#/").split("/"):
            if not isinstance(current, dict):
                raise AssertionError(f"cannot resolve OpenAPI ref through {part!r}: {ref}")
            current = current[part]
        return current


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
