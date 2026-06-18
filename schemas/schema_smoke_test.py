import json
import os
import re
import sys
import unittest


HERE = os.path.dirname(__file__)

SCHEMA_FIXTURES = {
    "Chain": ["fixtures/chain_configured.json", "fixtures/chain_template.json"],
    "Event": ["fixtures/event_throw_started.json"],
    "Module": ["fixtures/module_artifacts.json"],
    "ThrowPlan": ["fixtures/throw_plan.json"],
}


class SchemaSmokeTest(unittest.TestCase):
    def test_schema_files_parse_and_require_descriptor_shape(self):
        for path in sys.argv[1:]:
            with self.subTest(path=path):
                with open(path, "r", encoding="utf-8") as handle:
                    schema = json.load(handle)
                self.assertEqual(schema["type"], "object")
                kind = schema_kind(schema)
                if kind == "Event":
                    self.assertIn("id", schema["required"])
                    self.assertIn("schemaVersion", schema["required"])
                    self.assertIn("type", schema["required"])
                    self.assertIn("refs", schema["required"])
                    spec = schema["properties"]
                    self.assertEqual(spec["schemaVersion"]["const"], "hovel.event/v1alpha1")
                    self.assertEqual(spec["level"]["enum"], ["debug", "info", "warn", "error"])
                    pattern = spec["type"]["pattern"]
                    self.assertRegex("workspace.initialized", pattern)
                    self.assertNotRegex("workspace initialized", pattern)
                    self.assertNotRegex("module.mock-survey.log", pattern)
                    continue
                self.assertIn("apiVersion", schema["required"])
                self.assertIn("kind", schema["required"])
                self.assertIn("metadata", schema["required"])
                self.assertIn("spec", schema["required"])
                self.assertIn("const", schema["properties"]["kind"])
                spec = schema["properties"]["spec"]["properties"]
                if kind in {"Module", "Service"}:
                    self.assertEqual(spec["runtime"]["properties"]["type"]["enum"], ["jsonrpc-stdio"])
                if schema["properties"]["kind"]["const"] == "Module":
                    self.assertEqual(spec["moduleType"]["enum"], ["survey", "exploit", "payload_provider"])
                    artifact = schema["$defs"]["artifactOutput"]
                    self.assertEqual(artifact["properties"]["mode"]["enum"], ["inline", "file"])
                    self.assertEqual(spec["outputs"]["properties"]["artifacts"]["items"]["$ref"], "#/$defs/artifactOutput")
                if schema["properties"]["kind"]["const"] == "Service":
                    self.assertIn("payload_provider", spec["serviceType"]["enum"])
                if schema["properties"]["kind"]["const"] == "Chain":
                    self.assertEqual(spec["mode"]["enum"], ["template", "configured"])
                    self.assertEqual(spec["steps"]["items"]["$ref"], "#/$defs/step")
                if schema["properties"]["kind"]["const"] == "ThrowPlan":
                    self.assertIn("confirmation", spec)
                    self.assertIn("now_bypass", schema["$defs"]["confirmation"]["properties"]["method"]["enum"])
                    self.assertIn("reviewed_yes", schema["$defs"]["confirmation"]["properties"]["method"]["enum"])

    def test_contract_fixtures_match_schemas(self):
        schemas = {}
        for path in sys.argv[1:]:
            with open(path, "r", encoding="utf-8") as handle:
                schema = json.load(handle)
            schemas[schema_kind(schema)] = schema

        for kind, fixtures in SCHEMA_FIXTURES.items():
            self.assertIn(kind, schemas)
            for fixture in fixtures:
                with self.subTest(kind=kind, fixture=fixture):
                    with open(os.path.join(HERE, fixture), "r", encoding="utf-8") as handle:
                        instance = json.load(handle)
                    validate(instance, schemas[kind], schemas[kind], "$")

    def test_chain_schema_captures_template_and_configured_contracts(self):
        schema = schema_by_kind(sys.argv[1:], "Chain")
        step = schema["$defs"]["step"]
        target = schema["$defs"]["target"]
        self.assertEqual(step["required"], ["id", "uses"])
        self.assertEqual(target["required"], ["id"])
        self.assertEqual(schema["properties"]["spec"]["required"], ["mode", "steps"])
        self.assertEqual(schema["properties"]["spec"]["properties"]["targets"]["items"]["$ref"], "#/$defs/target")


def schema_by_kind(paths, kind):
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            schema = json.load(handle)
        if schema_kind(schema) == kind:
            return schema
    raise AssertionError(f"missing schema for {kind}")


def schema_kind(schema):
    properties = schema.get("properties", {})
    kind = properties.get("kind", {})
    if "const" in kind:
        return kind["const"]
    if schema.get("$id", "").endswith("/hovel.event.schema.json"):
        return "Event"
    raise AssertionError(f"schema kind not identifiable: {schema.get('$id')!r}")


def validate(value, schema, root, path):
    if "$ref" in schema:
        schema = resolve_ref(root, schema["$ref"])
    if "const" in schema and value != schema["const"]:
        raise AssertionError(f"{path}: {value!r} != const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise AssertionError(f"{path}: {value!r} not in {schema['enum']!r}")
    if "type" in schema:
        validate_type(value, schema["type"], path)
    if schema.get("type") == "object":
        validate_object(value, schema, root, path)
    if schema.get("type") == "array":
        validate_array(value, schema, root, path)
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise AssertionError(f"{path}: string shorter than {schema['minLength']}")
        if "pattern" in schema and not re.match(schema["pattern"], value):
            raise AssertionError(f"{path}: {value!r} does not match {schema['pattern']!r}")


def validate_type(value, expected, path):
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
    }
    if expected not in checks:
        raise AssertionError(f"{path}: unsupported schema type {expected!r}")
    if not checks[expected](value):
        raise AssertionError(f"{path}: expected {expected}, got {type(value).__name__}")


def validate_object(value, schema, root, path):
    required = schema.get("required", [])
    for key in required:
        if key not in value:
            raise AssertionError(f"{path}: missing required key {key!r}")

    properties = schema.get("properties", {})
    additional = schema.get("additionalProperties", True)
    for key, item in value.items():
        item_path = f"{path}.{key}"
        if key in properties:
            validate(item, properties[key], root, item_path)
        elif isinstance(additional, dict):
            validate(item, additional, root, item_path)
        elif additional is False:
            raise AssertionError(f"{path}: unexpected key {key!r}")


def validate_array(value, schema, root, path):
    if "minItems" in schema and len(value) < schema["minItems"]:
        raise AssertionError(f"{path}: fewer than {schema['minItems']} item(s)")
    if "items" in schema:
        for index, item in enumerate(value):
            validate(item, schema["items"], root, f"{path}[{index}]")


def resolve_ref(root, ref):
    if not ref.startswith("#/"):
        raise AssertionError(f"unsupported ref {ref!r}")
    out = root
    for part in ref[2:].split("/"):
        out = out[part]
    return out


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
