"""Reject incomplete, mismatched, or cache-only reproducibility evidence."""
import json
from pathlib import Path
import tempfile
import unittest

from reproducibility import FAMILIES, FLAGS, SCHEMA, check_options, compare, file_manifest, prepare


def evidence(replica: str) -> dict:
    return {
        "schema_version": SCHEMA, "replica": replica, "commit": "1" * 40,
        "fresh_output_root": True, "flags": FLAGS,
        "started_at": "2026-01-01T00:00:00+00:00" if replica == "a" else "2026-01-01T00:02:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00" if replica == "a" else "2026-01-01T00:03:00+00:00",
        "execution": [{"invocation_id": replica, "executed_actions": 1, "options_verified": True, "container_image": "docker://ubuntu@sha256:" + "3" * 64}],
        "artifacts": {
            family: {str(index): {"sha256": "2" * 64, "size": 1} for index in range(minimum)}
            for family, (_, _, minimum) in FAMILIES.items()
        },
    }


class ReproducibilityTest(unittest.TestCase):
    def test_canonical_flags_override_environment_claims(self):
        values = {flag[2:].split("=", 1)[0]: flag.split("=", 1)[1] for flag in FLAGS if "exec_properties" not in flag}
        values["remote_executor"] = "grpcs://vibepwners.buildbuddy.io"
        properties = {"recycle-runner": "false", "preserve-workspace": "false", "network": "off", "container-image": "docker://ubuntu@sha256:" + "3" * 64}
        check_options(values, properties)
        values["remote_accept_cached"] = "true"
        with self.assertRaisesRegex(ValueError, "remote_accept_cached"):
            check_options(values, properties)

    def test_equal_payloads_require_independent_execution_evidence(self):
        a, b = evidence("a"), evidence("b")
        self.assertEqual(compare(a, b), [])
        b["execution"] = a["execution"]
        self.assertIn("builds reused invocation evidence", compare(a, b))
        b["execution"] = []
        self.assertIn("b: missing actual execution evidence", compare(a, b))

    def test_artifact_mismatch_and_symmetric_omission_fail(self):
        a, b = evidence("a"), evidence("b")
        b["artifacts"]["sdk"]["0"]["sha256"] = "3" * 64
        self.assertTrue(any(item.startswith("sdk/0:") for item in compare(a, b)))
        for item in (a, b):
            del item["artifacts"]["hovel"]["0"]
        self.assertIn("a: incomplete hovel artifacts", compare(a, b))
        self.assertIn("b: incomplete hovel artifacts", compare(a, b))

    def test_disabled_isolation_or_different_source_fails(self):
        a, b = evidence("a"), evidence("b")
        b["flags"] = []
        b["commit"] = "4" * 40
        self.assertIn("b: missing isolation evidence", compare(a, b))
        self.assertIn("source commits differ or are invalid", compare(a, b))

    def test_prepare_refuses_output_root_reuse_and_exports_no_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "RUNNER_TEMP": tmp, "GITHUB_ENV": str(Path(tmp) / "env"),
                "HOVEL_REPRO_REPLICA": "a", "HOVEL_BUILDBUDDY_MODE": "remote-execution",
                "HOVEL_BAZEL_ARGS": "--config=buildbuddy", "BUILDBUDDY_API_KEY": "secret-test-key",
            }
            prepare(env)
            exported = Path(env["GITHUB_ENV"]).read_text()
            self.assertNotIn("secret-test-key", exported)
            self.assertIn("--remote_accept_cached=false", exported)
            self.assertTrue(json.loads((Path(tmp) / "hovel-repro-a/setup.json").read_text())["fresh_output_root"])
            with self.assertRaises(FileExistsError):
                prepare(env)

    def test_missing_family_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Incomplete hovel"):
                file_manifest(Path(tmp))


if __name__ == "__main__":
    unittest.main()
