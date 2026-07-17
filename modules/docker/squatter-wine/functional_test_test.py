from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

import functional_test


class RecordingRunner:
    def __init__(self) -> None:
        self.output = ""

    def write(self, text: str) -> None:
        self.output += text


class FunctionalTestTest(unittest.TestCase):
    module_surface = frozenset({"cmd", "echo"})

    def test_loads_unique_module_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "surface.json"
            path.write_text(json.dumps(sorted(self.module_surface)), encoding="utf-8")
            self.assertEqual(
                functional_test.load_module_surface(path), self.module_surface
            )

    def test_requires_every_feature_marker_for_one_abi(self) -> None:
        output = "\n".join(
            [*(f"E2E module={name} passed" for name in self.module_surface)]
            + [
                *(
                    f"E2E transport={name} passed"
                    for name in functional_test.TRANSPORT_SURFACE
                )
            ]
            + [
                *(
                    f"E2E lifecycle={name} passed"
                    for name in functional_test.SERVICE_SURFACE
                )
            ]
        )
        runner = RecordingRunner()

        self.assertEqual(
            functional_test.require_surface_markers(
                runner, 32, output, self.module_surface
            ),
            (
                len(self.module_surface),
                len(functional_test.TRANSPORT_SURFACE),
                len(functional_test.SERVICE_SURFACE),
            ),
        )
        self.assertIn("coverage validated", runner.output)

    def test_rejects_incomplete_feature_evidence(self) -> None:
        runner = RecordingRunner()

        with self.assertRaisesRegex(RuntimeError, "surface evidence is incomplete"):
            functional_test.require_surface_markers(
                runner, 64, "E2E module=echo passed", self.module_surface
            )

        self.assertIn('"modules"', runner.output)
        self.assertIn('"transports"', runner.output)
        self.assertIn('"service lifecycles"', runner.output)

    def test_requires_exactly_one_mesh_tls_marker_per_abi(self) -> None:
        runner = RecordingRunner()

        self.assertEqual(
            functional_test.require_mesh_tls_marker(
                runner, 64, functional_test.MESH_TLS_EVIDENCE
            ),
            1,
        )
        with self.assertRaisesRegex(RuntimeError, "Mesh/TLS evidence is incomplete"):
            functional_test.require_mesh_tls_marker(runner, 64, "")

    def test_parses_test_results_and_attributes_markers_to_cases(self) -> None:
        output = """=== RUN   TestEcho
    functest_test.go:1: E2E module=echo interactive passed
--- PASS: TestEcho (0.04s)
=== RUN   TestCmd
    functest_test.go:2: E2E module=cmd one-shot passed
--- PASS: TestCmd (0.12s)
"""

        self.assertEqual(
            functional_test.parse_go_test_cases(output),
            (
                functional_test.TestCaseResult("TestEcho", "PASS", 0.04),
                functional_test.TestCaseResult("TestCmd", "PASS", 0.12),
            ),
        )
        self.assertEqual(
            functional_test.marker_test_map(output, "module", self.module_surface),
            {"cmd": ("TestCmd",), "echo": ("TestEcho",)},
        )

    def test_review_report_is_human_first_and_preserves_raw_appendices(self) -> None:
        functional_output = "\n".join(
            [
                "=== RUN   TestSurface",
                *(f"E2E module={name} passed" for name in sorted(self.module_surface)),
                *(
                    f"E2E transport={name} passed"
                    for name in sorted(functional_test.TRANSPORT_SURFACE)
                ),
                *(
                    f"E2E lifecycle={name} passed"
                    for name in sorted(functional_test.SERVICE_SURFACE)
                ),
                "--- PASS: TestSurface (1.25s)",
            ]
        )
        provider_output = "\n".join(
            [
                "=== RUN   TestProviderMeshTLSStreamCarriesRealWinePayload",
                functional_test.MESH_TLS_EVIDENCE,
                "--- PASS: TestProviderMeshTLSStreamCarriesRealWinePayload (0.50s)",
            ]
        )
        evidence = [
            functional_test.build_abi_evidence(
                bits=bits,
                wine_arch=wine_arch,
                functional_output=functional_output,
                provider_output=provider_output,
                module_surface=self.module_surface,
            )
            for bits, wine_arch in ((32, "win32"), (64, "win64"))
        ]
        report = functional_test.render_review_report(
            status="PASSED",
            duration=4.2,
            module_surface=self.module_surface,
            abi_evidence=evidence,
            transcripts=[
                functional_test.Transcript("raw suite", "noisy raw line\n", 0, 1.25)
            ],
            failure="",
        )

        self.assertLess(
            report.index("COVERAGE MATRIX"), report.index("RAW TRANSCRIPT APPENDICES")
        )
        self.assertIn("Registered modules", report)
        self.assertIn("4/4 PASS", report)
        self.assertIn("[PASS] echo", report)
        self.assertIn("exercised by: TestSurface", report)
        self.assertIn("PASS         1.25  TestSurface", report)
        self.assertIn("APPENDIX 1: raw suite", report)
        self.assertIn("noisy raw line", report)


if __name__ == "__main__":
    unittest.main()
