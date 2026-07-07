from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import checkout


class CheckoutTest(unittest.TestCase):
    def test_full_checkout_requirement_includes_repo_quality_slice(self) -> None:
        repo_slice = next(item for item in checkout.SLICES if item.name == "repo")

        for path in repo_slice.paths:
            self.assertIn(path, checkout.FULL_CHECKOUT_PATHS)

    def test_full_checkout_requirement_rejects_missing_repo_quality_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for path in ("core", "docs", "modules", "repo-tools", "sdk"):
                (repo / path).mkdir(parents=True)

            self.assertEqual(checkout.require_paths(repo, checkout.FULL_CHECKOUT_PATHS), 2)

            for path in ("BUILD.bazel", "OWNERS"):
                (repo / path).touch()
            (repo / "tools/bazel").mkdir(parents=True)

            self.assertEqual(checkout.require_paths(repo, checkout.FULL_CHECKOUT_PATHS), 0)


if __name__ == "__main__":
    unittest.main()
