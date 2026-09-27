"""Coverage for source declaration boundaries and stable materialization."""
from pathlib import Path
import tempfile
import unittest

from lint_sources import block, replace_block, source_groups


class LintSourcesTest(unittest.TestCase):
    def test_nearest_package_owns_sources_and_symlinks_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "core/pkg").mkdir(parents=True)
            for name in ["BUILD.bazel", "core/BUILD.bazel", "core/pkg/BUILD.bazel", "core/pkg/example.go"]:
                (root / name).write_text("")
            (root / "secret-link").symlink_to(root / "core/pkg/example.go")
            groups = source_groups(root, ["core/pkg/example.go", "secret-link"])
            self.assertEqual(groups, {root / "core/pkg/BUILD.bazel": ["example.go"]})

    def test_replacement_preserves_rules_and_is_idempotent(self):
        text = 'package(default_visibility = ["//visibility:private"])\n'
        generated = replace_block(text, block(["mesh-development.html", "mesh.html"]))
        self.assertTrue(generated.startswith(text))
        self.assertEqual(replace_block(generated, block(["mesh.html", "mesh-development.html"])), generated)
        self.assertLess(generated.index('"mesh.html"'), generated.index('"mesh-development.html"'))


if __name__ == "__main__":
    unittest.main()
