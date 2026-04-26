import json
import sys
import unittest


class SchemaSmokeTest(unittest.TestCase):
    def test_schema_files_parse_and_require_descriptor_shape(self):
        for path in sys.argv[1:]:
            with self.subTest(path=path):
                with open(path, "r", encoding="utf-8") as handle:
                    schema = json.load(handle)
                self.assertEqual(schema["type"], "object")
                self.assertIn("apiVersion", schema["required"])
                self.assertIn("kind", schema["required"])
                self.assertIn("metadata", schema["required"])
                self.assertIn("spec", schema["required"])
                self.assertIn("const", schema["properties"]["kind"])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
