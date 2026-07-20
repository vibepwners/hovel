import unittest

from coverage_check import percentage, totals


class CoverageCheckTest(unittest.TestCase):
    def test_aggregates_records(self) -> None:
        report = "\n".join(
            [
                "SF:first.go",
                "LF:10",
                "LH:9",
                "end_of_record",
                "SF:second.go",
                "LF:20",
                "LH:18",
                "end_of_record",
            ]
        )
        self.assertEqual(totals(report), (27, 30))
        self.assertEqual(percentage(*totals(report)), 90.0)

    def test_rejects_empty_and_inconsistent_reports(self) -> None:
        with self.assertRaisesRegex(ValueError, "no instrumented lines"):
            totals("TN:\n")
        with self.assertRaisesRegex(ValueError, "more hit lines"):
            totals("LF:1\nLH:2\n")


if __name__ == "__main__":
    unittest.main()
