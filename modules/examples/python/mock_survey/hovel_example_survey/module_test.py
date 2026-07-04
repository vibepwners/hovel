import unittest

from hovel_example_survey.module import MockSurvey
from hovel_sdk import Context


class MockSurveyTest(unittest.TestCase):
    def test_survey_returns_facts(self) -> None:
        result = MockSurvey().run(
            Context(
                run_id="run-1",
                module_id="mock-survey",
                target="mock://router-01",
                target_config={"target.host": "router-01", "target.port": "22"},
            ),
        )
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.outputs["facts"]["host"], "router-01")

    def test_survey_declares_target_configuration(self) -> None:
        schema = MockSurvey().module_schema()
        self.assertEqual(schema["chainConfig"], [])
        self.assertEqual(schema["targetConfig"][0]["key"], "target.host")


if __name__ == "__main__":
    unittest.main()
