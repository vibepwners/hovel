import unittest

from hovel_ms17_010_survey.module import MS17010Survey, verdict_for_status
from hovel_ms17_010_survey.smb import (
    CMD_NEGOTIATE,
    PIPE_WHITELIST,
    STATUS_INSUFF_SERVER_RESOURCES,
    STATUS_INVALID_HANDLE,
    build_header,
)


class MS17010SurveyTest(unittest.TestCase):
    def test_module_is_a_safe_survey(self) -> None:
        module = MS17010Survey()
        info = module.info()
        self.assertEqual(info["moduleType"], "survey")
        self.assertNotIn("dangerous", info["tags"])

    def test_schema_declares_target(self) -> None:
        schema = MS17010Survey().module_schema()
        keys = [requirement["key"] for requirement in schema["targetConfig"]]
        self.assertIn("target.host", keys)
        self.assertIn("target.port", keys)

    def test_verdict_classification(self) -> None:
        self.assertEqual(verdict_for_status(STATUS_INSUFF_SERVER_RESOURCES), "vulnerable")
        self.assertEqual(verdict_for_status(STATUS_INVALID_HANDLE), "likely_patched")
        self.assertEqual(verdict_for_status(0), "likely_patched")

    def test_header_is_32_bytes_and_well_formed(self) -> None:
        header = build_header(CMD_NEGOTIATE, tree_id=0, user_id=0, mid=1)
        self.assertEqual(len(header), 32)
        self.assertEqual(header[:4], b"\xffSMB")
        self.assertEqual(header[4], CMD_NEGOTIATE)

    def test_pipe_whitelist_matches_ms17_010_probe(self) -> None:
        self.assertEqual(PIPE_WHITELIST, ("spoolss", "browser", "lsarpc"))


if __name__ == "__main__":
    unittest.main()
