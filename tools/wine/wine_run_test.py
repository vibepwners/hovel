from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools.wine import wine_run


class WineRunTest(unittest.TestCase):
    def test_environment_is_isolated_and_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = wine_run._wine_environment(
                {"TEST_TMPDIR": directory, "WINEARCH": "win32"}
            )

            self.assertEqual(environment["WINEPREFIX"], f"{directory}/wine-prefix")
            self.assertEqual(environment["WINEDEBUG"], "-all")
            self.assertEqual(environment["WINEARCH"], "win32")
            runtime_dir = Path(environment["XDG_RUNTIME_DIR"])
            self.assertTrue(runtime_dir.is_dir())
            self.assertEqual(
                stat.S_IMODE(runtime_dir.stat().st_mode),
                0o700,
            )

    def test_main_resolves_runfiles_symlink_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "echo_test.exe"
            executable.touch()
            runfiles_link = root / "long-runfiles-name.exe"
            runfiles_link.symlink_to(executable)

            completed = mock.Mock(returncode=19)
            environment = {
                "HOVEL_WINE_BIN": "/host/wine",
                "TEST_TMPDIR": directory,
                "WINEARCH": "win64",
            }
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                wine_run.subprocess, "run", return_value=completed
            ) as run:
                result = wine_run.main([str(runfiles_link), "--gtest_filter=Echo.*"])

            self.assertEqual(result, 19)
            command = run.call_args.args[0]
            self.assertEqual(
                command,
                [
                    "/host/wine",
                    str(executable.resolve()),
                    "--gtest_filter=Echo.*",
                ],
            )
            self.assertEqual(run.call_args.kwargs["env"]["WINEARCH"], "win64")

    def test_main_rejects_missing_target(self) -> None:
        self.assertEqual(wine_run.main([]), 2)
        self.assertEqual(wine_run.main(["missing.exe"]), 2)

    def test_main_reports_missing_wine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "test.exe"
            executable.touch()
            environment = {
                "HOVEL_WINE_BIN": "/missing/wine",
                "TEST_TMPDIR": directory,
            }
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                wine_run.subprocess, "run", side_effect=FileNotFoundError
            ):
                self.assertEqual(wine_run.main([str(executable)]), 127)


if __name__ == "__main__":
    unittest.main()
