from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from image_tool import download, registry_transfer, validate_lock


LOCK = json.loads(Path(sys.argv.pop()).read_text())


class ImageLockTest(unittest.TestCase):
    def test_registry_credentials_are_temporary_even_on_failure(self):
        for failure in (None, "login", "pull", "push"):
            with self.subTest(failure=failure):
                configs = []
                operation = "push" if failure == "push" else "pull"

                def run(command, **kwargs):
                    config = Path(kwargs["env"]["DOCKER_CONFIG"])
                    configs.append(config)
                    self.assertTrue(config.is_dir())
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    self.assertNotIn("test-token", command)
                    if command[1] == "login":
                        self.assertEqual(kwargs["input"], "test-token")
                        self.assertEqual(command[-1], "--password-stdin")
                    else:
                        self.assertNotIn("input", kwargs)
                    if command[1] == failure:
                        raise subprocess.CalledProcessError(1, command)

                with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "test-token", "GITHUB_ACTOR": "actor"}), mock.patch("image_tool.subprocess.run", side_effect=run) as docker:
                    if failure:
                        with self.assertRaises(subprocess.CalledProcessError):
                            registry_transfer(operation, "ghcr.io/vibepwners/hovel-ci-wine@sha256:abc")
                    else:
                        registry_transfer(operation, "ghcr.io/vibepwners/hovel-ci-wine@sha256:abc")
                    self.assertEqual(docker.call_count, 1 if failure == "login" else 2)
                self.assertEqual(len(set(configs)), 1)
                self.assertFalse(configs[0].exists())

    def test_local_pull_preserves_existing_docker_auth(self):
        with mock.patch.dict(os.environ, {"DOCKER_CONFIG": "/local/auth"}, clear=True), mock.patch("image_tool.subprocess.run") as docker:
            registry_transfer("pull", "ghcr.io/vibepwners/hovel-ci-wine@sha256:abc")
            self.assertEqual(docker.call_count, 1)
            self.assertEqual(docker.call_args.kwargs["env"]["DOCKER_CONFIG"], "/local/auth")

    def test_github_credentials_are_not_used_for_other_registries(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}), mock.patch("image_tool.subprocess.run") as docker:
            registry_transfer("pull", "example.org/wine@sha256:abc")
            self.assertEqual(docker.call_count, 1)
            self.assertNotIn("GITHUB_TOKEN", docker.call_args.kwargs["env"])

    def test_download_retries_transport_failure_then_checks_hash(self):
        package = dict(LOCK["packages"][0], sha256=hashlib.sha256(b"valid").hexdigest())
        with tempfile.TemporaryDirectory() as directory, mock.patch("urllib.request.urlopen") as response, mock.patch("time.sleep"):
            stream = mock.MagicMock()
            stream.__enter__.return_value.read.return_value = b"valid"
            response.side_effect = [ConnectionResetError(), stream]
            self.assertEqual(download(package, Path(directory)).read_bytes(), b"valid")
            self.assertEqual(response.call_count, 2)

    def test_complete_lock_is_pinned(self):
        validate_lock(LOCK)
        self.assertGreater(len(LOCK["packages"]), 1)

    def test_rejects_unpinned_or_escaping_inputs(self):
        for field, value in [("filename", "../escape.deb"), ("url", "http://example.org/pkg.deb"), ("sha256", "bad")]:
            lock = copy.deepcopy(LOCK)
            lock["packages"][0][field] = value
            with self.assertRaises(ValueError):
                validate_lock(lock)

    def test_download_rejects_corrupt_data(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch("urllib.request.urlopen") as response:
            response.return_value.__enter__.return_value.read.return_value = b"corrupt"
            with self.assertRaises(ValueError):
                download(LOCK["packages"][0], Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
