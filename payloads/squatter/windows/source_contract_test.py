from pathlib import Path
import sys
import unittest


REQUIRED_FILES = [
    "base/win.h",
    "iocpserver/server.c",
    "modules/echo.c",
    "modules/file_xfer.c",
    "modules/getfile.c",
    "modules/putfile.c",
    "runtime/channel.c",
    "runtime/module.c",
    "runtime/session.c",
    "sqlog/sqlog.c",
    "wire/control.proto",
    "wire/control_codec.c",
    "wire/frame.c",
    "wire/framing.c",
    "squatter.c",
]


class SourceContractTest(unittest.TestCase):
    def test_upstream_runtime_layout_is_present(self):
        root = source_root()
        for relative in REQUIRED_FILES:
            with self.subTest(path=relative):
                self.assertTrue((root / relative).is_file())

    def test_windows_headers_are_centralized(self):
        root = source_root()
        win_header = (root / "base/win.h").read_text()
        self.assertIn("#include <winsock2.h>", win_header)
        self.assertIn("#include <windows.h>", win_header)

        for path in root.rglob("*.[ch]"):
            relative = path.relative_to(root).as_posix()
            if relative == "base/win.h" or relative.startswith("sqlog/"):
                continue
            text = path.read_text().lower()
            with self.subTest(path=relative):
                self.assertNotIn("#include <windows.h>", text)
                self.assertNotIn("#include <winsock2.h>", text)

    def test_hovel_payload_config_bridge_is_embedded(self):
        text = (source_root() / "squatter.c").read_text()
        self.assertIn("'S', 'Q', 'U', 'A', 'T', '0', '0', '1'", text)
        self.assertIn("'S', 'Q', 'C', 'F', 'G', '0', '0', '1'", text)
        self.assertIn("squatter_transport_config", text)
        self.assertIn("connect_reverse_tcp", text)
        self.assertIn("CreateNamedPipeW", text)
        self.assertIn("ConnectNamedPipe", text)
        self.assertIn("sq_channel_from_handle", text)
        self.assertIn("sq_session_create", text)

    def test_mux_and_modules_are_wired(self):
        text = (source_root() / "squatter.c").read_text()
        for module in ["echo", "getfile", "putfile"]:
            with self.subTest(module=module):
                self.assertIn(f'"{module}"', text)
        self.assertIn("sq_channel_from_socket", text)
        self.assertIn("sq_session_create", text)


def source_root():
    if len(sys.argv) != 2:
        raise AssertionError("expected squatter.c argument")
    return Path(sys.argv[1]).parent


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
