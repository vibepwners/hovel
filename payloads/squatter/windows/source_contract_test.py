from pathlib import Path
import sys
import unittest


BANNED_INCLUDES = {
    "stdio.h",
    "stdlib.h",
    "string.h",
    "stdint.h",
}

class SourceContractTest(unittest.TestCase):
    def test_modular_runtime_files_exist(self):
        for path in source_paths():
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())

    def test_no_crt_or_win32_headers(self):
        for path in source_paths():
            text = path.read_text()
            lowered = text.lower()
            for include in BANNED_INCLUDES:
                with self.subTest(path=path.name, include=include):
                    self.assertNotIn(f"#include <{include}>", lowered)

    def test_windows_header_is_limited_to_linker_boundary(self):
        for path in source_paths():
            text = path.read_text().lower()
            if path.name == "sq_linker.h":
                self.assertIn("#include <windows.h>", text)
                continue
            if path.name == "sq_winapi.h":
                self.assertIn("#include <winsock2.h>", text)
                continue
            with self.subTest(path=path.name):
                self.assertNotIn("#include <windows.h>", text)
                self.assertNotIn("#include <winsock2.h>", text)

    def test_tasks_use_central_io_dispatcher(self):
        task_text = file_named("sq_task.c").read_text()
        self.assertIn("SqIoPost(", task_text)
        self.assertIn("SqTaskNoopEntry", task_text)

    def test_linker_bootstraps_from_peb_and_exports(self):
        linker_text = file_named("sq_linker.c").read_text()
        self.assertIn("SqGetPeb", linker_text)
        self.assertIn("fs:0x30", linker_text)
        self.assertIn("LoadLibraryW", linker_text)
        self.assertIn("GetProcAddress", linker_text)
        self.assertIn("IMAGE_EXPORT_DIRECTORY", linker_text)

    def test_winapi_table_uses_lazy_symbol_resolution(self):
        api_header = file_named("sq_winapi.h").read_text()
        api_text = file_named("sq_winapi.c").read_text()

        for symbol in [
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "WaitNamedPipeW",
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "closesocket",
        ]:
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, api_header)
                self.assertIn(f'"{symbol}"', api_text)

        self.assertIn("SqLinkerResolve", api_text)
        self.assertIn("api->CreateFileW == SQ_NULL", api_text)
        self.assertIn("api->send == SQ_NULL", api_text)

    def test_transport_supports_named_pipe_and_reverse_tcp(self):
        transport_text = file_named("sq_transport.c").read_text()
        main_text = file_named("main.c").read_text()

        self.assertIn("SqTransportConnectNamedPipe", transport_text)
        self.assertIn("SqTransportConnectReverseTcp", transport_text)
        self.assertIn("SqWinApiCreateFileW", transport_text)
        self.assertIn("SqWinApiConnect", transport_text)
        self.assertIn("SqWinApiSend", transport_text)
        self.assertIn("SqWinApiWriteFile", transport_text)
        self.assertIn("squatter_transport_config", main_text)
        self.assertIn("127u, 0u, 0u, 1u", main_text)


def source_paths():
    return [Path(path) for path in sys.argv[1:]]


def file_named(name):
    for path in source_paths():
        if path.name == name:
            return path
    raise AssertionError(f"missing source file {name}")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
