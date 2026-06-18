import struct
import sys
import unittest


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
SQUATTER_VERSION = 0x00010000
SQUATTER_CAPABILITIES = 0x0000001F
SQUATTER_TRANSPORTS = 0x00000007


class PETest(unittest.TestCase):
    def test_payload_is_i386_console_pe_with_hovel_markers(self):
        with open(sys.argv[1], "rb") as handle:
            data = handle.read()

        self.assertGreaterEqual(len(data), 0x40)
        self.assertEqual(data[:2], b"MZ")

        pe_offset = u32(data, 0x3C)
        self.assertEqual(data[pe_offset : pe_offset + 4], b"PE\0\0")

        coff = pe_offset + 4
        self.assertEqual(u16(data, coff), IMAGE_FILE_MACHINE_I386)

        optional_size = u16(data, coff + 16)
        optional = coff + 20
        self.assertGreaterEqual(optional_size, 104)
        self.assertEqual(u16(data, optional), IMAGE_NT_OPTIONAL_HDR32_MAGIC)

        entry_point_rva = u32(data, optional + 16)
        self.assertNotEqual(entry_point_rva, 0)

        subsystem = u16(data, optional + 68)
        self.assertEqual(subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI)

        marker = data.find(b"SQUAT001")
        self.assertNotEqual(marker, -1)
        self.assertEqual(u32(data, marker + 8), SQUATTER_VERSION)
        self.assertEqual(u32(data, marker + 12), SQUATTER_CAPABILITIES)
        self.assertEqual(u32(data, marker + 16), SQUATTER_TRANSPORTS)

        config_marker = data.find(b"SQCFG001")
        self.assertNotEqual(config_marker, -1)
        self.assertIn(b"squatter", data)

        import_rva = u32(data, optional + 96 + 8)
        if import_rva != 0:
            import_offset = rva_to_offset(data, coff, import_rva)
            first_descriptor = data[import_offset : import_offset + 20]
            self.assertEqual(first_descriptor, b"\0" * 20)

        forbidden_runtime_imports = [
            b"api-ms-win-crt",
            b"ucrtbase",
            b"msvcrt",
            b"GetTickCount64",
        ]
        for needle in forbidden_runtime_imports:
            self.assertNotIn(needle, data)


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def rva_to_offset(data, coff, rva):
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    section = coff + 20 + optional_size

    for index in range(section_count):
        offset = section + index * 40
        virtual_size = u32(data, offset + 8)
        virtual_address = u32(data, offset + 12)
        raw_size = u32(data, offset + 16)
        raw_pointer = u32(data, offset + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            return raw_pointer + (rva - virtual_address)
    raise AssertionError(f"RVA 0x{rva:x} is not in any section")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
