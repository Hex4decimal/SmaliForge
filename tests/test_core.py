import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

import android_smali_gui as gui


class CoreTests(unittest.TestCase):
    def test_sanitize_filename(self):
        self.assertEqual(gui.sanitize_filename("com.example:bad/name"), "com.example_bad_name")

    def test_version_key_numeric_order(self):
        self.assertGreater(gui._version_key("35.0.1"), gui._version_key("34.0.9"))

    def test_valid_minimal_dex_header(self):
        data = bytearray(0x70)
        data[:8] = b"dex\n035\0"
        struct.pack_into("<I", data, 0x20, len(data))
        struct.pack_into("<I", data, 0x24, 0x70)
        struct.pack_into("<I", data, 0x28, 0x12345678)
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
        gui.AndroidSmaliGui._validate_dex_bytes(bytes(data), "test.dex")

    def test_invalid_dex_checksum_is_rejected(self):
        data = bytearray(0x70)
        data[:8] = b"dex\n035\0"
        struct.pack_into("<I", data, 0x20, len(data))
        struct.pack_into("<I", data, 0x24, 0x70)
        struct.pack_into("<I", data, 0x28, 0x12345678)
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, 123)
        with self.assertRaises(gui.ToolError):
            gui.AndroidSmaliGui._validate_dex_bytes(bytes(data), "bad.dex")

    def test_manifest_package_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(
                '<manifest package="com.example.test"></manifest>', encoding="utf-8"
            )
            self.assertEqual(gui.AndroidSmaliGui._manifest_package(root), "com.example.test")

    def test_safe_rmtree_rejects_parent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(gui.ToolError):
                gui.safe_rmtree(root, root)

    def test_safe_rmtree_allows_descendant(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            child = root / "child"
            child.mkdir()
            gui.safe_rmtree(child, root)
            self.assertFalse(child.exists())


if __name__ == "__main__":
    unittest.main()
