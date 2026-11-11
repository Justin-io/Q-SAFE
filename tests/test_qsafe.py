import unittest
from qsafe import analyse_bytes, entropy, file_format, quarantine_file, restore_item

class QSafeTests(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(entropy(b""), 0.0)
        self.assertEqual(entropy(b"A"*256), 0.0)
        self.assertGreater(entropy(bytes(range(256))), 7.9)

    def test_plain_text_not_high_risk(self):
        result = analyse_bytes(b"Harmless notes about a project.\n", "notes.txt")
        self.assertEqual(result["verdict"], "no-known-indicators")

    def test_script_indicators(self):
        sample = b"import base64\nexec(base64.b64decode('YWJj'))\nshell = True\n"
        result = analyse_bytes(sample, "example.py")
        self.assertGreaterEqual(result["score"], 20)
        self.assertTrue(result["evidence"])

    def test_format_identification(self):
        self.assertEqual(file_format(b"\x7fELF"+b"\0"*32), "ELF executable/object")
        self.assertEqual(file_format(b"#!/bin/sh\necho safe\n"), "script")
        self.assertEqual(file_format(b"MZ"+b"\0"*80), "PE/DOS executable candidate")

    def test_entropy_alone_not_polymorphic(self):
        result = analyse_bytes(bytes(range(256))*32, "random.dat")
        self.assertFalse(result["polymorphic_candidate"])

    def test_quarantine_and_restore_round_trip(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "sample.txt"
            original.write_text("harmless sample", encoding="utf-8")
            manifest = quarantine_file(original, root / "quarantine", confirmed=True)
            self.assertFalse(original.exists())
            restored = restore_item(manifest["id"], root / "quarantine")
            self.assertEqual(restored.read_text(encoding="utf-8"), "harmless sample")

    def test_quarantine_requires_explicit_confirmation(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "sample.txt"
            original.write_text("unchanged", encoding="utf-8")
            with self.assertRaises(PermissionError):
                quarantine_file(original, Path(directory) / "store", confirmed=False)
            self.assertEqual(original.read_text(encoding="utf-8"), "unchanged")

if __name__ == "__main__":
    unittest.main()
