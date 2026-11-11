import tempfile
import unittest
import zipfile
from pathlib import Path

from qsafe import analyse_bytes
from qsafe_extras import scan_archive_bytes, scan_archives, create_baseline, check_baseline


class ArchiveAndBaselineTests(unittest.TestCase):
    def test_zip_member_scanned_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../../outside.py", "exec(base64.b64decode('YWJj'))\nsocket.connect(('127.0.0.1', 4444))")
            entries = scan_archive_bytes(archive_path.read_bytes(), str(archive_path), analyse_bytes)
            scanned = [entry for entry in entries if entry["status"] == "scanned"]
            self.assertEqual(len(scanned), 1)
            self.assertGreaterEqual(scanned[0]["analysis"]["score"], 20)
            self.assertFalse((Path(directory).parent / "outside.py").exists())

    def test_directory_archive_scan_discovers_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "input.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("inside.py", "exec(base64.b64decode('YWJj'))")
            entries = scan_archives(root, analyse_bytes)
            self.assertTrue(any(entry.get("archive") == str(archive_path) for entry in entries))

    def test_baseline_detects_added_and_modified_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            first = root / "first.txt"
            first.write_text("version one", encoding="utf-8")
            baseline = Path(directory) / "baseline.json"
            create_baseline(root, baseline)
            first.write_text("version two", encoding="utf-8")
            (root / "new.txt").write_text("new file", encoding="utf-8")
            result = check_baseline(root, baseline)
            self.assertIn("first.txt", result["modified"])
            self.assertIn("new.txt", result["added"])
            self.assertEqual(result["removed"], [])

    def test_baseline_detects_permission_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            target = root / "program.bin"
            target.write_bytes(b"binary")
            baseline = Path(directory) / "permissions.json"
            create_baseline(root, baseline)
            target.chmod(0o600)
            result = check_baseline(root, baseline)
            self.assertIn("program.bin", result["modified"])

    def test_baseline_file_inside_root_is_not_self_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            (root / "app.txt").write_text("known", encoding="utf-8")
            baseline = root / ".qsafe-baseline.json"
            create_baseline(root, baseline)
            result = check_baseline(root, baseline)
            self.assertEqual(result["added"], [])
            self.assertEqual(result["modified"], [])
            self.assertEqual(result["removed"], [])


if __name__ == "__main__":
    unittest.main()
