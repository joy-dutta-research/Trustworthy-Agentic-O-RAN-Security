"""Small adversarial fixtures for the publication-only verifier."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_repository as verify
from recompute_packet_evidence import same_numbers


class IntegrityTests(unittest.TestCase):
    def test_unsafe_paths_rejected(self):
        for name in ("../x", "/x", "C:/x", "a\\b", "a//b", "a/./b", "con.txt", "file.", "x:y"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify.safe_member(name)

    def test_safe_paths_accepted(self):
        self.assertEqual(str(verify.safe_member("data/part-1.json")), "data/part-1.json")

    def test_case_collisions_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("A.txt", "one")
            archive.writestr("a.txt", "two")
        with zipfile.ZipFile(stream) as archive, self.assertRaises(ValueError):
            verify.validate_zip_members(archive)

    def test_archive_symlink_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            item = zipfile.ZipInfo("link")
            item.external_attr = 0o120777 << 16
            archive.writestr(item, "target")
        with zipfile.ZipFile(stream) as archive, self.assertRaises(ValueError):
            verify.validate_zip_members(archive)

    def test_hash_change_detected_and_partial_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            readme = root / "README.md"
            readme.write_text("# Example\n", encoding="utf-8")
            manifest = {"schema_version": 1, "files": {
                "README.md": {"bytes": readme.stat().st_size, "sha256": verify.digest_file(readme)},
                "evidence/raw_archives/example.zip": {"bytes": 1, "sha256": "unused"},
            }}
            (root / verify.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(verify.verify(root, True)["status"], "PARTIAL_SOURCE_CHECK")
            self.assertEqual(verify.verify(root)["status"], "FAIL")
            readme.write_text("# Changed\n", encoding="utf-8")
            self.assertEqual(verify.verify(root, True)["status"], "FAIL")

    def test_comparison_checks_every_condition(self):
        same_numbers({"x": [1.0, None]}, {"x": [1, None]})
        with self.assertRaises(ValueError):
            same_numbers({"x": [1, 2]}, {"x": [1, 3]})
        with self.assertRaises(ValueError):
            same_numbers({"x": []}, {"y": []})


if __name__ == "__main__":
    unittest.main()
