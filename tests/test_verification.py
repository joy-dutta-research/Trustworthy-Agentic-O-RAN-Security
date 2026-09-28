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
            manifest_path = root / verify.MANIFEST_NAME
            manifest_path.parent.mkdir(parents=True)
            (manifest_path.parent / "README.md").write_text("# Release records\n", encoding="utf-8")
            manifest = {"schema_version": 1, "files": {
                name: {"bytes": path.stat().st_size, "sha256": verify.digest_file(path)}
                for name, path in verify.repository_files(root).items()
            }}
            manifest["files"]["evidence/raw_archives/example.zip"] = {"bytes": 1, "sha256": "unused"}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(verify.verify(root, True)["status"], "PARTIAL_SOURCE_CHECK")
            self.assertEqual(verify.verify(root)["status"], "FAIL")
            readme.write_text("# Changed\n", encoding="utf-8")
            self.assertEqual(verify.verify(root, True)["status"], "FAIL")

    def test_relocated_manifest_excludes_only_itself(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            manifest_path = root / verify.MANIFEST_NAME
            self.assertEqual(manifest_path.parent, root / "release")
            manifest_path.parent.mkdir(parents=True)
            (manifest_path.parent / "README.md").write_text("# Release records\n", encoding="utf-8")
            # A same-named file elsewhere must still be checked, not silently
            # excluded by basename after moving the active manifest.
            historical = root / "REPOSITORY_MANIFEST.json"
            historical.write_text("{}\n", encoding="utf-8")
            manifest_path.write_text("{}\n", encoding="utf-8")
            files = verify.repository_files(root)
            self.assertNotIn(verify.MANIFEST_NAME, files)
            self.assertIn("REPOSITORY_MANIFEST.json", files)
            manifest = {"schema_version": 1, "files": {
                name: {"bytes": path.stat().st_size, "sha256": verify.digest_file(path)}
                for name, path in files.items()
            }}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(verify.verify(root)["status"], "PASS")
            historical.write_text('{"changed": true}\n', encoding="utf-8")
            self.assertIn("Changed: REPOSITORY_MANIFEST.json", verify.verify(root)["failures"])

    def test_comparison_checks_every_condition(self):
        same_numbers({"x": [1.0, None]}, {"x": [1, None]})
        with self.assertRaises(ValueError):
            same_numbers({"x": [1, 2]}, {"x": [1, 3]})
        with self.assertRaises(ValueError):
            same_numbers({"x": []}, {"y": []})


class LandingPageTests(unittest.TestCase):
    @staticmethod
    def write_fixture(root, files):
        for name in files:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# Fixture guidance\n", encoding="utf-8")
        manifest_path = root / verify.MANIFEST_NAME
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        (manifest_path.parent / "README.md").write_text("# Release records\n", encoding="utf-8")
        manifest = {"schema_version": 1, "files": {
            name: {"bytes": path.stat().st_size, "sha256": verify.digest_file(path)}
            for name, path in verify.repository_files(root).items()
        }}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_missing_root_readme_fails_even_with_valid_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root, ["GUIDE.md"])
            result = verify.verify(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("Landing page: root README.md is required (exact filename)", result["failures"])

    def test_immediate_github_readme_aliases_are_rejected(self):
        for filename in ("README", "README.md", "readme.rst", "ReadMe.txt"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_fixture(root, ["README.md", ".github/GUIDE.md", ".github/" + filename])
                result = verify.verify(root)
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(any(".github README can shadow" in error for error in result["failures"]))

    def test_competing_root_readme_formats_are_rejected(self):
        for filename in ("README", "ReadMe.txt", "readme.rst"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_fixture(root, ["README.md", filename])
                result = verify.verify(root)
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(any("competing root README" in error for error in result["failures"]))

    def test_canonical_root_readme_spelling_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root, ["readme.md"])
            result = verify.verify(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("Landing page: root README.md is required (exact filename)", result["failures"])

    def test_folder_readmes_and_github_guide_remain_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root, ["README.md", ".github/GUIDE.md",
                                      ".github/workflows/README.md", "docs/README.md"])
            self.assertEqual(verify.landing_page(root), [])
            self.assertEqual(verify.verify(root)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
