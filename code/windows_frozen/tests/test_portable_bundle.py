"""Offline archive/privacy/return checks; no VM, Linux packets or network."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("portable_bundle_test_module", ROOT / "scripts/portable_bundle.py")
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class PortableBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self):
        for name in bundle.SOURCE_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture: " + name, encoding="utf-8")
        for tree in bundle.SOURCE_TREES:
            (self.root / tree).mkdir(exist_ok=True)
        (self.root / "src/example.py").write_text("value = 1\n", encoding="utf-8")
        return bundle.source_payload(self.root)

    def test_source_is_allowlisted_not_recursive_repository_copy(self):
        expected = self.source()
        for name in ("data/raw/private.db", "review/private/key.json", ".vm-local/vm.vhdx",
                     ".env", "results/local/old.json", ".git/config"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private", encoding="utf-8")
        self.assertEqual(bundle.source_payload(self.root), expected)

    def test_zip_roundtrip_manifest_and_sidecar(self):
        payload = {"readme.md": b"test\n", "nested/a.json": b"{}\n"}
        output = self.root / "source.zip"
        result = bundle.write_archive(output, payload, "source", "oran-home-lab")
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(bundle.verify_archive(output)["status"], "VERIFIED_ARCHIVE")
        self.assertEqual(Path(str(output) + ".sha256").read_text().split()[0], bundle.digest(output.read_bytes()))

    def test_never_overwrites_zip_or_sidecar(self):
        output = self.root / "source.zip"
        output.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            bundle.write_archive(output, {}, "source", "oran-home-lab")
        self.assertEqual(output.read_bytes(), b"keep")
        second = self.root / "second.zip"
        Path(str(second) + ".sha256").write_text("keep")
        with self.assertRaises(FileExistsError):
            bundle.write_archive(second, {}, "source", "oran-home-lab")

    def test_archive_paths_cannot_escape_or_use_windows_streams(self):
        for name in ("../escape", "/root", "a/../../x", "a\\x", "C:/x", "a:stream", "a//x", "a/./x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.clean_relative(name)

    def test_archive_detects_tampering(self):
        payload = {"a.txt": b"correct"}
        metadata = bundle.manifest_for(payload, "source")
        output = self.root / "tampered.zip"
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("oran-home-lab/a.txt", "changed")
            archive.writestr("oran-home-lab/BUNDLE_MANIFEST.json", bundle.encoded(metadata))
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            bundle.verify_archive(output)

    def test_archive_rejects_symlink_members(self):
        output = self.root / "link.zip"
        with zipfile.ZipFile(output, "w") as archive:
            link = zipfile.ZipInfo("oran-home-lab/a.txt")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "target")
        with self.assertRaisesRegex(ValueError, "non-regular"):
            bundle.verify_archive(output)

    def test_archive_rejects_case_collisions(self):
        output = self.root / "duplicate.zip"
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("oran-home-lab/a.txt", "a")
            archive.writestr("oran-home-lab/A.txt", "b")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            bundle.verify_archive(output)

    def test_extracted_tree_checksum_and_added_source_detection(self):
        payload = self.source()
        (self.root / bundle.MANIFEST).write_bytes(bundle.encoded(bundle.manifest_for(payload, "source")))
        self.assertEqual(bundle.verify_tree(self.root)["status"], "VERIFIED_SOURCE_TREE")
        (self.root / "src/new.py").write_text("new = True\n")
        with self.assertRaisesRegex(ValueError, "Source differs"):
            bundle.verify_tree(self.root)

    def test_missing_manifest_is_not_success(self):
        with self.assertRaises(FileNotFoundError):
            bundle.verify_tree(self.root)

    def test_no_results_cannot_be_exported_as_success(self):
        with self.assertRaisesRegex(ValueError, "nothing has been run"):
            bundle.return_payload(self.root)

    def test_returns_every_session_including_failure_and_no_receipt(self):
        self.source()
        base = self.root / "results/local/handoff_runs"
        for name, status in (("one", "PILOT_COMPLETE_NOT_CONFIRMATORY"),
                             ("two", "INCOMPLETE_NOT_PUBLISHABLE"), ("three", None)):
            session = base / name
            session.mkdir(parents=True)
            (session / "raw.jsonl").write_text('{"real":1}\n')
            if status:
                (session / "session_receipt.json").write_text(json.dumps({"status": status}))
        returned = bundle.return_payload(self.root)
        index = json.loads(returned["RESULTS_INDEX.json"])
        self.assertEqual(len(index["sessions"]), 3)
        self.assertEqual({x["reported_status"] for x in index["sessions"]},
                         {"PILOT_COMPLETE_NOT_CONFIRMATORY", "INCOMPLETE_NOT_PUBLISHABLE",
                          "UNCLASSIFIED_OR_INTERRUPTED_RETAINED"})
        self.assertIn("source_snapshot/src/example.py", returned)
        self.assertIn("runs/two/raw.jsonl", returned)

    def test_return_zip_roundtrip_preserves_failure_and_source_changes(self):
        original = self.source()
        (self.root / bundle.MANIFEST).write_bytes(bundle.encoded(bundle.manifest_for(original, "source")))
        (self.root / "src/example.py").write_text("value = 2\n", encoding="utf-8")
        session = self.root / "results/local/handoff_runs/failed-fixture"
        session.mkdir(parents=True)
        (session / "session_receipt.json").write_text(json.dumps({"status": "INCOMPLETE_NOT_PUBLISHABLE"}))
        output = self.root / "return.zip"
        bundle.write_archive(output, bundle.return_payload(self.root), "results", "oran-home-results")
        with zipfile.ZipFile(output) as archive:
            changes = json.loads(archive.read("oran-home-results/SOURCE_CHANGES.json"))
            self.assertEqual(changes["modified"], ["src/example.py"])
            index = json.loads(archive.read("oran-home-results/RESULTS_INDEX.json"))
            self.assertEqual(index["sessions"][0]["reported_status"], "INCOMPLETE_NOT_PUBLISHABLE")
            self.assertIn("oran-home-results/received_source_manifest.json", archive.namelist())
        self.assertEqual(bundle.verify_archive(output)["kind"], "results")

    def test_active_run_lock_blocks_export(self):
        base = self.root / "results/local/handoff_runs"
        base.mkdir(parents=True)
        (base / ".active-run.lock").write_text("running")
        with self.assertRaisesRegex(ValueError, "Unexpected file"):
            bundle.return_payload(self.root)

    def test_unexpected_or_secret_result_files_refuse_export(self):
        self.source()
        session = self.root / "results/local/handoff_runs/one"
        session.mkdir(parents=True)
        bad = session / ".env"
        bad.write_text("SECRET=value")
        with self.assertRaisesRegex(ValueError, "Unexpected result"):
            bundle.return_payload(self.root)
        bad.unlink()
        (session / "stderr.log").write_text("-----BEGIN " + "PRIVATE KEY-----")
        with self.assertRaisesRegex(ValueError, "credential"):
            bundle.return_payload(self.root)

    def test_return_requires_explicit_privacy_review(self):
        with self.assertRaises(SystemExit), patch.object(bundle, "return_payload") as export:
            bundle.main(["return", "--output", str(self.root / "results.zip")])
        export.assert_not_called()


if __name__ == "__main__":
    unittest.main()
