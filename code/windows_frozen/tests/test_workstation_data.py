"""Small pinned fixtures for private companion import; no real raw data copied."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workstation_data_tests", ROOT / "scripts/workstation_data.py")
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)


class WorkstationDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = {name: ("fixture:" + name).encode() for name in data.RAW}
        pins = {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                for name, value in self.raw.items()}
        patcher = patch.object(data, "RAW", pins)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def source(self):
        for name, value in self.raw.items():
            self.put(name, value)
        nets = data.RAW["data/raw/Lower_Layer_Data.db"]
        self.put(data.RECEIPT, data.bundle.encoded({"archive_filename": "archive.zip", "created_at": "2026-09-22T10:25:34Z",
            "member": "Lower_Layer_Data.db", "member_crc32": "15d7cdc9", "member_sha256": nets["sha256"],
            "member_size_bytes": nets["bytes"], "receipt_version": "0.1.0"}))
        nidd = data.RAW["data/raw/5g-nidd/Combined.zip"]
        provenance = {"access": "open", "archive": {"checksum": "sha256:" + nidd["sha256"], "filename": "Combined.zip",
            "frozen": "2022-12-10T23:27:02Z", "id": "fixture", "modified": "2022-12-07T08:29:25Z", "pathname": "/Combined.zip",
            "size": nidd["bytes"], "storage_identifier": "fixture"}, "archive_members": [],
            "dataset_doi": "https://doi.org/fixture", "dataset_id": "fixture", "descriptor_doi": "https://doi.org/fixture",
            "files_url": "https://example.test/files", "license": "https://creativecommons.org/licenses/by/4.0/",
            "metadata_modified": "2025-08-14", "metadata_url": "https://example.test/metadata", "receipt_version": "1.0",
            "title": {"en": "Fixture dataset"}, "verified_sha256": nidd["sha256"], "version": 1,
            "private_acquisition_field": "must be stripped"}
        provenance.update(data.PROVENANCE_URLS)
        self.put(data.PROVENANCE, data.bundle.encoded(provenance))
        self.put(data.ATTRIBUTION, b"Creator attribution and third-party dataset licence notice.\n")
        return data.source_payload(self.root)

    def build(self):
        output = self.root / "private.zip"
        data.write_archive(output, self.source())
        return output

    def test_build_only_pinned_inputs_and_sanitized_metadata(self):
        self.put("data/raw/not_requested.db", b"do not transfer")
        self.put("archive.zip", b"do not transfer parent")
        output = self.build()
        metadata = data.verify_archive(output)
        self.assertEqual(set(metadata["files"]), data.MEMBERS)
        self.assertFalse(metadata["public_upload_authorized"])
        with zipfile.ZipFile(output) as archive:
            provenance = json.loads(archive.read(data.PREFIX + "/" + data.PROVENANCE))
            self.assertNotIn("private_acquisition_field", provenance)
        self.assertTrue(Path(str(output) + ".sha256").is_file())

    def test_streamed_roundtrip_and_idempotent_import(self):
        output = self.build()
        destination = self.root / "destination"
        with patch.object(Path, "read_bytes", side_effect=AssertionError("No whole-file reads")):
            first = data.import_archive(output, destination)
            second = data.import_archive(output, destination)
        self.assertEqual(len(first["written"]), len(data.MEMBERS) + 1)
        self.assertEqual(second["written"], [])
        self.assertEqual(len(second["identical_existing_preserved"]), len(data.MEMBERS) + 1)
        self.assertEqual((destination / "data/raw/Lower_Layer_Data.db").read_bytes(), self.raw["data/raw/Lower_Layer_Data.db"])
        self.assertTrue((destination / "data/raw/PRIVATE_DATA_MANIFEST.json").is_file())
        self.assertFalse((destination / "PRIVATE_DATA_MANIFEST.json").exists())

    def test_matching_readonly_file_preserved(self):
        output = self.build()
        destination = self.root / "destination"
        target = destination / "data/raw/Lower_Layer_Data.db"
        target.parent.mkdir(parents=True)
        target.write_bytes(self.raw["data/raw/Lower_Layer_Data.db"])
        target.chmod(stat.S_IREAD)
        try:
            result = data.import_archive(output, destination)
            self.assertIn("data/raw/Lower_Layer_Data.db", result["identical_existing_preserved"])
        finally:
            target.chmod(stat.S_IREAD | stat.S_IWRITE)

    def test_wrong_raw_hash_rejected_before_build(self):
        self.source()
        self.put("data/raw/Lower_Layer_Data.db", b"changed")
        with self.assertRaisesRegex(ValueError, "differs from frozen"):
            data.source_payload(self.root)

    def test_existing_different_file_preflight_no_other_files_written(self):
        output = self.build()
        destination = self.root / "destination"
        target = destination / "data/raw/Lower_Layer_Data.db"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"existing unrelated input")
        with self.assertRaises(FileExistsError):
            data.import_archive(output, destination)
        self.assertEqual(target.read_bytes(), b"existing unrelated input")
        self.assertFalse((destination / data.PROVENANCE).exists())

    def test_no_overwrite_zip_or_checksum(self):
        payload = self.source()
        output = self.put("existing.zip", b"preserve")
        with self.assertRaises(FileExistsError):
            data.write_archive(output, payload)
        self.put("sidecar.zip.sha256", b"preserve")
        with self.assertRaises(FileExistsError):
            data.write_archive(self.root / "sidecar.zip", payload)

    def test_wrong_receipt_and_private_provenance_refused(self):
        self.source()
        raw = json.loads((self.root / data.RECEIPT).read_text())
        raw["member_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned"):
            data.checked_receipt(data.bundle.encoded(raw))
        raw = json.loads((self.root / data.PROVENANCE).read_text())
        raw["metadata_url"] += "?private-token=secret"
        with self.assertRaisesRegex(ValueError, "private"):
            data.sanitized_provenance(data.bundle.encoded(raw))

    def test_traversal_extra_member_and_symlink_fail_before_import(self):
        good = self.build()
        for name, mode in ((data.PREFIX + "/../escape", stat.S_IFREG),
                           (data.PREFIX + "/extra.txt", stat.S_IFREG),
                           (data.PREFIX + "/link", stat.S_IFLNK)):
            output = self.root / "bad.zip"
            with zipfile.ZipFile(good) as original, zipfile.ZipFile(output, "w") as archive:
                for member in original.infolist():
                    archive.writestr(member, original.read(member))
                member = zipfile.ZipInfo(name)
                member.external_attr = (mode | 0o644) << 16
                archive.writestr(member, "target")
            with self.assertRaises(ValueError):
                data.import_archive(output, self.root / "destination")
            self.assertFalse((self.root / "destination").exists())

    def test_archive_tampering_detected(self):
        good = self.build()
        output = self.root / "tampered.zip"
        with zipfile.ZipFile(good) as original, zipfile.ZipFile(output, "w") as archive:
            for member in original.infolist():
                value = original.read(member)
                if member.filename.endswith("Lower_Layer_Data.db"):
                    value = b"tampered"
                archive.writestr(member, value)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            data.verify_archive(output)

    def test_raw_data_not_added_to_result_export_allowlist(self):
        self.assertNotIn("data/raw/Lower_Layer_Data.db", data.bundle.SOURCE_FILES)
        self.assertNotIn("data/raw/5g-nidd/Combined.zip", data.bundle.SOURCE_FILES)
        self.assertNotIn("data/raw", data.bundle.SOURCE_TREES)


if __name__ == "__main__":
    unittest.main()
