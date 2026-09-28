from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import unittest
import urllib.request
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("download_5gnidd", ROOT / "scripts" / "download_5gnidd.py")
downloader = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = downloader
spec.loader.exec_module(downloader)


class FakeResponse(io.BytesIO):
    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = headers or {}


class FiveGNIDDDownloadTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp" / "tests").mkdir(parents=True, exist_ok=True)
        self.directory = ROOT / "tmp" / "tests" / ("5gnidd-download-" + uuid.uuid4().hex)
        self.directory.mkdir()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()

    def test_url_validation_rejects_untrusted_origin_and_credentials(self):
        for url in ("http://download.fairdata.fi/download", "https://download.fairdata.fi.evil.test/",
                    "https://user:password@download.fairdata.fi/", "https://download.fairdata.fi:444/",
                    "https://download.fairdata.fi/#fragment", "https://download.fairdata.fi/\n", None):
            with self.subTest(url=url), self.assertRaises(downloader.DownloadError):
                downloader.validate_url(url)
        downloader.validate_url("https://download.fairdata.fi/download?token=opaque")

    def test_stream_verifies_hash_before_atomic_publication(self):
        raw = b"example archive bytes"
        target = self.directory / "archive.zip"
        downloader.stream_archive(FakeResponse(raw), target, size=len(raw), digest=hashlib.sha256(raw).hexdigest())
        self.assertEqual(target.read_bytes(), raw)
        self.assertEqual(list(self.directory.glob("*.partial")), [])

    def test_redirects_cannot_forward_token_to_another_origin(self):
        request = urllib.request.Request("https://download.fairdata.fi/download?token=private")
        with self.assertRaises(downloader.DownloadError) as failure:
            downloader.RestrictedRedirect().redirect_request(
                request, None, 302, "Found", {}, "https://etsin.fairdata.fi/other"
            )
        self.assertNotIn("private", str(failure.exception))

    def test_archive_listing_rejects_path_traversal_without_extracting(self):
        target = self.directory / "unsafe.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("../outside.csv", "private")
        with self.assertRaises(downloader.DownloadError):
            downloader.list_archive(target)
        self.assertFalse((self.directory.parent / "outside.csv").exists())

    def test_bad_hash_truncation_and_oversize_leave_no_final_file(self):
        for raw, size in ((b"abc", 3), (b"ab", 3), (b"abcd", 3)):
            target = self.directory / "bad.zip"
            with self.subTest(raw=raw), self.assertRaises(downloader.DownloadError):
                downloader.stream_archive(FakeResponse(raw), target, size=size, digest="0" * 64)
            self.assertFalse(target.exists())
            self.assertEqual(list(self.directory.glob("*.partial")), [])

    def test_existing_different_file_is_not_overwritten(self):
        target = self.directory / "archive.zip"
        target.write_bytes(b"original")
        with self.assertRaises(downloader.DownloadError):
            downloader.stream_archive(FakeResponse(b"replacement"), target, size=11, digest="0" * 64)
        self.assertEqual(target.read_bytes(), b"original")

    def test_concurrent_target_is_not_replaced(self):
        partial = self.directory / "partial"
        target = self.directory / "target"
        partial.write_bytes(b"new")
        target.write_bytes(b"existing")
        with self.assertRaises(downloader.DownloadError):
            downloader.publish_no_replace(partial, target)
        self.assertEqual(target.read_bytes(), b"existing")

    def test_license_and_checksum_must_match_original_metadata(self):
        dataset = {"id": downloader.DATASET_ID,
                   "persistent_identifier": downloader.DATASET_DOI.replace("https://doi.org/", "doi:"),
                   "access_rights": {"access_type": {"url": "http://example/open"},
                                     "license": [{"custom_url": downloader.LICENSE_URL}]}}
        files = [{"pathname": "/Combined.zip", "size": downloader.EXPECTED_SIZE,
                  "checksum": "sha256:" + downloader.EXPECTED_SHA256, "user": "private-service-user"}]
        receipt = downloader.verify_source_metadata(dataset, files)
        self.assertNotIn("private-service-user", json.dumps(receipt))
        files[0]["size"] += 1
        with self.assertRaises(downloader.DownloadError):
            downloader.verify_source_metadata(dataset, files)
        files[0]["size"] -= 1
        dataset["access_rights"]["license"] = []
        with self.assertRaises(downloader.DownloadError):
            downloader.verify_source_metadata(dataset, files)

    def test_receipts_are_idempotent_and_preserve_prior_versions(self):
        downloader.write_receipt(self.directory, {"license": "one"})
        downloader.write_receipt(self.directory, {"license": "one"})
        self.assertEqual(len(list(self.directory.glob("provenance-*.json"))), 1)
        downloader.write_receipt(self.directory, {"license": "two"})
        self.assertEqual(len(list(self.directory.glob("provenance-*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
