"""Offline image-authentication tests; no downloads or VM mutations."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ubuntu_media", ROOT / "scripts/vm/download_ubuntu_iso.py")
media = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(media)


class UbuntuMediaTests(unittest.TestCase):
    def status(self, fingerprint=None, algorithm="10"):
        fpr = fingerprint or media.SIGNING_KEY
        return f"[GNUPG:] VALIDSIG {fpr} 2026-09-22 1790000000 0 4 0 1 {algorithm} 00 {fpr}\n"

    def test_requires_exact_pinned_checksum_and_filename_once(self):
        correct = media.EXPECTED_SHA256 + " *" + media.FILENAME + "\n"
        media.verify_checksum_text(correct)
        for value in ("", correct + correct, correct.replace(media.EXPECTED_SHA256, "0" * 64),
                      correct.replace(media.FILENAME, "different.iso")):
            with self.assertRaises(ValueError):
                media.verify_checksum_text(value)

    def test_requires_pinned_valid_signature_not_goodsig_text(self):
        media.verify_gpg_status(self.status())
        for value in ("[GNUPG:] GOODSIG D94AA3F0EFE21092 Ubuntu\n", self.status("0" * 40),
                      self.status(algorithm="2"), ""):
            with self.assertRaises(ValueError):
                media.verify_gpg_status(value)

    def test_bad_expired_or_revoked_signature_never_accepted(self):
        for keyword in ("BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"):
            with self.assertRaises(ValueError):
                media.verify_gpg_status(self.status() + f"[GNUPG:] {keyword} key\n")

    def test_redirect_cannot_leave_trusted_origin_or_downgrade_tls(self):
        request = urllib.request.Request(media.BASE + media.FILENAME)
        handler = media.SameOriginRedirect()
        for url in ("http://releases.ubuntu.com/file.iso", "https://evil.example/file.iso",
                    "https://user:pass@releases.ubuntu.com/file.iso"):
            with self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)

    def test_gpg_uses_repository_relative_paths_and_never_shell(self):
        with patch.object(media.subprocess, "run", return_value=Mock(returncode=0)) as run:
            media.run_gpg(Path(sys.executable), ROOT / ".vm-local/gnupg", "--verify",
                          str(ROOT / ".vm-local/verification/test/SHA256SUMS.gpg"))
        args, kwargs = run.call_args
        self.assertIn(".vm-local/gnupg", args[0])
        self.assertIn(".vm-local/verification/test/SHA256SUMS.gpg", args[0])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["cwd"], ROOT)

    def test_existing_iso_is_rehashed_and_never_overwritten(self):
        path = Mock()
        path.exists.return_value = True
        path.is_symlink.return_value = False
        path.stat.return_value.st_file_attributes = 0
        with patch.object(media, "sha256", return_value=media.EXPECTED_SHA256):
            self.assertEqual(media.download_iso(path, resume=False), "existing_iso_reverified")
        with patch.object(media, "sha256", return_value="0" * 64), self.assertRaises(ValueError):
            media.download_iso(path, resume=False)
        path.open.assert_not_called()

    def test_windows_junction_is_rejected_even_if_not_a_symlink(self):
        path = Mock()
        path.is_symlink.return_value = False
        path.exists.return_value = True
        path.stat.return_value.st_file_attributes = 0x400
        with self.assertRaises(ValueError):
            media.reject_reparse(path)

    def test_existing_receipt_is_validated_not_silently_reused(self):
        receipt, iso = Mock(), Mock()
        receipt.is_symlink.return_value = False
        receipt.exists.return_value = True
        receipt.is_file.return_value = True
        receipt.stat.return_value.st_file_attributes = 0
        iso.stat.return_value.st_size = 100
        valid = {"status": "VERIFIED_SIGNATURE_AND_SHA256", "iso_filename": media.FILENAME,
                 "iso_sha256": media.EXPECTED_SHA256, "signing_key_fingerprint": media.SIGNING_KEY,
                 "iso_bytes": 100}
        with patch.object(media, "strict_json_load", return_value=valid):
            media.validate_existing_receipt(receipt, iso)
        for wrong in ({}, valid | {"iso_bytes": 99}, valid | {"status": "DOWNLOADING"}):
            with patch.object(media, "strict_json_load", return_value=wrong), self.assertRaises(ValueError):
                media.validate_existing_receipt(receipt, iso)

    def test_zero_byte_partial_can_be_explicitly_resumed(self):
        destination, partial = Mock(), Mock()
        for path in (destination, partial):
            path.is_symlink.return_value = False
            path.stat.return_value.st_file_attributes = 0
        destination.exists.return_value = False
        destination.suffix = ".iso"
        destination.with_suffix.return_value = partial
        partial.exists.return_value = True
        partial.stat.return_value.st_size = 0
        partial.open.return_value.__enter__ = Mock(return_value=Mock())
        partial.open.return_value.__exit__ = Mock(return_value=False)
        response = Mock(status=200, headers={"Content-Length": str(1024**3)})
        response.read.side_effect = RuntimeError("stop before any download")
        connection = Mock()
        connection.__enter__ = Mock(return_value=response)
        connection.__exit__ = Mock(return_value=False)
        with patch.object(media, "opener") as open_factory, patch.object(media.shutil, "disk_usage") as usage:
            open_factory.return_value.open.return_value = connection
            usage.return_value.free = 10 * 1024**3
            with self.assertRaisesRegex(RuntimeError, "stop before any download"):
                media.download_iso(destination, resume=True)
        partial.open.assert_called_once_with("ab")


if __name__ == "__main__":
    unittest.main()
