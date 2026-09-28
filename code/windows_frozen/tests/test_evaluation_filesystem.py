"""Focused fixtures for the narrowly scoped dynamic-output metadata rule."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary import evaluation_filesystem as scanner
from oran_trust_boundary.evaluation_performance import _no_links, PerformanceError


class DynamicOutputFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oran-output-scan-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.study = self.root / "requests.csv"
        self.study.write_bytes(b"measurement fixture")

    def scan(self):
        return scanner.dynamic_tree_bytes(self.root, check_chain=_no_links)

    def disappearing(self, target: Path, *, remove_parent=False):
        original = Path.lstat
        calls = []

        def lstat(path):
            if path == target:
                calls.append(path)
                if target.exists():
                    target.unlink()
                if remove_parent:
                    target.parent.rmdir()
                error = FileNotFoundError(2, "fixture leaf disappeared", str(target))
                error.winerror = 2
                raise error
            return original(path)
        return lstat, calls

    def test_existing_metadata_counted_normally_and_leaf_inspected_once(self):
        desktop = self.root / "desktop.ini"
        desktop.write_bytes(b"existing metadata")
        original = Path.lstat
        counts = {}

        def lstat(path):
            counts[path] = counts.get(path, 0) + 1
            return original(path)

        with patch.object(Path, "lstat", lstat):
            total = self.scan()
        self.assertEqual(total, len(b"measurement fixture") + len(b"existing metadata"))
        self.assertEqual(counts[desktop], 1)
        self.assertEqual(counts[self.study], 1)
        self.assertFalse((self.root / scanner.MONITOR_LOG_NAME).exists())

    def test_only_vanished_windows_metadata_is_logged_and_log_bytes_counted(self):
        desktop = self.root / "DeSkToP.InI"
        desktop.write_bytes(b"metadata")
        lstat, calls = self.disappearing(desktop)
        with patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
            total = self.scan()
        log = self.root / scanner.MONITOR_LOG_NAME
        event = json.loads(log.read_text())
        self.assertEqual(calls, [desktop])
        self.assertEqual(event["event"], "vanished_windows_directory_metadata")
        self.assertEqual(event["path"], desktop.name)
        self.assertEqual(event["output_monitor_version"], scanner.OUTPUT_MONITOR_VERSION)
        self.assertEqual(event["errno"], 2)
        self.assertEqual(event["winerror"], 2)
        self.assertEqual(total, self.study.stat().st_size + log.stat().st_size)
        self.assertNotIn(str(self.root), log.read_text())
        self.assertEqual(self.scan(), total)

    def test_preexisting_log_count_is_adjusted_not_double_counted(self):
        log = self.root / scanner.MONITOR_LOG_NAME
        log.write_bytes(b'{"prior_event":true}\n')
        desktop = self.root / "desktop.ini"
        desktop.write_bytes(b"metadata")
        lstat, _ = self.disappearing(desktop)
        with patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
            total = self.scan()
        self.assertEqual(total, self.study.stat().st_size + log.stat().st_size)
        self.assertEqual(len(log.read_text().splitlines()), 2)

    def test_monitor_log_creation_is_exclusive_and_append_cannot_recreate(self):
        log = self.root / scanner.MONITOR_LOG_NAME
        original_open = os.open
        flags_seen = []

        def record_open(path, flags, mode=0o777):
            flags_seen.append(flags)
            return original_open(path, flags, mode)

        with patch.object(scanner.os, "open", record_open):
            scanner._record_skips(self.root, [{"fixture": 1}], _no_links, {})
            scanner._record_skips(self.root, [{"fixture": 2}], _no_links, {log: log.stat().st_size})
        self.assertTrue(flags_seen[0] & os.O_CREAT)
        self.assertTrue(flags_seen[0] & os.O_EXCL)
        self.assertFalse(flags_seen[1] & os.O_CREAT)
        self.assertFalse(flags_seen[1] & os.O_EXCL)

    def test_raced_in_monitor_log_fails_closed_without_appending(self):
        log = self.root / scanner.MONITOR_LOG_NAME
        original_open = os.open

        def raced_open(path, flags, mode=0o777):
            log.write_bytes(b"raced-in fixture must remain unchanged")
            return original_open(path, flags, mode)

        with patch.object(scanner.os, "open", raced_open):
            with self.assertRaises(FileExistsError):
                scanner._record_skips(self.root, [{"fixture": 1}], _no_links, {})
        self.assertEqual(log.read_bytes(), b"raced-in fixture must remain unchanged")

    def test_vanished_study_file_and_similar_metadata_name_are_not_ignored(self):
        for name in ("summary.json", "desktop.ini.tmp"):
            target = self.root / name
            target.write_bytes(b"must not disappear")
            lstat, _ = self.disappearing(target)
            with self.subTest(name=name), patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
                with self.assertRaises(FileNotFoundError):
                    self.scan()
        self.assertFalse((self.root / scanner.MONITOR_LOG_NAME).exists())

    def test_non_windows_missing_metadata_is_not_ignored(self):
        desktop = self.root / "desktop.ini"
        desktop.write_bytes(b"metadata")
        lstat, _ = self.disappearing(desktop)
        with patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=False):
            with self.assertRaises(FileNotFoundError):
                self.scan()
        self.assertFalse((self.root / scanner.MONITOR_LOG_NAME).exists())

    def test_missing_parent_is_not_mistaken_for_missing_metadata(self):
        parent = self.root / "cell"
        parent.mkdir()
        desktop = parent / "desktop.ini"
        desktop.write_bytes(b"metadata")
        lstat, _ = self.disappearing(desktop, remove_parent=True)
        with patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
            with self.assertRaises(PerformanceError):
                self.scan()
        self.assertFalse((self.root / scanner.MONITOR_LOG_NAME).exists())

    def test_existing_symlink_and_reparse_metadata_are_refused(self):
        desktop = self.root / "desktop.ini"
        desktop.write_bytes(b"fixture")
        original = Path.lstat
        for mode, attributes in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o644, 0x400)):
            def lstat(path):
                return SimpleNamespace(st_mode=mode, st_file_attributes=attributes) if path == desktop else original(path)
            with self.subTest(mode=mode, attributes=attributes), patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
                with self.assertRaises(scanner.OutputScanError):
                    self.scan()

    def test_permission_and_other_io_failures_are_not_ignored(self):
        desktop = self.root / "desktop.ini"
        desktop.write_bytes(b"fixture")
        original = Path.lstat
        for error in (PermissionError(13, "fixture permission failure"), OSError(5, "fixture I/O failure")):
            def lstat(path):
                if path == desktop:
                    raise error
                return original(path)
            with self.subTest(error=type(error)), patch.object(Path, "lstat", lstat), patch.object(scanner, "_is_windows", return_value=True):
                with self.assertRaises(type(error)):
                    self.scan()
        self.assertFalse((self.root / scanner.MONITOR_LOG_NAME).exists())

    def test_missing_root_and_file_instead_of_root_are_refused(self):
        with self.assertRaises(PerformanceError):
            scanner.dynamic_tree_bytes(self.root / "missing", check_chain=_no_links)
        with self.assertRaises(scanner.OutputScanError):
            scanner.dynamic_tree_bytes(self.study, check_chain=_no_links)


if __name__ == "__main__":
    unittest.main()
