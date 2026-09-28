from __future__ import annotations

import csv
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.inventory import inventory_dataset


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_root = ROOT / "tmp" / "tests"
        cls.temp_root.mkdir(parents=True, exist_ok=True)

    def test_directory_inventory_records_schema_not_rows(self) -> None:
        source = self.temp_root / "inventory-directory"
        source.mkdir(parents=True, exist_ok=True)
        csv_path = source / "radio.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "ue_id", "sinr", "label"])
            writer.writerow(["private-value", "ue-private", "10", "benign"])
        inventory = inventory_dataset(source)
        self.assertEqual(inventory["file_count"], 1)
        self.assertEqual(
            inventory["files"][0]["columns"],
            ["timestamp", "ue_id", "sinr", "label"],
        )
        self.assertNotIn("private-value", str(inventory))
        self.assertNotIn("ue-private", str(inventory))

    def test_zip_inventory_does_not_extract_archive(self) -> None:
        archive_path = self.temp_root / "inventory-dataset.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("nested/radio.csv", "timestamp,sinr,label\n1,10,benign\n")
        inventory = inventory_dataset(archive_path)
        self.assertEqual(inventory["input_type"], "zip")
        self.assertEqual(inventory["files"][0]["columns"], ["timestamp", "sinr", "label"])
        self.assertFalse((self.temp_root / "nested").exists())

    def test_suspicious_archive_names_are_flagged_not_extracted(self) -> None:
        archive_path = self.temp_root / "inventory-path-traversal.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../outside.csv", "timestamp,label\n1,benign\n")
        inventory = inventory_dataset(archive_path)
        self.assertTrue(inventory["files"][0]["unsafe_archive_path"])
        self.assertFalse((self.temp_root.parent / "outside.csv").exists())

    def test_oversized_header_is_bounded(self) -> None:
        source = self.temp_root / "inventory-long-header"
        source.mkdir(parents=True, exist_ok=True)
        csv_path = source / "long.csv"
        csv_path.write_text("x" * 70_000 + "\n1\n", encoding="utf-8")
        inventory = inventory_dataset(source)
        self.assertIn("header_error", inventory["files"][0])


if __name__ == "__main__":
    unittest.main()
