from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.sqlite_profile import profile_sqlite_database


class SqliteProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_root = ROOT / "tmp" / "tests"
        cls.temp_root.mkdir(parents=True, exist_ok=True)

    def test_profile_contains_counts_but_not_raw_identifiers(self) -> None:
        database = self.temp_root / "profile-test.db"
        if database.exists():
            database.unlink()
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE telemetry ("
                "ue_id TEXT, sinr REAL, traffic_type TEXT, attack_subcategory TEXT)"
            )
            connection.executemany(
                "INSERT INTO telemetry VALUES (?, ?, ?, ?)",
                [
                    ("private-ue-a", 10.0, "Benign", "Benign"),
                    ("private-ue-b", 2.0, "Attack", "UDP Flood"),
                ],
            )
            connection.commit()
        finally:
            connection.close()
        profile = profile_sqlite_database(database)
        self.assertEqual(profile["sqlite_quick_check"], "ok")
        self.assertEqual(profile["tables"][0]["row_count"], 2)
        self.assertEqual(profile["profile_version"], "0.2.0")
        self.assertEqual(profile["tables"][0]["identifier_cardinality"]["ue_id"], 2)
        self.assertEqual(profile["tables"][0]["numeric_summaries"]["sinr"]["mean"], 6.0)
        self.assertNotIn("private-ue-a", str(profile))
        self.assertIn("UDP Flood", str(profile))


if __name__ == "__main__":
    unittest.main()
