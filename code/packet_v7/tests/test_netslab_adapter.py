from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.netslab_adapter import (
    DatasetValidationError,
    REPLAY_BINDINGS,
    build_context_manifest,
)
from oran_trust_boundary.audit import canonical_sha256
from oran_trust_boundary.provenance import sha256_file


class NetsLabAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = ROOT / "tmp" / "tests" / "adapter-test.db"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.database.exists():
            self.database.unlink()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "CREATE TABLE lower_layer_data ("
                "ue_id TEXT, cellid TEXT, traffic_type INTEGER, "
                "attack_category TEXT, attack_subcategory TEXT, "
                "cqi REAL, sinr REAL, rsrp REAL, rsrq REAL, rssi REAL, "
                "dlBler REAL, ulBler REAL)"
            )
            for index, subcategory in enumerate(REPLAY_BINDINGS):
                benign = subcategory == "Benign"
                connection.execute(
                    "INSERT INTO lower_layer_data VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"private-ue-{index}",
                        "private-cell",
                        0 if benign else 1,
                        "Benign" if benign else "SyntheticAttackCategory",
                        subcategory,
                        10,
                        5,
                        -100,
                        -12,
                        -70,
                        0.1,
                        0.2,
                    ),
                )
            connection.commit()
        finally:
            connection.close()

    def test_manifest_is_exhaustive_deterministic_and_private(self) -> None:
        digest = sha256_file(self.database)
        first = build_context_manifest(self.database, expected_sha256=digest)
        second = build_context_manifest(self.database, expected_sha256=digest)
        self.assertEqual(first, second)
        self.assertEqual(len(first["strata"]), len(REPLAY_BINDINGS))
        self.assertTrue(all(item["selected_for_replay"] for item in first["strata"]))
        self.assertNotIn("private-ue", str(first))
        self.assertNotIn("private-cell", str(first))

    def test_hash_mismatch_fails_closed(self) -> None:
        with self.assertRaises(DatasetValidationError):
            build_context_manifest(self.database, expected_sha256="0" * 64)

    def test_committed_context_manifest_is_self_consistent(self) -> None:
        path = ROOT / "data" / "processed" / "netslab_contexts_v0.1.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        supplied = manifest.pop("manifest_sha256")
        self.assertEqual(canonical_sha256(manifest), supplied)
        self.assertEqual(manifest["dataset"]["license"]["spdx"], "CC-BY-4.0")
        self.assertEqual(len(manifest["strata"]), 19)
        self.assertEqual(
            sum(item["selected_for_replay"] for item in manifest["strata"]),
            6,
        )


if __name__ == "__main__":
    unittest.main()
