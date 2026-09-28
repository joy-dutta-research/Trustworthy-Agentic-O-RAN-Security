from __future__ import annotations

import csv
import io
import json
import sys
import uuid
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.nidd_adapter import NiddValidationError, profile_archive
from oran_trust_boundary.provenance import sha256_file


class NiddAdapterTests(unittest.TestCase):
    def setUp(self):
        folder = ROOT / "tmp" / "tests"
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / ("nidd-" + uuid.uuid4().hex + ".zip")
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))

    def write_fixture(self, extra=(), member="Combined.csv", fields=None):
        fields = fields or ["", "Attack Type", "Label", "Dur", "TotPkts", "SrcAddr"]
        rows = [[str(i), label, "Benign" if label == "Benign" else "Malicious", "2", str(2000 + i), "private-source-do-not-export"]
                for i, label in enumerate(("Benign", "ICMPFlood", "SYNFlood", "UDPFlood"))]
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(fields)
        writer.writerows(rows + list(extra))
        with zipfile.ZipFile(self.path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, buffer.getvalue())
        return sha256_file(self.path)

    def test_reproducible_profile_and_no_identifiers(self):
        digest = self.write_fixture()
        first = profile_archive(self.path, expected_sha256=digest)
        self.assertEqual(first, profile_archive(self.path, expected_sha256=digest))
        self.assertEqual(first["audit"]["row_count"], 4)
        self.assertEqual(len(first["contexts"]), 4)
        self.assertNotIn("private-source-do-not-export", json.dumps(first))
        self.assertEqual(first["contexts"][1]["packets_per_second"], 1000.5)

    def test_hash_mismatch_and_bad_sample_size(self):
        digest = self.write_fixture()
        with self.assertRaisesRegex(NiddValidationError, "mismatch"):
            profile_archive(self.path, expected_sha256="0" * 64)
        for invalid in (0, 101, True, 1.5):
            with self.assertRaises(NiddValidationError):
                profile_archive(self.path, expected_sha256=digest, sample_per_label=invalid)

    def test_duplicate_export_index_not_counted_as_new_record(self):
        digest = self.write_fixture([["999", "SYNFlood", "Malicious", "2", "2002", "private-source-do-not-export"]])
        result = profile_archive(self.path, expected_sha256=digest)
        self.assertEqual(result["audit"]["duplicate_rows"], 1)
        self.assertEqual(result["audit"]["eligible_unique_counts"]["SYNFlood"], 1)

    def test_invalid_and_zero_duration_are_counted_not_imputed(self):
        digest = self.write_fixture([
            ["8", "SYNFlood", "Malicious", "nan", "99", "x"],
            ["9", "SYNFlood", "Malicious", "0", "99", "x"],
            ["10", "Benign", "Benign", "0", "1", "x"],
        ])
        result = profile_archive(self.path, expected_sha256=digest)
        self.assertEqual(result["audit"]["invalid_measurement_rows"], 1)
        self.assertEqual(result["audit"]["selection_exclusions"]["SYNFlood:nonpositive_or_undefined_packet_rate"], 1)
        self.assertTrue(any(row["packets_per_second"] is None for row in result["contexts"]))

    def test_unsafe_layout_and_headers_fail(self):
        digest = self.write_fixture(member="../Combined.csv")
        with self.assertRaises(NiddValidationError):
            profile_archive(self.path, expected_sha256=digest)
        digest = self.write_fixture(fields=["", "Attack Type", "Label", "Dur", "Dur", "SrcAddr"])
        with self.assertRaises(NiddValidationError):
            profile_archive(self.path, expected_sha256=digest)

    def test_label_disagreement_fails(self):
        digest = self.write_fixture([["8", "SYNFlood", "Benign", "1", "1", "x"]])
        with self.assertRaisesRegex(NiddValidationError, "inconsistent"):
            profile_archive(self.path, expected_sha256=digest)

    def test_unterminated_quote_fails(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Combined.csv", 'Attack Type,Label,Dur,TotPkts,Extra\nBenign,Benign,1,2,"unterminated')
        with self.assertRaisesRegex(NiddValidationError, "grammar"):
            profile_archive(self.path, expected_sha256=sha256_file(self.path))

    def test_sampling_bounded_with_full_population_audit(self):
        extra = [[str(i), "SYNFlood", "Malicious", "2", str(i * 30), "x"] for i in range(10, 100)]
        digest = self.write_fixture(extra)
        result = profile_archive(self.path, expected_sha256=digest, sample_per_label=3)
        self.assertEqual(result["audit"]["row_count"], 94)
        self.assertEqual(result["selection"]["selected_counts"]["SYNFlood"], 3)


if __name__ == "__main__":
    unittest.main()
