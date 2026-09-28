from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.review import compare_reviews, export_blinded_review


class ReviewTests(unittest.TestCase):
    def test_blinded_export_removes_identifier_label_leakage(self) -> None:
        output = ROOT / "tmp" / "tests" / "blinded-review.csv"
        output.parent.mkdir(parents=True, exist_ok=True)
        _, mapping = export_blinded_review(
            list(generate_cases()),
            output,
            blind_key=b"r" * 32,
        )
        exported = output.read_text(encoding="utf-8")
        self.assertIn("review_id", exported.splitlines()[0])
        self.assertNotIn("case_id", exported.splitlines()[0])
        self.assertNotIn("case-01-allow", exported)
        self.assertNotIn("action-01-safe", exported)
        self.assertNotIn("approval-11-allow", exported)
        self.assertIn("case-01-allow", mapping.values())

    def test_perfect_agreement(self) -> None:
        first = {"a": "ALLOW", "b": "DENY", "c": "ESCALATE"}
        result = compare_reviews(first, dict(first))
        self.assertEqual(result["observed_agreement"], 1.0)
        self.assertEqual(result["cohens_kappa"], 1.0)

    def test_disagreement_is_reported(self) -> None:
        first = {"a": "ALLOW", "b": "DENY", "c": "ESCALATE"}
        second = {"a": "DENY", "b": "DENY", "c": "ESCALATE"}
        result = compare_reviews(first, second)
        self.assertEqual(result["disagreement_case_ids"], ["a"])
        self.assertLess(result["cohens_kappa"], 1.0)


if __name__ == "__main__":
    unittest.main()
