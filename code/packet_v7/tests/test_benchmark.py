from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.benchmark import run_benchmark, wilson_interval
from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.engine import TrustBoundary


class BenchmarkTests(unittest.TestCase):
    def test_expected_comparative_pattern(self) -> None:
        engine = TrustBoundary.from_file(
            ROOT / "configs" / "paper_policy.json",
            ROOT / "data" / "conformance" / "approval_registry_v0.1.json",
        )
        _, summaries = run_benchmark(
            list(generate_cases()),
            engine,
            repeats=1,
            timing_seed=7,
        )
        by_system = {summary["system"]: summary for summary in summaries}
        self.assertEqual(by_system["direct"]["unsafe_action_admission_rate"], 1.0)
        self.assertEqual(by_system["contract"]["unsafe_action_admission_rate"], 1.0)
        self.assertEqual(by_system["contract_rbac"]["unsafe_action_admission_rate"], 0.8)
        self.assertEqual(by_system["trust_boundary"]["unsafe_action_admission_rate"], 0.0)
        self.assertEqual(by_system["trust_boundary"]["safe_action_acceptance_rate"], 1.0)
        self.assertEqual(by_system["trust_boundary"]["audit_completeness"], 1.0)

    def test_wilson_interval_is_bounded_at_extremes(self) -> None:
        zero_low, zero_high = wilson_interval(0, 100)
        one_low, one_high = wilson_interval(100, 100)
        self.assertEqual(zero_low, 0.0)
        self.assertGreater(zero_high, 0.0)
        self.assertLess(one_low, 1.0)
        self.assertEqual(one_high, 1.0)


if __name__ == "__main__":
    unittest.main()
