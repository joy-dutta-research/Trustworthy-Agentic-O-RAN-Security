from __future__ import annotations

import sys
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.audit import completeness
from oran_trust_boundary.baselines import contract_only, contract_rbac, direct_execution
from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.contract import parse_action
from oran_trust_boundary.engine import TrustBoundary


class ConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = list(generate_cases())
        cls.engine = TrustBoundary.from_file(
            ROOT / "configs" / "paper_policy.json",
            ROOT / "data" / "conformance" / "approval_registry_v0.1.json",
        )

    def test_suite_has_expected_balanced_categories(self) -> None:
        self.assertEqual(len(self.cases), 120)
        counts = Counter(case["category"] for case in self.cases)
        self.assertEqual(set(counts.values()), {20})
        decisions = Counter(case["expected_decision"] for case in self.cases)
        self.assertEqual(decisions, {"ALLOW": 20, "DENY": 60, "ESCALATE": 40})

    def test_every_case_is_structurally_valid(self) -> None:
        for case in self.cases:
            proposal, issues = parse_action(case["proposal"])
            self.assertIsNotNone(proposal, case["case_id"])
            self.assertEqual(issues, (), case["case_id"])
            for active in case["active_actions"]:
                active_proposal, active_issues = parse_action(active)
                self.assertIsNotNone(active_proposal, case["case_id"])
                self.assertEqual(active_issues, (), case["case_id"])

    def test_dataset_and_standards_scenarios_are_not_conflated(self) -> None:
        dataset_cases = [
            case
            for case in self.cases
            if case["source_context"]["kind"] == "dataset_label_scenario"
        ]
        standards_cases = [
            case
            for case in self.cases
            if case["source_context"]["kind"] == "standards_threat_scenario"
        ]
        self.assertEqual(len(dataset_cases), 60)
        self.assertEqual(len(standards_cases), 60)
        self.assertTrue(
            all(
                case["proposal"]["action"] in {"rate_limit_ue", "quarantine_ue"}
                for case in dataset_cases
            )
        )
        self.assertTrue(
            all(
                case["source_context"]["dataset_binding"]["status"] == "exact_label"
                for case in dataset_cases
            )
        )
        self.assertTrue(
            all(
                case["proposal"]["action"] in {"isolate_xapp", "modify_a1_policy"}
                for case in standards_cases
            )
        )

    def test_baselines_allow_all_well_formed_cases(self) -> None:
        for case in self.cases:
            self.assertEqual(direct_execution(case["proposal"]).decision.value, "ALLOW")
            self.assertEqual(contract_only(case["proposal"]).decision.value, "ALLOW")

    def test_rbac_baseline_blocks_only_unauthorized_category(self) -> None:
        for case in self.cases:
            result = contract_rbac(
                case["proposal"],
                policy=self.engine.policy,
                authenticated_principal=case["authenticated_principal"],
            )
            expected = "DENY" if case["category"] == "unauthorized" else "ALLOW"
            self.assertEqual(result.decision.value, expected, case["case_id"])

    def test_trust_boundary_matches_frozen_expected_outcomes(self) -> None:
        for case in self.cases:
            as_of = datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))
            result = self.engine.evaluate(
                case["proposal"],
                case["active_actions"],
                authenticated_principal=case["authenticated_principal"],
                as_of=as_of,
            )
            self.assertEqual(
                result.decision.value,
                case["expected_decision"],
                case["case_id"],
            )
            self.assertIn(case["expected_reason"], result.reason_codes, case["case_id"])
            self.assertIn(case["policy_under_test"], result.policy_ids, case["case_id"])

    def test_complete_audit_record_for_every_well_formed_case(self) -> None:
        required = self.engine.policy["audit_required_fields"]
        for case in self.cases:
            as_of = datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))
            result = self.engine.evaluate(
                case["proposal"],
                case["active_actions"],
                authenticated_principal=case["authenticated_principal"],
                as_of=as_of,
            )
            self.assertEqual(completeness(result.audit_record, required), 1.0, case["case_id"])


if __name__ == "__main__":
    unittest.main()
