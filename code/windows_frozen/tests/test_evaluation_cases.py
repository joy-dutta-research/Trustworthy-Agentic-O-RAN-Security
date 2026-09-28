from collections import Counter
from copy import deepcopy
from datetime import datetime
from itertools import islice
from pathlib import Path
import sys
import unittest
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.evaluation_cases import (iter_stage1_cases, iter_netslab_cases, coverage_report,
                                                make_case, seal_case, semantic_hash, RULES)
from oran_trust_boundary.evaluation_reference import ReferencePolicy
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.approval import StaticApprovalRegistry


class CaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = ReferencePolicy()
        cls.cases = list(iter_stage1_cases())

    def test_unique_ids_and_six_actions(self):
        self.assertEqual(len(self.cases), len({c["case_id"] for c in self.cases}))
        self.assertEqual(len({c["proposal"]["action"] for c in self.cases}), 6)

    def test_pairwise_and_targeted_threeway_coverage(self):
        coverage = coverage_report(self.cases)
        self.assertEqual(coverage["pairwise_missing"], [])
        self.assertTrue(coverage["targeted_three_way"])
        for value in coverage["targeted_three_way"].values():
            self.assertEqual(value["covered"], value["required"])

    def test_factor_labels_match_independent_reference(self):
        for case in self.cases:
            if "fault_factors" in case:
                self.assertEqual({RULES[f] for f in case["fault_factors"]}, set(case["expected_reference"]["violated_rules"]), case["case_id"])

    def test_constructed_suite_differential_decisions_and_reasons(self):
        for case in self.cases:
            engine = TrustBoundary(self.reference.operator_policy, StaticApprovalRegistry(case["approval_registry"]))
            result = engine.evaluate(case["proposal"], active_actions=case["active_actions"],
                                     authenticated_principal=case["authenticated_principal"],
                                     as_of=datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00")))
            self.assertEqual(result.decision.value, case["expected_decision"], case["case_id"])
            if case["expected_reference"]["reason_comparison"] == "exact_set":
                self.assertEqual(set(result.reason_codes), set(case["expected_reasons"]), case["case_id"])

    def test_one_seed_counts_and_unmasked_rules(self):
        cases = list(iter_netslab_cases([1000]))
        self.assertEqual(len(cases), 1000)
        self.assertEqual(Counter(c["category"] for c in cases), {"compliant": 200, "single_rule_violation": 400, "two_or_three_rule_violation": 400})
        self.assertEqual(Counter(c["source_context"]["kind"] for c in cases), {"dataset_label_context": 500, "standards_context": 500})
        for case in cases:
            self.assertEqual({RULES[f] for f in case["fault_factors"]}, set(case["expected_reference"]["violated_rules"]), case["case_id"])
            if case["category"] == "compliant":
                self.assertEqual(case["expected_decision"], "ALLOW")

    def test_seed_reproducibility_and_meaningful_change(self):
        a = list(islice(iter_netslab_cases([1000]), 10))
        b = list(islice(iter_netslab_cases([1000]), 10))
        c = list(islice(iter_netslab_cases([1001]), 10))
        self.assertEqual(a, b)
        self.assertNotEqual([x["semantic_sha256"] for x in a], [x["semantic_sha256"] for x in c])

    def test_semantic_normalization_retains_binding_tamper(self):
        a = make_case("isolate_xapp", "one")
        b = make_case("isolate_xapp", "two")
        self.assertEqual(semantic_hash(a), semantic_hash(b))
        a["approval_registry"][a["proposal"]["approval"]["approval_id"]]["proposal_sha256"] = "0" * 64
        self.assertNotEqual(semantic_hash(a), semantic_hash(b))

    def test_invalid_identifier_not_normalized_into_valid_case(self):
        a = make_case()
        b = deepcopy(a)
        b["proposal"]["incident_id"] = "   "
        self.assertNotEqual(semantic_hash(a), semantic_hash(b))

    def test_same_id_exemption_probe_really_has_matching_conflict_key(self):
        for case in self.cases:
            if case.get("probe") != "same_id_active":
                continue
            changed = deepcopy(case)
            changed["active_actions"][0]["action_id"] += "-now-distinct"
            self.assertEqual(case["expected_decision"], "ALLOW")
            self.assertEqual(self.reference.evaluate(changed)["decision"], "ESCALATE")

    def test_test_only_mutations_and_scoped_properties(self):
        spec = importlib.util.spec_from_file_location("validity_runner_test", ROOT / "scripts/run_validity_v02.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        mutations = runner.mutation_report(self.cases, self.reference.operator_policy)
        self.assertEqual(mutations["detected"], 14)
        self.assertEqual(mutations["survivors"], [])
        self.assertFalse(any(item["unhandled_errors"] for item in mutations["mutations"]))
        self.assertEqual(runner.property_report(self.reference.operator_policy)["failed"], 0)
        legacy = runner.legacy_reference_audit(self.reference)
        self.assertEqual(legacy["case_count"], 120)
        self.assertEqual(legacy["decision_disagreements"], 0)
        self.assertEqual(legacy["reason_disagreements"], 0)


if __name__ == "__main__":
    unittest.main()
