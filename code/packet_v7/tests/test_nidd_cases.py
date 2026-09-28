from __future__ import annotations

import math
import sys
import unittest
from copy import deepcopy
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.contract import parse_action
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.nidd_cases import EVALUATION_TIME, build_cases


def context(record_id="record-1", *, attack_type="SYNFlood", packets=2000, duration=1.0):
    return {
        "record_id": record_id,
        "source_row_number": 2,
        "attack_type": attack_type,
        "duration_seconds": duration,
        "total_packets": packets,
        "packets_per_second": packets / duration if duration else None,
    }


class NiddCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = TrustBoundary.from_file(ROOT / "configs" / "paper_policy.json")

    def evaluate(self, case):
        return self.engine.evaluate(
            case["proposal"], case["active_actions"],
            authenticated_principal=case["authenticated_principal"],
            as_of=datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00")),
        )

    def test_counts_unique_ids_and_contract_validity(self):
        contexts = [context(f"record-{index}", attack_type=label) for index, label in enumerate(
            ("ICMPFlood", "SYNFlood", "UDPFlood", "Benign")
        )]
        groups = build_cases(contexts)
        self.assertEqual({group: len(cases) for group, cases in groups.items()}, {
            "conformance": 19, "record_proposals": 4, "false_alarm_probes": 1,
        })
        all_cases = [case for cases in groups.values() for case in cases]
        self.assertEqual(len({case["case_id"] for case in all_cases}), len(all_cases))
        for case in all_cases:
            for proposal in [case["proposal"], *case["active_actions"]]:
                parsed, issues = parse_action(proposal)
                self.assertIsNotNone(parsed, (case["case_id"], issues))
                self.assertEqual(issues, ())
            self.assertEqual(case["evaluation_time"], EVALUATION_TIME)

    def test_unclipped_numeric_boundaries_and_conformance_clipping(self):
        for pps, reduction, decision in (
            (1, 1, "ALLOW"), (1000, 1, "ALLOW"), (2000, 50, "ALLOW"),
            (5000, 80, "ALLOW"), (5001, 81, "DENY"), (1000000, 100, "DENY"),
        ):
            with self.subTest(pps=pps):
                groups = build_cases([context(packets=pps)])
                record_case = groups["record_proposals"][0]
                self.assertEqual(record_case["proposal"]["parameters"]["reduction_percent"], reduction)
                self.assertEqual(record_case["expected_decision"], decision)
                self.assertEqual(self.evaluate(record_case).decision.value, decision)
                self.assertEqual(groups["conformance"][0]["proposal"]["parameters"]["reduction_percent"], min(80, reduction))

    def test_record_values_actually_change_proposal(self):
        first = build_cases([context(packets=2000)])["record_proposals"][0]
        second = build_cases([context(packets=4000)])["record_proposals"][0]
        self.assertNotEqual(first["proposal"]["parameters"], second["proposal"]["parameters"])

    def test_policy_matches_every_expected_decision_and_reason(self):
        for cases in build_cases([context(), context("benign-1", attack_type="Benign")]).values():
            for case in cases:
                result = self.evaluate(case)
                self.assertEqual(result.decision.value, case["expected_decision"], case["case_id"])
                self.assertIn(case["expected_reason"], result.reason_codes, case["case_id"])
                self.assertIn(case["policy_under_test"], result.policy_ids, case["case_id"])

    def test_benign_conformance_is_notification_only(self):
        groups = build_cases([context(attack_type="Benign", duration=0)])
        self.assertEqual(len(groups["conformance"]), 1)
        for group in ("conformance", "record_proposals"):
            case = groups[group][0]
            self.assertEqual(case["proposal"]["action"], "notify_operator")
            self.assertEqual(self.evaluate(case).decision.value, "ALLOW")

    def test_false_alarm_limitation_is_explicit_and_separate(self):
        groups = build_cases([context(attack_type="Benign")])
        case = groups["false_alarm_probes"][0]
        self.assertEqual(case["proposal"]["action"], "rate_limit_ue")
        self.assertEqual(case["proposal"]["parameters"]["reduction_percent"], 30)
        self.assertEqual(self.evaluate(case).decision.value, "ALLOW")
        self.assertEqual(case["expected_decision"], "ALLOW")
        self.assertIn("do not count", case["source_context"]["negative_control"])
        self.assertNotIn(case, groups["conformance"])
        self.assertNotIn(case, groups["record_proposals"])

    def test_observed_data_and_simulated_control_are_separate(self):
        source = context()
        for cases in build_cases([source]).values():
            for case in cases:
                self.assertEqual(case["source_context"]["observed"], source)
                fixture = case["source_context"]["simulated_control_fixture"]
                self.assertEqual(fixture["source_to_ue_identity_mapping"], "not_available_simulated_target_only")
                self.assertTrue(case["proposal"]["target"]["target_id"].startswith("simulated-"))
                self.assertNotIn("ue_id", case["source_context"]["observed"])
                self.assertEqual(case["base_record_id"], source["record_id"])

    def test_no_input_mutation_or_cross_case_aliasing(self):
        source = context()
        original = deepcopy(source)
        groups = build_cases([source])
        self.assertEqual(source, original)
        groups["conformance"][0]["source_context"]["observed"]["total_packets"] = 999
        groups["conformance"][0]["proposal"]["target"]["target_id"] = "modified"
        self.assertEqual(source, original)
        self.assertEqual(groups["conformance"][1]["source_context"]["observed"], original)
        self.assertEqual(groups["record_proposals"][0]["proposal"]["target"]["target_id"], "simulated-ue-01")

    def test_invalid_contexts_fail_closed(self):
        changes = (
            {"record_id": "192.0.2.1"}, {"record_id": ""}, {"source_row_number": True},
            {"source_row_number": 0}, {"attack_type": "TCPFlood"},
            {"total_packets": True}, {"total_packets": 1.5}, {"total_packets": -1},
            {"duration_seconds": True}, {"duration_seconds": -1},
            {"duration_seconds": math.inf}, {"packets_per_second": math.nan},
            {"packets_per_second": "2000"}, {"packets_per_second": 3000},
            {"packets_per_second": True}, {"source_ip": "192.0.2.1"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                build_cases([{**context(), **change}])
        for bad in ({}, [], None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_cases([bad])

    def test_attack_zero_rate_or_duration_is_rejected(self):
        for value in (context(packets=0), context(duration=0)):
            with self.assertRaises(ValueError):
                build_cases([value])

    def test_duplicate_ids_and_empty_contexts_rejected(self):
        with self.assertRaises(ValueError):
            build_cases([context(), context()])
        with self.assertRaises(ValueError):
            build_cases([])

    def test_repeated_generation_is_deterministic(self):
        contexts = [context(), context("benign", attack_type="Benign")]
        self.assertEqual(build_cases(contexts), build_cases(contexts))


if __name__ == "__main__":
    unittest.main()
