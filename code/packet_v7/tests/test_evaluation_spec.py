"""Stage-0 specification consistency checks; no gateway decisions are evaluated."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(relative: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"non-finite constant: {value}")

    return json.loads((ROOT / relative).read_text(encoding="utf-8"),
                      object_pairs_hook=unique, parse_constant=reject_constant)


class EvaluationSpecificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_json("configs/paper_policy.json")
        cls.reference = load_json("configs/evaluation_v0.2/reference_policy_v0.1.json")
        cls.design = load_json("configs/evaluation_v0.2/study_design.json")

    def test_reference_pins_original_policy_bytes(self):
        digest = hashlib.sha256((ROOT / self.reference["policy_file"]).read_bytes()).hexdigest()
        self.assertEqual(digest, self.reference["policy_sha256"])
        self.assertEqual(self.design["policy_version"], self.policy["policy_version"])
        self.assertIs(self.design["policy_change_authorized"], False)

    def test_all_six_actions_match_declared_policy(self):
        self.assertEqual(len(self.reference["actions"]), 6)
        self.assertEqual(set(self.reference["actions"]), set(self.policy["action_targets"]))
        for name, row in self.reference["actions"].items():
            with self.subTest(action=name):
                self.assertEqual([row["target_type"]], self.policy["action_targets"][name])
                self.assertEqual([row["interface"]], [key for key, values in self.policy["interface_actions"].items() if name in values])
                self.assertEqual(set(row["authorized_roles"]), {key for key, values in self.policy["roles"].items() if name in values})
                self.assertEqual(row["minimum_risk"], self.policy["minimum_risk_by_action"][name])
                self.assertEqual(row["disruptive"], name in self.policy["disruptive_actions"])
                self.assertEqual(row["action_requires_approval"], name in self.policy["approval_required_actions"])
                contract = self.policy["action_parameter_contracts"][name]
                self.assertEqual(row["control_parameter"], contract["control_parameter"])
                self.assertEqual(set(row["required_fields"]), set(contract["required_fields"]))
                actual = {field: [bound["minimum"], bound["maximum"]] for field, bound in self.policy["parameter_bounds"].get(name, {}).items()}
                self.assertEqual(row["numeric_bounds"], actual)

    def test_temporal_bounds_and_precedence_are_explicit(self):
        times = self.reference["time_boundaries"]
        for reference_name, policy_name in [
            ("maximum_proposal_age_seconds", "max_proposal_age_seconds"),
            ("maximum_future_skew_seconds", "max_clock_skew_seconds"),
            ("maximum_ttl_seconds", "max_ttl_seconds"),
        ]:
            self.assertEqual(times[reference_name], self.policy[policy_name])
        self.assertTrue(times["elapsed_age_equals_ttl_is_valid"])
        self.assertFalse(times["approval_expiry_equals_evaluation_is_valid"])
        self.assertEqual(self.reference["decision_precedence"], ["DENY", "ESCALATE", "ALLOW"])

    def test_rule_and_limitation_ids_are_unique(self):
        self.assertEqual([r["id"] for r in self.reference["rules"]], [f"R{i:02d}" for i in range(1, 15)])
        limitations = [item["id"] for item in self.reference["known_limitations"]]
        self.assertEqual(len(limitations), len(set(limitations)))
        self.assertIn("L03", limitations)
        self.assertIn("L07", limitations)
        self.assertFalse(self.reference["actions"]["rollback_policy"]["disruptive"])
        self.assertEqual(self.reference["author_table_verification"], "pending_before_publication")

    def test_seed_domains_do_not_overlap(self):
        seen = set()
        for name, values in self.design["seeds"].items():
            with self.subTest(domain=name):
                self.assertTrue(all(type(value) is int for value in values))
                self.assertEqual(len(values), len(set(values)))
                self.assertFalse(seen.intersection(values))
                seen.update(values)
        self.assertEqual(self.design["seeds"]["source_selection"], list(range(20)))

    def test_5gnidd_counts_and_panel_arithmetic(self):
        item = self.design["5gnidd"]
        counts = item["expected_eligible_unique_counts"]
        self.assertEqual(sum(counts.values()), 733693)
        self.assertEqual(4 * sum(counts.values()), 2934772)
        self.assertLessEqual(max(item["sample_sizes_per_label"]), min(counts.values()))
        panel = max(item["sample_sizes_per_label"])
        self.assertEqual(item["controlled_conformance_proposals_per_seed"], 3 * panel * 6 + panel)
        self.assertEqual(item["false_alarm_proposals_per_seed"], panel)

    def test_netslab_generated_case_arithmetic(self):
        item = self.design["netslab"]
        bases = item["dataset_context_bases"] + item["standards_context_bases"]
        variants = sum(item["variants_per_base_per_seed"].values())
        seeds = len(self.design["seeds"]["control_generation"])
        self.assertEqual(bases * variants * seeds, item["generated_proposals_total"])
        self.assertEqual(item["source_mode"], "exhaustive_aggregate_context_not_row_sampling")

    def test_measurement_budgets_and_pending_freezes_are_honest(self):
        self.assertEqual(self.design["performance"]["process_blocks"], len(self.design["seeds"]["timing_order"]))
        self.assertEqual(self.design["state_scaling"]["process_runs_per_cell"], len(self.design["seeds"]["state_scaling_order"]))
        self.assertEqual(self.design["offered_load"]["process_runs_per_cell"], len(self.design["seeds"]["arrival_schedule_order"]))
        self.assertEqual(self.design["offered_load"]["latency_origin"], "scheduled_arrival")
        self.assertEqual(self.design["vm"]["status"], "NOT_RUN")
        self.assertIn("MUST_BE_SPECIFIED", self.design["performance"]["workload_mix_status"])
        limits = self.design["technical_resource_limits"]
        self.assertGreater(limits["minimum_free_disk_bytes_before_large_runs"], limits["maximum_new_output_bytes_per_run"])


if __name__ == "__main__":
    unittest.main()
