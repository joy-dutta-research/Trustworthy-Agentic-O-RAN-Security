"""Small qualification checks; never run a scientific performance workload."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import workstation_reproduce as reproduction
from oran_trust_boundary.evaluation_cases import make_case, seal_case, attach_expectation
from oran_trust_boundary.evaluation_reference import ReferencePolicy


def manifest_fixture():
    cases = [{"path": "data/workstation_reproduction/common_validity.jsonl", "sha256": "a" * 64,
              "count": 777, "group": "common_validity", "seed": None},
             {"path": "data/workstation_reproduction/netslab.jsonl", "sha256": "b" * 64,
              "count": 20000, "group": "netslab", "seed": None}]
    for seed in range(20):
        for group, count in (("5gnidd_conformance", 4750), ("5gnidd_false_alarm_probes", 250)):
            cases.append({"path": f"data/workstation_reproduction/{group}_{seed}.jsonl", "sha256": "c" * 64,
                          "count": count, "group": group, "seed": seed})
    return {"schema_version": "workstation-reproduction-inputs/v1", "cases": cases,
            "workloads_directory": "data/workstation_reproduction/workloads",
            "design_path": "configs/evaluation_v0.2/study_design.json",
            "pilot_design_path": "data/workstation_reproduction/pilot_design.json",
            "freeze_spec_path": "configs/workstation_reproduction_freeze.json"}


class WorkstationReproductionTests(unittest.TestCase):
    def test_full_manifest_counts_and_seeds(self):
        value = manifest_fixture()
        self.assertIs(reproduction.validate_manifest(value), value)
        self.assertEqual(sum(row["count"] for row in value["cases"]), 120777)

    def test_partial_duplicate_wrong_seed_or_count_refused(self):
        mutations = []
        value = manifest_fixture(); value["cases"].pop(); mutations.append(value)
        value = manifest_fixture(); value["cases"][0]["path"] = value["cases"][1]["path"]; mutations.append(value)
        value = manifest_fixture(); value["cases"][2]["seed"] = 19; mutations.append(value)
        value = manifest_fixture(); value["cases"][2]["count"] += 1; mutations.append(value)
        value = manifest_fixture(); value["cases"][2]["sha256"] = "not-a-digest"; mutations.append(value)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                reproduction.validate_manifest(value)

    def test_traversal_and_absolute_paths_refused(self):
        for path in ("../secret.jsonl", "C:/secret.jsonl", "/secret", "data/../secret"):
            value = manifest_fixture()
            value["cases"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                reproduction.validate_manifest(value)

    def test_plan_preserves_full_original_comparison_cells(self):
        plan = reproduction.performance_plan(manifest_fixture())
        self.assertEqual(len(plan), 24)
        self.assertEqual(len({row["id"] for row in plan}), 24)
        self.assertEqual(sum(row["expected_cells"] for row in plan if not row["pilot"]), 1820)
        self.assertEqual(sum(row["expected_cells"] for row in plan if row["pilot"]), 84)
        self.assertTrue(all(row["pilot"] for row in plan[:6]))
        self.assertFalse(any("--block-stop" in row["arguments"] for row in plan))
        self.assertFalse(any("--output" in row["arguments"] for row in plan))

    def test_default_command_only_plans(self):
        with patch.object(reproduction, "verified_inputs", return_value=manifest_fixture()), \
                patch.object(reproduction, "run_campaign") as execute, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(reproduction.main([]), 0)
            execute.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["status"], "PLAN_ONLY_NOT_RUN")

    def test_performance_requires_quiet_host_before_filesystem_work(self):
        with patch.object(reproduction.os, "name", "nt"), \
                patch.object(reproduction, "verified_inputs") as verify:
            with self.assertRaisesRegex(ValueError, "quiet-host"):
                reproduction.run_campaign("irrelevant.json", "performance", False)
            verify.assert_not_called()

    def test_replay_small_valid_case_and_intentional_false_alarm_allow(self):
        reference = ReferencePolicy()
        case = attach_expectation(seal_case(make_case("rate_limit_ue", "replay-test")))
        with tempfile.TemporaryDirectory(prefix="oran-stage7-test-") as temp:
            path = Path(temp) / "cases.jsonl"
            path.write_text(json.dumps(case) + "\n", encoding="utf-8")
            output = io.StringIO()
            result = reproduction.replay_file(path, {"count": 1, "group": "5gnidd_false_alarm_probes", "seed": 0},
                                             reference.operator_policy, reference, output)
            self.assertEqual(result["counts"]["cases"], 1)
            self.assertEqual(sum(result["findings"].values()), 0)
            self.assertEqual(json.loads(output.getvalue())["results"]["trust_boundary"]["decision"], "ALLOW")
            self.assertTrue(json.loads(output.getvalue())["results"]["trust_boundary"]["audit_checksum_verified"])

    def test_replay_wrong_frozen_label_is_a_finding_not_repaired(self):
        reference = ReferencePolicy()
        case = attach_expectation(seal_case(make_case("rate_limit_ue", "replay-wrong-expectation")))
        case["expected_decision"] = "DENY"
        with tempfile.TemporaryDirectory(prefix="oran-stage7-test-") as temp:
            path = Path(temp) / "cases.jsonl"
            path.write_text(json.dumps(case) + "\n", encoding="utf-8")
            result = reproduction.replay_file(path, {"count": 1, "group": "common_validity", "seed": None},
                                             reference.operator_policy, reference, io.StringIO())
            self.assertEqual(result["findings"]["gateway_decision"], 1)
            self.assertEqual(result["findings"]["reference_vs_frozen_decision"], 1)
            self.assertEqual(case["expected_decision"], "DENY")

    def test_replay_duplicate_and_count_mismatch_are_technical_failures(self):
        reference = ReferencePolicy()
        case = attach_expectation(seal_case(make_case("rate_limit_ue", "replay-duplicate")))
        with tempfile.TemporaryDirectory(prefix="oran-stage7-test-") as temp:
            path = Path(temp) / "cases.jsonl"
            for lines, count in (([case, case], 2), ([case], 2)):
                path.write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
                with self.assertRaises(ValueError):
                    reproduction.replay_file(path, {"count": count, "group": "common_validity", "seed": None},
                                             reference.operator_policy, reference, io.StringIO())

    def test_session_parent_and_exclusive_receipts(self):
        with tempfile.TemporaryDirectory(prefix="oran-stage7-test-") as temp:
            parent = reproduction.session_parent(Path(temp))
            self.assertTrue(parent.is_dir())
            receipt = parent / "one.json"
            reproduction.write_new(receipt, {"one": 1})
            with self.assertRaises(FileExistsError):
                reproduction.write_new(receipt, {"two": 2})

    def test_partition_cell_count_and_findings_checked(self):
        with tempfile.TemporaryDirectory(prefix="oran-stage7-test-") as temp:
            root = Path(temp)
            directory = root / "partition"
            (directory / "work").mkdir(parents=True)
            parent = {"status": "COMPLETE", "source_unchanged": True, "baseline_after": {"status": "pass"}}
            reproduction.write_new(directory / "COMPLETE.json", parent)
            reproduction.write_new(directory / "work/COMPLETE.json", {"status": "complete"})
            summary = {"status": "complete", "planned_cells": 2, "cell_summaries": [{"status": "complete"}] * 2}
            reproduction.write_new(directory / "work/summary.json", summary)
            with patch.object(reproduction, "ROOT", root):
                self.assertEqual(reproduction.completed_partition(directory, 2)["cells"], 2)
                with self.assertRaises(RuntimeError):
                    reproduction.completed_partition(directory, 3)
                (directory / "work/summary.json").write_text(json.dumps({**summary, "status": "completed_with_reference_disagreement"}))
                with self.assertRaises(RuntimeError):
                    reproduction.completed_partition(directory, 2)


if __name__ == "__main__":
    unittest.main()
