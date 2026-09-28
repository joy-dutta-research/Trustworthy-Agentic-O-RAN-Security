"""Compact second-host adapter fixtures; no performance workloads."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import summarize_workstation_reproduction as summary
from test_workstation_reproduce import manifest_fixture


class WorkstationSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oran-workstation-summary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def put(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        return target

    def fixture_session(self, phase="performance"):
        session = self.root / "results/local/workstation_runs/20260101T000000Z_1234abcd"
        manifest = manifest_fixture()
        manifest_path = self.put("data/workstation_reproduction/manifest.json", manifest)
        plan = {"phase": phase, "manifest_path": "data/workstation_reproduction/manifest.json",
                "manifest_sha256": summary.reproduction.digest(manifest_path), "performance": summary.reproduction.performance_plan(manifest),
                "environment": {"processor": "fixture"}, "quiet_host_confirmed_by_operator": True}
        complete = {"status": "COMPLETE", "failure": None, "phase": phase, "source_unchanged": True,
                    "baseline_after": {"status": "pass"}, "partitions": []}
        relative = session.relative_to(self.root).as_posix()
        self.put(relative + "/PLAN.json", plan)
        self.put(relative + "/SOURCE_BEFORE.json", {"file": "a" * 64})
        self.put(relative + "/SOURCE_AFTER.json", {"file": "a" * 64})
        for index, item in enumerate(plan["performance"]):
            path = "results/evaluation_v0.2/s7_1234abcd_" + item["id"] + "_20260101T000000Z_8765abcd"
            parent = self.put(path + "/COMPLETE.json", {"status": "COMPLETE", "failure": None,
                "source_unchanged": True, "runner_exit_code": 0, "baseline_after": {"status": "pass"}})
            self.put(path + "/SOURCE_BEFORE.json", {"file": "b" * 64})
            self.put(path + "/SOURCE_AFTER.json", {"file": "b" * 64})
            self.put(path + "/work/COMPLETE.json", {"status": "complete"})
            work = self.put(path + "/work/summary.json", {"status": "complete", "completed_cells": item["expected_cells"],
                "planned_cells": item["expected_cells"], "scientific_scope": "PILOT_NOT_CONFIRMATORY" if item["pilot"] else "PREDECLARED_EVALUATION_PARTITION"})
            row = {"id": item["id"], "pilot": item["pilot"], "path": path, "cells": item["expected_cells"],
                   "runner_exit_code": 0, "summary_sha256": summary.reproduction.digest(work),
                   "supervisor_receipt_sha256": summary.reproduction.digest(parent)}
            complete["partitions"].append(row)
            self.put(relative + f"/PARTITION_{index:02d}.json", row)
        self.put(relative + "/COMPLETE.json", complete)
        return session, plan, complete

    @staticmethod
    def mock_partition(reader, directory, key):
        return {"partition": list(key), "run": directory.name, "summary": {}, "cells": [],
                "source_snapshot_sha256": "c" * 64,
                "plan_metadata": {"output_monitor_version": "fixture", "design_sha256": "d" * 64,
                                  "workload_manifest_sha256": "e" * 64}}

    def test_identifier_mapping_and_full_partition_set(self):
        plan = summary.reproduction.performance_plan(manifest_fixture())
        keys = [summary.partition_key(row) for row in plan if not row["pilot"]]
        summary.require_complete_keys(keys)
        self.assertEqual(len(keys), 18)
        self.assertIn(("micro", "netslab", None), keys)
        self.assertIn(("scaling", "5gnidd", 1000), keys)
        for invalid in (keys[:-1], keys[:-1] + [keys[0]]):
            with self.assertRaises(ValueError):
                summary.require_complete_keys(invalid)
        with self.assertRaises(ValueError):
            summary.partition_key(plan[0])

    def test_complete_explicit_selection_excludes_pilots(self):
        session, _, _ = self.fixture_session()
        with patch.object(summary.analysis, "performance_partition", side_effect=self.mock_partition) as adapter:
            result = summary.collect_performance(summary.analysis.Reader(self.root), self.root, session)
        self.assertEqual(adapter.call_count, 18)
        self.assertEqual(result["final_cells"], 1820)
        self.assertEqual(len(result["excluded_instrumentation_pilots"]), 6)
        self.assertEqual(result["environment"], {"processor": "fixture"})

    def test_changed_index_hash_is_refused(self):
        session, _, complete = self.fixture_session()
        path = complete["partitions"][6]["path"]
        self.put(path + "/work/summary.json", {"changed": True})
        with patch.object(summary.analysis, "performance_partition", side_effect=self.mock_partition), self.assertRaisesRegex(ValueError, "hash differs"):
            summary.collect_performance(summary.analysis.Reader(self.root), self.root, session)

    def test_missing_partitions_and_incomplete_session_refused(self):
        session, _, complete = self.fixture_session()
        relative = session.relative_to(self.root).as_posix()
        self.put(relative + "/COMPLETE.json", {**complete, "partitions": complete["partitions"][:-1]})
        with self.assertRaisesRegex(ValueError, "full frozen"):
            summary.collect_performance(summary.analysis.Reader(self.root), self.root, session)
        self.put(relative + "/COMPLETE.json", {**complete, "status": "INCOMPLETE"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            summary.collect_performance(summary.analysis.Reader(self.root), self.root, session)

    def test_mixed_source_inventory_refused(self):
        session, _, _ = self.fixture_session()
        def mixed(reader, directory, key):
            value = self.mock_partition(reader, directory, key)
            value["source_snapshot_sha256"] = ("a" if key[1] == "netslab" else "b") * 64
            return value
        with patch.object(summary.analysis, "performance_partition", side_effect=mixed), self.assertRaises(ValueError):
            summary.collect_performance(summary.analysis.Reader(self.root), self.root, session)

    def test_explicit_session_scope_and_traversal_refused(self):
        session, _, _ = self.fixture_session()
        self.assertEqual(summary.session_path(self.root, session.relative_to(self.root).as_posix()), session)
        for path in ("../outside", "C:/outside", "results/evaluation_v0.2"):
            with self.assertRaises((ValueError, OSError)):
                summary.session_path(self.root, path)

    def test_replay_requires_exact_files_and_records_raw_hash_without_reread(self):
        session, _, _ = self.fixture_session(phase="all")
        relative = session.relative_to(self.root).as_posix()
        manifest = manifest_fixture()
        value = {"status": "PASS", "case_count": 120777, "files": [
            {"input": row, "counts": {"cases": row["count"]}, "findings": {"gateway_decision": 0}}
            for row in manifest["cases"]]}
        path = self.put(relative + "/replay/summary.json", value)
        self.put(relative + "/replay/COMPLETE.json", {"status": "PASS", "files": {
            "summary.json": summary.reproduction.digest(path), "decisions.jsonl": "f" * 64}})
        self.put(relative + "/replay/SUPERVISION.json", {"status": "COMPLETE", "failure": None})
        result = summary.collect_replay(summary.analysis.Reader(self.root), self.root, session)
        self.assertEqual(result["recorded_decisions_sha256_not_recomputed"], "f" * 64)
        self.assertFalse((session / "replay/decisions.jsonl").exists())
        value["case_count"] = 1
        path = self.put(relative + "/replay/summary.json", value)
        self.put(relative + "/replay/COMPLETE.json", {"status": "PASS", "files": {
            "summary.json": summary.reproduction.digest(path), "decisions.jsonl": "f" * 64}})
        with self.assertRaisesRegex(ValueError, "coverage"):
            summary.collect_replay(summary.analysis.Reader(self.root), self.root, session)

    def test_original_host_capsule_hash_is_verified(self):
        path = self.put("reference/university/final_verified/analysis.json", {
            "status": "COMPLETE_WITH_REPORTED_FINDINGS", "performance": {"old_host": True}})
        self.put("reference/university/CAPSULE_MANIFEST.json", {"files": [{"path": "final_verified/analysis.json",
            "sha256": summary.reproduction.digest(path)}]})
        self.put("reference/university/host_context.json", {"processor": "old"})
        result = summary.original_host(summary.analysis.Reader(self.root), self.root)
        self.assertEqual(result["performance"], {"old_host": True})
        self.put("reference/university/final_verified/analysis.json", {"changed": True})
        with self.assertRaises(ValueError):
            summary.original_host(summary.analysis.Reader(self.root), self.root)

    def test_failed_analysis_retains_not_complete_report_and_no_overwrite(self):
        session, _, complete = self.fixture_session()
        relative = session.relative_to(self.root).as_posix()
        self.put(relative + "/COMPLETE.json", {**complete, "status": "INCOMPLETE"})
        output = "results/local/workstation_runs/comparison_fixture"
        result = summary.summarize(self.root, relative, None, output)
        self.assertEqual(result["status"], "NOT_COMPLETE")
        self.assertTrue((self.root / output / "STATUS.json").exists())
        self.assertFalse(result["host_observations_pooled"])
        self.assertIn("not reread", result["verification_scope"])
        with self.assertRaises(ValueError):
            summary.summarize(self.root, relative, None, output)

    def test_full_campaign_all_19_fixed_roles_and_counts(self):
        session = self.root / "results/local/full_campaign_runs/20260101T000000Z_1234abcd"
        relative = session.relative_to(self.root).as_posix()
        manifest_path = self.put("data/workstation_reproduction/manifest.json", manifest_fixture())
        raw_path = self.put("data/raw/Lower_Layer_Data.db", {"fixture": 1})
        pins = {"data/raw/Lower_Layer_Data.db": {"size_bytes": raw_path.stat().st_size,
                "sha256": summary.reproduction.digest(raw_path)}}
        expected = summary.campaign.planned_partitions()
        plan = {"schema_version": "full-workstation-campaign/v1", "phase": "orders0_3_and_workload_preparation",
                "partitions": expected, "reproduction_manifest": "data/workstation_reproduction/manifest.json",
                "reproduction_manifest_sha256": summary.reproduction.digest(manifest_path), "environment": {"fixture": True},
                "raw_inputs": {name: {"status": "VERIFIED", **row} for name, row in pins.items()}}
        complete = {"status": "COMPLETE", "failure": None, "phase": plan["phase"], "source_unchanged": True,
            "baseline_after": {"status": "pass"}, "performance_ready": True, "expected_partitions": 19,
            "completed_partitions": 19, "partitions": [], "case_comparison": "CASE_REGENERATION_COMPARISON.json",
            "workload_comparison": "WORKLOAD_COMPARISON.json"}
        self.put(relative + "/PLAN.json", plan)
        self.put(relative + "/SOURCE_BEFORE.json", {})
        self.put(relative + "/SOURCE_AFTER.json", {})
        outputs, science = {}, {}
        for index, item in enumerate(expected):
            path = "results/evaluation_v0.2/full_1234abcd_" + item["id"] + "_20260101T000000Z_8765abcd"
            parent = self.put(path + "/COMPLETE.json", {"status": "COMPLETE", "failure": None,
                "source_unchanged": True, "runner_exit_code": 0, "baseline_after": {"status": "pass"}})
            self.put(path + "/SOURCE_BEFORE.json", {})
            self.put(path + "/SOURCE_AFTER.json", {})
            prepare = item["id"] == "stage4_prepare"
            filename = "manifest.json" if prepare else "summary.json"
            child_name = "COMPLETE.json" if prepare or item["script"] == "scripts/run_validity_v02.py" else "RUN.json"
            value = {"status": "PREPARED_NOT_MEASURED" if prepare else "PILOT_NOT_CONFIRMATORY" if item["pilot"] else "COMPLETED",
                     "constructed_case_count": item["cases"], "instrumentation_records": item["cases"],
                     "groups": {"fixture": {"overall": {"trust_boundary": {"cases": item["cases"]}}}}}
            receipt = {"output_sha256": {}}
            if item["id"] == "stage2_nidd_census":
                for extra in ("dataset_audit.json", "natural_panel_analysis.json", "sampling_protocol.json"):
                    extra_path = self.put(path + "/work/" + extra, {"overlap_by_label_and_size": {}, "eligible_release_poststratified_min_max_across_seeds": {}, "note": "fixture"})
                    receipt["output_sha256"][extra] = summary.reproduction.digest(extra_path)
            work = self.put(path + "/work/" + filename, value)
            child = self.put(path + "/work/" + child_name, receipt)
            row = {**item, "arguments": summary.campaign.resolve_arguments(item["arguments"], outputs),
                "path": path, "runner_exit_code": 0, "validation_error": None, "summary_file": filename,
                "summary_sha256": summary.reproduction.digest(work), "child_receipt_sha256": summary.reproduction.digest(child),
                "supervisor_receipt_sha256": summary.reproduction.digest(parent)}
            complete["partitions"].append(row)
            self.put(relative + f"/PARTITION_{index:02d}.json", row)
            outputs[item["id"]] = path + "/work"
            science[path] = (value, receipt)
        self.put(relative + "/COMPLETE.json", complete)
        with patch.object(summary.campaign, "RAW_INPUTS", pins), \
                patch.object(summary.analysis, "verify_child_summary", side_effect=lambda reader, directory, kind: science[directory.relative_to(self.root).as_posix()]) as child_check, \
                patch.object(summary, "verify_regeneration", return_value={"fixture": True}) as regeneration:
            result = summary.collect_full_campaign(summary.analysis.Reader(self.root), self.root, relative)
            self.assertEqual(child_check.call_count, 16)
            self.assertEqual(len(result["excluded_pilots"]), 2)
            self.assertEqual(len(result["sensitivity"]), 12)
            self.assertIn("RERUN_AND_RECONCILED", result["raw_dataset_census"])
            regeneration.assert_called_once()
        self.put(relative + "/COMPLETE.json", {**complete, "completed_partitions": 18})
        with self.assertRaisesRegex(ValueError, "19-partition"):
            summary.collect_full_campaign(summary.analysis.Reader(self.root), self.root, relative)

    def test_verified_full_regeneration_allows_omitting_optional_replay(self):
        session, _, _ = self.fixture_session()
        relative = session.relative_to(self.root).as_posix()
        with patch.object(summary, "collect_performance", return_value={"shared_source_sha256": "a" * 64}), \
                patch.object(summary, "collect_full_campaign", return_value={"shared_source_sha256": "a" * 64, "raw_dataset_census": "RERUN_AND_RECONCILED_733693_ELIGIBLE_RECORDS"}), \
                patch.object(summary, "collect_replay") as replay, \
                patch.object(summary, "original_host", return_value={}):
            result = summary.summarize(self.root, relative, None, "results/local/workstation_runs/full_comparison_fixture", "full_fixture")
        replay.assert_not_called()
        self.assertEqual(result["status"], "COMPLETE_COMPACT_VALIDATION")
        self.assertEqual(result["replay"]["status"], "NOT_RUN_NOT_REQUIRED_FULL_REGENERATION")
        self.assertIn("RERUN_AND_RECONCILED", result["raw_dataset_census"])

    def test_regeneration_comparison_refuses_missing_files(self):
        session = self.root / "full"
        self.put("full/CASE_REGENERATION_COMPARISON.json", {"status": "MATCH", "file_count": 41, "case_count": 120777, "files": []})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            summary.verify_regeneration(summary.analysis.Reader(self.root), self.root, session, manifest_fixture(), {})


if __name__ == "__main__":
    unittest.main()
