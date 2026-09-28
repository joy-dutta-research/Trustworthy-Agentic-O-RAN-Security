"""Small deterministic handoff tests; no corpus regeneration or benchmarks."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import workstation_campaign as campaign


class WorkstationCampaignTests(unittest.TestCase):
    def test_fixed_complete_order_and_no_timing_commands(self):
        rows = campaign.planned_partitions()
        self.assertEqual(len(rows), 19)
        self.assertEqual(len({row["id"] for row in rows}), 19)
        self.assertEqual([r["id"] for r in rows if r["pilot"]], ["pilot_validity", "pilot_nidd_census"])
        self.assertEqual(sum(r["id"].startswith("stage3_") for r in rows), 12)
        self.assertEqual(rows[-1]["id"], "stage4_prepare")
        self.assertEqual([r["cases"] for r in rows[:6]], [50, 777, 20000, 1000, 733693, 100000])
        self.assertTrue(all(r["script"] in campaign.supervisor.APPROVED for r in rows))
        self.assertFalse(any("--output" in r["arguments"] for r in rows))
        self.assertFalse(any(r["arguments"][0] in {"micro", "scaling", "load"} for r in rows))

    def test_upstream_resolution_requires_completed_identifier(self):
        self.assertEqual(campaign.resolve_arguments(["--input", "@census/panels.json"],
            {"census": "results/evaluation_v0.2/example/work"}),
            ["--input", "results/evaluation_v0.2/example/work/panels.json"])
        with self.assertRaises(ValueError):
            campaign.resolve_arguments(["@absent"], {})
        with self.assertRaises(ValueError):
            campaign.resolve_arguments(["@census/../secret"], {"census": "results/test"})

    def test_raw_missing_plan_allowed_execution_refused_and_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-plan-") as folder:
            root = Path(folder)
            payload = b"small fixture"
            relative = "data/raw/fixture.bin"
            pin = {relative: {"size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}
            with patch.object(campaign, "RAW_INPUTS", pin):
                self.assertEqual(campaign.raw_inventory(root, require=False)[relative]["status"], "MISSING")
                with self.assertRaises(ValueError):
                    campaign.raw_inventory(root, require=True)
                target = root / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(payload)
                self.assertEqual(campaign.raw_inventory(root, require=True)[relative]["status"], "VERIFIED")
                target.write_bytes(b"modified")
                with self.assertRaises(ValueError):
                    campaign.raw_inventory(root, require=False)

    def test_default_plan_never_calls_execute(self):
        minimal = {"cases": [{"count": 3}]}
        with patch.object(campaign, "verify_full_inputs", return_value=(minimal, {})), \
             patch.object(campaign, "run_campaign") as run, patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(campaign.main([]), 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "PLAN_ONLY_NOT_RUN")
            run.assert_not_called()

    def test_non_windows_refuses_without_creating_outputs(self):
        with patch.object(campaign, "os", SimpleNamespace(name="posix")), \
             patch.object(campaign, "new_session_parent") as create:
            with self.assertRaises(RuntimeError):
                campaign.run_campaign()
            create.assert_not_called()

    def test_artifact_receipt_rejects_tamper_and_traversal(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-receipt-") as folder:
            root = Path(folder)
            (root / "small.json").write_text("{}", encoding="utf-8")
            sha = campaign.digest(root / "small.json")
            campaign.verify_artifact_hashes(root, {"small.json": sha})
            with self.assertRaises(ValueError):
                campaign.verify_artifact_hashes(root, {"small.json": "0" * 64})
            with self.assertRaises(ValueError):
                campaign.verify_artifact_hashes(root, {"../small.json": sha})

    def test_aggregate_never_overwrites_original_and_retains_difference(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-aggregate-") as folder:
            root = Path(folder)
            original = root / campaign.AGGREGATE
            original.parent.mkdir(parents=True)
            value = {"dataset": {"total_row_count": 45244}, "manifest_sha256": "a" * 64}
            original.write_text(json.dumps(value), encoding="utf-8")
            before = original.read_bytes()
            session = root / "session"
            session.mkdir()
            different = {**value, "manifest_sha256": "b" * 64}
            with patch.object(campaign, "build_context_manifest", return_value=different):
                with self.assertRaises(RuntimeError):
                    campaign.regenerate_aggregate(root, session)
            self.assertEqual(original.read_bytes(), before)
            self.assertEqual(json.loads((session / "AGGREGATE_COMPARISON.json").read_text())["status"], "DIFFERENT")
            self.assertTrue((session / "regenerated_netslab_contexts.json").is_file())

    def test_workload_mismatch_records_both_and_refuses_timing_ready(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-workloads-") as folder:
            root = Path(folder)
            original, regenerated, session = (root / name for name in ("original", "prepared", "session"))
            for path in (original, regenerated, session):
                path.mkdir()
            for dataset in ("netslab", "5gnidd"):
                (original / f"{dataset}_workload.jsonl").write_text("original\n")
                (regenerated / f"{dataset}_workload.jsonl").write_text("changed\n" if dataset == "netslab" else "original\n")
            with self.assertRaises(RuntimeError):
                campaign.compare_workloads(root, session, {"workloads_directory": "original"}, {"stage4_prepare": "prepared"})
            result = json.loads((session / "WORKLOAD_COMPARISON.json").read_text())
            self.assertEqual(result["status"], "DIFFERENT")
            self.assertEqual([row["match"] for row in result["datasets"]], [False, True])

    def test_case_mismatch_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-cases-") as folder:
            root = Path(folder)
            (root / "regenerated").mkdir()
            (root / "regenerated/cases.jsonl").write_text("changed\n")
            (root / "session").mkdir()
            manifest = {"cases": [{"group": "common_validity", "seed": None, "count": 777,
                                    "path": "original.jsonl", "sha256": "0" * 64}]}
            with self.assertRaises(RuntimeError):
                campaign.compare_regenerated_cases(root, root / "session", manifest, {"stage1_validity": "regenerated"})
            result = json.loads((root / "session/CASE_REGENERATION_COMPARISON.json").read_text())
            self.assertEqual(result["status"], "DIFFERENT")

    def test_reference_findings_are_not_completion_even_when_child_exits_successfully(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-findings-") as folder:
            root = Path(folder)
            item = campaign.planned_partitions()[1]
            (root / "COMPLETE.json").write_text(json.dumps({"status": "COMPLETED_WITH_FINDINGS"}))
            (root / "summary.json").write_text(json.dumps({"status": "COMPLETED_WITH_FINDINGS"}))
            with self.assertRaises(RuntimeError):
                campaign.verify_child_summary(item, root)

    def test_partition_failure_has_index_and_no_success_output(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-partition-") as folder:
            root = Path(folder)
            (root / "session").mkdir()
            outputs = {}
            with patch.object(campaign.supervisor, "supervise", side_effect=RuntimeError("fixture guard failure")):
                with self.assertRaises(RuntimeError):
                    campaign.run_partition(root, root / "session", "abcd1234", 0,
                        campaign.planned_partitions()[0], outputs, root / "baseline")
            self.assertEqual(outputs, {})
            record = json.loads((root / "session/PARTITION_00.json").read_text())
            self.assertIn("guard failure", record["validation_error"])
            self.assertIsNone(record["runner_exit_code"])

    def test_failed_campaign_stops_and_preserves_incomplete_receipt(self):
        with tempfile.TemporaryDirectory(prefix="oran-full-campaign-") as folder, ExitStack() as stack:
            root = Path(folder)
            stack.enter_context(patch.object(campaign, "ROOT", root))
            stack.enter_context(patch.object(campaign, "os", SimpleNamespace(name="nt")))
            stack.enter_context(patch.object(campaign, "verify_full_inputs", return_value=({"cases": []}, {})))
            stack.enter_context(patch.object(campaign.shutil, "disk_usage", return_value=SimpleNamespace(free=20 * 1024**3)))
            stack.enter_context(patch.object(campaign.supervisor, "source_snapshot", return_value={"fixture": True}))
            stack.enter_context(patch.object(campaign.freeze, "freeze_baseline", return_value=root / "results/evaluation_v0.2/stage0_fixture"))
            stack.enter_context(patch.object(campaign.freeze, "verify_baseline", return_value={"status": "pass"}))
            stack.enter_context(patch.object(campaign, "digest", return_value="0" * 64))
            stack.enter_context(patch.object(campaign.reproduction, "environment", return_value={}))
            stack.enter_context(patch.object(campaign, "regenerate_aggregate"))
            runner = stack.enter_context(patch.object(campaign, "run_partition", side_effect=RuntimeError("bounded fixture failure")))
            compare = stack.enter_context(patch.object(campaign, "compare_workloads"))
            stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
            self.assertEqual(campaign.run_campaign(), 1)
            self.assertEqual(runner.call_count, 1)
            compare.assert_not_called()
            receipts = list((root / campaign.SESSION_ROOT).glob("*/INCOMPLETE.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text())
            self.assertFalse(receipt["performance_ready"])
            self.assertIn("fixture failure", receipt["failure"])
            self.assertFalse((root / campaign.SESSION_ROOT / ".active-campaign.lock").exists())
            self.assertTrue((receipts[0].parent / "PLAN.json").is_file())


if __name__ == "__main__":
    unittest.main()
