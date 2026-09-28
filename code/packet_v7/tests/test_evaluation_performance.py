"""Small, offline fixture tests; no confirmatory performance experiment."""

from __future__ import annotations

import copy
import csv
import io
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary import evaluation_performance as perf
from oran_trust_boundary.evaluation_cases import make_case, attach_expectation


class EvaluationPerformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oran-perf-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = json.loads((ROOT / "configs/paper_policy.json").read_text())
        self.write_json("configs/paper_policy.json", self.policy)
        self.design = json.loads((ROOT / "configs/evaluation_v0.2/study_design.json").read_text())
        self.source_cases = []
        for action in ("rate_limit_ue", "isolate_xapp", "notify_operator"):
            base = make_case(action, "perf-" + action)
            self.source_cases.append(attach_expectation(base))
            denied = copy.deepcopy(base)
            denied["case_id"] += "-denied"
            denied["authenticated_principal"] = "unregistered-principal"
            self.source_cases.append(attach_expectation(denied))
            approval = copy.deepcopy(base)
            approval["case_id"] += "-approval"
            approval["proposal"]["risk_level"] = "high"
            approval["proposal"]["approval"] = None
            self.source_cases.append(attach_expectation(approval))
            conflict = copy.deepcopy(base)
            conflict["case_id"] += "-conflict"
            active = copy.deepcopy(base["proposal"])
            active["action_id"] = "active-other"
            conflict["active_actions"] = [active]
            self.source_cases.append(attach_expectation(conflict))
        self.sources = {}
        for dataset in ("netslab", "5gnidd"):
            source = self.root / f"{dataset}_source.jsonl"
            source.write_text("".join(perf.canonical({**case, **({"selection_seed": 0} if dataset == "5gnidd" else {})}) + "\n"
                                      for case in self.source_cases), encoding="utf-8")
            self.sources[dataset] = source

    def write_json(self, relative: str, value: object) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def prepared(self) -> Path:
        path = perf.new_output(self.root, "results/evaluation_v0.2/prepared")
        # Test only the pool-builder with tiny fixtures, never pretend these
        # are a complete research dataset campaign. Production validation is
        # separately exercised below and cannot be disabled through the CLI.
        with patch.object(perf, "verify_case_source", return_value={"expected_case_count": len(self.source_cases), "completion_receipts": {}}):
            perf.prepare_workloads(self.root, self.sources, path)
        return path

    def job(self, prepared: Path, *, mode: str = "micro", method: str = "trust_boundary") -> dict:
        return {"version": perf.VERSION, "mode": mode, "dataset": "netslab", "method": method,
                "workloads": prepared.relative_to(self.root).as_posix(), "block": 0, "seed": 2000,
                "boundary": perf.BOUNDARIES[0], "warmup": 1, "measured": 10, "cell_wall_seconds": 30}

    def test_preparation_is_deterministic_balanced_and_integrity_checked(self) -> None:
        prepared = self.prepared()
        cases = perf.load_workload(prepared, "netslab")
        self.assertEqual(set(case["stratum"] for case in cases), set(perf.STRATA))
        first = perf.make_sequence(cases, 100, 12)
        self.assertEqual(first, perf.make_sequence(cases, 100, 12))
        self.assertEqual({stratum: sum(cases[i]["stratum"] == stratum for i in first) for stratum in perf.STRATA},
                         {stratum: 20 for stratum in perf.STRATA})
        with (prepared / "netslab_workload.jsonl").open("a") as handle:
            handle.write("{}\n")
        with self.assertRaisesRegex(perf.PerformanceError, "checksum"):
            perf.load_workload(prepared, "netslab")

    def test_independent_case_authority_fixtures_are_preserved(self) -> None:
        prepared = self.prepared()
        cases = perf.load_workload(prepared, "netslab")
        runtime = perf.runtime_cases(cases, self.policy, "trust_boundary")
        for case in runtime:
            with self.subTest(case=case["case_id"]):
                self.assertEqual(perf.invoke(case, perf.BOUNDARIES[0]).decision.value, case["expected_decision"])

    def test_matched_local_path_serializes_full_response_and_logs_audit(self) -> None:
        prepared = self.prepared()
        cases = perf.load_workload(prepared, "netslab")
        compliant = next(case for case in cases if case["stratum"] == "allow")
        logs = {}
        for method in ("direct", "trust_boundary"):
            runtime = perf.runtime_cases([compliant], self.policy, method)[0]
            stream = io.StringIO()
            result = perf.invoke(runtime, perf.BOUNDARIES[1], stream)
            logs[method] = json.loads(stream.getvalue())
            self.assertEqual(logs[method]["response"], result.to_mapping())
            self.assertEqual(runtime["_kwargs"]["as_of"].isoformat(), "2026-01-15T12:05:00+00:00")
        self.assertIsNone(logs["direct"]["response"]["audit_record"])
        self.assertIsNotNone(logs["trust_boundary"]["response"]["audit_record"])

    def test_scaling_paths_and_large_payload_preserve_expected_decisions(self) -> None:
        for action in ("rate_limit_ue", "quarantine_ue", "isolate_xapp", "modify_a1_policy", "rollback_policy", "notify_operator"):
            base = perf.compact_case(attach_expectation(make_case(action)))
            base.update(stratum="allow", action=action)
            for path in ("no_conflict", "conflict_first", "conflict_last", "malformed_last"):
                for large in (False, True):
                    case = perf.scaling_case(base, 3, path, large=large)
                    runtime = perf.runtime_cases([case], self.policy, "trust_boundary")[0]
                    with self.subTest(action=action, path=path, large=large):
                        result = perf.invoke(runtime, perf.BOUNDARIES[0])
                        self.assertEqual(result.decision.value, case["expected_decision"])
                        if path != "no_conflict":
                            self.assertNotEqual(case["stratum"], "allow")
            with self.assertRaises(perf.PerformanceError):
                perf.scaling_case(base, 0, "conflict_first")

    def test_small_time_worker_and_separate_resource_mode(self) -> None:
        prepared = self.prepared()
        job = self.job(prepared)
        output = perf.new_output(self.root, "results/evaluation_v0.2/timing")
        result = perf.time_worker(self.root, job, output)
        self.assertEqual(result["reference_agreement_count"], 10)
        self.assertEqual(result["timing"]["sample_count"], 10)
        self.assertFalse(result["empty_timer_subtracted"])
        with (output / "requests.csv").open(newline="", encoding="utf-8") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 10)
        resource_job = {**job, "mode": "scaling", "state_size": 1, "state_path": "conflict_last",
                        "large_input": False, "resource_only": True}
        output = perf.new_output(self.root, "results/evaluation_v0.2/resource")
        result = perf.time_worker(self.root, resource_job, output)
        self.assertEqual(result["reference_agreement_count"], 10)
        self.assertEqual(result["timing"]["sample_count"], 0)
        self.assertEqual(result["memory_measurement"], "separate_resource_run")

    def test_job_partition_counts_and_no_zero_state_conflicts(self) -> None:
        groups = perf._job_groups(self.design, "micro", "netslab", "workloads")
        self.assertEqual(len(groups), 20)
        self.assertTrue(all(len(group) == 8 for group in groups))
        scaling = perf._job_groups(self.design, "scaling", "netslab", "workloads", block_start=0, block_stop=1, state_size=0)
        self.assertEqual(len(scaling[0]), 16)
        self.assertTrue(all(job["state_path"] == "no_conflict" for job in scaling[0]))
        load = perf._job_groups(self.design, "load", "netslab", "workloads", block_start=0, block_stop=1, rate=100)
        self.assertEqual(len(load[0]), 2)
        for job in groups[0] + scaling[0] + load[0]:
            perf.validate_job(job)
        with self.assertRaises(perf.PerformanceError):
            perf._job_groups(self.design, "load", "netslab", "workloads", rate=999)

    def test_invalid_worker_limits_and_empty_samples_are_rejected(self) -> None:
        prepared = self.prepared()
        job = self.job(prepared)
        for key, value in (("measured", 0), ("measured", 10**12), ("seed", True), ("boundary", "unknown")):
            invalid = {**job, key: value}
            with self.subTest(key=key), self.assertRaises(perf.PerformanceError):
                perf.validate_job(invalid)
        self.assertIsNone(perf.percentile([], .95))
        self.assertEqual(perf.percentile([1, 3], .5), 2)

    def test_paired_bootstrap_uses_blocks_and_does_not_invent_single_block_ci(self) -> None:
        result = perf.bootstrap_paired([10., 20., 30.], draws=50)
        self.assertEqual(result, perf.bootstrap_paired([10., 20., 30.], draws=50))
        self.assertEqual(result["blocks"], 3)
        self.assertEqual(result["mean"], 20)
        self.assertIsNone(perf.bootstrap_paired([1.])["ci95"])

    def test_root_escape_output_reuse_and_symlink_bits_refused(self) -> None:
        with self.assertRaises(perf.PerformanceError):
            perf.new_output(self.root, "../outside")
        with self.assertRaises(perf.PerformanceError):
            perf.new_output(self.root, "results")
        result = perf.new_output(self.root, "results/evaluation_v0.2/owned")
        with self.assertRaises(perf.PerformanceError):
            perf.new_output(self.root, result)

    def test_output_byte_guard_uses_shared_strict_scanner(self) -> None:
        with patch.object(perf, "dynamic_tree_bytes", return_value=123) as shared:
            self.assertEqual(perf.output_bytes(self.root), 123)
        shared.assert_called_once_with(self.root, check_chain=perf._no_links)

    def test_upstream_incomplete_or_unverified_sources_are_refused(self) -> None:
        for dataset in ("netslab", "5gnidd"):
            with self.subTest(dataset=dataset), self.assertRaises((perf.PerformanceError, ValueError, FileNotFoundError)):
                perf.verify_case_source(dataset, self.sources[dataset])

    def test_complete_netslab_receipt_binds_all_required_artifacts(self) -> None:
        directory = self.root / "results/evaluation_v0.2/upstream/work"
        directory.mkdir(parents=True)
        files = {}
        for name in ("cases.jsonl", "decisions.jsonl", "summary.json", "REPORT.md"):
            path = directory / name
            path.write_bytes(b"test fixture")
            files[name] = {"sha256": perf.file_hash(path)}
        perf.write_json(directory / "COMPLETE.json", {"status": "COMPLETED_WITH_FINDINGS", "mode": "netslab", "constructed_case_count": 20000, "files": files})
        perf.write_json(directory.parent / "COMPLETE.json", {"status": "COMPLETE", "source_unchanged": True, "baseline_after": {"status": "pass"}})
        result = perf.verify_case_source("netslab", directory / "cases.jsonl")
        self.assertEqual(result["expected_case_count"], 20000)
        (directory / "summary.json").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            perf.verify_case_source("netslab", directory / "cases.jsonl")

    def test_complete_5gnidd_panel_receipt_is_not_a_census_receipt(self) -> None:
        directory = self.root / "results/evaluation_v0.2/panels/work"
        directory.mkdir(parents=True)
        source = directory / "cases_seed_00_conformance.jsonl"
        source.write_bytes(b"small receipt-validation fixture; no research cases")
        receipt = {"status": "COMPLETE", "inputs_and_source_unchanged": True,
                   "stage": "stage2b_5gnidd_conformance", "conformance_proposals": 95000,
                   "false_alarm_proposals": 5000, "progress": {"proposals": 100000, "comparator_decisions": 400000},
                   "output_sha256": {source.name: perf.file_hash(source)}}
        self.write_json("results/evaluation_v0.2/panels/work/RUN.json", receipt)
        self.write_json("results/evaluation_v0.2/panels/COMPLETE.json",
                        {"status": "COMPLETE", "source_unchanged": True, "baseline_after": {"status": "pass"}})
        self.assertEqual(perf.verify_case_source("5gnidd", source)["expected_case_count"], 4750)
        for changed in ({"stage": "stage2a_5gnidd_census"}, {"conformance_proposals": 4750}, {"inputs_and_source_unchanged": False}):
            self.write_json("results/evaluation_v0.2/panels/work/RUN.json", {**receipt, **changed})
            with self.subTest(changed=changed), self.assertRaises(perf.PerformanceError):
                perf.verify_case_source("5gnidd", source)

    def test_drain_endpoint_excludes_cleanup_grace_completions(self) -> None:
        directory = perf.new_output(self.root, "results/evaluation_v0.2/trace")
        with (directory / "arrivals.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(("request", "phase", "case_index", "scheduled_ns", "attempted_enqueue_ns", "admitted"))
            writer.writerows([(1, "measurement", 0, 100, 110, 1), (2, "measurement", 0, 200, 210, 1), (3, "measurement", 0, 300, 310, 0)])
        with (directory / "completions.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(("request", "phase", "case_index", "scheduled_ns", "enqueued_ns", "service_start_ns", "completed_ns", "decision", "reference_agreement"))
            writer.writerows([(1, "measurement", 0, 100, 110, 120, 150, "ALLOW", 1), (2, "measurement", 0, 200, 210, 400, 501, "ALLOW", 1)])
        result = perf.summarize_load_trace(directory, measurement_start_ns=100, measurement_end_ns=400, drain_deadline_ns=500)
        self.assertEqual(result["completed_by_drain"], 1)
        self.assertEqual(result["completed_after_drain"], 1)
        self.assertEqual(result["unfinished_or_admitted_too_late_at_drain"], 1)
        self.assertEqual(result["completion_latency"]["sample_count"], 1)

    def test_real_two_process_bounded_load_smoke_without_network(self) -> None:
        prepared = self.prepared()
        job = {**self.job(prepared, mode="load", method="direct"), "boundary": perf.BOUNDARIES[1],
               "rate": 100, "state_size": 1, "queue_capacity": 2, "warmup_seconds": .02,
               "measurement_seconds": .05, "drain_seconds": 2, "consumer_wall_seconds": 10}
        perf.validate_job(job)
        output = perf.new_output(self.root, "results/evaluation_v0.2/load_smoke")
        result = perf.load_worker(self.root, job, output)
        self.assertFalse(result["network_traffic_generated"])
        self.assertEqual(result["scheduled_measurement"], 5)
        self.assertEqual(result["admitted_measurement"] + result["overflow_measurement"], 5)
        self.assertEqual(result["completed_measurement"] + result["unfinished_at_drain_bound"], result["admitted_measurement"])
        self.assertEqual(result["consumer_endpoint_metrics"]["reference_agreement_count"], result["completed_measurement"])

    def test_missing_path_diagnostics_preserve_native_error_and_exact_entry(self) -> None:
        missing = self.root / "diagnostic-missing-entry"
        native = FileNotFoundError(2, "injected missing entry")
        native.winerror = 3
        original = Path.lstat

        def lstat(path):
            if path == missing:
                raise native
            return original(path)

        with patch.object(Path, "lstat", lstat):
            with self.assertRaises(perf.PerformanceError) as caught:
                perf._no_links(missing)
        self.assertIn(str(missing), str(caught.exception))
        self.assertIn("errno=2", str(caught.exception))
        self.assertIn("winerror=3", str(caught.exception))
        self.assertIs(caught.exception.__cause__, native)

    def _runner_module(self):
        spec = importlib.util.spec_from_file_location("performance_diagnostic_runner", ROOT / "scripts/run_performance_v02.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.ROOT = self.root
        return module

    def test_parent_failure_saves_local_traceback_without_running_experiment(self) -> None:
        runner = self._runner_module()
        relative = "results/evaluation_v0.2/diagnostic_parent"
        with redirect_stdout(io.StringIO()):
            code = runner.main(["micro", "--workloads", "missing_workload", "--dataset", "netslab", "--output", relative])
        self.assertEqual(code, 2)
        output = self.root / relative
        trace = (output / "failure_traceback.txt").read_text(encoding="utf-8")
        self.assertIn("Traceback", trace)
        self.assertIn("FileNotFoundError", trace)
        self.assertIn("required path is missing", trace)
        self.assertFalse((output / "COMPLETE.json").exists())
        receipt = json.loads((output / "INCOMPLETE.json").read_text())
        self.assertEqual(receipt["status"], "incomplete")
        self.assertIn("saved_local", receipt["diagnostic_trace"])

    def test_worker_failure_saves_trace_and_never_overwrites_previous_trace(self) -> None:
        runner = self._runner_module()
        relative = "results/evaluation_v0.2/diagnostic_worker/job.json"
        job = self.write_json(relative, {"fixture": "no evaluation is executed"})
        with patch.object(runner, "run_worker", side_effect=perf.PerformanceError("injected diagnostic failure")):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(["worker", "--job", relative]), 2)
            first = (job.parent / "failure_traceback.txt").read_bytes()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(["worker", "--job", relative]), 2)
        self.assertEqual((job.parent / "failure_traceback.txt").read_bytes(), first)
        self.assertIn(b"injected diagnostic failure", first)


if __name__ == "__main__":
    unittest.main()
