#!/usr/bin/env python3
"""Explicit Windows Orders 0-3 regeneration and performance-workload preparation.

The default is a read-only plan. Execution uses exact privately supplied raw
inputs and the unchanged bounded scientific runners. It never downloads data,
overwrites previous results, starts a VM, changes policy or runs timings.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import freeze_evaluation_baseline as freeze
import supervise_evaluation_v02 as supervisor
import workstation_reproduce as reproduction
from oran_trust_boundary.netslab_adapter import build_context_manifest

SESSION_ROOT = "results/local/full_campaign_runs"
FREEZE_SPEC = "configs/full_campaign_freeze.json"
RAW_INPUTS = {
    "data/raw/Lower_Layer_Data.db": {
        "size_bytes": 5402624,
        "sha256": "d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64"},
    "data/raw/5g-nidd/Combined.zip": {
        "size_bytes": 28028224,
        "sha256": "07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d"},
}
AGGREGATE = "data/processed/netslab_contexts_v0.1.json"
HISTORICAL_AUDIT = "results/5gnidd_v0.1_verified/dataset_audit.json"
CONDITIONS = ("original", "reduction60", "reduction90", "ttl300", "ttl600")


def write_new(path: Path, value):
    reproduction.write_new(path, value)


def read_json(path: Path):
    return reproduction.read_json(path)


def digest(path: Path):
    return reproduction.digest(path)


def planned_partitions():
    """Fixed counts and upstream tokens; no user-selected favorable subset."""
    validity = "scripts/run_validity_v02.py"
    datasets = "scripts/run_dataset_evaluation_v02.py"
    records = [
        {"id": "pilot_validity", "pilot": True, "script": validity,
         "arguments": ["--mode", "validity", "--pilot-limit", "50"], "cases": 50},
        {"id": "stage1_validity", "pilot": False, "script": validity,
         "arguments": ["--mode", "validity"], "cases": 777},
        {"id": "stage2_netslab", "pilot": False, "script": validity,
         "arguments": ["--mode", "netslab"], "cases": 20000},
        {"id": "pilot_nidd_census", "pilot": True, "script": datasets,
         "arguments": ["census", "--archive", "data/raw/5g-nidd/Combined.zip", "--pilot-records", "1000"],
         "cases": 1000},
        {"id": "stage2_nidd_census", "pilot": False, "script": datasets,
         "arguments": ["census", "--archive", "data/raw/5g-nidd/Combined.zip"], "cases": 733693},
        {"id": "stage2_nidd_panels", "pilot": False, "script": datasets,
         "arguments": ["panels", "--census-output", "@stage2_nidd_census"], "cases": 100000},
    ]
    for source in ("netslab", "nidd"):
        for condition in CONDITIONS + (("budget500", "budget2000") if source == "nidd" else ()):
            records.append({"id": f"stage3_{source}_{condition}", "pilot": False,
                "script": "scripts/run_sensitivity_v02.py", "cases": 20000 if source == "netslab" else 120000,
                "arguments": ["--source", source, "--input",
                              "@stage2_netslab" if source == "netslab" else "@stage2_nidd_census",
                              "--condition", condition]})
    records.append({"id": "stage4_prepare", "pilot": False,
        "script": "scripts/run_performance_v02.py", "cases": None,
        "arguments": ["prepare", "--netslab-cases", "@stage2_netslab/cases.jsonl",
                      "--5gnidd-cases", "@stage2_nidd_panels/cases_seed_00_conformance.jsonl"]})
    return records


def resolve_arguments(arguments, outputs):
    resolved = []
    for value in arguments:
        if not value.startswith("@"):
            resolved.append(value)
            continue
        key, separator, suffix = value[1:].partition("/")
        if key not in outputs:
            raise ValueError("upstream partition is not complete: " + key)
        if separator:
            freeze._relative(suffix)
        resolved.append(outputs[key] + ("/" + suffix if separator else ""))
    return resolved


def raw_inventory(root: Path, *, require: bool):
    inventory = {}
    for relative, expected in RAW_INPUTS.items():
        path = root / relative
        if not freeze._check_chain(path, required=False):
            inventory[relative] = {"status": "MISSING", "expected": expected}
            if require:
                raise ValueError("private raw companion not installed: " + relative)
            continue
        measured = freeze._stable_bytes(path)[0]
        if measured != expected:
            raise ValueError("raw input size/SHA differs from pinned release: " + relative)
        inventory[relative] = {"status": "VERIFIED", **measured}
    return inventory


def verify_full_inputs(root: Path, *, require_raw: bool):
    manifest = reproduction.verified_inputs(root, reproduction.MANIFEST)
    inventory = raw_inventory(root, require=require_raw)
    spec = freeze.validate_spec(read_json(root / FREEZE_SPEC))
    pinned = {item["path"]: item["expected_sha256"] for item in spec["files"]}
    if any(pinned.get(name) != record["sha256"] for name, record in RAW_INPUTS.items()):
        raise ValueError("full campaign freeze must pin both exact raw inputs")
    if HISTORICAL_AUDIT not in pinned or AGGREGATE not in pinned:
        raise ValueError("historical audit and aggregate require explicit freeze pins")
    for name in (HISTORICAL_AUDIT, AGGREGATE):
        if digest(root / name) != pinned[name]:
            raise ValueError("historical input changed: " + name)
    return manifest, inventory


def regenerate_aggregate(root: Path, session: Path):
    """Read the exact small SQLite input; never overwrite the shipped aggregate."""
    name = "data/raw/Lower_Layer_Data.db"
    result = build_context_manifest(root / name, expected_sha256=RAW_INPUTS[name]["sha256"])
    target = session / "regenerated_netslab_contexts.json"
    write_new(target, result)
    expected = read_json(root / AGGREGATE)
    record = {"status": "MATCH" if result == expected else "DIFFERENT",
              "comparison": "exact parsed JSON including canonical manifest digest; serialization newline is not a scientific input",
              "database": RAW_INPUTS[name], "original_aggregate_sha256": digest(root / AGGREGATE),
              "regenerated_aggregate_sha256": digest(target),
              "expected_rows": 45244, "observed_rows": result["dataset"]["total_row_count"]}
    write_new(session / "AGGREGATE_COMPARISON.json", record)
    if result != expected or record["observed_rows"] != 45244:
        raise RuntimeError("regenerated NetsLab aggregate differs; preserve evidence and stop")
    return record


def verify_artifact_hashes(directory: Path, records: dict):
    if not isinstance(records, dict) or not records:
        raise ValueError("missing child artifact hashes")
    for name, expected in records.items():
        freeze._relative(name)
        if "/" in name:
            raise ValueError("unexpected nested child receipt path")
        expected = expected["sha256"] if isinstance(expected, dict) else expected
        if not isinstance(expected, str) or not freeze.HEX256.fullmatch(expected):
            raise ValueError("invalid child artifact digest")
        if digest(directory / name) != expected:
            raise ValueError("child artifact hash mismatch: " + name)


def verify_child_summary(partition: dict, work: Path):
    """Require completion, complete denominators and no gateway/reference faults.

    Admission of declared false alarms and ablation disagreements are findings
    about policy scope, not failure criteria. No favorable metric is required.
    """
    identifier = partition["id"]
    if identifier == "stage4_prepare":
        child = read_json(work / "COMPLETE.json")
        summary = read_json(work / "manifest.json")
        if child.get("status") != "PREPARED_NOT_MEASURED" or summary.get("status") != "PREPARED_NOT_MEASURED":
            raise RuntimeError("workload preparation did not complete")
        for dataset in ("netslab", "5gnidd"):
            reproduction.load_workload(work, dataset)
        return {"scientific_status": "PREPARED_NOT_MEASURED", "summary_file": "manifest.json",
                "summary_sha256": digest(work / "manifest.json"), "child_receipt_sha256": digest(work / "COMPLETE.json")}
    summary = read_json(work / "summary.json")
    if partition["script"] == "scripts/run_validity_v02.py":
        child_name = "COMPLETE.json"
        child = read_json(work / child_name)
        expected_status = "PILOT_NOT_CONFIRMATORY" if partition["pilot"] else "COMPLETED"
        if child.get("status") != expected_status or summary.get("status") != expected_status:
            raise RuntimeError("validity/control partition incomplete or has findings")
        if summary.get("constructed_case_count") != partition["cases"]:
            raise RuntimeError("constructed case count differs from fixed plan")
        for key in ("full_gateway_decision_mismatches", "full_gateway_reason_mismatches", "audit_failures", "unhandled_errors"):
            if summary.get(key) != []:
                raise RuntimeError("gateway validity finding or missing evidence: " + key)
        verify_artifact_hashes(work, child["files"])
        scientific_status = expected_status
    else:
        child_name = "RUN.json"
        child = read_json(work / child_name)
        if child.get("status") != "COMPLETE" or child.get("inputs_and_source_unchanged") is not True:
            raise RuntimeError("dataset partition incomplete or source/input changed")
        verify_artifact_hashes(work, child["output_sha256"])
        if partition["pilot"]:
            if summary.get("status") != "PILOT_NOT_CONFIRMATORY" or summary.get("instrumentation_records") != partition["cases"]:
                raise RuntimeError("dataset instrumentation pilot count/status mismatch")
            metrics = summary["metrics"]
        else:
            metrics = summary.get("overall", summary)
        if metrics.get("scientific_status") != "COMPLETED" or any(metrics.get("trust_boundary_findings", {"missing": 1}).values()):
            raise RuntimeError("dataset reference/audit findings require review")
        counts = sum(group["overall"]["trust_boundary"]["cases"] for group in metrics["groups"].values())
        if counts != partition["cases"]:
            raise RuntimeError("dataset partition denominator differs from fixed plan")
        if identifier == "stage2_nidd_census" and child.get("audit_reconciled") is not True:
            raise RuntimeError("full census was not reconciled against original source audit")
        scientific_status = "PILOT_NOT_CONFIRMATORY" if partition["pilot"] else metrics["scientific_status"]
    return {"scientific_status": scientific_status, "summary_file": "summary.json",
            "summary_sha256": digest(work / "summary.json"), "child_receipt_sha256": digest(work / child_name)}


def run_partition(root: Path, session: Path, short_id: str, index: int, item: dict,
                  outputs: dict, baseline: Path):
    arguments = resolve_arguments(item["arguments"], outputs)
    label = "full_" + short_id + "_" + item["id"]
    row = {**item, "arguments": arguments, "label": label, "path": None,
           "runner_exit_code": None, "validation_error": None}
    try:
        code = supervisor.supervise(item["script"], arguments, label, baseline.relative_to(root).as_posix())
        row["runner_exit_code"] = code
        paths = list((root / "results/evaluation_v0.2").glob(label + "_*"))
        if len(paths) != 1:
            raise RuntimeError("new supervised partition cannot be uniquely resolved")
        directory = paths[0]
        row["path"] = directory.relative_to(root).as_posix()
        if code:
            raise RuntimeError("supervised runner failed; retain attempt; no automatic retry")
        receipt = read_json(directory / "COMPLETE.json")
        if (receipt.get("status") != "COMPLETE" or receipt.get("source_unchanged") is not True
                or receipt.get("baseline_after", {}).get("status") != "pass"):
            raise RuntimeError("supervisor completion/provenance is invalid")
        row.update(verify_child_summary(item, directory / "work"))
        row["supervisor_receipt_sha256"] = digest(directory / "COMPLETE.json")
        outputs[item["id"]] = (directory / "work").relative_to(root).as_posix()
    except BaseException as exc:
        row["validation_error"] = type(exc).__name__ + ": " + str(exc).replace(str(root), "<BUNDLE_ROOT>")
        raise
    finally:
        write_new(session / f"PARTITION_{index:02d}.json", row)
    return row


def compare_regenerated_cases(root: Path, session: Path, manifest: dict, outputs: dict):
    comparisons = []
    for item in manifest["cases"]:
        group = item["group"]
        if group in {"common_validity", "netslab"}:
            source = root / outputs["stage1_validity" if group == "common_validity" else "stage2_netslab"] / "cases.jsonl"
        else:
            suffix = "conformance" if group == "5gnidd_conformance" else "false_alarm_probes"
            source = root / outputs["stage2_nidd_panels"] / f"cases_seed_{item['seed']:02d}_{suffix}.jsonl"
        actual = digest(source)
        comparisons.append({"group": group, "seed": item["seed"], "count": item["count"],
            "original_path": item["path"], "regenerated_path": source.relative_to(root).as_posix(),
            "expected_sha256": item["sha256"], "actual_sha256": actual, "match": actual == item["sha256"]})
    result = {"status": "MATCH" if all(row["match"] for row in comparisons) else "DIFFERENT",
              "files": comparisons, "file_count": len(comparisons), "case_count": sum(x["count"] for x in comparisons),
              "interpretation": "Exact byte regeneration of frozen constructed cases; not independent new incidents."}
    write_new(session / "CASE_REGENERATION_COMPARISON.json", result)
    if result["status"] != "MATCH":
        raise RuntimeError("regenerated case bytes differ; preserve results, stop before timing, do not retune labels")
    return result


def compare_workloads(root: Path, session: Path, manifest: dict, outputs: dict):
    prepared = root / outputs["stage4_prepare"]
    original = root / manifest["workloads_directory"]
    rows = []
    for dataset in ("netslab", "5gnidd"):
        filename = dataset + "_workload.jsonl"
        expected, actual = digest(original / filename), digest(prepared / filename)
        rows.append({"dataset": dataset, "expected_sha256": expected, "actual_sha256": actual,
                     "match": actual == expected, "regenerated_path": (prepared / filename).relative_to(root).as_posix()})
    result = {"status": "MATCH" if all(row["match"] for row in rows) else "DIFFERENT", "datasets": rows,
              "comparison_scope": "Exact workload JSONL bytes. New preparation timestamps/source paths/receipts are intentionally different.",
              "performance_input_directory": manifest["workloads_directory"]}
    write_new(session / "WORKLOAD_COMPARISON.json", result)
    if result["status"] != "MATCH":
        raise RuntimeError("regenerated workload differs; stop before performance, retain all evidence")
    return result


def new_session_parent(root: Path):
    path = root
    for part in SESSION_ROOT.split("/"):
        path = path / part
        if not freeze._check_chain(path, required=False):
            path.mkdir()
        if not path.is_dir():
            raise ValueError("campaign output ancestor is not a directory")
    return path


def run_campaign():
    if os.name != "nt":
        raise RuntimeError("full offline campaign requires Windows Job supervision; no unbounded fallback")
    manifest, raw = verify_full_inputs(ROOT, require_raw=True)
    if shutil.disk_usage(ROOT).free < 10 * 1024**3:
        raise RuntimeError("at least 10 GiB free disk is required")
    parent = new_session_parent(ROOT)
    session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    lock = parent / ".active-campaign.lock"
    with lock.open("x", encoding="utf-8") as stream:
        stream.write(session_id + "\n")
    session = parent / session_id
    baseline, before, after, verification = None, None, None, None
    rows, outputs, failure = [], {}, None
    try:
        session.mkdir()
        before = supervisor.source_snapshot(ROOT)
        write_new(session / "SOURCE_BEFORE.json", before)
        write_new(session / "PLAN.json", {"schema_version": "full-workstation-campaign/v1",
            "phase": "orders0_3_and_workload_preparation", "partitions": planned_partitions(),
            "raw_inputs": raw, "freeze_spec": FREEZE_SPEC, "reproduction_manifest": reproduction.MANIFEST,
            "reproduction_manifest_sha256": digest(ROOT / reproduction.MANIFEST),
            "prior_results_replaced": False, "timing_not_run_by_this_command": True,
            "environment": reproduction.environment()})
        baseline = freeze.freeze_baseline(ROOT, FREEZE_SPEC)
        write_new(session / "TRANSFER_BASELINE.json", {"path": baseline.relative_to(ROOT).as_posix(),
            "scope": "New full destination source/raw-input inventory, not the university Stage0."})
        regenerate_aggregate(ROOT, session)
        for index, item in enumerate(planned_partitions()):
            row = run_partition(ROOT, session, session_id[-8:], index, item, outputs, baseline)
            rows.append(row)
            if item["id"] == "stage2_nidd_panels":
                compare_regenerated_cases(ROOT, session, manifest, outputs)
        compare_workloads(ROOT, session, manifest, outputs)
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc).replace(str(ROOT), "<BUNDLE_ROOT>")
    finally:
        try:
            if session.is_dir():
                try:
                    after = supervisor.source_snapshot(ROOT)
                    write_new(session / "SOURCE_AFTER.json", after)
                    verification = freeze.verify_baseline(ROOT, baseline) if baseline is not None else None
                    if before != after or verification is None or verification["status"] != "pass":
                        failure = failure or "source or frozen full inputs changed during campaign"
                except BaseException as exc:
                    failure = failure or "final integrity check failed: " + type(exc).__name__
                receipt = {"schema_version": "full-workstation-campaign/v1",
                    "status": "INCOMPLETE" if failure else "COMPLETE", "failure": failure,
                    "phase": "orders0_3_and_workload_preparation", "performance_ready": failure is None,
                    "partitions": rows, "expected_partitions": 19, "completed_partitions": len(rows),
                    "source_unchanged": before == after, "baseline_after": verification,
                    "case_comparison": "CASE_REGENERATION_COMPARISON.json",
                    "workload_comparison": "WORKLOAD_COMPARISON.json",
                    "scope": "Fresh full eligible release regeneration and constructed-policy evaluation, not new independent datasets or operational safety.",
                    "next_step": "Inspect comparisons, then run workstation_reproduce.py --execute --phase performance --quiet-host-confirmed once; do not repeat timings for another headline result."}
                write_new(session / ("INCOMPLETE.json" if failure else "COMPLETE.json"), receipt)
                print(json.dumps({"session": session.relative_to(ROOT).as_posix(), "status": receipt["status"],
                                  "failure": failure, "performance_ready": receipt["performance_ready"]}), flush=True)
        finally:
            # Only this invocation's exclusively created lock is removed. A
            # forced process kill leaves it as an explicit recovery checkpoint.
            lock.unlink()
    return 1 if failure else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--plan", action="store_true", help="read-only default")
    action.add_argument("--execute", action="store_true", help="run new full Orders0-3 plus preparation; no timings")
    args = parser.parse_args(argv)
    if args.execute:
        return run_campaign()
    manifest, raw = verify_full_inputs(ROOT, require_raw=False)
    print(json.dumps({"status": "PLAN_ONLY_NOT_RUN", "raw_inputs": raw,
        "raw_ready": all(row["status"] == "VERIFIED" for row in raw.values()),
        "partitions": planned_partitions(), "final_case_regeneration_files": len(manifest["cases"]),
        "final_constructed_case_count": sum(item["count"] for item in manifest["cases"]),
        "full_census_eligible_records": 733693, "census_comparator_decisions": 2934772,
        "sensitivity_conditions": 12, "timings": "Separate existing performance phase; same regenerated workload bytes required."},
        indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError) as exc:
        print(json.dumps({"status": "REFUSED_OR_INCOMPLETE", "error": str(exc).replace(str(ROOT), "<BUNDLE_ROOT>")}), file=sys.stderr)
        raise SystemExit(2)
