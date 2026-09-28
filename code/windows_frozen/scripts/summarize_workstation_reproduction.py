#!/usr/bin/env python3
"""Validate explicitly selected Stage7 sessions and compare compact host summaries.

Reuses the original validated summary functions without changing historical run
selection. Raw CSV/JSONL is retained but is NOT independently recomputed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import freeze_evaluation_baseline as freeze
import summarize_evaluation_v02 as analysis
import workstation_reproduce as reproduction
import workstation_campaign as campaign
from workstation_bundle import clean_relative

SCOPE = ("Compact JSON/protocol and recorded provenance validation; full-campaign mode additionally hashes regenerated case/workload bytes and supplied raw inputs. "
         "Raw timing observations are not reread and experiment decisions are not independently recomputed.")


def safe_path(root: Path, value: str):
    path = root / clean_relative(value)
    freeze._check_chain(path)
    return path


def session_path(root: Path, value: str):
    path = safe_path(root, value)
    if path.parent != root / reproduction.SESSION_ROOT or not re.fullmatch(r"\d{8}T\d{6}Z_[a-f0-9]{8}", path.name):
        raise ValueError("select an explicit timestamped runner session")
    return path


def read_session(reader, directory):
    plan = reader.json(directory / "PLAN.json")
    complete = reader.json(directory / "COMPLETE.json")
    before = reader.json(directory / "SOURCE_BEFORE.json")
    after = reader.json(directory / "SOURCE_AFTER.json")
    if (complete.get("status") != "COMPLETE" or complete.get("failure") is not None
            or complete.get("source_unchanged") is not True or before != after
            or complete.get("baseline_after", {}).get("status") != "pass"
            or plan.get("phase") != complete.get("phase")):
        raise ValueError("selected session is incomplete or has invalid provenance")
    return plan, complete


def partition_key(item):
    match = re.fullmatch(r"final_(netslab|5gnidd)_(micro|scaling|load)(?:_([0-9]+))?", item["id"])
    if not match or item.get("pilot") is not False:
        raise ValueError("not a predeclared final partition identifier")
    dataset, mode, number = match.groups()
    key = (mode, dataset, int(number) if number is not None else None)
    if key not in analysis.expected_partitions():
        raise ValueError("unexpected final partition")
    return key


def require_complete_keys(keys):
    if len(keys) != 18 or len(set(keys)) != 18 or set(keys) != set(analysis.expected_partitions()):
        raise ValueError("all 18 unique final partitions are required; no duplicate or missing selection")


def collect_performance(reader, root, session):
    plan, complete = read_session(reader, session)
    if plan["phase"] not in {"performance", "all"} or plan.get("quiet_host_confirmed_by_operator") is not True:
        raise ValueError("selected session is not a qualified performance campaign")
    manifest_path = safe_path(root, plan["manifest_path"])
    manifest = reproduction.validate_manifest(reader.json(manifest_path))
    if reader.digest(manifest_path) != plan["manifest_sha256"]:
        raise ValueError("performance input manifest has changed")
    expected_plan = reproduction.performance_plan(manifest)
    if plan["performance"] != expected_plan or len(complete.get("partitions", [])) != 24:
        raise ValueError("campaign does not match the full frozen pilot/final plan")
    partitions, keys, pilots, selected = [], [], [], []
    for index, item in enumerate(expected_plan):
        row = reader.json(session / f"PARTITION_{index:02d}.json")
        if (row != complete["partitions"][index] or row["id"] != item["id"] or row["pilot"] != item["pilot"]
                or row.get("runner_exit_code") != 0 or row.get("cells") != item["expected_cells"]):
            raise ValueError("session partition receipts do not bind the expected plan")
        directory = safe_path(root, row["path"])
        prefix = "s7_" + session.name[-8:] + "_" + item["id"] + "_"
        if directory.parent != root / "results/evaluation_v0.2" or not directory.name.startswith(prefix):
            raise ValueError("partition path is not owned by the selected session")
        if (reader.digest(directory / "work/summary.json") != row["summary_sha256"]
                or reader.digest(directory / "COMPLETE.json") != row["supervisor_receipt_sha256"]):
            raise ValueError("partition summary/receipt hash differs from the session index")
        if item["pilot"]:
            analysis.verify_parent(reader, directory)
            summary = reader.json(directory / "work/summary.json")
            child = reader.json(directory / "work/COMPLETE.json")
            if (summary.get("scientific_scope") != "PILOT_NOT_CONFIRMATORY"
                    or summary.get("completed_cells") != item["expected_cells"]
                    or summary.get("planned_cells") != item["expected_cells"]
                    or summary.get("status") != "complete" or child.get("status") != "complete"):
                raise ValueError("instrumentation qualification is incomplete")
            pilots.append(row)
            continue
        key = partition_key(item)
        keys.append(key)
        part = analysis.performance_partition(reader, directory, key)
        partitions.append(part)
        selected.append({"partition": list(key), "path": row["path"], "cells": row["cells"]})
    require_complete_keys(keys)
    shared_source = analysis.require_shared_source_snapshot(p["source_snapshot_sha256"] for p in partitions)
    for field in ("output_monitor_version", "design_sha256", "workload_manifest_sha256"):
        if len({analysis.canonical(part["plan_metadata"].get(field)) for part in partitions}) != 1:
            raise ValueError("inconsistent final performance provenance: " + field)
    return {"environment": plan["environment"], "session": session.relative_to(root).as_posix(),
            "selected_partitions": selected, "excluded_instrumentation_pilots": pilots,
            "final_cells": sum(p["cells"] for p in selected), "shared_source_sha256": shared_source,
            "performance": analysis.aggregate_performance(partitions)}


def collect_replay(reader, root, session):
    plan, _ = read_session(reader, session)
    if plan["phase"] not in {"replay", "all"}:
        raise ValueError("select a completed replay or all-phase session")
    receipt = reader.json(session / "replay/COMPLETE.json")
    supervision = reader.json(session / "replay/SUPERVISION.json")
    summary = reader.json(session / "replay/summary.json")
    if (receipt.get("status") != "PASS" or summary.get("status") != "PASS"
            or supervision.get("status") != "COMPLETE" or supervision.get("failure") is not None
            or reader.digest(session / "replay/summary.json") != receipt.get("files", {}).get("summary.json")):
        raise ValueError("replay completion/hash/supervision is invalid")
    manifest_path = safe_path(root, plan["manifest_path"])
    manifest = reproduction.validate_manifest(reader.json(manifest_path))
    if reader.digest(manifest_path) != plan["manifest_sha256"]:
        raise ValueError("replay input manifest has changed")
    if ([row["input"] for row in summary["files"]] != manifest["cases"]
            or summary.get("case_count") != 120777
            or any(row["counts"].get("cases") != row["input"]["count"] or sum(row["findings"].values())
                   for row in summary["files"])):
        raise ValueError("replay coverage or findings do not match the frozen complete suite")
    return {"session": session.relative_to(root).as_posix(), "environment": plan["environment"],
            "summary": summary, "recorded_decisions_sha256_not_recomputed": receipt["files"]["decisions.jsonl"],
            "raw_dataset_census": "NOT_RERUN_RAW_DATA_NOT_INCLUDED"}


def original_host(reader, root):
    capsule_root = root / "reference/university"
    capsule = reader.json(capsule_root / "CAPSULE_MANIFEST.json")
    matches = [row for row in capsule["files"] if row["path"] == "final_verified/analysis.json"]
    if len(matches) != 1:
        raise ValueError("comparison capsule lacks one unambiguous original analysis")
    path = safe_path(root, "reference/university/final_verified/analysis.json")
    value = reader.json(path)
    if reader.digest(path) != matches[0]["sha256"] or value.get("status") != "COMPLETE_WITH_REPORTED_FINDINGS":
        raise ValueError("original compact analysis is not intact/complete")
    return {"label": "preserved_original_workstation_not_rerun",
            "environment": reader.json(capsule_root / "host_context.json"), "performance": value["performance"],
            "policy_and_datasets": value.get("policy_and_datasets", {}), "sensitivity": value.get("sensitivity", {}),
            "original_analysis_sha256": matches[0]["sha256"]}


def byte_digest(reader, path):
    record = freeze._stable_bytes(path)[0]
    relative = path.relative_to(reader.root).as_posix()
    prior = reader.manifest.get(relative)
    value = {"sha256": record["sha256"], "bytes": record["size_bytes"]}
    if prior is not None and prior != value:
        raise ValueError("derived input changed between reads")
    reader.manifest[relative] = value
    return record["sha256"]


def verify_regeneration(reader, root, session, manifest, outputs):
    case_check = reader.json(session / "CASE_REGENERATION_COMPARISON.json")
    if (case_check.get("status") != "MATCH" or case_check.get("file_count") != 42
            or case_check.get("case_count") != 120777 or len(case_check.get("files", [])) != 42):
        raise ValueError("full frozen-case regeneration comparison is incomplete")
    for item, row in zip(manifest["cases"], case_check["files"]):
        group = item["group"]
        if group in {"common_validity", "netslab"}:
            regenerated = outputs["stage1_validity" if group == "common_validity" else "stage2_netslab"] + "/cases.jsonl"
        else:
            suffix = "conformance" if group == "5gnidd_conformance" else "false_alarm_probes"
            regenerated = outputs["stage2_nidd_panels"] + f"/cases_seed_{item['seed']:02d}_{suffix}.jsonl"
        if (any(row.get(key) != item[key] for key in ("group", "seed", "count"))
                or row.get("original_path") != item["path"] or row.get("regenerated_path") != regenerated
                or row.get("match") is not True or row.get("expected_sha256") != item["sha256"]
                or row.get("actual_sha256") != item["sha256"]
                or byte_digest(reader, safe_path(root, regenerated)) != item["sha256"]):
            raise ValueError("regenerated case file differs from the frozen input")
    aggregate = reader.json(session / "AGGREGATE_COMPARISON.json")
    original = reader.json(root / campaign.AGGREGATE)
    regenerated = reader.json(session / "regenerated_netslab_contexts.json")
    if (aggregate.get("status") != "MATCH" or original != regenerated
            or aggregate.get("expected_rows") != 45244 or aggregate.get("observed_rows") != 45244
            or regenerated["dataset"]["total_row_count"] != 45244
            or aggregate.get("database") != campaign.RAW_INPUTS["data/raw/Lower_Layer_Data.db"]
            or reader.digest(root / campaign.AGGREGATE) != aggregate.get("original_aggregate_sha256")
            or reader.digest(session / "regenerated_netslab_contexts.json") != aggregate.get("regenerated_aggregate_sha256")):
        raise ValueError("regenerated NetsLab aggregate is not an exact parsed match")
    workloads = reader.json(session / "WORKLOAD_COMPARISON.json")
    if (workloads.get("status") != "MATCH" or workloads.get("performance_input_directory") != manifest["workloads_directory"]
            or [row.get("dataset") for row in workloads.get("datasets", [])] != ["netslab", "5gnidd"]):
        raise ValueError("performance-workload regeneration is incomplete")
    for row in workloads["datasets"]:
        name = row["dataset"] + "_workload.jsonl"
        original_path = safe_path(root, manifest["workloads_directory"] + "/" + name)
        regenerated_path = outputs["stage4_prepare"] + "/" + name
        expected = byte_digest(reader, original_path)
        if (row.get("match") is not True or row.get("regenerated_path") != regenerated_path
                or row.get("expected_sha256") != expected or row.get("actual_sha256") != expected
                or byte_digest(reader, safe_path(root, regenerated_path)) != expected):
            raise ValueError("regenerated performance workload bytes differ")
    return {"case_comparison": case_check, "aggregate_comparison": aggregate, "workload_comparison": workloads,
            "verification": "Regenerated case/workload files independently rehashed; no recomputation of gateway decisions."}


def collect_full_campaign(reader, root, session_value):
    session = safe_path(root, session_value)
    if session.parent != root / campaign.SESSION_ROOT or not re.fullmatch(r"\d{8}T\d{6}Z_[a-f0-9]{8}", session.name):
        raise ValueError("select an explicit timestamped full-campaign session")
    plan, complete = read_session(reader, session)
    expected = campaign.planned_partitions()
    if (plan.get("schema_version") != "full-workstation-campaign/v1"
            or plan.get("phase") != "orders0_3_and_workload_preparation" or plan.get("partitions") != expected
            or complete.get("performance_ready") is not True or complete.get("expected_partitions") != 19
            or complete.get("completed_partitions") != 19 or len(complete.get("partitions", [])) != 19
            or complete.get("case_comparison") != "CASE_REGENERATION_COMPARISON.json"
            or complete.get("workload_comparison") != "WORKLOAD_COMPARISON.json"):
        raise ValueError("full campaign is not the complete fixed 19-partition plan")
    manifest_path = safe_path(root, plan["reproduction_manifest"])
    manifest = reproduction.validate_manifest(reader.json(manifest_path))
    if reader.digest(manifest_path) != plan["reproduction_manifest_sha256"]:
        raise ValueError("full-campaign input manifest changed")
    for name, pinned in campaign.RAW_INPUTS.items():
        if (plan.get("raw_inputs", {}).get(name) != {"status": "VERIFIED", **pinned}
                or byte_digest(reader, safe_path(root, name)) != pinned["sha256"]
                or reader.manifest[name]["bytes"] != pinned["size_bytes"]):
            raise ValueError("full campaign raw release differs from pinned data")
    result = {"session": session_value, "environment": plan["environment"], "policy_and_datasets": {},
              "sensitivity": {}, "excluded_pilots": [], "raw_dataset_census": "RERUN_AND_RECONCILED_733693_ELIGIBLE_RECORDS"}
    outputs, source_hashes = {}, []
    kinds = {"stage1_validity": "validity", "stage2_netslab": "netslab", "stage2_nidd_census": "census", "stage2_nidd_panels": "panels"}
    for index, item in enumerate(expected):
        row = reader.json(session / f"PARTITION_{index:02d}.json")
        if (row != complete["partitions"][index] or any(row.get(key) != item[key] for key in ("id", "pilot", "script", "cases"))
                or row.get("arguments") != campaign.resolve_arguments(item["arguments"], outputs)
                or row.get("runner_exit_code") != 0 or row.get("validation_error") is not None):
            raise ValueError("full-campaign partition does not bind its fixed plan")
        directory = safe_path(root, row["path"])
        if (directory.parent != root / "results/evaluation_v0.2"
                or not directory.name.startswith("full_" + session.name[-8:] + "_" + item["id"] + "_")):
            raise ValueError("full-campaign child belongs to another session")
        analysis.verify_parent(reader, directory)
        source_hashes.append(reader.digest(directory / "SOURCE_BEFORE.json"))
        is_preparation = item["id"] == "stage4_prepare"
        summary_file = "manifest.json" if is_preparation else "summary.json"
        child_receipt = "COMPLETE.json" if is_preparation or item["script"] == "scripts/run_validity_v02.py" else "RUN.json"
        if (row.get("summary_file") != summary_file
                or reader.digest(directory / "work" / summary_file) != row["summary_sha256"]
                or reader.digest(directory / "work" / child_receipt) != row["child_receipt_sha256"]
                or reader.digest(directory / "COMPLETE.json") != row["supervisor_receipt_sha256"]):
            raise ValueError("full-campaign compact artifacts do not match receipts")
        value = reader.json(directory / "work" / summary_file)
        if item["pilot"]:
            count = value.get("constructed_case_count") if item["id"] == "pilot_validity" else value.get("instrumentation_records")
            if value.get("status") != "PILOT_NOT_CONFIRMATORY" or count != item["cases"]:
                raise ValueError("full-campaign pilot qualification is incomplete")
            result["excluded_pilots"].append(row)
        elif is_preparation:
            if value.get("status") != "PREPARED_NOT_MEASURED":
                raise ValueError("workload preparation is incomplete")
            result["prepared_workloads"] = row
        else:
            kind = kinds.get(item["id"])
            if kind is None:
                _, source, condition = item["id"].split("_", 2)
                kind = f"sensitivity:{source}:{condition}"
            value, receipt = analysis.verify_child_summary(reader, directory, kind)
            if kind in {"validity", "netslab"}:
                if value.get("constructed_case_count") != item["cases"]:
                    raise ValueError("full constructed-case denominator differs")
                result["policy_and_datasets"][kind] = value
            else:
                metrics = value.get("overall", value)
                if sum(group["overall"]["trust_boundary"]["cases"] for group in metrics["groups"].values()) != item["cases"]:
                    raise ValueError("full dataset/sensitivity denominator differs")
                result["sensitivity" if kind.startswith("sensitivity:") else "policy_and_datasets"][kind] = analysis.compact_dataset_summary(value)
                if kind == "census":
                    for filename in ("dataset_audit.json", "natural_panel_analysis.json", "sampling_protocol.json"):
                        supplement = reader.json(directory / "work" / filename)
                        if reader.digest(directory / "work" / filename) != receipt["output_sha256"].get(filename):
                            raise ValueError("census supplemental summary hash mismatch")
                        result["policy_and_datasets"][filename.removesuffix(".json")] = supplement if filename != "natural_panel_analysis.json" else {
                            key: supplement[key] for key in ("overlap_by_label_and_size", "eligible_release_poststratified_min_max_across_seeds", "note")}
        outputs[item["id"]] = (directory / "work").relative_to(root).as_posix()
    result["shared_source_sha256"] = analysis.require_shared_source_snapshot(source_hashes)
    result["regeneration"] = verify_regeneration(reader, root, session, manifest, outputs)
    return result


def summarize(root: Path, performance_session: str, replay_session: str | None, output: str, full_campaign_session: str | None = None):
    # Ancestors are link-checked before canonicalizing Windows short-name aliases.
    root = freeze._root(root).resolve()
    session = session_path(root, performance_session)
    destination = root / freeze._relative(output)
    if destination.parent != root / reproduction.SESSION_ROOT or destination.exists():
        raise ValueError("output must be a fresh named directory directly under results/local/workstation_runs")
    freeze._check_chain(destination.parent)
    destination.mkdir()
    reader = analysis.Reader(root)
    generator = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result = {"schema_version": "workstation-summary/v1", "status": "NOT_COMPLETE", "errors": [],
              "verification_scope": SCOPE, "host_observations_pooled": False,
              "raw_dataset_census": "FULL_CAMPAIGN_REQUESTED_NOT_YET_VERIFIED" if full_campaign_session else "NOT_RERUN_RAW_DATA_NOT_INCLUDED",
              "author_review": "STILL_REQUIRED"}
    try:
        result["new_host"] = collect_performance(reader, root, session)
        if full_campaign_session:
            result["full_campaign"] = collect_full_campaign(reader, root, full_campaign_session)
            if result["full_campaign"]["shared_source_sha256"] != result["new_host"]["shared_source_sha256"]:
                raise ValueError("full regeneration and performance used different frozen source inventories")
            result["raw_dataset_census"] = result["full_campaign"]["raw_dataset_census"]
            if replay_session:
                result["replay"] = collect_replay(reader, root, session_path(root, replay_session))
            elif reader.json(session / "PLAN.json")["phase"] == "all":
                result["replay"] = collect_replay(reader, root, session)
            else:
                result["replay"] = {"status": "NOT_RUN_NOT_REQUIRED_FULL_REGENERATION", "interpretation": "Exact full case regeneration was verified instead."}
        else:
            result["replay"] = collect_replay(reader, root, session_path(root, replay_session) if replay_session else session)
        result["original_host"] = original_host(reader, root)
        result["status"] = "COMPLETE_COMPACT_VALIDATION"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result["errors"].append({"type": type(exc).__name__, "reason": str(exc)})
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != generator:
        result["status"] = "NOT_COMPLETE"
        result["errors"].append({"reason": "summary source changed during analysis"})
    report = ("# Second-workstation compact validation\n\nStatus: " + result["status"] + ".\n\n" + SCOPE + "\n\n"
        "See analysis.json: original_host and new_host retain separate performance estimates; replay contains the frozen-case agreement report. "
        "No observations are pooled and no hardware-independent speedup is inferred. All 18 primary partitions (1,820 cells) are required; "
        "84 instrumentation-pilot cells are excluded by role.\n\n"
        "Policy permission is not mitigation necessity or operational safety. False-alarm admissions remain a limitation. "
        "Raw-dataset census status: " + result["raw_dataset_census"] + ". Author verification remains pending, and Stage6 has separate evidence.\n"
        "A full regeneration remains the same original datasets, not new independent datasets. Natural policy-permitted proposals with no required-block cases "
        "do not establish blocking superiority; zero required-block denominators remain undefined, not successful blocking evidence.\n")
    if result["errors"]:
        report += "\nMissing or invalid evidence:\n\n" + "\n".join("- " + e["reason"] for e in result["errors"]) + "\n"
    reproduction.write_new(destination / "analysis.json", result)
    with (destination / "REPORT.md").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(report)
    reproduction.write_new(destination / "manifest.json", {"schema_version": result["schema_version"], "status": result["status"],
        "consumed_compact_files": reader.manifest, "generator_sha256": generator, "verification_scope": SCOPE,
        "output_sha256": {name: reproduction.digest(destination / name) for name in ("analysis.json", "REPORT.md")}})
    reproduction.write_new(destination / "STATUS.json", {"status": result["status"], "verification_scope": SCOPE,
        "errors": result["errors"]})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True, help="explicit completed performance/all runner session")
    parser.add_argument("--replay-session", help="explicit replay session when separate from performance")
    parser.add_argument("--full-campaign-session", help="explicit completed raw-data Orders0-3 regeneration session; permits omitting optional replay")
    parser.add_argument("--output", required=True, help="fresh directory under results/local/workstation_runs")
    args = parser.parse_args(argv)
    result = summarize(ROOT, args.session, args.replay_session, args.output, args.full_campaign_session)
    print(json.dumps({"status": result["status"], "errors": result["errors"]}, sort_keys=True))
    return 0 if result["status"] == "COMPLETE_COMPACT_VALIDATION" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "REFUSED_OR_INCOMPLETE", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
