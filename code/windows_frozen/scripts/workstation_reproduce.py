#!/usr/bin/env python3
"""Plan or execute the offline, Windows second-workstation reproduction.

Planning is read-only. Execution is explicit, bounded and creates fresh outputs.
No policy edits, raw-dataset download, networking, administrator change or VM
operation is performed. Performance is measured separately on each host.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import freeze_evaluation_baseline as freeze
import supervise_evaluation_v02 as supervisor
from oran_trust_boundary.approval import StaticApprovalRegistry
from oran_trust_boundary.audit import verify_record_checksum
from oran_trust_boundary.baselines import direct_execution, contract_only, contract_rbac
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.evaluation_performance import environment, load_workload
from oran_trust_boundary.evaluation_reference import ReferencePolicy
from oran_trust_boundary.jsonio import strict_json_load, strict_json_loads

MANIFEST = "data/workstation_reproduction/manifest.json"
POLICY_SHA = "bf5915cd92557ca193d692273021342e5bfa495878a0d4500742662497e6921c"
GROUP_TOTALS = {"common_validity": 777, "netslab": 20000,
                "5gnidd_conformance": 95000, "5gnidd_false_alarm_probes": 5000}
SESSION_ROOT = "results/local/workstation_runs"
MAX_REPLAY_SECONDS = 3600
MAX_OUTPUT_BYTES = 5 * 1024 ** 3
MAX_MEMORY_BYTES = 2 * 1024 ** 3


def write_new(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def read_json(path: Path):
    freeze._check_chain(path)
    return strict_json_load(path, maximum_bytes=16 * 1024 ** 2)


def digest(path: Path):
    return freeze._stable_bytes(path)[0]["sha256"]


def input_path(root: Path, value: str):
    return freeze._input_path(root, value)


def session_parent(root: Path):
    current = root
    freeze._check_chain(current)
    for part in SESSION_ROOT.split("/"):
        current = current / part
        if not freeze._check_chain(current, required=False):
            current.mkdir()
        freeze._check_chain(current)
        if not current.is_dir():
            raise ValueError("session output ancestor is not a directory")
    return current


def validate_manifest(value: dict):
    required = {"schema_version", "cases", "workloads_directory", "design_path",
                "pilot_design_path", "freeze_spec_path"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("invalid reproduction manifest fields")
    if value["schema_version"] != "workstation-reproduction-inputs/v1":
        raise ValueError("unsupported reproduction input version")
    for name in required - {"schema_version", "cases"}:
        freeze._relative(value[name])
    totals, paths, groups = Counter(), set(), defaultdict(list)
    if not isinstance(value["cases"], list) or len(value["cases"]) != 42:
        raise ValueError("the complete 42-file frozen replay is required")
    for item in value["cases"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "count", "group", "seed"}:
            raise ValueError("invalid replay file entry")
        freeze._relative(item["path"])
        if item["path"].casefold() in paths or not freeze.HEX256.fullmatch(item["sha256"]):
            raise ValueError("duplicate replay path or invalid digest")
        paths.add(item["path"].casefold())
        group = item["group"]
        if group not in GROUP_TOTALS or type(item["count"]) is not int or item["count"] <= 0:
            raise ValueError("invalid replay group or count")
        totals[group] += item["count"]
        groups[group].append(item)
    if dict(totals) != GROUP_TOTALS:
        raise ValueError("frozen replay totals differ from the declared experiment")
    for group, entries in groups.items():
        if group in {"common_validity", "netslab"}:
            if len(entries) != 1 or entries[0]["seed"] is not None:
                raise ValueError("common/NetsLab input grouping is invalid")
        elif sorted(row["seed"] for row in entries if type(row["seed"]) is int) != list(range(20)):
            raise ValueError("5G-NIDD must include exactly the original 20 seeds")
        elif any(row["count"] != (4750 if group == "5gnidd_conformance" else 250) for row in entries):
            raise ValueError("5G-NIDD per-seed case count mismatch")
    return value


def verified_inputs(root: Path, manifest_path: str):
    path = input_path(root, manifest_path)
    manifest = validate_manifest(read_json(path))
    if digest(root / "configs/paper_policy.json") != POLICY_SHA:
        raise ValueError("the original v0.1 policy has changed")
    for item in manifest["cases"]:
        if digest(input_path(root, item["path"])) != item["sha256"]:
            raise ValueError("frozen replay input checksum mismatch: " + item["path"])
    workloads = input_path(root, manifest["workloads_directory"])
    for dataset in ("netslab", "5gnidd"):
        load_workload(workloads, dataset)
    for key in ("design_path", "pilot_design_path", "freeze_spec_path"):
        read_json(input_path(root, manifest[key]))
    return manifest


def performance_plan(manifest: dict):
    result = []
    for pilot in (True, False):
        for dataset in ("netslab", "5gnidd"):
            selections = [("micro", None)]
            selections += [("scaling", size) for size in ([1000] if pilot else [0, 1, 10, 100, 1000])]
            selections += [("load", rate) for rate in ([1000] if pilot else [100, 1000, 5000])]
            for mode, selection in selections:
                identifier = ("pilot_" if pilot else "final_") + dataset + "_" + mode
                args = [mode, "--design", manifest["pilot_design_path" if pilot else "design_path"],
                        "--workloads", manifest["workloads_directory"], "--dataset", dataset]
                if selection is not None:
                    identifier += "_" + str(selection)
                    args += ["--state-size" if mode == "scaling" else "--rate", str(selection)]
                expected_cells = (8 if mode == "micro" else 32 if mode == "scaling" else 2) if pilot else (
                    160 if mode == "micro" else (80 if selection == 0 else 160) if mode == "scaling" else 10)
                result.append({"id": identifier, "pilot": pilot, "arguments": args,
                               "expected_cells": expected_cells})
    return result


def replay_file(path: Path, item: dict, policy: dict, reference: ReferencePolicy, output):
    counts, findings, seen = Counter(), Counter(), set()
    with path.open(encoding="utf-8") as handle:
        for ordinal, line in enumerate(handle, 1):
            if not line.strip():
                raise ValueError("blank replay record refused")
            case = strict_json_loads(line, maximum_bytes=1024 * 1024)
            if case["case_id"] in seen:
                raise ValueError("duplicate case identifier within one frozen file")
            seen.add(case["case_id"])
            expected = case["expected_decision"]
            if expected not in {"ALLOW", "DENY", "ESCALATE"}:
                raise ValueError("invalid frozen expected decision")
            answer = reference.evaluate(case)
            findings["reference_vs_frozen_decision"] += answer["decision"] != expected
            if case["expected_reference"]["reason_comparison"] == "exact_set":
                findings["reference_vs_frozen_reasons"] += set(answer["reasons"]) != set(case["expected_reasons"])
            engine = TrustBoundary(policy, StaticApprovalRegistry(case["approval_registry"]))
            kwargs = {"active_actions": case["active_actions"],
                      "authenticated_principal": case["authenticated_principal"],
                      "as_of": datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))}
            row = {"group": item["group"], "seed": item["seed"], "ordinal": ordinal,
                   "case_id": case["case_id"], "expected_decision": expected, "results": {}}
            for name, evaluator in (("direct", direct_execution), ("contract", contract_only),
                    ("contract_rbac", lambda p, **kw: contract_rbac(p, policy=policy, **kw)),
                    ("trust_boundary", engine.evaluate)):
                result = evaluator(case["proposal"], **kwargs)
                actual = result.decision.value
                counts[name + ":" + actual] += 1
                counts[name + ":block_required_admitted"] += expected != "ALLOW" and actual == "ALLOW"
                record = {"decision": actual, "reasons": list(result.reason_codes)}
                if name == "trust_boundary":
                    reasons_ok = bool(result.reason_codes) if case["expected_reference"]["reason_comparison"] == "structural_nonempty" else set(result.reason_codes) == set(case["expected_reasons"])
                    audit_ok = bool(result.audit_record) and set(policy["audit_required_fields"]) <= result.audit_record.keys() and verify_record_checksum(result.audit_record)
                    findings["gateway_decision"] += actual != expected
                    findings["gateway_reasons"] += not reasons_ok
                    findings["gateway_audit"] += not audit_ok
                    record.update(audit_checksum_verified=bool(audit_ok), audit_record=result.audit_record)
                row["results"][name] = record
            output.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            counts["cases"] += 1
            if counts["cases"] % 1000 == 0:
                print(json.dumps({"group": item["group"], "seed": item["seed"], "cases": counts["cases"]}), flush=True)
    if counts["cases"] != item["count"]:
        raise ValueError("frozen replay file record count mismatch")
    return {"input": item, "counts": dict(counts), "findings": dict(findings)}


def replay_worker(manifest_path: str, output: Path):
    manifest = verified_inputs(ROOT, manifest_path)
    reference = ReferencePolicy()
    records = []
    with (output / "decisions.jsonl").open("x", encoding="utf-8", newline="\n") as target:
        for item in manifest["cases"]:
            records.append(replay_file(input_path(ROOT, item["path"]), item, reference.operator_policy, reference, target))
    summary = {"status": "COMPLETED_WITH_FINDINGS" if any(sum(r["findings"].values()) for r in records) else "PASS",
               "case_count": sum(r["counts"]["cases"] for r in records), "files": records,
               "interpretation": "Frozen decision replay, not independent new cases or dataset regeneration.",
               "raw_dataset_census": "NOT_RERUN_RAW_DATA_NOT_INCLUDED",
               "false_alarm_interpretation": "ALLOW remains a policy limitation, not evidence of needed or beneficial mitigation."}
    write_new(output / "summary.json", summary)
    write_new(output / "COMPLETE.json", {"status": summary["status"], "files": {
        name: digest(output / name) for name in ("summary.json", "decisions.jsonl")}})
    return 0


def bounded_replay(manifest_path: str, session: Path):
    output = session / "replay"
    output.mkdir()
    job, process = None, None
    started, peak_rss, peak_commit = time.monotonic(), 0, 0
    failure = None
    try:
        job = supervisor.WindowsJob(MAX_MEMORY_BYTES)
        with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
            process = subprocess.Popen([sys.executable, "-u", str(Path(__file__)), "--gated-replay", manifest_path,
                output.relative_to(ROOT).as_posix()], cwd=ROOT, stdin=subprocess.PIPE, stdout=stdout,
                stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
            job.attach(process)
            process.stdin.write(b"RUN\n")
            process.stdin.close()
            next_progress = 0
            while process.poll() is None:
                elapsed = time.monotonic() - started
                usage = job.usage()
                peak_rss = max(peak_rss, usage["maximum_observed_process_peak_rss_bytes"])
                peak_commit = max(peak_commit, usage["peak_job_committed_bytes"])
                if elapsed > MAX_REPLAY_SECONDS or peak_rss > MAX_MEMORY_BYTES or supervisor.tree_bytes(output) > MAX_OUTPUT_BYTES:
                    raise RuntimeError("frozen replay resource guard reached")
                if elapsed >= next_progress:
                    print(json.dumps({"phase": "replay", "elapsed_seconds": round(elapsed, 1)}), flush=True)
                    next_progress = elapsed + 30
                time.sleep(1)
            if process.returncode or job.usage()["active_processes"]:
                raise RuntimeError("replay child failed or left descendants; inspect retained logs")
            if supervisor.tree_bytes(output) > MAX_OUTPUT_BYTES:
                raise RuntimeError("replay output bound exceeded")
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    finally:
        if job is not None:
            job.terminate()
            job.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    write_new(output / "SUPERVISION.json", {"status": "INCOMPLETE" if failure else "COMPLETE", "failure": failure,
        "elapsed_seconds": time.monotonic() - started, "peak_job_committed_bytes": peak_commit,
        "maximum_observed_process_peak_rss_bytes": peak_rss})
    if failure:
        raise RuntimeError(failure)
    return read_json(output / "summary.json")


def completed_partition(directory: Path, expected_cells: int):
    parent = read_json(directory / "COMPLETE.json")
    child = read_json(directory / "work/COMPLETE.json")
    summary = read_json(directory / "work/summary.json")
    if parent.get("status") != "COMPLETE" or parent.get("source_unchanged") is not True or parent.get("baseline_after", {}).get("status") != "pass":
        raise RuntimeError("performance supervision did not complete cleanly")
    if child.get("status") != "complete" or summary.get("status") != "complete":
        raise RuntimeError("performance completed with findings or is incomplete; retain and review")
    # Both micro/scaling and load summaries expose the complete cell inventory.
    cells = summary.get("cell_summaries")
    if (not isinstance(cells, list) or len(cells) != expected_cells
            or summary.get("planned_cells") != expected_cells
            or any(item.get("status") != "complete" for item in cells)):
        raise RuntimeError("performance partition cell count mismatch")
    return {"path": directory.relative_to(ROOT).as_posix(), "cells": len(cells),
            "summary_sha256": digest(directory / "work/summary.json"),
            "supervisor_receipt_sha256": digest(directory / "COMPLETE.json")}


def run_campaign(manifest_path: str, phase: str, quiet_host: bool):
    if os.name != "nt":
        raise RuntimeError("Stage7 host reproduction requires Windows; Stage6 has a separate Ubuntu runner")
    if phase in {"all", "performance"} and not quiet_host:
        raise ValueError("performance requires --quiet-host-confirmed; do not benchmark while running the VM")
    manifest = verified_inputs(ROOT, manifest_path)
    if shutil.disk_usage(ROOT).free < 10 * 1024 ** 3:
        raise RuntimeError("at least 10 GiB free disk is required")
    parent = session_parent(ROOT)
    session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    session = parent / session_id
    session.mkdir()
    before = supervisor.source_snapshot(ROOT)
    write_new(session / "SOURCE_BEFORE.json", before)
    plan = performance_plan(manifest)
    write_new(session / "PLAN.json", {"phase": phase, "manifest_path": manifest_path,
        "manifest_sha256": digest(input_path(ROOT, manifest_path)), "performance": plan,
        "final_performance_cells": sum(p["expected_cells"] for p in plan if not p["pilot"]),
        "raw_dataset_census": "NOT_RERUN_RAW_DATA_NOT_INCLUDED", "environment": environment(),
        "quiet_host_confirmed_by_operator": quiet_host, "timings_pooled_with_first_host": False,
        "author_standards_policy_verification": "HUMAN_REVIEW_STILL_REQUIRED"})
    findings, partitions, failure = [], [], None
    baseline = None
    try:
        # This is a NEW transfer-input baseline, not a relabelled original Stage0.
        baseline = freeze.freeze_baseline(ROOT, manifest["freeze_spec_path"])
        write_new(session / "TRANSFER_BASELINE.json", {"path": baseline.relative_to(ROOT).as_posix(),
            "scope": "New destination transfer-input inventory; not the original workstation Stage0."})
        if phase in {"replay", "all"}:
            replay = bounded_replay(manifest_path, session)
            if replay["status"] != "PASS":
                findings.append("frozen_replay_disagreements")
                raise RuntimeError("replay disagreements require review before timing")
        if phase in {"performance", "all"}:
            for index, partition in enumerate(plan):
                label = "s7_" + session_id[-8:] + "_" + partition["id"]
                code = supervisor.supervise("scripts/run_performance_v02.py", partition["arguments"], label,
                                            baseline.relative_to(ROOT).as_posix())
                paths = list((ROOT / "results/evaluation_v0.2").glob(label + "_*"))
                if len(paths) != 1:
                    raise RuntimeError("cannot uniquely resolve newly created performance partition")
                row = {"id": partition["id"], "pilot": partition["pilot"],
                       "path": paths[0].relative_to(ROOT).as_posix(), "runner_exit_code": code}
                if code == 0:
                    row.update(completed_partition(paths[0], partition["expected_cells"]))
                partitions.append(row)
                write_new(session / (f"PARTITION_{index:02d}.json"), row)
                if code:
                    raise RuntimeError("performance partition failed; no automatic retry or selection")
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    after = supervisor.source_snapshot(ROOT)
    write_new(session / "SOURCE_AFTER.json", after)
    if after != before:
        failure = "source changed during reproduction"
    verification = freeze.verify_baseline(ROOT, baseline) if baseline is not None else None
    if verification is not None and verification["status"] != "pass":
        failure = "transfer inputs changed during reproduction"
    receipt = {"status": "INCOMPLETE" if failure else "COMPLETE", "phase": phase, "failure": failure,
        "findings": findings, "partitions": partitions, "source_unchanged": after == before,
        "baseline_after": verification, "scope": "Second-host frozen-case replay and separately reported performance.",
        "raw_dataset_census": "NOT_RERUN_RAW_DATA_NOT_INCLUDED",
        "not_established": ["whole framework validity", "detection accuracy", "policy adequacy", "live O-RAN effectiveness", "author verification"]}
    write_new(session / ("INCOMPLETE.json" if failure else "COMPLETE.json"), receipt)
    print(json.dumps({"session": session.relative_to(ROOT).as_posix(), **receipt}), flush=True)
    return 1 if failure else 0


def main(argv=None):
    args_list = sys.argv[1:] if argv is None else argv
    if args_list[:1] == ["--gated-replay"]:
        if len(args_list) != 3 or sys.stdin.buffer.readline(4) != b"RUN\n":
            raise ValueError("replay worker must be released by its owned Job supervisor")
        output = ROOT / freeze._relative(args_list[2])
        if not output.is_relative_to(ROOT / SESSION_ROOT):
            raise ValueError("invalid replay output")
        freeze._check_chain(output)
        return replay_worker(args_list[1], output)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=MANIFEST)
    parser.add_argument("--phase", choices=("replay", "performance", "all"), default="all")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--plan", action="store_true", help="read-only default")
    action.add_argument("--execute", action="store_true")
    parser.add_argument("--quiet-host-confirmed", action="store_true")
    args = parser.parse_args(args_list)
    if args.execute:
        return run_campaign(args.manifest, args.phase, args.quiet_host_confirmed)
    manifest = verified_inputs(ROOT, args.manifest)
    plan = performance_plan(manifest)
    print(json.dumps({"status": "PLAN_ONLY_NOT_RUN", "phase": args.phase,
        "replay_counts": GROUP_TOTALS, "performance": plan,
        "final_cells": sum(p["expected_cells"] for p in plan if not p["pilot"]),
        "pilot_cells_excluded": sum(p["expected_cells"] for p in plan if p["pilot"]),
        "raw_dataset_census": "NOT_RERUN_RAW_DATA_NOT_INCLUDED"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError) as exc:
        print(json.dumps({"status": "REFUSED_OR_INCOMPLETE", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
