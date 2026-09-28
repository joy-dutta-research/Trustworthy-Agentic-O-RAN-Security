"""Bounded, local performance experiments; never executes a network action.

The proposal's logical evaluation time is frozen. Wall time is used only for
measurement and resource limits. Local-path logging is buffered, NOT durable.
Microbenchmark samples are repeated requests; process blocks, not requests,
are the uncertainty-analysis units. Generated state is contract-shaped fixture
state, not an authenticated live controller database.
"""

from __future__ import annotations

import copy
import csv
import ctypes
import hashlib
import json
import math
import multiprocessing as mp
import os
import platform
import queue
import random
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .approval import StaticApprovalRegistry
from .baselines import contract_only, contract_rbac, direct_execution
from .engine import TrustBoundary
from .evaluation_filesystem import OUTPUT_MONITOR_VERSION, dynamic_tree_bytes
from .jsonio import strict_json_load, strict_json_loads

METHODS = ("direct", "contract", "contract_rbac", "trust_boundary")
STRATA = ("allow", "policy_deny", "other_escalate", "conflict", "malformed")
BOUNDARIES = ("evaluator_component", "matched_local_processing_with_buffered_event_logging")
VERSION = "evaluation-performance/0.2.0"
MAX_OUTPUT = 5 * 1024 ** 3
MAX_RSS = 2 * 1024 ** 3
MAX_WALL = 3600
ANALYSIS_SEED = 9000
BOOTSTRAP_DRAWS = 2500


class PerformanceError(ValueError):
    """Invalid workload, unsafe output target, or technical resource limit."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_hash(path: Path) -> str:
    before = path.stat()
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            result.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise PerformanceError("input changed during hashing")
    return result.hexdigest()


def _no_links(path: Path, *, missing: bool = False) -> None:
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            if missing:
                return
            # Local diagnostics only: retain the actual failed ancestor/entry
            # and native error codes; do not retry or weaken this guard.
            raise PerformanceError(
                f"required path is missing: {current} "
                f"(errno={error.errno}, winerror={getattr(error, 'winerror', None)})"
            ) from error
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PerformanceError("symbolic links and reparse points refused")


def local_path(root: Path, value: str | Path, *, missing: bool = False) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    if ".." in candidate.parts:
        raise PerformanceError("path traversal refused")
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PerformanceError("paths must remain within this repository") from None
    _no_links(candidate, missing=missing)
    return candidate


def new_output(root: Path, value: str | Path) -> Path:
    target = local_path(root, value, missing=True)
    dedicated = root / "results" / "evaluation_v0.2"
    try:
        relative = target.relative_to(dedicated)
    except ValueError:
        raise PerformanceError("outputs must be under results/evaluation_v0.2") from None
    if not relative.parts or target.exists():
        raise PerformanceError("output must be a NEW named subdirectory")
    target.parent.mkdir(parents=True, exist_ok=True)
    _no_links(target.parent)
    target.mkdir()
    return target


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def read_json(path: Path, maximum: int = 64 * 1024 ** 2) -> Any:
    return strict_json_load(path, maximum_bytes=maximum)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def environment() -> dict[str, Any]:
    clock = time.get_clock_info("perf_counter")
    cpu_name = platform.processor()
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            cpu_name = str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
    return {"python": platform.python_version(), "implementation": platform.python_implementation(),
            "os": platform.system(), "os_release": platform.release(), "machine": platform.machine(),
            "processor": cpu_name, "logical_cpu_count": os.cpu_count(),
            "clock": {"implementation": clock.implementation, "resolution_seconds": clock.resolution,
                      "monotonic": clock.monotonic}, "power_security_settings_changed": False}


def process_memory(pid: int | None = None) -> tuple[int, int]:
    """Current and peak resident bytes; no optional library or privilege change."""
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("peak_working", "working", "peak_paged", "paged",
                                                   "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        psapi.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = kernel.GetCurrentProcess() if pid is None else kernel.OpenProcess(0x1000 | 0x10, False, pid)
        if not handle:
            raise PerformanceError("process memory monitoring is unavailable")
        try:
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                raise PerformanceError("process memory monitoring failed")
            return int(counters.working), int(counters.peak_working)
        finally:
            if pid is not None:
                kernel.CloseHandle(handle)
    if sys.platform.startswith("linux"):
        text = Path(f"/proc/{pid or 'self'}/status").read_text()
        values = {line.split(":", 1)[0]: int(line.split()[1]) * 1024
                  for line in text.splitlines() if line.startswith(("VmRSS:", "VmHWM:"))}
        if "VmRSS" not in values or "VmHWM" not in values:
            raise PerformanceError("process memory monitoring is unavailable")
        return values["VmRSS"], values["VmHWM"]
    raise PerformanceError("unsupported resident-memory monitor; do not assume resource limits")


def output_bytes(directory: Path) -> int:
    return dynamic_tree_bytes(directory, check_chain=_no_links)


def check_limits(started: float, output: Path, *, wall: float = MAX_WALL,
                 rss: int = MAX_RSS, disk: int = MAX_OUTPUT) -> None:
    if time.monotonic() - started >= wall:
        raise PerformanceError("predeclared wall-time bound reached")
    if process_memory()[0] > rss:
        raise PerformanceError("predeclared resident-memory bound reached")
    if output_bytes(output) > disk:
        raise PerformanceError("predeclared new-output bound reached")


def percentile(values: list[int | float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower))


def timing_summary(values: list[int]) -> dict[str, Any]:
    return {"sample_count": len(values), **{f"p{p}_ns": percentile(values, p / 100) for p in (50, 95, 99)},
            "mean_ns": statistics.fmean(values) if values else None,
            "maximum_ns": max(values) if values else None}


def bootstrap_paired(values: list[float], *, draws: int = BOOTSTRAP_DRAWS,
                     seed: int = ANALYSIS_SEED) -> dict[str, Any]:
    """CI for the mean paired block statistic, not individual request samples."""
    if not values:
        return {"blocks": 0, "mean": None, "ci95": None}
    generator = random.Random(seed)
    boot = [statistics.fmean(generator.choices(values, k=len(values))) for _ in range(draws)]
    return {"blocks": len(values), "mean": statistics.fmean(values),
            "ci95": [percentile(boot, .025), percentile(boot, .975)] if len(values) > 1 else None,
            "minimum": min(values), "maximum": max(values), "draws": draws, "analysis_seed": seed}


def _reasons(case: dict[str, Any]) -> list[str]:
    value = case.get("expected_reasons", case.get("expected_reference", {}).get("required_reasons"))
    if value is None:
        value = [case["expected_reason"]] if case.get("expected_reason") else []
    return list(value)


def compact_case(value: dict[str, Any]) -> dict[str, Any]:
    required = ("case_id", "proposal", "active_actions", "authenticated_principal", "evaluation_time", "expected_decision")
    if not isinstance(value, dict) or any(key not in value for key in required):
        raise PerformanceError("source case lacks the required benchmark envelope")
    logical = datetime.fromisoformat(value["evaluation_time"].replace("Z", "+00:00"))
    if logical.tzinfo is None or value["expected_decision"] not in {"ALLOW", "DENY", "ESCALATE"}:
        raise PerformanceError("case logical time or reference decision is invalid")
    registry = value.get("approval_registry", {})
    if not isinstance(registry, dict):
        raise PerformanceError("per-case approval registry must be an object")
    return {**{key: copy.deepcopy(value[key]) for key in required}, "expected_reasons": _reasons(value),
            "approval_registry": copy.deepcopy(registry)}


def classify_case(case: dict[str, Any]) -> str:
    if case["expected_decision"] == "ALLOW":
        return "allow"
    if "ACTION_CONFLICT" in case["expected_reasons"]:
        return "conflict"
    if case["expected_decision"] == "ESCALATE":
        return "other_escalate"
    contract_reasons = {"MISSING_FIELD", "UNKNOWN_FIELD", "INVALID_TYPE", "INVALID_STRING", "INVALID_FIELD_NAME",
                        "INVALID_DATETIME", "UNKNOWN_ACTION", "UNKNOWN_INTERFACE", "UNKNOWN_TARGET_TYPE", "INVALID_PARAMETERS",
                        "UNKNOWN_RISK", "INVALID_TTL", "INVALID_EVIDENCE", "DUPLICATE_EVIDENCE", "INVALID_APPROVER",
                        "PARAMETER_NESTING_TOO_DEEP", "CYCLIC_PARAMETER", "PARAMETER_COLLECTION_TOO_LARGE",
                        "INVALID_PARAMETER_KEY", "NON_FINITE_PARAMETER", "PARAMETER_STRING_TOO_LONG", "NON_JSON_PARAMETER", "PARAMETERS_TOO_LARGE"}
    if contract_reasons.intersection(case["expected_reasons"]):
        return "malformed"
    return "policy_deny"


def _keep_smallest(bucket: list[tuple[str, dict[str, Any]]], key: str,
                   case: dict[str, Any], count: int = 8) -> None:
    if any(previous == key for previous, _ in bucket):
        return
    bucket.append((key, case))
    bucket.sort(key=lambda pair: pair[0])
    del bucket[count:]


def verify_case_source(dataset: str, source: Path) -> dict[str, Any]:
    """Require complete supervised upstream artifacts; favorable subsets refused."""
    from .evaluation_datasets import verify_netslab_input
    _no_links(source)
    directory = source.parent
    if dataset == "netslab":
        if source.name != "cases.jsonl":
            raise PerformanceError("NetsLab timing input must be the complete cases.jsonl campaign")
        artifacts = verify_netslab_input(directory)
        expected = 20000
        receipt_paths = [artifacts["generated_suite_receipt"], artifacts["supervisor_receipt"]]
        for path in artifacts.values():
            _no_links(path)
    else:
        if source.name != "cases_seed_00_conformance.jsonl":
            raise PerformanceError("5G-NIDD timing source is the predeclared seed-00 conformance panel")
        receipt_path = directory / "RUN.json"
        _no_links(receipt_path)
        receipt = read_json(receipt_path, maximum=4 * 1024 ** 2)
        progress = receipt.get("progress", {})
        if (receipt.get("status") != "COMPLETE" or receipt.get("inputs_and_source_unchanged") is not True
                or receipt.get("stage") != "stage2b_5gnidd_conformance"
                or receipt.get("conformance_proposals") != 95000 or receipt.get("false_alarm_proposals") != 5000
                or progress.get("proposals") != 100000 or progress.get("comparator_decisions") != 400000
                or receipt.get("output_sha256", {}).get(source.name) != file_hash(source)):
            raise PerformanceError("5G-NIDD input must be a complete unchanged 20-panel campaign with matching case hash")
        supervisor_path = directory.parent / "COMPLETE.json"
        _no_links(supervisor_path)
        supervisor = read_json(supervisor_path)
        if supervisor.get("status") != "COMPLETE" or supervisor.get("source_unchanged") is not True or supervisor.get("baseline_after", {}).get("status") != "pass":
            raise PerformanceError("5G-NIDD source lacks successful supervised provenance")
        expected = 4750
        receipt_paths = [directory / "RUN.json", supervisor_path]
    return {"expected_case_count": expected,
            "completion_receipts": {path.name if path.parent == directory else "supervisor/COMPLETE.json": file_hash(path)
                                    for path in receipt_paths}}


def prepare_workloads(root: Path, sources: dict[str, Path], output: Path,
                      fallback_registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """Freeze deterministic, action-stratified pools before any comparative run."""
    if set(sources) != {"netslab", "5gnidd"}:
        raise PerformanceError("both named source-associated workloads are required")
    manifest: dict[str, Any] = {"version": VERSION, "created_at_utc": utc_now(), "status": "PREPARED_NOT_MEASURED",
        "selection": "8 smallest canonical SHA256 cases per action/path; explicit malformed copies of compliant proposals",
        "micro_mix": {name: .2 for name in STRATA},
        "scaling_load_mix": "compliant-only; available actions balanced; not operational prevalence",
        "logical_clock": "fixed_per_case", "bootstrap_draws": BOOTSTRAP_DRAWS, "analysis_seed": ANALYSIS_SEED,
        "datasets": {}}
    for dataset, source in sources.items():
        source_receipts = verify_case_source(dataset, source)
        buckets: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        source_hash = file_hash(source)
        input_count = 0
        with source.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                raw = strict_json_loads(line, maximum_bytes=1024 * 1024)
                if dataset == "5gnidd" and raw.get("selection_seed") != 0:
                    raise PerformanceError("5G-NIDD performance source must contain only the declared seed-00 panel")
                case = compact_case(raw)
                if "approval_registry" not in raw and fallback_registry:
                    approval = case["proposal"].get("approval")
                    if approval and approval["approval_id"] in fallback_registry:
                        case["approval_registry"] = {approval["approval_id"]: fallback_registry[approval["approval_id"]]}
                stratum = classify_case(case)
                case["stratum"] = stratum
                case["action"] = case["proposal"].get("action", "malformed")
                _keep_smallest(buckets[(stratum, case["action"])], digest(case), case)
                input_count += 1
        if source_hash != file_hash(source):
            raise PerformanceError("case source changed while preparing workload")
        if input_count != source_receipts["expected_case_count"] or source_receipts != verify_case_source(dataset, source):
            raise PerformanceError("source count or completion provenance changed during preparation")
        cases = [case for key in sorted(buckets) for _, case in buckets[key]]
        allow = [case for case in cases if case["stratum"] == "allow"]
        for base in allow:
            malformed = copy.deepcopy(base)
            malformed["case_id"] = "perf-malformed-" + digest(base)[:24]
            malformed["proposal"].pop("ttl_seconds", None)
            malformed.update(stratum="malformed", expected_decision="DENY", expected_reasons=["MISSING_FIELD"])
            cases.append(malformed)
        counts = Counter(case["stratum"] for case in cases)
        if set(counts) != set(STRATA):
            raise PerformanceError("each prepared workload must cover all five declared path strata")
        case_path = output / f"{dataset}_workload.jsonl"
        with case_path.open("x", encoding="utf-8", newline="\n") as handle:
            for case in cases:
                handle.write(canonical(case) + "\n")
        manifest["datasets"][dataset] = {"file": case_path.name, "sha256": file_hash(case_path),
            "input_source": source.relative_to(root).as_posix(), "input_sha256": source_hash,
            "upstream_completion": source_receipts,
            "input_case_count": input_count, "pool_count": len(cases), "stratum_counts": dict(counts),
            "action_counts": dict(Counter(case["action"] for case in cases))}
    write_json(output / "manifest.json", manifest)
    return manifest


def load_workload(directory: Path, dataset: str) -> list[dict[str, Any]]:
    manifest = read_json(directory / "manifest.json")
    if manifest.get("version") != VERSION:
        raise PerformanceError("unsupported workload manifest")
    info = manifest["datasets"][dataset]
    if info["file"] != f"{dataset}_workload.jsonl":
        raise PerformanceError("workload filename mismatch")
    source = directory / info["file"]
    _no_links(source)
    if file_hash(source) != info["sha256"]:
        raise PerformanceError("frozen workload checksum mismatch")
    with source.open(encoding="utf-8") as handle:
        cases = [strict_json_loads(line, maximum_bytes=1024 * 1024) for line in handle if line.strip()]
    if len(cases) != info["pool_count"]:
        raise PerformanceError("workload count mismatch")
    return cases


def make_sequence(cases: list[dict[str, Any]], count: int, seed: int,
                  *, compliant_only: bool = False) -> list[int]:
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, case in enumerate(cases):
        if not compliant_only or case["stratum"] == "allow":
            groups[(case["stratum"], case["action"])].append(index)
    if not groups:
        raise PerformanceError("empty workload selection")
    randomizer = random.Random(seed)
    for group in groups.values():
        randomizer.shuffle(group)
    strata = sorted({key[0] for key in groups})
    randomizer.shuffle(strata)
    actions = {stratum: sorted(action for s, action in groups if s == stratum) for stratum in strata}
    result = []
    visits: Counter[str] = Counter()
    group_visits: Counter[tuple[str, str]] = Counter()
    for i in range(count):
        stratum = strata[i % len(strata)]
        action = actions[stratum][visits[stratum] % len(actions[stratum])]
        visits[stratum] += 1
        group = groups[(stratum, action)]
        result.append(group[group_visits[(stratum, action)] % len(group)])
        group_visits[(stratum, action)] += 1
    return result


def _rebind(case: dict[str, Any]) -> None:
    approval = case["proposal"].get("approval")
    if approval:
        record = case["approval_registry"].get(approval["approval_id"])
        if not record or record.get("status") != "approved":
            raise PerformanceError("compliant transformed case lacks a trusted approval fixture")
        record.update(action_id=case["proposal"]["action_id"], agent_id=case["proposal"]["agent"]["agent_id"],
                      proposal_sha256=digest(case["proposal"]))


def scaling_case(base: dict[str, Any], size: int, path: str, *, large: bool = False) -> dict[str, Any]:
    if base["expected_decision"] != "ALLOW" or size < 0 or path not in {"no_conflict", "conflict_first", "conflict_last", "malformed_last"}:
        raise PerformanceError("invalid scaling fixture request")
    if size == 0 and path != "no_conflict":
        raise PerformanceError("conflict paths are inapplicable to zero state")
    case = copy.deepcopy(base)
    if large:
        case["proposal"]["action_id"] = "p" * 128
        case["proposal"]["incident_id"] = "i" * 128
        case["proposal"]["target"]["target_id"] = "t" * 128
        case["proposal"]["expected_kpi"] = "k" * 256
        case["proposal"]["rollback"]["procedure"] = "r" * 512
        case["proposal"]["evidence_refs"] = [f"{i:02d}-" + "e" * 253 for i in range(32)]
        _rebind(case)
    active = []
    for i in range(size):
        item = copy.deepcopy(case["proposal"])
        item["action_id"] = f"perf-active-{i:04d}"
        item["target"]["target_id"] = f"perf-background-{i:04d}"
        if item["target"]["target_id"] == case["proposal"]["target"]["target_id"]:
            item["target"]["target_id"] += "-other"
        item["approval"] = None  # Typed state is parsed, not re-authorized by this prototype.
        active.append(item)
    if path in {"conflict_first", "conflict_last"}:
        at = 0 if path == "conflict_first" else -1
        active[at]["target"] = copy.deepcopy(case["proposal"]["target"])
        case.update(stratum="conflict", expected_decision="ESCALATE", expected_reasons=["ACTION_CONFLICT"])
    elif path == "malformed_last":
        active[-1] = {"deliberately_malformed_active_state": True}
        case.update(stratum="unverifiable_state", expected_decision="ESCALATE", expected_reasons=["ACTIVE_STATE_UNVERIFIABLE"])
    case["active_actions"] = active
    return case


def runtime_cases(cases: list[dict[str, Any]], policy: dict[str, Any], method: str) -> list[dict[str, Any]]:
    prepared = []
    for source in cases:
        case = dict(source)
        if method == "trust_boundary":
            engine = TrustBoundary(policy, StaticApprovalRegistry(case["approval_registry"]))
            evaluator = engine.evaluate
        elif method == "contract_rbac":
            evaluator = lambda proposal, _policy=policy, **kwargs: contract_rbac(proposal, policy=_policy, **kwargs)
        else:
            evaluator = {"direct": direct_execution, "contract": contract_only}[method]
        case["_evaluate"] = evaluator
        case["_raw_proposal"] = canonical(case["proposal"])
        case["_kwargs"] = {"active_actions": case["active_actions"],
                           "authenticated_principal": case["authenticated_principal"],
                           "as_of": datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))}
        prepared.append(case)
    return prepared


def invoke(case: dict[str, Any], boundary: str, event_log: Any = None) -> Any:
    if boundary == "evaluator_component":
        return case["_evaluate"](case["proposal"], **case["_kwargs"])
    if boundary != "matched_local_processing_with_buffered_event_logging" or event_log is None:
        raise PerformanceError("invalid timing boundary or missing buffered event sink")
    proposal = strict_json_loads(case["_raw_proposal"], maximum_bytes=1024 * 1024)
    kwargs = dict(case["_kwargs"])
    result = case["_evaluate"](proposal, **kwargs)
    encoded_response = canonical(result.to_mapping())
    event_log.write('{"case_id":' + canonical(case["case_id"]) + ',"response":' + encoded_response + '}\n')
    return result


def _compliant_bases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = {}
    for case in cases:
        if case["stratum"] == "allow" and case["action"] not in selected:
            selected[case["action"]] = case
    if not selected:
        raise PerformanceError("scaling/load requires compliant source cases")
    return [selected[key] for key in sorted(selected)]


def time_worker(root: Path, job: dict[str, Any], output: Path) -> dict[str, Any]:
    started = time.monotonic()
    cases = load_workload(local_path(root, job["workloads"]), job["dataset"])
    if job["mode"] == "scaling":
        cases = [scaling_case(case, job["state_size"], job["state_path"], large=job["large_input"])
                 for case in _compliant_bases(cases)]
    prepared = runtime_cases(cases, read_json(root / "configs/paper_policy.json"), job["method"])
    count = job["warmup"] + job["measured"]
    sequence = make_sequence(cases, count, job["seed"])
    values: list[int] = []
    groups: dict[str, list[int]] = defaultdict(list)
    agreements = 0
    empty_values = []
    for _ in range(10000):
        begin = time.perf_counter_ns()
        end = time.perf_counter_ns()
        empty_values.append(end - begin)
    resource_mode = job.get("resource_only", False)
    before_cpu = time.process_time()
    with (output / "events.jsonl").open("x", encoding="utf-8", buffering=1024 * 1024, newline="\n") as events, \
            (output / "requests.csv").open("x", encoding="utf-8", buffering=1024 * 1024, newline="") as raw:
        writer = csv.writer(raw)
        writer.writerow(("request", "case_index", "latency_ns", "decision", "reference_agreement"))
        for number, index in enumerate(sequence):
            case = prepared[index]
            begin = time.perf_counter_ns() if not resource_mode else 0
            result = invoke(case, job["boundary"], events)
            elapsed = time.perf_counter_ns() - begin if not resource_mode else None
            if number >= job["warmup"]:
                agrees = result.decision.value == case["expected_decision"]
                agreements += agrees
                writer.writerow((number - job["warmup"], index, elapsed, result.decision.value, int(agrees)))
                if elapsed is not None:
                    values.append(elapsed)
                    groups[f'{case["action"]}/{case["stratum"]}'].append(elapsed)
            if number % 250 == 0:
                check_limits(started, output, wall=job["cell_wall_seconds"])
    current_rss, peak_rss = process_memory()
    result = {"version": VERSION, "status": "complete", "job": job,
              "timing": timing_summary(values), "by_action_path": {key: timing_summary(value) for key, value in groups.items()},
              "empty_timer_harness": timing_summary(empty_values), "empty_timer_subtracted": False,
              "reference_agreement_count": agreements, "reference_total": job["measured"],
              "cpu_seconds_including_instrumentation": time.process_time() - before_cpu,
              "resident_bytes": current_rss, "peak_resident_bytes": peak_rss,
              "memory_measurement": "separate_resource_run" if resource_mode else "technical_guard_only",
              "wall_seconds_including_setup": time.monotonic() - started,
              "timing_excludes": ["initialization", "final_buffer_flush", "raw_metrics_emission", "external_network_and_services"],
              "event_logging": "common buffered event writes; no fsync; not durable"}
    if job["method"] == "trust_boundary" and agreements != job["measured"]:
        result["status"] = "completed_with_reference_disagreement"
    return result


def _load_consumer(root_value: str, job: dict[str, Any], output_value: str,
                   requests: Any, stop: Any, ready: Any) -> None:
    """One independent evaluator process; no network socket or shared executor."""
    root, output = Path(root_value), Path(output_value)
    started = time.monotonic()
    try:
        source = load_workload(local_path(root, job["workloads"]), job["dataset"])
        cases = [scaling_case(case, job["state_size"], "no_conflict") for case in _compliant_bases(source)]
        prepared = runtime_cases(cases, read_json(root / "configs/paper_policy.json"), job["method"])
        completion_times: list[int] = []
        queue_times: list[int] = []
        service_times: list[int] = []
        counts: Counter[str] = Counter()
        cpu_start = time.process_time()
        finished_normally = False
        with (output / "completions.csv").open("x", encoding="utf-8", buffering=1024 * 1024, newline="") as raw, \
                (output / "events.jsonl").open("x", encoding="utf-8", buffering=1024 * 1024, newline="\n") as events:
            writer = csv.writer(raw)
            writer.writerow(("request", "phase", "case_index", "scheduled_ns", "enqueued_ns", "service_start_ns", "completed_ns", "decision", "reference_agreement"))
            ready.set()
            while not stop.is_set():
                if time.monotonic() - started > job["consumer_wall_seconds"]:
                    raise PerformanceError("load consumer wall-time bound reached")
                try:
                    message = requests.get(timeout=.05)
                except queue.Empty:
                    continue
                if message is None:
                    finished_normally = True
                    break
                number, phase, index, scheduled, enqueued = message
                case = prepared[index]
                service_start = time.perf_counter_ns()
                result = invoke(case, BOUNDARIES[1], events)
                completed = time.perf_counter_ns()
                agrees = result.decision.value == case["expected_decision"]
                writer.writerow((number, phase, index, scheduled, enqueued, service_start, completed, result.decision.value, int(agrees)))
                counts[phase] += 1
                if phase == "measurement":
                    counts["agreements"] += agrees
                    completion_times.append(completed - scheduled)
                    queue_times.append(service_start - enqueued)
                    service_times.append(completed - service_start)
                if sum(counts[phase] for phase in ("warmup", "measurement")) % 250 == 0:
                    check_limits(started, output, wall=job["consumer_wall_seconds"])
        current_rss, peak_rss = process_memory()
        write_json(output / "consumer_summary.json", {
            "status": "drained" if finished_normally else "stopped_with_pending_work",
            "completed_warmup": counts["warmup"], "completed_measurement": counts["measurement"],
            "reference_agreement_count": counts["agreements"], "completion_latency": timing_summary(completion_times),
            "queue_latency": timing_summary(queue_times), "service_latency": timing_summary(service_times),
            "illustrative_deadline_met_counts": {str(ms): sum(value <= ms * 1000000 for value in completion_times) for ms in (1, 10, 100)},
            "cpu_seconds": time.process_time() - cpu_start, "resident_bytes": current_rss,
            "peak_resident_bytes": peak_rss, "wall_seconds": time.monotonic() - started})
    except BaseException as error:
        try:
            write_json(output / "consumer_failure.json", {"status": "failed", "type": type(error).__name__,
                                                         "reason": str(error) if isinstance(error, PerformanceError) else "consumer execution failed"})
        finally:
            ready.set()
            stop.set()
        return


def _wait_scheduled(scheduled_ns: int) -> None:
    while True:
        remaining = (scheduled_ns - time.perf_counter_ns()) / 1e9
        if remaining <= 0:
            return
        time.sleep(min(remaining, .001))


def summarize_load_trace(output: Path, *, measurement_start_ns: int,
                         measurement_end_ns: int, drain_deadline_ns: int) -> dict[str, Any]:
    """Recompute endpoint counts using timestamps, excluding cleanup-grace work.

    Raw late completions are retained; they cannot rescue the declared drain
    endpoint. Outstanding-work high-water is a trace reconstruction, not the
    multiprocessing queue's private internal occupancy.
    """
    outstanding_events: list[tuple[int, int]] = []
    admitted_ids: set[int] = set()
    with (output / "arrivals.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["admitted"] == "1":
                when = int(row["attempted_enqueue_ns"])
                outstanding_events.append((when, 1))
                if row["phase"] == "measurement":
                    admitted_ids.add(int(row["request"]))
    latency, waiting, service = [], [], []
    completed_ids: set[int] = set()
    observed_ids: set[int] = set()
    late_ids: set[int] = set()
    agreement = completed_window = all_completed_window = 0
    with (output / "completions.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            number, end = int(row["request"]), int(row["completed_ns"])
            if number in observed_ids:
                raise PerformanceError("duplicate completion identifier")
            observed_ids.add(number)
            outstanding_events.append((end, -1))
            if measurement_start_ns <= end < measurement_end_ns:
                all_completed_window += 1
            if row["phase"] != "measurement":
                continue
            if number not in admitted_ids:
                raise PerformanceError("completion does not correspond to an admitted measurement request")
            if end > drain_deadline_ns:
                late_ids.add(number)
                continue
            completed_ids.add(number)
            agreement += int(row["reference_agreement"])
            completed_window += measurement_start_ns <= end < measurement_end_ns
            latency.append(end - int(row["scheduled_ns"]))
            waiting.append(int(row["service_start_ns"]) - int(row["enqueued_ns"]))
            service.append(end - int(row["service_start_ns"]))
    balance = high_water = 0
    for when, change in sorted(outstanding_events, key=lambda item: (item[0], -item[1])):
        if when > drain_deadline_ns:
            continue
        balance += change
        if balance < 0:
            raise PerformanceError("completion trace preceded its admission")
        high_water = max(high_water, balance)
    return {"completed_by_drain": len(completed_ids), "completed_after_drain": len(late_ids),
            "unfinished_or_admitted_too_late_at_drain": len(admitted_ids - completed_ids),
            "reference_agreement_count": agreement,
            "measurement_cohort_completed_inside_offering_window": completed_window,
            "all_phases_completed_inside_measurement_window": all_completed_window,
            "maximum_admitted_not_completed_from_trace": high_water,
            "completion_latency": timing_summary(latency), "queue_latency": timing_summary(waiting),
            "service_latency": timing_summary(service),
            "illustrative_deadline_met_counts": {str(ms): sum(value <= ms * 1000000 for value in latency) for ms in (1, 10, 100)}}


def load_worker(root: Path, job: dict[str, Any], output: Path) -> dict[str, Any]:
    """Open-loop producer in this process, evaluator in a separate process.

    The queue transports immutable case indexes and timestamps, not a network
    protocol. Results are streamed by the consumer, avoiding response-driven
    arrivals. Overflows and censored/unfinished requests remain in denominators.
    """
    started = time.monotonic()
    cases = _compliant_bases(load_workload(local_path(root, job["workloads"]), job["dataset"]))
    rate = job["rate"]
    warm_count = int(rate * job["warmup_seconds"])
    measured_count = int(rate * job["measurement_seconds"])
    sequence = make_sequence(cases, warm_count + measured_count, job["seed"], compliant_only=True)
    context = mp.get_context("spawn")
    requests = context.Queue(maxsize=job["queue_capacity"])
    stop, ready = context.Event(), context.Event()
    consumer = context.Process(target=_load_consumer, args=(str(root), job, str(output), requests, stop, ready))
    consumer.start()
    accepted: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    lateness_values: list[int] = []
    high_lateness = 0
    observed_max_queue = 0
    queue_size_supported = True
    producer_cpu = time.process_time()
    completed_schedule = False
    try:
        if not ready.wait(timeout=30) or stop.is_set() or not consumer.is_alive():
            raise PerformanceError("load consumer could not initialize")
        origin = time.perf_counter_ns() + 250000000
        # One 1 ms floor avoids classifying unavoidable nanosecond jitter as a
        # generator failure. The 2-arrival-interval and 1% thresholds are explicit
        # engineering diagnostics, not telecommunications standards.
        lateness_threshold_ns = max(1000000, math.ceil(2e9 / rate))
        with (output / "arrivals.csv").open("x", encoding="utf-8", buffering=1024 * 1024, newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(("request", "phase", "case_index", "scheduled_ns", "attempted_enqueue_ns", "admitted"))
            for number, index in enumerate(sequence):
                scheduled = origin + (number * 1000000000 // rate)
                _wait_scheduled(scheduled)
                actual = time.perf_counter_ns()
                phase = "warmup" if number < warm_count else "measurement"
                if stop.is_set() or not consumer.is_alive():
                    raise PerformanceError("load consumer stopped before arrival schedule completed")
                try:
                    requests.put_nowait((number, phase, index, scheduled, actual))
                    accepted[phase] += 1
                    admitted = True
                except queue.Full:
                    dropped[phase] += 1
                    admitted = False
                writer.writerow((number, phase, index, scheduled, actual, int(admitted)))
                if phase == "measurement":
                    lateness = max(0, actual - scheduled)
                    lateness_values.append(lateness)
                    high_lateness += lateness > lateness_threshold_ns
                if number % 100 == 0:
                    try:
                        observed_max_queue = max(observed_max_queue, requests.qsize())
                    except (NotImplementedError, OSError):
                        queue_size_supported = False
                if number % max(1, rate) == 0:
                    check_limits(started, output, wall=job["cell_wall_seconds"])
                    if process_memory(consumer.pid)[0] > MAX_RSS:
                        raise PerformanceError("load consumer resident-memory bound reached")
            completed_schedule = True
        measurement_start_ns = origin + round(job["warmup_seconds"] * 1e9)
        measurement_end_ns = measurement_start_ns + round(job["measurement_seconds"] * 1e9)
        deadline_ns = measurement_end_ns + round(job["drain_seconds"] * 1e9)
        sent_end = False
        while consumer.is_alive() and time.perf_counter_ns() < deadline_ns:
            if not sent_end:
                try:
                    requests.put_nowait(None)
                    sent_end = True
                except queue.Full:
                    pass
            consumer.join(timeout=.05)
        if consumer.is_alive():
            stop.set()
            consumer.join(timeout=5)
        if consumer.is_alive():
            consumer.terminate()
            consumer.join(timeout=5)
        if not (output / "consumer_summary.json").exists():
            raise PerformanceError("consumer failed without a completed measurement receipt")
        measured = read_json(output / "consumer_summary.json")
        if consumer.exitcode != 0:
            raise PerformanceError("consumer exited abnormally")
        bounded = summarize_load_trace(output, measurement_start_ns=measurement_start_ns,
                                       measurement_end_ns=measurement_end_ns, drain_deadline_ns=deadline_ns)
        completed = bounded["completed_by_drain"]
        unfinished = bounded["unfinished_or_admitted_too_late_at_drain"]
        if unfinished < 0 or accepted["measurement"] + dropped["measurement"] != measured_count:
            raise PerformanceError("offered/admitted/completed accounting mismatch")
        generator_limited = high_lateness / measured_count > .01
        result = {"version": VERSION, "status": "complete", "job": job,
            "scheduled_measurement": measured_count, "admitted_measurement": accepted["measurement"],
            "overflow_measurement": dropped["measurement"], "completed_measurement": completed,
            "unfinished_at_drain_bound": unfinished, "per_request_timeout_policy": "none; unfinished requests right-censored at bounded drain",
            "late_completions_during_cleanup_grace": bounded["completed_after_drain"],
            "offered_per_second": rate, "admitted_per_second": accepted["measurement"] / job["measurement_seconds"],
            "actual_measurement_cohort_completions_per_offering_second": bounded["measurement_cohort_completed_inside_offering_window"] / job["measurement_seconds"],
            "all_phase_completions_in_measurement_window_per_second": bounded["all_phases_completed_inside_measurement_window"] / job["measurement_seconds"],
            "completion_count_divided_by_offering_window": completed / job["measurement_seconds"],
            "throughput_caveat": "completions can include bounded drain; not steady-state capacity",
            "generator_limited": generator_limited, "generator_lateness": timing_summary(lateness_values),
            "generator_lateness_threshold_ns": lateness_threshold_ns, "generator_high_lateness_fraction": high_lateness / measured_count,
            "observed_max_queue": observed_max_queue if queue_size_supported else None,
            "queue_sampling": "every 100 offered requests; approximate sampled maximum, not exact high-water mark",
            "maximum_admitted_not_completed_from_trace": bounded["maximum_admitted_not_completed_from_trace"],
            "producer_cpu_seconds": time.process_time() - producer_cpu,
            "producer_peak_rss": process_memory()[1], "consumer_raw_summary_including_cleanup_grace": measured,
            "consumer_endpoint_metrics": bounded,
            "completion_latency_caveat": "percentiles describe completions only; losses and right-censored requests reported separately",
            "deadline_denominator": measured_count,
            "deadline_success_fractions": {key: value / measured_count for key, value in bounded["illustrative_deadline_met_counts"].items()},
            "wall_seconds": time.monotonic() - started, "network_traffic_generated": False}
        if bounded["reference_agreement_count"] != completed:
            result["status"] = "completed_with_reference_disagreement"
        return result
    finally:
        if consumer.is_alive():
            stop.set()
            consumer.join(timeout=2)
        if consumer.is_alive():
            consumer.terminate()
            consumer.join(timeout=5)
        requests.cancel_join_thread()
        requests.close()


def run_worker(root: Path, job_path: Path) -> dict[str, Any]:
    job = read_json(job_path)
    validate_job(job)
    if not job_path.relative_to(root).as_posix().startswith("results/evaluation_v0.2/") or job_path.name != "job.json":
        raise PerformanceError("worker jobs must be owned evaluation result files")
    output = job_path.parent
    result = load_worker(root, job, output) if job["mode"] == "load" else time_worker(root, job, output)
    write_json(output / "summary.json", result)
    return result


def validate_job(job: dict[str, Any]) -> None:
    """Fail closed before allocating a sequence or starting a child producer."""
    if not isinstance(job, dict) or job.get("version") != VERSION or job.get("mode") not in {"micro", "scaling", "load"}:
        raise PerformanceError("invalid performance worker job")
    if job.get("method") not in METHODS or job.get("dataset") not in {"netslab", "5gnidd"} or job.get("boundary") not in BOUNDARIES:
        raise PerformanceError("invalid comparator, workload or timing boundary")
    def bounded_integer(name: str, minimum: int, maximum: int) -> None:
        value = job.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise PerformanceError("invalid bounded job field: " + name)
    bounded_integer("seed", 0, 2**32 - 1)
    if not isinstance(job.get("cell_wall_seconds"), (int, float)) or not 1 <= job["cell_wall_seconds"] <= MAX_WALL:
        raise PerformanceError("invalid cell wall-time limit")
    if job["mode"] == "load":
        bounded_integer("rate", 1, 10000)
        bounded_integer("queue_capacity", 1, 10000)
        bounded_integer("state_size", 0, 1000)
        for name, upper in (("warmup_seconds", 60), ("measurement_seconds", 120), ("drain_seconds", 30), ("consumer_wall_seconds", 300)):
            value = job.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= upper:
                raise PerformanceError("invalid load duration: " + name)
        if job["rate"] * job["measurement_seconds"] < 1:
            raise PerformanceError("load measurement must schedule at least one request")
    else:
        bounded_integer("warmup", 0, 10000)
        bounded_integer("measured", 1, 100000)
        if job["mode"] == "scaling":
            bounded_integer("state_size", 0, 1000)
            if job.get("state_path") not in {"no_conflict", "conflict_first", "conflict_last", "malformed_last"}:
                raise PerformanceError("invalid state path")
            if job["state_size"] == 0 and job["state_path"] != "no_conflict":
                raise PerformanceError("zero-state conflict path is inapplicable")
            if type(job.get("resource_only")) is not bool or type(job.get("large_input")) is not bool:
                raise PerformanceError("scaling mode flags must be booleans")


def _job_groups(design: dict[str, Any], mode: str, dataset: str, workloads: str,
                *, block_start: int = 0, block_stop: int | None = None,
                state_size: int | None = None, rate: int | None = None) -> list[list[dict[str, Any]]]:
    limits = design["technical_resource_limits"]
    groups = []
    seed_name = {"micro": "timing_order", "scaling": "state_scaling_order", "load": "arrival_schedule_order"}[mode]
    all_seeds = design["seeds"][seed_name]
    stop = len(all_seeds) if block_stop is None else block_stop
    if not 0 <= block_start < stop <= len(all_seeds):
        raise PerformanceError("invalid predeclared process-block partition")
    for block in range(block_start, stop):
        seed = all_seeds[block]
        common = {"version": VERSION, "mode": mode, "dataset": dataset, "workloads": workloads,
                  "block": block, "seed": seed, "cell_wall_seconds": min(600, limits["maximum_wall_seconds_per_offline_runner"])}
        block_jobs = []
        if mode == "micro":
            spec = design["performance"]
            for boundary in spec["boundaries"]:
                block_jobs.extend({**common, "method": method, "boundary": boundary,
                                   "warmup": spec["warmup_requests_per_method_block"],
                                   "measured": spec["measured_requests_per_method_block"]} for method in METHODS)
        elif mode == "scaling":
            spec = design["state_scaling"]
            sizes = spec["active_action_counts"] if state_size is None else [state_size]
            if any(size not in spec["active_action_counts"] for size in sizes):
                raise PerformanceError("state size is not in the frozen design")
            for size in sizes:
                for path in spec["paths"]:
                    if size == 0 and path != "no_conflict":
                        continue
                    for large in ([False, True] if size == 0 else [False]):
                        for resource_only in (False, True):
                            block_jobs.extend({**common, "method": method, "boundary": BOUNDARIES[0],
                                "warmup": spec["warmup_requests"], "measured": spec["measured_requests"],
                                "state_size": size, "state_path": path, "large_input": large,
                                "resource_only": resource_only} for method in METHODS)
        else:
            spec = design["offered_load"]
            rates = spec["proposals_per_second"] if rate is None else [rate]
            if any(value not in spec["proposals_per_second"] for value in rates):
                raise PerformanceError("offered rate is not in the frozen design")
            for offered in rates:
                block_jobs.extend({**common, "method": method, "rate": offered,
                    "boundary": BOUNDARIES[1], "state_size": spec["active_nonconflicting_actions"],
                    "queue_capacity": spec["queue_capacity"], "warmup_seconds": spec["warmup_seconds"],
                    "measurement_seconds": spec["measurement_seconds"], "drain_seconds": spec["maximum_drain_seconds"],
                    "consumer_wall_seconds": spec["warmup_seconds"] + spec["measurement_seconds"] + spec["maximum_drain_seconds"] + 35}
                                  for method in spec["comparators"])
        random.Random(seed).shuffle(block_jobs)
        groups.append(block_jobs)
    return groups


def aggregate_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[int, dict[str, dict[str, Any]]]] = defaultdict(lambda: defaultdict(dict))
    for result in results:
        job = result["job"]
        if job["mode"] == "load" or job.get("resource_only"):
            continue
        key = canonical({name: job.get(name) for name in ("mode", "dataset", "boundary", "state_size", "state_path", "large_input")})
        grouped[key][job["block"]][job["method"]] = result
    comparisons = []
    for key, blocks in sorted(grouped.items()):
        for comparator in ("direct", "contract_rbac"):
            for percentile_name in ("p50_ns", "p95_ns", "p99_ns"):
                differences, ratios = [], []
                for block in blocks.values():
                    if "trust_boundary" in block and comparator in block:
                        full = block["trust_boundary"]["timing"][percentile_name]
                        baseline = block[comparator]["timing"][percentile_name]
                        if full is not None and baseline is not None:
                            differences.append(full - baseline)
                            if baseline > 0:
                                ratios.append(full / baseline)
                comparisons.append({"condition": json.loads(key), "baseline": comparator, "statistic": percentile_name,
                    "absolute_added_ns": bootstrap_paired(differences), "slowdown_ratio": bootstrap_paired(ratios),
                    "interpretation": "mean paired process-block difference of percentiles; not percentile of per-request added time"})
    return {"version": VERSION, "completed_cells": len(results), "comparisons": comparisons,
            "inference_unit": "fresh process block", "bootstrap_draws": BOOTSTRAP_DRAWS, "analysis_seed": ANALYSIS_SEED,
            "limits": "local computational experiment; no hard real-time, production throughput or O-RAN interoperability claim"}


def run_experiment(root: Path, design_path: Path, workloads: Path, output: Path, mode: str,
                   dataset: str, *, block_start: int = 0, block_stop: int | None = None,
                   state_size: int | None = None, rate: int | None = None) -> dict[str, Any]:
    started = time.monotonic()
    design = read_json(design_path)
    process_memory()  # Fail preflight rather than silently omitting memory bounds.
    limits = design["technical_resource_limits"]
    if shutil.disk_usage(output).free < limits["minimum_free_disk_bytes_before_large_runs"]:
        raise PerformanceError("insufficient free disk for the predeclared run")
    load_workload(workloads, dataset)
    workload_manifest_hash = file_hash(workloads / "manifest.json")
    design_hash = file_hash(design_path)
    groups = _job_groups(design, mode, dataset, workloads.relative_to(root).as_posix(),
                         block_start=block_start, block_stop=block_stop, state_size=state_size, rate=rate)
    jobs = [job for group in groups for job in group]
    for job in jobs:
        validate_job(job)
    write_json(output / "run_plan.json", {"version": VERSION, "output_monitor_version": OUTPUT_MONITOR_VERSION,
        "created_at_utc": utc_now(), "environment": environment(),
        "design_sha256": design_hash, "workload_manifest_sha256": workload_manifest_hash,
        "requested_partition": {"mode": mode, "dataset": dataset, "block_start": block_start,
                                "block_stop": block_stop, "state_size": state_size, "rate": rate},
        "jobs": jobs, "bootstrap_draws": BOOTSTRAP_DRAWS, "analysis_seed": ANALYSIS_SEED,
        "interpretation": "Completion applies to this explicit partition, not all protocol stages."})
    results = []
    script = root / "scripts" / "run_performance_v02.py"
    with (output / "progress.jsonl").open("x", encoding="utf-8", newline="\n") as progress:
        for number, job in enumerate(jobs):
            check_limits(started, output, wall=limits["maximum_wall_seconds_per_offline_runner"],
                         rss=limits["maximum_worker_rss_bytes"], disk=limits["maximum_new_output_bytes_per_run"])
            remaining = limits["maximum_wall_seconds_per_offline_runner"] - (time.monotonic() - started)
            required = (job["consumer_wall_seconds"] + 35) if mode == "load" else 10
            if remaining < required:
                raise PerformanceError("insufficient bounded time to start next cell; retain this partition and use a new subrun")
            cell = output / f"cell_{number:04d}"
            cell.mkdir()
            write_json(cell / "job.json", job)
            event = {"event": "started", "cell": cell.name, "ordinal": number + 1, "total": len(jobs), "at": utc_now()}
            progress.write(canonical(event) + "\n")
            progress.flush()
            print(canonical(event), flush=True)
            environment_values = dict(os.environ)
            environment_values["PYTHONHASHSEED"] = str(job["seed"])
            with (cell / "stdout.log").open("x", encoding="utf-8") as stdout, (cell / "stderr.log").open("x", encoding="utf-8") as stderr:
                child = subprocess.Popen([sys.executable, "-B", str(script), "worker", "--job", str((cell / "job.json").relative_to(root))],
                                         cwd=root, env=environment_values, stdout=stdout, stderr=stderr,
                                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                cell_started = time.monotonic()
                try:
                    while child.poll() is None:
                        time.sleep(.1)
                        check_limits(started, output, wall=limits["maximum_wall_seconds_per_offline_runner"],
                                     rss=limits["maximum_worker_rss_bytes"], disk=limits["maximum_new_output_bytes_per_run"])
                        if time.monotonic() - cell_started > job["cell_wall_seconds"]:
                            raise PerformanceError("child cell exceeded its predeclared wall-time bound")
                        if child.poll() is None and process_memory(child.pid)[0] > limits["maximum_worker_rss_bytes"]:
                            raise PerformanceError("child resident-memory bound reached")
                finally:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait(timeout=5)
            if child.returncode != 0 or not (cell / "summary.json").exists():
                raise PerformanceError("child failed; raw cell artifacts retained")
            result = read_json(cell / "summary.json")
            results.append(result)
            event = {"event": "completed", "cell": cell.name, "ordinal": number + 1, "total": len(jobs),
                     "at": utc_now(), "status": result["status"]}
            progress.write(canonical(event) + "\n")
            progress.flush()
            print(canonical(event), flush=True)
        if design_hash != file_hash(design_path) or workload_manifest_hash != file_hash(workloads / "manifest.json"):
            raise PerformanceError("design or workload manifest changed during measurement")
        load_workload(workloads, dataset)  # Also recheck actual prepared case bytes.
    summary = aggregate_results(results)
    summary.update(status="complete" if all(result["status"] == "complete" for result in results) else "completed_with_reference_disagreement",
                   output_monitor_version=OUTPUT_MONITOR_VERSION,
                   design_status=design.get("status"),
                   scientific_scope="PILOT_NOT_CONFIRMATORY" if "pilot" in str(design.get("status", "")).lower() else "PREDECLARED_EVALUATION_PARTITION",
                   planned_cells=len(jobs), wall_seconds=time.monotonic() - started,
                   cell_summaries=[{"directory": f"cell_{number:04d}", "status": result["status"]} for number, result in enumerate(results)])
    write_json(output / "summary.json", summary)
    return summary
