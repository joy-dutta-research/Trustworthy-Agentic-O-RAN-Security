"""Benchmark runner and metric calculations."""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .audit import completeness
from .baselines import contract_only, contract_rbac, direct_execution
from .engine import TrustBoundary
from .models import EvaluationResult
from .jsonio import StrictJsonError, strict_json_loads


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    input_path = Path(path)
    if input_path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("conformance suite exceeds 50 MiB")
    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                case = strict_json_loads(line, maximum_bytes=1024 * 1024)
                if not isinstance(case, dict):
                    raise ValueError("each conformance case must be an object")
                cases.append(case)
            except (StrictJsonError, ValueError) as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc}") from exc
    if not cases:
        raise ValueError("conformance suite is empty")
    case_ids = [case["case_id"] for case in cases]
    duplicates = [item for item, count in Counter(case_ids).items() if count > 1]
    if duplicates:
        raise ValueError(f"duplicate case IDs: {duplicates}")
    return cases


def percentile(values: list[int], percentage: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * percentage
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Return the two-sided Wilson score interval for a binomial proportion."""

    if total == 0:
        return 0.0, 0.0
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total + z * z / (4 * total * total)
        )
        / denominator
    )
    lower = 0.0 if successes == 0 else max(0.0, centre - margin)
    upper = 1.0 if successes == total else min(1.0, centre + margin)
    return lower, upper


def _evaluate_timed(
    evaluator: Callable[..., EvaluationResult],
    case: dict[str, Any],
    repeats: int,
) -> tuple[EvaluationResult, list[int]]:
    as_of = datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))
    kwargs = {
        "active_actions": case["active_actions"],
        "authenticated_principal": case["authenticated_principal"],
        "as_of": as_of,
    }
    for _ in range(5):
        evaluator(case["proposal"], **kwargs)
    samples: list[int] = []
    result: EvaluationResult | None = None
    for _ in range(repeats):
        started = time.perf_counter_ns()
        result = evaluator(case["proposal"], **kwargs)
        samples.append(time.perf_counter_ns() - started)
    if result is None:
        raise RuntimeError("evaluator did not return a result")
    return result, samples


def _summarize(
    system: str,
    rows: list[dict[str, Any]],
    all_latency_samples: list[int],
) -> dict[str, Any]:
    total = len(rows)
    safe = [row for row in rows if row["expected_decision"] == "ALLOW"]
    deny = [row for row in rows if row["expected_decision"] == "DENY"]
    escalate = [row for row in rows if row["expected_decision"] == "ESCALATE"]
    unsafe = deny + escalate

    def rate(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    total_seconds = sum(all_latency_samples) / 1_000_000_000
    accuracy_successes = sum(row["correct"] for row in rows)
    safe_successes = sum(row["actual_decision"] == "ALLOW" for row in safe)
    unsafe_admissions = sum(row["actual_decision"] == "ALLOW" for row in unsafe)
    deny_successes = sum(row["actual_decision"] == "DENY" for row in deny)
    escalate_successes = sum(
        row["actual_decision"] == "ESCALATE" for row in escalate
    )
    accuracy_ci = wilson_interval(accuracy_successes, total)
    safe_ci = wilson_interval(safe_successes, len(safe))
    unsafe_ci = wilson_interval(unsafe_admissions, len(unsafe))
    deny_ci = wilson_interval(deny_successes, len(deny))
    escalate_ci = wilson_interval(escalate_successes, len(escalate))
    return {
        "system": system,
        "case_count": total,
        "correct_decision_count": accuracy_successes,
        "decision_accuracy": rate(accuracy_successes, total),
        "decision_accuracy_ci95_low": accuracy_ci[0],
        "decision_accuracy_ci95_high": accuracy_ci[1],
        "safe_case_count": len(safe),
        "safe_action_accepted_count": safe_successes,
        "safe_action_acceptance_rate": rate(safe_successes, len(safe)),
        "safe_action_acceptance_ci95_low": safe_ci[0],
        "safe_action_acceptance_ci95_high": safe_ci[1],
        "unsafe_case_count": len(unsafe),
        "unsafe_action_admitted_count": unsafe_admissions,
        "unsafe_action_admission_rate": rate(unsafe_admissions, len(unsafe)),
        "unsafe_action_admission_ci95_low": unsafe_ci[0],
        "unsafe_action_admission_ci95_high": unsafe_ci[1],
        "deny_case_count": len(deny),
        "correct_denial_count": deny_successes,
        "correct_denial_rate": rate(deny_successes, len(deny)),
        "correct_denial_ci95_low": deny_ci[0],
        "correct_denial_ci95_high": deny_ci[1],
        "escalate_case_count": len(escalate),
        "correct_escalation_count": escalate_successes,
        "correct_escalation_rate": rate(escalate_successes, len(escalate)),
        "correct_escalation_ci95_low": escalate_ci[0],
        "correct_escalation_ci95_high": escalate_ci[1],
        "latency_p50_ms": percentile(all_latency_samples, 0.50) / 1_000_000,
        "latency_p95_ms": percentile(all_latency_samples, 0.95) / 1_000_000,
        "latency_sample_count": len(all_latency_samples),
        "throughput_actions_per_second": (
            len(all_latency_samples) / total_seconds if total_seconds else 0.0
        ),
        "audit_completeness": statistics.fmean(
            row["audit_completeness"] for row in rows
        ),
    }


def run_benchmark(
    cases: Iterable[dict[str, Any]],
    engine: TrustBoundary,
    *,
    repeats: int,
    timing_seed: int = 20260922,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    cases = list(cases)
    evaluators: tuple[tuple[str, Callable[..., EvaluationResult]], ...] = (
        ("direct", direct_execution),
        ("contract", contract_only),
        (
            "contract_rbac",
            lambda proposal, **kwargs: contract_rbac(
                proposal,
                policy=engine.policy,
                **kwargs,
            ),
        ),
        ("trust_boundary", engine.evaluate),
    )
    rows_by_system: dict[str, list[dict[str, Any]]] = {
        system: [] for system, _ in evaluators
    }
    latency_by_system: dict[str, list[int]] = {
        system: [] for system, _ in evaluators
    }
    required_audit_fields = engine.policy["audit_required_fields"]

    # Randomize evaluation blocks to reduce systematic warm-cache and system-order
    # bias. The seed is recorded and does not affect policy decisions.
    tasks = [
        (system, evaluator, case)
        for system, evaluator in evaluators
        for case in cases
    ]
    random.Random(timing_seed).shuffle(tasks)
    for system, evaluator, case in tasks:
        result, samples = _evaluate_timed(evaluator, case, repeats)
        latency_by_system[system].extend(samples)
        rows_by_system[system].append(
            {
                "suite_version": case["suite_version"],
                "case_id": case["case_id"],
                "category": case["category"],
                "system": system,
                "expected_decision": case["expected_decision"],
                "expected_reason": case["expected_reason"],
                "actual_decision": result.decision.value,
                "actual_reasons": list(result.reason_codes),
                "policy_ids": list(result.policy_ids),
                "correct": result.decision.value == case["expected_decision"],
                "expected_reason_observed": case["expected_reason"] in result.reason_codes,
                "latency_ns_median": int(statistics.median(samples)),
                "latency_samples_ns": samples,
                "audit_completeness": completeness(
                    result.audit_record, required_audit_fields
                ),
                "audit_record": result.audit_record,
            }
        )

    raw_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for system, _ in evaluators:
        system_rows = sorted(rows_by_system[system], key=lambda row: row["case_id"])
        raw_rows.extend(system_rows)
        summaries.append(_summarize(system, system_rows, latency_by_system[system]))
    return raw_rows, summaries


def write_results(
    raw_rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    output_directory: str | Path,
) -> tuple[Path, Path]:
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / "raw_decisions.jsonl"
    summary_path = output / "summary.csv"

    with raw_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in raw_rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    fieldnames = list(summaries[0]) if summaries else []
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summaries)
    return raw_path, summary_path
