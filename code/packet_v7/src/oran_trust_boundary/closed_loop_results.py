"""Offline, send-cohort scoring; ground truth is allowed only in this module."""
from __future__ import annotations

import math
from pathlib import Path
from statistics import fmean
from typing import Any

from .jsonio import strict_json_loads

SCENARIOS = ("persistent_flood", "benign_burst", "ineffective_action")


def read_jsonl(path: Path, *, completed: bool = False) -> list[dict[str, Any]]:
    if not path.exists():
        if completed:
            raise ValueError("Required worker log is missing")
        return []
    if path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Worker log exceeds lab bounds or is a symlink")
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        if completed:
            raise ValueError("Incomplete worker log")
        lines = lines[:-1]
    records = [strict_json_loads(line, maximum_bytes=16 * 1024 * 1024) for line in lines if line.strip()]
    if any(not isinstance(row, dict) for row in records):
        raise ValueError("Worker records must be JSON objects")
    return records


def check_offered_load(records: list[dict[str, Any]], duration: float,
                       offered_schedule: list[dict[str, Any]]) -> dict[str, Any]:
    """Reject technical under-generation, not poor mitigation or packet loss.

    Ten-percent pacing tolerance is an illustrative pilot acceptance bound,
    frozen before packet execution. It must be revisited only in a new version.
    """
    summaries = [row for row in records if row.get("type") == "cohort_summary"]
    if len(summaries) != 1:
        raise ValueError("Missing final traffic accounting")
    summary = summaries[0]
    planned = sum((row["end"] - row["start"]) * row["pps"] for row in offered_schedule)
    actual = sum(row["sent"] for row in summary["cohorts"])
    if not 0.9 * planned <= actual <= 1.02 * planned:
        raise ValueError("Technical workload pacing outside frozen tolerance; retain failed run")
    if summary["cohorts"][-1]["window_end"] != duration:
        raise ValueError("Worker did not account for the complete episode")
    window_quality = []
    for cohort in summary["cohorts"]:
        expected = sum(max(0, min(cohort["window_end"], phase["end"])
                           - max(cohort["window_start"], phase["start"])) * phase["pps"]
                       for phase in offered_schedule)
        if not max(0, 0.9 * expected - 1) <= cohort["sent"] <= 1.02 * expected + 1:
            raise ValueError("Technical per-window pacing failure; do not hide a missed burst in totals")
        window_quality.append({"window_start": cohort["window_start"], "planned_packets": expected,
                               "actually_sent": cohort["sent"]})
    counters = summary.get("counters", {})
    if any(counters.get(key, 0) != 0 for key in
           ("send_errors", "receive_errors", "malformed", "unknown_replies")):
        raise ValueError("Worker transport/accounting error; retain failed run")
    return {"planned_packets": planned, "actually_sent": actual,
            "offered_fraction": actual / planned, "counters": counters,
            "windows": window_quality,
            "acceptance": "at_least_90_percent_of_planned_no_transport_errors"}


def score_server(records: list[dict[str, Any]], clients: dict[str, list[dict[str, Any]]],
                 duration: float, packet_bytes: int) -> dict[str, Any]:
    summaries = [row for row in records if row.get("type") == "server_summary"]
    if len(summaries) != 1 or summaries[0].get("invalid") != 0:
        raise ValueError("Server measurement incomplete or contains invalid datagrams")
    output = {}
    for role in ("legitimate", "suspect"):
        receiver = summaries[0]["sources"][role]
        summary = next(row for row in clients[role] if row.get("type") == "cohort_summary")
        count = receiver["received"]
        if (type(count) is not int or type(receiver["echoed"]) is not int
                or not 0 <= summary["received"] <= receiver["echoed"] <= count <= summary["sent"]
                or receiver["received_bytes"] != count * packet_bytes
                or receiver["echo_errors"] != 0):
            raise ValueError("Server/client accounting mismatch or echo transport failure")
        output[role] = {"received_datagrams": count, "received_payload_bytes": receiver["received_bytes"],
                        "receiver_payload_kbit_per_offered_second": receiver["received_bytes"] * 8 / duration / 1000}
    return {"scope": "whole_offered_episode_including_drain_receipts_not_event_interval", "sources": output}


def percentile(values: list[float], fraction: float = 0.95) -> float | None:
    """Nearest-rank percentile, explicitly conditional on received replies."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def score_cohorts(records: list[dict[str, Any]], start: float, end: float,
                  packet_bytes: int) -> dict[str, Any]:
    summaries = [r for r in records if r.get("type") == "cohort_summary"]
    if len(summaries) != 1:
        raise ValueError("Exactly one completed send-cohort summary is required")
    cohorts = [r for r in summaries[0]["cohorts"]
               if start <= r["window_start"] and r["window_end"] <= end]
    expected = list(range(int(start), int(end)))
    if start != int(start) or end != int(end) or [r["window_start"] for r in cohorts] != expected:
        raise ValueError("Scoring requires every one-second send cohort in the fixed interval")
    sent = received = 0
    rtts: list[float] = []
    for row in cohorts:
        if row["window_end"] - row["window_start"] != 1:
            raise ValueError("Unexpected cohort duration")
        if any(type(row[k]) is not int for k in ("sent", "received")):
            raise ValueError("Invalid packet count")
        if not 0 <= row["received"] <= row["sent"] <= 1000:
            raise ValueError("Invalid packet count")
        if len(row["rtt_ms"]) != row["received"]:
            raise ValueError("RTT count does not match received packets")
        if any(isinstance(x, bool) or not isinstance(x, (int, float))
               or not math.isfinite(x) or x < 0 for x in row["rtt_ms"]):
            raise ValueError("Invalid latency")
        sent += row["sent"]
        received += row["received"]
        rtts.extend(row["rtt_ms"])
    timely = sum(x <= 500 for x in rtts)
    return {"sent": sent, "received": received, "lost_after_drain": sent - received,
            "timely_500ms": timely,
            "delivery_ratio": received / sent if sent else None,
            "timely_delivery_ratio": timely / sent if sent else None,
            "echo_goodput_kbit_s": received * packet_bytes * 8 / (end - start) / 1000,
            "rtt_p95_ms_received_only": percentile(rtts),
            "deadline_miss_ratio": (sent - timely) / sent if sent else None}


def paired_pilot_summary(episodes: list[dict[str, Any]]) -> dict[str, Any]:
    """Descriptive paired pilot deltas only; packets are not replicates."""
    output: dict[str, Any] = {"status": "PILOT_NOT_CONFIRMATORY", "comparisons": []}
    for scenario in SCENARIOS:
        reference = {x["replicate"]: x for x in episodes
                     if x["scenario"] == scenario and x["method"] == "no_action"}
        for method in ("fixed_rule", "current_gate", "evidence_feedback"):
            members = [x for x in episodes if x["scenario"] == scenario and x["method"] == method]
            differences = []
            collateral = []
            for item in members:
                base = reference.get(item["replicate"])
                if base is None:
                    raise ValueError("Missing paired no-action episode")
                left = item["legitimate"]["timely_delivery_ratio"]
                right = base["legitimate"]["timely_delivery_ratio"]
                if left is None or right is None:
                    raise ValueError("Empty legitimate workload cannot be scored")
                differences.append(left - right)
                collateral.append(item["suspect"]["echo_goodput_kbit_s"]
                                  - base["suspect"]["echo_goodput_kbit_s"])
            if differences:
                output["comparisons"].append({
                    "scenario": scenario, "method": method, "paired_episodes": len(differences),
                    "mean_delta_legitimate_timely_delivery": fmean(differences),
                    "paired_deltas": differences,
                    "mean_delta_suspect_goodput_kbit_s": fmean(collateral),
                    "suspect_is_benign": scenario == "benign_burst",
                    "confidence_interval": None,
                    "inference_note": "Descriptive pilot. Freeze a confirmatory design; no population or independent-packet inference.",
                })
    return output
