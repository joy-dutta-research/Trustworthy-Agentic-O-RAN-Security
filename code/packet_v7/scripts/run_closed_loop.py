"""Opt-in isolated Linux packet pilot; default/preflight never actuates.

No API access, live LLM, trained IDS, radio stack, or production interface.
Run only in a disposable Linux VM/lab host after reviewing the protocol.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import json
from pathlib import Path
import platform
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.closed_loop import METHODS, Observation, ReferenceController, Settings
from oran_trust_boundary.closed_loop_lab import preflight
from oran_trust_boundary.stable_linux_lab import StableLinuxLab as LinuxLab
from oran_trust_boundary.closed_loop_results import (SCENARIOS, check_offered_load,
                                                    paired_pilot_summary, read_jsonl, score_cohorts, score_server)
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.jsonio import strict_json_load
from oran_trust_boundary.provenance import combined_manifest_sha256, sha256_file, source_manifest
from run_5gnidd import FROZEN_FILES


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def schedule(settings, scenario):
    # This generation metadata is never passed to ReferenceController.step.
    stop = (settings.event_start + settings.benign_burst_seconds
            if scenario == "benign_burst" else settings.event_end)
    return [{"start": 0, "end": settings.event_start, "pps": settings.background_pps},
            {"start": settings.event_start, "end": stop, "pps": settings.flood_pps},
            {"start": stop, "end": settings.duration_seconds, "pps": settings.background_pps}]


def episode(directory, settings, scenario, method, replicate):
    directory.mkdir(exist_ok=False)
    gate = TrustBoundary.from_file(ROOT / "configs/paper_policy.json")
    controller = ReferenceController(method, settings, gate)
    events = []
    observations = []
    last_end = -1
    audit_path = directory / "controller.jsonl"
    with audit_path.open("x", encoding="utf-8", newline="\n") as audit:
        def log(record):
            audit.write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
            audit.flush()

        with LinuxLab(directory, capacity_kbit=settings.capacity_kbit,
                      packet_bytes=settings.packet_bytes) as lab:
            traffic = lab.start_traffic(duration_seconds=settings.duration_seconds,
                                        suspect_schedule=schedule(settings, scenario),
                                        legitimate_pps=settings.legitimate_pps, seed=replicate)
            started = traffic["started_at"]
            paths = {key: Path(value) for key, value in traffic["paths"].items()}

            def perform(decision, now):
                event = {"at_seconds": now, "decision": decision}
                log({"type": "decision_before_dispatch", **event})
                if decision["kind"] == "apply":
                    controller.validate_dispatch(time.monotonic() - started)
                    if scenario == "ineffective_action":
                        # An explicit, recorded actuator fault. NOT supplied to
                        # the controller, and never used to manufacture KPIs.
                        event["actuator"] = {"fault_injection": "acknowledged_noop",
                                             "configuration_changed": False}
                    else:
                        event["actuator"] = lab.apply_limit(settings.reduction_percent)
                    controller.applied(time.monotonic() - started)
                elif decision["kind"] == "restore":
                    before = time.monotonic()
                    event["actuator"] = lab.restore()
                    event["restore_command_seconds"] = time.monotonic() - before
                    controller.restored()
                    event["operator_review_required"] = decision["reason"] not in ("ACTION_TTL_EXPIRED", "EPISODE_END")
                events.append(event)
                log({"type": "decision", **event})

            while time.monotonic() < started + settings.duration_seconds + 0.8:
                now = time.monotonic() - started
                expiry = controller.watchdog(now)
                if expiry:
                    perform(expiry, now)
                left = {row["window_end"]: row for row in read_jsonl(paths["legitimate"])
                        if row.get("type") == "window"}
                right = {row["window_end"]: row for row in read_jsonl(paths["suspect"])
                         if row.get("type") == "window"}
                for end in sorted(set(left) & set(right)):
                    if end <= last_end:
                        continue
                    a, b = left[end], right[end]
                    if any(row.get("measurement_semantics") != "send_cohort_500ms" for row in (a, b)):
                        raise ValueError("Worker telemetry is not matched send-cohort evidence")
                    if a["window_start"] != b["window_start"]:
                        raise ValueError("Worker cohort windows do not align")
                    observation = Observation(a["window_start"], end, a["sent"], a["received"], b["sent"])
                    now = time.monotonic() - started
                    observations.append(asdict(observation))
                    log({"type": "observation", "at_seconds": now, **asdict(observation)})
                    perform(controller.step(observation, now=now, utc_now=datetime.now(UTC)), now)
                    last_end = end
                time.sleep(0.05)
            if controller.applied_at is not None:
                perform({"kind": "restore", "reason": "EPISODE_END"}, time.monotonic() - started)
            completion = lab.finish()
            # Context teardown is a further backstop, not reported as successful
            # feedback or rollback. Readback failure aborts the measured run.
            final_readback = lab.restore()
        legitimate_records = read_jsonl(paths["legitimate"], completed=True)
        suspect_records = read_jsonl(paths["suspect"], completed=True)
        quality = {"legitimate": check_offered_load(legitimate_records, settings.duration_seconds,
                        [{"start": 0, "end": settings.duration_seconds, "pps": settings.legitimate_pps}]),
                   "suspect": check_offered_load(suspect_records, settings.duration_seconds, schedule(settings, scenario))}
        server_measurement = score_server(read_jsonl(paths["server"], completed=True),
                                         {"legitimate": legitimate_records, "suspect": suspect_records},
                                         settings.duration_seconds, settings.packet_bytes)
        # Public artifacts must not retain the user's absolute output directory.
        completion["paths"] = {role: Path(path).name for role, path in completion["paths"].items()}
        result = {"scenario": scenario, "method": method, "replicate": replicate,
                  "status": "MEASURED_REFERENCE_CONTROLLER_PILOT",
                  "legitimate": score_cohorts(legitimate_records,
                                             settings.event_start, settings.event_end, settings.packet_bytes),
                  "suspect": score_cohorts(suspect_records,
                                         settings.event_start, settings.event_end, settings.packet_bytes),
                  "intervention_attempts": sum(x["decision"]["kind"] == "apply" for x in events),
                  "restore_events": [x for x in events if x["decision"]["kind"] == "restore"],
                  "worker_completion": completion, "final_readback": final_readback, "traffic_quality": quality,
                  "server_whole_episode": server_measurement,
                  "scenario_labels_visible_to_controller": False,
                  "live_model_evaluated": False, "oran_interface_exercised": False}
        write_json(directory / "metrics.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", help="Read-only runtime inventory")
    parser.add_argument("--execute-isolated-lab", action="store_true", help="Opt in to bounded namespace actuation")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/closed_loop_pilot.json")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--order-seed", type=int, default=220926)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight(), indent=2, sort_keys=True))
        return 0
    if not args.execute_isolated_lab:
        parser.error("Default is non-actuating. Use --preflight, or explicitly opt in inside an isolated Linux lab.")
    if not 1 <= args.repetitions <= 30 or not 0 <= args.order_seed < 2**32:
        parser.error("Repetitions must be 1..30; order seed must be an unsigned 32-bit integer")
    environment = preflight()
    if not environment["ready"]:
        print(json.dumps({"status": "NOT_RUN", "preflight": environment}, indent=2))
        return 2
    settings = Settings.from_mapping(strict_json_load(args.config, maximum_bytes=16384))
    for filename, expected in FROZEN_FILES.items():
        if sha256_file(ROOT / filename) != expected:
            raise ValueError("Frozen original comparator changed: " + filename)
    base = (ROOT / "results/local").resolve()
    output = (args.output or base / ("closed_loop_pilot_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))).resolve()
    if not output.is_relative_to(base) or output == base:
        parser.error("Output must be a new child directory of repository results/local")
    output.mkdir(parents=True, exist_ok=False)
    sources = source_manifest(ROOT)
    jobs = [{"replicate": replicate, "scenario": scenario, "method": method}
            for replicate in range(args.repetitions) for scenario in SCENARIOS for method in METHODS]
    random.Random(args.order_seed).shuffle(jobs)
    manifest = {"status": "STARTED_NOT_COMPLETE", "settings": asdict(settings),
                "settings_sha256": sha256_file(args.config), "source_files": sources,
                "source_tree_sha256": combined_manifest_sha256(sources),
                "environment": {"python": platform.python_version(), "kernel": platform.release(),
                                "machine": platform.machine(), "preflight": environment},
                "planner": "deterministic_reference_controller_not_LLM",
                "order_seed": args.order_seed, "randomness_scope": "execution_order_only",
                "jobs": jobs, "live_model_evaluated": False, "oran_interface_exercised": False}
    manifest["environment"]["preflight"]["tools"] = {name: Path(path).name if path else None
                                                     for name, path in environment["tools"].items()}
    write_json(output / "run_plan.json", manifest)
    results = []
    try:
        for index, job in enumerate(jobs):
            print(f"Episode {index + 1}/{len(jobs)}: {job['scenario']} / {job['method']}", flush=True)
            results.append(episode(output / f"episode_{index:04d}", settings, **job))
        if source_manifest(ROOT) != sources or sha256_file(args.config) != manifest["settings_sha256"]:
            raise ValueError("Source or settings changed during measurement")
        write_json(output / "episodes.json", results)
        summary = paired_pilot_summary(results)
        write_json(output / "summary.json", summary)
        report = ["# Closed-loop reference-controller pilot", "", "Status: MEASURED PILOT; not confirmatory.", "",
                  "Actual namespace packets and Linux traffic control; no live LLM, detector benchmark, radio stack, or E2 actuation.", "",
                  "| Scenario | Method | Paired episodes | Mean change in legitimate 500-ms delivery | Suspect echoed goodput change (kbit/s) |",
                  "|---|---|---:|---:|---:|"]
        for row in summary["comparisons"]:
            report.append(f"| {row['scenario']} | {row['method']} | {row['paired_episodes']} | "
                          f"{row['mean_delta_legitimate_timely_delivery']:+.4f} | {row['mean_delta_suspect_goodput_kbit_s']:+.2f} |")
        report += ["", "Deltas are against the paired no-action episode. In benign_burst, the suspect is legitimate traffic: negative goodput change is collateral damage.",
                   "", "Inspect raw cohorts, loss/deadline misses and all controller/actuator events. RTT percentiles include received replies only.",
                   "", "The table's suspect metric is client-echoed payload goodput over the fixed event interval; independent server receive counters are validated and reported separately over the whole episode in metrics.json.",
                   "", "The acknowledged-no-op fault evaluates ineffective-action detection, not reversal of actual harm. Fixed-rule/current-gate similarity is expected because proposals are policy-compliant.",
                   "", "Do not treat packets as independent trials, infer population safety, or select only favourable episodes. Independent reproduction and a frozen confirmatory protocol remain required.", ""]
        with (output / "REPORT.md").open("x", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(report))
        manifest["status"] = "COMPLETE_REFERENCE_CONTROLLER_PILOT"
        manifest["outputs"] = {p.relative_to(output).as_posix(): sha256_file(p)
                               for p in sorted(output.rglob("*")) if p.is_file()}
        write_json(output / "run_manifest.json", manifest)
    except BaseException as error:
        write_json(output / "INCOMPLETE.json", {"status": "INCOMPLETE_NOT_PUBLISHABLE",
                   "exception_type": type(error).__name__, "completed_episodes": len(results)})
        raise
    print("Completed pilot: " + str(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
