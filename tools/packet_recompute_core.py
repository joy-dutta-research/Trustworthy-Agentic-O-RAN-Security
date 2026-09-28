"""Read-only cohort/episode arithmetic from the original independent packet audit.

Adapted only for portable public ZIP inputs. No traffic, network commands or
archived launchers are executed. The wrapper handles artifact integrity.
The formulas and evidence assertions retain the original audit definitions.
"""
from __future__ import annotations

from collections import Counter
import json
import math
from statistics import fmean
import zipfile

SCENARIOS = ("persistent_flood", "benign_burst", "ineffective_action")
METHODS = ("no_action", "fixed_rule", "current_gate", "evidence_feedback")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(z, name):
    return json.loads(z.read(name))


def jsonl(z, name):
    payload = z.read(name)
    check(payload.endswith(b"\n"), f"Incomplete log: {name}")
    return [json.loads(line) for line in payload.splitlines() if line.strip()]


def audit_run(label, path):
    with zipfile.ZipFile(path) as z:
        # Successful summary uniquely identifies the primary pilot. Earlier
        # partial pilots retained in the first return must not be mixed in.
        summaries = [n for n in z.namelist() if n.endswith("/packet_pilot/summary.json")]
        check(len(summaries) == 1, "Ambiguous successful pilot")
        base = summaries[0].rsplit("/", 1)[0]
        plan = read_json(z, base + "/run_plan.json")
        check(plan["order_seed"] == 220926, "Changed order seed")
        check(len(plan["jobs"]) == 36, "Unexpected episode count")
        check(Counter((j["scenario"], j["method"]) for j in plan["jobs"]) ==
              Counter({(s, m): 3 for s in SCENARIOS for m in METHODS}), "Unbalanced conditions")
        all_rows = []
        for index, job in enumerate(plan["jobs"]):
            folder = base + f"/episode_{index:04d}"
            metric = read_json(z, folder + "/metrics.json")
            check(all(metric[k] == job[k] for k in job), "Job/metric mismatch")
            server = next(r for r in jsonl(z, folder + "/server.jsonl") if r["type"] == "server_summary")
            check(server["invalid"] == 0, "Invalid server input")
            for role in ("legitimate", "suspect"):
                records = jsonl(z, folder + f"/{role}.jsonl")
                summary = next(r for r in records if r["type"] == "cohort_summary")
                metadata = next(r for r in records if r["type"] == "metadata")
                all_cohorts = summary["cohorts"]
                event_cohorts = [r for r in all_cohorts if 4 <= r["window_start"] < 14]
                check(len(event_cohorts) == 10 and len(all_cohorts) == 20, "Missing cohorts")
                sent = sum(r["sent"] for r in event_cohorts)
                received = sum(r["received"] for r in event_cohorts)
                rtts = [v for r in event_cohorts for v in r["rtt_ms"]]
                check(received == len(rtts), "RTT/accounting mismatch")
                timely = sum(v <= 500 for v in rtts)
                derived = {"sent": sent, "received": received, "lost_after_drain": sent-received,
                           "timely_500ms": timely, "timely_delivery_ratio": timely/sent,
                           "delivery_ratio": received/sent, "deadline_miss_ratio": (sent-timely)/sent,
                           "rtt_p95_ms_received_only": sorted(rtts)[math.ceil(0.95*len(rtts))-1],
                           "echo_goodput_kbit_s": received*512*8/10/1000}
                for k, v in derived.items():
                    check(math.isclose(v, metric[role][k], rel_tol=1e-12, abs_tol=1e-12), f"Metric mismatch {k}")
                counters = summary["counters"]
                check(all(v == 0 for k, v in counters.items() if k != "missed_send_slots"), "Transport/accounting error")
                planned = sum((p["end"]-p["start"])*p["pps"] for p in metadata["schedule"])
                check(0.9*planned <= summary["sent"] <= 1.02*planned, "Offered total out of tolerance")
                for cohort in all_cohorts:
                    scheduled = sum(max(0, min(cohort["window_end"], p["end"])-max(cohort["window_start"],p["start"]))*p["pps"] for p in metadata["schedule"])
                    check(max(0, 0.9*scheduled-1) <= cohort["sent"] <= 1.02*scheduled+1, "Offered window out of tolerance")
                receiver = server["sources"][role]
                check(0 <= summary["received"] <= receiver["echoed"] <= receiver["received"] <= summary["sent"], "Client/server accounting inequality violated")
                check(receiver["echo_errors"] == 0, "Server echo error")
                check(receiver["received_bytes"] == receiver["received"]*512, "Server payload mismatch")
                derived_server = {"received_datagrams": receiver["received"], "received_payload_bytes": receiver["received_bytes"], "receiver_payload_kbit_per_offered_second": receiver["received_bytes"]*8/20/1000}
                check(derived_server == metric["server_whole_episode"]["sources"][role], "Server metric mismatch")
            events = [r for r in jsonl(z, folder + "/controller.jsonl") if r["type"] == "decision"]
            actions = [r for r in events if r["decision"]["kind"] == "apply"]
            restores = [r for r in events if r["decision"]["kind"] == "restore"]
            check(len(actions) == metric["intervention_attempts"], "Action count mismatch")
            check(metric["worker_completion"]["returncodes"] == [0, 0, 0], "Worker failure")
            check(metric["final_readback"]["configuration_verified"], "Restore unverified")
            kernel = read_json(z, folder + "/kernel_commands.json")
            check(kernel["cleanup_errors"] == [], "Cleanup errors")
            check(len(kernel["namespaces"]) == 4, "Wrong topology")
            check(all(v["verified"] for v in kernel["topology_snapshot"].values()), "Topology unverified")
            neighbors = read_json(z, folder + "/neighbor_final.json")
            check(sum(map(len, neighbors.values())) == 6, "Missing neighbor readback")
            check(all(n["state"] == ["PERMANENT"] for table in neighbors.values() for n in table), "Nonpermanent neighbor")
            all_rows.append({"vm": label, **job, "raw_path": folder,
                             "legitimate": metric["legitimate"], "suspect": metric["suspect"],
                             "actions": actions, "restores": restores})
        derived_comparisons = []
        aggregates = []
        supplied = read_json(z, summaries[0])["comparisons"]
        for scenario in SCENARIOS:
            baseline = {r["replicate"]: r for r in all_rows if r["scenario"] == scenario and r["method"] == "no_action"}
            for method in METHODS:
                rows = [r for r in all_rows if r["scenario"] == scenario and r["method"] == method]
                actions = [a for r in rows for a in r["actions"]]
                restores = [e for r in rows for e in r["restores"]]
                agg = {"scenario": scenario, "method": method,
                       "mean_legitimate_timely_percent": 100*fmean(r["legitimate"]["timely_delivery_ratio"] for r in rows),
                       "mean_suspect_goodput_kbit_s": fmean(r["suspect"]["echo_goodput_kbit_s"] for r in rows),
                       "mean_legitimate_received_rtt_p95_ms": fmean(r["legitimate"]["rtt_p95_ms_received_only"] for r in rows),
                       "intervention_count": len(actions),
                       "mean_apply_seconds_from_event_start": fmean(a["at_seconds"]-4 for a in actions) if actions else None,
                       "restore_reasons": dict(Counter(e["decision"]["reason"] for e in restores)),
                       "restore_command_ms": [1000*e["restore_command_seconds"] for e in restores],
                       "apply_decision_to_restore_trigger_seconds": [r["restores"][0]["at_seconds"]-r["actions"][0]["at_seconds"] for r in rows if r["actions"] and r["restores"]]}
                aggregates.append(agg)
                if method == "no_action":
                    continue
                delta = [r["legitimate"]["timely_delivery_ratio"]-baseline[r["replicate"]]["legitimate"]["timely_delivery_ratio"] for r in rows]
                goodput = [r["suspect"]["echo_goodput_kbit_s"]-baseline[r["replicate"]]["suspect"]["echo_goodput_kbit_s"] for r in rows]
                original = next(c for c in supplied if c["scenario"] == scenario and c["method"] == method)
                check(math.isclose(fmean(delta), original["mean_delta_legitimate_timely_delivery"], abs_tol=1e-12), "Summary delivery mismatch")
                check(math.isclose(fmean(goodput), original["mean_delta_suspect_goodput_kbit_s"], abs_tol=1e-12), "Summary goodput mismatch")
                derived_comparisons.append({"scenario": scenario, "method": method,
                    "delta_timely_pp": 100*fmean(delta), "individual_delta_timely_pp": [100*v for v in delta],
                    "delta_suspect_goodput_kbit_s": fmean(goodput)})
    return {"successful_pilot_path": base, "episode_count": len(all_rows), "plan": plan,
            "comparisons": derived_comparisons, "aggregate_conditions": aggregates, "episodes": all_rows}


