#!/usr/bin/env python3
"""Build reader-facing result views from saved evidence, without rerunning science.

Only the Python standard library is needed. Sources are read-only. Every output is
derived from the two named JSON evidence files or explicitly labelled protocol
interpretation. --check compares in memory and never changes result files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = "windows_comparison.json"
PACKET = "packet_recomputation.json"
METHODS = ("direct", "contract", "contract_rbac", "trust_boundary")
PACKET_METHODS = ("no_action", "fixed_rule", "current_gate", "evidence_feedback")
SCENARIOS = ("persistent_flood", "benign_burst", "ineffective_action")
FOLDERS = (
    "00_overview", "01_policy_validity", "02_dataset_robustness",
    "03_sensitivity", "04_processing_cost", "05_scaling_and_load",
    "06_packet_feedback", "07_reproducibility",
)
METHOD_LABELS = {
    "direct": "Direct", "contract": "Contract", "contract_rbac": "Contract + RBAC",
    "trust_boundary": "Full Trust Boundary", "no_action": "No action",
    "fixed_rule": "Fixed rule", "current_gate": "Policy gate",
    "evidence_feedback": "Evidence + feedback",
}
DATASET_LABELS = {"netslab": "NetsLab", "5gnidd": "5G-NIDD"}
HOST_LABELS = {"university": "Workstation 1", "workstation": "Workstation 2"}


def pointer(file: str, path: str) -> str:
    """Repository-relative JSON Pointer. No historical host paths are needed."""
    return f"evidence/summaries/{file}#{path}"


def json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def flatten(value: dict, prefix: str = "") -> dict:
    """Flatten nested objects; lists retain explicit JSON rather than fake totals."""
    output = {}
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            output.update(flatten(item, name))
        elif isinstance(item, list):
            output[name] = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        else:
            output[name] = item
    return output


def csv_text(rows: list[dict]) -> str:
    flat = [flatten(row) for row in rows]
    fields = list(dict.fromkeys(key for row in flat for key in row))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(flat)
    return stream.getvalue()


def show(value: object) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value).replace("|", "\\|").replace("\n", " ")


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines.extend("| " + " | ".join(show(item) for item in row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


class Views:
    """Keep outputs in memory so the verification mode is genuinely read-only."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.counts: dict[str, int] = {}

    def text(self, folder: str, name: str, content: str) -> None:
        self.files[f"{folder}/{name}"] = content.rstrip() + "\n"

    def rows(self, folder: str, name: str, rows: list[dict]) -> None:
        self.text(folder, name + ".json", json_text(rows))
        self.text(folder, name + ".csv", csv_text(rows))
        self.counts[f"{folder}/{name}"] = len(rows)

    def readme(self, index: int, title: str, content: str) -> None:
        previous = FOLDERS[index - 1] if index else None
        following = FOLDERS[index + 1] if index + 1 < len(FOLDERS) else None
        navigation = ["[Results guide](../README.md)"]
        if previous:
            navigation.append(f"[Previous stage](../{previous}/README.md)")
        if following:
            navigation.append(f"[Next stage](../{following}/README.md)")
        self.text(FOLDERS[index], "README.md", f"# {title}\n\n{content.strip()}\n\n[Column meanings and units](DATA_DICTIONARY.md)\n\n" + " · ".join(navigation))


def comparator_rows(summary: dict, population: str, source: str) -> list[dict]:
    rows = []
    for method in METHODS:
        item = summary["comparators"][method]
        rows.append({
            "population": population, "method": method,
            "case_occurrences": item["evaluations"],
            "reference_decision_agreement": item["decision_agreement"],
            "block_required_admitted": item["policy_block_required_admitted"],
            "block_required_total": item["reference_block_required"],
            "permitted_admitted": item["reference_allow_admitted"],
            "permitted_total": item["reference_allow"],
            "source": source + "/comparators/" + method,
        })
    return rows


def group_rows(summary: dict, population: str, source: str) -> list[dict]:
    rows = []
    for group, values in summary["groups"].items():
        for method in METHODS:
            rows.append({
                "population": population, "group": group, "method": method,
                "distinct_configurations_union": values["distinct_meaningful_configurations_union"],
                **values["overall"][method],
                "source": source + "/groups/" + group + "/overall/" + method,
            })
    return rows


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError("Evidence consistency check failed: " + description)


def build(windows: dict, packet: dict, identities: dict) -> Views:
    views = Views()
    policy = windows["full_campaign"]["policy_and_datasets"]
    common = policy["validity"]
    hosts = (("university", "original_host"), ("workstation", "new_host"))
    require(windows["errors"] == [], "Windows comparison reports errors")
    require(set(packet["runs"]) == {"first", "repeat"}, "two packet runs")
    require(common["constructed_case_count"] == 777, "777 validity cases")
    require(len(windows["full_campaign"]["sensitivity"]) == 12, "12 sensitivity conditions")
    require(windows["original_host"]["policy_and_datasets"] == policy, "cross-host policy and dataset equality")
    require(windows["original_host"]["sensitivity"] == windows["full_campaign"]["sensitivity"], "cross-host sensitivity equality")
    require(common["unique_semantic_configurations"] == 669, "validity semantic-configuration count")
    require(common["comparators"]["trust_boundary"]["policy_block_required_admitted"] == 0 and common["comparators"]["trust_boundary"]["reference_block_required"] == 647, "common policy headline")
    require(common["scoped_properties"]["passed"] == 25 and common["scoped_properties"]["failed"] == 0, "scoped property headline")
    require(common["test_sensitivity"]["detected"] == 14, "targeted mutant headline")
    require(policy["netslab"]["constructed_case_count"] == 20000 and policy["netslab"]["unique_semantic_configurations"] == 19945, "NetsLab coverage headline")
    net_full = policy["netslab"]["comparators"]["trust_boundary"]
    require((net_full["policy_block_required_admitted"], net_full["reference_block_required"], net_full["reference_allow_admitted"]) == (0, 16000, 4000), "NetsLab conformance headline")
    conformance = policy["panels"]["groups"]["conformance"]
    require(conformance["distinct_meaningful_configurations_union"] == 162, "NIDD conformance configurations")
    nidd_full = conformance["overall"]["trust_boundary"]
    require(nidd_full["cases"] == 95000 and nidd_full["policy_block_required_admissions"] == {"denominator": 75000, "numerator": 0, "rate": 0.0}, "NIDD conformance headline")
    for method in METHODS:
        false_alarm = policy["panels"]["groups"]["false_alarm_probes"]["overall"][method]["benign_disruptive_admission"]
        require(false_alarm == {"denominator": 5000, "numerator": 5000, "rate": 1.0}, "forced false-alarm headline")

    # Stage 0: give readers the scope and source identities before the numbers.
    stages = [
        {"stage": 0, "question": "Are the inputs and code traceable?", "evidence": "Frozen source/input identities and regeneration records", "meaning": "A stable baseline for repeating the study"},
        {"stage": 1, "question": "Does the Trust Boundary enforce the stated policy?", "evidence": "777 constructed cases, scoped properties, targeted mutants", "meaning": "Policy conformance under the tested rules"},
        {"stage": 2, "question": "Does the result hold across the defined dataset mappings and seeds?", "evidence": "NetsLab controls, 5G-NIDD census and seeded panels", "meaning": "Coverage beyond a small illustrative example"},
        {"stage": 3, "question": "How do operator assumptions affect decisions?", "evidence": "12 predefined sensitivity conditions", "meaning": "Explicit dependence on the selected policy and mapping"},
        {"stage": 4, "question": "What does local verification cost?", "evidence": "Four methods, two timing boundaries, 20 process blocks", "meaning": "Measured local processing overhead"},
        {"stage": 5, "question": "What happens as state and incoming load grow?", "evidence": "All declared state paths and offered-load conditions", "meaning": "A measured operating envelope for the prototype"},
        {"stage": 6, "question": "Does action, corroboration and feedback improve the tested packet scenarios?", "evidence": "36 exploratory episodes", "meaning": "Flood benefit, collateral avoidance and ineffective-action recognition"},
        {"stage": 7, "question": "Can the same protocol be reproduced in another environment?", "evidence": "Second Windows host and 36-episode clean-VM repeat", "meaning": "Cross-host Windows reproducibility and same-host packet repeatability"},
    ]
    views.rows(FOLDERS[0], "stage_map", stages)
    views.text(FOLDERS[0], "source_identities.json", json_text(identities))
    views.readme(0, "Start here: the completed proof of concept", """
We evaluate three complementary responsibilities: check whether an action is permitted, establish whether intervention is justified, and verify whether it helped. Read the stages in order, or use the summary below to find a specific question.

This is the completed **initial PoC Stages 0–7**. The larger confirmatory packet study remains future work. We ran the Windows campaigns on **Workstation 1** and **Workstation 2**, two different physical computers. Both packet runs used separately installed VMs on **Workstation 2**; we keep their results separate.

For traceability, the machine-readable files retain their original host keys: `university` means Workstation 1 and `workstation` means Workstation 2. The reader-facing tables use the workstation names. The [environment and provenance guide](../../docs/04_provenance_and_scope.md) describes the recorded hardware and software.

The experiments evaluate deterministic policy and feedback mechanisms. They do not evaluate a live LLM, train a detector, or exercise a real O-RAN radio/E2 integration. Frontier-model consistency review is documented separately under [model review](../../model_review/README.md).

`stage_map.csv` and `stage_map.json` are the machine-readable reading guide. `source_identities.json` identifies the saved evidence used to build these views. Hash matches establish file identity, not scientific validity.

All result views are regenerated by `python tools/build_result_views.py`. This command reads saved evidence only. `--check` verifies that the checked-in views match without writing anything. Empty CSV cells and JSON `null` mean unavailable/not applicable, never a measured zero. Markdown rounds presentation to three decimals; JSON/CSV preserve underlying numeric precision.
""" + "\n" + table(["Stage", "Question", "What it establishes"], [[x["stage"], x["question"], x["meaning"]] for x in stages]))

    # Stage 1: compare every baseline, not only the successful boundary.
    validity = comparator_rows(common, "common_validity", pointer(WINDOWS, "/full_campaign/policy_and_datasets/validity"))
    views.rows(FOLDERS[1], "method_comparison", validity)
    properties = [{k: v for k, v in item.items() if k != "fixture"} for item in common["scoped_properties"]["checks"]]
    views.rows(FOLDERS[1], "scoped_properties", properties)
    views.rows(FOLDERS[1], "targeted_mutations", common["test_sensitivity"]["mutations"])
    views.rows(FOLDERS[1], "stratified_results", common["stratified"])
    views.text(FOLDERS[1], "coverage.json", json_text({
        "case_occurrences": common["constructed_case_count"],
        "semantic_configurations": common["unique_semantic_configurations"],
        "case_groups": common["groups"], "interaction_coverage": common["interaction_coverage"],
        "property_scope": common["scoped_properties"]["scope"],
        "mutation_scope": common["test_sensitivity"]["scope"],
        "source": pointer(WINDOWS, "/full_campaign/policy_and_datasets/validity"),
    }))
    views.readme(1, "Stage 1: policy validity", """
The full Trust Boundary agreed with the reference decision for all 777 constructed cases and admitted none of the 647 proposals that required blocking. All four methods admitted all 130 reference-permitted proposals. This demonstrates the value of the complete policy check over the simpler baselines within the declared test design.

| File | How to read it |
|---|---|
| `method_comparison.csv` / `.json` | One row per method; admitted/total counts retain their denominators. |
| `scoped_properties.csv` / `.json` | 25 checks on selected valid-action witnesses; not universal proofs. |
| `targeted_mutations.csv` / `.json` | All 14 predefined test-only code mutations were detected. |
| `stratified_results.csv` / `.json` | The original group/action strata, without adding them into a second overall total. |
| `coverage.json` | Case groups, 669 distinct semantic configurations and declared interaction coverage. |

**What we learn.** This supports Safe Action Verification at the Trust Boundary. Reference-policy agreement is not detector accuracy or proof that every permitted action is operationally safe. The 130 permitted cases include 12 legacy-limitation probes. We retain the frozen policy's protected-service restriction gap for `rollback_policy` so the comparison remains consistent. A separately versioned correction is a next step, not a change made retrospectively to these results.
""" + "\n" + table(["Method", "Agreement / 777", "Block-required admitted / 647", "Permitted admitted / 130"], [[METHOD_LABELS[r["method"]], r["reference_decision_agreement"], r["block_required_admitted"], r["permitted_admitted"]] for r in validity]))

    # Stage 2: keep natural mappings, conformance probes and false alarms distinct.
    netslab = comparator_rows(policy["netslab"], "NetsLab generated controls", pointer(WINDOWS, "/full_campaign/policy_and_datasets/netslab"))
    dataset_rows = netslab
    nidd_groups = []
    for name in ("census", "panels"):
        nidd_groups.extend(group_rows(policy[name], "5G-NIDD " + name, pointer(WINDOWS, "/full_campaign/policy_and_datasets/" + name)))
    views.rows(FOLDERS[2], "netslab_method_comparison", dataset_rows)
    views.rows(FOLDERS[2], "netslab_stratified_results", policy["netslab"]["stratified"])
    views.rows(FOLDERS[2], "nidd_group_results", nidd_groups)
    views.text(FOLDERS[2], "sampling_and_eligibility.json", json_text({
        "dataset_audit": policy["dataset_audit"], "sampling_protocol": policy["sampling_protocol"],
        "natural_panel_analysis": policy["natural_panel_analysis"],
        "netslab_semantic_configurations": policy["netslab"]["unique_semantic_configurations"],
        "source": pointer(WINDOWS, "/full_campaign/policy_and_datasets"),
    }))
    rows = []
    for item in netslab:
        rows.append(["NetsLab controls", METHOD_LABELS[item["method"]], item["case_occurrences"], f"{item['block_required_admitted']}/{item['block_required_total']}", f"{item['permitted_admitted']}/{item['permitted_total']}"])
    for item in nidd_groups:
        block = item["policy_block_required_admissions"]
        allowed = item["compliant_action_acceptance"]
        allowed_text = f"{allowed['numerator']}/{allowed['denominator']}" if allowed is not None else "n/a; see benign probes below"
        rows.append(["5G-NIDD " + item["group"], METHOD_LABELS[item["method"]], item["cases"], f"{block['numerator']}/{block['denominator']}", allowed_text])
    views.readme(2, "Stage 2: dataset coverage and seeded robustness", """
Our dataset-grounded tests extend the policy result beyond the common validity suite. The full Trust Boundary admitted 0/16,000 block-required NetsLab proposals and 0/75,000 block-required 5G-NIDD conformance proposals, while admitting every reference-permitted proposal in those groups. These policy and dataset summaries matched between Workstation 1 and Workstation 2.

NetsLab supplies exhaustive aggregate context from 45,244 lower-layer rows, combined with standards-context bases. Twenty control-generation seeds produce 20,000 constructed proposals and 19,945 semantic configurations. `netslab_stratified_results` retains every reported action and seed stratum.

5G-NIDD starts with 1,215,890 source rows. Its eligible natural census contains 733,693 unique records, but only 33 meaningful proposal configurations; all natural proposals are reference-ALLOW and every method admits them. Twenty seeds and nested per-label sizes of 25/100/250 support the separate panel analysis. The 95,000 conformance occurrences contain 162 normalized configurations. Overlapping panels and generated variants must not be counted as independent real incidents.

The **5,000 deliberately forced benign-mitigation probes were admitted by every method**. This gives the feedback experiment a clear motivation: an action can comply with policy yet be unnecessary. It is not a detector false-positive-rate estimate. The gate enforces authorization and constraints; corroboration addresses intervention necessity in Stage 6.

`netslab_method_comparison` contains the four overall method rows. `nidd_group_results` separates the natural census, conformance and false-alarm populations, with original numerator/denominator/rate objects. Ratios use 0–1 units. `sampling_and_eligibility.json` preserves source counts, exclusions, seeds and overlap information. A `0/0` entry below means the group contains no such cases, not a zero failure rate.
""" + "\n" + table(["Population", "Method", "Cases", "Block-required admitted / total", "Permitted admitted / total"], rows))

    # Stage 3: expose unchanged results as well as settings that change decisions.
    sensitivity = []
    sensitivity_details = []
    for condition, value in windows["full_campaign"]["sensitivity"].items():
        sensitivity.append({"condition": condition, **value["assumption_effect_on_fixed_inputs"], "source": pointer(WINDOWS, "/full_campaign/sensitivity/" + condition)})
        for row in group_rows(value, condition, pointer(WINDOWS, "/full_campaign/sensitivity/" + condition)):
            sensitivity_details.append(row)
    views.rows(FOLDERS[3], "assumption_changes", sensitivity)
    views.rows(FOLDERS[3], "all_method_results", sensitivity_details)
    views.readme(3, "Stage 3: assumption sensitivity", """
We use 12 predefined conditions to show how the prototype responds to different operator choices. All sensitivity summaries matched between Workstation 1 and Workstation 2. Tighter NetsLab reduction/TTL limits change some decisions, while the tested 5G-NIDD budget settings change proposal payloads without changing decisions. This makes the role of policy assumptions visible and reproducible.

`assumption_changes.csv` / `.json` compares each condition with the frozen primary setting on its fixed inputs. Changes count case occurrences, not independent incidents. `all_method_results.csv` / `.json` retains every method, group and denominator under all 12 conditions, including zero changes. JSON contains the same values in nested form.

These are illustrative operator thresholds, not requirements attributed to a standard. The next policy study can test additional choices against operational requirements while preserving this version as the baseline.
""" + "\n" + table(["Condition", "Cases", "Decision changes", "Reason changes", "Proposal changes"], [[r["condition"], r["cases"], r["expected_decision_changed_from_primary"], r["expected_reasons_changed_from_primary"], r["proposal_changed_from_primary"]] for r in sensitivity]))

    # Stages 4–5: preserve separate hosts and every final condition.
    micro, scaling, loads, bootstrap = [], [], [], []
    for host, key in hosts:
        perf = windows[key]["performance"]
        for index, item in enumerate(perf["timing_and_scaling"]):
            row = {"host": host, **item, "source": pointer(WINDOWS, f"/{key}/performance/timing_and_scaling/{index}")}
            (micro if item["mode"] == "micro" else scaling).append(row)
        for index, item in enumerate(perf["load_by_seed_all_conditions_retained"]):
            loads.append({"host": host, **item, "source": pointer(WINDOWS, f"/{key}/performance/load_by_seed_all_conditions_retained/{index}")})
        for index, item in enumerate(perf["existing_paired_block_bootstrap_comparisons"]):
            bootstrap.append({"host": host, **item, "source": pointer(WINDOWS, f"/{key}/performance/existing_paired_block_bootstrap_comparisons/{index}")})
    require(len(micro) == 32 and len(scaling) == 576 and len(loads) == 120 and len(bootstrap) == 480, "complete performance view counts")
    views.rows(FOLDERS[4], "microbenchmarks", micro)
    views.rows(FOLDERS[4], "micro_paired_block_comparisons", [row for row in bootstrap if row["condition"]["mode"] == "micro"])
    micro_lookup = {(x["host"], x["dataset"], x["boundary"], x["method"]): x for x in micro}
    micro_table = []
    for dataset in ("5gnidd", "netslab"):
        for boundary in ("evaluator_component", "matched_local_processing_with_buffered_event_logging"):
            for method in METHODS:
                a = micro_lookup[("university", dataset, boundary, method)]["block_percentile_statistics_microseconds"]
                b = micro_lookup[("workstation", dataset, boundary, method)]["block_percentile_statistics_microseconds"]
                micro_table.append([DATASET_LABELS[dataset], "Component" if boundary == "evaluator_component" else "Matched", METHOD_LABELS[method], a["p50"]["mean"], b["p50"]["mean"], a["p95"]["mean"], b["p95"]["mean"]])
    views.readme(4, "Stage 4: local processing cost", """
The low-state measurements quantify the cost of applying the Trust Boundary. They support feasibility for the tested local verification path while showing the extra work required by the safeguards. Read Stage 5 before drawing a capacity conclusion.

Values below are **microseconds (µs), means of 20 process-block percentiles**. They are not percentiles pooled over all requests. Each microbenchmark uses 1,000 warm-up and 10,000 measured requests per method/block. Workstation 1 and Workstation 2 are separate physical computers; hardware, scheduling and power conditions prevent a causal CPU-only comparison. In the unchanged CSV/JSON files, `university` means Workstation 1 and `workstation` means Workstation 2.

The component boundary times the evaluator. The matched boundary includes matched local processing with **buffered** event logging. Neither includes LLM inference, network/actuator latency, radio response, remote audit durability, initialization or final log flush. Workstation 2 is not uniformly faster; compare p50 and p95 separately.

`microbenchmarks.csv` / `.json` retains all 32 host-specific cells, p50/p95/p99, block ranges, request counts and process-resource measurements. CPU includes instrumentation. `micro_paired_block_comparisons` retains our recorded bootstrap summaries: differences of matched process-block percentile statistics, not percentiles of per-request overhead. `absolute_added_ns` is nanoseconds; `slowdown_ratio` is unitless. These existing within-host intervals are not a new cross-host significance test.
""" + "\n" + table(["Dataset", "Boundary", "Method", "Workstation 1 p50 µs", "Workstation 2 p50 µs", "Workstation 1 p95 µs", "Workstation 2 p95 µs"], micro_table))

    views.rows(FOLDERS[5], "state_and_input_scaling", scaling)
    views.rows(FOLDERS[5], "load_by_seed", loads)
    views.rows(FOLDERS[5], "scaling_paired_block_comparisons", [row for row in bootstrap if row["condition"]["mode"] != "micro"])
    grouped = defaultdict(list)
    for row in loads:
        grouped[(row["host"], row["dataset"], row["method"], row["offered_per_second"])].append(row)
        if row["offered_per_second"] == 100 or row["method"] == "direct":
            require(row["all_offered_fractions"]["completed"]["rate"] == 1.0, "low-load/direct completion headline")
        elif row["method"] == "trust_boundary":
            require(row["all_offered_fractions"]["overflow"]["numerator"] > 0 and row["deadline_success_fractions_all_offered"]["10"] == 0, "full-gate high-load findings")
    load_summary = []
    for (host, dataset, method, rate), values in sorted(grouped.items()):
        complete = [100 * x["all_offered_fractions"]["completed"]["rate"] for x in values]
        load_summary.append({
            "host": host, "dataset": dataset, "method": method, "offered_proposals_per_second": rate,
            "seed_count": len(values), "completion_percent_mean": mean(complete),
            "completion_percent_min": min(complete), "completion_percent_max": max(complete),
            "all_offered_10ms_success_percent_mean": mean(100 * x["deadline_success_fractions_all_offered"]["10"] for x in values),
            "completed_only_scheduled_arrival_p95_ms_mean": mean(x["completion_latency_completed_only"]["p95_ns"] / 1e6 for x in values),
            "generator_limited_seed_count": sum(x["generator_limited"] for x in values),
            "right_censored_count_total": sum(x["all_offered_fractions"]["right_censored"]["numerator"] for x in values),
            "source_rows": [x["source"] for x in values],
        })
    views.rows(FOLDERS[5], "load_summary", load_summary)
    state_table = []
    for row in scaling:
        if row["method"] == "trust_boundary" and row["state_path"] == "no_conflict" and not row["large_input"] and not row["resource_only"]:
            state_table.append([HOST_LABELS[row["host"]], DATASET_LABELS[row["dataset"]], row["state_size"], row["block_percentile_statistics_microseconds"]["p95"]["mean"] / 1000])
    views.readme(5, "Stage 5: state scaling and offered load", """
The experiments identify the prototype's operating envelope and the most useful engineering priorities. Every offered request completed at 100 proposals/s. Increasing state and offered load shows where indexing, scheduling and admission control will be valuable.

The full gate's queue **overflowed at 1,000 and 5,000 proposals/s**. All full-gate cells at those two rates had zero all-offered success within the illustrative 10-ms deadline. These are measured outcomes, retained alongside the successful low-rate case. They are not production-capacity results. Direct execution completed every offered request at all three tested rates.

Load means **action proposals/s, not network packets/s**: one consumer, 100 fixed nonconflicting actions, queue capacity 1,000, 10-s warm-up, 60-s offering and up to 30-s drain. Completion includes drain and is not a steady-state throughput estimate. Completed-only latency excludes dropped requests, so read it beside completion/overflow/deadline fractions. We retain and flag two generator-limited Workstation 1 cells.

`state_and_input_scaling` contains all 576 host-specific conditions, including conflict-first, conflict-last, malformed-last, near-limit input and resource-only runs. Timing is µs in those source columns; the selected no-conflict table below converts p95 to ms. Resource-only cells have no timing statistic rather than a fabricated zero. `load_by_seed` retains all 120 cells and their counts, 1/10/100-ms deadlines, timing components and resource records. `load_summary` averages five seeds per host/dataset/method/rate; min/max are observed ranges, **not confidence intervals**. `scaling_paired_block_comparisons` contains our recorded within-host bootstrap summaries, not new statistical tests. The raw host keys remain `university` for Workstation 1 and `workstation` for Workstation 2.

## Full-gate ordinary-input state scan
""" + "\n" + table(["Host", "Dataset", "Active actions", "Mean block-p95 ms"], state_table) + "\n## Offered-load completion\n\n" + table(["Host", "Dataset", "Method", "Proposals/s", "Complete % mean", "Min %", "Max %", "Within 10 ms %"], [[HOST_LABELS[r["host"]], DATASET_LABELS[r["dataset"]], METHOD_LABELS[r["method"]], r["offered_proposals_per_second"], r["completion_percent_mean"], r["completion_percent_min"], r["completion_percent_max"], r["all_offered_10ms_success_percent_mean"]] for r in load_summary]))

    # Stage 6: publish episode-level outcomes, all conditions and paired contrasts.
    episodes, conditions, contrasts, paired_episodes, protocol = [], [], [], [], {}
    for vm in ("first", "repeat"):
        run = packet["runs"][vm]
        require(run["episode_count"] == len(run["episodes"]) == 36, "36 episodes per VM")
        protocol[vm] = {key: run["plan"][key] for key in ("settings", "settings_sha256", "order_seed", "randomness_scope", "planner", "live_model_evaluated", "oran_interface_exercised", "environment", "source_files")}
        event_start = run["plan"]["settings"]["event_start"]
        for index, ep in enumerate(run["episodes"]):
            row = {
                "vm": vm, "scenario": ep["scenario"], "method": ep["method"], "replicate": ep["replicate"],
                "episode_id": ep["raw_path"].rsplit("/", 1)[-1],
                "protected": ep["legitimate"], "suspect": ep["suspect"],
                "intervention_count": len(ep["actions"]),
                "event_to_apply_decision_seconds": [x["at_seconds"] - event_start for x in ep["actions"]],
                "restore_reasons": [x["decision"]["reason"] for x in ep["restores"]],
                "operator_review_requested": any(x["operator_review_required"] for x in ep["restores"]),
                "restoration_command_ms": [x["restore_command_seconds"] * 1000 for x in ep["restores"]],
                "apply_decision_to_restore_trigger_seconds": [x["at_seconds"] - ep["actions"][0]["at_seconds"] for x in ep["restores"]] if ep["actions"] else [],
                "source": pointer(PACKET, f"/runs/{vm}/episodes/{index}"),
            }
            require(row["protected"]["timely_500ms"] <= row["protected"]["received"] <= row["protected"]["sent"], "packet count nesting")
            episodes.append(row)
        for index, condition in enumerate(run["aggregate_conditions"]):
            selected = [ep for ep in episodes if ep["vm"] == vm and ep["scenario"] == condition["scenario"] and ep["method"] == condition["method"]]
            require(len(selected) == 3, "three paired episodes per condition")
            observed = mean(ep["protected"]["timely_delivery_ratio"] * 100 for ep in selected)
            require(abs(observed - condition["mean_legitimate_timely_percent"]) < 1e-9, "packet condition timely mean")
            goodput = mean(ep["suspect"]["echo_goodput_kbit_s"] for ep in selected)
            require(abs(goodput - condition["mean_suspect_goodput_kbit_s"]) < 1e-9, "packet condition goodput mean")
            conditions.append({"vm": vm, "paired_repetitions": 3, **condition, "source": pointer(PACKET, f"/runs/{vm}/aggregate_conditions/{index}")})
        for index, contrast in enumerate(run["comparisons"]):
            method_episodes = {x["replicate"]: x for x in episodes if (x["vm"], x["scenario"], x["method"]) == (vm, contrast["scenario"], contrast["method"])}
            baseline_episodes = {x["replicate"]: x for x in episodes if (x["vm"], x["scenario"], x["method"]) == (vm, contrast["scenario"], "no_action")}
            delivery_deltas = [(method_episodes[i]["protected"]["timely_delivery_ratio"] - baseline_episodes[i]["protected"]["timely_delivery_ratio"]) * 100 for i in (0, 1, 2)]
            goodput_deltas = [method_episodes[i]["suspect"]["echo_goodput_kbit_s"] - baseline_episodes[i]["suspect"]["echo_goodput_kbit_s"] for i in (0, 1, 2)]
            require(abs(mean(delivery_deltas) - contrast["delta_timely_pp"]) < 1e-9, "paired packet delivery contrast")
            require(abs(mean(goodput_deltas) - contrast["delta_suspect_goodput_kbit_s"]) < 1e-9, "paired packet goodput contrast")
            # The historical audit lists individual differences in execution
            # order, which is not necessarily replicate-number order.
            require(all(abs(a - b) < 1e-9 for a, b in zip(sorted(delivery_deltas), sorted(contrast["individual_delta_timely_pp"]), strict=True)), "individual paired delivery differences")
            for replicate in (0, 1, 2):
                paired_episodes.append({
                    "vm": vm, "scenario": contrast["scenario"], "method": contrast["method"],
                    "baseline": "no_action", "replicate": replicate,
                    "delta_timely_pp": delivery_deltas[replicate],
                    "delta_suspect_goodput_kbit_s": goodput_deltas[replicate],
                    "method_episode_source": method_episodes[replicate]["source"],
                    "baseline_episode_source": baseline_episodes[replicate]["source"],
                })
            contrasts.append({"vm": vm, "baseline": "no_action", "paired_repetitions": 3, **contrast, "source": pointer(PACKET, f"/runs/{vm}/comparisons/{index}")})
    require(len(episodes) == 72 and len(conditions) == 24 and len(contrasts) == 18, "complete packet views")
    for condition in SCENARIOS:
        for vm in ("first", "repeat"):
            for method in PACKET_METHODS:
                require(sorted(x["replicate"] for x in episodes if (x["vm"], x["scenario"], x["method"]) == (vm, condition, method)) == [0, 1, 2], "paired replicate identities")
    for ep in episodes:
        if ep["scenario"] == "benign_burst":
            require(ep["intervention_count"] == (0 if ep["method"] in ("no_action", "evidence_feedback") else 1), "benign intervention headline")
        if ep["scenario"] == "ineffective_action" and ep["method"] == "evidence_feedback":
            require("NO_OBSERVED_BENEFIT" in ep["restore_reasons"] and ep["operator_review_requested"], "ineffective-action feedback headline")
    views.rows(FOLDERS[6], "episode_outcomes", episodes)
    views.rows(FOLDERS[6], "condition_means", conditions)
    views.rows(FOLDERS[6], "paired_contrasts", contrasts)
    views.rows(FOLDERS[6], "paired_episode_contrasts", paired_episodes)
    views.text(FOLDERS[6], "protocol.json", json_text(protocol))
    packet_table = []
    for scenario in SCENARIOS:
        for method in PACKET_METHODS:
            pair = [next(x for x in conditions if (x["vm"], x["scenario"], x["method"]) == (vm, scenario, method)) for vm in ("first", "repeat")]
            packet_table.append([scenario, METHOD_LABELS[method], pair[0]["mean_legitimate_timely_percent"], pair[1]["mean_legitimate_timely_percent"], pair[0]["mean_suspect_goodput_kbit_s"], pair[1]["mean_suspect_goodput_kbit_s"]])
    views.readme(6, "Stage 6: packet action and feedback", """
Our packet experiment connects policy checking to observable service outcomes. We retain all methods and all three scenarios below, for the first VM and its clean-VM repeat, both on Workstation 2. The result is exploratory: **three paired episode repetitions per condition per VM**. Packets are measurements within an episode, not independent experimental repetitions.

**Persistent flood:** the three intervention methods improved protected timely delivery from about 29% without action to about 73%. Evidence + feedback retained this benefit; the data do not establish superior flood mitigation over the other intervention methods. Delivery did not fully recover during the event: the six-second action expired while the flood continued, and the protocol allowed one intervention.

**Transient benign burst:** evidence + feedback abstained in all three repetitions per VM. Fixed rule and policy gate intervened in all three, reducing the legitimate suspect client's echoed goodput by approximately 99–100 kbit/s. Avoiding this unnecessary restriction illustrates the value of corroborating fresh, target-bound evidence beyond policy permission.

**Acknowledged but ineffective action:** feedback recognized no observed benefit and requested restoration/local operator review in all three repetitions per VM. Protected delivery did not improve. Because the injected action was a no-op, this demonstrates outcome monitoring and an escalation/restoration trigger, not recovery from harmful actuation or a tested human response service.

## How the measurements work

Four Linux namespaces represent a protected UDP client, suspect client, router and echo server, with a 1,000-kbit/s bottleneck. Each episode lasts 20 s; the event cohort is requests sent in seconds [4,14). Payloads are 512 bytes; protected traffic is 100 packets/s, suspect background 120 packets/s, flood 400 packets/s, and the benign high-rate burst lasts 0.6 s. The action requests an 80% reduction for 6 s. The order seed 220926 randomizes job order only.

Protected timely delivery is the percentage of event-cohort requests receiving an echo within 500 ms, retaining lost/late requests in the denominator. Suspect goodput is echoed **application payload** in decimal kbit/s over the event window, not router ingress rate. RTT p95 is conditional on received echoes and must not be used alone to describe delivery quality.

`episode_outcomes.csv` / `.json` contains all 72 episodes. `condition_means` contains all 24 means. `paired_contrasts` contains all 18 method-minus-no-action contrasts; positive timely-delivery differences are percentage points, not relative percent gains. Its individual-delivery-difference list preserves the original execution order. `paired_episode_contrasts` gives the same differences as 54 explicitly keyed VM/scenario/method/replicate rows, with sources for both paired episodes. No packet-level confidence intervals or significance claims are introduced. `protocol.json` records settings, source identities and environments.

The action timestamp is recorded **before dispatch**, not at actuator acknowledgement. Feedback's extra observation interval is approximately one second; it is not processor overhead. Restoration-command time is not time to restore service. Both VMs ran on Workstation 2, the same physical computer. These are synthetic packet mechanisms, not real E2/radio integration, and the controller is deterministic rather than an LLM.
""" + "\n" + table(["Scenario", "Method", "First timely %", "Repeat timely %", "First suspect kbit/s", "Repeat suspect kbit/s"], packet_table) + "\n## Paired differences from no action\n\n" + table(["VM", "Scenario", "Method", "Timely change pp", "Suspect goodput change kbit/s"], [[r["vm"], r["scenario"], METHOD_LABELS[r["method"]], r["delta_timely_pp"], r["delta_suspect_goodput_kbit_s"]] for r in contrasts]))

    # Stage 7: equality of fixed outputs and repeatability are different claims.
    reproducibility = []
    for name in policy:
        reproducibility.append({"kind": "policy_and_dataset_summary", "item": name, "equal_across_windows_hosts": windows["original_host"]["policy_and_datasets"][name] == policy[name], "source": pointer(WINDOWS, "/full_campaign/policy_and_datasets/" + name)})
    for name in windows["full_campaign"]["sensitivity"]:
        reproducibility.append({"kind": "sensitivity_summary", "item": name, "equal_across_windows_hosts": windows["original_host"]["sensitivity"][name] == windows["full_campaign"]["sensitivity"][name], "source": pointer(WINDOWS, "/full_campaign/sensitivity/" + name)})
    regeneration = windows["full_campaign"]["regeneration"]
    views.rows(FOLDERS[7], "cross_host_fixed_output_checks", reproducibility)
    views.rows(FOLDERS[7], "regenerated_case_identity", [{k: v for k, v in x.items() if k not in ("original_path", "regenerated_path")} for x in regeneration["case_comparison"]["files"]])
    views.text(FOLDERS[7], "regeneration_summary.json", json_text({
        "case_count": regeneration["case_comparison"]["case_count"],
        "case_file_count": regeneration["case_comparison"]["file_count"],
        "case_status": regeneration["case_comparison"]["status"],
        "aggregate_comparison": regeneration["aggregate_comparison"],
        "workload_status": regeneration["workload_comparison"]["status"],
        "workload_comparison_scope": regeneration["workload_comparison"]["comparison_scope"],
        "packet_source_and_returns": packet["verification"],
        "packet_same_physical_workstation": True,
        "windows_raw_timing_reanalysis_by_this_exporter": False,
    }))
    views.readme(7, "Stage 7: reproducibility and what to repeat next", """
The frozen policy/dataset summaries and all 12 sensitivity summaries agree between Workstation 1 and Workstation 2. All 42 regenerated case files, containing 120,777 constructed cases, match our frozen inputs byte for byte. Both benchmark workloads also match. The NetsLab aggregate agrees as parsed JSON; its serialized bytes differ, so we do not describe every regenerated artifact as byte-identical.

We repeated the same 36-job packet protocol in a separately installed clean VM on Workstation 2. Its findings agree in direction: flood benefit, avoidance of the tested benign restriction with corroboration, and recognition of the no-op's lack of benefit. This establishes **same-hardware clean-environment repeatability**, not replication on a second packet-test physical host. Windows timings and packet outcomes are reported separately rather than pooled.

`cross_host_fixed_output_checks` contains the exact fixed-summary comparisons. `regenerated_case_identity` lists the 42 case-file hashes and counts without historical machine paths. `regeneration_summary.json` distinguishes parsed equality from byte equality and preserves packet source/return identities. The result exporter checks aggregate structure and packet arithmetic, but does not reread every raw Windows timing observation or rerun gateway decisions. Hash verification demonstrates identity, not scientific improvement.

## Lessons retained with the successful runs

Developmental v3/v4 packet attempts were incomplete and are not mixed with the 36-episode result sets. The v4 logs establish UDP send timeouts as the immediate failure; the underlying kernel/socket cause was not conclusively reproduced. Later diagnostics motivated a versioned permanent-neighbor setup applied consistently across methods. The successful comparative episodes used the repaired v7 protocol. Qualification ran at 10,000 kbit/s, whereas the comparative pilot used 1,000 kbit/s; qualification is therefore not a capacity validation of the final study condition.

## Next study

Our completed initial PoC provides a reproducible baseline for a larger confirmatory study: more paired episodes, additional independent physical hosts, realistic radio/control integration, broader benign/attack patterns, recovery from harmful actions, and state/load engineering. These next steps extend the measured scope; they do not replace the mixed outcomes already reported in Stages 2, 5 and 6. We retain operator thresholds, policy semantics and standards locators as explicit review items in the release checklist.
""")

    dictionaries = [
        """`stage_map` has one row per stage: `question` is the evaluation question, `evidence` describes the completed test, and `meaning` states the supported conclusion. `source_identities` records SHA-256 and byte length of the two evidence JSON inputs actually read by this exporter. `export_checks` describes export consistency only; PASS is not a new scientific result.""",
        """`case_occurrences`/`evaluations` are constructed cases, not independent real incidents. `reference_decision_agreement` counts exact agreement with the reference ALLOW/DENY/ESCALATE decision. `block_required_admitted` counts ALLOW outcomes when the reference required DENY or ESCALATE; `block_required_total` is that population's denominator. `permitted_admitted` and `permitted_total` count reference-ALLOW cases. `actual_*` and `reference_*` in strata are decision counts. Strata overlap (for example, an action and a test group), so do not add all strata to form an overall total.\n\nProperty rows name the selected action/witness, original/actual decisions and reasons; `passed` is the scoped check outcome. Mutation rows name the injected test-only mutation and the number of mismatches detected; their witness list is illustrative, not a separate denominator. All counts are unitless integers.""",
        """The NetsLab comparison uses the Stage 1 count definitions. In 5G-NIDD group rows, each measurement such as `decision_agreement` or `policy_block_required_admissions` has a `numerator`, `denominator`, and 0–1 `rate`. CSV writes nested names as dotted column names. For example, `policy_block_required_admissions.numerator` is the admitted count and `.denominator` is the block-required count. A zero denominator has `rate = null`, not zero risk.\n\n`benign_disruptive_admission` is a specifically constructed false-alarm probe outcome, not a detector metric. `compliant_action_acceptance` is deliberately null for that probe group, so it is not silently relabelled useful mitigation. `distinct_configurations_union` counts normalized meaningful proposals across the group's categories, not source rows. Audit-field completeness/checksum validity concern the recorded audit format, not adversarial integrity or remote persistence.\n\nThe eligibility audit has original source-row counts and exclusion reasons. Source records, unique eligible records, generated case occurrences and distinct proposal configurations are different denominators. Seed overlap statistics describe shared selected rows; do not sum panels into an independent sample size.""",
        """`condition` identifies one fixed policy/mapping variant. `cases` is the number of case occurrences used to compare that condition with the primary setting. `expected_decision_changed_from_primary`, `expected_reasons_changed_from_primary`, and `proposal_changed_from_primary` are counts on those same fixed inputs; they are not percentages. A zero change does not mean the setting is universally insensitive.\n\n`all_method_results` uses the same nested numerator/denominator/rate definitions as Stage 2. `population` identifies the sensitivity condition; `group` keeps natural records, conformance and false-alarm probes separate. Every method is retained, even when a condition has no decision changes.""",
        """`host` preserves the raw identifiers: `university` means Workstation 1 and `workstation` means Workstation 2. Reader-facing Markdown tables use Workstation 1/2. `dataset`, `method`, and `boundary` define the timing cell. `blocks` counts repeated processes, and `measured_requests` is their total measured call count. `block_percentile_statistics_microseconds.p50/p95/p99.mean` is the arithmetic mean of each process block's percentile in microseconds. Its `minimum`/`maximum` describe the observed block range, not a confidence interval. `cpu_seconds_including_instrumentation` is process CPU seconds with instrumentation; `peak_rss_bytes` is process resident memory in bytes.\n\nPaired-block comparisons use nanoseconds under `absolute_added_ns`, and a unitless multiplier under `slowdown_ratio`. `ci95` is the recorded within-host bootstrap interval based on the stated `blocks`, `draws` and `analysis_seed`; no interval is recalculated here. The `statistic` names the per-block percentile being compared. It is not a distribution of paired per-request delays. Missing state/input fields in microbenchmarks are not applicable.""",
        """Scaling rows use the same timing/resource units as Stage 4. `state_size` is the number of active actions, `state_path` locates the conflict/validation path, `large_input` identifies the near-limit payload, and `resource_only` identifies runs used only for resource measurement. Missing timing values in resource-only runs stay unavailable.\n\nLoad `offered_per_second` is scheduled action proposals/s. `counts.scheduled_measurement` is the all-offered denominator, `completed_measurement` counts completions including drain, `overflow_measurement` counts queue drops, and `unfinished_at_drain_bound` counts right-censored admitted requests. `all_offered_fractions` are 0–1 ratios. `deadline_success_fractions_all_offered.1/.10/.100` use millisecond deadlines and the all-offered denominator.\n\n`completion_latency_completed_only`, `queue_latency_completed_only`, `service_latency_completed_only`, and `generator_lateness` expose mean/percentile/maximum nanoseconds and sample counts. Completion latency begins at scheduled arrival; it is not service time alone. Generator-limited cells remain flagged. Producer/consumer CPU are seconds, peak RSS is bytes; neither is whole-machine memory. Counts divided by offering duration are explicitly not sustained-capacity estimates.\n\n`load_summary` converts completion/deadline fractions to 0–100 percent and completion p95 to milliseconds, then averages the five seed statistics within each host/dataset/method/rate. Min/max are observed ranges, not confidence intervals. No request-level values or physical hosts are pooled.""",
        """`vm` is `first` or `repeat`, identifying two separately installed VMs on Workstation 2, not two physical computers. `replicate` is the paired episode identity (0, 1, 2). `episode_id` is its stable local episode identifier. The `protected` and `suspect` objects contain event-cohort `sent`, `received`, `timely_500ms` and loss counts. Delivery/deadline-miss fields are 0–1 ratios. `rtt_p95_ms_received_only` is milliseconds conditional on receiving an echo; `echo_goodput_kbit_s` is echoed payload in decimal kbit/s.\n\n`intervention_count` is the number of apply decisions. Action/restore time fields name their seconds or milliseconds explicitly. List values remain JSON arrays inside CSV cells: an empty list means no corresponding event, not zero delay. `operator_review_requested` is a local flag, not evidence of a human response.\n\nIn condition means, `mean_legitimate_timely_percent` uses a 0–100 percentage scale, `mean_suspect_goodput_kbit_s` is decimal kbit/s and `mean_legitimate_received_rtt_p95_ms` is the mean of three received-only episode p95s. `intervention_count` sums apply events across the three episodes. `restore_reasons` contains reason counts. Action-delay means average only episodes where an action occurred.\n\nPaired `delta_timely_pp` is method minus no action in percentage points; `delta_suspect_goodput_kbit_s` is the same paired subtraction in decimal kbit/s. A suspect-goodput decrease is desired for the flood but collateral loss for the benign scenario. `paired_episode_contrasts` explicitly keys both sides by VM/scenario/replicate. All conditions use three repetitions; packet counts are not replication counts.""",
        """`equal_across_windows_hosts` compares complete saved fixed-summary objects, not only rounded headlines. Case identity rows retain `group`, `seed`, `count`, `expected_sha256`, `actual_sha256`, and `match`; null seed denotes a file not keyed to a dataset-sampling seed. All 42 case-file identities are retained.\n\nThe regeneration summary distinguishes exact case/workload bytes from parsed aggregate equality. Packet source/return hashes identify historical archives whose source data support the views. A file hash is not a digital signature, privacy certification, or proof that an experiment's scientific claim is true. This exporter reads aggregate evidence; consult the repository's raw-evidence guide for packet logs and full raw Windows measurements.""",
    ]
    for folder, description in zip(FOLDERS, dictionaries, strict=True):
        views.text(folder, "DATA_DICTIONARY.md", "# Column meanings and units\n\n" + description + "\n\nCSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.\n\n[Back to this stage](README.md)")

    # Checks are derived independently of reader-facing narrative and do not gate
    # scientific outcomes. They only detect an incomplete or inconsistent export.
    checks = {
        "status": "PASS", "meaning": "Saved-evidence structure and export arithmetic checks; not a new experiment",
        "output_row_counts": views.counts,
        "checks": ["both Windows fixed policy/dataset summaries equal", "all 12 sensitivity summaries equal", "narrative conformance and false-alarm headline counts match saved evidence", "32 micro and 576 scaling cells retained", "120 load cells and 480 bootstrap summaries retained", "low-rate completion and high-rate overflow/deadline findings match saved evidence", "72 episode rows, 24 condition means, 18 paired comparisons retained", "packet timely/goodput means and paired contrasts agree with episode rows", "three paired replicate identities per method/scenario/VM", "benign abstention and ineffective-action feedback claims match episode records"],
        "source_identities": identities,
    }
    views.text(FOLDERS[0], "export_checks.json", json_text(checks))
    return views


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "evidence" / "summaries", help="Directory holding the two saved JSON evidence inputs")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results", help="Derived result-view directory; original evidence is never changed")
    parser.add_argument("--check", action="store_true", help="Compare all generated views in memory; do not write files")
    args = parser.parse_args()
    loaded, identities = {}, {}
    for filename in (WINDOWS, PACKET):
        data = (args.evidence_dir / filename).read_bytes()
        loaded[filename] = json.loads(data)
        identities[filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "repository_source": "evidence/summaries/" + filename}
    views = build(loaded[WINDOWS], loaded[PACKET], identities)
    problems = []
    for relative, content in sorted(views.files.items()):
        target = args.output_dir / relative
        encoded = content.encode("utf-8")
        if args.check:
            if not target.is_file():
                problems.append("missing: " + relative)
            elif target.read_bytes() != encoded:
                problems.append("different: " + relative)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded)
    if problems:
        print("Result-view verification failed:\n" + "\n".join(problems))
        return 1
    verb = "Verified without modifying" if args.check else "Built"
    print(f"{verb} {len(views.files)} derived files across Stages 0–7. No experiments rerun.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
