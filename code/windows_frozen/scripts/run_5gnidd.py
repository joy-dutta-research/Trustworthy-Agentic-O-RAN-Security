"""Run the checksum-pinned, offline second-source experiment (no credentials)."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.benchmark import run_benchmark
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.nidd_adapter import profile_archive
from oran_trust_boundary.nidd_cases import build_cases
from oran_trust_boundary.provenance import combined_manifest_sha256, sha256_file, source_manifest

FROZEN_FILES = {
    "configs/paper_policy.json": "bf5915cd92557ca193d692273021342e5bfa495878a0d4500742662497e6921c",
    "src/oran_trust_boundary/engine.py": "8876b45a8188d1d33eaeead12178c09ca431a064cdc481b7d0072b7a865f57cd",
    "src/oran_trust_boundary/baselines.py": "6cd02ac76aab4d1d8551eab6c4a78d7ac1d4ab2fd54b6502f53c3e59fc0568f4",
    "src/oran_trust_boundary/contract.py": "afb39c882eace8ae2f382cf908073fa03f9037f08deadbf81c8e9170c3127030",
    "src/oran_trust_boundary/policy.py": "8aeaf472a11ec5d3a7348da142e0241b91730e110e3607740701e20a10ef9401",
    "src/oran_trust_boundary/approval.py": "218f3c7927994dcd0cc8ac053e07897cd6e26d6f94e01ae4fe5b316e3b1b1d21",
    "src/oran_trust_boundary/models.py": "354b745c0b4d4f36f0a2609682e5821475b70d2dc86ddec991f7d1269089c915",
    "src/oran_trust_boundary/audit.py": "d5bad2c1f1b5770da974a41914997bb4dd1fb4cea9fafe4dcc70381f08bf428c",
    "src/oran_trust_boundary/jsonio.py": "2fc6a9c73258f3140868d7debce0252dbaf92cafa4a64051d7942f5ce90a4d2d",
}


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def write_jsonl(path, rows):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False, separators=(",", ":")) + "\n")


def compact_metrics(summary, group):
    result = {"system": summary["system"], "case_count": summary["case_count"],
              "latency_p50_ms": summary["latency_p50_ms"], "latency_p95_ms": summary["latency_p95_ms"],
              "audit_completeness": summary["audit_completeness"]}
    if group == "false_alarm_probes":
        result.update({"benign_disruptive_proposals": summary["case_count"],
                       "benign_disruptive_proposals_admitted": summary["safe_action_accepted_count"],
                       "benign_mitigation_admission_rate": summary["safe_action_acceptance_rate"]})
    else:
        for source, dest in (("safe_case_count", "policy_permitted_cases"),
                             ("safe_action_accepted_count", "policy_permitted_admitted"),
                             ("unsafe_case_count", "policy_block_required_cases"),
                             ("unsafe_action_admitted_count", "policy_block_required_admitted"),
                             ("escalate_case_count", "escalation_required_cases"),
                             ("correct_escalation_count", "correct_escalations"),
                             ("correct_decision_count", "policy_decision_agreement_count")):
            result[dest] = summary[source]
    # No fabricated zero rates for absent strata, nor population CIs on fixtures.
    return result


def build_report(manifest, profile, groups, summaries):
    audit = profile["audit"]
    lines = ["# 5G-NIDD preliminary second-source results", "",
             "Offline record-conditioned policy conformance. Not an IDS accuracy, live-network safety, or mitigation-effectiveness evaluation.", "",
             f"Source: [5G-NIDD public DOI](https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361), CC BY 4.0. Archive SHA-256: `{profile['dataset']['archive_sha256']}`.", "",
             f"Audited **{audit['row_count']:,} flow rows**. Selected **{len(profile['contexts'])} source records** by the predeclared hash-ranked sampling rule. This does not establish independent sessions.", "",
             f"Invalid duration/packet measurements: {audit['invalid_measurement_rows']:,}. Exact parsed-row duplicates (excluding unnamed export indices): {audit['duplicate_rows']:,}. Malformed rows: {audit['malformed_rows']:,}.", "",
             "## Source-label coverage", "", "| Original label | Full-source rows | Eligible unique records | Selected records |", "| --- | ---: | ---: | ---: |"]
    counts = profile["selection"]["selected_counts"]
    for label, count in audit["attack_counts"].items():
        eligible = audit['eligible_unique_counts'].get(label, 'out of scope')
        lines.append(f"| {label} | {count:,} | {eligible} | {counts.get(label, 0)} |")
    lines += ["", "Records with undefined/nonpositive packet rates are excluded from flood selection, not imputed. This excludes many UDP-flood rows, so the selected sample does not represent all flood records."]
    for group in ("conformance", "record_proposals"):
        lines += ["", f"## {group.replace('_', ' ').title()}", "",
                  f"{len(groups[group])} proposals; outcomes expected under the frozen illustrative operator policy, not observed safe-action labels.", "",
                  "| System | Policy-permitted accepted | Policy-block-required admitted | Correct escalation | p95 decision latency (ms) |",
                  "| --- | ---: | ---: | ---: | ---: |"]
        for row in summaries[group]:
            def fraction(numerator, denominator):
                return f"{row[numerator]}/{row[denominator]}" if row[denominator] else "not applicable"
            lines.append(f"| {row['system']} | {fraction('policy_permitted_admitted', 'policy_permitted_cases')} | {fraction('policy_block_required_admitted', 'policy_block_required_cases')} | {fraction('correct_escalations', 'escalation_required_cases')} | {row['latency_p95_ms']:.4f} |")
        if group == "record_proposals" and all(row["policy_block_required_cases"] == 0 for row in summaries[group]):
            lines += ["", "The fixed record-derived proposal rule produced no policy-violating proposals in this sample. This group therefore does **not** demonstrate an admission advantage over the baselines. Comparative blocking evidence comes from the explicitly controlled conformance variants."]
    lines += ["", "## Forced false-alarm limitation", "",
              "These compliant disruptive proposals deliberately reference benign records. Admission is **not** counted as safe acceptance. No claim of false-alarm detection is made.", "",
              "| System | Benign disruptive proposals admitted |", "| --- | ---: |"]
    for row in summaries["false_alarm_probes"]:
        lines.append(f"| {row['system']} | {row['benign_disruptive_proposals_admitted']}/{row['benign_disruptive_proposals']} |")
    lines += ["", "## Interpretation", "",
              "- The gate, policy and baseline files were unchanged and verified by SHA-256 before and after the run.",
              "- The full gate checks governance, not incident truth or the contents of evidence references. A policy-compliant action can therefore be inappropriate for a benign flow.",
              "- Dataset labels are oracle incident context. UE/slice/authority/interface/clock/rollback values are explicitly simulated, not inferred from flow IPs.",
              "- The upstream 1000 packets/s budget is an illustrative fixed stress-test rule, not an O-RAN standard, measured capacity, or validated mitigation strategy.",
              "- Timing repetitions and six variants per base are not independent safety trials. No population confidence intervals are reported.",
              "- Measurements omit ingestion, detection, planning, networking and actuation. Baselines are controlled ablations.",
              "- Independent co-author scenario review is still required before journal use. Results are preliminary and have not been selected or tuned to improve the outcome.", "",
              "Reproduce using `scripts/download_5gnidd.py`, then `scripts/run_5gnidd.py`. See `docs/5gnidd_protocol.md` and the accompanying manifest, data audit, cases, raw decisions and metrics.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "data/raw/5g-nidd/Combined.zip")
    parser.add_argument("--output", type=Path, default=ROOT / "results/local" / ("5gnidd_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--repeats", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 1000:
        parser.error("--repeats must be between 1 and 1000")
    for filename, expected in FROZEN_FILES.items():
        if sha256_file(ROOT / filename) != expected:
            parser.error(f"frozen file changed: {filename}; create a new protocol version")
    if args.output.exists():
        parser.error("output already exists; choose a fresh directory to preserve prior runs")
    sources = source_manifest(ROOT)
    protocol_sha256 = sha256_file(ROOT / "docs/5gnidd_protocol.md")
    started = datetime.now(UTC).isoformat()
    print("Auditing checksum-pinned 5G-NIDD archive and selecting records...", flush=True)
    profile = profile_archive(args.archive)
    groups = build_cases(profile["contexts"])
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output / "dataset_audit.json", profile)
    engine = TrustBoundary.from_file(ROOT / "configs/paper_policy.json")
    summaries = {}
    for group, cases in groups.items():
        write_jsonl(args.output / f"{group}_cases.jsonl", cases)
        raw, aggregate = run_benchmark(cases, engine, repeats=args.repeats, timing_seed=20260922)
        case_by_id = {case["case_id"]: case for case in cases}
        for row in raw:
            context = case_by_id[row["case_id"]]
            row.update({"experiment_group": group, "base_record_id": context["base_record_id"],
                        "expectation_semantics": "frozen_policy_not_physical_safety"})
        write_jsonl(args.output / f"{group}_decisions.jsonl", raw)
        summaries[group] = [compact_metrics(row, group) for row in aggregate]
        print(f"{group}: {len(cases)} proposals, {len(raw)} system decisions", flush=True)
    write_json(args.output / "metrics.json", summaries)
    if source_manifest(ROOT) != sources:
        raise RuntimeError("source files changed during experiment; results incomplete, rerun in fresh directory")
    if sha256_file(ROOT / "docs/5gnidd_protocol.md") != protocol_sha256:
        raise RuntimeError("protocol changed during experiment; results incomplete")
    import platform
    import time
    manifest = {"status": "completed_preliminary_unreviewed", "started_at_utc": started,
                "finished_at_utc": datetime.now(UTC).isoformat(), "python": platform.python_version(),
                "os": platform.system(), "machine": platform.machine(),
                "timing": {"repeats": args.repeats, "warmups": 5, "seed": 20260922,
                           "clock": time.get_clock_info("perf_counter").implementation},
                "frozen_files": FROZEN_FILES, "source_files": sources,
                "source_tree_sha256": combined_manifest_sha256(sources),
                "protocol_sha256": protocol_sha256,
                "dataset_archive_sha256": profile["dataset"]["archive_sha256"],
                "case_groups": {name: dict(Counter(case["expected_decision"] for case in cases)) for name, cases in groups.items()},
                "outputs": {path.name: sha256_file(path) for path in sorted(args.output.iterdir()) if path.is_file()},
                "limitation": "Constructed policy expectations; not detector accuracy or real mitigation safety. False-alarm probes are separate."}
    report = build_report(manifest, profile, groups, summaries)
    report_path = args.output / "REPORT.md"
    with report_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(report)
    manifest["outputs"]["REPORT.md"] = sha256_file(report_path)
    write_json(args.output / "run_manifest.json", manifest)
    print(f"Completed. Report: {report_path}", flush=True)


if __name__ == "__main__":
    main()
