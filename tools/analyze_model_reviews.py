#!/usr/bin/env python3
"""Recompute the auxiliary model-review tables, without calling any model.

Python 3.10+; standard library only. Default: regenerate derived results.
--check: compare expected bytes with saved results without writing any files.
The input responses, policy, cases and post-review crosswalks are never edited.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from datetime import date
from pathlib import Path

LABELS = ("ALLOW", "DENY", "ESCALATE", "INSUFFICIENT_INFORMATION")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path):
    def reject_constant(value):
        raise ValueError(f"Non-finite JSON number: {value}")
    return json.loads(path.read_text(encoding="utf-8-sig"),
                      object_pairs_hook=unique_object, parse_constant=reject_constant)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources(root):
    manifest = read_json(root / "model_review/SOURCE_MANIFEST.json")
    for item in manifest["files"]:
        path = (root / item["public_path"]).resolve()
        require(path.is_relative_to(root.resolve()), "Source path escapes the repository")
        require(path.is_file(), f"Missing source: {item['public_path']}")
        require(digest(path) == item["public_sha256"], f"Source hash mismatch: {item['public_path']}")
    return manifest


def validate_response(response, package, mapping, reviewer):
    require(response["package_id"] == package["package_id"] == mapping["package_id"],
            f"{reviewer}: mismatched package identifiers")
    require(set(response) == {"package_id", "run_metadata", "decisions", "policy_critique"},
            f"{reviewer}: unexpected top-level response fields")
    metadata = response["run_metadata"]
    require(set(metadata) == {"model_name_as_displayed", "mode_as_displayed", "run_date_utc", "tools_used", "unavailable_settings"},
            f"{reviewer}: unexpected metadata fields")
    for name in ("model_name_as_displayed", "mode_as_displayed", "run_date_utc"):
        require(isinstance(metadata[name], str) and bool(metadata[name]), f"{reviewer}: invalid {name}")
    require(date.fromisoformat(metadata["run_date_utc"]).isoformat() == metadata["run_date_utc"],
            f"{reviewer}: invalid ISO calendar date")
    for name in ("tools_used", "unavailable_settings"):
        require(isinstance(metadata[name], list) and all(isinstance(x, str) for x in metadata[name]),
                f"{reviewer}: invalid {name}")
    require(isinstance(response["policy_critique"], list) and all(isinstance(x, str) for x in response["policy_critique"]),
            f"{reviewer}: invalid policy critique")
    case_ids = [case["review_id"] for case in package["cases"]]
    require(len(case_ids) == len(set(case_ids)) == 120, f"{reviewer}: expected 120 unique case IDs")
    require(set(case_ids) == set(mapping["review_id_to_case_id"]), f"{reviewer}: incomplete crosswalk")
    base_ids = list(mapping["review_id_to_case_id"].values())
    require(len(base_ids) == len(set(base_ids)) == 120, f"{reviewer}: non-bijective crosswalk")
    require(set(base_ids) == set(mapping["constructed_references"]), f"{reviewer}: missing references")
    require(isinstance(response["decisions"], list) and len(response["decisions"]) == 120,
            f"{reviewer}: expected 120 decisions")
    output = {}
    for record in response["decisions"]:
        require(set(record) == {"review_id", "decision", "rationale", "rule_refs", "ambiguity", "notes"},
                f"{reviewer}: unexpected decision fields")
        review_id = record["review_id"]
        require(review_id in case_ids and review_id not in output, f"{reviewer}: duplicate or unknown review ID")
        require(record["decision"] in LABELS, f"{reviewer}: unknown decision label")
        require(type(record["ambiguity"]) is bool, f"{reviewer}: ambiguity must be boolean")
        require(isinstance(record["rationale"], str) and bool(record["rationale"].strip()), f"{reviewer}: empty rationale")
        require(isinstance(record["notes"], str), f"{reviewer}: invalid notes")
        require(isinstance(record["rule_refs"], list) and all(isinstance(x, str) for x in record["rule_refs"]),
                f"{reviewer}: invalid rule references")
        output[review_id] = record
    require(set(output) == set(case_ids), f"{reviewer}: incomplete response")
    return {mapping["review_id_to_case_id"][key]: value for key, value in output.items()}


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def csv_bytes(rows, fields):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def analyze(root):
    manifest = verify_sources(root)
    responses, packages, mappings, decisions, summaries = {}, {}, {}, {}, {}
    for reviewer in ("reviewer_a", "reviewer_b"):
        responses[reviewer] = read_json(root / f"model_review/responses/{reviewer}.json")
        packages[reviewer] = read_json(root / f"model_review/inputs/{reviewer}/CASES.json")
        mappings[reviewer] = read_json(root / f"model_review/post_review/{reviewer}_mapping.json")
        decisions[reviewer] = validate_response(responses[reviewer], packages[reviewer], mappings[reviewer], reviewer)
        counts = Counter(row["decision"] for row in decisions[reviewer].values())
        references = mappings[reviewer]["constructed_references"]
        summaries[reviewer] = {
            "case_count": len(decisions[reviewer]),
            "label_counts": {label: counts[label] for label in LABELS},
            "reference_matching_count": sum(row["decision"] == references[key]["decision"] for key, row in decisions[reviewer].items()),
            "ambiguity_count": sum(row["ambiguity"] for row in decisions[reviewer].values()),
            "nonempty_rule_reference_count": sum(bool(row["rule_refs"]) for row in decisions[reviewer].values()),
            "empty_rule_reference_count": sum(not row["rule_refs"] for row in decisions[reviewer].values()),
            "empty_rule_refs_by_decision": {label: sum(row["decision"] == label and not row["rule_refs"] for row in decisions[reviewer].values()) for label in LABELS},
            "policy_critique_count": len(responses[reviewer]["policy_critique"]),
            "run_metadata": responses[reviewer]["run_metadata"],
        }
    require(mappings["reviewer_a"]["constructed_references"] == mappings["reviewer_b"]["constructed_references"],
            "Constructed references differ between reviewers")
    for name in ("POLICY.json", "ACTION_SCHEMA.json"):
        require((root / f"model_review/inputs/reviewer_a/{name}").read_bytes() == (root / f"model_review/inputs/reviewer_b/{name}").read_bytes(),
                f"Reviewer inputs differ for {name}")
    confusion = {left: {right: 0 for right in LABELS} for left in LABELS}
    rows = []
    case_contexts = {mappings["reviewer_a"]["review_id_to_case_id"][row["review_id"]]: row["source_context"] for row in packages["reviewer_a"]["cases"]}
    for case_id in sorted(decisions["reviewer_a"]):
        a, b = (decisions[r][case_id] for r in ("reviewer_a", "reviewer_b"))
        ref = mappings["reviewer_a"]["constructed_references"][case_id]
        confusion[a["decision"]][b["decision"]] += 1
        row = {"case_id": case_id, "source_ref": case_contexts[case_id]["source_ref"],
               "reference_decision": ref["decision"], "reference_reason": ref["reason"],
               "pairwise_agreement": a["decision"] == b["decision"]}
        for short, item in (("a", a), ("b", b)):
            row.update({f"reviewer_{short}_{key}": item[key] for key in ("review_id", "decision", "rationale", "notes", "ambiguity")})
            row[f"reviewer_{short}_rule_refs_json"] = json.dumps(item["rule_refs"], ensure_ascii=False)
            row[f"reviewer_{short}_rule_refs_present"] = bool(item["rule_refs"])
            row[f"reviewer_{short}_reference_agreement"] = item["decision"] == ref["decision"]
        rows.append(row)
    decided = [row for row in rows if row["reviewer_a_decision"] != LABELS[-1] and row["reviewer_b_decision"] != LABELS[-1]]
    joint_n = len(decided)
    observed = sum(row["pairwise_agreement"] for row in decided) / joint_n if joint_n else None
    if joint_n:
        left = Counter(row["reviewer_a_decision"] for row in decided)
        right = Counter(row["reviewer_b_decision"] for row in decided)
        expected = sum(left[label] * right[label] for label in LABELS[:-1]) / (joint_n ** 2)
        kappa = (observed - expected) / (1 - expected) if expected < 1 else None
    else:
        kappa = None
    critique_rows = [{"reviewer": reviewer, "critique_number": number, "critique": critique}
                     for reviewer in responses for number, critique in enumerate(responses[reviewer]["policy_critique"], 1)]
    summary = {
        "schema_version": 1,
        "scope": "Auxiliary answer-masked 120-case policy-consistency review; not Stage 8 or runtime LLM evaluation.",
        "source_manifest_file_count": len(manifest["files"]),
        "case_count": len(rows),
        "reviewers": summaries,
        "pairwise_matching_count": sum(row["pairwise_agreement"] for row in rows),
        "pairwise_agreement_fraction": sum(row["pairwise_agreement"] for row in rows) / len(rows),
        "joint_decided_count": joint_n,
        "cohens_kappa_among_joint_decided": kappa,
        "confusion_reviewer_a_rows_reviewer_b_columns": confusion,
        "source_reference_counts": dict(sorted(Counter(row["source_ref"] for row in rows).items())),
        "disagreement_case_ids": [row["case_id"] for row in rows if not row["pairwise_agreement"]],
        "abstention_or_ambiguity_case_ids": [row["case_id"] for row in rows if row["reviewer_a_ambiguity"] or row["reviewer_b_ambiguity"] or LABELS[-1] in (row["reviewer_a_decision"], row["reviewer_b_decision"])],
        "model_identification": read_json(root / "model_review/MODEL_IDENTIFICATION.json"),
        "interpretation": "Agreement with declared fixture rules supports policy-interpretation consistency. Constructed references are not independent ground truth. Human policy approval, service-enforced isolation and displayed model versions are not established by these records.",
    }
    historical = read_json(root / "model_review/post_review/original_comparison.json")
    require(summary["case_count"] == historical["case_count"], "Historical case count differs")
    require(summary["pairwise_agreement_fraction"] == historical["all_label_agreement_including_abstentions"],
            "Historical pairwise agreement differs")
    require(kappa == historical["cohens_kappa_among_joint_decided"], "Historical kappa differs")
    require(confusion == historical["confusion_including_abstentions"], "Historical confusion matrix differs")
    for reviewer, old_name in (("reviewer_a", "first"), ("reviewer_b", "second")):
        require(summaries[reviewer]["reference_matching_count"] == historical["constructed_reference_agreement"][old_name]["matching_count"],
                f"Historical reference agreement differs: {reviewer}")
    summary["historical_comparison_checked"] = True
    summary_rows = [{"reviewer": reviewer, "case_count": s["case_count"],
                     **{label.lower(): s["label_counts"][label] for label in LABELS},
                     "reference_matching_count": s["reference_matching_count"],
                     "ambiguity_count": s["ambiguity_count"],
                     "nonempty_rule_reference_count": s["nonempty_rule_reference_count"],
                     "empty_rule_reference_count": s["empty_rule_reference_count"],
                     "policy_critique_count": s["policy_critique_count"]} for reviewer, s in summaries.items()]
    lines = ["# Model-review results", "", "These tables are recomputed from the preserved first responses and the released post-review crosswalks. No model is called by this analysis.", "",
             "| Measure | Reviewer A | Reviewer B |", "| --- | ---: | ---: |"]
    for title, key in (("Complete unique responses", "case_count"), ("Reference matches", "reference_matching_count"), ("Ambiguity flags", "ambiguity_count"), ("Decisions with explicit rule references", "nonempty_rule_reference_count"), ("Decisions without explicit rule references", "empty_rule_reference_count")):
        lines.append(f"| {title} | {summaries['reviewer_a'][key]} | {summaries['reviewer_b'][key]} |")
    for label in LABELS:
        lines.append(f"| {label} | {summaries['reviewer_a']['label_counts'][label]} | {summaries['reviewer_b']['label_counts'][label]} |")
    lines += ["", f"Pairwise decision agreement: **{summary['pairwise_matching_count']}/{len(rows)}**. Cohen's kappa among jointly decided cases: **{kappa if kappa is not None else 'undefined'}**.", "",
              "The two reviews agree on the stated policy decisions. Explicit rule citations remain an opportunity to improve explanation traceability: Reviewer B left 40 such fields empty (20 ALLOW and 20 conflict-related ESCALATE cases), while supplying a rationale for every case. The supplied schema permits empty rule-reference arrays.", "",
              "The useful contribution is a separately recorded check that the written policy can be interpreted consistently. The open-ended critiques also identify concrete next steps for target mapping, policy maintenance and cumulative-action controls. See [the interpretation](INTERPRETATION.md) before citing these descriptive results.", "",
              "These are 120 constructed cases, including related variants, not independent incidents. The review does not measure detector accuracy, model effectiveness in the controller, or operational safety. Displayed model/mode identities and service-enforced blinding were not independently verified. All original critiques remain available.", ""]
    return {
        "summary.json": json_bytes(summary),
        "summary.csv": csv_bytes(summary_rows, list(summary_rows[0])),
        "case_comparison.csv": csv_bytes(rows, list(rows[0])),
        "policy_critiques.csv": csv_bytes(critique_rows, ["reviewer", "critique_number", "critique"]),
        "SUMMARY.md": "\n".join(lines).encode("utf-8"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true", help="Read-only comparison against saved derived tables")
    args = parser.parse_args()
    root = args.root.resolve()
    outputs = analyze(root)
    destination = root / "results/08_model_review"
    if args.check:
        for name, expected in outputs.items():
            require((destination / name).is_file() and (destination / name).read_bytes() == expected,
                    f"Derived result differs or is missing: {name}")
        print(f"PASS: {len(outputs)} derived files match recomputation; no files changed.")
    else:
        destination.mkdir(parents=True, exist_ok=True)
        for name, content in outputs.items():
            (destination / name).write_bytes(content)
        print(f"Wrote {len(outputs)} derived files to results/08_model_review; source files unchanged.")


if __name__ == "__main__":
    main()
