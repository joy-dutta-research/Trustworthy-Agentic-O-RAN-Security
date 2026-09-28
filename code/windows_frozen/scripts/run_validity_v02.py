"""Run new v0.2 validity/control campaigns without modifying frozen v0.1.

Use only after source/protocol freezing. A supervising runner is responsible
for declared OS memory/disk/wall limits on final campaigns.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime
from itertools import islice
import json
import hashlib
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.approval import ApprovalVerification, StaticApprovalRegistry
from oran_trust_boundary.baselines import direct_execution, contract_only, contract_rbac
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.contract import parse_action
from oran_trust_boundary.models import Decision
from oran_trust_boundary.evaluation_reference import ReferencePolicy, canonical_digest
from oran_trust_boundary.evaluation_cases import iter_stage1_cases, iter_netslab_cases, coverage_report, make_case, seal_case


def dump_line(handle, value):
    handle.write(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_one(case, policy, engine_class=TrustBoundary, verifier=None):
    engine = engine_class(policy, approval_verifier=verifier or StaticApprovalRegistry(case.get("approval_registry", {})))
    return engine.evaluate(case["proposal"], active_actions=case.get("active_actions", []),
                           authenticated_principal=case.get("authenticated_principal"),
                           as_of=datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00")))


def mutation_report(cases, policy):
    methods = ("identity", "authorization", "interface", "target_type", "freshness", "protected_target",
               "parameters", "risk_floor", "ttl", "rollback", "conflicts", "approval")
    mutations = [("disable_" + method, type("TestOnlyMutation", (TrustBoundary,), {"_check_" + method: lambda *args: None}), None)
                 for method in methods]

    class IgnoreApprovalBinding:
        def verify(self, *args):
            return ApprovalVerification(True, "TEST_MUTANT_TRUSTS_BINDING")

    class EscalateInsteadOfDeny(TrustBoundary):
        def evaluate(self, *args, **kwargs):
            result = super().evaluate(*args, **kwargs)
            proposal, issues = parse_action(args[0])
            if result.decision == Decision.DENY and proposal is not None and not issues:
                reasons, rules = [], []
                self._check_conflicts(proposal, kwargs.get("active_actions", []), reasons, rules)
                self._check_approval(proposal, kwargs["as_of"], reasons, rules)
                if reasons:
                    return replace(result, decision=Decision.ESCALATE)
            return result

    mutations += [("ignore_approval_binding", TrustBoundary, IgnoreApprovalBinding()),
                  ("escalation_overrides_hard_denial", EscalateInsteadOfDeny, None)]
    outcomes = []
    for name, cls, verifier in mutations:
        witnesses, errors = [], []
        for case in cases:
            try:
                result = run_one(case, policy, cls, verifier)
            except Exception as exc:
                errors.append({"case_id": case["case_id"], "error_type": type(exc).__name__})
                continue
            if result.decision.value != case["expected_decision"]:
                witnesses.append(case["case_id"])
        outcomes.append({"mutation": name, "detected": bool(witnesses), "decision_mismatch_count": len(witnesses),
                         "first_witnesses": witnesses[:5], "unhandled_errors": errors})
    return {"scope": "14 predeclared test-only targeted mutations; not exhaustive fault coverage",
            "mutations": outcomes, "detected": sum(item["detected"] for item in outcomes),
            "survivors": [item["mutation"] for item in outcomes if not item["detected"]]}


def property_report(policy):
    records = []
    for action in ReferencePolicy().spec["actions"]:
        base = make_case(action, "property-" + action)
        original = run_one(base, policy)
        probes = []
        no_authority = deepcopy(base)
        no_authority["authenticated_principal"] = None
        probes.append(("removing_authenticated_authority_never_grants", no_authority, "not_allow"))
        reordered = deepcopy(base)
        reordered["proposal"] = dict(reversed(list(reordered["proposal"].items())))
        probes.append(("object_key_order_invariant", reordered, "same"))
        probes.append(("fixed_input_decision_repeatability", deepcopy(base), "same"))
        if action in policy["disruptive_actions"]:
            protected = deepcopy(base)
            protected["proposal"]["target"]["slice_id"] = "slice-emergency"
            probes.append(("applicable_protected_service_never_admitted", seal_case(protected), "not_allow"))
        if base["proposal"]["approval"] is not None:
            changed = deepcopy(base)
            changed["proposal"]["incident_id"] += "-changed-after-approval"
            probes.append(("changed_proposal_cannot_reuse_approval", changed, "not_allow"))
        for name, case, expected in probes:
            result = run_one(case, policy)
            passed = original.decision == Decision.ALLOW and (
                result.decision != Decision.ALLOW if expected == "not_allow"
                else (result.decision, set(result.reason_codes)) == (original.decision, set(original.reason_codes)))
            records.append({"property": name, "action": action, "passed": passed,
                            "fixture": case, "original_decision": original.decision.value,
                            "actual_decision": result.decision.value, "actual_reasons": list(result.reason_codes)})
    return {"scope": "scoped properties on six valid action witnesses; not universal proofs",
            "checks": records, "passed": sum(row["passed"] for row in records),
            "failed": sum(not row["passed"] for row in records)}


def legacy_reference_audit(reference):
    """Compare preserved legacy labels, never use them to construct new answers."""
    suite = ROOT / "data/conformance/conformance_v0.1.jsonl"
    registry_path = ROOT / "data/conformance/approval_registry_v0.1.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))["approvals"]
    rows = []
    with suite.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            case = json.loads(line)
            case["approval_registry"] = registry
            answer = reference.evaluate(case)
            rows.append({"case_id": case["case_id"], "legacy_expected": case["expected_decision"],
                         "legacy_expected_reason": case["expected_reason"], "reference": answer,
                         "decision_agreement": answer["decision"] == case["expected_decision"],
                         "legacy_reason_present": case["expected_reason"] in answer["reasons"]})
    return {"scope": "Original frozen 120 cases, independently reinterpreted; not new source observations",
            "suite_sha256": file_digest(suite), "approval_registry_sha256": file_digest(registry_path),
            "case_count": len(rows), "decision_disagreements": sum(not row["decision_agreement"] for row in rows),
            "reason_disagreements": sum(not row["legacy_reason_present"] for row in rows), "cases": rows}


def run(mode: str, output: Path, pilot_limit: int | None = None, seeds=range(1000, 1020)) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    reference = ReferencePolicy()
    policy = reference.operator_policy
    inputs = iter_stage1_cases() if mode == "validity" else iter_netslab_cases(seeds)
    if pilot_limit is not None:
        inputs = islice(inputs, pilot_limit)
    counts = defaultdict(Counter)
    stratified = defaultdict(Counter)
    group_counts = Counter()
    semantics = set()
    violations = Counter()
    all_cases = []
    mismatches, errors, reason_mismatches, audit_failures = [], [], [], []
    status_path = output / "INCOMPLETE.json"
    status_path.write_text(json.dumps({"status": "RUNNING", "mode": mode}) + "\n", encoding="utf-8")
    try:
        with (output / "cases.jsonl").open("x", encoding="utf-8", newline="\n") as cases_out, (output / "decisions.jsonl").open("x", encoding="utf-8", newline="\n") as decisions_out:
            for ordinal, case in enumerate(inputs, 1):
                dump_line(cases_out, case)
                if mode == "validity":
                    all_cases.append(case)
                semantics.add(case["semantic_sha256"])
                group_counts[case.get("suite_group", "unspecified")] += 1
                violations.update(case["expected_reference"]["violated_rules"])
                kwargs = {"active_actions": case.get("active_actions", []), "authenticated_principal": case.get("authenticated_principal"),
                          "as_of": datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00"))}
                engine = TrustBoundary(policy, StaticApprovalRegistry(case["approval_registry"]))
                for name, evaluator in (("direct", direct_execution), ("contract", contract_only),
                                        ("contract_rbac", lambda p, **kw: contract_rbac(p, policy=policy, **kw)), ("trust_boundary", engine.evaluate)):
                    row = {"case_id": case["case_id"], "system": name, "seed": case.get("seed"),
                           "category": case["category"], "suite_group": case.get("suite_group"),
                           "expected_decision": case["expected_decision"]}
                    try:
                        result = evaluator(case["proposal"], **kwargs)
                        row.update(result.to_mapping())
                        expected = case["expected_decision"]
                        count = counts[name]
                        count["evaluations"] += 1
                        count["decision_" + result.decision.value] += 1
                        count["reference_allow"] += expected == "ALLOW"
                        count["reference_block_required"] += expected != "ALLOW"
                        count["reference_allow_admitted"] += expected == "ALLOW" and result.decision.value == "ALLOW"
                        count["policy_block_required_admitted"] += expected != "ALLOW" and result.decision.value == "ALLOW"
                        count["decision_agreement"] += expected == result.decision.value
                        for stratum in ("group:" + case.get("suite_group", "unspecified"),
                                        "seed:" + str(case.get("seed", "not_applicable")),
                                        "action:" + case["proposal"].get("action", "invalid")):
                            group_count = stratified[(name, stratum)]
                            group_count["evaluations"] += 1
                            group_count["reference_" + expected] += 1
                            group_count["actual_" + result.decision.value] += 1
                            group_count["agreement"] += expected == result.decision.value
                            group_count["policy_block_required_admitted"] += expected != "ALLOW" and result.decision.value == "ALLOW"
                        row["agrees_with_full_reference"] = result.decision.value == expected
                        if name == "trust_boundary":
                            if not row["agrees_with_full_reference"]:
                                mismatches.append(case["case_id"])
                            reason_mode = case["expected_reference"]["reason_comparison"]
                            reason_ok = bool(result.reason_codes) if reason_mode == "structural_nonempty" else set(result.reason_codes) == set(case["expected_reasons"])
                            row["required_reason_check"] = reason_ok
                            if not reason_ok:
                                reason_mismatches.append(case["case_id"])
                            if not result.audit_record or not set(policy["audit_required_fields"]) <= result.audit_record.keys():
                                audit_failures.append(case["case_id"])
                    except Exception as exc:
                        row["error"] = {"type": type(exc).__name__, "message": str(exc)}
                        errors.append({"case_id": case["case_id"], "system": name, **row["error"]})
                    dump_line(decisions_out, row)
                if ordinal % 1000 == 0:
                    print(json.dumps({"mode": mode, "cases_completed": ordinal}), flush=True)
        summary = {"mode": mode, "status": "PILOT_NOT_CONFIRMATORY" if pilot_limit else "COMPLETED",
                   "constructed_case_count": sum(group_counts.values()), "unique_semantic_configurations": len(semantics),
                   "groups": dict(group_counts), "rule_violation_coverage": dict(violations),
                   "comparators": {name: dict(value) for name, value in counts.items()}, "full_gateway_decision_mismatches": mismatches,
                   "stratified": [{"system": system, "stratum": stratum, **dict(value)} for (system, stratum), value in sorted(stratified.items())],
                   "full_gateway_reason_mismatches": reason_mismatches, "audit_failures": audit_failures, "unhandled_errors": errors,
                   "reference_author_verification": reference.spec["author_table_verification"],
                   "interpretation": "Constructed policy-conformance coverage, not independent safety trials or operational assurance."}
        if mode == "validity":
            summary["interaction_coverage"] = coverage_report(all_cases)
            if not pilot_limit:
                summary["test_sensitivity"] = mutation_report(all_cases, policy)
                summary["scoped_properties"] = property_report(policy)
                summary["legacy_reference_audit"] = legacy_reference_audit(reference)
        coverage_failed = mode == "validity" and not pilot_limit and (
            bool(summary["interaction_coverage"]["pairwise_missing"])
            or any(value["covered"] != value["required"] for value in summary["interaction_coverage"]["targeted_three_way"].values())
            or bool(summary["test_sensitivity"]["survivors"])
            or bool(summary["scoped_properties"]["failed"])
            or bool(summary["legacy_reference_audit"]["decision_disagreements"])
            or bool(summary["legacy_reference_audit"]["reason_disagreements"]))
        if mismatches or reason_mismatches or audit_failures or errors or coverage_failed:
            summary["status"] = "COMPLETED_WITH_FINDINGS"
        (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "REPORT.md").write_text(
            f"# v0.2 {mode} evaluation\n\nStatus: {summary['status']}.\n\n"
            f"Constructed cases: {summary['constructed_case_count']}; normalized configurations: {len(semantics)}.\n\n"
            f"Gateway decision disagreements: {len(mismatches)}; reason disagreements: {len(reason_mismatches)}; unhandled errors: {len(errors)}.\n\n"
            "See summary.json and the preserved per-case decisions. Ablation disagreements with the full reference are expected, not software failures.\n\n"
            "The unchanged policy retains its documented limitations. This evaluation does not establish incident truth, operational safety, detection accuracy or network benefit.\n", encoding="utf-8")
        # Initial RUNNING receipt is intentionally preserved; only this final
        # marker closes the attempt. A consumer must verify the artifact hashes.
        completion = {"status": summary["status"], "mode": mode,
                      "constructed_case_count": summary["constructed_case_count"],
                      "files": {name: {"sha256": file_digest(output / name)} for name in
                                ("cases.jsonl", "decisions.jsonl", "summary.json", "REPORT.md")},
                      "initial_receipt": "INCOMPLETE.json is the preserved start marker; COMPLETE.json closes this attempt."}
        if errors:
            completion["status"] = "INCOMPLETE_TECHNICAL_ERROR"
            (output / "FAILED.json").write_text(json.dumps(completion, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            (output / "COMPLETE.json").write_text(json.dumps(completion, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return summary
    except BaseException:
        (output / "failure.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("validity", "netslab"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pilot-limit", type=int)
    args = parser.parse_args()
    if args.pilot_limit is not None and not 1 <= args.pilot_limit <= 1000:
        parser.error("pilot limit must be 1..1000")
    summary = run(args.mode, args.output, args.pilot_limit)
    print(json.dumps({"output": str(args.output), "status": summary["status"]}), flush=True)
    return 1 if summary["unhandled_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
