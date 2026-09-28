"""New, reproducible constructed cases; no imports from the frozen case generator."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from itertools import combinations, product
import math
import random
from typing import Iterable

from .evaluation_reference import ReferencePolicy, canonical_digest

EVALUATION_TIME = "2026-01-15T12:05:00Z"
NOW = datetime.fromisoformat(EVALUATION_TIME.replace("Z", "+00:00"))
ACTION_SPECS = {
    "rate_limit_ue": ("E2", "ue", "medium", "traffic_rate_limit", "reduction_percent", 30),
    "quarantine_ue": ("E2", "ue", "medium", "ue_admission_state", "duration_seconds", 120),
    "isolate_xapp": ("SMO", "xapp", "high", "xapp_execution_state", "duration_seconds", 300),
    "modify_a1_policy": ("A1", "policy", "high", "a1_policy_weight", "policy_weight", 0.5),
    "rollback_policy": ("A1", "policy", "high", "a1_policy_state", "snapshot_id", "snapshot-fixture"),
    "notify_operator": ("SMO", "operator", "low", "operator_notification", "message", "Offline notification"),
}
RULES = {"identity": "R02", "authorization": "R03", "interface": "R04", "target": "R05",
         "freshness": "R06", "protected": "R07", "parameter": "R08", "risk": "R09",
         "ttl": "R10", "rollback": "R11", "conflict": "R12", "approval": "R13"}


def stamp(age: float) -> str:
    return (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z")


def seal_case(case: dict) -> dict:
    """Return an isolated case with a legitimate approval for its exact proposal."""
    result = deepcopy(case)
    p = result["proposal"]
    result["approval_registry"] = {}
    if p["risk_level"] in ("high", "critical") or p["action"] in ("isolate_xapp", "modify_a1_policy", "rollback_policy"):
        if p["approval"] is None:
            p["approval"] = {"approval_id": "approval-" + p["action_id"],
                             "approved_by_role": "human_operator", "expires_at": stamp(-3600)}
        approval = p["approval"]
        result["approval_registry"][approval["approval_id"]] = {
            "status": "approved", "action_id": p["action_id"], "agent_id": p["agent"]["agent_id"],
            "approved_by_role": approval["approved_by_role"], "expires_at": approval["expires_at"],
            "proposal_sha256": canonical_digest(p)}
    return result


def make_case(action: str = "rate_limit_ue", case_id: str = "fixture") -> dict:
    interface, target, risk, control, field, value = ACTION_SPECS[action]
    p = {"action_id": case_id, "incident_id": "incident-fixture", "requested_at": stamp(10),
         "agent": {"agent_id": "agent-orchestrator-01", "role": "security_orchestrator"},
         "action": action, "interface": interface,
         "target": {"target_type": target, "target_id": target + "-fixture", "cell_id": "cell-fixture", "slice_id": "slice-best-effort"},
         "parameters": {"control_parameter": control, field: value}, "risk_level": risk,
         "ttl_seconds": 300, "expected_kpi": "offline_policy_check", "rollback": {"available": True, "procedure": "Restore offline fixture."},
         "evidence_refs": ["fixture:unverified-context"], "approval": None}
    return seal_case({"case_id": case_id, "proposal": p, "authenticated_principal": "agent-orchestrator-01",
                      "active_actions": [], "evaluation_time": EVALUATION_TIME, "category": "compliant",
                      "source_context": {"kind": "constructed_governance_fixture"}})


def attach_expectation(case: dict, reference: ReferencePolicy | None = None) -> dict:
    result = deepcopy(case)
    result["expected_reference"] = (reference or ReferencePolicy()).evaluate(result)
    result["expected_decision"] = result["expected_reference"]["decision"]
    result["expected_reasons"] = result["expected_reference"]["reasons"]
    result["semantic_sha256"] = semantic_hash(result)
    return result


def semantic_hash(case: dict) -> str:
    """Normalize opaque IDs but retain equality relations and approval trust/binding.

    Source labels and valid evidence pointer strings are not decision features.
    Structural validity and equality relations are retained. This is fixture-semantic normalization,
    not a claim to partition the entire engine input space minimally.
    """
    value = deepcopy({key: case.get(key) for key in
                      ("proposal", "active_actions", "authenticated_principal", "evaluation_time", "approval_registry")})
    p = value["proposal"]
    registry = value.pop("approval_registry") or {}
    if isinstance(p, dict):
        def string_profile(item, maximum):
            return {"type": type(item).__name__, "valid": isinstance(item, str) and bool(item.strip()) and len(item) <= maximum}
        value["opaque_identifier_profiles"] = {key: string_profile(p.get(key), 128) for key in ("action_id", "incident_id")}
        evidence = p.get("evidence_refs")
        if isinstance(evidence, list):
            value["evidence_profile"] = {"count": len(evidence), "valid_strings": all(string_profile(item, 256)["valid"] for item in evidence),
                                         "unique_count": len({canonical_digest(item) for item in evidence})}
        approval = p.get("approval")
        if isinstance(approval, dict):
            record = registry.get(approval.get("approval_id"))
            value["approval_relationship"] = None if not isinstance(record, dict) else {
                "status": record.get("status"),
                "action_matches": record.get("action_id") == p.get("action_id"),
                "agent_matches": record.get("agent_id") == p.get("agent", {}).get("agent_id"),
                "role_matches": record.get("approved_by_role") == approval.get("approved_by_role"),
                "expiry_matches": record.get("expires_at") == approval.get("expires_at"),
                "digest_matches": record.get("proposal_sha256") == canonical_digest(p)}
            approval["approval_id"] = "approval-normalized"
        original_id = p.get("action_id")
        p["action_id"] = "proposal-normalized"
        p["incident_id"] = "incident-normalized"
        if isinstance(p.get("evidence_refs"), list):
            p["evidence_refs"] = ["reference" for _ in p["evidence_refs"]]
        for active in value["active_actions"] or []:
            if isinstance(active, dict):
                active["_opaque_profiles"] = {key: string_profile(active.get(key), 128) for key in ("action_id", "incident_id")}
                active["action_id"] = "proposal-normalized" if active.get("action_id") == original_id else "other-active"
                active["incident_id"] = "incident-normalized"
                if isinstance(active.get("approval"), dict):
                    active["approval"]["approval_id"] = "active-approval"
                if isinstance(active.get("evidence_refs"), list):
                    active["evidence_refs"] = ["reference" for _ in active["evidence_refs"]]
    return canonical_digest(value)


def applicable_factors(action: str) -> list[str]:
    factors = list(RULES)
    if action == "notify_operator":
        factors.remove("authorization")
        factors.remove("risk")
    if action in ("notify_operator", "rollback_policy"):
        factors.remove("protected")
        factors.remove("rollback")
    return factors


def apply_faults(case: dict, factors: Iterable[str]) -> dict:
    factors = tuple(factors)
    result = deepcopy(case)
    p = result["proposal"]
    if "approval" in factors:
        p["risk_level"] = "high"  # Make missing approval applicable to every action.
    if "identity" in factors:
        result["authenticated_principal"] = None
    if "authorization" in factors:
        p["agent"] = {"agent_id": "agent-observer-01", "role": "observer"}
        result["authenticated_principal"] = "agent-observer-01" if "identity" not in factors else None
    if "interface" in factors:
        p["interface"] = "A1" if p["interface"] != "A1" else "E2"
    if "target" in factors:
        p["target"]["target_type"] = "cell"
    if "freshness" in factors:
        p["requested_at"], p["ttl_seconds"] = stamp(601), 900
    if "protected" in factors:
        p["target"]["slice_id"] = "slice-emergency"
    if "parameter" in factors:
        # One semantic-rule fault, without malformed structure or risk coupling.
        p["parameters"]["control_parameter"] = "unapproved_control_alias"
    if "risk" in factors:
        p["risk_level"] = "low"
    if "ttl" in factors:
        p["ttl_seconds"] = 901
    if "rollback" in factors:
        p["rollback"]["available"] = False
    result = seal_case(result)
    p = result["proposal"]
    if "approval" in factors:
        # Risk-low + missing approval is not an independent approval fault for
        # low-minimum actions; this combination is constrained out by callers.
        p["approval"] = None
    if "conflict" in factors:
        active = deepcopy(p)
        active["action_id"] += "-active"
        result["active_actions"] = [active]
    result["fault_factors"] = list(factors)
    result["category"] = "compliant" if not factors else "single_rule_violation" if len(factors) == 1 else "two_or_three_rule_violation"
    return result


def feasible(action: str, factors: Iterable[str]) -> bool:
    factors = set(factors)
    # Understated risk removes approval applicability for rate-limit/quarantine.
    return not ({"risk", "approval"} <= factors and action in ("rate_limit_ue", "quarantine_ue"))


def _named(case: dict, suffix: str) -> dict:
    result = deepcopy(case)
    result["case_id"] += "-" + suffix
    result["proposal"]["action_id"] = result["case_id"]
    return seal_case(result)


def iter_stage1_cases() -> Iterable[dict]:
    ref = ReferencePolicy()
    for action in ACTION_SPECS:
        base = make_case(action, "validity-" + action)
        factors = applicable_factors(action)
        # Exhaust all supported one/two fault assignments; all other factors
        # stay false. An independent checker verifies every feasible binary pair.
        for size in (0, 1, 2):
            for selected in combinations(factors, size):
                if feasible(action, selected):
                    case = apply_faults(_named(base, "pair-" + ("-".join(selected) or "none")), selected)
                    case["suite_group"] = "pairwise"
                    yield attach_expectation(case, ref)
        triples = [("authorization", "protected", "approval"), ("freshness", "ttl", "approval"),
                   ("conflict", "parameter", "approval")]
        for triplet in triples:
            if not set(triplet) <= set(factors):
                continue
            for bits in product((0, 1), repeat=3):
                selected = tuple(f for f, bit in zip(triplet, bits) if bit)
                case = apply_faults(_named(base, "triple-" + "-".join(triplet) + "-" + "".join(map(str, bits))), selected)
                if triplet == ("freshness", "ttl", "approval") and "approval" in selected:
                    # This targeted interaction is expiry, not merely missing
                    # approval: trusted binding is intact but expires exactly now.
                    case = seal_case(case)
                    case["proposal"]["approval"]["expires_at"] = EVALUATION_TIME
                    case = seal_case(case)
                    case["triple_approval_mode"] = "expired_at_evaluation"
                case["suite_group"], case["targeted_triple"] = "targeted_three_way", list(triplet)
                yield attach_expectation(case, ref)
        action_spec = ref.spec["actions"][action]
        for field, (lower, upper) in action_spec["numeric_bounds"].items():
            # Integer neighbours plus adjacent binary64 numbers detect equality.
            for boundary in sorted(set((lower, upper))):
                neighbours = [math.nextafter(float(boundary), -math.inf), boundary,
                              math.nextafter(float(boundary), math.inf), boundary - 1, boundary + 1]
                for index, value in enumerate(neighbours):
                    case = _named(base, f"numeric-{field}-{boundary}-{index}")
                    case["proposal"]["parameters"][field] = value
                    case = seal_case(case)
                    case["suite_group"], case["boundary"] = "boundary", {"field": field, "value": value, "boundary": boundary}
                    yield attach_expectation(case, ref)
        for kind, values in (("age", (-30.000001, -30, -29.999999, 599.999999, 600, 600.000001)),
                             ("ttl", (0, 1, 2, 899, 900, 901, 86399, 86400, 86401)),
                             ("expiry", (-0.000001, 0, 0.000001)),
                             ("elapsed_ttl", (299.999999, 300, 300.000001))):
            for index, value in enumerate(values):
                case = _named(base, f"time-{kind}-{index}")
                p = case["proposal"]
                if kind == "age":
                    p["requested_at"], p["ttl_seconds"] = stamp(value), 900
                elif kind == "ttl":
                    p["requested_at"], p["ttl_seconds"] = stamp(0), value
                elif kind == "elapsed_ttl":
                    p["requested_at"], p["ttl_seconds"] = stamp(value), 300
                else:
                    p["risk_level"] = "high"
                    p["approval"] = {"approval_id": "expiry-" + case["case_id"], "approved_by_role": "human_operator", "expires_at": stamp(-value)}
                case = seal_case(case)
                case["suite_group"], case["boundary"] = "boundary", {"field": kind, "value": value}
                yield attach_expectation(case, ref)
        for mode in ("missing_field", "extra_field", "whitespace_id", "float_ttl", "bool_numeric", "bad_evidence",
                     "malformed_active", "tampered_approval", "revoked_approval", "same_id_active", "expired_active",
                     "protected_rollback", "optional_expired_approval", "null_untyped_parameter", "key_order"):
            case = _named(base, mode)
            p = case["proposal"]
            if mode == "missing_field":
                p.pop("evidence_refs")
            elif mode == "extra_field":
                p["unknown"] = 1
            elif mode == "whitespace_id":
                p["incident_id"] = "   "
            elif mode == "float_ttl":
                p["ttl_seconds"] = 300.0
            elif mode == "bool_numeric":
                if not action_spec["numeric_bounds"]:
                    continue
                p["parameters"][next(iter(action_spec["numeric_bounds"]))] = True
            elif mode == "bad_evidence":
                p["evidence_refs"] = []
            elif mode == "malformed_active":
                case["active_actions"] = [{"malformed": True}]
            elif mode in ("tampered_approval", "revoked_approval"):
                p["risk_level"] = "high"
                case = seal_case(case)
                record = next(iter(case["approval_registry"].values()))
                if mode == "tampered_approval":
                    record["proposal_sha256"] = "0" * 64
                else:
                    record["status"] = "revoked"
            elif mode in ("same_id_active", "expired_active"):
                active = deepcopy(p)
                if mode == "same_id_active":
                    field = ACTION_SPECS[action][4]
                    original = active["parameters"][field]
                    active["parameters"][field] = original + 1 if isinstance(original, (int, float)) else original + "-changed"
                else:
                    active["action_id"] += "-expired"
                    active["requested_at"] = stamp(86400)
                case["active_actions"] = [active]
            elif mode == "protected_rollback":
                if action != "rollback_policy":
                    continue
                p["target"]["slice_id"] = "slice-emergency"
                p["rollback"] = {"available": False, "procedure": ""}
                case = seal_case(case)
            elif mode == "optional_expired_approval":
                if action_spec["action_requires_approval"]:
                    continue
                p["approval"] = {"approval_id": "optional", "approved_by_role": "human_operator", "expires_at": stamp(100)}
            elif mode == "null_untyped_parameter":
                if action not in ("rollback_policy", "notify_operator"):
                    continue
                p["parameters"]["snapshot_id" if action == "rollback_policy" else "message"] = None
                case = seal_case(case)
            elif mode == "key_order":
                case["proposal"] = dict(reversed(list(p.items())))
            # Legitimate changes normally need resealing, while approval faults
            # and structurally malformed probes intentionally keep their bytes.
            if mode == "bool_numeric":
                case = seal_case(case)
            case["suite_group"] = "legacy_limitation" if mode in ("same_id_active", "expired_active", "protected_rollback", "optional_expired_approval", "null_untyped_parameter") else "adversarial"
            case["probe"] = mode
            yield attach_expectation(case, ref)


def coverage_report(cases: Iterable[dict]) -> dict:
    cases = list(cases)
    missing, covered, excluded = [], 0, []
    for action in ACTION_SPECS:
        rows = [{factor for factor, rule in RULES.items() if rule in c["expected_reference"]["violated_rules"]}
                for c in cases if c["proposal"].get("action") == action and c.get("suite_group") == "pairwise"]
        for pair in combinations(applicable_factors(action), 2):
            for bits in product((0, 1), repeat=2):
                selected = {f for f, bit in zip(pair, bits) if bit}
                key = [action, list(pair), list(bits)]
                # Independently stated applicability constraint: low risk on a
                # non-approval-required action removes the approval predicate.
                if action in ("rate_limit_ue", "quarantine_ue") and {"risk", "approval"} <= selected:
                    excluded.append(key)
                elif any(tuple(int(f in row) for f in pair) == bits for row in rows):
                    covered += 1
                else:
                    missing.append(key)
    triples = {}
    for case in cases:
        if "targeted_triple" in case:
            key = case["proposal"]["action"] + ":" + ",".join(case["targeted_triple"])
            actual_rules = case["expected_reference"]["violated_rules"]
            triples.setdefault(key, set()).add(tuple(int(RULES[f] in actual_rules) for f in case["targeted_triple"]))
    return {"pairwise_covered": covered, "pairwise_missing": missing, "pairwise_constraints_excluded": excluded,
            "targeted_three_way": {key: {"covered": len(value), "required": 8} for key, value in sorted(triples.items())},
            "coverage_scope": "declared binary factor partitions, not exhaustive engine input space"}


def iter_netslab_cases(seeds: Iterable[int] = range(1000, 1020)) -> Iterable[dict]:
    ref = ReferencePolicy()
    labels = ("DDoS_ACK", "DDoS_ICMP", "DDoS_SYN", "DDoS_UDP", "Probe_PortScan")
    bases = [(action, "dataset_label_context", {"label": label, "source_ref": "NetsLab-5GORAN-IDD"})
             for label in labels for action in ("rate_limit_ue", "quarantine_ue")]
    xapp_names = ("xapp_vulnerability_exploitation", "xapp_misconfiguration", "direct_xapp_conflict",
                  "malicious_xapp_control", "unauthorized_xapp_access")
    a1_names = ("false_a1_policy", "malicious_a1_policy", "unauthorized_a1_policy_update",
               "a1_policy_scope_violation", "conflicting_a1_policy")
    bases += [("isolate_xapp", "standards_context", {"source_ref": f"ETSI-TR-104106:T-xApp-{'02' if i == 2 else '01'}",
              "local_scenario_id": f"xapp-{i}", "local_scenario_name": name}) for i, name in enumerate(xapp_names)]
    bases += [("modify_a1_policy", "standards_context", {"source_ref": "ETSI-TR-104106:T-xApp-04",
              "local_scenario_id": f"a1-{i}", "local_scenario_name": name}) for i, name in enumerate(a1_names)]
    for seed in seeds:
        rng = random.Random(seed)
        for base_index, (action, kind, context) in enumerate(bases):
            factors = applicable_factors(action)
            for variant in range(50):
                case = make_case(action, f"netslab-s{seed}-b{base_index:02d}-v{variant:02d}")
                p = case["proposal"]
                age = rng.randint(0, 200)
                p["requested_at"], p["ttl_seconds"] = stamp(age), rng.randint(max(age, 1), 900)
                p["target"]["slice_id"] = rng.choice(("slice-best-effort", "slice-test", None))
                principal = rng.choice(("agent-orchestrator-01", "operator-test-01"))
                p["agent"] = {"agent_id": principal, "role": ref.principals[principal]}
                case["authenticated_principal"] = principal
                for field, (lower, upper) in ref.spec["actions"][action]["numeric_bounds"].items():
                    p["parameters"][field] = round(rng.uniform(lower, upper), 6) if field == "policy_weight" else rng.randint(int(lower), int(upper))
                selected = [] if variant < 10 else [rng.choice(factors)] if variant < 30 else rng.sample(factors, 2 + variant % 2)
                while not feasible(action, selected):
                    selected = rng.sample(factors, len(selected))
                case = apply_faults(case, selected)
                case["seed"], case["base_index"] = seed, base_index
                case["source_context"] = {"kind": kind, **context, "not_independent_incident": True}
                case["suite_group"] = "netslab_control_robustness"
                yield attach_expectation(case, ref)
