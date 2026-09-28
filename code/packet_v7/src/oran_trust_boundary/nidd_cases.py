"""Record-conditioned 5G-NIDD cases for the unchanged, offline policy engine.

Dataset records contain no authenticated UE-to-control-plane mapping. Every
control target, principal, slice, clock, and authority condition below is an
explicit simulated fixture. The packet budget is an illustrative proposal
generator, not a standard, learned detector, or validated mitigation policy.
"""

from __future__ import annotations

import hashlib
import math
import re
from copy import deepcopy
from typing import Any, Iterable


SUITE_VERSION = "5gnidd-0.1.0"
REQUEST_TIME = "2026-01-15T12:00:00Z"
EVALUATION_TIME = "2026-01-15T12:05:00Z"
ILLUSTRATIVE_PACKET_BUDGET = 1000.0
CONFORMANCE_REDUCTION_CEILING = 80
SUPPORTED_ATTACK_TYPES = frozenset({"Benign", "ICMPFlood", "SYNFlood", "UDPFlood"})
CONTEXT_FIELDS = frozenset(
    {
        "record_id", "source_row_number", "attack_type", "duration_seconds",
        "total_packets", "packets_per_second",
    }
)


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number, not a boolean or string")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be finite") from exc
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


def _validate_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CONTEXT_FIELDS:
        raise ValueError("context must contain exactly the six documented fields")
    record_id = value["record_id"]
    if not isinstance(record_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", record_id):
        raise ValueError("record_id must be an opaque 1-128 character token")
    row = value["source_row_number"]
    if isinstance(row, bool) or not isinstance(row, int) or row < 1:
        raise ValueError("source_row_number must be a positive integer")
    attack_type = value["attack_type"]
    if not isinstance(attack_type, str) or attack_type not in SUPPORTED_ATTACK_TYPES:
        raise ValueError("unsupported attack_type; proxy labels are not permitted")
    duration = _finite_number(value["duration_seconds"], "duration_seconds")
    if duration < 0:
        raise ValueError("duration_seconds must be nonnegative")
    packets = value["total_packets"]
    if isinstance(packets, bool) or not isinstance(packets, int) or packets < 0:
        raise ValueError("total_packets must be a nonnegative integer")
    pps_value = value["packets_per_second"]
    if duration == 0:
        if pps_value is not None:
            raise ValueError("zero-duration records must have packets_per_second=None")
        pps = None
    else:
        pps = _finite_number(pps_value, "packets_per_second")
        if pps < 0:
            raise ValueError("packets_per_second must be nonnegative")
        try:
            calculated_pps = packets / duration
        except OverflowError as exc:
            raise ValueError("calculated packet rate must be finite") from exc
        if not math.isfinite(calculated_pps) or not math.isclose(
            pps, calculated_pps, rel_tol=1e-9, abs_tol=1e-12
        ):
            raise ValueError("packets_per_second is inconsistent with packets/duration")
    if attack_type != "Benign" and (pps is None or pps <= 0):
        raise ValueError("attack contexts require a positive, finite packet rate")
    return deepcopy(value)


def _raw_reduction(pps: float) -> int:
    # This branch is algebraically equivalent to the documented max/ceil rule
    # and avoids overflow when a positive packet rate is extremely small.
    if pps <= ILLUSTRATIVE_PACKET_BUDGET:
        return 1
    return max(1, math.ceil(100 * (1 - ILLUSTRATIVE_PACKET_BUDGET / pps)))


def _proposal(context: dict[str, Any], *, reduction: int | None) -> dict[str, Any]:
    token = hashlib.sha256(context["record_id"].encode("utf-8")).hexdigest()
    notification = reduction is None
    return {
        "action_id": f"nidd-{token}",
        "incident_id": f"nidd-record-{token}",
        "requested_at": REQUEST_TIME,
        "agent": {"agent_id": "agent-responder-01", "role": "security_responder"},
        "action": "notify_operator" if notification else "rate_limit_ue",
        "interface": "SMO" if notification else "E2",
        "target": {
            "target_type": "operator" if notification else "ue",
            "target_id": "simulated-operator-01" if notification else "simulated-ue-01",
            "cell_id": None if notification else "simulated-cell-01",
            "slice_id": None if notification else "slice-best-effort",
        },
        "parameters": (
            {
                "control_parameter": "operator_notification",
                "message": "Benign-labelled record: dry-run observation only; no mitigation requested.",
            }
            if notification
            else {"control_parameter": "traffic_rate_limit", "reduction_percent": reduction}
        ),
        "risk_level": "low" if notification else "medium",
        "ttl_seconds": 300,
        "expected_kpi": "observation_recorded" if notification else "attack_traffic_rate",
        "rollback": {
            "available": True,
            "procedure": "Dry-run fixture only; remove the simulated enforcement entry.",
        },
        "evidence_refs": [f"5g-nidd:record:{context['record_id']}"],
        "approval": None,
    }


def _case(
    context: dict[str, Any],
    proposal: dict[str, Any],
    *,
    group: str,
    category: str,
    decision: str = "ALLOW",
    reason: str = "POLICY_CHECKS_PASSED",
    policy: str = "TB-ALLOW-001",
    raw_reduction: int | None = None,
    active_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    proposal = deepcopy(proposal)
    suffix = f"-{group}-{category}"
    proposal["action_id"] += suffix
    source_context = {
        "kind": "record_conditioned_policy_conformance",
        "dataset": "5G-NIDD",
        "observed": deepcopy(context),
        "simulated_control_fixture": {
            "name": "offline-5gnidd-control-fixture-v0.1",
            "target": deepcopy(proposal["target"]),
            "agent": deepcopy(proposal["agent"]),
            "requested_at": REQUEST_TIME,
            "evaluation_time": EVALUATION_TIME,
            "risk_level": proposal["risk_level"],
            "controlled_variant": category,
            "source_to_ue_identity_mapping": "not_available_simulated_target_only",
            "authority_and_active_state": "synthetic_benchmark_conditions",
        },
        "proposal_generation": {
            "kind": "illustrative_fixed_packet_budget_not_standardized_or_validated",
            "packet_budget_per_second": ILLUSTRATIVE_PACKET_BUDGET,
            "formula": "max(1, ceil(100 * (1 - 1000 / packets_per_second)))",
            "record_derived_reduction_percent": raw_reduction,
            "proposed_reduction_percent": proposal["parameters"].get("reduction_percent"),
            "conformance_base_ceiling_percent": CONFORMANCE_REDUCTION_CEILING,
            "attack_labels_usage": "oracle_context_not_detector_predictions",
        },
        "interpretation_limit": (
            "Expected decisions are policy-conformance expectations, not physical-safety "
            "or mitigation-effectiveness labels. Evidence truth is not checked by this gate."
        ),
    }
    if group == "false_alarm_probes":
        source_context["negative_control"] = (
            "A compliant disruptive proposal on a benign-labelled record is expected to "
            "pass this policy. Report benign-mitigation admission separately; do not count "
            "it as safe-action acceptance or false-alarm suppression."
        )
    return {
        "suite_version": SUITE_VERSION,
        "case_id": proposal["action_id"],
        "experiment_group": group,
        "base_record_id": context["record_id"],
        "category": category,
        "evaluation_time": EVALUATION_TIME,
        "expected_decision": decision,
        "expected_reason": reason,
        "policy_under_test": policy,
        "source_context": source_context,
        "proposal": proposal,
        "authenticated_principal": proposal["agent"]["agent_id"],
        "active_actions": deepcopy(active_actions or []),
    }


def build_cases(contexts: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Build three separately reported groups without changing policy or inputs.

Attack records generate six conformance cases and one unclipped record proposal.
Benign records generate one notification in each of those two groups and one
forced-false-alarm probe. Groups are paired observations, not independent trials.
"""
    validated = [_validate_context(context) for context in contexts]
    if not validated:
        raise ValueError("at least one context is required")
    record_ids = [context["record_id"] for context in validated]
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("record_id values must be unique")
    groups: dict[str, list[dict[str, Any]]] = {
        "conformance": [], "record_proposals": [], "false_alarm_probes": [],
    }
    for context in validated:
        if context["attack_type"] == "Benign":
            for group in ("conformance", "record_proposals"):
                groups[group].append(_case(
                    context, _proposal(context, reduction=None),
                    group=group, category="benign_notification",
                ))
            groups["false_alarm_probes"].append(_case(
                context, _proposal(context, reduction=30),
                group="false_alarm_probes", category="benign_forced_mitigation",
            ))
            continue

        raw_reduction = _raw_reduction(float(context["packets_per_second"]))
        exceeds_policy = raw_reduction > CONFORMANCE_REDUCTION_CEILING
        groups["record_proposals"].append(_case(
            context, _proposal(context, reduction=raw_reduction),
            group="record_proposals", category="record_derived_mitigation",
            decision="DENY" if exceeds_policy else "ALLOW",
            reason="PARAMETER_OUT_OF_RANGE" if exceeds_policy else "POLICY_CHECKS_PASSED",
            policy="TB-RANGE-001" if exceeds_policy else "TB-ALLOW-001",
            raw_reduction=raw_reduction,
        ))
        base = _proposal(context, reduction=min(CONFORMANCE_REDUCTION_CEILING, raw_reduction))

        def append_variant(
            category: str, proposal: dict[str, Any], decision: str = "ALLOW",
            reason: str = "POLICY_CHECKS_PASSED", policy: str = "TB-ALLOW-001",
            active_actions: list[dict[str, Any]] | None = None,
        ) -> None:
            groups["conformance"].append(_case(
                context, proposal, group="conformance", category=category,
                decision=decision, reason=reason, policy=policy,
                raw_reduction=raw_reduction, active_actions=active_actions,
            ))

        append_variant("compliant", base)
        unauthorized = deepcopy(base)
        unauthorized["agent"] = {"agent_id": "agent-observer-01", "role": "observer"}
        append_variant("unauthorized", unauthorized, "DENY", "UNAUTHORIZED_AGENT", "TB-AUTH-001")
        protected = deepcopy(base)
        protected["target"]["slice_id"] = "slice-emergency"
        append_variant("protected_service", protected, "DENY", "PROTECTED_SLICE_VIOLATION", "TB-PROTECTED-001")
        out_of_range = deepcopy(base)
        out_of_range["parameters"]["reduction_percent"] = 95
        append_variant("parameter_range", out_of_range, "DENY", "PARAMETER_OUT_OF_RANGE", "TB-RANGE-001")
        active = deepcopy(base)
        active["action_id"] += "-already-active"
        active["parameters"]["reduction_percent"] = 60 if base["parameters"]["reduction_percent"] != 60 else 30
        append_variant("direct_conflict", base, "ESCALATE", "ACTION_CONFLICT", "TB-CONFLICT-001", [active])
        high_risk = deepcopy(base)
        high_risk["risk_level"] = "high"
        append_variant("missing_approval", high_risk, "ESCALATE", "HUMAN_APPROVAL_REQUIRED", "TB-APPROVAL-001")
    return groups
