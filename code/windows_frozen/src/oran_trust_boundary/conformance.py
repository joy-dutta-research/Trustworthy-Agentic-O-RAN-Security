"""Deterministic generation of the policy-conformance test suite."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterator

from .audit import canonical_sha256


SUITE_VERSION = "0.1.0"
EVALUATION_TIME = "2026-01-15T12:05:00Z"

NETSLAB_LOWER_LAYER_SHA256 = (
    "d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64"
)
ATTACK_CONTEXTS = {
    "icmp_flood": "DDoS_ICMP",
    "syn_flood": "DDoS_SYN",
    "ack_flood": "DDoS_ACK",
    "udp_flood": "DDoS_UDP",
    "port_scan": "Probe_PortScan",
}

ACTION_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "action": "rate_limit_ue",
        "interface": "E2",
        "role": "security_responder",
        "target_type": "ue",
        "parameters": {
            "control_parameter": "traffic_rate_limit",
            "reduction_percent": 30,
        },
        "out_of_range": ("reduction_percent", 95),
        "conflicting_value": ("reduction_percent", 60),
        "expected_kpi": "attack_traffic_rate",
    },
    {
        "action": "quarantine_ue",
        "interface": "E2",
        "role": "security_responder",
        "target_type": "ue",
        "parameters": {
            "control_parameter": "ue_admission_state",
            "duration_seconds": 120,
        },
        "out_of_range": ("duration_seconds", 600),
        "conflicting_value": ("duration_seconds", 60),
        "expected_kpi": "malicious_ue_connectivity",
    },
    {
        "action": "isolate_xapp",
        "interface": "SMO",
        "role": "security_orchestrator",
        "risk_level": "high",
        "target_type": "xapp",
        "parameters": {
            "control_parameter": "xapp_execution_state",
            "duration_seconds": 300,
        },
        "out_of_range": ("duration_seconds", 1200),
        "conflicting_value": ("duration_seconds", 180),
        "expected_kpi": "untrusted_xapp_activity",
    },
    {
        "action": "modify_a1_policy",
        "interface": "A1",
        "role": "security_orchestrator",
        "risk_level": "high",
        "target_type": "policy",
        "parameters": {
            "control_parameter": "a1_policy_weight",
            "policy_weight": 0.5,
        },
        "out_of_range": ("policy_weight", 1.5),
        "conflicting_value": ("policy_weight", 0.75),
        "expected_kpi": "policy_compliance_rate",
    },
)


DATASET_SCENARIOS: tuple[dict[str, Any], ...] = tuple(
    {
        "incident_class": attack,
        "template_index": template_index,
        "evidence_ref": f"netslab-5goran-idd:attack_subcategory:{dataset_label}",
        "source_context": {
            "kind": "dataset_label_scenario",
            "incident_class": attack,
            "source_ref": "NetsLab-5GORAN-IDD",
            "dataset_binding": {
                "status": "exact_label",
                "attack_subcategory": dataset_label,
                "lower_layer_database_sha256": NETSLAB_LOWER_LAYER_SHA256,
            },
        },
    }
    for attack, dataset_label in ATTACK_CONTEXTS.items()
    for template_index in (0, 1)
)

GOVERNANCE_SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "incident_class": "xapp_vulnerability_exploitation",
        "template_index": 2,
        "source_ref": "ETSI-TR-104106:T-xApp-01",
    },
    {
        "incident_class": "xapp_misconfiguration",
        "template_index": 2,
        "source_ref": "ETSI-TR-104106:T-xApp-01",
    },
    {
        "incident_class": "direct_xapp_conflict",
        "template_index": 2,
        "source_ref": "ETSI-TR-104106:T-xApp-02",
    },
    {
        "incident_class": "malicious_xapp_control",
        "template_index": 2,
        "source_ref": "ETSI-TR-104106:T-xApp-01",
    },
    {
        "incident_class": "unauthorized_xapp_access",
        "template_index": 2,
        "source_ref": "ETSI-TR-104106:T-xApp-01",
    },
    {
        "incident_class": "false_a1_policy",
        "template_index": 3,
        "source_ref": "ETSI-TR-104106:T-xApp-04",
    },
    {
        "incident_class": "malicious_a1_policy",
        "template_index": 3,
        "source_ref": "ETSI-TR-104106:T-xApp-04",
    },
    {
        "incident_class": "unauthorized_a1_policy_update",
        "template_index": 3,
        "source_ref": "ETSI-TR-104106:T-xApp-04",
    },
    {
        "incident_class": "a1_policy_scope_violation",
        "template_index": 3,
        "source_ref": "ETSI-TR-104106:T-xApp-04",
    },
    {
        "incident_class": "conflicting_a1_policy",
        "template_index": 3,
        "source_ref": "ETSI-TR-104106:T-xApp-04",
    },
)

BASE_SCENARIOS: tuple[dict[str, Any], ...] = DATASET_SCENARIOS + tuple(
    {
        **scenario,
        "evidence_ref": scenario["source_ref"],
        "source_context": {
            "kind": "standards_threat_scenario",
            "incident_class": scenario["incident_class"],
            "source_ref": scenario["source_ref"],
            "dataset_binding": "not_applicable",
        },
    }
    for scenario in GOVERNANCE_SCENARIOS
)


def _base_proposal(
    index: int,
    scenario: dict[str, Any],
    template: dict[str, Any],
) -> dict[str, Any]:
    ordinal = f"{index:02d}"
    incident_class = scenario["incident_class"]
    risk_level = template.get("risk_level", "medium")
    approval = None
    if risk_level in {"high", "critical"}:
        approval = {
            "approval_id": f"approval-{ordinal}-allow",
            "approved_by_role": "human_operator",
            "expires_at": "2026-01-15T13:00:00Z",
        }
    agent_id = {
        "security_responder": "agent-responder-01",
        "security_orchestrator": "agent-orchestrator-01",
    }[template["role"]]
    return {
        "action_id": f"action-{ordinal}-safe",
        "incident_id": f"incident-{incident_class}-{ordinal}",
        "requested_at": "2026-01-15T12:00:00Z",
        "agent": {
            "agent_id": agent_id,
            "role": template["role"],
        },
        "action": template["action"],
        "interface": template["interface"],
        "target": {
            "target_type": template["target_type"],
            "target_id": f"{template['target_type']}-test-{ordinal}",
            "cell_id": f"cell-test-{(index % 4) + 1}",
            "slice_id": "slice-best-effort",
        },
        "parameters": deepcopy(template["parameters"]),
        "risk_level": risk_level,
        "ttl_seconds": 300,
        "expected_kpi": template["expected_kpi"],
        "rollback": {
            "available": True,
            "procedure": "Remove the dry-run enforcement entry and restore the previous policy snapshot.",
        },
        "evidence_refs": [scenario["evidence_ref"]],
        "approval": approval,
    }


def _set_variant_identity(proposal: dict[str, Any], index: int, suffix: str) -> None:
    proposal["action_id"] = f"action-{index:02d}-{suffix}"
    if proposal["approval"] is not None:
        proposal["approval"]["approval_id"] = f"approval-{index:02d}-{suffix}"


def _case(
    case_id: str,
    category: str,
    expected_decision: str,
    expected_reason: str,
    policy_under_test: str,
    source_context: dict[str, Any],
    proposal: dict[str, Any],
    active_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "suite_version": SUITE_VERSION,
        "case_id": case_id,
        "category": category,
        "evaluation_time": EVALUATION_TIME,
        "expected_decision": expected_decision,
        "expected_reason": expected_reason,
        "policy_under_test": policy_under_test,
        "source_context": deepcopy(source_context),
        "proposal": proposal,
        "authenticated_principal": proposal["agent"]["agent_id"],
        "active_actions": active_actions or [],
    }


def generate_cases() -> Iterator[dict[str, Any]]:
    """Yield 120 deterministic, well-formed conformance cases."""

    for index, scenario in enumerate(BASE_SCENARIOS, start=1):
        template = ACTION_TEMPLATES[scenario["template_index"]]
        source_context = scenario["source_context"]
        prefix = f"case-{index:02d}"
        base = _base_proposal(index, scenario, template)

        yield _case(
            f"{prefix}-allow",
            "compliant",
            "ALLOW",
            "POLICY_CHECKS_PASSED",
            "TB-ALLOW-001",
            source_context,
            deepcopy(base),
        )

        unauthorized = deepcopy(base)
        _set_variant_identity(unauthorized, index, "unauthorized")
        unauthorized["agent"] = {
            "agent_id": "agent-observer-01",
            "role": "observer",
        }
        yield _case(
            f"{prefix}-unauthorized",
            "unauthorized",
            "DENY",
            "UNAUTHORIZED_AGENT",
            "TB-AUTH-001",
            source_context,
            unauthorized,
        )

        protected = deepcopy(base)
        _set_variant_identity(protected, index, "protected")
        protected["target"]["slice_id"] = "slice-emergency"
        yield _case(
            f"{prefix}-protected",
            "protected_service",
            "DENY",
            "PROTECTED_SLICE_VIOLATION",
            "TB-PROTECTED-001",
            source_context,
            protected,
        )

        out_of_range = deepcopy(base)
        _set_variant_identity(out_of_range, index, "range")
        field, value = template["out_of_range"]
        out_of_range["parameters"][field] = value
        yield _case(
            f"{prefix}-range",
            "parameter_range",
            "DENY",
            "PARAMETER_OUT_OF_RANGE",
            "TB-RANGE-001",
            source_context,
            out_of_range,
        )

        conflict = deepcopy(base)
        _set_variant_identity(conflict, index, "conflict")
        active = deepcopy(base)
        active["action_id"] = f"action-{index:02d}-already-active"
        conflict_field, conflict_value = template["conflicting_value"]
        active["parameters"][conflict_field] = conflict_value
        yield _case(
            f"{prefix}-conflict",
            "direct_conflict",
            "ESCALATE",
            "ACTION_CONFLICT",
            "TB-CONFLICT-001",
            source_context,
            conflict,
            [active],
        )

        high_risk = deepcopy(base)
        _set_variant_identity(high_risk, index, "approval")
        high_risk["risk_level"] = "high"
        high_risk["approval"] = None
        yield _case(
            f"{prefix}-approval",
            "missing_approval",
            "ESCALATE",
            "HUMAN_APPROVAL_REQUIRED",
            "TB-APPROVAL-001",
            source_context,
            high_risk,
        )


def approval_registry(cases: Iterator[dict[str, Any]] | list[dict[str, Any]]) -> dict[str, Any]:
    """Build the offline approval-authority fixture for approved proposals."""

    records: dict[str, Any] = {}
    for case in cases:
        proposal = case["proposal"]
        approval = proposal["approval"]
        if approval is None:
            continue
        records[approval["approval_id"]] = {
            "status": "approved",
            "action_id": proposal["action_id"],
            "agent_id": proposal["agent"]["agent_id"],
            "approved_by_role": approval["approved_by_role"],
            "expires_at": approval["expires_at"],
            "proposal_sha256": canonical_sha256(proposal),
        }
    return {
        "registry_version": SUITE_VERSION,
        "description": "Offline benchmark fixture; not a production approval authority.",
        "approvals": dict(sorted(records.items())),
    }
