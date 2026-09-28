"""Fail-closed parser for the published action contract.

The implementation uses only the Python standard library so that the core
experiment does not depend on a package registry. The accompanying JSON Schema
is the language-neutral contract for external integrations.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Any

from .models import (
    ActionProposal,
    Agent,
    Approval,
    ContractIssue,
    Rollback,
    Target,
)


ALLOWED_ACTIONS = frozenset(
    {
        "rate_limit_ue",
        "quarantine_ue",
        "isolate_xapp",
        "modify_a1_policy",
        "rollback_policy",
        "notify_operator",
    }
)
ALLOWED_INTERFACES = frozenset({"E2", "A1", "SMO"})
ALLOWED_TARGET_TYPES = frozenset({"ue", "xapp", "policy", "cell", "operator"})
ALLOWED_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})

TOP_LEVEL_FIELDS = frozenset(
    {
        "action_id",
        "incident_id",
        "requested_at",
        "agent",
        "action",
        "interface",
        "target",
        "parameters",
        "risk_level",
        "ttl_seconds",
        "expected_kpi",
        "rollback",
        "evidence_refs",
        "approval",
    }
)


def _is_nonempty_string(value: Any, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= maximum
    )


def _is_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _object_shape(
    value: Any,
    field: str,
    required: frozenset[str],
    issues: list[ContractIssue],
) -> bool:
    if not isinstance(value, dict):
        issues.append(ContractIssue("INVALID_TYPE", field, "must be an object"))
        return False
    if any(not isinstance(name, str) for name in value):
        issues.append(
            ContractIssue("INVALID_FIELD_NAME", field, "field names must be strings")
        )
        return False
    missing = required - set(value)
    unknown = set(value) - required
    for name in sorted(missing):
        issues.append(ContractIssue("MISSING_FIELD", f"{field}.{name}", "is required"))
    for name in sorted(unknown):
        issues.append(ContractIssue("UNKNOWN_FIELD", f"{field}.{name}", "is not permitted"))
    return not missing and not unknown


def _validate_json_value(
    value: Any,
    field: str,
    issues: list[ContractIssue],
    *,
    depth: int = 0,
    seen: set[int] | None = None,
) -> None:
    """Bound recursive parameter content and reject non-finite JSON values."""

    if depth > 6:
        issues.append(ContractIssue("PARAMETER_NESTING_TOO_DEEP", field, "exceeds six levels"))
        return
    if seen is None:
        seen = set()
    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in seen:
            issues.append(ContractIssue("CYCLIC_PARAMETER", field, "contains a cycle"))
            return
        seen.add(identity)
    if isinstance(value, dict):
        if len(value) > 64:
            issues.append(ContractIssue("PARAMETER_COLLECTION_TOO_LARGE", field, "has more than 64 entries"))
        for key, item in value.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 128:
                issues.append(ContractIssue("INVALID_PARAMETER_KEY", field, "keys must contain 1-128 characters"))
                continue
            _validate_json_value(item, f"{field}.{key}", issues, depth=depth + 1, seen=seen)
    elif isinstance(value, list):
        if len(value) > 64:
            issues.append(ContractIssue("PARAMETER_COLLECTION_TOO_LARGE", field, "has more than 64 entries"))
        for index, item in enumerate(value):
            _validate_json_value(item, f"{field}[{index}]", issues, depth=depth + 1, seen=seen)
    elif isinstance(value, float) and not math.isfinite(value):
        issues.append(ContractIssue("NON_FINITE_PARAMETER", field, "must be finite"))
    elif isinstance(value, str) and len(value) > 1024:
        issues.append(ContractIssue("PARAMETER_STRING_TOO_LONG", field, "exceeds 1024 characters"))
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        issues.append(ContractIssue("NON_JSON_PARAMETER", field, "has an unsupported type"))
    if isinstance(value, (dict, list)):
        seen.discard(id(value))


def parse_action(value: Any) -> tuple[ActionProposal | None, tuple[ContractIssue, ...]]:
    """Validate and parse one candidate action without coercing values."""

    issues: list[ContractIssue] = []
    if not isinstance(value, dict):
        return None, (ContractIssue("INVALID_TYPE", "$", "proposal must be an object"),)
    if any(not isinstance(name, str) for name in value):
        return None, (
            ContractIssue("INVALID_FIELD_NAME", "$", "field names must be strings"),
        )

    missing = TOP_LEVEL_FIELDS - set(value)
    unknown = set(value) - TOP_LEVEL_FIELDS
    for name in sorted(missing):
        issues.append(ContractIssue("MISSING_FIELD", name, "is required"))
    for name in sorted(unknown):
        issues.append(ContractIssue("UNKNOWN_FIELD", name, "is not permitted"))
    if missing or unknown:
        return None, tuple(issues)

    for field in ("action_id", "incident_id"):
        if not _is_nonempty_string(value[field], 128):
            issues.append(ContractIssue("INVALID_STRING", field, "must contain 1-128 characters"))
    if not _is_datetime(value["requested_at"]):
        issues.append(
            ContractIssue("INVALID_DATETIME", "requested_at", "must be a timezone-aware ISO-8601 value")
        )

    agent_ok = _object_shape(value["agent"], "agent", frozenset({"agent_id", "role"}), issues)
    if agent_ok:
        if not _is_nonempty_string(value["agent"]["agent_id"], 128):
            issues.append(ContractIssue("INVALID_STRING", "agent.agent_id", "must contain 1-128 characters"))
        if not _is_nonempty_string(value["agent"]["role"], 64):
            issues.append(ContractIssue("INVALID_STRING", "agent.role", "must contain 1-64 characters"))

    if not isinstance(value["action"], str) or value["action"] not in ALLOWED_ACTIONS:
        issues.append(ContractIssue("UNKNOWN_ACTION", "action", "is not in the action allowlist"))
    if not isinstance(value["interface"], str) or value["interface"] not in ALLOWED_INTERFACES:
        issues.append(ContractIssue("UNKNOWN_INTERFACE", "interface", "is not a supported interface"))

    target_fields = frozenset({"target_type", "target_id", "cell_id", "slice_id"})
    target_ok = _object_shape(value["target"], "target", target_fields, issues)
    if target_ok:
        target = value["target"]
        if (
            not isinstance(target["target_type"], str)
            or target["target_type"] not in ALLOWED_TARGET_TYPES
        ):
            issues.append(ContractIssue("UNKNOWN_TARGET_TYPE", "target.target_type", "is not supported"))
        if not _is_nonempty_string(target["target_id"], 128):
            issues.append(ContractIssue("INVALID_STRING", "target.target_id", "must contain 1-128 characters"))
        for field in ("cell_id", "slice_id"):
            if target[field] is not None and not _is_nonempty_string(target[field], 128):
                issues.append(ContractIssue("INVALID_STRING", f"target.{field}", "must be null or 1-128 characters"))

    parameters = value["parameters"]
    if not isinstance(parameters, dict) or not 1 <= len(parameters) <= 16:
        issues.append(ContractIssue("INVALID_PARAMETERS", "parameters", "must contain 1-16 entries"))
    else:
        _validate_json_value(parameters, "parameters", issues)
        try:
            encoded_parameters = json.dumps(
                parameters,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError):
            issues.append(ContractIssue("NON_JSON_PARAMETER", "parameters", "must be JSON serializable"))
        else:
            if len(encoded_parameters.encode("utf-8")) > 4096:
                issues.append(ContractIssue("PARAMETERS_TOO_LARGE", "parameters", "must not exceed 4096 bytes"))

    if (
        not isinstance(value["risk_level"], str)
        or value["risk_level"] not in ALLOWED_RISK_LEVELS
    ):
        issues.append(ContractIssue("UNKNOWN_RISK", "risk_level", "is not supported"))
    ttl = value["ttl_seconds"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 86400:
        issues.append(ContractIssue("INVALID_TTL", "ttl_seconds", "must be an integer from 1 to 86400"))
    if not _is_nonempty_string(value["expected_kpi"], 256):
        issues.append(ContractIssue("INVALID_STRING", "expected_kpi", "must contain 1-256 characters"))

    rollback_ok = _object_shape(
        value["rollback"], "rollback", frozenset({"available", "procedure"}), issues
    )
    if rollback_ok:
        if not isinstance(value["rollback"]["available"], bool):
            issues.append(ContractIssue("INVALID_TYPE", "rollback.available", "must be boolean"))
        if not isinstance(value["rollback"]["procedure"], str) or len(value["rollback"]["procedure"]) > 512:
            issues.append(ContractIssue("INVALID_STRING", "rollback.procedure", "must not exceed 512 characters"))

    evidence = value["evidence_refs"]
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 32:
        issues.append(ContractIssue("INVALID_EVIDENCE", "evidence_refs", "must contain 1-32 references"))
    elif any(not _is_nonempty_string(item, 256) for item in evidence):
        issues.append(ContractIssue("INVALID_EVIDENCE", "evidence_refs", "contains an invalid reference"))
    elif len(evidence) != len(set(evidence)):
        issues.append(ContractIssue("DUPLICATE_EVIDENCE", "evidence_refs", "contains duplicate references"))

    approval = value["approval"]
    approval_ok = approval is None
    if approval is not None:
        approval_ok = _object_shape(
            approval,
            "approval",
            frozenset({"approval_id", "approved_by_role", "expires_at"}),
            issues,
        )
        if approval_ok:
            if not _is_nonempty_string(approval["approval_id"], 128):
                issues.append(ContractIssue("INVALID_STRING", "approval.approval_id", "must contain 1-128 characters"))
            if approval["approved_by_role"] != "human_operator":
                issues.append(ContractIssue("INVALID_APPROVER", "approval.approved_by_role", "must be human_operator"))
            if not _is_datetime(approval["expires_at"]):
                issues.append(ContractIssue("INVALID_DATETIME", "approval.expires_at", "must be timezone-aware ISO-8601"))

    if issues:
        return None, tuple(issues)

    parsed_approval = None
    if approval is not None:
        parsed_approval = Approval(
            approval_id=approval["approval_id"],
            approved_by_role=approval["approved_by_role"],
            expires_at=approval["expires_at"],
        )

    proposal = ActionProposal(
        action_id=value["action_id"],
        incident_id=value["incident_id"],
        requested_at=value["requested_at"],
        agent=Agent(agent_id=value["agent"]["agent_id"], role=value["agent"]["role"]),
        action=value["action"],
        interface=value["interface"],
        target=Target(
            target_type=value["target"]["target_type"],
            target_id=value["target"]["target_id"],
            cell_id=value["target"]["cell_id"],
            slice_id=value["target"]["slice_id"],
        ),
        parameters=dict(parameters),
        risk_level=value["risk_level"],
        ttl_seconds=ttl,
        expected_kpi=value["expected_kpi"],
        rollback=Rollback(
            available=value["rollback"]["available"],
            procedure=value["rollback"]["procedure"],
        ),
        evidence_refs=tuple(evidence),
        approval=parsed_approval,
    )
    return proposal, ()
