"""Strict validation and freezing of policy-as-code configuration."""

from __future__ import annotations

import json
import math
from typing import Any, Mapping

from .audit import canonical_sha256
from .contract import (
    ALLOWED_ACTIONS,
    ALLOWED_INTERFACES,
    ALLOWED_RISK_LEVELS,
    ALLOWED_TARGET_TYPES,
)


class PolicyConfigurationError(ValueError):
    """Raised when a policy cannot be evaluated safely."""


REQUIRED_FIELDS = frozenset(
    {
        "policy_version",
        "description",
        "principals",
        "roles",
        "interface_actions",
        "action_targets",
        "action_parameter_contracts",
        "protected_slices",
        "disruptive_actions",
        "max_ttl_seconds",
        "max_proposal_age_seconds",
        "max_clock_skew_seconds",
        "parameter_bounds",
        "minimum_risk_by_action",
        "approval_required_for_risk",
        "approval_required_actions",
        "audit_required_fields",
    }
)


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not _nonempty_string(item) for item in value):
        raise PolicyConfigurationError(f"{field} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise PolicyConfigurationError(f"{field} contains duplicates")
    return value


def validate_policy(value: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Return an isolated policy copy and its canonical digest."""

    if not isinstance(value, Mapping):
        raise PolicyConfigurationError("policy must be an object")
    if any(not isinstance(field, str) for field in value):
        raise PolicyConfigurationError("policy field names must be strings")
    missing = REQUIRED_FIELDS - set(value)
    unknown = set(value) - REQUIRED_FIELDS
    if missing:
        raise PolicyConfigurationError(f"policy is missing fields: {sorted(missing)}")
    if unknown:
        raise PolicyConfigurationError(f"policy has unknown fields: {sorted(unknown)}")
    try:
        policy = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise PolicyConfigurationError(f"policy must be finite JSON: {exc}") from exc

    if not _nonempty_string(policy["policy_version"]):
        raise PolicyConfigurationError("policy_version must be a non-empty string")
    if not _nonempty_string(policy["description"]):
        raise PolicyConfigurationError("description must be a non-empty string")

    roles = policy["roles"]
    if not isinstance(roles, dict) or not roles:
        raise PolicyConfigurationError("roles must be a non-empty object")
    for role, actions in roles.items():
        if not _nonempty_string(role):
            raise PolicyConfigurationError("role names must be non-empty strings")
        unknown_actions = set(_string_list(actions, f"roles.{role}")) - ALLOWED_ACTIONS
        if unknown_actions:
            raise PolicyConfigurationError(
                f"roles.{role} contains unknown actions: {sorted(unknown_actions)}"
            )

    principals = policy["principals"]
    if not isinstance(principals, dict) or not principals:
        raise PolicyConfigurationError("principals must be a non-empty object")
    for principal, role in principals.items():
        if not _nonempty_string(principal) or role not in roles:
            raise PolicyConfigurationError(
                f"principal {principal!r} must map to a configured role"
            )

    interface_actions = policy["interface_actions"]
    if not isinstance(interface_actions, dict) or set(interface_actions) != set(ALLOWED_INTERFACES):
        raise PolicyConfigurationError(
            f"interface_actions must define exactly {sorted(ALLOWED_INTERFACES)}"
        )
    assigned_actions: set[str] = set()
    for interface, actions in interface_actions.items():
        parsed_actions = set(_string_list(actions, f"interface_actions.{interface}"))
        unknown_actions = parsed_actions - ALLOWED_ACTIONS
        duplicate_assignment = assigned_actions & parsed_actions
        if unknown_actions or duplicate_assignment:
            raise PolicyConfigurationError(
                f"invalid interface action mapping for {interface}: "
                f"unknown={sorted(unknown_actions)}, duplicate={sorted(duplicate_assignment)}"
            )
        assigned_actions.update(parsed_actions)
    if assigned_actions != set(ALLOWED_ACTIONS):
        raise PolicyConfigurationError(
            f"interface mapping omits actions: {sorted(ALLOWED_ACTIONS - assigned_actions)}"
        )

    action_targets = policy["action_targets"]
    if not isinstance(action_targets, dict) or set(action_targets) != set(ALLOWED_ACTIONS):
        raise PolicyConfigurationError("action_targets must cover every action exactly")
    for action, target_types in action_targets.items():
        parsed_targets = set(_string_list(target_types, f"action_targets.{action}"))
        if not parsed_targets or parsed_targets - ALLOWED_TARGET_TYPES:
            raise PolicyConfigurationError(f"invalid target types for {action}")

    parameter_contracts = policy["action_parameter_contracts"]
    if (
        not isinstance(parameter_contracts, dict)
        or set(parameter_contracts) != set(ALLOWED_ACTIONS)
    ):
        raise PolicyConfigurationError(
            "action_parameter_contracts must cover every action exactly"
        )
    for action, contract in parameter_contracts.items():
        if not isinstance(contract, dict) or set(contract) != {
            "required_fields",
            "control_parameter",
        }:
            raise PolicyConfigurationError(f"invalid parameter contract for {action}")
        required = set(
            _string_list(contract["required_fields"], f"action_parameter_contracts.{action}.required_fields")
        )
        if "control_parameter" not in required:
            raise PolicyConfigurationError(
                f"parameter contract for {action} must require control_parameter"
            )
        if not _nonempty_string(contract["control_parameter"]):
            raise PolicyConfigurationError(
                f"control_parameter for {action} must be a non-empty string"
            )

    _string_list(policy["protected_slices"], "protected_slices")
    disruptive = set(_string_list(policy["disruptive_actions"], "disruptive_actions"))
    if disruptive - ALLOWED_ACTIONS:
        raise PolicyConfigurationError("disruptive_actions contains unknown actions")

    for field in (
        "max_ttl_seconds",
        "max_proposal_age_seconds",
        "max_clock_skew_seconds",
    ):
        number = policy[field]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise PolicyConfigurationError(f"{field} must be a non-negative integer")
    if policy["max_ttl_seconds"] < 1 or policy["max_proposal_age_seconds"] < 1:
        raise PolicyConfigurationError("TTL and proposal age limits must be positive")

    bounds = policy["parameter_bounds"]
    if not isinstance(bounds, dict):
        raise PolicyConfigurationError("parameter_bounds must be an object")
    for action, action_bounds in bounds.items():
        if action not in ALLOWED_ACTIONS or not isinstance(action_bounds, dict):
            raise PolicyConfigurationError(f"invalid parameter bounds for {action}")
        for parameter, limits in action_bounds.items():
            if (
                not _nonempty_string(parameter)
                or not isinstance(limits, dict)
                or set(limits) != {"minimum", "maximum"}
            ):
                raise PolicyConfigurationError(f"invalid bound shape for {action}.{parameter}")
            minimum, maximum = limits["minimum"], limits["maximum"]
            if any(
                isinstance(item, bool)
                or not isinstance(item, (int, float))
                or not math.isfinite(item)
                for item in (minimum, maximum)
            ):
                raise PolicyConfigurationError(f"bounds for {action}.{parameter} must be finite")
            if minimum > maximum:
                raise PolicyConfigurationError(f"minimum exceeds maximum for {action}.{parameter}")
        required = set(parameter_contracts[action]["required_fields"])
        unknown_bounded_parameters = set(action_bounds) - required
        if unknown_bounded_parameters:
            raise PolicyConfigurationError(
                f"bounds for {action} reference parameters outside its contract: "
                f"{sorted(unknown_bounded_parameters)}"
            )

    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    minimum_risk = policy["minimum_risk_by_action"]
    if not isinstance(minimum_risk, dict) or set(minimum_risk) != set(ALLOWED_ACTIONS):
        raise PolicyConfigurationError("minimum_risk_by_action must cover every action")
    if any(risk not in risk_order for risk in minimum_risk.values()):
        raise PolicyConfigurationError("minimum_risk_by_action contains an unknown risk")

    approval_risks = set(
        _string_list(policy["approval_required_for_risk"], "approval_required_for_risk")
    )
    if approval_risks - ALLOWED_RISK_LEVELS:
        raise PolicyConfigurationError("approval_required_for_risk contains an unknown risk")
    approval_actions = set(
        _string_list(policy["approval_required_actions"], "approval_required_actions")
    )
    if approval_actions - ALLOWED_ACTIONS:
        raise PolicyConfigurationError("approval_required_actions contains an unknown action")

    audit_fields = set(_string_list(policy["audit_required_fields"], "audit_required_fields"))
    required_audit_minimum = {
        "audit_id",
        "action_id",
        "decision",
        "reason_codes",
        "policy_ids",
        "policy_version",
        "policy_sha256",
        "proposal_sha256",
        "evaluated_at",
        "record_sha256",
        "authenticated_principal",
    }
    if not required_audit_minimum <= audit_fields:
        raise PolicyConfigurationError(
            f"audit_required_fields omits {sorted(required_audit_minimum - audit_fields)}"
        )

    return policy, canonical_sha256(policy)
