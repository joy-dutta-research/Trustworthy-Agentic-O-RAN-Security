"""Comparison systems used in the paper experiment."""

from __future__ import annotations

from typing import Any, Mapping

from .contract import parse_action
from .models import Decision, EvaluationResult


def direct_execution(_: Any, **__: Any) -> EvaluationResult:
    """Model an unsafe pipeline that forwards every proposal."""

    return EvaluationResult(
        system="direct",
        decision=Decision.ALLOW,
        reason_codes=("NO_PRE_ACTION_CHECK",),
        policy_ids=(),
        audit_record=None,
    )


def contract_only(proposal_value: Any, **__: Any) -> EvaluationResult:
    """Validate only the structure and action allowlist."""

    proposal, issues = parse_action(proposal_value)
    if proposal is None:
        return EvaluationResult(
            system="contract",
            decision=Decision.DENY,
            reason_codes=tuple(dict.fromkeys(issue.code for issue in issues)),
            policy_ids=("TB-CONTRACT-001",),
            audit_record=None,
        )
    return EvaluationResult(
        system="contract",
        decision=Decision.ALLOW,
        reason_codes=("CONTRACT_VALID",),
        policy_ids=("TB-CONTRACT-001",),
        audit_record=None,
    )


def contract_rbac(
    proposal_value: Any,
    *,
    policy: Mapping[str, Any],
    authenticated_principal: str | None = None,
    **__: Any,
) -> EvaluationResult:
    """Apply contract, registered-role, action, and interface allowlists only."""

    proposal, issues = parse_action(proposal_value)
    if proposal is None:
        return EvaluationResult(
            system="contract_rbac",
            decision=Decision.DENY,
            reason_codes=tuple(dict.fromkeys(issue.code for issue in issues)),
            policy_ids=("TB-CONTRACT-001",),
            audit_record=None,
        )
    reasons: list[str] = []
    policy_ids: list[str] = []
    registered_role = None
    if authenticated_principal is None:
        reasons.append("AUTHENTICATED_PRINCIPAL_REQUIRED")
        policy_ids.append("TB-IDENTITY-001")
    elif authenticated_principal != proposal.agent.agent_id:
        reasons.append("AGENT_IDENTITY_MISMATCH")
        policy_ids.append("TB-IDENTITY-001")
    else:
        registered_role = policy["principals"].get(authenticated_principal)
    if authenticated_principal is not None and registered_role is None:
        reasons.append("UNKNOWN_PRINCIPAL")
        policy_ids.append("TB-IDENTITY-001")
    elif registered_role is not None and registered_role != proposal.agent.role:
        reasons.append("AGENT_ROLE_MISMATCH")
        policy_ids.append("TB-IDENTITY-001")
    if proposal.action not in policy["roles"].get(proposal.agent.role, []):
        reasons.append("UNAUTHORIZED_AGENT")
        policy_ids.append("TB-AUTH-001")
    if proposal.action not in policy["interface_actions"].get(proposal.interface, []):
        reasons.append("ACTION_INTERFACE_MISMATCH")
        policy_ids.append("TB-INTERFACE-001")
    if reasons:
        return EvaluationResult(
            system="contract_rbac",
            decision=Decision.DENY,
            reason_codes=tuple(dict.fromkeys(reasons)),
            policy_ids=tuple(dict.fromkeys(policy_ids)),
            audit_record=None,
        )
    return EvaluationResult(
        system="contract_rbac",
        decision=Decision.ALLOW,
        reason_codes=("CONTRACT_AND_RBAC_VALID",),
        policy_ids=("TB-CONTRACT-001", "TB-IDENTITY-001", "TB-AUTH-001", "TB-INTERFACE-001"),
        audit_record=None,
    )
