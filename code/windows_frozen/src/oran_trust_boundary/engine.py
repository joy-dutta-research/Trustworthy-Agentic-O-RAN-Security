"""Deterministic Trust-Boundary policy engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .approval import ApprovalVerifier, DenyAllApprovalVerifier, StaticApprovalRegistry
from .audit import create_audit_record, create_rejection_audit_record
from .contract import parse_action
from .models import ActionProposal, Decision, EvaluationResult
from .jsonio import strict_json_load
from .policy import validate_policy


class TrustBoundary:
    """Evaluate candidate actions using a frozen policy-as-code configuration."""

    def __init__(
        self,
        policy: Mapping[str, Any],
        approval_verifier: ApprovalVerifier | None = None,
    ):
        self.policy, self.policy_sha256 = validate_policy(policy)
        self.policy_version = str(self.policy["policy_version"])
        self.approval_verifier = approval_verifier or DenyAllApprovalVerifier()

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        approval_registry_path: str | Path | None = None,
    ) -> "TrustBoundary":
        policy = strict_json_load(path, maximum_bytes=1024 * 1024)
        verifier = None
        if approval_registry_path is not None:
            verifier = StaticApprovalRegistry.from_file(approval_registry_path)
        return cls(policy, approval_verifier=verifier)

    def evaluate(
        self,
        proposal_value: Any,
        active_actions: Iterable[Any] = (),
        *,
        authenticated_principal: str | None = None,
        as_of: datetime | None = None,
    ) -> EvaluationResult:
        evaluated_at = as_of or datetime.now(UTC)
        if evaluated_at.tzinfo is None:
            raise ValueError("as_of must be timezone aware")

        proposal, contract_issues = parse_action(proposal_value)
        if proposal is None:
            reason_codes = tuple(dict.fromkeys(issue.code for issue in contract_issues))
            audit_record = create_rejection_audit_record(
                proposal_value,
                Decision.DENY,
                reason_codes,
                ("TB-CONTRACT-001",),
                self.policy_version,
                self.policy_sha256,
                evaluated_at,
                authenticated_principal,
            )
            return EvaluationResult(
                system="trust_boundary",
                decision=Decision.DENY,
                reason_codes=reason_codes,
                policy_ids=("TB-CONTRACT-001",),
                audit_record=audit_record,
            )

        deny_reasons: list[str] = []
        deny_policies: list[str] = []
        escalate_reasons: list[str] = []
        escalate_policies: list[str] = []

        self._check_identity(
            proposal,
            authenticated_principal,
            deny_reasons,
            deny_policies,
        )
        self._check_authorization(proposal, deny_reasons, deny_policies)
        self._check_interface(proposal, deny_reasons, deny_policies)
        self._check_target_type(proposal, deny_reasons, deny_policies)
        self._check_freshness(proposal, evaluated_at, deny_reasons, deny_policies)
        self._check_protected_target(proposal, deny_reasons, deny_policies)
        self._check_parameters(proposal, deny_reasons, deny_policies)
        self._check_risk_floor(proposal, deny_reasons, deny_policies)
        self._check_ttl(proposal, evaluated_at, deny_reasons, deny_policies)
        self._check_rollback(proposal, deny_reasons, deny_policies)
        self._check_conflicts(proposal, active_actions, escalate_reasons, escalate_policies)
        self._check_approval(
            proposal,
            evaluated_at,
            escalate_reasons,
            escalate_policies,
        )

        if deny_reasons:
            decision = Decision.DENY
            reasons = tuple(dict.fromkeys(deny_reasons))
            policies = tuple(dict.fromkeys(deny_policies))
        elif escalate_reasons:
            decision = Decision.ESCALATE
            reasons = tuple(dict.fromkeys(escalate_reasons))
            policies = tuple(dict.fromkeys(escalate_policies))
        else:
            decision = Decision.ALLOW
            reasons = ("POLICY_CHECKS_PASSED",)
            policies = ("TB-ALLOW-001",)

        audit_record = create_audit_record(
            proposal,
            decision,
            reasons,
            policies,
            self.policy_version,
            self.policy_sha256,
            evaluated_at,
            authenticated_principal,
        )
        return EvaluationResult(
            system="trust_boundary",
            decision=decision,
            reason_codes=reasons,
            policy_ids=policies,
            audit_record=audit_record,
        )

    def _check_identity(
        self,
        proposal: ActionProposal,
        authenticated_principal: str | None,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        if authenticated_principal is None:
            reasons.append("AUTHENTICATED_PRINCIPAL_REQUIRED")
            policies.append("TB-IDENTITY-001")
            return
        if authenticated_principal != proposal.agent.agent_id:
            reasons.append("AGENT_IDENTITY_MISMATCH")
            policies.append("TB-IDENTITY-001")
            return
        registered_role = self.policy["principals"].get(authenticated_principal)
        if registered_role is None:
            reasons.append("UNKNOWN_PRINCIPAL")
            policies.append("TB-IDENTITY-001")
        elif registered_role != proposal.agent.role:
            reasons.append("AGENT_ROLE_MISMATCH")
            policies.append("TB-IDENTITY-001")

    def _check_authorization(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        allowed = self.policy.get("roles", {}).get(proposal.agent.role, [])
        if proposal.action not in allowed:
            reasons.append("UNAUTHORIZED_AGENT")
            policies.append("TB-AUTH-001")

    def _check_interface(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        allowed = self.policy.get("interface_actions", {}).get(proposal.interface, [])
        if proposal.action not in allowed:
            reasons.append("ACTION_INTERFACE_MISMATCH")
            policies.append("TB-INTERFACE-001")

    def _check_freshness(
        self,
        proposal: ActionProposal,
        as_of: datetime,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        requested_at = datetime.fromisoformat(proposal.requested_at.replace("Z", "+00:00"))
        age_seconds = (as_of - requested_at).total_seconds()
        if age_seconds < -int(self.policy["max_clock_skew_seconds"]):
            reasons.append("REQUEST_TIMESTAMP_IN_FUTURE")
            policies.append("TB-FRESHNESS-001")
        elif age_seconds > int(self.policy["max_proposal_age_seconds"]):
            reasons.append("STALE_ACTION_PROPOSAL")
            policies.append("TB-FRESHNESS-001")

    def _check_target_type(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        allowed = self.policy["action_targets"][proposal.action]
        if proposal.target.target_type not in allowed:
            reasons.append("ACTION_TARGET_MISMATCH")
            policies.append("TB-TARGET-001")

    def _check_protected_target(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        protected = set(self.policy.get("protected_slices", []))
        disruptive = set(self.policy.get("disruptive_actions", []))
        if proposal.target.slice_id in protected and proposal.action in disruptive:
            reasons.append("PROTECTED_SLICE_VIOLATION")
            policies.append("TB-PROTECTED-001")

    def _check_parameters(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        contract = self.policy["action_parameter_contracts"][proposal.action]
        required_fields = set(contract["required_fields"])
        actual_fields = set(proposal.parameters)
        if actual_fields != required_fields:
            reasons.append("ACTION_PARAMETER_CONTRACT_MISMATCH")
            policies.append("TB-PARAMETER-001")
        if proposal.parameters.get("control_parameter") != contract["control_parameter"]:
            reasons.append("CONTROL_PARAMETER_MISMATCH")
            policies.append("TB-PARAMETER-001")
        bounds = self.policy.get("parameter_bounds", {}).get(proposal.action, {})
        for name, limits in bounds.items():
            value = proposal.parameters.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                reasons.append("REQUIRED_NUMERIC_PARAMETER_MISSING")
                policies.append("TB-RANGE-001")
                continue
            if value < limits["minimum"] or value > limits["maximum"]:
                reasons.append("PARAMETER_OUT_OF_RANGE")
                policies.append("TB-RANGE-001")

    def _check_risk_floor(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        minimum = self.policy["minimum_risk_by_action"][proposal.action]
        if risk_order[proposal.risk_level] < risk_order[minimum]:
            reasons.append("RISK_CLASSIFICATION_UNDERSTATED")
            policies.append("TB-RISK-001")

    def _check_ttl(
        self,
        proposal: ActionProposal,
        as_of: datetime,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        if proposal.ttl_seconds > int(self.policy["max_ttl_seconds"]):
            reasons.append("TTL_EXCEEDS_POLICY")
            policies.append("TB-EXPIRY-001")
        requested_at = datetime.fromisoformat(proposal.requested_at.replace("Z", "+00:00"))
        if (as_of - requested_at).total_seconds() > proposal.ttl_seconds:
            reasons.append("ACTION_TTL_EXPIRED")
            policies.append("TB-EXPIRY-001")

    def _check_rollback(
        self,
        proposal: ActionProposal,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        disruptive = set(self.policy.get("disruptive_actions", []))
        if proposal.action in disruptive:
            if not proposal.rollback.available or not proposal.rollback.procedure.strip():
                reasons.append("ROLLBACK_REQUIRED")
                policies.append("TB-ROLLBACK-001")

    def _check_conflicts(
        self,
        proposal: ActionProposal,
        active_actions: Iterable[Any],
        reasons: list[str],
        policies: list[str],
    ) -> None:
        for active_value in active_actions:
            active, issues = parse_action(active_value)
            if issues or active is None:
                reasons.append("ACTIVE_STATE_UNVERIFIABLE")
                policies.append("TB-CONFLICT-001")
                return
            if active.action_id == proposal.action_id:
                continue
            same_target = (
                active.interface == proposal.interface
                and active.target.target_type == proposal.target.target_type
                and active.target.target_id == proposal.target.target_id
            )
            same_parameter = (
                active.parameters.get("control_parameter")
                and active.parameters.get("control_parameter")
                == proposal.parameters.get("control_parameter")
            )
            if same_target and same_parameter:
                reasons.append("ACTION_CONFLICT")
                policies.append("TB-CONFLICT-001")
                return

    def _check_approval(
        self,
        proposal: ActionProposal,
        as_of: datetime,
        reasons: list[str],
        policies: list[str],
    ) -> None:
        risk_requires = proposal.risk_level in set(
            self.policy.get("approval_required_for_risk", [])
        )
        action_requires = proposal.action in set(
            self.policy.get("approval_required_actions", [])
        )
        if not (risk_requires or action_requires):
            return
        if proposal.approval is None:
            reasons.append("HUMAN_APPROVAL_REQUIRED")
            policies.append("TB-APPROVAL-001")
            return
        expires_at = datetime.fromisoformat(
            proposal.approval.expires_at.replace("Z", "+00:00")
        )
        if expires_at <= as_of:
            reasons.append("HUMAN_APPROVAL_EXPIRED")
            policies.append("TB-APPROVAL-001")
            return
        verification = self.approval_verifier.verify(
            proposal.approval,
            proposal,
            as_of,
        )
        if not verification.trusted:
            reasons.append(verification.reason_code)
            policies.append("TB-APPROVAL-001")
