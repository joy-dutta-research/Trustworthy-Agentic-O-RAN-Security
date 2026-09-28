"""Typed domain models used by the Trust Boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Possible pre-action decisions."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class Agent:
    agent_id: str
    role: str


@dataclass(frozen=True)
class Target:
    target_type: str
    target_id: str
    cell_id: str | None
    slice_id: str | None


@dataclass(frozen=True)
class Rollback:
    available: bool
    procedure: str


@dataclass(frozen=True)
class Approval:
    approval_id: str
    approved_by_role: str
    expires_at: str


@dataclass(frozen=True)
class ActionProposal:
    action_id: str
    incident_id: str
    requested_at: str
    agent: Agent
    action: str
    interface: str
    target: Target
    parameters: dict[str, Any]
    risk_level: str
    ttl_seconds: int
    expected_kpi: str
    rollback: Rollback
    evidence_refs: tuple[str, ...]
    approval: Approval | None

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        value = asdict(self)
        value["evidence_refs"] = list(self.evidence_refs)
        return value


@dataclass(frozen=True)
class ContractIssue:
    code: str
    field: str
    message: str


@dataclass(frozen=True)
class EvaluationResult:
    system: str
    decision: Decision
    reason_codes: tuple[str, ...]
    policy_ids: tuple[str, ...]
    audit_record: dict[str, Any] | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "policy_ids": list(self.policy_ids),
            "audit_record": self.audit_record,
        }

