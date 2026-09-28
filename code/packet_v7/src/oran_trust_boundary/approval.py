"""Out-of-band verification of human approval references."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from .audit import canonical_sha256
from .jsonio import strict_json_load
from .models import ActionProposal, Approval


@dataclass(frozen=True)
class ApprovalVerification:
    trusted: bool
    reason_code: str


class ApprovalVerifier(Protocol):
    def verify(
        self,
        approval: Approval,
        proposal: ActionProposal,
        as_of: datetime,
    ) -> ApprovalVerification: ...


class DenyAllApprovalVerifier:
    """Safe default when no trusted approval authority is configured."""

    def verify(
        self,
        approval: Approval,
        proposal: ActionProposal,
        as_of: datetime,
    ) -> ApprovalVerification:
        del approval, proposal, as_of
        return ApprovalVerification(False, "HUMAN_APPROVAL_UNTRUSTED")


class StaticApprovalRegistry:
    """Offline benchmark adapter for an external approval authority.

    Production deployments must replace this fixture with an authenticated,
    integrity-protected approval service. Proposal-supplied approval claims are
    never trusted without a matching registry record.
    """

    def __init__(self, records: Mapping[str, Any]):
        if not isinstance(records, Mapping):
            raise ValueError("approval registry must be an object")
        copied = json.loads(json.dumps(records, allow_nan=False))
        expected_fields = {
            "status",
            "action_id",
            "agent_id",
            "approved_by_role",
            "expires_at",
            "proposal_sha256",
        }
        for approval_id, record in copied.items():
            if not isinstance(approval_id, str) or not approval_id:
                raise ValueError("approval IDs must be non-empty strings")
            if not isinstance(record, dict) or set(record) != expected_fields:
                raise ValueError(f"invalid approval registry record {approval_id}")
            if record["status"] not in {"approved", "revoked"}:
                raise ValueError(f"invalid approval status for {approval_id}")
            if any(
                not isinstance(record[field], str) or not record[field]
                for field in (
                    "action_id",
                    "agent_id",
                    "approved_by_role",
                    "expires_at",
                    "proposal_sha256",
                )
            ):
                raise ValueError(f"invalid approval values for {approval_id}")
            try:
                expires_at = datetime.fromisoformat(
                    record["expires_at"].replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError(f"invalid approval expiry for {approval_id}") from exc
            if expires_at.tzinfo is None:
                raise ValueError(f"approval expiry must be timezone aware for {approval_id}")
            digest = record["proposal_sha256"]
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ValueError(f"invalid proposal digest for {approval_id}")
        self._records = copied

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticApprovalRegistry":
        value = strict_json_load(path, maximum_bytes=5 * 1024 * 1024)
        if not isinstance(value, dict) or set(value) != {
            "registry_version",
            "description",
            "approvals",
        }:
            raise ValueError("approval registry envelope is invalid")
        if not isinstance(value["registry_version"], str) or not value["registry_version"]:
            raise ValueError("approval registry version is invalid")
        if not isinstance(value["description"], str) or not value["description"].strip():
            raise ValueError("approval registry description is invalid")
        return cls(value["approvals"])

    def verify(
        self,
        approval: Approval,
        proposal: ActionProposal,
        as_of: datetime,
    ) -> ApprovalVerification:
        record = self._records.get(approval.approval_id)
        if not isinstance(record, dict) or record.get("status") != "approved":
            return ApprovalVerification(False, "HUMAN_APPROVAL_UNTRUSTED")
        expected = {
            "action_id": proposal.action_id,
            "agent_id": proposal.agent.agent_id,
            "approved_by_role": approval.approved_by_role,
            "expires_at": approval.expires_at,
            "proposal_sha256": canonical_sha256(proposal.to_mapping()),
        }
        if any(record.get(field) != value for field, value in expected.items()):
            return ApprovalVerification(False, "HUMAN_APPROVAL_BINDING_MISMATCH")
        expires_at = datetime.fromisoformat(approval.expires_at.replace("Z", "+00:00"))
        if expires_at <= as_of:
            return ApprovalVerification(False, "HUMAN_APPROVAL_EXPIRED")
        return ApprovalVerification(True, "HUMAN_APPROVAL_VERIFIED")
