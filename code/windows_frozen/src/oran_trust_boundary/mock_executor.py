"""Non-networked executor used to prove that no live actuation is possible."""

from __future__ import annotations

from typing import Any, Mapping

from .audit import canonical_sha256, verify_record_checksum
from .models import Decision, EvaluationResult


class DryRunExecutor:
    """Record allowed proposals without performing an external side effect."""

    def __init__(self) -> None:
        self.receipts: list[dict[str, str]] = []
        self._submitted_action_ids: set[str] = set()

    def submit(
        self,
        proposal: Mapping[str, Any],
        result: EvaluationResult,
    ) -> dict[str, str]:
        if result.decision is not Decision.ALLOW:
            raise PermissionError("only ALLOW decisions can reach the dry-run executor")
        if result.audit_record is None:
            raise PermissionError("an auditable Trust-Boundary decision is required")
        if result.system != "trust_boundary":
            raise PermissionError("decision must originate from the Trust Boundary")
        if not verify_record_checksum(result.audit_record):
            raise PermissionError("audit record checksum verification failed")
        if result.audit_record.get("decision") != Decision.ALLOW.value:
            raise PermissionError("audit record does not contain an ALLOW decision")
        proposal_sha256 = canonical_sha256(proposal)
        if result.audit_record.get("proposal_sha256") != proposal_sha256:
            raise PermissionError("decision is not bound to this proposal")
        action_id = str(proposal["action_id"])
        if result.audit_record.get("action_id") != action_id:
            raise PermissionError("decision action ID does not match this proposal")
        if action_id in self._submitted_action_ids:
            raise RuntimeError("replayed action_id rejected")
        receipt = {
            "mode": "dry-run",
            "action_id": action_id,
            "proposal_sha256": proposal_sha256,
        }
        self.receipts.append(receipt)
        self._submitted_action_ids.add(action_id)
        return receipt
