from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.approval import StaticApprovalRegistry
from oran_trust_boundary.audit import completeness
from oran_trust_boundary.audit import canonical_sha256
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.mock_executor import DryRunExecutor


class EngineEdgeCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = next(generate_cases())
        self.engine = TrustBoundary.from_file(ROOT / "configs" / "paper_policy.json")
        self.as_of = datetime.fromisoformat(
            self.case["evaluation_time"].replace("Z", "+00:00")
        )

    def evaluate(self, proposal):
        return self.engine.evaluate(
            proposal,
            authenticated_principal=self.case["authenticated_principal"],
            as_of=self.as_of,
        )

    def test_high_risk_with_current_human_approval_is_allowed(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["risk_level"] = "high"
        proposal["approval"] = {
            "approval_id": "approval-test-001",
            "approved_by_role": "human_operator",
            "expires_at": "2026-01-15T13:00:00Z",
        }
        verifier = StaticApprovalRegistry(
            {
                "approval-test-001": {
                    "status": "approved",
                    "action_id": proposal["action_id"],
                    "agent_id": proposal["agent"]["agent_id"],
                    "approved_by_role": "human_operator",
                    "expires_at": "2026-01-15T13:00:00Z",
                    "proposal_sha256": canonical_sha256(proposal),
                }
            }
        )
        trusted_engine = TrustBoundary(self.engine.policy, verifier)
        result = trusted_engine.evaluate(
            proposal,
            authenticated_principal=self.case["authenticated_principal"],
            as_of=self.as_of,
        )
        self.assertEqual(result.decision.value, "ALLOW")

    def test_in_band_approval_is_not_trusted_by_default(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["risk_level"] = "high"
        proposal["approval"] = {
            "approval_id": "self-asserted",
            "approved_by_role": "human_operator",
            "expires_at": "2026-01-15T13:00:00Z",
        }
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "ESCALATE")
        self.assertIn("HUMAN_APPROVAL_UNTRUSTED", result.reason_codes)

    def test_approval_is_bound_to_exact_proposal_digest(self) -> None:
        approved = deepcopy(self.case["proposal"])
        approved["risk_level"] = "high"
        approved["approval"] = {
            "approval_id": "approval-bound-001",
            "approved_by_role": "human_operator",
            "expires_at": "2026-01-15T13:00:00Z",
        }
        verifier = StaticApprovalRegistry(
            {
                "approval-bound-001": {
                    "status": "approved",
                    "action_id": approved["action_id"],
                    "agent_id": approved["agent"]["agent_id"],
                    "approved_by_role": "human_operator",
                    "expires_at": "2026-01-15T13:00:00Z",
                    "proposal_sha256": canonical_sha256(approved),
                }
            }
        )
        tampered = deepcopy(approved)
        tampered["parameters"]["reduction_percent"] = 60
        engine = TrustBoundary(self.engine.policy, verifier)
        result = engine.evaluate(
            tampered,
            authenticated_principal=self.case["authenticated_principal"],
            as_of=self.as_of,
        )
        self.assertEqual(result.decision.value, "ESCALATE")
        self.assertIn("HUMAN_APPROVAL_BINDING_MISMATCH", result.reason_codes)

    def test_expired_approval_is_escalated(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["risk_level"] = "high"
        proposal["approval"] = {
            "approval_id": "approval-test-expired",
            "approved_by_role": "human_operator",
            "expires_at": "2026-01-15T11:00:00Z",
        }
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "ESCALATE")
        self.assertIn("HUMAN_APPROVAL_EXPIRED", result.reason_codes)

    def test_missing_rollback_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["rollback"] = {"available": False, "procedure": ""}
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("ROLLBACK_REQUIRED", result.reason_codes)

    def test_deny_precedes_escalation(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["agent"]["role"] = "observer"
        proposal["risk_level"] = "high"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("UNAUTHORIZED_AGENT", result.reason_codes)

    def test_dry_run_executor_rejects_non_allow_decision(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["agent"]["role"] = "observer"
        result = self.evaluate(proposal)
        executor = DryRunExecutor()
        with self.assertRaises(PermissionError):
            executor.submit(proposal, result)

    def test_dry_run_executor_returns_non_network_receipt(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        result = self.evaluate(proposal)
        executor = DryRunExecutor()
        receipt = executor.submit(proposal, result)
        self.assertEqual(receipt["mode"], "dry-run")
        self.assertEqual(len(executor.receipts), 1)
        with self.assertRaises(RuntimeError):
            executor.submit(proposal, result)

    def test_executor_rejects_proposal_changed_after_allow(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        result = self.evaluate(proposal)
        tampered = deepcopy(proposal)
        tampered["parameters"]["reduction_percent"] = 70
        with self.assertRaises(PermissionError):
            DryRunExecutor().submit(tampered, result)

    def test_executor_rejects_tampered_audit_record(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        result = self.evaluate(proposal)
        audit_record = deepcopy(result.audit_record)
        audit_record["reason_codes"] = ["TAMPERED"]
        tampered_result = replace(result, audit_record=audit_record)
        with self.assertRaises(PermissionError):
            DryRunExecutor().submit(proposal, tampered_result)

    def test_missing_authenticated_principal_is_denied(self) -> None:
        result = self.engine.evaluate(self.case["proposal"], as_of=self.as_of)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("AUTHENTICATED_PRINCIPAL_REQUIRED", result.reason_codes)

    def test_forged_registered_agent_id_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["agent"]["agent_id"] = "agent-orchestrator-01"
        proposal["agent"]["role"] = "security_orchestrator"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("AGENT_IDENTITY_MISMATCH", result.reason_codes)

    def test_self_asserted_role_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["agent"]["role"] = "security_orchestrator"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("AGENT_ROLE_MISMATCH", result.reason_codes)

    def test_understated_risk_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["risk_level"] = "low"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("RISK_CLASSIFICATION_UNDERSTATED", result.reason_codes)

    def test_action_ttl_is_enforced_at_evaluation_time(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["requested_at"] = "2026-01-15T11:59:59Z"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("ACTION_TTL_EXPIRED", result.reason_codes)

    def test_audit_records_authenticated_not_only_claimed_identity(self) -> None:
        result = self.evaluate(deepcopy(self.case["proposal"]))
        self.assertEqual(
            result.audit_record["authenticated_principal"],
            self.case["authenticated_principal"],
        )

    def test_wrong_target_type_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["target"]["target_type"] = "operator"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("ACTION_TARGET_MISMATCH", result.reason_codes)

    def test_unexpected_action_parameter_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["parameters"]["ignored_instruction"] = "unsafe"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("ACTION_PARAMETER_CONTRACT_MISMATCH", result.reason_codes)

    def test_control_parameter_alias_is_denied(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        proposal["parameters"]["control_parameter"] = "different_control"
        result = self.evaluate(proposal)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("CONTROL_PARAMETER_MISMATCH", result.reason_codes)

    def test_malformed_proposal_still_has_complete_audit(self) -> None:
        proposal = deepcopy(self.case["proposal"])
        del proposal["action"]
        result = self.evaluate(proposal)
        required = self.engine.policy["audit_required_fields"]
        self.assertEqual(result.decision.value, "DENY")
        self.assertEqual(completeness(result.audit_record, required), 1.0)

    def test_invalid_active_state_escalates(self) -> None:
        result = self.engine.evaluate(
            self.case["proposal"],
            active_actions=[{"not": "an action"}],
            authenticated_principal=self.case["authenticated_principal"],
            as_of=self.as_of,
        )
        self.assertEqual(result.decision.value, "ESCALATE")
        self.assertIn("ACTIVE_STATE_UNVERIFIABLE", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
