from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.audit import completeness
from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.policy import PolicyConfigurationError


class PolicyAndAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (ROOT / "configs" / "paper_policy.json").read_text(encoding="utf-8")
        )
        cls.case = next(generate_cases())
        cls.as_of = datetime.fromisoformat(
            cls.case["evaluation_time"].replace("Z", "+00:00")
        )

    def test_unknown_policy_field_is_rejected(self) -> None:
        policy = deepcopy(self.policy)
        policy["permit_all_debug"] = True
        with self.assertRaises(PolicyConfigurationError):
            TrustBoundary(policy)

    def test_invalid_bounds_are_rejected(self) -> None:
        policy = deepcopy(self.policy)
        policy["parameter_bounds"]["rate_limit_ue"]["reduction_percent"] = {
            "minimum": 80,
            "maximum": 1,
        }
        with self.assertRaises(PolicyConfigurationError):
            TrustBoundary(policy)

    def test_wrong_policy_container_shapes_are_rejected_cleanly(self) -> None:
        for field, replacement in (
            ("interface_actions", ["E2", "A1", "SMO"]),
            ("minimum_risk_by_action", list(self.policy["minimum_risk_by_action"])),
        ):
            policy = deepcopy(self.policy)
            policy[field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(PolicyConfigurationError):
                    TrustBoundary(policy)

    def test_caller_mutation_cannot_change_loaded_policy(self) -> None:
        policy = deepcopy(self.policy)
        engine = TrustBoundary(policy)
        policy["roles"]["observer"].append("rate_limit_ue")
        result = engine.evaluate(
            {
                **deepcopy(self.case["proposal"]),
                "agent": {"agent_id": "agent-observer-01", "role": "observer"},
            },
            authenticated_principal="agent-observer-01",
            as_of=self.as_of,
        )
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("UNAUTHORIZED_AGENT", result.reason_codes)

    def test_malformed_inputs_never_bypass_and_are_audited(self) -> None:
        engine = TrustBoundary(self.policy)
        required = engine.policy["audit_required_fields"]
        malformed_values = [None, "action", [], 42, {}, {"action": "unknown"}]
        for value in malformed_values:
            result = engine.evaluate(value, as_of=self.as_of)
            self.assertEqual(result.decision.value, "DENY")
            self.assertEqual(completeness(result.audit_record, required), 1.0)

    def test_malformed_object_repr_is_not_invoked_during_audit(self) -> None:
        class HostileObject:
            def __repr__(self) -> str:
                raise AssertionError("repr must not be called")

        engine = TrustBoundary(self.policy)
        result = engine.evaluate(HostileObject(), as_of=self.as_of)
        self.assertEqual(result.decision.value, "DENY")
        self.assertIsNotNone(result.audit_record)

    def test_cyclic_parameter_input_is_denied_not_crashed(self) -> None:
        engine = TrustBoundary(self.policy)
        proposal = deepcopy(self.case["proposal"])
        proposal["parameters"]["loop"] = proposal["parameters"]
        result = engine.evaluate(
            proposal,
            authenticated_principal=self.case["authenticated_principal"],
            as_of=self.as_of,
        )
        self.assertEqual(result.decision.value, "DENY")
        self.assertIn("CYCLIC_PARAMETER", result.reason_codes)

    def test_stale_and_future_requests_are_denied(self) -> None:
        engine = TrustBoundary(self.policy)
        stale = deepcopy(self.case["proposal"])
        stale["requested_at"] = "2026-01-15T11:00:00Z"
        future = deepcopy(self.case["proposal"])
        future["requested_at"] = "2026-01-15T13:00:00Z"
        self.assertIn(
            "STALE_ACTION_PROPOSAL",
            engine.evaluate(
                stale,
                authenticated_principal=self.case["authenticated_principal"],
                as_of=self.as_of,
            ).reason_codes,
        )
        self.assertIn(
            "REQUEST_TIMESTAMP_IN_FUTURE",
            engine.evaluate(
                future,
                authenticated_principal=self.case["authenticated_principal"],
                as_of=self.as_of,
            ).reason_codes,
        )


if __name__ == "__main__":
    unittest.main()
