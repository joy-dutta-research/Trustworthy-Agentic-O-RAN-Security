"""Independent reference witnesses and differential checks on small fixtures."""
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.evaluation_reference import ReferencePolicy
from oran_trust_boundary.evaluation_cases import ACTION_SPECS, make_case, seal_case, stamp
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.approval import StaticApprovalRegistry


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.reference = ReferencePolicy()

    def test_six_valid_actions(self):
        for action in ACTION_SPECS:
            case = make_case(action)
            self.assertEqual(self.reference.evaluate(case)["decision"], "ALLOW", action)

    def test_expiry_equality_differs_from_ttl(self):
        case = make_case()
        case["proposal"]["requested_at"] = stamp(300)
        self.assertEqual(self.reference.evaluate(case)["decision"], "ALLOW")
        case["proposal"]["requested_at"] = stamp(300.000001)
        self.assertIn("ACTION_TTL_EXPIRED", self.reference.evaluate(case)["reasons"])
        case = make_case("rollback_policy")
        case["proposal"]["approval"]["expires_at"] = case["evaluation_time"]
        case = seal_case(case)
        self.assertEqual(self.reference.evaluate(case)["decision"], "ESCALATE")

    def test_legacy_rollback_scope_and_untyped_parameter_retained(self):
        case = make_case("rollback_policy")
        case["proposal"]["target"]["slice_id"] = "slice-emergency"
        case["proposal"]["rollback"] = {"available": False, "procedure": ""}
        case["proposal"]["parameters"]["snapshot_id"] = None
        case = seal_case(case)
        self.assertEqual(self.reference.evaluate(case)["decision"], "ALLOW")
        self.assertIn("L03", self.reference.evaluate(case)["legacy_limitations"])

    def test_independent_approval_binding(self):
        case = make_case("isolate_xapp")
        case["proposal"]["parameters"]["duration_seconds"] = 200
        result = self.reference.evaluate(case)
        self.assertEqual(result["reasons"], ["HUMAN_APPROVAL_BINDING_MISMATCH"])
        self.assertEqual(self.reference.evaluate(seal_case(case))["decision"], "ALLOW")

    def test_python_profile_and_schema_differences(self):
        for field, value in (("ttl_seconds", 300.0), ("incident_id", "   ")):
            case = make_case()
            case["proposal"][field] = value
            self.assertFalse(self.reference.structural_valid(case["proposal"]))
        case = make_case()
        case["proposal"]["parameters"]["reduction_percent"] = True
        self.assertTrue(self.reference.structural_valid(case["proposal"]))
        self.assertIn("REQUIRED_NUMERIC_PARAMETER_MISSING", self.reference.evaluate(case)["reasons"])

    def test_overrides_do_not_mutate_original(self):
        changed = self.reference.with_overrides(maximum_reduction_percent=60, maximum_ttl_seconds=300)
        self.assertEqual(self.reference.spec["actions"]["rate_limit_ue"]["numeric_bounds"]["reduction_percent"][1], 80)
        self.assertEqual(changed.operator_policy["parameter_bounds"]["rate_limit_ue"]["reduction_percent"]["maximum"], 60)

    def test_reference_has_no_production_imports(self):
        text = (ROOT / "src/oran_trust_boundary/evaluation_reference.py").read_text()
        for forbidden in ("from .engine", "from .contract", "from .approval", "from .audit", "import TrustBoundary"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
