from __future__ import annotations

import json
import math
from copy import deepcopy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.conformance import generate_cases
from oran_trust_boundary.contract import (
    ALLOWED_ACTIONS,
    ALLOWED_INTERFACES,
    ALLOWED_RISK_LEVELS,
    ALLOWED_TARGET_TYPES,
    parse_action,
)


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proposal = next(generate_cases())["proposal"]

    def test_valid_proposal_parses_without_coercion(self) -> None:
        parsed, issues = parse_action(self.proposal)
        self.assertIsNotNone(parsed)
        self.assertEqual(issues, ())
        self.assertEqual(parsed.to_mapping(), self.proposal)

    def test_unknown_action_fails_closed(self) -> None:
        self.proposal["action"] = "execute_arbitrary_command"
        parsed, issues = parse_action(self.proposal)
        self.assertIsNone(parsed)
        self.assertIn("UNKNOWN_ACTION", {issue.code for issue in issues})

    def test_unknown_field_is_rejected(self) -> None:
        self.proposal["debug_override"] = True
        parsed, issues = parse_action(self.proposal)
        self.assertIsNone(parsed)
        self.assertIn("UNKNOWN_FIELD", {issue.code for issue in issues})

    def test_schema_and_parser_action_enums_match(self) -> None:
        schema = json.loads((ROOT / "schemas" / "action.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["properties"]["action"]["enum"]), set(ALLOWED_ACTIONS))
        self.assertEqual(
            set(schema["properties"]["interface"]["enum"]),
            set(ALLOWED_INTERFACES),
        )
        self.assertEqual(
            set(schema["properties"]["risk_level"]["enum"]),
            set(ALLOWED_RISK_LEVELS),
        )
        self.assertEqual(
            set(schema["properties"]["target"]["properties"]["target_type"]["enum"]),
            set(ALLOWED_TARGET_TYPES),
        )

    def test_non_finite_parameter_is_rejected(self) -> None:
        self.proposal["parameters"]["reduction_percent"] = math.nan
        parsed, issues = parse_action(self.proposal)
        self.assertIsNone(parsed)
        self.assertIn("NON_FINITE_PARAMETER", {issue.code for issue in issues})

    def test_unhashable_enum_values_are_rejected_not_raised(self) -> None:
        for field in ("action", "interface", "risk_level"):
            proposal = deepcopy(self.proposal)
            proposal[field] = []
            parsed, issues = parse_action(proposal)
            self.assertIsNone(parsed)
            self.assertTrue(issues)

    def test_non_string_object_key_is_rejected_not_sorted(self) -> None:
        proposal = deepcopy(self.proposal)
        proposal[1] = "not-json"
        parsed, issues = parse_action(proposal)
        self.assertIsNone(parsed)
        self.assertIn("INVALID_FIELD_NAME", {issue.code for issue in issues})


if __name__ == "__main__":
    unittest.main()
