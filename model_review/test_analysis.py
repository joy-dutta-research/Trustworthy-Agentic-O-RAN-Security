"""Small regression and malformed-response tests; no model calls or file writes."""

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("analyze_model_reviews", ROOT / "tools/analyze_model_reviews.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ModelReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.response = MODULE.read_json(ROOT / "model_review/responses/reviewer_a.json")
        cls.package = MODULE.read_json(ROOT / "model_review/inputs/reviewer_a/CASES.json")
        cls.mapping = MODULE.read_json(ROOT / "model_review/post_review/reviewer_a_mapping.json")

    def validate(self, response=None, mapping=None):
        return MODULE.validate_response(response or self.response, self.package,
                                        mapping or self.mapping, "reviewer_a")

    def test_saved_results_match_recomputation(self):
        for name, content in MODULE.analyze(ROOT).items():
            self.assertEqual((ROOT / "results/08_model_review" / name).read_bytes(), content, name)

    def test_complete_original_response(self):
        self.assertEqual(len(self.validate()), 120)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.unique_object([("decision", "ALLOW"), ("decision", "DENY")])

    def test_duplicate_case_rejected(self):
        response = copy.deepcopy(self.response)
        response["decisions"][1] = response["decisions"][0]
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_missing_case_rejected(self):
        response = copy.deepcopy(self.response)
        response["decisions"].pop()
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_unknown_case_rejected(self):
        response = copy.deepcopy(self.response)
        response["decisions"][0]["review_id"] = "unknown"
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_invalid_label_rejected(self):
        response = copy.deepcopy(self.response)
        response["decisions"][0]["decision"] = "SAFE"
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_ambiguity_must_be_boolean(self):
        response = copy.deepcopy(self.response)
        response["decisions"][0]["ambiguity"] = "false"
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_empty_rationale_rejected(self):
        response = copy.deepcopy(self.response)
        response["decisions"][0]["rationale"] = " "
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_wrong_package_rejected(self):
        response = copy.deepcopy(self.response)
        response["package_id"] = "another-round"
        with self.assertRaises(ValueError):
            self.validate(response)

    def test_nonbijective_crosswalk_rejected(self):
        mapping = copy.deepcopy(self.mapping)
        keys = list(mapping["review_id_to_case_id"])
        mapping["review_id_to_case_id"][keys[1]] = mapping["review_id_to_case_id"][keys[0]]
        with self.assertRaises(ValueError):
            self.validate(mapping=mapping)

    def test_original_reference_rule_disclosure(self):
        self.assertEqual(self.mapping["constructed_references"]["case-01-approval"]["decision"], "ESCALATE")
        self.assertNotIn("blind_key_hex", self.mapping)


if __name__ == "__main__":
    unittest.main()
