from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
import zipfile
from copy import deepcopy
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.approval import StaticApprovalRegistry
from oran_trust_boundary.audit import canonical_sha256
from oran_trust_boundary.conformance import approval_registry, generate_cases
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.jsonio import StrictJsonError, strict_json_load, strict_json_loads
from oran_trust_boundary.model_review import (
    PUBLIC_FILES, build_blinded_package, compare_model_responses,
    prepare_packages, validate_model_response,
)


def response(private):
    return {
        "package_id": private["package_id"],
        "run_metadata": {
            "model_name_as_displayed": "test model",
            "mode_as_displayed": "test mode",
            "run_date_utc": "2026-09-22", "tools_used": [],
            "unavailable_settings": ["seed", "temperature"],
        },
        "decisions": [{
            "review_id": review_id,
            "decision": private["constructed_references"][case_id]["decision"],
            "rule_refs": ["test reference"], "rationale": "Test fixture rationale.",
            "ambiguity": False, "notes": "",
        } for review_id, case_id in private["review_id_to_case_id"].items()],
        "policy_critique": [],
    }


class ModelReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(generate_cases())
        cls.policy = strict_json_load(ROOT / "configs/paper_policy.json", maximum_bytes=1024 * 1024)
        cls.schema = strict_json_load(ROOT / "schemas/action.schema.json", maximum_bytes=1024 * 1024)
        cls.registry = approval_registry(cls.cases)
        cls.files_a, cls.private_a = build_blinded_package(
            cls.cases, cls.policy, cls.schema, cls.registry,
            package_id="reviewer_a", blind_key=b"a" * 32,
        )
        cls.files_b, cls.private_b = build_blinded_package(
            cls.cases, cls.policy, cls.schema, cls.registry,
            package_id="reviewer_b", blind_key=b"b" * 32,
        )

    def test_public_bundle_has_no_labels_mappings_keys_or_original_ids(self):
        self.assertEqual(set(self.files_a), PUBLIC_FILES)
        public_text = json.dumps(self.files_a)
        for secret in (
            self.private_a["blind_key_hex"], "expected_decision", "expected_reason",
            "policy_under_test", "constructed_references", "review_id_to_case_id",
        ):
            self.assertNotIn(secret, public_text)
        for case in self.cases:
            self.assertNotIn('"' + case["case_id"] + '"', public_text)
            self.assertNotIn('"' + case["proposal"]["action_id"] + '"', public_text)
            self.assertNotIn('"' + case["proposal"]["incident_id"] + '"', public_text)
        for case in self.files_a["CASES.json"]["cases"]:
            self.assertNotIn("category", case)
            self.assertNotIn("kind", case["source_context"])

    def test_policy_and_schema_are_unchanged(self):
        self.assertEqual(self.files_a["POLICY.json"], self.policy)
        self.assertEqual(self.files_a["ACTION_SCHEMA.json"], self.schema)
        self.assertEqual(self.files_a["POLICY.json"], self.files_b["POLICY.json"])

    def test_case_order_shuffled_and_ids_distinct_between_packages(self):
        ordered = [self.private_a["review_id_to_case_id"][case["review_id"]]
                   for case in self.files_a["CASES.json"]["cases"]]
        self.assertCountEqual(ordered, [case["case_id"] for case in self.cases])
        self.assertNotEqual(ordered, [case["case_id"] for case in self.cases])
        self.assertTrue(set(self.private_a["review_id_to_case_id"]).isdisjoint(
            self.private_b["review_id_to_case_id"],
        ))
        repeat, _ = build_blinded_package(
            self.cases, self.policy, self.schema, self.registry,
            package_id="reviewer_a", blind_key=b"a" * 32,
        )
        self.assertEqual(repeat, self.files_a)

    def test_approval_remapping_preserves_all_engine_decisions(self):
        doc = self.files_a["CASES.json"]
        engine = TrustBoundary(self.policy, StaticApprovalRegistry(doc["trusted_approval_registry"]["approvals"]))
        for case in doc["cases"]:
            result = engine.evaluate(
                case["proposal"], case["active_actions"],
                authenticated_principal=case["authenticated_principal"],
                as_of=datetime.fromisoformat(case["evaluation_time"].replace("Z", "+00:00")),
            )
            canonical_id = self.private_a["review_id_to_case_id"][case["review_id"]]
            expected = self.private_a["constructed_references"][canonical_id]
            self.assertEqual(result.decision.value, expected["decision"], canonical_id)
            self.assertIn(expected["reason"], result.reason_codes, canonical_id)

    def test_approval_attestations_are_recomputed_not_repaired(self):
        doc = self.files_a["CASES.json"]
        registry = doc["trusted_approval_registry"]["approvals"]
        observed_valid = observed_invalid = False
        for case in doc["cases"]:
            for proposal in [case["proposal"], *case["active_actions"]]:
                if proposal["approval"] is None:
                    continue
                binding = doc["approval_binding_verification"][proposal["action_id"]]
                actual = canonical_sha256(proposal)
                self.assertEqual(binding["proposal_sha256"], actual)
                matches = registry[binding["approval_id"]]["proposal_sha256"] == actual
                self.assertEqual(binding["registry_hash_matches_proposal"], matches)
                observed_valid |= matches
                observed_invalid |= not matches
        self.assertTrue(observed_valid)
        self.assertTrue(observed_invalid)  # Existing active-action approval reuse stays invalid.

    def test_export_does_not_mutate_inputs(self):
        before = deepcopy((self.cases, self.policy, self.schema, self.registry))
        build_blinded_package(*before, package_id="test", blind_key=b"x" * 32)
        self.assertEqual(before, (self.cases, self.policy, self.schema, self.registry))

    def test_zip_is_allowlisted_and_private_is_separate(self):
        parent = ROOT / "tmp/tests"
        directory = parent / ("model-review-" + uuid.uuid4().hex)
        directory.mkdir(parents=True)

        def cleanup():
            # Delete only this test's fresh, resolved child, never a broad root.
            resolved = directory.resolve(strict=True)
            if resolved.parent != parent.resolve(strict=True) or not resolved.name.startswith("model-review-"):
                raise ValueError("test cleanup escaped its assigned parent")
            shutil.rmtree(resolved)

        self.addCleanup(cleanup)
        archives = prepare_packages(directory, self.cases, self.policy, self.schema, self.registry)
        for archive in archives:
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), PUBLIC_FILES)
                self.assertTrue(all("private" not in filename for filename in bundle.namelist()))
        private = directory / "review/private/model_review_round1"
        self.assertTrue((private / "reviewer_a_private.json").is_file())
        self.assertFalse(private.is_relative_to(archives[0].parent))
        with self.assertRaises(FileExistsError):
            prepare_packages(directory, self.cases, self.policy, self.schema, self.registry)

    def test_response_rejects_missing_duplicate_wrong_package_unknown_and_extra_fields(self):
        bad_responses = []
        missing = response(self.private_a); missing["decisions"].pop(); bad_responses.append(missing)
        duplicate = response(self.private_a); duplicate["decisions"].append(duplicate["decisions"][0]); bad_responses.append(duplicate)
        wrong = response(self.private_a); wrong["package_id"] = "wrong"; bad_responses.append(wrong)
        unknown = response(self.private_a); unknown["decisions"][0]["review_id"] = "unknown"; bad_responses.append(unknown)
        extra = response(self.private_a); extra["decisions"][0]["extra"] = "not permitted"; bad_responses.append(extra)
        malformed = response(self.private_a); malformed["decisions"][0]["ambiguity"] = "false"; bad_responses.append(malformed)
        invalid_date = response(self.private_a); invalid_date["run_metadata"]["run_date_utc"] = "20260922"; bad_responses.append(invalid_date)
        for value in bad_responses:
            with self.subTest(value=value["package_id"]), self.assertRaises(ValueError):
                validate_model_response(value, self.private_a)
        with self.assertRaises(StrictJsonError):
            strict_json_loads('{"package_id":"a","package_id":"b"}', maximum_bytes=1024)

    def test_complete_agreement_and_kappa(self):
        result = compare_model_responses(response(self.private_a), response(self.private_b), self.private_a, self.private_b)
        self.assertEqual(result["case_count"], 120)
        self.assertEqual(result["agreement_among_joint_decided"], 1.0)
        self.assertEqual(result["cohens_kappa_among_joint_decided"], 1.0)
        self.assertEqual(result["coverage"]["joint_decided"], 120)
        self.assertEqual(result["disagreements"], [])
        self.assertIn("not accuracy", result["interpretation"])

    def test_different_rule_inputs_or_review_protocol_are_rejected(self):
        for field in ("policy_sha256", "suite_sha256", "action_schema_sha256",
                      "approval_registry_sha256", "review_protocol_sha256"):
            private = deepcopy(self.private_b)
            private[field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_model_responses(response(self.private_a), response(private), self.private_a, private)

    def test_abstentions_and_degenerate_kappa_are_separate(self):
        first, second = response(self.private_a), response(self.private_b)
        first["decisions"][0]["decision"] = "INSUFFICIENT_INFORMATION"
        result = compare_model_responses(first, second, self.private_a, self.private_b)
        self.assertEqual(result["coverage"]["first_decided"], 119)
        self.assertEqual(result["coverage"]["joint_decided"], 119)
        self.assertEqual(result["agreement_among_joint_decided"], 1.0)
        self.assertEqual(len(result["disagreements"]), 1)
        self.assertEqual(len(result["abstentions_or_ambiguities"]), 1)
        for data in (first, second):
            for row in data["decisions"]:
                row["decision"] = "ALLOW"
        degenerate = compare_model_responses(first, second, self.private_a, self.private_b)
        self.assertIsNone(degenerate["cohens_kappa_among_joint_decided"])
        for data in (first, second):
            for row in data["decisions"]:
                row["decision"] = "INSUFFICIENT_INFORMATION"
        abstentions = compare_model_responses(first, second, self.private_a, self.private_b)
        self.assertIsNone(abstentions["agreement_among_joint_decided"])
        self.assertIsNone(abstentions["cohens_kappa_among_joint_decided"])


if __name__ == "__main__":
    unittest.main()
