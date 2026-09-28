"""Offline, temporary-fixture tests for the hash-only Stage 0 inventory."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "freeze_evaluation_baseline.py"
MODULE_SPEC = importlib.util.spec_from_file_location("evaluation_freeze", SCRIPT)
freeze = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(freeze)


class EvaluationFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oran-freeze-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("src/gateway.py", b"# frozen fixture\n")
        self.write("src/__pycache__/gateway.pyc", b"not selected")
        self.write("src/not-selected.txt", b"not selected")
        self.write("data/raw/receipt.json", json.dumps({"archive_name": "archive.zip", "digest": "a" * 64, "size": 25000000000}).encode())
        self.spec = {
            "schema_version": freeze.SPEC_VERSION,
            "files": [{"path": "src/gateway.py", "expected_sha256": hashlib.sha256(b"# frozen fixture\n").hexdigest()}],
            "trees": [{"path": "src", "suffixes": [".py"], "exclude_dirs": ["__pycache__"]}],
            "provenance_only": [{"artifact_id": "large_archive", "receipt": "data/raw/receipt.json", "sha256_pointer": "/digest", "size_pointer": "/size"}],
        }
        self.spec_relative = "docs/evaluation_v0.2/spec.json"
        self.save_spec()

    def write(self, relative: str, content: bytes) -> Path:
        target = self.root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def save_spec(self) -> None:
        self.write(self.spec_relative, json.dumps(self.spec).encode("utf-8"))

    def baseline(self) -> Path:
        self.save_spec()
        return freeze.freeze_baseline(self.root, self.spec_relative)

    def test_roundtrip_and_hash_only_provenance(self) -> None:
        result = self.baseline()
        report = freeze.verify_baseline(self.root, result)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["tracked_file_count"], 3)
        self.assertEqual(report["receipt_only_artifacts_not_rehashed"], ["large_archive"])
        manifest = json.loads((result / "manifest.json").read_text())
        self.assertEqual(manifest["provenance_only"][0]["artifact_sha256_receipt_reported"], "a" * 64)
        self.assertEqual(manifest["provenance_only"][0]["verification"], "receipt_only_artifact_not_rehashed")
        self.assertFalse((self.root / "archive.zip").exists())
        self.assertNotIn(str(self.root), (result / "manifest.json").read_text())
        self.assertNotIn("# frozen fixture", (result / "manifest.json").read_text())
        self.assertEqual(set(item.name for item in result.iterdir()), {"STARTED.json", "manifest.json", "COMPLETE.json"})

    def test_modification_missing_and_added_are_reported(self) -> None:
        self.write("src/second.py", b"second")
        result = self.baseline()
        self.write("src/gateway.py", b"modified")
        (self.root / "src/second.py").unlink()
        self.write("src/new.py", b"new")
        report = freeze.verify_baseline(self.root, result)
        self.assertEqual(report["status"], "different")
        self.assertEqual(report["modified"], ["src/gateway.py"])
        self.assertEqual(report["missing"], ["src/second.py"])
        self.assertEqual(report["added"], ["src/new.py"])

    def test_untracked_extensions_and_excluded_cache_do_not_change_baseline(self) -> None:
        result = self.baseline()
        self.write("src/new.txt", b"not tracked")
        self.write("src/__pycache__/new.py", b"excluded directory")
        self.assertEqual(freeze.verify_baseline(self.root, result)["status"], "pass")

    def test_all_files_tree_detects_added_arbitrary_extension(self) -> None:
        self.write("results/legacy/summary.json", b"{}")
        self.spec["trees"].append({"path": "results/legacy", "suffixes": None, "exclude_dirs": []})
        result = self.baseline()
        self.write("results/legacy/new.bin", b"addition")
        self.assertEqual(freeze.verify_baseline(self.root, result)["added"], ["results/legacy/new.bin"])

    def test_output_is_exclusive_and_never_overwritten(self) -> None:
        first = self.baseline()
        original = (first / "manifest.json").read_bytes()
        second = self.baseline()
        self.assertNotEqual(first, second)
        self.assertEqual((first / "manifest.json").read_bytes(), original)
        with self.assertRaises(freeze.FreezeError):
            freeze._write_new(first / "manifest.json", {})

    def test_expected_hash_mismatch_retains_failed_attempt(self) -> None:
        self.spec["files"][0]["expected_sha256"] = "0" * 64
        self.save_spec()
        with self.assertRaisesRegex(freeze.FreezeError, "historically expected hash mismatch"):
            freeze.freeze_baseline(self.root, self.spec_relative)
        attempts = list((self.root / freeze.OUTPUT_ROOT).iterdir())
        self.assertEqual(len(attempts), 1)
        self.assertTrue((attempts[0] / "STARTED.json").exists())
        self.assertTrue((attempts[0] / "FAILED.json").exists())
        self.assertFalse((attempts[0] / "COMPLETE.json").exists())
        with self.assertRaises(freeze.FreezeError):
            freeze.verify_baseline(self.root, attempts[0])

    def test_file_tree_overlap_is_deduplicated_but_conflicting_pins_refused(self) -> None:
        self.spec["files"].append({"path": "src/gateway.py"})
        result = self.baseline()
        self.assertEqual(freeze.verify_baseline(self.root, result)["tracked_file_count"], 3)
        self.spec["files"].append({"path": "src/gateway.py", "expected_sha256": "b" * 64})
        with self.assertRaisesRegex(freeze.FreezeError, "contradictory"):
            freeze.validate_spec(self.spec)

    def test_null_receipt_pointers_do_not_invent_archive_hash(self) -> None:
        self.spec["provenance_only"][0]["sha256_pointer"] = None
        self.spec["provenance_only"][0]["size_pointer"] = None
        result = self.baseline()
        manifest = json.loads((result / "manifest.json").read_text())
        self.assertIsNone(manifest["provenance_only"][0]["artifact_sha256_receipt_reported"])
        self.assertIsNone(manifest["provenance_only"][0]["artifact_size_bytes_receipt_reported"])

    def test_receipt_change_detected_even_when_new_json_invalid(self) -> None:
        result = self.baseline()
        self.write("data/raw/receipt.json", b"not JSON")
        report = freeze.verify_baseline(self.root, result)
        self.assertEqual(report["modified"], ["data/raw/receipt.json"])
        self.assertTrue(report["provenance_changed"])

    def test_spec_change_is_detected_using_original_selection(self) -> None:
        result = self.baseline()
        self.spec["trees"] = []
        self.spec["files"] = []
        self.save_spec()
        self.write("src/new.py", b"must still be detected")
        report = freeze.verify_baseline(self.root, result)
        self.assertIn(self.spec_relative, report["modified"])
        self.assertIn("src/new.py", report["added"])

    def test_manifest_tamper_and_incomplete_baseline_refused(self) -> None:
        result = self.baseline()
        (result / "manifest.json").write_bytes(b"{}")
        with self.assertRaisesRegex(freeze.FreezeError, "checksum"):
            freeze.verify_baseline(self.root, result)
        (result / "COMPLETE.json").unlink()
        with self.assertRaises(freeze.FreezeError):
            freeze.verify_baseline(self.root, result)

    def test_unknown_fields_duplicate_keys_nonfinite_and_bad_versions_refused(self) -> None:
        for field, value in (("extra", 1), ("schema_version", "future"), ("trees", "src")):
            spec = copy.deepcopy(self.spec)
            spec[field] = value
            with self.subTest(field=field), self.assertRaises(freeze.FreezeError):
                freeze.validate_spec(spec)
        for content in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            self.write(self.spec_relative, content)
            with self.subTest(content=content), self.assertRaises(freeze.FreezeError):
                freeze.freeze_baseline(self.root, self.spec_relative)

    def test_path_traversal_absolute_credentials_private_and_output_inputs_refused(self) -> None:
        for name in ("../escape", "/absolute", "C:/secret", "src\\file.py", "src/../file.py", "src/./file.py",
                     "src/file.py.", ".env", "data/kaggle.json", "review/private/a.json", "src/CON.txt",
                     "results/evaluation_v0.2/x", "Results/Evaluation_v0.2/x"):
            spec = copy.deepcopy(self.spec)
            spec["files"] = [{"path": name}]
            with self.subTest(name=name), self.assertRaises(freeze.FreezeError):
                freeze.validate_spec(spec)

    def test_broad_roots_empty_suffixes_and_ambiguous_case_refused(self) -> None:
        for name in (".", "results", "data", "data/raw", "deliverables", "review"):
            spec = copy.deepcopy(self.spec)
            spec["trees"][0]["path"] = name
            with self.subTest(name=name), self.assertRaises(freeze.FreezeError):
                freeze.validate_spec(spec)
        self.spec["trees"][0]["suffixes"] = []
        with self.assertRaises(freeze.FreezeError):
            freeze.validate_spec(self.spec)
        self.spec["trees"][0]["suffixes"] = [".py"]
        self.spec["files"].append({"path": "SRC/gateway.py"})
        with self.assertRaises(freeze.FreezeError):
            freeze.validate_spec(self.spec)

    def test_bad_provenance_pointer_or_digest_retains_failed_artifact(self) -> None:
        self.spec["provenance_only"][0]["sha256_pointer"] = "/missing"
        with self.assertRaisesRegex(freeze.FreezeError, "does not resolve"):
            self.baseline()
        self.spec["provenance_only"][0]["sha256_pointer"] = "/archive_name"
        with self.assertRaisesRegex(freeze.FreezeError, "SHA-256"):
            self.baseline()

    def test_json_pointer_object_escaping_and_arrays(self) -> None:
        self.assertEqual(freeze._at_pointer({"a/b": {"~x": ["ok"]}}, "/a~1b/~0x/0"), "ok")
        with self.assertRaises(freeze.FreezeError):
            freeze._pointer("/bad~2")
        with self.assertRaises(freeze.FreezeError):
            freeze._at_pointer([1], "/-1")

    def test_missing_explicit_file_refused_on_freeze_and_reported_on_verify(self) -> None:
        self.spec["files"].append({"path": "src/absent.py"})
        with self.assertRaises(freeze.FreezeError):
            self.baseline()
        self.spec["files"].pop()
        result = self.baseline()
        (self.root / "src/gateway.py").unlink()
        self.assertIn("src/gateway.py", freeze.verify_baseline(self.root, result)["missing"])

    def test_reparse_attribute_is_refused(self) -> None:
        self.assertTrue(freeze._is_link(SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400)))
        self.assertFalse(freeze._is_link(SimpleNamespace(st_mode=0o100644, st_file_attributes=0)))

    def test_symlink_input_is_refused_if_platform_allows_links(self) -> None:
        target = self.root / "src/link.py"
        try:
            target.symlink_to(self.root / "src/gateway.py")
        except (OSError, NotImplementedError):
            self.skipTest("creating symbolic links unavailable to this account")
        with self.assertRaisesRegex(freeze.FreezeError, "symbolic links"):
            self.baseline()

    def test_late_input_change_and_tree_addition_are_detected(self) -> None:
        original = freeze._stable_bytes
        changed = False

        def change_after_hash(path: Path, **kwargs):
            nonlocal changed
            result = original(path, **kwargs)
            if path.name == "gateway.py" and not changed:
                changed = True
                path.write_bytes(b"changed after hash")
            return result

        with patch.object(freeze, "_stable_bytes", side_effect=change_after_hash):
            with self.assertRaisesRegex(freeze.FreezeError, "changed before inventory completed"):
                self.baseline()
        self.write("src/gateway.py", b"# frozen fixture\n")
        added = False

        def add_after_hash(path: Path, **kwargs):
            nonlocal added
            result = original(path, **kwargs)
            if path.name == "gateway.py" and not added:
                added = True
                self.write("src/new.py", b"new")
            return result

        with patch.object(freeze, "_stable_bytes", side_effect=add_after_hash):
            with self.assertRaisesRegex(freeze.FreezeError, "membership changed"):
                self.baseline()

    def test_cli_has_privacy_safe_json_and_exit_status(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = freeze.main(["freeze", "--root", str(self.root), "--spec", self.spec_relative])
        self.assertEqual(status, 0)
        response = json.loads(output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output):
            status = freeze.main(["verify", "--root", str(self.root), "--baseline", response["baseline"]])
        self.assertEqual(status, 0)
        self.write("src/gateway.py", b"changed")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(freeze.main(["verify", "--root", str(self.root), "--baseline", response["baseline"]]), 1)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(freeze.main(["verify", "--root", str(self.root), "--baseline", "../escape"]), 2)


if __name__ == "__main__":
    unittest.main()
