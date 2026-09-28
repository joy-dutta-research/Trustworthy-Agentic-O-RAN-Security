"""Small offline fixtures for streaming handoff, integrity and complete-attempt export."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workstation_bundle_test_module", ROOT / "scripts/workstation_bundle.py")
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class WorkstationBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, data=b"fixture\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def source(self):
        for name in bundle.SOURCE_FILES:
            self.put(name)
        for tree in bundle.SOURCE_TREES:
            (self.root / tree).mkdir(parents=True, exist_ok=True)
        self.put("src/example.py", b"value = 1\n")
        self.put("data/workstation_reproduction/frozen.jsonl", b'{"case":1}\n')
        self.put("reference/university/report.md", b"Preserved comparison reference.\n")
        payload = bundle.source_payload(self.root)
        records = {name: bundle.record_for(value) for name, value in payload.items()}
        self.put(bundle.MANIFEST, bundle.encoded(bundle.manifest_for(records, "source")))
        return payload

    def session(self, name="one", status="INCOMPLETE_NOT_PUBLISHABLE"):
        base = "results/local/workstation_runs/" + name
        self.put(base + "/raw.jsonl", b'{"measured":1}\n')
        if status is not None:
            self.put(base + "/INCOMPLETE.json", bundle.encoded({"status": status}))
        return base

    def test_source_allowlist_excludes_private_and_runtime_files(self):
        original = self.source()
        for name in ("data/raw/secret.db", "review/private/key.json", ".git/config", ".env",
                     ".vm-local/vm.vhdx", "results/local/workstation_runs/one/raw.json"):
            self.put(name, b"private")
        self.assertEqual(bundle.source_payload(self.root), original)
        self.assertEqual(bundle.verify_tree(self.root)["status"], "VERIFIED_SOURCE_TREE")

    def test_required_package_files_and_trees_are_not_silently_omitted(self):
        with self.assertRaisesRegex(ValueError, "Required source file"):
            bundle.source_payload(self.root)
        self.source()
        (self.root / "schemas").rmdir()
        with self.assertRaisesRegex(ValueError, "Required source tree"):
            bundle.source_payload(self.root)

    def test_streaming_copy_hash_and_no_whole_file_read(self):
        path = self.put("large.jsonl", b"x" * 5000)
        destination = io.BytesIO()
        with patch.object(bundle, "CHUNK", 63), patch.object(Path, "read_bytes", side_effect=AssertionError("whole read")):
            record = bundle.stream_file(path, destination)
        self.assertEqual(record, {"sha256": hashlib.sha256(b"x" * 5000).hexdigest(), "bytes": 5000})
        self.assertEqual(len(destination.getvalue()), 5000)

    def test_secret_crossing_chunk_boundary_is_rejected(self):
        key = b"-----BEGIN " + b"PRIVATE KEY-----"
        path = self.put("unsafe.log", b"a" * 60 + key)
        with patch.object(bundle, "CHUNK", 64), self.assertRaisesRegex(ValueError, "credential"):
            bundle.stream_file(path)

    def test_file_size_and_mutation_are_rejected(self):
        path = self.put("small.txt", b"1234")
        with self.assertRaisesRegex(ValueError, "oversized"):
            bundle.stream_file(path, maximum=3)
        class MutatingWriter:
            def write(_self, data):
                path.write_bytes(b"more bytes")
        with self.assertRaisesRegex(ValueError, "changed"):
            bundle.stream_file(path, MutatingWriter())

    def test_path_traversal_windows_stream_and_reserved_names_rejected(self):
        for name in ("../a", "/a", "a//b", "a/./b", "a/../b", "C:/a", "a:b", "a\\b",
                     "a/CON.txt", "a/end.", "a/end ", "nul", "a/line\nfile", 'a/"x', "a/*"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.clean_relative(name)

    def test_case_collisions_fail(self):
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            bundle.write_archive(self.root / "x.zip", {"A.txt": b"x", "a.txt": b"y"}, "source")

    def test_file_directory_prefix_collision_fails(self):
        with self.assertRaisesRegex(ValueError, "prefix collision"):
            bundle.unique_names(["folder/file", "FOLDER"])

    def test_reparse_marker_fails(self):
        path = self.put("a.txt")
        real = Path.lstat
        def marked(candidate):
            result = real(candidate)
            if candidate == path:
                class Fake:
                    st_mode = result.st_mode
                    st_file_attributes = 0x400
                return Fake()
            return result
        with patch.object(Path, "lstat", marked), self.assertRaisesRegex(ValueError, "reparse"):
            bundle.no_links(path)

    def test_real_symlink_rejected_when_available(self):
        target = self.put("actual.txt")
        try:
            (self.root / "link.txt").symlink_to(target)
        except OSError:
            self.skipTest("Symbolic link creation not permitted")
        with self.assertRaisesRegex(ValueError, "links"):
            bundle.stream_file(self.root / "link.txt")

    def test_source_zip_roundtrip_streamed_and_sidecar(self):
        payload = self.source()
        output = self.root / "source.zip"
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole read")):
            result = bundle.write_archive(output, payload, "source")
            self.assertEqual(bundle.verify_archive(output)["status"], "VERIFIED_ARCHIVE")
        self.assertEqual(result["file_count"], len(payload))
        self.assertEqual(Path(str(output) + ".sha256").read_text().split()[0], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_no_overwrite_or_overwrite_of_sidecar(self):
        output = self.put("source.zip", b"preserve")
        with self.assertRaises(FileExistsError):
            bundle.write_archive(output, {"a.txt": b"a"}, "source")
        self.assertEqual(output.read_bytes(), b"preserve")
        self.put("second.zip.sha256", b"preserve")
        with self.assertRaises(FileExistsError):
            bundle.write_archive(self.root / "second.zip", {"a.txt": b"a"}, "source")

    def test_total_size_is_bounded_before_archive_creation(self):
        output = self.root / "oversized.zip"
        with patch.object(bundle, "MAX_SOURCE", 2), self.assertRaisesRegex(ValueError, "total size"):
            bundle.write_archive(output, {"a.txt": b"abc"}, "source")
        self.assertFalse(output.exists())

    def make_zip(self, names):
        output = self.root / "bad.zip"
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in names:
                archive.writestr(name, content)
        return output

    def test_zip_rejects_collision_symlink_and_traversal(self):
        for name in ("oran-workstation-lab/../escape", "oran-workstation-lab/CON"):
            output = self.make_zip([(name, "x")])
            with self.assertRaises(ValueError):
                bundle.verify_archive(output)
        output = self.make_zip([("oran-workstation-lab/a", "a"), ("oran-workstation-lab/A", "b")])
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            bundle.verify_archive(output)
        item = zipfile.ZipInfo("oran-workstation-lab/link")
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        output = self.make_zip([(item, "target")])
        with self.assertRaisesRegex(ValueError, "non-regular"):
            bundle.verify_archive(output)

    def test_zip_tampering_detected(self):
        records = {"a.txt": bundle.record_for(b"expected")}
        output = self.make_zip([("oran-workstation-lab/a.txt", "tampered"),
                                ("oran-workstation-lab/" + bundle.MANIFEST,
                                 bundle.encoded(bundle.manifest_for(records, "source")))])
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            bundle.verify_archive(output)

    def test_added_and_changed_protected_source_detected(self):
        self.source()
        self.put("src/extra.py", b"value = 2\n")
        with self.assertRaisesRegex(ValueError, "membership differs"):
            bundle.verify_tree(self.root)
        (self.root / "src/extra.py").unlink()
        self.put("src/example.py", b"value = 3\n")
        with self.assertRaisesRegex(ValueError, "Source differs"):
            bundle.verify_tree(self.root)

    def test_unexpected_file_in_source_tree_is_not_ignored(self):
        self.source()
        self.put("src/.env", b"private")
        with self.assertRaisesRegex(ValueError, "protected-source"):
            bundle.source_payload(self.root)

    def test_legitimate_docs_json_is_included_and_verified(self):
        self.source()
        path = self.put("docs/evaluation_v0.2/baseline_spec.json", b'{"inputs":[]}\n')
        self.assertEqual(bundle.source_payload(self.root)["docs/evaluation_v0.2/baseline_spec.json"], path)

    def test_malformed_receipts_retained_but_not_validated(self):
        self.source()
        for index, raw in enumerate((b'{"status":', b'{"status":"A","status":"B"}',
                                     b'{"status":NaN}', b'\xff')):
            base = self.session("partial_" + str(index), None)
            self.put(base + "/summary.json", raw)
        payload = bundle.return_payload(self.root)
        index = json.loads(payload["RESULTS_INDEX.json"])
        self.assertEqual(len(index["attempts"]), 4)
        for attempt in index["attempts"]:
            observed = attempt["observed_statuses"][0]["observed"]
            self.assertEqual(observed["classification"], "UNPARSEABLE_RECEIPT_RETAINED")
            self.assertFalse(observed["validated"])
        bundle.write_archive(self.root / "partials.zip", payload, "results")

    def test_receipt_safety_failures_not_swallowed_as_parse_errors(self):
        path = self.put("summary.json", b"-----BEGIN " + b"PRIVATE KEY-----")
        with self.assertRaisesRegex(ValueError, "credential"):
            bundle.observed_status(path)
        with self.assertRaises(FileNotFoundError):
            bundle.observed_status(self.root / "missing.json")
        with patch.object(bundle, "stream_file", side_effect=ValueError("Artifact changed while reading")):
            with self.assertRaisesRegex(ValueError, "changed"):
                bundle.observed_status(path)

    def test_uppercase_completion_receipts_are_observed_not_inferred(self):
        self.source()
        complete = self.session("reported_complete", None)
        partial = self.session("truncated_incomplete", None)
        self.put(complete + "/COMPLETE.json", b'{"status":"COMPLETE"}')
        self.put(partial + "/INCOMPLETE.json", b'{"status":')
        payload = bundle.return_payload(self.root)
        index = json.loads(payload["RESULTS_INDEX.json"])
        attempts = {item["path"]: item for item in index["attempts"]}
        self.assertEqual(attempts[complete]["observed_statuses"], [
            {"path": "COMPLETE.json", "observed": {"status": "COMPLETE"}}])
        self.assertEqual(attempts[complete]["classification"], "STATUS_LABELS_ONLY_NOT_VALIDATED")
        self.assertEqual(attempts[partial]["observed_statuses"], [
            {"path": "INCOMPLETE.json", "observed": {
                "classification": "UNPARSEABLE_RECEIPT_RETAINED", "validated": False}}])
        self.assertNotIn("status", index)
        bundle.write_archive(self.root / "observed-statuses.zip", payload, "results")

    def test_full_campaign_sessions_and_orphan_partitions_retained(self):
        self.source()
        self.put("results/local/full_campaign_runs/attempt/INCOMPLETE.json", b'{"status":"INCOMPLETE"}')
        self.put("results/evaluation_v0.2/full_unreferenced_failure/stdout.log", b"failed before receipt")
        self.put("data/raw/Lower_Layer_Data.db", b"private raw data not returned")
        payload = bundle.return_payload(self.root)
        index = json.loads(payload["RESULTS_INDEX.json"])
        self.assertEqual({item["path"] for item in index["attempts"]}, {
            "results/local/full_campaign_runs/attempt", "results/evaluation_v0.2/full_unreferenced_failure"})
        self.assertNotIn("source_snapshot/data/raw/Lower_Layer_Data.db", payload)
        self.assertGreaterEqual(bundle.MAX_FILE, 1067137148)

    def test_no_results_cannot_export(self):
        self.source()
        with self.assertRaisesRegex(ValueError, "nothing has been run"):
            bundle.return_payload(self.root)

    def test_return_all_partial_runs_source_changes_and_replay_binding(self):
        self.source()
        self.session("failed")
        self.session("interrupted", None)
        self.put("results/local/stage6_runs/pilot/summary.json", b'{"status":"PILOT_ONLY"}')
        self.put("results/evaluation_v0.2/s7_orphan/stdout.log", b"partial")
        self.put("results/evaluation_v0.2/stage0_new/manifest.json", b"{}")
        self.put("results/evaluation_v0.2/old_university/private.json", b"not shipped")
        self.put("src/example.py", b"value = 2\n")
        payload = bundle.return_payload(self.root)
        index = json.loads(payload["RESULTS_INDEX.json"])
        self.assertEqual(len(index["attempts"]), 5)
        self.assertEqual(json.loads(payload["SOURCE_CHANGES.json"])["modified"], ["src/example.py"])
        self.assertNotIn("source_snapshot/data/workstation_reproduction/frozen.jsonl", payload)
        self.assertIn("data/workstation_reproduction/frozen.jsonl", index["replay_input_binding"])
        self.assertIn("source_snapshot/reference/university/report.md", payload)
        self.assertFalse(any("old_university" in name for name in payload))
        result = bundle.write_archive(self.root / "return.zip", payload, "results")
        self.assertEqual(result["kind"], "results")
        self.assertEqual(bundle.verify_archive(self.root / "return.zip")["kind"], "results")

    def test_index_binding_detects_mutation_between_inventory_and_copy(self):
        self.source()
        base = self.session()
        payload = bundle.return_payload(self.root)
        self.put(base + "/raw.jsonl", b'{"changed":1}\n')
        with self.assertRaisesRegex(ValueError, "Result index differs"):
            bundle.write_archive(self.root / "changed.zip", payload, "results")
        self.assertFalse((self.root / "changed.zip.sha256").exists())

    def test_active_lock_or_secret_result_blocks_export(self):
        self.source()
        base = self.session()
        self.put("results/local/workstation_runs/.active-run.lock", b"running")
        with self.assertRaisesRegex(ValueError, "active lock"):
            bundle.return_payload(self.root)
        (self.root / "results/local/workstation_runs/.active-run.lock").unlink()
        self.put(base + "/stderr.log", b"-----BEGIN " + b"PRIVATE KEY-----")
        with self.assertRaisesRegex(ValueError, "credential"):
            bundle.return_payload(self.root)

    def test_imported_legacy_results_retained_not_claimed_verified(self):
        self.source()
        output = self.root / "results/local/stage6_returns/legacy.zip"
        output.parent.mkdir(parents=True)
        record = bundle.record_for(b"measured")
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("oran-home-results/run.txt", b"measured")
            archive.writestr("oran-home-results/BUNDLE_MANIFEST.json", bundle.encoded({
                "format": "home-lab-handoff-1", "kind": "results", "files": {"run.txt": record}}))
        payload = bundle.return_payload(self.root)
        index = json.loads(payload["RESULTS_INDEX.json"])
        self.assertEqual(index["imported_stage6_artifacts"][0]["classification"], "IMPORTED_ARTIFACT_NOT_SCIENTIFICALLY_VALIDATED")
        self.assertEqual(index["attempts"], [])
        self.assertTrue(index["imported_stage6_artifacts"][0]["legacy_zip_integrity_verified"])

    def test_invalid_imported_zip_is_not_exported(self):
        self.source()
        self.put("results/local/stage6_returns/invalid.zip", b"not a ZIP")
        with self.assertRaises(zipfile.BadZipFile):
            bundle.return_payload(self.root)

    def test_legacy_zip_streamed_integrity_and_secret_check(self):
        content = b"-----BEGIN " + b"PRIVATE KEY-----"
        output = self.make_zip([("oran-home-results/run.txt", content),
                                ("oran-home-results/BUNDLE_MANIFEST.json", bundle.encoded({
                                    "format": "home-lab-handoff-1", "kind": "results", "files": {
                                        "run.txt": {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}}}))])
        with self.assertRaisesRegex(ValueError, "credential"):
            bundle.verify_archive(output, legacy=True)

    def test_return_requires_explicit_privacy_review(self):
        with self.assertRaises(SystemExit), patch.object(bundle, "return_payload") as export:
            bundle.main(["return", "--root", str(self.root), "--output", str(self.root / "return.zip")])
        export.assert_not_called()


if __name__ == "__main__":
    unittest.main()
