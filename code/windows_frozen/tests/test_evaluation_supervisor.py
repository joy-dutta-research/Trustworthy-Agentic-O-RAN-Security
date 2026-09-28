"""Offline supervisor checks; no scientific workloads or network activity."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import supervise_evaluation_v02 as supervisor


class SupervisorTests(unittest.TestCase):
    def test_unapproved_runner_and_custom_output_refused(self):
        with self.assertRaises(ValueError):
            supervisor.validate_arguments(ROOT, "scripts/download_5gnidd.py", [])
        with tempfile.TemporaryDirectory(prefix="oran-supervisor-test-") as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            (root / "scripts/run_validity_v02.py").write_text("pass\n")
            for args in (["--output", "bad"], ["--output=bad"]):
                with self.assertRaises(ValueError):
                    supervisor.validate_arguments(root, "scripts/run_validity_v02.py", args)
            supervisor.validate_arguments(root, "scripts/run_validity_v02.py", ["fixed"])

    def test_snapshot_ignores_bytecode_and_detects_source_changes(self):
        with tempfile.TemporaryDirectory(prefix="oran-supervisor-test-") as temp:
            root = Path(temp)
            for name in supervisor.SOURCE_ROOTS:
                (root / name).mkdir(parents=True, exist_ok=True)
            source = root / "src/example.py"
            source.write_text("pass\n")
            first = supervisor.source_snapshot(root)
            (root / "src/__pycache__").mkdir()
            (root / "src/__pycache__/example.pyc").write_bytes(b"cache")
            self.assertEqual(first, supervisor.source_snapshot(root))
            source.write_text("changed = True\n")
            self.assertNotEqual(first, supervisor.source_snapshot(root))

    def test_exclusive_receipt_and_byte_count(self):
        with tempfile.TemporaryDirectory(prefix="oran-supervisor-test-") as temp:
            root = Path(temp)
            path = root / "receipt.json"
            supervisor.write_new(path, {"ok": True})
            self.assertEqual(supervisor.tree_bytes(root), path.stat().st_size)
            with self.assertRaises(FileExistsError):
                supervisor.write_new(path, {})

    def test_tree_byte_guard_uses_shared_strict_scanner(self):
        with patch.object(supervisor, "dynamic_tree_bytes", return_value=123) as shared:
            self.assertEqual(supervisor.tree_bytes(ROOT), 123)
        shared.assert_called_once_with(ROOT, check_chain=supervisor.freeze._check_chain)

    @unittest.skipUnless(os.name == "nt", "Windows containment qualification")
    def test_owned_job_gates_and_observes_only_own_child(self):
        job = supervisor.WindowsJob(256 * 1024 * 1024)
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-c", "import sys,time;sys.stdin.buffer.readline();print('ready',flush=True);time.sleep(0.5)"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            job.attach(process)
            self.assertEqual(job.usage()["active_processes"], 1)
            out, err = process.communicate(b"RUN\n", timeout=10)
            self.assertEqual(process.returncode, 0, err)
            self.assertEqual(out.strip(), b"ready")
            self.assertGreater(job.usage()["peak_job_committed_bytes"], 0)
        finally:
            job.terminate()
            job.close()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
