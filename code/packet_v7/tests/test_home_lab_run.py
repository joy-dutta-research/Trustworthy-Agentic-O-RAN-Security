"""Unprivileged portable-wrapper contract tests; never packet-run evidence."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("home_lab_run", ROOT / "scripts/home_lab_run.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

READY = {"ready": True, "tools": {"ip": "/usr/sbin/ip", "tc": "/usr/sbin/tc", "sysctl": "/usr/sbin/sysctl"}}


def qualification_fixture(root, directory):
    """Synthetic unit-test fixture only; never stored as real run evidence."""
    environment = {key: "test-only" for key in ("os_id", "os_version", "kernel", "machine", "python", "logical_cpu_count", "tools")}
    environment["memory"] = {"MemTotal_KiB": 1}
    MODULE.write_json(root / "BUNDLE_MANIFEST.json", {"test_only": True})
    bundle_hash = MODULE.sha256_file(root / "BUNDLE_MANIFEST.json")
    directory.mkdir()
    isolation = {"verified": True, "interfaces": ["lo"], "only_loopback_addresses": True,
                 "only_loopback_routes": True, "existing_namespace_count": 0}
    for name in ("isolation_before", "isolation_after_tests", "isolation_after"):
        MODULE.write_json(directory / (name + ".json"), isolation)
    for name in ("environment_before", "environment_after"):
        MODULE.write_json(directory / (name + ".json"), environment)
    for name in ("unit_tests", "bundle_verification_before", "bundle_verification_after"):
        MODULE.write_json(directory / (name + ".receipt.json"),
                          {"returncode": 0, "timed_out": False, "interrupted": False, "forced_kill": False})
        MODULE.write_json(directory / (name + ".stdout.txt"),
                          {"status": "VERIFIED_SOURCE_TREE", "manifest_sha256": bundle_hash})
        (directory / (name + ".stderr.txt")).touch()
    namespaces = {role: "orcl-unit-test-" + role for role in ("legitimate", "suspect", "router", "server")}
    audit = {"namespaces": namespaces, "cleanup_errors": [],
             "commands": [{"argv": ["ip", "netns", operation, namespace], "returncode": 0}
                          for namespace in namespaces.values() for operation in ("add", "del")],
             "topology_snapshot": {role: {"verified": True} for role in namespaces}}
    packet_dir = directory / "qualification_packets"
    for name in ("qualification_packets", "intentional_exception_cleanup"):
        (directory / name).mkdir()
        MODULE.write_json(directory / name / "kernel_commands.json", audit)
    clients = {}
    for role, rate in (("legitimate", 20), ("suspect", 200)):
        cohorts = []
        for index in range(12):
            received = 80 if role == "suspect" and 4 <= index < 8 else rate
            cohorts.append({"window_start": index, "window_end": index + 1, "sent": rate,
                            "received": received, "rtt_ms": [10] * received})
        clients[role] = [{"type": "cohort_summary", "sent": 12 * rate,
                          "received": sum(row["received"] for row in cohorts), "cohorts": cohorts, "counters": {}}]
    server = [{"type": "server_summary", "invalid": 0, "sources": {
        role: {"received": rows[0]["received"], "received_bytes": rows[0]["received"] * 512,
               "echoed": rows[0]["received"], "echo_errors": 0} for role, rows in clients.items()}}]
    for role, rows in {**clients, "server": server}.items():
        with (packet_dir / (role + ".jsonl")).open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row) + "\n")
        (packet_dir / (role + ".stderr.log")).touch()
    transitions = {"applied_at_seconds": 4.1, "restored_at_seconds": 8.1,
                   "worker_returncodes": [0, 0, 0], "apply_readback": {"configuration_verified": True},
                   "restore_readback": {"configuration_verified": True, "changed": True},
                   "netem_configuration_readback": [{"kind": "netem"}]}
    MODULE.write_json(directory / "qualification_transitions.json", transitions)
    metrics = MODULE.assess_qualification(clients, server, transitions)
    metrics.update(normal_cleanup=isolation, exception_cleanup=isolation)
    MODULE.write_json(directory / "qualification_metrics.json", metrics)
    receipt = {"mode": "qualify", "status": "QUALIFICATION_PASSED", "source_files": {},
               "environment_identity": MODULE.environment_identity(environment),
               "received_bundle_manifest_sha256": bundle_hash, "artifacts": MODULE.file_hashes(directory)}
    MODULE.write_json(directory / "session_receipt.json", receipt)
    return receipt, environment


def replace_fixture_json(directory, name, transform):
    """Mutate synthetic data and recompute hashes, testing semantics not hashes."""
    path = directory / name
    value = json.loads(path.read_text())
    transform(value)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    receipt_path = directory / "session_receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["artifacts"] = MODULE.file_hashes(directory)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")


class Inventory:
    def __init__(self):
        self.commands = []
        self.links = [{"ifname": "lo"}]
        self.addresses = [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                                                          {"family": "inet6", "local": "::1", "prefixlen": 128}]}]
        self.routes4 = [{"dst": "127.0.0.0/8", "dev": "lo", "type": "local"}]
        self.routes6 = [{"dst": "::1", "dev": "lo", "type": "local"}]
        self.namespaces = ""
        self.container = "none"
        self.vm = "microsoft"

    def __call__(self, command):
        self.commands.append(command)
        code = 0
        if command[-1] == "--container":
            output = self.container + "\n"
            code = 1 if self.container == "none" else 0
        elif command[-1] == "--vm":
            output = self.vm + "\n"
            code = 1 if self.vm == "none" else 0
        elif command[1:] == ["netns", "list"]:
            output = self.namespaces
        elif "link" in command:
            output = json.dumps(self.links)
        elif "addr" in command:
            output = json.dumps(self.addresses)
        elif "route" in command:
            output = json.dumps(self.routes4 if "-4" in command else self.routes6)
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, code, output, "")


class TestIsolation(unittest.TestCase):
    def setUp(self):
        self.inventory = Inventory()
        patches = [patch.object(MODULE, "preflight", return_value=READY),
                   patch.object(MODULE.platform, "freedesktop_os_release", return_value={"ID": "ubuntu"}),
                   patch.object(MODULE.shutil, "which", return_value="/usr/bin/systemd-detect-virt"),
                   patch.object(MODULE, "small_command", side_effect=self.inventory)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_loopback_only_ubuntu_vm_passes_without_mutations(self):
        self.assertTrue(MODULE.inspect_isolation()["verified"])
        for command in self.inventory.commands:
            self.assertFalse(set(command) & {"add", "del", "replace", "set", "exec"})

    def test_disconnected_adapter_is_also_refused(self):
        self.inventory.links.append({"ifname": "eth0", "operstate": "DOWN"})
        with self.assertRaisesRegex(RuntimeError, "every VM network adapter"):
            MODULE.inspect_isolation()

    def test_external_loopback_bound_address_is_refused(self):
        self.inventory.addresses[0]["addr_info"].append({"family": "inet", "local": "192.0.2.1", "prefixlen": 24})
        with self.assertRaisesRegex(RuntimeError, "binding"):
            MODULE.inspect_isolation()

    def test_default_external_and_multipath_routes_are_refused(self):
        for route in ({"dst": "default", "dev": "lo"}, {"dst": "192.0.2.0/24", "dev": "lo"},
                      {"dst": "127.0.0.0/8", "dev": "lo", "nexthops": []},
                      {"dst": "127.0.0.0/8", "dev": "eth0"}):
            self.inventory.routes4 = [route]
            with self.subTest(route=route), self.assertRaises(RuntimeError):
                MODULE.inspect_isolation()

    def test_container_and_wsl_are_refused(self):
        self.inventory.container = "wsl"
        with self.assertRaisesRegex(RuntimeError, "Container"):
            MODULE.inspect_isolation()
        self.inventory.container = "none"
        self.inventory.vm = "none"
        with self.assertRaisesRegex(RuntimeError, "recognized"):
            MODULE.inspect_isolation()

    def test_existing_namespaces_are_not_removed(self):
        self.inventory.namespaces = "unrelated-private-name\n"
        with self.assertRaisesRegex(RuntimeError, "Existing network namespaces") as raised:
            MODULE.inspect_isolation()
        self.assertNotIn("unrelated-private-name", str(raised.exception))
        self.assertFalse(any("del" in command for command in self.inventory.commands))

    def test_nonubuntu_is_refused(self):
        with patch.object(MODULE.platform, "freedesktop_os_release", return_value={"ID": "debian"}):
            with self.assertRaisesRegex(RuntimeError, "Ubuntu"):
                MODULE.inspect_isolation()

    def test_missing_root_or_tools_is_refused_before_inventory(self):
        with patch.object(MODULE, "preflight", return_value={"ready": False}):
            with self.assertRaises(RuntimeError):
                MODULE.inspect_isolation()
        self.assertEqual(self.inventory.commands, [])


class TestPortableWorkflow(unittest.TestCase):
    def test_missing_bundle_manifest_refuses_before_launching_verifier(self):
        with patch.object(MODULE.Path, "is_file", return_value=False), \
             patch.object(MODULE, "captured_process") as process:
            with self.assertRaisesRegex(RuntimeError, "verified portable bundle"):
                MODULE.verify_bundle(ROOT, "unused")
        process.assert_not_called()

    def test_timeout_requests_graceful_interrupt_and_preserves_logs(self):
        process = MagicMock()
        process.returncode = 130
        process.communicate.side_effect = [subprocess.TimeoutExpired(["python"], 1),
                                          ("retained stdout", "retained stderr")]
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
             patch.object(MODULE.subprocess, "Popen", return_value=process) as popen:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "failed or was interrupted"):
                MODULE.captured_process(["python", "bounded-test"], directory, "child", 1)
            process.send_signal.assert_called_once_with(MODULE.signal.SIGINT)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertFalse(popen.call_args.kwargs["shell"])
            self.assertEqual((directory / "child.stdout.txt").read_text(), "retained stdout")
            receipt = json.loads((directory / "child.receipt.json").read_text())
            self.assertTrue(receipt["timed_out"])
            self.assertFalse(receipt["forced_kill"])

    def test_timeout_forced_kill_targets_only_the_child_process_group(self):
        process = MagicMock()
        process.pid = 45678
        process.returncode = -9
        process.communicate.side_effect = [subprocess.TimeoutExpired(["python"], 1),
                                          subprocess.TimeoutExpired(["python"], 40),
                                          ("partial stdout", "partial stderr")]
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
             patch.object(MODULE.subprocess, "Popen", return_value=process), \
             patch.object(MODULE.os, "killpg", create=True) as killpg, \
             patch.object(MODULE.signal, "SIGKILL", 9, create=True):
            directory = Path(temporary)
            with self.assertRaises(RuntimeError):
                MODULE.captured_process(["python", "bounded-test"], directory, "child", 1)
            killpg.assert_called_once_with(45678, 9)
            self.assertTrue(json.loads((directory / "child.receipt.json").read_text())["forced_kill"])

    def test_default_is_plan_only(self):
        with patch.object(MODULE, "run_session") as run, patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(MODULE.main([]), 0)
        run.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "PLAN_ONLY_NO_WRITES_NO_PACKETS")

    def test_missing_explicit_ack_is_refused(self):
        with patch.object(MODULE, "run_session") as run, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                MODULE.main(["--qualify"])
        run.assert_not_called()

    def test_windows_is_refused_without_session_creation(self):
        with patch.object(MODULE.platform, "system", return_value="Windows"), \
             patch.object(MODULE, "run_session") as run, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                MODULE.main(["--qualify", "--acknowledge-isolated-vm"])
        run.assert_not_called()

    def test_parent_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Parent traversal"):
            MODULE.checked_path(ROOT / "results" / ".." / "other")

    def test_hashes_include_nested_receipts(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory = Path(temporary)
            child = directory / "qualification_evidence"
            child.mkdir()
            MODULE.write_json(directory / "session_receipt.json", {"outer": True})
            MODULE.write_json(child / "session_receipt.json", {"inner": True})
            self.assertEqual(set(MODULE.file_hashes(directory)), {"qualification_evidence/session_receipt.json"})

    def test_qualification_uses_measured_effect_and_recovery(self):
        metrics = [{"timely_delivery_ratio": 1, "echo_goodput_kbit_s": rate}
                   for rate in (10, 100, 10, 40, 10, 100)]
        with patch.object(MODULE, "check_offered_load", return_value={}), \
             patch.object(MODULE, "score_server", return_value={}), \
             patch.object(MODULE, "score_cohorts", side_effect=metrics):
            result = MODULE.assess_qualification({"legitimate": [], "suspect": []}, [],
                                                 {"applied_at_seconds": 4.1, "restored_at_seconds": 8.1})
        self.assertTrue(result["passed"])

    def test_acknowledged_but_ineffective_limiter_fails_qualification(self):
        metrics = [{"timely_delivery_ratio": 1, "echo_goodput_kbit_s": 100}] * 6
        with patch.object(MODULE, "check_offered_load", return_value={}), \
             patch.object(MODULE, "score_server", return_value={}), \
             patch.object(MODULE, "score_cohorts", side_effect=metrics):
            result = MODULE.assess_qualification({"legitimate": [], "suspect": []}, [],
                                                 {"applied_at_seconds": 4.1, "restored_at_seconds": 8.1})
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["measured_policer_effect"])

    def test_failed_guard_preserves_receipt_without_tests_or_packets(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, patch.object(MODULE, "BASE", Path(temporary) / "runs"), \
             patch.object(MODULE, "inspect_isolation", side_effect=RuntimeError("unsafe environment")), \
             patch.object(MODULE, "tests_first") as tests, patch.object(MODULE, "qualify") as qualify, \
             patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                MODULE.run_session("qualify", None, 3, 1)
            directories = list(MODULE.BASE.iterdir())
            self.assertEqual(len(directories), 1)
            receipt = json.loads((directories[0] / "session_receipt.json").read_text())
            self.assertEqual(receipt["status"], "INCOMPLETE_NOT_PUBLISHABLE")
            self.assertEqual(receipt["classification"], "PILOT_NOT_CONFIRMATORY")
        tests.assert_not_called()
        qualify.assert_not_called()

    def test_wrong_status_or_changed_artifacts_cannot_authorize_pilot(self):
        environment = {key: "example" for key in ("os_id", "os_version", "kernel", "machine", "python", "logical_cpu_count", "tools")}
        environment["memory"] = {"MemTotal_KiB": 1}
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, patch.object(MODULE, "BASE", Path(temporary)):
            directory = Path(temporary) / "qualifier"
            directory.mkdir()
            receipt = {"mode": "qualify", "status": "QUALIFICATION_PASSED", "source_files": {},
                       "environment_identity": MODULE.environment_identity(environment), "artifacts": {}}
            MODULE.write_json(directory / "session_receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "mandatory measured evidence"):
                MODULE.validate_qualification(directory, {}, environment)
            MODULE.write_json(directory / "unexpected.json", {"changed": True})
            with self.assertRaisesRegex(ValueError, "integrity"):
                MODULE.validate_qualification(directory, {}, environment)
            with self.assertRaisesRegex(ValueError, "Source or environment"):
                MODULE.validate_qualification(directory, {"changed.py": "hash"}, environment)

    def test_complete_synthetic_qualification_evidence_passes_recomputation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
             patch.object(MODULE, "ROOT", Path(temporary)), patch.object(MODULE, "BASE", Path(temporary) / "runs"):
            MODULE.BASE.mkdir()
            directory = MODULE.BASE / "qualifier"
            receipt, environment = qualification_fixture(MODULE.ROOT, directory)
            self.assertEqual(MODULE.validate_qualification(directory, {}, environment), receipt)

    def test_semantically_failed_or_inconsistent_evidence_is_rejected_even_with_updated_hashes(self):
        mutations = [
            ("qualification_metrics.json", lambda value: value.update(passed=False)),
            ("qualification_metrics.json", lambda value: value["checks"].update(measured_policer_effect=False)),
            ("qualification_metrics.json", lambda value: value["checks"].update(measured_policer_effect=1)),
            ("qualification_metrics.json", lambda value: value["phase_metrics"]["baseline"]["suspect"].update(sent=999)),
            ("qualification_metrics.json", lambda value: value["normal_cleanup"].update(verified=False)),
            ("qualification_metrics.json", lambda value: value["exception_cleanup"].update(verified=False)),
            ("isolation_after.json", lambda value: value.update(verified=False)),
            ("unit_tests.receipt.json", lambda value: value.update(returncode=1)),
            ("bundle_verification_before.receipt.json", lambda value: value.update(timed_out=True)),
            ("bundle_verification_after.stdout.txt", lambda value: value.update(manifest_sha256="wrong")),
            ("qualification_packets/kernel_commands.json", lambda value: value.update(cleanup_errors=["failure"])),
            ("intentional_exception_cleanup/kernel_commands.json", lambda value: value.update(commands=[])),
            ("qualification_transitions.json", lambda value: value["restore_readback"].update(changed=False)),
            ("qualification_packets/legitimate.jsonl", lambda value: value["cohorts"][1]["rtt_ms"].__setitem__(0, 600)),
        ]
        for name, transform in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
                 patch.object(MODULE, "ROOT", Path(temporary)), patch.object(MODULE, "BASE", Path(temporary) / "runs"):
                MODULE.BASE.mkdir()
                directory = MODULE.BASE / "qualifier"
                _, environment = qualification_fixture(MODULE.ROOT, directory)
                replace_fixture_json(directory, name, transform)
                with self.assertRaises(ValueError):
                    MODULE.validate_qualification(directory, {}, environment)

    def test_missing_raw_log_cannot_be_replaced_by_a_success_receipt(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
             patch.object(MODULE, "ROOT", Path(temporary)), patch.object(MODULE, "BASE", Path(temporary) / "runs"):
            MODULE.BASE.mkdir()
            directory = MODULE.BASE / "qualifier"
            _, environment = qualification_fixture(MODULE.ROOT, directory)
            (directory / "qualification_packets/server.jsonl").unlink()
            replace_fixture_json(directory, "qualification_metrics.json", lambda value: None)
            with self.assertRaisesRegex(ValueError, "mandatory measured evidence"):
                MODULE.validate_qualification(directory, {}, environment)

    def test_different_bundle_cannot_reuse_qualification(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, \
             patch.object(MODULE, "ROOT", Path(temporary)), patch.object(MODULE, "BASE", Path(temporary) / "runs"):
            MODULE.BASE.mkdir()
            directory = MODULE.BASE / "qualifier"
            _, environment = qualification_fixture(MODULE.ROOT, directory)
            (MODULE.ROOT / "BUNDLE_MANIFEST.json").write_text('{"different":true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different portable bundle"):
                MODULE.validate_qualification(directory, {}, environment)


if __name__ == "__main__":
    unittest.main()
