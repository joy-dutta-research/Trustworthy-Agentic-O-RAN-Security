"""Unprivileged command-contract tests; not Linux packet integration evidence."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

from oran_trust_boundary.closed_loop_lab import LinuxLab, preflight, validate_schedule


READY = {"ready": True, "system": "Linux", "is_root": True,
         "tools": {"ip": "/usr/sbin/ip", "tc": "/usr/sbin/tc", "sysctl": "/usr/sbin/sysctl"},
         "reasons": []}
MODULE = "oran_trust_boundary.closed_loop_lab"


class FakeCommands:
    def __init__(self):
        self.commands = []
        self.ingress = False
        self.namespaces = ""
        self.fail_add_number = None
        self.add_count = 0
        self.readback_filter = [{"kind": "u32", "options": {"police": {"rate": 40960}}}]
        self.extra_interface = False
        self.default_route = False
        self.wrong_address = False
        self.wrong_gateway = False

    def topology(self, role, kind):
        interfaces = {
            "legitimate": {"lo": "127.0.0.1", "client0": "10.203.1.2"},
            "suspect": {"lo": "127.0.0.1", "client0": "10.203.2.2"},
            "router": {"lo": "127.0.0.1", "legit0": "10.203.1.1",
                       "suspect0": "10.203.2.1", "server0": "10.203.3.1"},
            "server": {"lo": "127.0.0.1", "server0": "10.203.3.2"},
        }[role]
        if kind == "link":
            result = [{"ifname": name} for name in interfaces]
            if self.extra_interface and role == "legitimate":
                result.append({"ifname": "eth0"})
            return result
        if kind == "addr":
            result = [{"ifname": name, "addr_info": [{"family": "inet", "local": address,
                                                      "prefixlen": 8 if name == "lo" else 30}]}
                      for name, address in interfaces.items()]
            if self.wrong_address and role == "legitimate":
                result[1]["addr_info"][0]["local"] = "192.0.2.5"
            return result
        routes = {
            "legitimate": [("10.203.1.0/30", "client0", None),
                           ("10.203.3.0/30", "client0", "10.203.1.1")],
            "suspect": [("10.203.2.0/30", "client0", None),
                        ("10.203.3.0/30", "client0", "10.203.2.1")],
            "router": [("10.203.1.0/30", "legit0", None),
                       ("10.203.2.0/30", "suspect0", None),
                       ("10.203.3.0/30", "server0", None)],
            "server": [("10.203.3.0/30", "server0", None),
                       ("10.203.1.0/30", "server0", "10.203.3.1"),
                       ("10.203.2.0/30", "server0", "10.203.3.1")],
        }[role]
        result = [{"dst": dest, "dev": dev, **({"gateway": gateway} if gateway else {})}
                  for dest, dev, gateway in routes]
        if self.default_route and role == "legitimate":
            result.append({"dst": "default", "dev": "client0", "gateway": "10.203.1.1"})
        if self.wrong_gateway and role == "legitimate":
            result[1]["gateway"] = "10.203.1.3"
        return result

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if kwargs.get("shell") is not False:
            raise AssertionError("Every invocation must explicitly avoid a shell")
        output = ""
        code = 0
        if command[1:] == ["netns", "list"]:
            output = self.namespaces
        elif command[1:3] == ["netns", "add"]:
            self.add_count += 1
            if self.add_count == self.fail_add_number:
                code = 1
        elif "qdisc" in command and "add" in command and "ingress" in command:
            self.ingress = True
        elif "qdisc" in command and "del" in command and "ingress" in command:
            self.ingress = False
        elif "-j" in command and "qdisc" in command:
            output = json.dumps([{"kind": "ingress"}] if self.ingress else [{"kind": "noqueue"}])
        elif "-j" in command and "filter" in command:
            output = json.dumps(self.readback_filter)
        elif command[1] == "-n" and "-j" in command:
            kind = next(word for word in ("link", "addr", "route") if word in command)
            output = json.dumps(self.topology(command[2].split("-")[-1], kind))
        return subprocess.CompletedProcess(command, code, output, "simulated failure" if code else "")


class TestPreflightAndBounds(unittest.TestCase):
    def test_preflight_is_read_only_and_reports_missing_tools(self):
        with patch(f"{MODULE}.platform.system", return_value="Windows"), \
             patch(f"{MODULE}.shutil.which", return_value=None), \
             patch(f"{MODULE}.subprocess.run") as run:
            state = preflight()
        self.assertFalse(state["ready"])
        self.assertTrue(any("ip" in reason for reason in state["reasons"]))
        run.assert_not_called()

    def test_unready_preflight_mutates_nothing(self):
        lab = LinuxLab(Path("uncreated-lab-test"))
        with patch(f"{MODULE}.preflight", return_value={"ready": False, "reasons": ["missing tc"]}), \
             patch(f"{MODULE}.subprocess.run") as run, patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(RuntimeError, "missing tc"):
                lab.__enter__()
        run.assert_not_called()
        mkdir.assert_not_called()

    def test_configuration_bounds(self):
        for kwargs in ({"capacity_kbit": True}, {"capacity_kbit": 99},
                       {"packet_bytes": 1201}, {"packet_bytes": 63}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                LinuxLab(Path("unused"), **kwargs)

    def test_schedule_validation(self):
        self.assertEqual(validate_schedule([{"start": 0, "end": 2, "pps": 10}], 2),
                         [{"start": 0.0, "end": 2.0, "pps": 10.0}])
        invalid = [[], [{"start": 0, "end": 1, "pps": 1001}],
                   [{"start": 0, "end": 1, "pps": float("nan")}],
                   [{"start": 0, "end": 1, "pps": True}],
                   [{"start": 0, "end": 1, "pps": 1, "target": "external"}],
                   [{"start": 0, "end": 2, "pps": 1}, {"start": 1, "end": 2, "pps": 1}],
                   [{"start": 0, "end": 3, "pps": 1}]]
        for schedule in invalid:
            with self.subTest(schedule=schedule), self.assertRaises(ValueError):
                validate_schedule(schedule, 2)


class TestLinuxLabCommands(unittest.TestCase):
    def setUp(self):
        self.fake = FakeCommands()
        self.preflight_patch = patch(f"{MODULE}.preflight", return_value=READY)
        self.command_patch = patch(f"{MODULE}.subprocess.run", side_effect=self.fake)
        self.mkdir_patch = patch.object(Path, "mkdir")
        self.audit_open = mock_open()
        self.open_patch = patch.object(Path, "open", self.audit_open)
        self.preflight_patch.start()
        self.command_patch.start()
        self.mkdir_patch.start()
        self.open_patch.start()
        self.addCleanup(self.preflight_patch.stop)
        self.addCleanup(self.command_patch.stop)
        self.addCleanup(self.mkdir_patch.stop)
        self.addCleanup(self.open_patch.stop)

    def lab(self):
        return LinuxLab(Path("uncreated-lab-test"))

    def test_topology_never_modifies_host_links_routes_or_forwarding(self):
        lab = self.lab()
        with lab:
            self.assertEqual(len(lab._owned), 4)
            calls = list(self.fake.commands)
            for command in calls:
                if any(word in command for word in ("link", "route", "addr")):
                    self.assertEqual(command[1], "-n")
                    self.assertIn(command[2], lab.namespaces.values())
                if "net.ipv4.ip_forward=1" in command:
                    self.assertEqual(command[1:4], ["netns", "exec", lab.namespaces["router"]])
                self.assertNotIn("default", command)
                self.assertNotIn("iptables", command)
                self.assertNotIn("nft", command)
                self.assertNotIn("bridge", command)
            links = [c for c in calls if "veth" in c]
            self.assertEqual(len(links), 3)
            self.assertTrue(all("netns" in command for command in links))
        removed = [c[-1] for c in self.fake.commands if c[1:3] == ["netns", "del"]]
        self.assertEqual(set(removed), set(lab.namespaces.values()))

    def test_collision_does_not_delete_preexisting_namespace(self):
        lab = self.lab()
        self.fake.namespaces = lab.namespaces["router"] + " (id: 4)\n"
        with self.assertRaisesRegex(RuntimeError, "collision"):
            lab.__enter__()
        self.assertEqual(len(self.fake.commands), 1)
        self.assertEqual(lab._owned, [])
        self.audit_open.assert_not_called()

    def test_partial_setup_deletes_only_successfully_created_namespaces(self):
        lab = self.lab()
        self.fake.fail_add_number = 3
        with self.assertRaisesRegex(RuntimeError, "command failed"):
            lab.__enter__()
        removed = [c[-1] for c in self.fake.commands if c[1:3] == ["netns", "del"]]
        self.assertEqual(removed, [lab.namespaces["suspect"], lab.namespaces["legitimate"]])

    def test_policer_is_bounded_to_suspect_namespace_interface_and_ip(self):
        with self.lab() as lab:
            result = lab.apply_limit(80)
            self.assertAlmostEqual(result["nominal_rate_kbit"], 327.68)
            self.assertEqual(result["target"], "ue-lab-suspect")
            self.assertTrue(result["configuration_verified"])
            command = next(c for c in self.fake.commands if "filter" in c and "replace" in c)
            self.assertEqual(command[1:4], ["netns", "exec", lab.namespaces["router"]])
            self.assertIn("suspect0", command)
            self.assertIn("10.203.2.2/32", command)
            self.assertNotIn("legit0", command)
            before = len(self.fake.commands)
            for value in (0, 81, True, 50.0, "80; rm -rf /"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    lab.apply_limit(value)
            self.assertEqual(len(self.fake.commands), before)

    def test_missing_filter_readback_is_not_success(self):
        self.fake.readback_filter = []
        with self.lab() as lab:
            with self.assertRaisesRegex(RuntimeError, "readback failed"):
                lab.apply_limit(80)

    def test_second_cap_requires_explicit_restore(self):
        with self.lab() as lab:
            lab.apply_limit(80)
            with self.assertRaisesRegex(RuntimeError, "restore before applying"):
                lab.apply_limit(50)
            lab.restore()
            self.assertTrue(lab.apply_limit(50)["configuration_verified"])

    def test_restore_verifies_absence_and_noop_is_allowed(self):
        with self.lab() as lab:
            self.assertFalse(lab.restore()["changed"])
            lab.apply_limit(80)
            self.assertTrue(lab.restore()["changed"])
            self.assertFalse(self.fake.ingress)

    def test_restore_failure_is_not_reported_success(self):
        with self.lab() as lab, patch.object(lab, "_qdiscs", return_value=[{"kind": "ingress"}]):
            with self.assertRaisesRegex(RuntimeError, "Rollback readback failed"):
                lab.restore()

    def test_context_is_required_for_actions(self):
        lab = self.lab()
        with self.assertRaises(RuntimeError):
            lab.apply_limit(80)
        with self.assertRaises(RuntimeError):
            lab.restore()

    def test_cleanup_terminates_only_owned_worker_handles(self):
        lab = self.lab()
        process = MagicMock()
        process.poll.return_value = None
        with lab:
            lab._workers.append(process)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=2)
        self.assertFalse(any("killall" in c or "pkill" in c for c in self.fake.commands))

    def test_invalid_traffic_does_not_launch_processes(self):
        with self.lab() as lab, patch.object(lab, "_launch") as launch:
            for duration in (0, 61, float("nan"), True):
                with self.subTest(duration=duration), self.assertRaises(ValueError):
                    lab.start_traffic(duration_seconds=duration,
                                      suspect_schedule=[{"start": 0, "end": 1, "pps": 1}])
            launch.assert_not_called()

    def test_isolation_snapshot_verifies_all_four_namespaces(self):
        with self.lab() as lab:
            snapshot = lab.verify_isolation()
            self.assertEqual(set(snapshot), set(lab.namespaces))
            self.assertTrue(all(value["verified"] for value in snapshot.values()))
            self.assertEqual(snapshot, lab.topology_snapshot)

    def test_extra_interface_blocks_traffic_before_worker_launch(self):
        self.fake.extra_interface = True
        with self.lab() as lab, patch.object(lab, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "Unexpected network interface"):
                lab.start_traffic(duration_seconds=2,
                                  suspect_schedule=[{"start": 0, "end": 2, "pps": 10}])
            launch.assert_not_called()

    def test_default_route_blocks_traffic_before_worker_launch(self):
        self.fake.default_route = True
        with self.lab() as lab, patch.object(lab, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "default IPv4 route"):
                lab.start_traffic(duration_seconds=2,
                                  suspect_schedule=[{"start": 0, "end": 2, "pps": 10}])
            launch.assert_not_called()

    def test_wrong_address_and_gateway_fail_isolation(self):
        with self.lab() as lab:
            self.fake.wrong_address = True
            with self.assertRaisesRegex(RuntimeError, "address binding"):
                lab.verify_isolation()
            self.fake.wrong_address = False
            self.fake.wrong_gateway = True
            with self.assertRaisesRegex(RuntimeError, "IPv4 route"):
                lab.verify_isolation()

    def test_start_returns_verified_snapshot(self):
        ready_checks = []

        def exists(path):
            if path.name != "server.ready":
                return False
            ready_checks.append(True)
            return len(ready_checks) > 1

        with self.lab() as lab, patch.object(Path, "exists", new=exists), \
             patch.object(lab, "_launch") as launch:
            metadata = lab.start_traffic(duration_seconds=2,
                                         suspect_schedule=[{"start": 0, "end": 2, "pps": 10}])
            self.assertEqual(launch.call_count, 3)
            self.assertTrue(all(row["verified"] for row in metadata["topology_snapshot"].values()))

    def test_cleanup_audit_includes_namespace_deletions_and_never_overwrites(self):
        with self.lab() as lab:
            lab.verify_isolation()
        self.audit_open.assert_called_once_with("x", encoding="utf-8", newline="\n")
        saved = "".join(call.args[0] for call in self.audit_open.return_value.write.call_args_list)
        audit = json.loads(saved)
        deleted = [row["argv"][-1] for row in audit["commands"]
                   if row["argv"][1:3] == ["netns", "del"]]
        self.assertEqual(set(deleted), set(lab.namespaces.values()))
        self.assertEqual(audit["cleanup_errors"], [])
        self.assertEqual(audit["topology_snapshot"], lab.topology_snapshot)
        lab._cleanup()
        self.audit_open.assert_called_once()

    def test_audit_failure_aborts_clean_teardown(self):
        self.audit_open.side_effect = FileExistsError("existing audit")
        with self.assertRaisesRegex(RuntimeError, "audit could not be saved"):
            with self.lab():
                pass

    def test_audit_failure_does_not_mask_primary_error(self):
        self.audit_open.side_effect = OSError("audit unavailable")
        with self.assertRaisesRegex(ValueError, "original failure") as caught:
            with self.lab():
                raise ValueError("original failure")
        self.assertTrue(any("audit could not be saved" in note for note in caught.exception.__notes__))

    def test_completed_context_cannot_be_reentered_without_a_new_audit(self):
        lab = self.lab()
        with lab:
            pass
        before = len(self.fake.commands)
        with self.assertRaisesRegex(RuntimeError, "entered twice"):
            lab.__enter__()
        self.assertEqual(len(self.fake.commands), before)


class TestWorkerIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).resolve().parents[1] / "scripts" / "closed_loop_worker.py"
        spec = importlib.util.spec_from_file_location("closed_loop_worker_tests", script)
        cls.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.worker)

    def test_worker_rejects_unbounded_or_wrong_names(self):
        for name in ("default", "../etc", "orcl-0123456789ab-router", "orcl-0123456789ab-suspect"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.worker.require_namespace(name, "legitimate")

    def test_worker_rejects_initial_network_namespace(self):
        stat = MagicMock(st_dev=5, st_ino=100)
        with patch.object(self.worker.os, "stat", return_value=stat):
            with self.assertRaisesRegex(RuntimeError, "initial network namespace"):
                self.worker.require_namespace("orcl-0123456789ab-legitimate", "legitimate")

    def test_worker_rejects_namespace_mismatch(self):
        states = [MagicMock(st_dev=5, st_ino=101), MagicMock(st_dev=5, st_ino=102),
                  MagicMock(st_dev=5, st_ino=100)]
        with patch.object(self.worker.os, "stat", side_effect=states):
            with self.assertRaisesRegex(RuntimeError, "not in its requested"):
                self.worker.require_namespace("orcl-0123456789ab-legitimate", "legitimate")

    def test_worker_cohorts_keep_late_replies_and_loss_in_denominators(self):
        """Fake socket/clock tests accounting only; it is not network evidence."""
        clock = SimpleNamespace(now=100.0)
        worker = self.worker

        class FakeSocket:
            def __init__(self):
                self.pending = []
                self.sent_sequences = []

            def bind(self, address):
                self.address = address

            def setblocking(self, value):
                pass

            def close(self):
                pass

            def sendto(self, data, address):
                sequence, _ = worker.HEADER.unpack_from(data)
                self.sent_sequences.append(sequence)
                # Deterministic mix: timely reply, late reply, permanent loss.
                if sequence % 3 != 2:
                    delay = 0.1 if sequence % 3 == 0 else 0.7
                    self.pending.append((clock.now + delay, data))
                    self.pending.sort(key=lambda item: item[0])
                return len(data)

            def recvfrom(self, size):
                if not self.pending or self.pending[0][0] > clock.now:
                    raise BlockingIOError()
                _, data = self.pending.pop(0)
                return data, (worker.SERVER_IP, worker.PORT)

        def fake_select(readable, writable, exceptional, timeout):
            clock.now += max(timeout, 0.000001)
            return [], [], []

        sock = FakeSocket()
        handle = io.StringIO()
        args = SimpleNamespace(schedule=json.dumps([{"start": 0, "end": 2, "pps": 10}]),
                               duration=2.0, start=100.1, role="legitimate", packet_bytes=512, seed=7)
        with patch.object(worker.time, "monotonic", side_effect=lambda: clock.now), \
             patch.object(worker.socket, "socket", return_value=sock), \
             patch.object(worker.select, "select", side_effect=fake_select):
            worker.client(args, handle)
        rows = [json.loads(line) for line in handle.getvalue().splitlines()]
        online = [row for row in rows if row["type"] == "window"]
        final = next(row for row in rows if row["type"] == "cohort_summary")
        self.assertEqual(len(online), 2)
        self.assertEqual(final["sent"], len(sock.sent_sequences))
        self.assertEqual(final["received"], sum(seq % 3 != 2 for seq in sock.sent_sequences))
        self.assertEqual(final["lost"], sum(seq % 3 == 2 for seq in sock.sent_sequences))
        timely = sum(seq % 3 == 0 for seq in sock.sent_sequences)
        self.assertEqual(sum(row["received"] for row in online), timely)
        self.assertEqual(sum(row["received_after_deadline"] for row in final["cohorts"]),
                         sum(seq % 3 == 1 for seq in sock.sent_sequences))
        for row in online:
            self.assertEqual(row["measurement_semantics"], "send_cohort_500ms")
            self.assertLessEqual(row["received"], row["sent"])
            self.assertTrue(all(rtt <= 500 for rtt in row["rtt_ms"]))
            self.assertGreaterEqual(row["emitted_at"], args.start + row["window_end"] + 0.5)
        for cohort in final["cohorts"]:
            self.assertEqual(cohort["deadline_missed"],
                             cohort["sent"] - cohort["received_within_deadline"])


if __name__ == "__main__":
    unittest.main()
