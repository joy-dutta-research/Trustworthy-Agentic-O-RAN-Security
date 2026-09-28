"""Opt-in, isolated Linux packet laboratory. No networking occurs on import.

This is a software IP-network experiment, not an E2/RAN implementation. It
requires an administrator-approved disposable Linux environment. All links and
routes live inside four newly created namespaces; no host link, route, firewall,
bridge, NAT or forwarding configuration is changed. Privileged integration
must be validated on Linux separately from the mocked unit tests.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any


MAX_DURATION_SECONDS = 60.0
MAX_PPS = 1000.0
DRAIN_SECONDS = 2.0
SERVER_IP = "10.203.3.2"
PORT = 19091


def preflight() -> dict[str, Any]:
    """Read-only availability check; never installs or enables anything."""
    system = platform.system()
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    tool_paths = {name: shutil.which(name) for name in ("ip", "tc", "sysctl")}
    reasons = []
    if system != "Linux":
        reasons.append("Linux network namespaces are required.")
    if not is_root:
        reasons.append("Explicit root execution in the approved lab is required.")
    for name, path in tool_paths.items():
        if path is None:
            reasons.append(f"Required executable is missing: {name}")
    return {"ready": not reasons, "system": system, "is_root": is_root,
            "tools": tool_paths, "reasons": reasons}


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return float(value)


def validate_schedule(schedule: Any, duration: float) -> list[dict[str, float]]:
    """Require bounded non-overlapping intervals; gaps mean no offered load."""
    if not isinstance(schedule, list) or not 1 <= len(schedule) <= 20:
        raise ValueError("schedule must contain 1..20 intervals")
    clean = []
    previous_end = 0.0
    for item in schedule:
        if not isinstance(item, dict) or set(item) != {"start", "end", "pps"}:
            raise ValueError("schedule entries require exactly start, end, pps")
        start = _number(item["start"], "start", 0, duration)
        end = _number(item["end"], "end", 0, duration)
        pps = _number(item["pps"], "pps", 0, MAX_PPS)
        if start < previous_end or end <= start:
            raise ValueError("schedule intervals must be ordered and non-overlapping")
        clean.append({"start": start, "end": end, "pps": pps})
        previous_end = end
    return clean


class LinuxLab:
    """One bounded episode, with explicit ownership and best-effort cleanup.

    start_traffic returns monotonic started_at, finish_deadline and log paths.
    finish waits for all workers, verifies successful exits and returns paths.
    Client type=window records are send cohorts with a 500 ms response deadline,
    emitted after that deadline matures. Final type=cohort_summary also includes
    later replies and losses, attributed to the original send windows.
    seed is recorded as an episode identifier; pacing is fixed, not randomized.
    """

    def __init__(self, output_dir: Path, capacity_kbit: int = 1000,
                 packet_bytes: int = 512) -> None:
        if type(capacity_kbit) is not int or not 100 <= capacity_kbit <= 10000:
            raise ValueError("capacity_kbit must be an integer in 100..10000")
        if type(packet_bytes) is not int or not 64 <= packet_bytes <= 1200:
            raise ValueError("packet_bytes must be an integer in 64..1200")
        self.output_dir = Path(output_dir).resolve()
        self.capacity_kbit = capacity_kbit
        self.packet_bytes = packet_bytes
        self.prefix = "orcl-" + uuid.uuid4().hex[:12]
        self.namespaces = {role: f"{self.prefix}-{role}" for role in
                           ("legitimate", "suspect", "router", "server")}
        self._owned: list[str] = []
        self._workers: list[subprocess.Popen] = []
        self._handles: list[Any] = []
        self._tools: dict[str, str] = {}
        self._active = False
        self._entered = False
        self._created_any = False
        self._audit_attempted = False
        self._traffic: dict[str, Any] | None = None
        self.command_log: list[dict[str, Any]] = []
        self.cleanup_errors: list[str] = []
        self.topology_snapshot: dict[str, Any] = {}

    def _run(self, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(argv, capture_output=True, text=True, check=False,
                                    timeout=10, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.command_log.append({"argv": argv, "returncode": None,
                                     "exception_type": type(exc).__name__})
            raise
        self.command_log.append({"argv": argv, "returncode": result.returncode,
                                 "stdout": result.stdout, "stderr": result.stderr})
        if check and result.returncode:
            raise RuntimeError(f"Lab command failed ({result.returncode}): {argv!r}; "
                               f"{result.stderr.strip()}")
        return result

    def _ip(self, role: str, *args: str) -> subprocess.CompletedProcess:
        return self._run([self._tools["ip"], "-n", self.namespaces[role], *args])

    def _tc(self, *args: str) -> subprocess.CompletedProcess:
        return self._run([self._tools["ip"], "netns", "exec", self.namespaces["router"],
                          self._tools["tc"], *args])

    def _require_active(self) -> None:
        if not self._active:
            raise RuntimeError("Lab context is not active")

    def __enter__(self) -> "LinuxLab":
        if self._entered:
            raise RuntimeError("Lab contexts cannot be entered twice")
        self._entered = True
        state = preflight()
        if not state["ready"]:
            raise RuntimeError(" ".join(state["reasons"]))
        self._tools = state["tools"]
        existing = self._run([self._tools["ip"], "netns", "list"]).stdout
        existing_names = {line.split()[0] for line in existing.splitlines() if line.strip()}
        if existing_names.intersection(self.namespaces.values()):
            raise RuntimeError("Namespace collision: refusing to reuse or remove existing objects")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            for namespace in self.namespaces.values():
                self._run([self._tools["ip"], "netns", "add", namespace])
                self._owned.append(namespace)
                self._created_any = True
            # Both ends are born inside owned namespaces, never in the host.
            for role, local_dev, router_dev, subnet in (
                ("legitimate", "client0", "legit0", 1),
                ("suspect", "client0", "suspect0", 2),
            ):
                self._ip(role, "link", "add", local_dev, "type", "veth", "peer", "name",
                         router_dev, "netns", self.namespaces["router"])
                self._ip(role, "addr", "add", f"10.203.{subnet}.2/30", "dev", local_dev)
                self._ip("router", "addr", "add", f"10.203.{subnet}.1/30", "dev", router_dev)
                self._ip(role, "link", "set", local_dev, "up")
                self._ip("router", "link", "set", router_dev, "up")
                self._ip(role, "route", "add", "10.203.3.0/30", "via", f"10.203.{subnet}.1")
            self._ip("router", "link", "add", "server0", "type", "veth", "peer", "name",
                     "server0", "netns", self.namespaces["server"])
            self._ip("router", "addr", "add", "10.203.3.1/30", "dev", "server0")
            self._ip("server", "addr", "add", "10.203.3.2/30", "dev", "server0")
            for role in self.namespaces:
                self._ip(role, "link", "set", "lo", "up")
            for role in ("router", "server"):
                self._ip(role, "link", "set", "server0", "up")
            for subnet in (1, 2):
                self._ip("server", "route", "add", f"10.203.{subnet}.0/30", "via", "10.203.3.1")
            self._run([self._tools["ip"], "netns", "exec", self.namespaces["router"],
                       self._tools["sysctl"], "-w", "net.ipv4.ip_forward=1"])
            self._tc("qdisc", "add", "dev", "server0", "root", "netem", "rate",
                     f"{self.capacity_kbit}kbit", "delay", "5ms", "limit", "30")
            self._active = True
            return self
        except BaseException as exc:
            self._cleanup()
            if self.cleanup_errors and hasattr(exc, "add_note"):
                exc.add_note("; ".join(self.cleanup_errors))
            raise

    def verify_isolation(self) -> dict[str, Any]:
        """Verify the exact fixed IPv4 topology before permitting any traffic.

        This is a point-in-time check, not protection against a concurrent root
        adversary. IPv6 link-local configuration is unused by the IPv4 workers;
        no additional network interface or IPv4 binding/route is accepted.
        """
        self._require_active()
        bindings = {
            "legitimate": {"lo": ("127.0.0.1", 8), "client0": ("10.203.1.2", 30)},
            "suspect": {"lo": ("127.0.0.1", 8), "client0": ("10.203.2.2", 30)},
            "router": {"lo": ("127.0.0.1", 8), "legit0": ("10.203.1.1", 30),
                       "suspect0": ("10.203.2.1", 30), "server0": ("10.203.3.1", 30)},
            "server": {"lo": ("127.0.0.1", 8), "server0": ("10.203.3.2", 30)},
        }
        routes = {
            "legitimate": {("10.203.1.0/30", "client0", None),
                           ("10.203.3.0/30", "client0", "10.203.1.1")},
            "suspect": {("10.203.2.0/30", "client0", None),
                        ("10.203.3.0/30", "client0", "10.203.2.1")},
            "router": {("10.203.1.0/30", "legit0", None),
                       ("10.203.2.0/30", "suspect0", None),
                       ("10.203.3.0/30", "server0", None)},
            "server": {("10.203.3.0/30", "server0", None),
                       ("10.203.1.0/30", "server0", "10.203.3.1"),
                       ("10.203.2.0/30", "server0", "10.203.3.1")},
        }
        self.topology_snapshot = {}
        for role, namespace in self.namespaces.items():
            snapshot = {"namespace": namespace, "verified": False}
            self.topology_snapshot[role] = snapshot
            for key, args in (("links", ("-j", "link", "show")),
                              ("addresses", ("-4", "-j", "addr", "show")),
                              ("routes", ("-4", "-j", "route", "show"))):
                data = json.loads(self._ip(role, *args).stdout)
                if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                    raise RuntimeError(f"Invalid {key} isolation readback for {role}")
                snapshot[key] = data
            links = snapshot["links"]
            if (len(links) != len(bindings[role])
                    or {link.get("ifname") for link in links} != set(bindings[role])):
                raise RuntimeError(f"Unexpected network interface in {role}; refusing traffic")
            actual_bindings = {}
            for interface in snapshot["addresses"]:
                device = interface.get("ifname")
                if device in actual_bindings:
                    raise RuntimeError(f"Duplicate address interface in {role}")
                info = interface.get("addr_info")
                if (not isinstance(info, list) or len(info) != 1
                        or not isinstance(info[0], dict) or info[0].get("family") != "inet"):
                    raise RuntimeError(f"Unexpected IPv4 address binding in {role}")
                actual_bindings[device] = (info[0].get("local"), info[0].get("prefixlen"))
            if actual_bindings != bindings[role]:
                raise RuntimeError(f"Unexpected IPv4 address binding in {role}")
            observed_routes = snapshot["routes"]
            actual_routes = {(route.get("dst"), route.get("dev"), route.get("gateway"))
                             for route in observed_routes}
            if len(observed_routes) != len(routes[role]) or actual_routes != routes[role]:
                raise RuntimeError(f"Unexpected or default IPv4 route in {role}; refusing traffic")
            known_sources = {address[0] for address in bindings[role].values()}
            for route in observed_routes:
                if ("nexthops" in route or "encap" in route or "via" in route
                        or route.get("type", "unicast") != "unicast"
                        or ("prefsrc" in route and route["prefsrc"] not in known_sources)):
                    raise RuntimeError(f"Unexpected IPv4 routing attributes in {role}")
            snapshot["verified"] = True
        return self.topology_snapshot

    def _qdiscs(self) -> list[dict[str, Any]]:
        data = json.loads(self._tc("-j", "qdisc", "show", "dev", "suspect0").stdout)
        if not isinstance(data, list):
            raise RuntimeError("Unexpected tc qdisc JSON readback")
        return data

    def apply_limit(self, reduction_percent: int) -> dict[str, Any]:
        """Apply only the fixed suspect ingress policer; no arbitrary target API.

        Rate is derived from a declared 400 pps reference load, not observed
        traffic. One cap is permitted at a time; restore before applying another.
        UDP payload bytes define this nominal rate; kernel policer
        accounting includes packet overhead, so achieved payload rate is measured.
        """
        self._require_active()
        if type(reduction_percent) is not int or not 1 <= reduction_percent <= 80:
            raise ValueError("reduction_percent must be an integer in 1..80")
        if any(q.get("kind") == "ingress" for q in self._qdiscs()):
            raise RuntimeError("An ingress policer already exists; restore before applying another cap")
        self._tc("qdisc", "add", "dev", "suspect0", "handle", "ffff:", "ingress")
        rate = 400 * self.packet_bytes * 8 * (100 - reduction_percent) / 100 / 1000
        self._tc("filter", "replace", "dev", "suspect0", "parent", "ffff:", "protocol", "ip",
                 "pref", "1", "u32", "match", "ip", "src", "10.203.2.2/32",
                 "police", "rate", f"{rate:.3f}kbit", "burst", "8192", "drop", "flowid", ":1")
        qdiscs = self._qdiscs()
        # iproute2 6.1.0 mixes plain-text legacy filter statistics into -j -s.
        # Read configuration as JSON and preserve statistics as a separate raw
        # readback; never sanitize malformed JSON into a success result.
        filters = json.loads(self._tc("-j", "filter", "show", "dev", "suspect0",
                                     "parent", "ffff:").stdout)
        if (not any(q.get("kind") == "ingress" for q in qdiscs)
                or not isinstance(filters, list) or not filters
                or "police" not in json.dumps(filters)):
            raise RuntimeError("Ingress policer readback failed; action cannot be reported successful")
        statistics = self._tc("-s", "filter", "show", "dev", "suspect0",
                              "parent", "ffff:").stdout
        return {"target": "ue-lab-suspect", "namespace": self.namespaces["router"],
                "interface": "suspect0", "reduction_percent": reduction_percent,
                "nominal_rate_kbit": rate, "qdiscs": qdiscs, "filters": filters,
                "filter_statistics_raw": statistics,
                "filter_readback_format": "configuration_json_and_separate_text_statistics",
                "configuration_verified": True,
                "verification_scope": "ingress qdisc and policer presence; configured command retained; "
                                      "achieved rate must be measured"}

    def restore(self) -> dict[str, Any]:
        """Remove only this lab's ingress qdisc; verify its absence."""
        self._require_active()
        before = self._qdiscs()
        changed = any(q.get("kind") == "ingress" for q in before)
        if changed:
            self._tc("qdisc", "del", "dev", "suspect0", "ingress")
        after = self._qdiscs()
        if any(q.get("kind") == "ingress" for q in after):
            raise RuntimeError("Rollback readback failed: ingress qdisc remains")
        return {"target": "ue-lab-suspect", "changed": changed, "qdiscs": after,
                "configuration_verified": True}

    def _launch(self, role: str, args: list[str]) -> None:
        worker = Path(__file__).resolve().parents[2] / "scripts" / "closed_loop_worker.py"
        if not worker.is_file():
            raise RuntimeError("closed_loop_worker.py is missing; use a source checkout")
        err = (self.output_dir / f"{role}.stderr.log").open("x", encoding="utf-8")
        self._handles.append(err)
        command = [self._tools["ip"], "netns", "exec", self.namespaces[role],
                   str(Path(sys.executable).resolve()), str(worker), "--role", role,
                   "--namespace", self.namespaces[role], *args]
        self._workers.append(subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=err, shell=False))

    def start_traffic(self, *, duration_seconds: float, suspect_schedule: list[dict[str, Any]],
                      legitimate_pps: float = 150, seed: int = 0) -> dict[str, Any]:
        self._require_active()
        if self._traffic is not None:
            raise RuntimeError("Only one traffic episode per lab context is supported")
        duration = _number(duration_seconds, "duration_seconds", 1, MAX_DURATION_SECONDS)
        legitimate = _number(legitimate_pps, "legitimate_pps", 1, MAX_PPS)
        schedule = validate_schedule(suspect_schedule, duration)
        if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
            raise ValueError("seed must be an integer in 0..2**32-1")
        self.verify_isolation()
        paths = {role: str(self.output_dir / f"{role}.jsonl")
                 for role in ("legitimate", "suspect", "server")}
        ready = self.output_dir / "server.ready"
        if ready.exists() or any(Path(path).exists() for path in paths.values()):
            raise RuntimeError("Episode outputs already exist; refusing overwrite")
        # Start server first. Its total lifetime remains bounded if clients fail.
        self._launch("server", ["--duration", str(duration), "--output", paths["server"],
                                "--ready", str(ready), "--packet-bytes", str(self.packet_bytes)])
        ready_deadline = time.monotonic() + 5
        while not ready.exists():
            if self._workers[0].poll() is not None:
                raise RuntimeError("Server exited before readiness; inspect server.stderr.log")
            if time.monotonic() >= ready_deadline:
                raise RuntimeError("Server readiness timed out")
            time.sleep(0.02)
        started_at = time.monotonic() + 1.0
        for role, role_schedule in (("legitimate", [{"start": 0, "end": duration, "pps": legitimate}]),
                                    ("suspect", schedule)):
            self._launch(role, ["--duration", str(duration), "--output", paths[role],
                                "--start", str(started_at), "--schedule", json.dumps(role_schedule),
                                "--packet-bytes", str(self.packet_bytes), "--seed", str(seed)])
        self._traffic = {"started_at": started_at, "paths": paths,
                         "finish_deadline": started_at + duration + DRAIN_SECONDS + 9,
                         "duration_seconds": duration, "seed": seed,
                         "topology_snapshot": self.topology_snapshot,
                         "pacing": "fixed-rate; seed is an episode identifier only"}
        return dict(self._traffic)

    def finish(self) -> dict[str, Any]:
        self._require_active()
        if self._traffic is None:
            raise RuntimeError("Traffic has not started")
        for worker in self._workers:
            remaining = max(0.01, self._traffic["finish_deadline"] - time.monotonic())
            try:
                worker.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Worker exceeded the bounded episode deadline") from exc
        codes = [worker.returncode for worker in self._workers]
        if any(code != 0 for code in codes):
            raise RuntimeError(f"Worker failure {codes}; inspect *.stderr.log; no valid episode")
        return {**self._traffic, "returncodes": codes}

    def _cleanup(self) -> None:
        for worker in self._workers:
            try:
                if worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.cleanup_errors.append(f"Worker cleanup failed: {exc}")
        for handle in self._handles:
            try:
                handle.close()
            except OSError as exc:
                self.cleanup_errors.append(f"Worker log close failed: {exc}")
        for namespace in reversed(self._owned):
            try:
                result = self._run([self._tools["ip"], "netns", "del", namespace], check=False)
                if result.returncode:
                    self.cleanup_errors.append(f"Namespace cleanup failed: {namespace}: {result.stderr}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.cleanup_errors.append(f"Namespace cleanup failed: {namespace}: {exc}")
        self._owned.clear()
        self._active = False
        if self._created_any and not self._audit_attempted:
            self._audit_attempted = True
            try:
                with (self.output_dir / "kernel_commands.json").open("x", encoding="utf-8", newline="\n") as handle:
                    json.dump({"commands": self.command_log, "cleanup_errors": self.cleanup_errors,
                               "namespaces": self.namespaces, "topology_snapshot": self.topology_snapshot},
                              handle, indent=2, sort_keys=True, allow_nan=False)
                    handle.write("\n")
            except (OSError, ValueError, TypeError) as exc:
                self.cleanup_errors.append(f"Kernel command audit could not be saved: {type(exc).__name__}")

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._cleanup()
        if self.cleanup_errors:
            error = RuntimeError("; ".join(self.cleanup_errors))
            if exc is not None:
                if hasattr(exc, "add_note"):
                    exc.add_note(str(error))
            else:
                raise error
