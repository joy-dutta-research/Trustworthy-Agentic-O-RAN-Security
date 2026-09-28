"""Portable, opt-in Ubuntu VM qualification and descriptive packet pilot.

Default invocation only prints a plan. Never installs packages, changes VM
networking, contacts a network service, or runs an LLM. Only a NIC-free Ubuntu
VM, with explicit root opt-in, may execute the bounded existing Linux lab.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.closed_loop_lab import preflight
from oran_trust_boundary.stable_linux_lab import StableLinuxLab as LinuxLab
from oran_trust_boundary.closed_loop_results import (check_offered_load, read_jsonl,
                                                    score_cohorts, score_server)
from oran_trust_boundary.provenance import (combined_manifest_sha256, sha256_file,
                                          source_manifest)
from oran_trust_boundary.jsonio import strict_json_load

BASE = ROOT / "results/local/handoff_runs"
CLASSIFICATION = "PILOT_NOT_CONFIRMATORY"
QUALIFICATION_CHECKS = {"baseline_connectivity", "restored_connectivity",
                        "legitimate_connectivity_during_limit", "measured_policer_effect",
                        "apply_before_scoring_window", "restore_before_scoring_window"}


def write_json(path: Path, data: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def checked_path(path: Path) -> Path:
    """Reject linked ancestors before any output creation or evidence reading."""
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise ValueError("Parent traversal is not permitted in evidence paths")
    for ancestor in [absolute, *absolute.parents]:
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise ValueError("Linked paths are not permitted for portable runs")
    return absolute


def small_command(arguments: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, timeout=10,
                          check=False, shell=False, stdin=subprocess.DEVNULL)


def require_json(arguments: list[str]) -> list[dict]:
    result = small_command(arguments)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise RuntimeError("Read-only isolation inventory failed")
    records = json.loads(result.stdout)
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise RuntimeError("Malformed isolation inventory")
    return records


def inspect_isolation() -> dict:
    """Require a whole dedicated VM, not WSL/container/host with a disconnected NIC.

    No private addresses, MACs, hostnames, usernames, or namespace names from a
    refused host are written to the evidence. No network mutation occurs here.
    This is a point-in-time check, not a defence against concurrent root changes.
    """
    state = preflight()
    if not state["ready"]:
        raise RuntimeError("Linux root and ip/tc/sysctl are required; no lab actions started")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu":
        raise RuntimeError("This portable workflow requires an Ubuntu VM")
    detect = shutil.which("systemd-detect-virt")
    if not detect:
        raise RuntimeError("systemd-detect-virt is required to qualify the VM boundary")
    container = small_command([detect, "--container"])
    vm = small_command([detect, "--vm"])
    if container.returncode != 1 or container.stdout.strip() not in ("none", ""):
        raise RuntimeError("Container environments are not supported")
    allowed_vms = {"microsoft", "kvm", "qemu", "vmware", "oracle", "xen", "parallels", "bhyve"}
    if vm.returncode != 0 or vm.stdout.strip() not in allowed_vms:
        raise RuntimeError("A recognized dedicated VM is required; WSL or bare-metal is refused")
    ip = state["tools"]["ip"]
    links = require_json([ip, "-j", "link", "show"])
    if len(links) != 1 or links[0].get("ifname") != "lo":
        raise RuntimeError("Remove every VM network adapter before running; loopback only is required")
    addresses = require_json([ip, "-j", "addr", "show"])
    if len(addresses) != 1 or addresses[0].get("ifname") != "lo":
        raise RuntimeError("Unexpected guest address interfaces")
    info = addresses[0].get("addr_info")
    if not isinstance(info, list) or not info:
        raise RuntimeError("Loopback addressing is missing")
    for row in info:
        allowed = {("inet", "127.0.0.1", 8), ("inet6", "::1", 128)}
        if not isinstance(row, dict) or (row.get("family"), row.get("local"), row.get("prefixlen")) not in allowed:
            raise RuntimeError("Unexpected guest address binding")
    route_counts = {}
    for family in ("-4", "-6"):
        routes = require_json([ip, "-j", family, "route", "show", "table", "all"])
        route_counts[family] = len(routes)
        for row in routes:
            destination = row.get("dst")
            if (row.get("dev") != "lo" or row.get("gateway") or row.get("via")
                    or "nexthops" in row or "encap" in row
                    or row.get("type", "unicast") not in ("local", "broadcast", "unicast")):
                raise RuntimeError("Guest has a non-loopback route; refusing packet execution")
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except (ValueError, TypeError):
                raise RuntimeError("Guest has a default or unrecognized route") from None
            safe = ipaddress.ip_network("127.0.0.0/8") if family == "-4" else ipaddress.ip_network("::1/128")
            if network.version != safe.version or not network.subnet_of(safe):
                raise RuntimeError("Guest has an external route; refusing packet execution")
    namespace_result = small_command([ip, "netns", "list"])
    if namespace_result.returncode or namespace_result.stdout.strip():
        raise RuntimeError("Existing network namespaces detected or inventory failed; use a clean VM")
    return {"verified": True, "virtualization": vm.stdout.strip(), "interfaces": ["lo"],
            "only_loopback_addresses": True, "only_loopback_routes": True,
            "route_counts": route_counts, "existing_namespace_count": 0,
            "scope": "point-in-time dedicated VM check; no protection against concurrent root changes"}


def environment_snapshot() -> dict:
    release = platform.freedesktop_os_release()
    memory = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            memory[key + "_KiB"] = int(value.split()[0])
    versions = {}
    for tool in ("ip", "tc"):
        executable = shutil.which(tool)
        result = small_command([executable, "-V"])
        if result.returncode:
            raise RuntimeError("Could not record required tool version")
        versions[tool] = (result.stdout or result.stderr).strip()
    return {"utc": datetime.now(UTC).isoformat(), "os_id": release.get("ID"),
            "os_version": release.get("VERSION_ID"), "kernel": platform.release(),
            "machine": platform.machine(), "python": platform.python_version(),
            "logical_cpu_count": os.cpu_count(), "memory": memory,
            "load_average_1_5_15": list(os.getloadavg()), "tools": versions,
            "privacy": "No usernames, hostnames, serials, environment variables or credentials collected"}


def environment_identity(environment: dict) -> dict:
    return {**{key: environment[key] for key in ("os_id", "os_version", "kernel", "machine",
                                                "python", "logical_cpu_count", "tools")},
            "memory_total_KiB": environment["memory"]["MemTotal_KiB"]}


def captured_process(command: list[str], directory: Path, name: str, timeout: int) -> dict:
    """Bound a child; interrupt first so the existing runner can clean up.

    A forced kill may leave lab namespaces; the final isolation check records
    that failure. Never delete unowned resources. Reboot this disposable VM
    before retrying if cleanup cannot be verified.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=ROOT, env=env, shell=False,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    timed_out = False
    interrupted = False
    forced_kill = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        interrupted = isinstance(error, KeyboardInterrupt)
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            forced_kill = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=10)
    for suffix, content in (("stdout", stdout), ("stderr", stderr)):
        with (directory / f"{name}.{suffix}.txt").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content.replace(str(ROOT), "<BUNDLE_ROOT>"))
    receipt = {"command": [item.replace(str(ROOT), "<BUNDLE_ROOT>") for item in command],
               "returncode": process.returncode, "timed_out": timed_out,
               "interrupted": interrupted, "forced_kill": forced_kill,
               "elapsed_seconds": time.monotonic() - started}
    write_json(directory / f"{name}.receipt.json", receipt)
    if process.returncode != 0 or timed_out or interrupted:
        raise RuntimeError(f"{name} failed or was interrupted; retained logs must be inspected")
    return receipt


def tests_first(directory: Path) -> dict:
    return captured_process([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                            directory, "unit_tests", 600)


def verify_bundle(directory: Path, name: str) -> dict:
    manifest = checked_path(ROOT / "BUNDLE_MANIFEST.json")
    if not manifest.is_file():
        raise RuntimeError("A verified portable bundle is required; do not run this wrapper from an unversioned development checkout")
    return captured_process([sys.executable, str(ROOT / "scripts/portable_bundle.py"), "verify-tree"],
                            directory, name, 120)


def wait_until(deadline: float) -> None:
    while time.monotonic() < deadline:
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def assess_qualification(clients: dict, server: list, transitions: dict) -> dict:
    duration = 12
    quality = {role: check_offered_load(rows, duration,
                   [{"start": 0, "end": duration, "pps": 20 if role == "legitimate" else 200}])
               for role, rows in clients.items()}
    independent = score_server(server, clients, duration, 512)
    phases = {name: {role: score_cohorts(rows, start, end, 512) for role, rows in clients.items()}
              for name, (start, end) in {"baseline": (1, 3), "limited": (5, 7), "restored": (9, 11)}.items()}
    checks = {
        "baseline_connectivity": all(value["timely_delivery_ratio"] >= 0.8 for value in phases["baseline"].values()),
        "restored_connectivity": all(value["timely_delivery_ratio"] >= 0.8 for value in phases["restored"].values()),
        "legitimate_connectivity_during_limit": phases["limited"]["legitimate"]["timely_delivery_ratio"] >= 0.8,
        "measured_policer_effect": phases["limited"]["suspect"]["echo_goodput_kbit_s"]
                                  < 0.7 * phases["baseline"]["suspect"]["echo_goodput_kbit_s"],
        "apply_before_scoring_window": 4 <= transitions["applied_at_seconds"] < 5,
        "restore_before_scoring_window": 8 <= transitions["restored_at_seconds"] < 9,
    }
    return {"passed": all(checks.values()), "checks": checks, "phase_metrics": phases,
            "traffic_quality": quality, "server_whole_episode": independent,
            "acceptance_scope": "Technical connectivity/policer/restoration qualification, not comparative efficacy",
            "thresholds": {"minimum_timely_connectivity": 0.8, "maximum_limited_to_baseline_echo_goodput": 0.7}}


def qualify(directory: Path) -> dict:
    """Actually measure packets and both ordinary and exceptional cleanup."""
    packet_dir = directory / "qualification_packets"
    packet_dir.mkdir()
    transitions = {}
    with LinuxLab(packet_dir, capacity_kbit=10000, packet_bytes=512) as lab:
        netem = json.loads(lab._tc("-j", "-s", "qdisc", "show", "dev", "server0").stdout)
        if not isinstance(netem, list) or not any(row.get("kind") == "netem" for row in netem):
            raise RuntimeError("NetEm qdisc placement readback failed")
        transitions["netem_configuration_readback"] = netem
        transitions["netem_scope"] = "Presence/configuration readback only; qualification uses 10000 kbit/s, not pilot bottleneck capacity"
        traffic = lab.start_traffic(duration_seconds=12, legitimate_pps=20,
                     suspect_schedule=[{"start": 0, "end": 12, "pps": 200}], seed=0)
        started = traffic["started_at"]
        wait_until(started + 4)
        transitions["apply_readback"] = lab.apply_limit(80)
        transitions["applied_at_seconds"] = time.monotonic() - started
        wait_until(started + 8)
        transitions["restore_readback"] = lab.restore()
        transitions["restored_at_seconds"] = time.monotonic() - started
        completion = lab.finish()
        transitions["worker_returncodes"] = completion["returncodes"]
    write_json(directory / "qualification_transitions.json", transitions)
    clients = {role: read_jsonl(packet_dir / f"{role}.jsonl", completed=True)
               for role in ("legitimate", "suspect")}
    result = assess_qualification(clients, read_jsonl(packet_dir / "server.jsonl", completed=True), transitions)
    result["normal_cleanup"] = inspect_isolation()
    class ExpectedCleanupProbe(Exception):
        pass
    failure_dir = directory / "intentional_exception_cleanup"
    failure_dir.mkdir()
    try:
        with LinuxLab(failure_dir) as failure_lab:
            failure_lab.verify_isolation()
            failure_lab.apply_limit(80)
            raise ExpectedCleanupProbe("Deliberate bounded exception after verified policer placement")
    except ExpectedCleanupProbe:
        pass
    if failure_lab.cleanup_errors:
        raise RuntimeError("Intentional exception cleanup reported errors")
    result["exception_cleanup"] = inspect_isolation()
    result["exception_probe_scope"] = "Exception after namespace setup and policer placement; no worker or power-loss fault coverage"
    write_json(directory / "qualification_metrics.json", result)
    if not result["passed"]:
        raise RuntimeError("Measured technical qualification did not pass; retain all artifacts and do not run the pilot")
    return result


def file_hashes(directory: Path) -> dict:
    result = {}
    for path in sorted(directory.rglob("*")):
        checked_path(path)
        if path.is_file() and path != directory / "session_receipt.json":
            result[path.relative_to(directory).as_posix()] = sha256_file(path)
    return result


def validate_qualification(path: Path, sources: dict, environment: dict) -> dict:
    path = checked_path(path)
    if not path.is_relative_to(checked_path(BASE)) or path == BASE:
        raise ValueError("Qualification must be a prior session inside results/local/handoff_runs")
    receipt = strict_json_load(checked_path(path / "session_receipt.json"), maximum_bytes=8 * 1024 * 1024)
    if receipt.get("mode") != "qualify" or receipt.get("status") != "QUALIFICATION_PASSED":
        raise ValueError("A completed measured qualification is required")
    if receipt.get("source_files") != sources or receipt.get("environment_identity") != environment_identity(environment):
        raise ValueError("Source or environment changed since qualification; qualify again without overwriting prior results")
    if receipt.get("artifacts") != file_hashes(path):
        raise ValueError("Qualification artifact integrity check failed")
    # Hash consistency alone cannot establish that measurements exist. Require
    # complete evidence and independently recompute the technical acceptance.
    # This detects missing/inconsistent records; it is not a signature or proof
    # against a privileged party fabricating an entire mutually consistent run.
    expected_artifacts = {"qualification_metrics.json", "qualification_transitions.json",
                          "isolation_before.json", "isolation_after_tests.json", "isolation_after.json",
                          "environment_before.json", "environment_after.json",
                          "qualification_packets/kernel_commands.json",
                          "intentional_exception_cleanup/kernel_commands.json"}
    for role in ("legitimate", "suspect", "server"):
        expected_artifacts.add(f"qualification_packets/{role}.jsonl")
        expected_artifacts.add(f"qualification_packets/{role}.stderr.log")
    for name in ("unit_tests", "bundle_verification_before", "bundle_verification_after"):
        expected_artifacts.update(f"{name}.{suffix}" for suffix in ("receipt.json", "stdout.txt", "stderr.txt"))
    if not expected_artifacts.issubset(receipt["artifacts"]):
        raise ValueError("Qualification is missing mandatory measured evidence")

    def record(name: str) -> dict:
        value = strict_json_load(checked_path(path / name), maximum_bytes=8 * 1024 * 1024)
        if not isinstance(value, dict):
            raise ValueError("Qualification evidence must be a JSON object: " + name)
        return value

    def clean_isolation(value: dict) -> bool:
        return (isinstance(value, dict) and value.get("verified") is True
                and value.get("interfaces") == ["lo"]
                and value.get("only_loopback_addresses") is True
                and value.get("only_loopback_routes") is True
                and type(value.get("existing_namespace_count")) is int
                and value["existing_namespace_count"] == 0)

    bundle_hash = sha256_file(checked_path(ROOT / "BUNDLE_MANIFEST.json"))
    if receipt.get("received_bundle_manifest_sha256") != bundle_hash:
        raise ValueError("Qualification belongs to a different portable bundle; qualify again")
    for name in ("unit_tests", "bundle_verification_before", "bundle_verification_after"):
        run = record(name + ".receipt.json")
        if (type(run.get("returncode")) is not int or run["returncode"] != 0
                or any(run.get(flag) is not False for flag in ("timed_out", "interrupted", "forced_kill"))):
            raise ValueError("Qualification has unsuccessful test or bundle-verification evidence")
        if name.startswith("bundle_verification"):
            verified = record(name + ".stdout.txt")
            if verified.get("status") != "VERIFIED_SOURCE_TREE" or verified.get("manifest_sha256") != bundle_hash:
                raise ValueError("Qualification source-verification result is missing or inconsistent")
    for name in ("isolation_before.json", "isolation_after_tests.json", "isolation_after.json"):
        if not clean_isolation(record(name)):
            raise ValueError("Qualification isolation/cleanup evidence is not verified")
    for name in ("environment_before.json", "environment_after.json"):
        if environment_identity(record(name)) != environment_identity(environment):
            raise ValueError("Qualification environment evidence changed or is inconsistent")
    for name in ("qualification_packets/kernel_commands.json", "intentional_exception_cleanup/kernel_commands.json"):
        audit = record(name)
        roles = {"legitimate", "suspect", "router", "server"}
        namespaces = audit.get("namespaces")
        commands = audit.get("commands")
        topology = audit.get("topology_snapshot")
        if (audit.get("cleanup_errors") != [] or not isinstance(commands, list) or not commands
                or not isinstance(namespaces, dict) or set(namespaces) != roles
                or not isinstance(topology, dict) or set(topology) != roles
                or any(not isinstance(topology[role], dict) or topology[role].get("verified") is not True for role in roles)):
            raise ValueError("Qualification kernel setup/cleanup audit is incomplete or failed")
        for namespace in namespaces.values():
            if not isinstance(namespace, str) or not namespace.startswith("orcl-"):
                raise ValueError("Unexpected qualification namespace ownership evidence")
            for operation in ("add", "del"):
                if not any(isinstance(command, dict) and isinstance(command.get("argv"), list)
                           and command["argv"][1:] == ["netns", operation, namespace]
                           and type(command.get("returncode")) is int and command["returncode"] == 0
                           for command in commands):
                    raise ValueError("Qualification lacks successful owned namespace setup/cleanup commands")
    transitions = record("qualification_transitions.json")
    if (transitions.get("worker_returncodes") != [0, 0, 0]
            or any(type(code) is not int for code in transitions["worker_returncodes"])
            or not isinstance(transitions.get("apply_readback"), dict)
            or transitions["apply_readback"].get("configuration_verified") is not True
            or not isinstance(transitions.get("restore_readback"), dict)
            or transitions["restore_readback"].get("configuration_verified") is not True
            or transitions["restore_readback"].get("changed") is not True
            or not isinstance(transitions.get("netem_configuration_readback"), list)
            or not any(isinstance(row, dict) and row.get("kind") == "netem"
                       for row in transitions["netem_configuration_readback"])):
        raise ValueError("Qualification actuator/worker completion evidence is incomplete")
    metrics = record("qualification_metrics.json")
    if (metrics.get("passed") is not True
            or not isinstance(metrics.get("checks"), dict)
            or set(metrics["checks"]) != QUALIFICATION_CHECKS
            or any(value is not True for value in metrics["checks"].values())
            or not clean_isolation(metrics.get("normal_cleanup"))
            or not clean_isolation(metrics.get("exception_cleanup"))):
        raise ValueError("Qualification required acceptance or cleanup checks did not pass")
    clients = {role: read_jsonl(path / "qualification_packets" / f"{role}.jsonl", completed=True)
               for role in ("legitimate", "suspect")}
    recomputed = assess_qualification(clients,
                    read_jsonl(path / "qualification_packets/server.jsonl", completed=True), transitions)
    if recomputed.get("passed") is not True or any(metrics.get(key) != value for key, value in recomputed.items()):
        raise ValueError("Qualification metrics do not match the raw measured evidence")
    return receipt


def run_session(mode: str, qualification: Path | None, repetitions: int, order_seed: int) -> Path:
    checked_path(BASE).mkdir(parents=True, exist_ok=True)
    lock = BASE / ".active-run.lock"
    with lock.open("x", encoding="utf-8") as handle:
        handle.write("Portable lab run in progress. Do not remove without confirming it stopped.\n")
    directory = BASE / (datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8] + "-" + mode)
    receipt = {"status": "INCOMPLETE", "mode": mode, "classification": CLASSIFICATION,
               "live_model_evaluated": False, "oran_interface_exercised": False}
    try:
        directory.mkdir()
        print("Evidence session: " + str(directory), flush=True)
        # Before tests, workers or any namespace operation; refusal still gets a receipt.
        write_json(directory / "isolation_before.json", inspect_isolation())
        verify_bundle(directory, "bundle_verification_before")
        receipt["received_bundle_manifest_sha256"] = sha256_file(ROOT / "BUNDLE_MANIFEST.json")
        before = environment_snapshot()
        write_json(directory / "environment_before.json", before)
        sources = source_manifest(ROOT)
        receipt.update({"source_files": sources, "source_tree_sha256": combined_manifest_sha256(sources),
                        "environment_identity": environment_identity(before)})
        tests_first(directory)
        write_json(directory / "isolation_after_tests.json", inspect_isolation())
        if mode == "qualify":
            qualify(directory)
            receipt["status"] = "QUALIFICATION_PASSED"
        else:
            if qualification is None:
                raise ValueError("Specify the successful qualification session directory")
            validate_qualification(qualification, sources, before)
            shutil.copytree(qualification, directory / "qualification_evidence", symlinks=False)
            output = directory / "packet_pilot"
            captured_process([sys.executable, str(ROOT / "scripts/run_closed_loop.py"),
                              "--execute-isolated-lab", "--repetitions", str(repetitions),
                              "--order-seed", str(order_seed), "--output", str(output)],
                             directory, "packet_pilot", 600 + repetitions * 12 * 60)
            manifest = strict_json_load(output / "run_manifest.json", maximum_bytes=16 * 1024 * 1024)
            if manifest.get("status") != "COMPLETE_REFERENCE_CONTROLLER_PILOT":
                raise RuntimeError("Packet runner did not create a complete pilot manifest")
            receipt["status"] = "PILOT_COMPLETE_NOT_CONFIRMATORY"
            receipt["repetitions"] = repetitions
            receipt["order_seed"] = order_seed
        if source_manifest(ROOT) != sources:
            raise RuntimeError("Source changed during execution")
        verify_bundle(directory, "bundle_verification_after")
    except BaseException as error:
        receipt["status"] = "INCOMPLETE_NOT_PUBLISHABLE"
        receipt["error_type"] = type(error).__name__
        receipt["error"] = str(error).replace(str(ROOT), "<BUNDLE_ROOT>")
        print("Run stopped: " + receipt["error"], file=sys.stderr, flush=True)
    finally:
        if directory.exists():
            try:
                write_json(directory / "isolation_after.json", inspect_isolation())
                write_json(directory / "environment_after.json", environment_snapshot())
            except BaseException as error:
                receipt["status"] = "INCOMPLETE_NOT_PUBLISHABLE"
                receipt["final_check_error_type"] = type(error).__name__
                receipt["final_check_error"] = str(error).replace(str(ROOT), "<BUNDLE_ROOT>")
                receipt["next_step"] = "Stop; inspect retained logs. Do not delete namespaces by wildcard. Reboot the disposable VM before retrying if cleanup is uncertain."
            receipt["artifacts"] = file_hashes(directory)
            write_json(directory / "session_receipt.json", receipt)
        lock.unlink()
    if receipt["status"] not in ("QUALIFICATION_PASSED", "PILOT_COMPLETE_NOT_CONFIRMATORY"):
        raise RuntimeError("Session did not complete; return the entire handoff_runs folder, including failures")
    return directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--qualify", action="store_true")
    actions.add_argument("--run-pilot", action="store_true")
    parser.add_argument("--acknowledge-isolated-vm", action="store_true")
    parser.add_argument("--qualification", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--order-seed", type=int, default=220926)
    args = parser.parse_args(argv)
    if not args.qualify and not args.run_pilot:
        print(json.dumps({"status": "PLAN_ONLY_NO_WRITES_NO_PACKETS", "classification": CLASSIFICATION,
              "commands": ["sudo python3 scripts/home_lab_run.py --qualify --acknowledge-isolated-vm",
                           "sudo python3 scripts/home_lab_run.py --run-pilot --acknowledge-isolated-vm --qualification results/local/handoff_runs/<QUALIFICATION_SESSION> --repetitions 3"],
              "requirements": ["Dedicated Ubuntu VM; every network adapter removed", "Python 3.11+ and iproute2/procps/systemd",
                               "Explicit root execution; no LLM or API key", "Keep every session, including failures"],
              "output_root": "results/local/handoff_runs", "interpretation": "Technical qualification then deterministic-controller descriptive pilot; not confirmatory"}, indent=2))
        return 0
    if not args.acknowledge_isolated_vm:
        parser.error("Explicit --acknowledge-isolated-vm is required; read the setup guide first")
    if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("Only root inside the dedicated Ubuntu VM may execute; nothing was started")
    if not 1 <= args.repetitions <= 10 or not 0 <= args.order_seed < 2**32:
        parser.error("Portable pilot repetitions must be 1..10 and order seed must be uint32")
    if args.run_pilot and args.qualification is None:
        parser.error("--run-pilot requires --qualification with the measured successful session directory")
    try:
        output = run_session("qualify" if args.qualify else "pilot", args.qualification,
                             args.repetitions, args.order_seed)
    except (OSError, RuntimeError, ValueError) as error:
        print(str(error).replace(str(ROOT), "<BUNDLE_ROOT>"), file=sys.stderr)
        return 2
    print("Complete: " + str(output))
    print("Return ALL results/local/handoff_runs sessions; do not select only favourable runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
