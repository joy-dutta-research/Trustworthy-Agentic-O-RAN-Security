"""Bounded Windows-only supervision for approved offline evaluation runners.

Creates new private local run artifacts, never overwrites experiments. A gated
Python child is assigned to an owned Windows Job before its runner starts;
descendants inherit memory/process limits and are terminated on guard failure.
No system configuration, network traffic, elevation, or external commands.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import time
import uuid

import freeze_evaluation_baseline as freeze

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.evaluation_filesystem import OUTPUT_MONITOR_VERSION, dynamic_tree_bytes
APPROVED = {"scripts/run_validity_v02.py", "scripts/run_dataset_evaluation_v02.py",
            "scripts/run_sensitivity_v02.py", "scripts/run_performance_v02.py"}
SOURCE_ROOTS = ("src", "scripts", "tests", "configs", "docs/evaluation_v0.2")
SOURCE_SUFFIXES = {".py", ".json", ".md"}


def write_new(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def source_snapshot(root: Path):
    files = {}
    for name in SOURCE_ROOTS:
        for path in sorted((root / name).rglob("*")):
            if "__pycache__" in path.parts:
                continue
            freeze._check_chain(path)
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            files[path.relative_to(root).as_posix()] = freeze._stable_bytes(path)[0]
    return files


def validate_arguments(root: Path, script: str, args: list[str]):
    if script not in APPROVED:
        raise ValueError("runner is not on the offline evaluation allowlist")
    freeze._check_chain(root / script)
    if any(arg == "--output" or arg.startswith("--output=") for arg in args):
        raise ValueError("output is supplied by the supervisor, not the runner arguments")
    if any("\x00" in arg for arg in args):
        raise ValueError("invalid runner argument")


class WindowsJob:
    """Owned process-tree containment; Windows aggregate committed-memory cap.

    Per-process working sets are checked separately. The commitment cap is an
    additional conservative bound, not mislabeled as an RSS measurement.
    """
    def __init__(self, memory_bytes: int):
        if os.name != "nt":
            raise RuntimeError("this supervisor requires Windows; no unguarded fallback")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        size = ctypes.c_size_t

        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("min_ws", size), ("max_ws", size),
                        ("active_limit", wintypes.DWORD), ("affinity", size),
                        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", size),
                        ("job_memory", size), ("peak_process_memory", size), ("peak_job_memory", size)]
        class Pids(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD), ("pids", size * 64)]
        class Memory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, size) for name in ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")]

        self.Extended, self.Pids, self.Memory = Extended, Pids, Memory
        for name, restype, argtypes in (
            ("CreateJobObjectW", wintypes.HANDLE, [ctypes.c_void_p, wintypes.LPCWSTR]),
            ("SetInformationJobObject", wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]),
            ("QueryInformationJobObject", wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]),
            ("AssignProcessToJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]),
            ("TerminateJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
            ("CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
            ("OpenProcess", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
        ):
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = restype, argtypes
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        self.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("cannot create an owned Windows Job")
        info = Extended()
        info.basic.flags = 0x2000 | 0x200 | 0x100 | 0x8
        info.basic.active_limit = 16
        info.process_memory = memory_bytes
        info.job_memory = memory_bytes
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close()
            raise OSError("cannot enforce memory/process bounds")

    def attach(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise OSError("cannot attach gated child to owned Job")

    def usage(self):
        info, pids = self.Extended(), self.Pids()
        if not self.kernel.QueryInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info), None):
            raise OSError("cannot inspect owned Job memory")
        if not self.kernel.QueryInformationJobObject(self.handle, 3, ctypes.byref(pids), ctypes.sizeof(pids), None):
            raise OSError("cannot inspect owned Job processes")
        peak_rss = 0
        for pid in pids.pids[:min(pids.count, 64)]:
            handle = self.kernel.OpenProcess(0x1000 | 0x10, False, pid)
            if not handle:
                # ERROR_INVALID_PARAMETER can mean this process just exited.
                if ctypes.get_last_error() == 87:
                    continue
                raise OSError("cannot inspect owned worker; resource monitoring refused")
            try:
                memory = self.Memory()
                memory.cb = ctypes.sizeof(memory)
                if not self.psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                    raise OSError("cannot inspect owned worker memory")
                peak_rss = max(peak_rss, memory.peak_ws)
            finally:
                self.kernel.CloseHandle(handle)
        return {"active_processes": pids.count,
                "peak_job_committed_bytes": int(info.peak_job_memory),
                "maximum_observed_process_peak_rss_bytes": int(peak_rss)}

    def terminate(self):
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 125)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def tree_bytes(directory: Path):
    return dynamic_tree_bytes(directory, check_chain=freeze._check_chain)


def supervise(script: str, arguments: list[str], label: str, baseline: str):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,60}", label):
        raise ValueError("invalid run label")
    validate_arguments(ROOT, script, arguments)
    previous = freeze.verify_baseline(ROOT, baseline)
    if previous["status"] != "pass":
        raise RuntimeError("original baseline changed; evaluation refused")
    limits = json.loads((ROOT / "configs/evaluation_v0.2/study_design.json").read_text())["technical_resource_limits"]
    if shutil.disk_usage(ROOT).free < limits["minimum_free_disk_bytes_before_large_runs"]:
        raise RuntimeError("insufficient free disk for bounded evaluation")
    snapshot = source_snapshot(ROOT)
    output = ROOT / "results/evaluation_v0.2" / (label + "_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8])
    freeze._check_chain(output.parent)
    output.mkdir(exist_ok=False)
    command_args = [*arguments, "--output", (output / "work").relative_to(ROOT).as_posix()]
    write_new(output / "SOURCE_BEFORE.json", snapshot)
    write_new(output / "STARTED.json", {"status": "STARTED", "label": label, "script": script,
              "output_monitor_version": OUTPUT_MONITOR_VERSION,
              "arguments": command_args, "baseline": baseline, "resource_limits": limits,
              "memory_guard": "Windows Job commitment limit plus sampled process peak RSS",
              "limits_sampling_seconds": 1, "timestamp_utc": datetime.now(UTC).isoformat()})
    print(json.dumps({"status": "STARTED", "run": output.relative_to(ROOT).as_posix()}), flush=True)
    job, process = None, None
    elapsed, peak_commit, peak_rss = 0.0, 0, 0
    failure = None
    exit_code = None
    started = time.monotonic()
    try:
        job = WindowsJob(limits["maximum_worker_rss_bytes"])
        with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
            process = subprocess.Popen([sys.executable, "-u", str(Path(__file__)), "--gated-child", script, *command_args],
                         cwd=ROOT, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                         creationflags=subprocess.CREATE_NO_WINDOW)
            job.attach(process)
            process.stdin.write(b"RUN\n")
            process.stdin.flush()
            process.stdin.close()
            next_progress = 0
            while process.poll() is None:
                elapsed = time.monotonic() - started
                usage = job.usage()
                peak_commit = max(peak_commit, usage["peak_job_committed_bytes"])
                peak_rss = max(peak_rss, usage["maximum_observed_process_peak_rss_bytes"])
                if elapsed > limits["maximum_wall_seconds_per_offline_runner"]:
                    raise RuntimeError("wall-time guard exceeded")
                if peak_rss > limits["maximum_worker_rss_bytes"]:
                    raise RuntimeError("worker RSS guard exceeded")
                if tree_bytes(output) > limits["maximum_new_output_bytes_per_run"]:
                    raise RuntimeError("new-output byte guard exceeded")
                if elapsed >= next_progress:
                    print(json.dumps({"status": "RUNNING", "run": output.name, "seconds": round(elapsed, 1),
                                      "peak_job_committed_bytes": peak_commit}), flush=True)
                    next_progress = elapsed + 30
                time.sleep(1)
            exit_code = process.returncode
            final_usage = job.usage()
            peak_commit = max(peak_commit, final_usage["peak_job_committed_bytes"])
            if final_usage["active_processes"]:
                raise RuntimeError("runner exited with live descendants; owned Job terminated")
            if exit_code != 0:
                raise RuntimeError(f"runner exited with code {exit_code}")
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    finally:
        if job is not None:
            job.terminate()
            job.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        elapsed = time.monotonic() - started
    after = source_snapshot(ROOT)
    write_new(output / "SOURCE_AFTER.json", after)
    baseline_after = freeze.verify_baseline(ROOT, baseline)
    if after != snapshot or baseline_after["status"] != "pass":
        failure = "source or original baseline changed during evaluation"
    if tree_bytes(output) > limits["maximum_new_output_bytes_per_run"]:
        failure = "new-output byte guard exceeded"
    receipt = {"status": "INCOMPLETE" if failure else "COMPLETE", "failure": failure,
               "output_monitor_version": OUTPUT_MONITOR_VERSION,
               "runner_exit_code": exit_code, "elapsed_seconds": elapsed,
               "peak_job_committed_bytes": peak_commit,
               "maximum_observed_process_peak_rss_bytes": peak_rss,
               "source_unchanged": after == snapshot, "baseline_after": baseline_after,
               "claim": "Execution/provenance receipt only; runner reports determine scientific findings."}
    write_new(output / ("INCOMPLETE.json" if failure else "COMPLETE.json"), receipt)
    print(json.dumps({"run": output.relative_to(ROOT).as_posix(), **receipt}), flush=True)
    return 1 if failure else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--gated-child":
        script, args = sys.argv[2], sys.argv[3:]
        if script not in APPROVED or sys.stdin.buffer.readline(4) != b"RUN\n":
            raise SystemExit("gated child was not released")
        sys.argv = [str(ROOT / script), *args]
        runpy.run_path(str(ROOT / script), run_name="__main__")
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", choices=sorted(APPROVED), required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    return supervise(args.script, arguments, args.label, args.baseline)


if __name__ == "__main__":
    raise SystemExit(main())
