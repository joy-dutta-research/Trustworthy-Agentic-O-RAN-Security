#!/usr/bin/env python3
"""Bounded UDP worker; runs only in the explicitly named isolated lab namespace.

Online window records are send cohorts matured after a 500 ms response deadline.
Final cohort_summary attributes each reply to its original send window and
retains all sent packets in denominators, including later replies separately.
The fixed two-second drain includes late replies; remaining packets are losses
under that stated observation timeout, not an assertion of permanent loss.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oran_trust_boundary.closed_loop_lab import (  # noqa: E402
    DRAIN_SECONDS, MAX_DURATION_SECONDS, PORT, SERVER_IP, validate_schedule,
)

HEADER = struct.Struct("!Qd")
SOURCES = {"legitimate": "10.203.1.2", "suspect": "10.203.2.2"}
REPLY_DEADLINE_SECONDS = 0.5


def require_namespace(namespace: str, role: str) -> None:
    if not re.fullmatch(r"orcl-[0-9a-f]{12}-(legitimate|suspect|server)", namespace):
        raise ValueError("Invalid isolated lab namespace name")
    if not namespace.endswith("-" + role):
        raise ValueError("Namespace and worker role do not match")
    expected = os.stat("/var/run/netns/" + namespace)
    current = os.stat("/proc/self/ns/net")
    initial = os.stat("/proc/1/ns/net")
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError("Worker is not in its requested namespace")
    if (current.st_dev, current.st_ino) == (initial.st_dev, initial.st_ino):
        raise RuntimeError("Refusing traffic from the initial network namespace")


def emit(handle, record: dict) -> None:
    handle.write(json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n")
    handle.flush()


def new_window(start: float, end: float) -> dict:
    return {"window_start": start, "window_end": end, "sent": 0, "received": 0,
            "received_bytes": 0, "rtt_ms": [], "late_receipts": 0}


def client(args, handle) -> None:
    schedule = validate_schedule(json.loads(args.schedule), args.duration)
    if not math.isfinite(args.start) or not time.monotonic() < args.start <= time.monotonic() + 5:
        raise ValueError("Client start must be in the next five seconds")
    cohorts = [new_window(float(i), min(float(i + 1), args.duration))
               for i in range(math.ceil(args.duration))]
    windows = [new_window(float(i), min(float(i + 1), args.duration))
               for i in range(math.ceil(args.duration))]
    sent_at: dict[int, tuple[float, int]] = {}
    received_sequences: set[int] = set()
    counters = {"duplicates": 0, "malformed": 0, "unknown_replies": 0,
                "send_errors": 0, "receive_errors": 0, "missed_send_slots": 0}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SOURCES[args.role], 0))
    sock.setblocking(False)
    sequence = 0
    next_send = args.start
    interval_index = 0
    emitted = 0
    emit(handle, {"type": "metadata", "role": args.role, "started_at": args.start,
                  "duration_seconds": args.duration, "drain_seconds": DRAIN_SECONDS,
                  "reply_deadline_seconds": REPLY_DEADLINE_SECONDS,
                  "packet_bytes": args.packet_bytes, "schedule": schedule, "seed": args.seed,
                  "seed_semantics": "episode identifier; fixed-rate pacing, not randomized"})
    try:
        while True:
            now = time.monotonic()
            elapsed = now - args.start
            if elapsed >= args.duration + DRAIN_SECONDS:
                break
            while (emitted < len(windows)
                   and elapsed >= windows[emitted]["window_end"] + REPLY_DEADLINE_SECONDS):
                emit(handle, {"type": "window", **windows[emitted],
                              "measurement_semantics": "send_cohort_500ms",
                              "reply_deadline_seconds": REPLY_DEADLINE_SECONDS,
                              "emitted_at": now})
                emitted += 1
            while interval_index < len(schedule) and elapsed >= schedule[interval_index]["end"]:
                interval_index += 1
                next_send = now
            if interval_index < len(schedule):
                interval = schedule[interval_index]
                active = interval["start"] <= elapsed < interval["end"] and interval["pps"] > 0
                if active and now >= next_send:
                    spacing = 1.0 / interval["pps"]
                    if now - next_send > spacing:
                        counters["missed_send_slots"] += int((now - next_send) / spacing)
                    next_send = now + spacing  # Never catch up by producing an unbounded burst.
                    payload = HEADER.pack(sequence, now) + bytes(args.packet_bytes - HEADER.size)
                    try:
                        sent = sock.sendto(payload, (SERVER_IP, PORT))
                        if sent != len(payload):
                            raise RuntimeError("Partial UDP datagram send")
                    except (BlockingIOError, InterruptedError):
                        counters["send_errors"] += 1
                    else:
                        cohort_id = min(int(elapsed), len(cohorts) - 1)
                        sent_at[sequence] = (now, cohort_id)
                        cohorts[cohort_id]["sent"] += 1
                        windows[cohort_id]["sent"] += 1
                        sequence += 1
            # Bounded drains avoid a continuously readable socket starving timers.
            for _ in range(128):
                try:
                    data, source = sock.recvfrom(2048)
                except BlockingIOError:
                    break
                except InterruptedError:
                    counters["receive_errors"] += 1
                    break
                received_time = time.monotonic()
                if source != (SERVER_IP, PORT) or len(data) != args.packet_bytes:
                    counters["malformed"] += 1
                    continue
                reply_seq, timestamp = HEADER.unpack_from(data)
                if reply_seq not in sent_at or timestamp != sent_at[reply_seq][0]:
                    counters["unknown_replies"] += 1
                    continue
                if reply_seq in received_sequences:
                    counters["duplicates"] += 1
                    continue
                received_sequences.add(reply_seq)
                sent_time, cohort_id = sent_at[reply_seq]
                cohort = cohorts[cohort_id]
                arrival = received_time - args.start
                rtt = (received_time - sent_time) * 1000
                cohort["received"] += 1
                cohort["received_bytes"] += len(data)
                cohort["rtt_ms"].append(rtt)
                if rtt <= REPLY_DEADLINE_SECONDS * 1000:
                    online = windows[cohort_id]
                    online["received"] += 1
                    online["received_bytes"] += len(data)
                    online["rtt_ms"].append(rtt)
                if arrival >= cohort["window_end"]:
                    cohort["late_receipts"] += 1
            wait_until = min(args.start + args.duration + DRAIN_SECONDS, now + 0.002)
            if interval_index < len(schedule):
                interval = schedule[interval_index]
                if elapsed < interval["start"]:
                    wait_until = min(wait_until, args.start + interval["start"])
                elif interval["pps"]:
                    wait_until = min(wait_until, next_send)
            select.select([sock], [], [], max(0, wait_until - time.monotonic()))
        for window in windows[emitted:]:
            emit(handle, {"type": "window", **window,
                          "measurement_semantics": "send_cohort_500ms",
                          "reply_deadline_seconds": REPLY_DEADLINE_SECONDS,
                          "emitted_at": time.monotonic()})
        for cohort, online in zip(cohorts, windows):
            cohort["lost"] = cohort["sent"] - cohort["received"]
            cohort["received_within_deadline"] = online["received"]
            cohort["deadline_missed"] = cohort["sent"] - online["received"]
            cohort["received_after_deadline"] = cohort["received"] - online["received"]
        emit(handle, {"type": "cohort_summary", "role": args.role, "cohorts": cohorts,
                      "sent": len(sent_at), "received": len(received_sequences),
                      "lost": len(sent_at) - len(received_sequences),
                      "drain_seconds": DRAIN_SECONDS, "counters": counters,
                      "finished_at": time.monotonic()})
    finally:
        sock.close()


def server(args, handle) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, PORT))
    sock.settimeout(0.05)
    totals = {role: {"received": 0, "received_bytes": 0, "echoed": 0, "echo_errors": 0}
              for role in SOURCES}
    by_ip = {address: role for role, address in SOURCES.items()}
    invalid = 0
    started = time.monotonic()
    deadline = started + args.duration + DRAIN_SECONDS + 7
    # Parent checks this marker only after the socket is successfully bound.
    with Path(args.ready).open("x", encoding="utf-8") as marker:
        marker.write(json.dumps({"bound": SERVER_IP, "port": PORT, "ready_at": started}))
    emit(handle, {"type": "ready", "ready_at": started, "deadline": deadline})
    try:
        while time.monotonic() < deadline:
            try:
                data, source = sock.recvfrom(2048)
            except socket.timeout:
                continue
            role = by_ip.get(source[0])
            if role is None or len(data) != args.packet_bytes:
                invalid += 1
                continue
            metric = totals[role]
            metric["received"] += 1
            metric["received_bytes"] += len(data)
            try:
                sock.sendto(data, source)
                metric["echoed"] += 1
            except (BlockingIOError, InterruptedError, socket.timeout):
                metric["echo_errors"] += 1
        emit(handle, {"type": "server_summary", "sources": totals, "invalid": invalid,
                      "finished_at": time.monotonic()})
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("legitimate", "suspect", "server"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--packet-bytes", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--start", type=float)
    parser.add_argument("--schedule")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--ready")
    args = parser.parse_args()
    if not math.isfinite(args.duration) or not 1 <= args.duration <= MAX_DURATION_SECONDS:
        parser.error("duration must be finite and in 1..60 seconds")
    if not 64 <= args.packet_bytes <= 1200 or not 0 <= args.seed <= 2**32 - 1:
        parser.error("packet size or seed is outside the permitted bounds")
    if args.role == "server" and not args.ready:
        parser.error("server requires a readiness path")
    if args.role != "server" and (args.start is None or args.schedule is None):
        parser.error("clients require start and schedule")
    require_namespace(args.namespace, args.role)
    with Path(args.output).open("x", encoding="utf-8") as handle:
        (server if args.role == "server" else client)(args, handle)


if __name__ == "__main__":
    main()
