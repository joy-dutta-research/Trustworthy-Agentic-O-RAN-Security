"""Read-only, bounded 5G-NIDD profiling and deterministic record selection.

No addresses, ports, raw timestamps or inferred O-RAN identities are exported.
Raw data stays in its checksum-pinned archive; no extraction is needed.
"""
from __future__ import annotations

import csv
import hashlib
import heapq
import io
import json
import math
import stat
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from .provenance import sha256_file

ARCHIVE_SHA256 = "07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d"
SELECTED_LABELS = ("Benign", "ICMPFlood", "SYNFlood", "UDPFlood")
REQUIRED_COLUMNS = frozenset({"Attack Type", "Label", "Dur", "TotPkts"})
MAX_CSV_BYTES = 1024 * 1024 * 1024
MAX_ROWS = 2_000_000


class NiddValidationError(ValueError):
    """The data cannot support the documented experiment without guessing."""


def _strict_rows(reader):
    try:
        yield from reader
    except csv.Error as exc:
        raise NiddValidationError("malformed CSV grammar") from exc


def _measurements(row: dict[str, str]) -> tuple[float, int, float | None]:
    try:
        duration = float(row["Dur"])
        packets = float(row["TotPkts"])
    except (ValueError, TypeError, OverflowError) as exc:
        raise NiddValidationError("missing or nonnumeric duration/packet count") from exc
    if (not math.isfinite(duration) or not math.isfinite(packets)
            or duration < 0 or packets < 0 or not packets.is_integer()):
        raise NiddValidationError("invalid duration/packet count")
    rate = packets / duration if duration > 0 else None
    if rate is not None and not math.isfinite(rate):
        raise NiddValidationError("nonfinite packet rate")
    return duration, int(packets), rate


def profile_archive(
    archive_path: str | Path,
    *,
    expected_sha256: str = ARCHIVE_SHA256,
    sample_per_label: int = 25,
) -> dict[str, Any]:
    """Audit every row; select unique usable records by deterministic hash rank.

    A custom checksum is available for unit fixtures, not silent production
    version substitution. The production runner always uses ARCHIVE_SHA256.
    """
    if isinstance(sample_per_label, bool) or not isinstance(sample_per_label, int) or not 1 <= sample_per_label <= 100:
        raise NiddValidationError("sample_per_label must be an integer from 1 to 100")
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise NiddValidationError("expected_sha256 must be a lowercase SHA-256 digest")
    path = Path(archive_path)
    if path.is_symlink() or not path.is_file():
        raise NiddValidationError("archive must be a regular nonsymlink file")
    if path.stat().st_size > 100 * 1024 * 1024:
        raise NiddValidationError("compressed archive exceeds 100 MiB")
    if sha256_file(path) != expected_sha256:
        raise NiddValidationError("archive SHA-256 mismatch")

    labels: Counter[str] = Counter()
    binary_labels: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    exclusions: Counter[str] = Counter()
    eligible: Counter[str] = Counter()
    duplicates: Counter[str] = Counter()
    seen: set[bytes] = set()
    reservoirs: dict[str, list[tuple[int, int, dict[str, Any]]]] = {label: [] for label in SELECTED_LABELS}
    malformed = 0
    numeric_invalid = 0
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) != 1:
            raise NiddValidationError("expected one CSV member, not an arbitrary archive layout")
        member = members[0]
        name = PurePosixPath(member.filename)
        if (name.is_absolute() or ".." in name.parts or "\\" in member.filename
                or ":" in member.filename or name.suffix.lower() != ".csv"
                or stat.S_ISLNK(member.external_attr >> 16) or member.flag_bits & 1
                or not 0 < member.file_size <= MAX_CSV_BYTES):
            raise NiddValidationError("unsafe or unsupported CSV archive member")
        # Reading to EOF validates the ZIP CRC. Original bytes remain unmodified.
        with archive.open(member) as binary, io.TextIOWrapper(binary, encoding="utf-8-sig", newline="") as text:
            reader = csv.DictReader(text, strict=True)
            try:
                columns = reader.fieldnames or []
            except csv.Error as exc:
                raise NiddValidationError("malformed CSV header") from exc
            if len(columns) != len(set(columns)) or not REQUIRED_COLUMNS <= set(columns):
                raise NiddValidationError("missing required or duplicate CSV headers")
            content_columns = [column for column in columns if column and not column.startswith("Unnamed:")]
            for ordinal, row in enumerate(_strict_rows(reader), start=1):
                total += 1
                if total > MAX_ROWS:
                    raise NiddValidationError("CSV row limit exceeded")
                if None in row or any(value is None for value in row.values()):
                    malformed += 1
                    continue
                for column, value in row.items():
                    if not value.strip() or value.strip().lower() in {"nan", "null", "none"}:
                        missing[column] += 1
                label = row["Attack Type"].strip()
                binary_label = row["Label"].strip()
                if not label or not binary_label:
                    raise NiddValidationError("missing incident label")
                labels[label] += 1
                binary_labels[binary_label] += 1
                if (label == "Benign" and binary_label != "Benign") or (label != "Benign" and binary_label != "Malicious"):
                    raise NiddValidationError("inconsistent binary and attack labels")
                encoded = json.dumps([row[column] for column in content_columns], separators=(",", ":"), ensure_ascii=True).encode()
                digest = hashlib.sha256(encoded).digest()
                duplicate = digest in seen
                seen.add(digest)
                if duplicate:
                    duplicates[label] += 1
                try:
                    duration, packets, rate = _measurements(row)
                except NiddValidationError:
                    numeric_invalid += 1
                    if label in reservoirs:
                        exclusions[f"{label}:invalid_measurements"] += 1
                    continue
                if label not in reservoirs:
                    exclusions[f"{label}:outside_predeclared_flood_comparison"] += 1
                    continue
                if duplicate:
                    exclusions[f"{label}:duplicate_record"] += 1
                    continue
                if label != "Benign" and (rate is None or rate <= 0):
                    exclusions[f"{label}:nonpositive_or_undefined_packet_rate"] += 1
                    continue
                eligible[label] += 1
                record_id = hashlib.sha256(f"{expected_sha256}:{member.filename}:{ordinal}".encode()).hexdigest()[:32]
                context = {"record_id": record_id, "source_row_number": ordinal,
                           "attack_type": label, "duration_seconds": duration,
                           "total_packets": packets, "packets_per_second": rate}
                item = (-int.from_bytes(digest, "big"), -ordinal, context)
                heap = reservoirs[label]
                if len(heap) < sample_per_label:
                    heapq.heappush(heap, item)
                elif item[:2] > heap[0][:2]:
                    heapq.heapreplace(heap, item)
    if malformed:
        raise NiddValidationError(f"CSV contains {malformed} malformed rows; no partial experiment permitted")
    if sha256_file(path) != expected_sha256:
        raise NiddValidationError("archive changed during profiling")
    absent = [label for label in SELECTED_LABELS if not reservoirs[label]]
    if absent:
        raise NiddValidationError(f"no usable records for required labels: {absent}")
    contexts = [item[2] for label in SELECTED_LABELS for item in sorted(reservoirs[label], key=lambda item: (-item[0], -item[1]))]
    return {
        "manifest_version": "5gnidd-0.1",
        "dataset": {"name": "5G-NIDD", "doi": "10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361",
                    "license": "CC-BY-4.0", "archive_sha256": expected_sha256,
                    "csv_member": member.filename, "csv_uncompressed_bytes": member.file_size},
        "audit": {"row_count": total, "columns": columns, "attack_counts": dict(sorted(labels.items())),
                  "binary_label_counts": dict(sorted(binary_labels.items())),
                  "missing_counts": dict(sorted(missing.items())), "malformed_rows": malformed,
                  "invalid_measurement_rows": numeric_invalid, "duplicate_rows": sum(duplicates.values()),
                  "duplicate_counts": dict(sorted(duplicates.items())),
                  "eligible_unique_counts": dict(sorted(eligible.items())),
                  "selection_exclusions": dict(sorted(exclusions.items()))},
        "selection": {"method": "smallest_sha256_unique_parsed_rows_excluding_unnamed_index",
                      "sample_per_label": sample_per_label, "selected_counts": {label: len(reservoirs[label]) for label in SELECTED_LABELS},
                      "session_independence": "not established; do not infer sessions/base stations from combined-row order"},
        "privacy": "No raw addresses, ports, timestamps, or network identifiers exported; opaque row references are linkable to the public source.",
        "contexts": contexts,
    }
