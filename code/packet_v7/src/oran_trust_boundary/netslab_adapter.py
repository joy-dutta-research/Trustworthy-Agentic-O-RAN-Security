"""Deterministic, privacy-preserving binding to NetsLab-5GORAN-IDD.

The adapter exports aggregate label strata only. It deliberately does not
export rows, timestamps, UE identifiers, RNTIs, or cell identifiers.
"""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any

from .audit import canonical_sha256
from .provenance import sha256_file


DATASET_DOI = "10.34740/kaggle/ds/7416931"
TABLE_NAME = "lower_layer_data"
REQUIRED_COLUMNS = frozenset(
    {
        "ue_id",
        "cellid",
        "traffic_type",
        "attack_category",
        "attack_subcategory",
        "cqi",
        "sinr",
        "rsrp",
        "rsrq",
        "rssi",
        "dlBler",
        "ulBler",
    }
)
SIGNAL_COLUMNS = ("cqi", "sinr", "rsrp", "rsrq", "rssi", "dlBler", "ulBler")
REPLAY_BINDINGS = {
    "Benign": "benign_negative_control",
    "DDoS_ICMP": "icmp_flood",
    "DDoS_ACK": "ack_flood",
    "DDoS_SYN": "syn_flood",
    "DDoS_UDP": "udp_flood",
    "Probe_PortScan": "port_scan",
}


class DatasetValidationError(ValueError):
    """Raised when the downloaded database cannot support a frozen replay."""


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _finite_or_none(value: Any, field: str) -> float | None:
    if value is None:
        return None
    converted = float(value)
    if not math.isfinite(converted):
        raise DatasetValidationError(f"non-finite aggregate for {field}")
    return converted


def build_context_manifest(
    database_path: str | Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Aggregate every attack subcategory and bind exact replay labels.

    ``expected_sha256`` is mandatory to prevent a silent dataset-version
    substitution. The unit of analysis remains the action proposal; database
    rows are contextual evidence and are not counted as independent trials.
    """

    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise DatasetValidationError("expected_sha256 must be a lowercase SHA-256 digest")
    database = Path(database_path).resolve(strict=True)
    actual_sha256 = sha256_file(database)
    if actual_sha256 != expected_sha256:
        raise DatasetValidationError(
            f"database SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise DatasetValidationError(f"SQLite integrity check failed: {quick_check}")
        table_exists = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
            (TABLE_NAME,),
        ).fetchone()[0]
        if table_exists != 1:
            raise DatasetValidationError(f"required table {TABLE_NAME!r} not found")
        quoted_table = _quote_identifier(TABLE_NAME)
        columns = {
            row[1] for row in connection.execute(f"PRAGMA table_info({quoted_table})")
        }
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise DatasetValidationError(
                f"dataset schema omits required columns: {sorted(missing)}"
            )

        signal_sql = ", ".join(
            f"AVG({_quote_identifier(column)})" for column in SIGNAL_COLUMNS
        )
        rows = connection.execute(
            "SELECT attack_subcategory, attack_category, traffic_type, "
            "COUNT(*), COUNT(DISTINCT ue_id), COUNT(DISTINCT cellid), "
            f"{signal_sql} FROM {quoted_table} "
            "GROUP BY attack_subcategory, attack_category, traffic_type "
            "ORDER BY attack_subcategory"
        ).fetchall()
        total_rows = connection.execute(
            f"SELECT COUNT(*) FROM {quoted_table}"
        ).fetchone()[0]
    finally:
        connection.close()

    strata: list[dict[str, Any]] = []
    observed_labels: set[str] = set()
    for row in rows:
        subcategory, category, traffic_type, row_count, ue_count, cell_count, *means = row
        if not isinstance(subcategory, str) or not subcategory.strip():
            raise DatasetValidationError("attack_subcategory contains a missing label")
        if subcategory in observed_labels:
            raise DatasetValidationError(
                f"subcategory {subcategory!r} maps to multiple category/type pairs"
            )
        observed_labels.add(subcategory)
        binding = REPLAY_BINDINGS.get(subcategory)
        strata.append(
            {
                "attack_subcategory": subcategory,
                "attack_category": category,
                "traffic_type": traffic_type,
                "row_count": row_count,
                "distinct_ue_count": ue_count,
                "distinct_cell_count": cell_count,
                "signal_means": {
                    column: _finite_or_none(value, f"{subcategory}.{column}")
                    for column, value in zip(SIGNAL_COLUMNS, means, strict=True)
                },
                "selected_for_replay": binding is not None,
                "replay_binding": binding,
            }
        )

    absent_bindings = sorted(set(REPLAY_BINDINGS) - observed_labels)
    if absent_bindings:
        raise DatasetValidationError(
            f"frozen replay labels are absent: {absent_bindings}"
        )

    manifest: dict[str, Any] = {
        "manifest_version": "0.1.0",
        "dataset": {
            "name": "NetsLab-5GORAN-IDD",
            "doi": DATASET_DOI,
            "source_url": "https://netslab.ucd.ie/netslab-datasets/netslab-5goran-idd/",
            "license": {
                "spdx": "CC-BY-4.0",
                "url": "https://creativecommons.org/licenses/by/4.0/",
            },
            "attribution": "NetsLab, University College Dublin",
            "database_filename": database.name,
            "database_sha256": actual_sha256,
            "sqlite_quick_check": quick_check,
            "table": TABLE_NAME,
            "total_row_count": total_rows,
        },
        "selection": {
            "strategy": "exhaustive_label_strata_no_row_sampling",
            "selected_labels": sorted(REPLAY_BINDINGS),
            "excluded_labels_are_reported": True,
            "unit_of_analysis": "action_proposal_not_telemetry_row",
        },
        "strata": strata,
        "legacy_scenario_notes": {
            "tcp_flood": (
                "No exact TCP-flood subcategory exists in this database; no proxy "
                "label is substituted."
            ),
            "udp_port_scan": (
                "The current label is Probe_PortScan and does not establish the "
                "transport protocol; replay uses the broader name port_scan."
            ),
        },
        "interpretation_limit": (
            "Labels provide incident context only; this adapter does not evaluate "
            "detector accuracy or prove mitigation effectiveness."
        ),
        "privacy_note": (
            "Contains aggregate counts and means only; no raw rows, timestamps, UE "
            "identifiers, RNTIs, or cell identifiers are exported."
        ),
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def write_context_manifest(manifest: dict[str, Any], output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
