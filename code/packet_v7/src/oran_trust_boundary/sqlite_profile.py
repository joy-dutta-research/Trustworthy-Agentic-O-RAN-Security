"""Privacy-conscious structural profiling of the extracted NetsLab database."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


LABEL_COLUMNS = (
    "traffic_type",
    "attack_type",
    "attack_category",
    "attack_subcategory",
    "label",
)
IDENTIFIER_COLUMNS = ("ue_id", "rnti", "cellid")
NUMERIC_TELEMETRY_COLUMNS = (
    "dlBytes",
    "dlMcs",
    "dlBler",
    "ulBytes",
    "ulMcs",
    "ulBler",
    "ri",
    "phr",
    "pcmax",
    "rsrq",
    "sinr",
    "rsrp",
    "rssi",
    "cqi",
    "pucchSnr",
    "puschSnr",
    "in_sync",
)


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def profile_sqlite_database(path: str | Path) -> dict[str, Any]:
    database = Path(path).resolve(strict=True)
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        table_names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        tables: list[dict[str, Any]] = []
        for table_name in table_names:
            quoted_table = _quote_identifier(table_name)
            columns = [
                {
                    "name": row[1],
                    "declared_type": row[2],
                    "not_null": bool(row[3]),
                    "primary_key_position": row[5],
                }
                for row in connection.execute(f"PRAGMA table_info({quoted_table})")
            ]
            column_names = {column["name"] for column in columns}
            label_distributions: dict[str, list[dict[str, Any]]] = {}
            for label_column in LABEL_COLUMNS:
                if label_column not in column_names:
                    continue
                quoted_column = _quote_identifier(label_column)
                distribution = connection.execute(
                    f"SELECT {quoted_column}, COUNT(*) FROM {quoted_table} "
                    f"GROUP BY {quoted_column} ORDER BY COUNT(*) DESC, {quoted_column}"
                ).fetchall()
                label_distributions[label_column] = [
                    {"value": value, "count": count} for value, count in distribution
                ]
            null_counts: dict[str, int] = {}
            for column_name in sorted(column_names):
                quoted_column = _quote_identifier(column_name)
                null_counts[column_name] = connection.execute(
                    f"SELECT COUNT(*) FROM {quoted_table} WHERE {quoted_column} IS NULL"
                ).fetchone()[0]
            identifier_cardinality: dict[str, int] = {}
            for column_name in IDENTIFIER_COLUMNS:
                if column_name not in column_names:
                    continue
                quoted_column = _quote_identifier(column_name)
                identifier_cardinality[column_name] = connection.execute(
                    f"SELECT COUNT(DISTINCT {quoted_column}) FROM {quoted_table}"
                ).fetchone()[0]
            numeric_summaries: dict[str, dict[str, int | float | None]] = {}
            for column_name in NUMERIC_TELEMETRY_COLUMNS:
                if column_name not in column_names:
                    continue
                quoted_column = _quote_identifier(column_name)
                count, minimum, maximum, mean = connection.execute(
                    f"SELECT COUNT({quoted_column}), MIN({quoted_column}), "
                    f"MAX({quoted_column}), AVG({quoted_column}) FROM {quoted_table}"
                ).fetchone()
                numeric_summaries[column_name] = {
                    "non_null_count": count,
                    "minimum": minimum,
                    "maximum": maximum,
                    "mean": mean,
                }
            tables.append(
                {
                    "name": table_name,
                    "row_count": connection.execute(
                        f"SELECT COUNT(*) FROM {quoted_table}"
                    ).fetchone()[0],
                    "columns": columns,
                    "label_distributions": label_distributions,
                    "null_counts": null_counts,
                    "identifier_cardinality": identifier_cardinality,
                    "numeric_summaries": numeric_summaries,
                }
            )
    finally:
        connection.close()
    return {
        "profile_version": "0.2.0",
        "database_filename": database.name,
        "database_size_bytes": database.stat().st_size,
        "database_sha256": _sha256_file(database),
        "sqlite_quick_check": quick_check,
        "tables": tables,
        "privacy_note": (
            "No raw rows or subscriber identifier values are included; "
            "identifier fields are represented only by distinct counts."
        ),
    }


def write_profile(profile: dict[str, Any], output: str | Path) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(profile, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path
