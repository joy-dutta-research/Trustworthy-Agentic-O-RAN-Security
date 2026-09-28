#!/usr/bin/env python3
"""Inspect schema, integrity, row counts, and label counts without raw rows."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.sqlite_profile import profile_sqlite_database, write_profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "database",
        type=Path,
        nargs="?",
        default=ROOT / "data" / "raw" / "Lower_Layer_Data.db",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "local" / "netslab_db_profile.json",
    )
    args = parser.parse_args()
    profile = profile_sqlite_database(args.database)
    output = write_profile(profile, args.output)
    print(f"integrity={profile['sqlite_quick_check']}")
    for table in profile["tables"]:
        print(f"table={table['name']} rows={table['row_count']}")
        for label, distribution in table["label_distributions"].items():
            print(f"{label}={distribution}")
    print(f"profile={output}")


if __name__ == "__main__":
    main()

