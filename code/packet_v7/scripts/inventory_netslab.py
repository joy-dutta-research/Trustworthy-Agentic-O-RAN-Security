#!/usr/bin/env python3
"""Create a privacy-conscious, read-only inventory of the NetsLab download."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.inventory import inventory_dataset, write_inventory


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="Downloaded archive or extracted directory")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "local" / "netslab_inventory.json",
    )
    args = parser.parse_args()
    inventory = inventory_dataset(args.source)
    output = write_inventory(inventory, args.output)
    print(f"inventoried {inventory['file_count']} files")
    print(f"inventory: {output}")


if __name__ == "__main__":
    main()

