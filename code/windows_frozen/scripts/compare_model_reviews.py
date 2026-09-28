#!/usr/bin/env python3
"""Validate first model responses and compare decisions using private mappings."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.jsonio import strict_json_load
from oran_trust_boundary.model_review import compare_model_responses


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--round-name", default="model_review_round1")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", args.round_name):
        parser.error("invalid --round-name")
    private = ROOT / "review/private" / args.round_name
    result = compare_model_responses(
        strict_json_load(args.first, maximum_bytes=10 * 1024 * 1024),
        strict_json_load(args.second, maximum_bytes=10 * 1024 * 1024),
        strict_json_load(private / "reviewer_a_private.json", maximum_bytes=5 * 1024 * 1024),
        strict_json_load(private / "reviewer_b_private.json", maximum_bytes=5 * 1024 * 1024),
    )
    output = private / "comparison.json"
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(f"private comparison: {output}")
    print("Model agreement is not human validation or ground-truth accuracy.")


if __name__ == "__main__":
    main()
