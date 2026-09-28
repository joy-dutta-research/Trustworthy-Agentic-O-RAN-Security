#!/usr/bin/env python3
"""Prepare two independent blinded model-review packages; make no API calls."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.benchmark import load_cases
from oran_trust_boundary.jsonio import strict_json_load
from oran_trust_boundary.model_review import prepare_packages


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=ROOT / "data/conformance/conformance_v0.1.jsonl")
    parser.add_argument("--policy", type=Path, default=ROOT / "configs/paper_policy.json")
    parser.add_argument("--schema", type=Path, default=ROOT / "schemas/action.schema.json")
    parser.add_argument("--approval-registry", type=Path, default=ROOT / "data/conformance/approval_registry_v0.1.json")
    parser.add_argument("--round-name", default="model_review_round1")
    args = parser.parse_args()
    archives = prepare_packages(
        ROOT, load_cases(args.suite), strict_json_load(args.policy, maximum_bytes=1024 * 1024),
        strict_json_load(args.schema, maximum_bytes=1024 * 1024),
        strict_json_load(args.approval_registry, maximum_bytes=5 * 1024 * 1024),
        round_name=args.round_name,
    )
    for archive in archives:
        print(f"reviewer archive: {archive}")
    print("Never upload review/private. No model was called and no result was generated.")


if __name__ == "__main__":
    main()
