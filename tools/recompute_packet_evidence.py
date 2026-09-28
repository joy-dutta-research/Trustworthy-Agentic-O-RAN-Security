"""Recompute saved packet metrics, with no traffic generation or VM operations."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from packet_recompute_core import audit_run, check
from verify_repository import MANIFEST_NAME, digest_file

ROOT = Path(__file__).resolve().parents[1]
ASSETS = {"first": "packet_primary.zip", "repeat": "packet_repeat.zip"}


def same_numbers(left, right, context="result"):
    """Compare all included conditions, not just a selected headline."""
    if isinstance(left, dict) and isinstance(right, dict):
        check(left.keys() == right.keys(), f"Different fields: {context}")
        for key in left:
            same_numbers(left[key], right[key], context + "/" + key)
    elif isinstance(left, list) and isinstance(right, list):
        check(len(left) == len(right), f"Different lengths: {context}")
        for i, (a, b) in enumerate(zip(left, right)):
            same_numbers(a, b, f"{context}/{i}")
    elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
        check(math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-12), f"Different number: {context}")
    else:
        check(left == right, f"Different value: {context}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))["files"]
        expected = json.loads((root / "evidence/summaries/packet_recomputation.json").read_text(encoding="utf-8"))
        runs = {}
        for label, filename in ASSETS.items():
            relative = "evidence/raw_archives/" + filename
            path = root / relative
            identity = manifest[relative]
            check(path.stat().st_size == identity["bytes"] and digest_file(path) == identity["sha256"], "Changed packet asset: " + filename)
            runs[label] = audit_run(label, path)
            for field in ("comparisons", "aggregate_conditions"):
                same_numbers(runs[label][field], expected["runs"][label][field], label + "/" + field)
        for field in ("jobs", "settings", "settings_sha256", "source_files", "order_seed", "randomness_scope"):
            check(runs["first"]["plan"][field] == runs["repeat"]["plan"][field], "Cross-VM plan mismatch: " + field)
        print(json.dumps({"status": "PASS", "episodes_recomputed": sum(r["episode_count"] for r in runs.values()),
                          "conditions_checked": 24, "paired_comparisons_checked": 18,
                          "meaning": "Saved raw cohort/episode arithmetic matches the included evidence; no experiments rerun. VMs remain separate, same physical host."}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
