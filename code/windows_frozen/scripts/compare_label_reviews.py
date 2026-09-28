#!/usr/bin/env python3
"""Compare two completed blinded review sheets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.review import compare_reviews, load_review


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    comparison = compare_reviews(load_review(args.first), load_review(args.second))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"agreement={comparison['observed_agreement']:.3f}")
    print(f"cohens_kappa={comparison['cohens_kappa']:.3f}")
    print(f"comparison: {args.output}")


if __name__ == "__main__":
    main()

