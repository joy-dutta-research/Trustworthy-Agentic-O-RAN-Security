#!/usr/bin/env python3
"""Generate the versioned conformance suite and its manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.conformance import (
    SUITE_VERSION,
    approval_registry,
    generate_cases,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "conformance" / "conformance_v0.1.jsonl",
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    cases = list(generate_cases())
    encoded_lines = [
        json.dumps(case, sort_keys=True, separators=(",", ":")) for case in cases
    ]
    encoded = ("\n".join(encoded_lines) + "\n").encode("utf-8")
    args.output.write_bytes(encoded)

    registry = approval_registry(cases)
    registry_path = args.output.parent / "approval_registry_v0.1.json"
    registry_encoded = (
        json.dumps(registry, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    registry_path.write_bytes(registry_encoded)

    manifest = {
        "suite_version": SUITE_VERSION,
        "case_count": len(cases),
        "category_counts": dict(sorted(Counter(case["category"] for case in cases).items())),
        "expected_decision_counts": dict(
            sorted(Counter(case["expected_decision"] for case in cases).items())
        ),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "approval_registry_sha256": hashlib.sha256(registry_encoded).hexdigest(),
        "dataset_bindings": {
            "NetsLab-5GORAN-IDD": {
                "lower_layer_database_sha256": next(
                    case["source_context"]["dataset_binding"]["lower_layer_database_sha256"]
                    for case in cases
                    if case["source_context"]["kind"] == "dataset_label_scenario"
                ),
                "attack_subcategories": sorted(
                    {
                        case["source_context"]["dataset_binding"]["attack_subcategory"]
                        for case in cases
                        if case["source_context"]["kind"] == "dataset_label_scenario"
                    }
                ),
            }
        },
    }
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {args.output}")
    print(f"manifest: {manifest_path}")
    print(f"approval registry: {registry_path}")


if __name__ == "__main__":
    main()
