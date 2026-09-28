#!/usr/bin/env python3
"""Create deterministic, de-identified dataset contexts for incident replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.netslab_adapter import (
    build_context_manifest,
    write_context_manifest,
)


def _receipt_digest(path: Path) -> str:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    digest = receipt.get("member_sha256")
    if not isinstance(digest, str):
        raise ValueError(f"receipt {path} has no member_sha256")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "database",
        type=Path,
        nargs="?",
        default=ROOT / "data" / "raw" / "Lower_Layer_Data.db",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=ROOT / "data" / "raw" / "extraction_receipt.json",
    )
    parser.add_argument("--expected-sha256")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "processed" / "netslab_contexts_v0.1.json",
    )
    args = parser.parse_args()
    expected_sha256 = args.expected_sha256 or _receipt_digest(args.receipt)
    manifest = build_context_manifest(
        args.database,
        expected_sha256=expected_sha256,
    )
    output = write_context_manifest(manifest, args.output)
    selected = sum(item["selected_for_replay"] for item in manifest["strata"])
    print(f"dataset_sha256={manifest['dataset']['database_sha256']}")
    print(f"rows={manifest['dataset']['total_row_count']}")
    print(f"strata={len(manifest['strata'])} selected={selected}")
    print(f"manifest_sha256={manifest['manifest_sha256']}")
    print(f"output={output}")


if __name__ == "__main__":
    main()
