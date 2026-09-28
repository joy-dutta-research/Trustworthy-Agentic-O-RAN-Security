#!/usr/bin/env python3
"""Export a blinded label-review sheet for a co-author."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.benchmark import load_cases
from oran_trust_boundary.review import export_blinded_review


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--suite",
        type=Path,
        default=ROOT / "data" / "conformance" / "conformance_v0.1.jsonl",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--blind-key-file",
        type=Path,
        default=ROOT / "review" / "private" / "blind_key.txt",
    )
    parser.add_argument("--create-blind-key", action="store_true")
    parser.add_argument("--mapping-output", type=Path)
    args = parser.parse_args()
    if args.create_blind_key:
        args.blind_key_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with args.blind_key_file.open("x", encoding="ascii", newline="\n") as handle:
                handle.write(secrets.token_hex(32) + "\n")
        except FileExistsError:
            raise FileExistsError(
                f"refusing to replace existing blind key {args.blind_key_file}"
            )
    if not args.blind_key_file.is_file():
        raise FileNotFoundError(
            "blind key is missing; pass --create-blind-key for the first export"
        )
    key_text = args.blind_key_file.read_text(encoding="ascii").strip()
    try:
        blind_key = bytes.fromhex(key_text)
    except ValueError as exc:
        raise ValueError("blind key file must contain hexadecimal bytes") from exc
    output, mapping = export_blinded_review(
        load_cases(args.suite),
        args.output,
        blind_key=blind_key,
    )
    if args.mapping_output is not None:
        args.mapping_output.parent.mkdir(parents=True, exist_ok=True)
        with args.mapping_output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(mapping, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"private mapping: {args.mapping_output}")
    print(f"review sheet: {output}")


if __name__ == "__main__":
    main()
