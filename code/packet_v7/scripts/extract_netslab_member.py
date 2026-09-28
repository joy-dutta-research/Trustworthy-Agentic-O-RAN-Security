#!/usr/bin/env python3
"""Safely extract one explicitly named, size-bounded dataset member."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath


DEFAULT_MEMBER = "Lower_Layer_Data.db"
MAX_MEMBER_BYTES = 100 * 1024 * 1024


def validate_member_name(name: str) -> None:
    normalized = PurePosixPath(name.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts or ":" in normalized.parts[0]:
        raise ValueError("unsafe archive member path")
    if normalized.as_posix() != name.replace("\\", "/"):
        raise ValueError("archive member path is not canonical")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--member", default=DEFAULT_MEMBER)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "raw" / DEFAULT_MEMBER,
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    archive_path = args.archive.resolve(strict=True)
    validate_member_name(args.member)
    output_path = args.output.resolve()
    raw_root = (Path(__file__).resolve().parents[1] / "data" / "raw").resolve()
    if output_path.parent != raw_root:
        raise ValueError(f"output must be directly inside {raw_root}")
    if output_path.exists() and not args.overwrite:
        raise FileExistsError(f"refusing to overwrite {output_path}; pass --overwrite explicitly")

    with zipfile.ZipFile(archive_path) as archive:
        matches = [info for info in archive.infolist() if info.filename == args.member]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one {args.member!r}, found {len(matches)}")
        info = matches[0]
        if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(
                f"member size {info.file_size} is outside 1-{MAX_MEMBER_BYTES} bytes"
            )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        partial_path = output_path.with_suffix(output_path.suffix + ".partial")
        if partial_path.exists():
            partial_path.unlink()
        try:
            with archive.open(info, "r") as source, partial_path.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            if partial_path.stat().st_size != info.file_size:
                raise ValueError("extracted size does not match archive metadata")
            os.replace(partial_path, output_path)
        finally:
            if partial_path.exists():
                partial_path.unlink()

    receipt = {
        "receipt_version": "0.1.0",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "archive_filename": archive_path.name,
        "member": args.member,
        "member_size_bytes": output_path.stat().st_size,
        "member_crc32": f"{info.CRC:08x}",
        "member_sha256": sha256_file(output_path),
    }
    receipt_path = raw_root / "extraction_receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"extracted: {output_path}")
    print(f"receipt: {receipt_path}")
    print(f"member_sha256: {receipt['member_sha256']}")


if __name__ == "__main__":
    main()

