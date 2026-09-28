"""Read-only inventory helpers for third-party dataset archives."""

from __future__ import annotations

import csv
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


TABULAR_SUFFIXES = frozenset({".csv", ".tsv", ".json", ".jsonl", ".parquet"})
MAX_HEADER_BYTES = 65_536
MAX_ARCHIVE_MEMBERS = 100_000
MAX_HEADER_COMPRESSION_RATIO = 1_000


def sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return sha256_stream(handle)


def _header_from_binary(handle: BinaryIO, suffix: str) -> list[str] | None:
    if suffix not in {".csv", ".tsv"}:
        return None
    raw_line = handle.readline(MAX_HEADER_BYTES + 1)
    if len(raw_line) > MAX_HEADER_BYTES:
        raise ValueError(f"header exceeds {MAX_HEADER_BYTES} bytes")
    line = raw_line.decode("utf-8-sig", errors="replace")
    delimiter = "\t" if suffix == ".tsv" else ","
    return next(csv.reader([line], delimiter=delimiter), None)


def _unsafe_archive_path(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or ".." in path.parts or bool(path.parts and ":" in path.parts[0])


def _inventory_zip(path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError(f"archive has more than {MAX_ARCHIVE_MEMBERS} members")
        for info in sorted(infos, key=lambda item: item.filename):
            if info.is_dir():
                continue
            suffix = Path(info.filename).suffix.lower()
            item: dict[str, Any] = {
                "path": info.filename,
                "size_bytes": info.file_size,
                "compressed_size_bytes": info.compress_size,
                "crc32": f"{info.CRC:08x}",
                "tabular_candidate": suffix in TABULAR_SUFFIXES,
                "unsafe_archive_path": _unsafe_archive_path(info.filename),
            }
            if suffix in {".csv", ".tsv"}:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > MAX_HEADER_COMPRESSION_RATIO:
                    item["header_error"] = "header skipped due to suspicious compression ratio"
                else:
                    try:
                        with archive.open(info, "r") as handle:
                            item["columns"] = _header_from_binary(handle, suffix)
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                        item["header_error"] = str(exc)[:256]
            members.append(item)
    return {
        "input_type": "zip",
        "input_path": str(path.resolve()),
        "archive_sha256": sha256_file(path),
        "file_count": len(members),
        "total_uncompressed_bytes": sum(item["size_bytes"] for item in members),
        "files": members,
    }


def _inventory_directory(path: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    skipped_symlinks: list[str] = []
    for file_path in sorted(path.rglob("*")):
        if file_path.is_symlink():
            skipped_symlinks.append(file_path.relative_to(path).as_posix())
            continue
        if not file_path.is_file():
            continue
        suffix = file_path.suffix.lower()
        item: dict[str, Any] = {
            "path": file_path.relative_to(path).as_posix(),
            "size_bytes": file_path.stat().st_size,
            "sha256": sha256_file(file_path),
            "tabular_candidate": suffix in TABULAR_SUFFIXES,
        }
        if suffix in {".csv", ".tsv"}:
            try:
                with file_path.open("rb") as handle:
                    item["columns"] = _header_from_binary(handle, suffix)
            except (OSError, ValueError) as exc:
                item["header_error"] = str(exc)[:256]
        files.append(item)
    return {
        "input_type": "directory",
        "input_path": str(path.resolve()),
        "file_count": len(files),
        "skipped_symlinks": skipped_symlinks,
        "files": files,
    }


def inventory_dataset(path: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    if not source.exists():
        raise FileNotFoundError(source)
    if source.is_dir():
        return _inventory_directory(source)
    if source.suffix.lower() == ".zip":
        return _inventory_zip(source)
    return {
        "input_type": "file",
        "input_path": str(source),
        "file_count": 1,
        "archive_sha256": sha256_file(source),
        "files": [
            {
                "path": source.name,
                "size_bytes": source.stat().st_size,
                "tabular_candidate": source.suffix.lower() in TABULAR_SUFFIXES,
            }
        ],
    }


def write_inventory(inventory: dict[str, Any], output: str | Path) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(inventory, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path
