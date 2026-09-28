#!/usr/bin/env python3
"""Prepare a new verified scientific checkout; never execute its contents.

Python 3.11+, standard library only. Public source snapshots are pinned below.
These omit a legacy manuscript template but preserve all scientific source bytes.
No installation, network request, VM operation or experiment is performed.
The destination must not exist. Interrupted output is preserved for inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = {
    "windows": {
        "name": "ORAN_WORKSTATION_PUBLIC_v1.zip",
        "sha256": "9c031dadfd9d22cd20b94a54515159d0a5cf6fb9d989e98f66fabcd57f363609",
        "original_archive_sha256": "d842312a8e8c10661ae1838e2504aa3c1fed3140e714ea872972d31c70d3be5c",
        "prefix": "oran-workstation-lab/",
        "manifest": "WORKSTATION_MANIFEST.json",
    },
    "packet": {
        "name": "ORAN_PACKET_V7_PUBLIC_v1.zip",
        "sha256": "c5c111106dbe4af49e27c933800f5851afc803947395d044f90e1681655dee29",
        "original_archive_sha256": "c439be5ae5ee5896f01617f0c2ffc4a0a4b20003f187a46542f7bf85a7d19f19",
        "prefix": "oran-transport-v7/",
        "manifest": "BUNDLE_MANIFEST.json",
    },
}
METADATA = {
    "data/raw/extraction_receipt.json": "c39cfa5fd4febfad79e180d62cdd1124dbff4f5261cbe0ee681e6114ec03a251",
    "data/raw/5g-nidd/provenance-8f9772c704659a01.json": "8f9772c704659a01f21e3522d323aeb964a10f1dbed3f700bf086a95e1dcad1e",
}
DATASETS = {
    "netslab": ("data/raw/Lower_Layer_Data.db", 5402624, "d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64"),
    "nidd": ("data/raw/5g-nidd/Combined.zip", 28028224, "07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d"),
}
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9]|LPT[1-9])(?:\.|$)", re.IGNORECASE)
MAX_MEMBERS = 10000
MAX_TOTAL_BYTES = 2 * 1024 ** 3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_stream(stream):
    result = hashlib.sha256()
    length = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(chunk)
        length += len(chunk)
    return result.hexdigest(), length


def file_identity(path):
    with path.open("rb") as stream:
        return digest_stream(stream)


def checked_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def safe_relative(name):
    """Accept only unambiguous relative portable paths, never Windows aliases."""
    require(isinstance(name, str) and bool(name), "Empty member name")
    require("\\" not in name and not name.startswith("/"), f"Absolute/backslash member: {name!r}")
    require("//" not in name, f"Repeated separator: {name!r}")
    parts = name.rstrip("/").split("/")
    require(all(part not in ("", ".", "..") for part in parts), f"Traversal/empty member: {name!r}")
    for part in parts:
        require(all(32 <= ord(ch) < 127 for ch in part), f"Non-portable member: {name!r}")
        require(not any(ch in ':<>|?*' for ch in part), f"ADS/reserved-character member: {name!r}")
        require(not part.endswith((" ", ".")), f"Ambiguous trailing character: {name!r}")
        require(not RESERVED.match(part), f"Windows device member: {name!r}")
    return PurePosixPath(*parts)


def validate_members(archive, prefix):
    """Validate every entry before any path is created; return stripped paths."""
    require(prefix.endswith("/"), "Invalid source archive prefix")
    entries = archive.infolist()
    require(0 < len(entries) <= MAX_MEMBERS, "Unexpected archive member count")
    require(sum(info.file_size for info in entries) <= MAX_TOTAL_BYTES, "Archive exceeds size budget")
    found, component_spellings, result = {}, {}, []
    for info in entries:
        require(info.filename == info.orig_filename, "Archive filename contains a NUL truncation")
        safe_relative(info.filename)
        require(info.filename.startswith(prefix), f"Unexpected archive root: {info.filename!r}")
        relative = info.filename[len(prefix):]
        require(bool(relative), "Explicit root-only archive members are not used by these snapshots")
        path = safe_relative(relative)
        mode_type = stat.S_IFMT(info.external_attr >> 16)
        allowed_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
        require(mode_type in (0, allowed_type), f"Link/special-file member rejected: {relative}")
        require(not (info.external_attr & 0x400), f"Reparse-point member rejected: {relative}")
        require(not (info.flag_bits & 1), f"Encrypted member rejected: {relative}")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Unsupported ZIP compression")
        key = str(path).casefold()
        require(key not in found, f"Duplicate/case-fold member: {relative}")
        found[key] = info.is_dir()
        for count in range(1, len(path.parts) + 1):
            component = "/".join(path.parts[:count])
            folded = component.casefold()
            require(folded not in component_spellings or component_spellings[folded] == component,
                    f"Inconsistent directory spelling: {relative}")
            component_spellings[folded] = component
        result.append((info, path))
    for key in found:
        parts = key.split("/")
        for count in range(1, len(parts)):
            ancestor = "/".join(parts[:count])
            require(ancestor not in found or found[ancestor], f"File used as directory: {key}")
    return result


def verify_manifest(archive, members, manifest_name):
    """Rehash all files and enforce the public source manifest membership."""
    files = {str(path): info for info, path in members if not info.is_dir()}
    require(manifest_name in files, "Source manifest is missing")
    manifest = checked_json(archive.read(files[manifest_name]))
    require(isinstance(manifest.get("files"), dict), "Invalid source manifest")
    require(set(manifest["files"]) == set(files) - {manifest_name}, "Source manifest membership differs")
    identities = {}
    for name, expected in manifest["files"].items():
        safe_relative(name)
        with archive.open(files[name]) as stream:
            actual_hash, actual_size = digest_stream(stream)
        require(actual_hash == expected["sha256"] and actual_size == expected["bytes"],
                f"Source member identity mismatch: {name}")
        identities[name] = {"sha256": actual_hash, "bytes": actual_size}
    return identities


def reject_link_ancestors(path):
    """Reject existing symlinks/junctions rather than resolve through them."""
    for candidate in (path, *path.parents):
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(details.st_mode), f"Symlink path component: {candidate.name}")
        require(not (getattr(details, "st_file_attributes", 0) & 0x400),
                f"Reparse-point path component: {candidate.name}")


def checked_copy(source, destination, expected_hash, expected_size=None):
    """Exclusive creation and post-copy identity check; input is untouched."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    actual_hash, actual_size = file_identity(destination)
    require(actual_hash == expected_hash and (expected_size is None or actual_size == expected_size),
            f"Copied input identity mismatch: {destination.name}")
    return {"path": destination.name, "sha256": actual_hash, "bytes": actual_size}


def prepare(kind, destination, netslab_db=None, nidd_zip=None, repository=ROOT):
    require(kind in SNAPSHOTS, "Unknown workspace kind")
    require((netslab_db is None) == (nidd_zip is None), "Supply both --netslab-db and --nidd-zip, or neither")
    require(kind == "windows" or netslab_db is None, "Dataset flags apply only to the Windows workspace")
    destination = Path(os.path.abspath(destination))
    receipt_path = destination.with_name(destination.name + ".preparation.json")
    reject_link_ancestors(destination)
    reject_link_ancestors(receipt_path)
    require(not destination.exists(), "Destination already exists; choose a new path")
    require(not receipt_path.exists(), "Preparation receipt already exists; choose a new path")
    spec = SNAPSHOTS[kind]
    source = repository / "evidence/source_snapshots" / spec["name"]
    archive_hash, archive_bytes = file_identity(source)
    require(archive_hash == spec["sha256"], "Public snapshot SHA-256 mismatch; nothing extracted")
    additions = []
    if kind == "windows":
        freeze = checked_json((repository / "code/windows_frozen/configs/full_campaign_freeze.json").read_bytes())
        freeze_hashes = {entry["path"]: entry["expected_sha256"] for entry in freeze["files"]}
        for relative, expected_hash in METADATA.items():
            metadata_source = repository / "code/windows_frozen" / relative
            actual_hash, length = file_identity(metadata_source)
            require(actual_hash == expected_hash == freeze_hashes.get(relative), f"Acquisition metadata differs: {relative}")
            additions.append((metadata_source, relative, actual_hash, length, "historical_acquisition_metadata"))
        if netslab_db is not None:
            for label, input_path in (("netslab", netslab_db), ("nidd", nidd_zip)):
                relative, expected_size, expected_hash = DATASETS[label]
                input_path = Path(input_path)
                actual_hash, length = file_identity(input_path)
                require((actual_hash, length) == (expected_hash, expected_size), f"{label} input SHA-256/size mismatch")
                additions.append((input_path, relative, actual_hash, length, "research_dataset_input"))
    with zipfile.ZipFile(source) as archive:
        members = validate_members(archive, spec["prefix"])
        identities = verify_manifest(archive, members, spec["manifest"])
        archive_paths = {str(path).casefold() for _, path in members}
        for _, relative, _, _, _ in additions:
            require(relative.casefold() not in archive_paths, f"Imported input would replace a source file: {relative}")
        # Recheck immediately before exclusive creation. Local setup assumes no hostile
        # process is concurrently replacing parent directories or modifying source ZIPs.
        reject_link_ancestors(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        receipt = {
            "schema_version": 1, "status": "preparing", "kind": kind,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "workspace_name": destination.name,
            "snapshot": {"filename": spec["name"], "sha256": archive_hash, "bytes": archive_bytes},
            "source_manifest": spec["manifest"], "source_manifest_file_count": len(identities),
            "public_packaging": {
                "original_archive_sha256": spec["original_archive_sha256"],
                "omitted_template": "docs/paper/closed_loop_experiment.tex",
                "scientific_source_bytes_preserved": True,
                "record": "evidence/source_snapshots/PUBLIC_SOURCE_OMISSIONS.json",
            },
            "added_inputs": [], "executed_code": False,
            "mode": "full_dataset_inputs_available" if netslab_db is not None else ("software_tests_only" if kind == "windows" else "packet_source_prepared_no_execution"),
            "note": "The public snapshot and its regenerated transport manifest are verified. The legacy manuscript template is omitted; scientific source, configuration and test bytes are unchanged from the historical bundle. Added historical metadata/dataset inputs are listed separately. This receipt is outside the workspace. No scientific run has occurred.",
        }
        with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, indent=2)
            handle.write("\n")
        try:
            destination.mkdir(exist_ok=False)
            for info, relative in members:
                target = destination.joinpath(*relative.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                if str(relative) in identities:
                    require(file_identity(target) == (identities[str(relative)]["sha256"], identities[str(relative)]["bytes"]),
                            f"Extracted file identity mismatch: {relative}")
            for input_path, relative, expected_hash, length, purpose in additions:
                record = checked_copy(input_path, destination / relative, expected_hash, length)
                record.update(path=relative, purpose=purpose)
                receipt["added_inputs"].append(record)
            require(file_identity(source)[0] == archive_hash, "Public source archive changed during preparation")
            receipt["status"] = "complete"
        except Exception as error:
            receipt["status"] = "incomplete"
            receipt["error_type"] = type(error).__name__
            receipt["recovery"] = "Partial files are preserved; inspect the receipt and choose a new destination. Nothing was executed."
            raise
        finally:
            # This file was exclusively created by this invocation and is not a source.
            with receipt_path.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(receipt, handle, indent=2)
                handle.write("\n")
    return receipt_path, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=SNAPSHOTS, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--netslab-db", type=Path)
    parser.add_argument("--nidd-zip", type=Path)
    args = parser.parse_args()
    try:
        receipt_path, receipt = prepare(args.kind, args.destination, args.netslab_db, args.nidd_zip)
    except (ValueError, OSError, zipfile.BadZipFile, KeyError) as error:
        print(f"Preparation stopped: {error}", file=sys.stderr)
        return 1
    print(f"Prepared {args.kind} source: {args.destination}")
    print(f"Mode: {receipt['mode']}. No code, experiments or VM operations were executed.")
    print(f"Preparation receipt: {receipt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
