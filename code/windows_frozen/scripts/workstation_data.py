"""Private same-user research-data companion; no downloads, execution or uploads.

The two raw files are pinned to the exact original experiment bytes. Do not put
this companion in the public code repository or return it with derived results.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import workstation_bundle as bundle

FORMAT = "private-research-data-companion/1"
PREFIX = "oran-workstation-private-data"
MANIFEST = "PRIVATE_DATA_MANIFEST.json"
MAX_TOTAL = 64 * 1024 ** 2
MAX_FILE = 32 * 1024 ** 2
RAW = {
    "data/raw/Lower_Layer_Data.db": {"bytes": 5402624,
        "sha256": "d76fe7df11379223948e624d0f19bcd5caf744a2b6ce20d1ee2143644199ab64"},
    "data/raw/5g-nidd/Combined.zip": {"bytes": 28028224,
        "sha256": "07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d"},
}
RECEIPT = "data/raw/extraction_receipt.json"
PROVENANCE = "data/raw/5g-nidd/provenance-8f9772c704659a01.json"
ATTRIBUTION = "DATASET.md"
NOTICE = "PRIVATE_DATA_README.md"
MEMBERS = {*RAW, RECEIPT, PROVENANCE, ATTRIBUTION, NOTICE}
PROVENANCE_URLS = {
    "dataset_doi": "https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361",
    "descriptor_doi": "https://doi.org/10.1109/IEEEDATA.2025.3592888",
    "metadata_url": "https://metax.fairdata.fi/v3/datasets/9d13ef28-2ca7-44b0-9950-225359afac65",
    "files_url": "https://metax.fairdata.fi/v3/datasets/9d13ef28-2ca7-44b0-9950-225359afac65/files?pagination=false",
}


def small_bytes(path):
    target = io.BytesIO()
    bundle.stream_file(path, target, maximum=1024 ** 2)
    return target.getvalue()


def checked_receipt(raw):
    value = bundle.strict_json(raw)
    if not isinstance(value, dict) or set(value) != {"archive_filename", "created_at", "member", "member_crc32",
                                                    "member_sha256", "member_size_bytes", "receipt_version"}:
        raise ValueError("Unexpected extraction receipt fields")
    expected = RAW["data/raw/Lower_Layer_Data.db"]
    if value["member"] != "Lower_Layer_Data.db" or value["member_sha256"] != expected["sha256"] or value["member_size_bytes"] != expected["bytes"]:
        raise ValueError("Extraction receipt does not identify the pinned NetsLab input")
    if value["archive_filename"] != "archive.zip" or value["member_crc32"] != "15d7cdc9" or value["receipt_version"] != "0.1.0":
        raise ValueError("Unexpected extraction receipt provenance")
    if not isinstance(value["created_at"], str) or len(value["created_at"]) > 40:
        raise ValueError("Invalid extraction time")
    return value


def sanitized_provenance(raw):
    value = bundle.strict_json(raw)
    if not isinstance(value, dict):
        raise ValueError("Provenance must be an object")
    # Select only public publication metadata, not arbitrary acquisition fields.
    keys = {"access", "archive", "archive_members", "dataset_doi", "dataset_id", "descriptor_doi",
            "files_url", "license", "metadata_modified", "metadata_url", "receipt_version", "title",
            "verified_sha256", "version"}
    sanitized = {key: value[key] for key in keys if key in value}
    expected = RAW["data/raw/5g-nidd/Combined.zip"]
    if set(sanitized) != keys or sanitized["verified_sha256"] != expected["sha256"]:
        raise ValueError("Provenance lacks the pinned 5G-NIDD checksum")
    archive = sanitized["archive"]
    archive_keys = {"checksum", "filename", "frozen", "id", "modified", "pathname", "size", "storage_identifier"}
    if not isinstance(archive, dict) or not archive_keys <= set(archive):
        raise ValueError("Invalid archive provenance")
    sanitized["archive"] = {key: archive[key] for key in archive_keys}
    if archive["checksum"] != "sha256:" + expected["sha256"] or archive["size"] != expected["bytes"] or archive["filename"] != "Combined.zip" or archive["pathname"] != "/Combined.zip":
        raise ValueError("Archive provenance does not match pinned input")
    if sanitized["license"] != "https://creativecommons.org/licenses/by/4.0/" or sanitized["access"] != "open":
        raise ValueError("Unexpected frozen dataset licence metadata")
    if any(sanitized[key] != expected for key, expected in PROVENANCE_URLS.items()):
        raise ValueError("Unexpected or potentially private provenance URL")
    # Reject local paths, query tokens and unusually large metadata even in the
    # selected fields. Exact raw bytes remain authoritative, not this metadata.
    serialized = bundle.encoded(sanitized)
    scanned = serialized.replace(b"?pagination=false", b"")
    if len(serialized) > 16384 or bundle.SECRET.search(serialized) or b"?" in scanned or b"C:\\" in serialized or b"/home/" in serialized or b"/Users/" in serialized:
        raise ValueError("Potentially private provenance refused")
    return sanitized


def notice():
    return (
        "# Private same-user research transfer\n\n"
        "This separate companion contains the two frozen raw research inputs.\n"
        "It is not part of the public code package and must not be automatically\n"
        "uploaded, committed, or included in the final results return ZIP.\n"
        "Raw datasets may contain network identifiers. Use only for the owner's\n"
        "authorized research on the destination machine. See DATASET.md for\n"
        "creator attribution, original sources, the recorded CC BY 4.0 notices\n"
        "and source-versus-data licence distinction. This notice does not replace\n"
        "the dataset licence or establish any new redistribution permission.\n"
        "The 24 GB parent NetsLab archive is intentionally absent: the pinned\n"
        "5.4 MB SQLite member is the full input used by these experiments.\n"
        "5G-NIDD's original Combined.zip is copied unchanged, not extracted here.\n"
        "SHA-256 verifies file identity, not publisher authenticity.\n"
        "Import verifies all members first, then creates only missing allowlisted\n"
        "files. Identical existing files are accepted; differing files are never\n"
        "overwritten. No download, experiment, VM or external action is executed.\n"
    ).encode("utf-8")


def source_payload(root):
    root = bundle.no_links(root)
    payload = {}
    for name, expected in RAW.items():
        path = bundle.no_links(root / name)
        if bundle.stream_file(path, maximum=MAX_FILE, scan_secret=False) != expected:
            raise ValueError("Local raw data differs from frozen experiment: " + name)
        payload[name] = path
    receipt = small_bytes(root / RECEIPT)
    checked_receipt(receipt)
    payload[RECEIPT] = receipt
    payload[PROVENANCE] = bundle.encoded(sanitized_provenance(small_bytes(root / PROVENANCE)))
    payload[ATTRIBUTION] = small_bytes(root / ATTRIBUTION)
    payload[NOTICE] = notice()
    return payload


def write_archive(output, payload):
    output = bundle.no_links(output)
    sidecar = bundle.no_links(Path(str(output) + ".sha256"))
    if output.suffix.lower() != ".zip" or set(payload) != MEMBERS:
        raise ValueError("Expected .zip output and exact private companion inventory")
    if output.exists() or sidecar.exists():
        raise FileExistsError("Refusing to overwrite private ZIP or checksum")
    output.parent.mkdir(parents=True, exist_ok=True)
    bundle.no_links(output.parent)
    records = {}
    with output.open("xb") as target:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, value in sorted(payload.items()):
                item = zipfile.ZipInfo(PREFIX + "/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.create_system = 3
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                with archive.open(item, "w", force_zip64=True) as destination:
                    if isinstance(value, bytes):
                        if len(value) > 1024 ** 2 or bundle.SECRET.search(value):
                            raise ValueError("Invalid or secret companion metadata")
                        destination.write(value)
                        records[name] = {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                    else:
                        records[name] = bundle.stream_file(value, destination, maximum=MAX_FILE, scan_secret=False)
                if name in RAW and records[name] != RAW[name]:
                    raise ValueError("Raw input changed before transfer archive")
            manifest = bundle.encoded({"format": FORMAT, "kind": "private_same_user_research_transfer",
                "files": records, "raw_inputs": RAW, "public_upload_authorized": False,
                "scientific_completion": "NOT_ASSERTED", "privacy": "Private companion; never include in result returns."})
            item = zipfile.ZipInfo(PREFIX + "/" + MANIFEST, date_time=(2026, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(item, manifest)
    verified = verify_archive(output)
    record = bundle.stream_file(output, maximum=MAX_TOTAL, scan_secret=False)
    with sidecar.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(record["sha256"] + "  " + output.name + "\n")
    return {"status": "PRIVATE_COMPANION_CREATED", "zip": str(output), **record,
            "files": len(verified["files"]), "public_upload_authorized": False}


def member_record(archive, name, destination=None):
    digest = hashlib.sha256()
    size = 0
    with archive.open(PREFIX + "/" + name) as source:
        while block := source.read(bundle.CHUNK):
            size += len(block)
            if size > MAX_FILE:
                raise ValueError("Oversized private companion member")
            digest.update(block)
            if destination is not None:
                destination.write(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def verify_archive(path):
    path = bundle.no_links(path)
    if not path.is_file() or path.stat().st_size > MAX_TOTAL:
        raise ValueError("Private companion archive missing or oversized")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        bundle.unique_names([item.filename for item in infos])
        if {item.filename for item in infos} != {PREFIX + "/" + name for name in {*MEMBERS, MANIFEST}}:
            raise ValueError("Unexpected private companion inventory")
        if sum(item.file_size for item in infos) > MAX_TOTAL:
            raise ValueError("Private companion exceeds total bound")
        for item in infos:
            if item.is_dir() or stat.S_IFMT(item.external_attr >> 16) not in {0, stat.S_IFREG} or item.external_attr & 0x400 or item.flag_bits & 1:
                raise ValueError("Unsafe private companion ZIP member")
            if item.file_size > MAX_FILE or item.file_size < 0:
                raise ValueError("Private companion member exceeds bound")
        for name in (MANIFEST, RECEIPT, PROVENANCE, ATTRIBUTION, NOTICE):
            if archive.getinfo(PREFIX + "/" + name).file_size > 1024 ** 2:
                raise ValueError("Oversized companion metadata")
        metadata = bundle.strict_json(archive.read(PREFIX + "/" + MANIFEST))
        if not isinstance(metadata, dict) or metadata.get("format") != FORMAT or metadata.get("kind") != "private_same_user_research_transfer" or metadata.get("public_upload_authorized") is not False:
            raise ValueError("Unsupported private companion manifest")
        records = metadata.get("files")
        bundle.validate_records(records)
        if set(records) != MEMBERS or metadata.get("raw_inputs") != RAW:
            raise ValueError("Private companion inventory/pinned inputs mismatch")
        for name, expected in records.items():
            actual = member_record(archive, name)
            if actual != expected or (name in RAW and actual != RAW[name]):
                raise ValueError("Private companion checksum mismatch: " + name)
        checked_receipt(archive.read(PREFIX + "/" + RECEIPT))
        provenance = archive.read(PREFIX + "/" + PROVENANCE)
        if bundle.strict_json(provenance) != sanitized_provenance(provenance):
            raise ValueError("Unexpected unsanitized provenance fields")
        for name in (RECEIPT, PROVENANCE, ATTRIBUTION, NOTICE):
            if bundle.SECRET.search(archive.read(PREFIX + "/" + name)):
                raise ValueError("Credential found in private companion metadata")
    return metadata


def import_archive(path, root):
    path, root = bundle.no_links(path), bundle.no_links(root)
    before = bundle.stream_file(path, maximum=MAX_TOTAL, scan_secret=False)
    metadata = verify_archive(path)
    # The manifest and notice are retained alongside raw inputs, not placed in
    # source-protected root directories. Attribution stays at its original path.
    targets = {name: root / ("data/raw/PRIVATE_DATA_README.md" if name == NOTICE else name) for name in MEMBERS}
    targets[MANIFEST] = root / "data/raw/PRIVATE_DATA_MANIFEST.json"
    manifest_bytes = bundle.encoded(metadata)
    expected_records = dict(metadata["files"])
    expected_records[MANIFEST] = {"bytes": len(manifest_bytes), "sha256": hashlib.sha256(manifest_bytes).hexdigest()}
    existing, missing = [], []
    # Preflight every target before writing any member; differing files are never
    # overwritten. If interrupted during later writes, partial files remain and
    # must be reviewed instead of silently replaced.
    for name, target in targets.items():
        bundle.no_links(target)
        if target.exists():
            if bundle.stream_file(target, maximum=MAX_FILE, scan_secret=False) != expected_records[name]:
                raise FileExistsError("Existing destination differs; refusing overwrite: " + name)
            existing.append(name)
        else:
            missing.append(name)
    written = []
    with zipfile.ZipFile(path) as archive:
        for name in sorted(missing):
            target = bundle.no_links(targets[name])
            target.parent.mkdir(parents=True, exist_ok=True)
            bundle.no_links(target.parent)
            with target.open("xb") as destination:
                if name == MANIFEST:
                    destination.write(manifest_bytes)
                    actual = expected_records[name]
                else:
                    actual = member_record(archive, name, destination)
            if actual != expected_records[name]:
                raise ValueError("Companion changed during import; retain and inspect partial artifacts")
            written.append(name)
    if bundle.stream_file(path, maximum=MAX_TOTAL, scan_secret=False) != before:
        raise ValueError("Companion changed during import")
    return {"status": "PRIVATE_INPUTS_VERIFIED_AND_IMPORTED", "written": written,
            "identical_existing_preserved": sorted(existing), "archive_sha256": before["sha256"],
            "public_upload_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build-local", action="store_true")
    modes.add_argument("--verify", type=Path)
    modes.add_argument("--import", dest="import_path", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.build_local:
            if args.output is None:
                parser.error("--build-local requires --output")
            result = write_archive(args.output, source_payload(args.root))
        elif args.verify is not None:
            metadata = verify_archive(args.verify)
            result = {"status": "VERIFIED_PRIVATE_COMPANION", "files": len(metadata["files"]), "public_upload_authorized": False}
        else:
            result = import_archive(args.import_path, args.root)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
