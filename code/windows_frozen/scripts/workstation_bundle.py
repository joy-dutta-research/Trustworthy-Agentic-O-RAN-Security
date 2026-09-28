"""Bounded, streaming workstation handoff/return archives; no execution or uploads.

An integrity manifest is not a signature or evidence that an experiment passed.
All attempts are retained. Review local logs before explicitly authorizing export.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "workstation-handoff/1"
MANIFEST = "WORKSTATION_MANIFEST.json"
SOURCE_PREFIX = "oran-workstation-lab"
RETURN_PREFIX = "oran-workstation-results"
CHUNK = 1024 * 1024
# Full-campaign return includes the measured 1,067,137,148-byte census log.
# This transport bound does not change any experiment resource guard.
MAX_FILE = 2 * 1024 * CHUNK
MAX_SOURCE = 2 * 1024 * CHUNK
MAX_RETURN = 16 * 1024 * CHUNK
MAX_METADATA = 16 * CHUNK
MAX_ENTRIES = 100000
SOURCE_TREES = {
    "src": {".py"}, "scripts": {".py", ".ps1"}, "tests": {".py"},
    "configs": {".json"}, "schemas": {".json"}, "docs": {".md", ".tex", ".csv", ".json"},
    "data/workstation_reproduction": {".json", ".jsonl", ".md", ".sha256", ".csv"},
    "reference/university": {".json", ".jsonl", ".md", ".txt", ".csv", ".sha256"},
}
SOURCE_FILES = (
    "WORKSTATION_START_HERE.md", "WORKSTATION_ASSISTANT_PROMPT.txt", "WORKSTATION_RETURN_SCHEMA.md",
    "START_HERE.md", "HOME_ASSISTANT_PROMPT.txt", "README.md", "LICENSE", "SECURITY.md",
    "THREAT_MODEL.md", "DATASET.md", "CHANGELOG.md", "CONTRIBUTING.md", "CITATION.cff",
    "pyproject.toml", ".gitignore", "data/conformance/conformance_v0.1.jsonl",
    "data/conformance/conformance_v0.1.manifest.json", "data/conformance/approval_registry_v0.1.json",
    "data/processed/netslab_contexts_v0.1.json", "data/processed/README.md",
    "stage6_bootstrap/ORAN_STAGE6_PILOT_v2.zip", "stage6_bootstrap/ORAN_STAGE6_PILOT_v2.zip.sha256",
    "results/5gnidd_v0.1_verified/dataset_audit.json",
)
REQUIRED = set(SOURCE_FILES)
RESULT_SUFFIXES = {".json", ".jsonl", ".txt", ".md", ".log", ".csv", ".sha256", ".ready",
                   ".py", ".ps1", ".toml", ".tex", ".cff", ".yaml", ".yml", ".zip"}
RECEIPTS = {"session_receipt.json", "run_receipt.json", "receipt.json", "supervisor_receipt.json",
            "summary.json", "STATUS.json", "COMPLETE.json", "INCOMPLETE.json", "PARTIAL.json"}
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
                    rb"\b(?:sk-proj-|sk-svcacct-)[A-Za-z0-9_-]{20,}|"
                    rb"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}")
WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", re.I)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def clean_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("Invalid archive-relative path")
    parts = value.split("/")
    if PurePosixPath(value).is_absolute() or any(
        p in ("", ".", "..") or p.endswith((".", " ")) or WINDOWS_RESERVED.match(p)
        or any(ord(c) < 32 or c in '<>"|?*' for c in p) for p in parts
    ):
        raise ValueError("Unsafe archive-relative path: " + value)
    return value


def no_links(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symbolic links/reparse paths are not permitted")
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def stream_file(path, destination=None, *, maximum=MAX_FILE, scan_secret=True):
    """Hash/copy one bounded regular file, detecting replacement and mutation."""
    path = no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("Non-regular or oversized artifact: " + path.name)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0
    tail = b""
    with os.fdopen(os.open(path, flags), "rb") as source:
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError("Artifact changed before reading")
        while block := source.read(CHUNK):
            size += len(block)
            if size > maximum:
                raise ValueError("Artifact grew beyond bounded size")
            if scan_secret and SECRET.search(tail + block):
                raise ValueError("Possible credential found; export refused: " + path.name)
            tail = block[-256:]
            digest.update(block)
            if destination is not None:
                destination.write(block)
        after_open = os.fstat(source.fileno())
    after = no_links(path).lstat()
    if size != before.st_size or identity(after_open) != identity(before) or identity(after) != identity(before):
        raise ValueError("Artifact changed while reading: " + path.name)
    return {"sha256": digest.hexdigest(), "bytes": size}


def strict_json(raw):
    if len(raw) > MAX_METADATA:
        raise ValueError("Oversized metadata")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def read_json(path):
    memory = io.BytesIO()
    stream_file(path, memory, maximum=MAX_METADATA)
    return strict_json(memory.getvalue())


def walk_files(directory):
    directory = no_links(directory)
    if not directory.is_dir():
        raise ValueError("Required directory is missing: " + directory.name)
    with os.scandir(directory) as items:
        entries = sorted(items, key=lambda item: item.name)
    for entry in entries:
        path = no_links(Path(entry.path))
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if entry.name != "__pycache__":
                yield from walk_files(path)
        elif stat.S_ISREG(info.st_mode):
            if path.suffix not in {".pyc", ".pyo"}:
                yield path
        else:
            raise ValueError("Non-regular artifact: " + path.name)


def unique_names(payload):
    seen = set()
    for name in payload:
        clean_relative(name)
        folded = name.casefold()
        if folded in seen:
            raise ValueError("Duplicate/case-colliding archive paths")
        seen.add(folded)
    if len(seen) > MAX_ENTRIES:
        raise ValueError("Too many archive entries")
    for name in seen:
        if any(parent.as_posix() in seen for parent in PurePosixPath(name).parents if parent.as_posix() != "."):
            raise ValueError("Archive file/directory prefix collision")


def source_payload(root, *, replay_inputs=True, require=True):
    """Path inventory, not file contents. Unrelated repository trees never enter it."""
    root = no_links(root)
    payload = {}
    for name in SOURCE_FILES:
        path = no_links(root / name)
        if path.exists():
            payload[name] = path
        elif require and name in REQUIRED:
            raise ValueError("Required source file missing: " + name)
    for tree, suffixes in SOURCE_TREES.items():
        if not replay_inputs and tree == "data/workstation_reproduction":
            continue
        directory = no_links(root / tree)
        if not directory.exists():
            if require:
                raise ValueError("Required source tree missing: " + tree)
            continue
        for path in walk_files(directory):
            relative = path.relative_to(root).as_posix()
            if path.name.startswith(".") or path.suffix not in suffixes:
                raise ValueError("Unexpected protected-source artifact: " + relative)
            payload[relative] = path
    unique_names(payload)
    return payload


def record_for(value):
    if isinstance(value, bytes):
        if len(value) > MAX_METADATA or SECRET.search(value):
            raise ValueError("Invalid/secret generated metadata")
        return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    return stream_file(value)


def manifest_for(records, kind):
    return {"format": VERSION, "kind": kind, "created_utc": datetime.now(UTC).isoformat(),
            "files": records, "integrity_note": "SHA-256 detects changes; this is not a publisher signature.",
            "scope_note": "Integrity verification does not establish scientific completion or validity."}


def validate_records(records):
    if not isinstance(records, dict) or not records:
        raise ValueError("Empty/invalid manifest inventory")
    unique_names(records)
    for name, record in records.items():
        if not isinstance(record, dict) or set(record) != {"bytes", "sha256"}:
            raise ValueError("Invalid inventory record: " + name)
        if type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_FILE:
            raise ValueError("Invalid artifact size")
        if not isinstance(record["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", record["sha256"]):
            raise ValueError("Invalid SHA-256")


def validate_result_index(records, index):
    """Bind the human-readable attempt/source index to the exact archived bytes."""
    expected = {"received_source_manifest.json": index["received_manifest_record"]}
    for attempt in index["attempts"]:
        clean_relative(attempt["path"])
        for name, record in attempt["files"].items():
            expected[attempt["path"] + "/" + clean_relative(name)] = record
    for entry in index["imported_stage6_artifacts"]:
        expected[clean_relative(entry["path"])] = {key: entry[key] for key in ("sha256", "bytes")}
    expected.update({"source_snapshot/" + clean_relative(name): record
                     for name, record in index["current_source_snapshot"].items()})
    if any(records.get(name) != record for name, record in expected.items()):
        raise ValueError("Result index differs from archived evidence; a file changed during export")


def write_archive(output, payload, kind):
    output = no_links(output)
    if kind not in {"source", "results"} or output.suffix.lower() != ".zip":
        raise ValueError("Expected source/results kind and .zip output")
    checksum = no_links(Path(str(output) + ".sha256"))
    if output.exists() or checksum.exists():
        raise FileExistsError("Refusing to overwrite ZIP or checksum")
    unique_names(payload)
    if MANIFEST.casefold() in {name.casefold() for name in payload}:
        raise ValueError("Manifest name is reserved")
    maximum = MAX_SOURCE if kind == "source" else MAX_RETURN
    # Bound before creating an archive, then enforce actual copied sizes as well.
    total = sum(len(value) if isinstance(value, bytes) else no_links(value).stat().st_size
                for value in payload.values())
    if total > maximum:
        raise ValueError("Export exceeds bounded total size; never omit failures to shrink it")
    prefix = SOURCE_PREFIX if kind == "source" else RETURN_PREFIX
    output.parent.mkdir(parents=True, exist_ok=True)
    no_links(output.parent)
    records = {}
    copied = 0
    with output.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, value in sorted(payload.items()):
                item = zipfile.ZipInfo(prefix + "/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.create_system = 3
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                with archive.open(item, "w", force_zip64=True) as target:
                    if isinstance(value, bytes):
                        records[name] = record_for(value)
                        target.write(value)
                    else:
                        records[name] = stream_file(value, target)
                copied += records[name]["bytes"]
                if copied > maximum:
                    raise ValueError("Export exceeds bounded total size")
            manifest = encoded(manifest_for(records, kind))
            if kind == "results":
                validate_result_index(records, strict_json(payload["RESULTS_INDEX.json"]))
            if len(manifest) > MAX_METADATA or copied + len(manifest) > maximum:
                raise ValueError("Manifest or total export exceeds bound")
            item = zipfile.ZipInfo(prefix + "/" + MANIFEST, date_time=(2026, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(item, manifest)
    verified = verify_archive(output)
    sha = stream_file(output, maximum=maximum, scan_secret=False)["sha256"]
    with checksum.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(sha + "  " + output.name + "\n")
    return {"zip": str(output), "sha256": sha, "file_count": verified["file_count"],
            "zip_bytes": output.stat().st_size, "kind": kind}


def verify_archive(path, *, legacy=False):
    path = no_links(path)
    if path.stat().st_size > MAX_RETURN:
        raise ValueError("Archive exceeds compressed size bound")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        unique_names([item.filename for item in infos])
        names = {item.filename for item in infos}
        roots = {name.split("/")[0] for name in names}
        source_prefix, return_prefix = ("oran-home-lab", "oran-home-results") if legacy else (SOURCE_PREFIX, RETURN_PREFIX)
        manifest_name = "BUNDLE_MANIFEST.json" if legacy else MANIFEST
        if len(roots) != 1 or not roots <= {source_prefix, return_prefix} or any("/" not in name for name in names):
            raise ValueError("Unexpected archive root")
        prefix = next(iter(roots)) + "/"
        for item in infos:
            mode = item.external_attr >> 16
            if item.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or item.flag_bits & 1 or item.external_attr & 0x400:
                raise ValueError("Unexpected non-regular/encrypted archive member")
            if item.file_size > (128 * CHUNK if legacy else MAX_FILE) or item.file_size < 0:
                raise ValueError("Archive member exceeds size bound")
        manifest_info = archive.getinfo(prefix + manifest_name)
        if manifest_info.file_size > MAX_METADATA:
            raise ValueError("Oversized manifest")
        metadata = strict_json(archive.read(manifest_info))
        kind = "source" if prefix == source_prefix + "/" else "results"
        if metadata.get("format") != ("home-lab-handoff-1" if legacy else VERSION) or metadata.get("kind") != kind:
            raise ValueError("Unsupported manifest")
        records = metadata.get("files")
        validate_records(records)
        maximum = 512 * CHUNK if legacy else (MAX_SOURCE if kind == "source" else MAX_RETURN)
        if sum(item.file_size for item in infos) > maximum:
            raise ValueError("Archive exceeds total size bound")
        if {name[len(prefix):] for name in names} != {*records, manifest_name}:
            raise ValueError("Archive membership does not match manifest")
        for name, expected in records.items():
            digest = hashlib.sha256()
            size = 0
            tail = b""
            with archive.open(prefix + name) as source:
                while block := source.read(CHUNK):
                    size += len(block)
                    if size > expected["bytes"]:
                        raise ValueError("Member exceeds declared size")
                    if SECRET.search(tail + block):
                        raise ValueError("Possible credential found in archive")
                    tail = block[-256:]
                    digest.update(block)
            if expected != {"bytes": size, "sha256": digest.hexdigest()}:
                raise ValueError("Checksum mismatch: " + name)
        if kind == "results" and not legacy:
            index_info = archive.getinfo(prefix + "RESULTS_INDEX.json")
            if index_info.file_size > MAX_METADATA:
                raise ValueError("Oversized results index")
            validate_result_index(records, strict_json(archive.read(index_info)))
    return {"status": "VERIFIED_ARCHIVE", "kind": kind, "file_count": len(records)}


def verify_tree(root):
    root = no_links(root)
    metadata = read_json(root / MANIFEST)
    if metadata.get("format") != VERSION or metadata.get("kind") != "source":
        raise ValueError("A source-bundle manifest is required")
    records = metadata.get("files")
    validate_records(records)
    current = source_payload(root)
    # Only known allowlisted names may be claimed as shipped source.
    if set(records) != set(current):
        raise ValueError("Source membership differs: " + ", ".join(sorted(set(records) ^ set(current))))
    changed = [name for name, path in current.items() if stream_file(path) != records[name]]
    if changed:
        raise ValueError("Source differs from received bundle: " + ", ".join(changed))
    return {"status": "VERIFIED_SOURCE_TREE", "file_count": len(records),
            "manifest_sha256": stream_file(root / MANIFEST)["sha256"]}


def observed_status(path):
    # Path, size, credentials and concurrent changes remain fatal. Only JSON
    # interpretation can fail non-fatally: a crash may leave a truncated receipt.
    memory = io.BytesIO()
    stream_file(path, memory, maximum=MAX_METADATA)
    try:
        value = strict_json(memory.getvalue())
    except (ValueError, UnicodeError):
        return {"classification": "UNPARSEABLE_RECEIPT_RETAINED", "validated": False}
    if not isinstance(value, dict):
        return {"classification": "NONOBJECT_RECEIPT_RETAINED"}
    return {key: value[key] for key in ("status", "completion_status", "mode", "phase", "stage", "dataset")
            if key in value}


def return_payload(root):
    root = no_links(root)
    received = root / MANIFEST
    original = read_json(received)
    if original.get("format") != VERSION or original.get("kind") != "source":
        raise ValueError("Original workstation source manifest required")
    validate_records(original.get("files"))
    payload = {"received_source_manifest.json": received}
    attempts = []
    bases = [("results/local/workstation_runs", None), ("results/local/stage6_runs", None),
             ("results/local/full_campaign_runs", None),
             ("results/evaluation_v0.2", ("s7_", "stage0_", "full_"))]
    for folder, name_prefix in bases:
        base = no_links(root / folder)
        if not base.exists():
            continue
        with os.scandir(base) as listing:
            children = sorted(listing, key=lambda entry: entry.name)
        for entry in children:
            if name_prefix and not entry.name.startswith(name_prefix):
                continue
            session = no_links(Path(entry.path))
            if not session.is_dir() or entry.name.startswith("."):
                raise ValueError("Unexpected file/active lock in run root: " + folder)
            records = {}
            statuses = []
            for path in walk_files(session):
                relative = path.relative_to(root).as_posix()
                if (path.suffix not in RESULT_SUFFIXES and path.name not in {"LICENSE", ".gitignore"}) or (
                    path.name.startswith(".") and path.name != ".gitignore"
                ):
                    raise ValueError("Unexpected result artifact; review before export: " + relative)
                payload[relative] = path
                records[path.relative_to(session).as_posix()] = stream_file(path)
                if path.name in RECEIPTS:
                    statuses.append({"path": path.relative_to(session).as_posix(), "observed": observed_status(path)})
            attempts.append({"path": session.relative_to(root).as_posix(), "files": records,
                             "observed_statuses": statuses,
                             "classification": "STATUS_LABELS_ONLY_NOT_VALIDATED" if statuses else "UNCLASSIFIED_OR_INTERRUPTED_RETAINED"})
    imported = no_links(root / "results/local/stage6_returns")
    imports = []
    if imported.exists():
        for path in walk_files(imported):
            if path.suffix not in {".zip", ".sha256", ".json", ".md", ".txt"} or path.name.startswith("."):
                raise ValueError("Unexpected imported Stage 6 artifact")
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".zip" and verify_archive(path, legacy=True)["kind"] != "results":
                raise ValueError("Imported Stage 6 ZIP is not a legacy results bundle")
            payload[relative] = path
            imports.append({"path": relative, **stream_file(path),
                            "classification": "IMPORTED_ARTIFACT_NOT_SCIENTIFICALLY_VALIDATED",
                            "legacy_zip_integrity_verified": path.suffix == ".zip"})
    if not attempts and not any(item["path"].endswith(".zip") for item in imports):
        raise ValueError("No workstation or Stage 6 attempts exist; nothing has been run")
    source = source_payload(root, replay_inputs=False, require=False)
    source_records = {name: stream_file(path) for name, path in source.items()}
    payload.update({"source_snapshot/" + name: path for name, path in source.items()})
    expected_snapshot = {name: record for name, record in original["files"].items()
                         if not name.startswith("data/workstation_reproduction/")}
    changes = {"modified": sorted(name for name in source_records if name in expected_snapshot
                                   and source_records[name] != expected_snapshot[name]),
               "added": sorted(set(source_records) - set(expected_snapshot)),
               "missing": sorted(set(expected_snapshot) - set(source_records)),
               "replay_inputs_omitted_from_return": "Bound to received manifest; not duplicated in return."}
    # Rehash replay inputs before export without copying their large payloads.
    replay_records = {}
    for name, expected in original["files"].items():
        if name.startswith("data/workstation_reproduction/"):
            path = root / name
            replay_records[name] = {"expected": expected, "observed": stream_file(path) if path.exists() else None}
    payload["SOURCE_CHANGES.json"] = encoded(changes)
    payload["RESULTS_INDEX.json"] = encoded({
        "format": VERSION, "received_manifest_sha256": stream_file(received)["sha256"],
        "received_manifest_record": stream_file(received),
        "attempts": attempts, "imported_stage6_artifacts": imports,
        "current_source_snapshot": source_records, "replay_input_binding": replay_records,
        "selection": "All attempts in prescribed roots, including failures and partial runs; no inferred scientific completion.",
        "privacy": "Owner explicitly authorized sharing after reviewing logs. No automatic upload.",
        "interpretation": "Run receipts, protocols and source/input hashes must be checked before scientific interpretation."})
    payload["READ_RESULTS_FIRST.md"] = (
        "# Returned workstation evidence\n\n"
        "Verify this ZIP, then read RESULTS_INDEX.json and SOURCE_CHANGES.json.\n"
        "Observed status labels are not independently validated successes. Missing\n"
        "receipts mean an interrupted or unclassified attempt, not completion.\n"
        "Check every attempt, qualification, frozen protocol, cleanup record and\n"
        "source/input binding. Recompute claims from raw records; retain failures.\n"
        "Stage 6 imported ZIPs require their own verification and examination.\n"
        "The comparison capsule is in source_snapshot/reference/university.\n"
        "Replay inputs are identified by SHA-256 and not copied back unnecessarily.\n"
        "Do not pool packets as independent experiments, equate policy permission\n"
        "with necessity, or call same-host clean-VM reproduction independent hardware.\n"
        "This package may be partial. Never infer that Orders 6 and 7 are complete\n"
        "because this exporter succeeded. Raw logs may contain private local paths;\n"
        "do not publish or upload automatically.\n").encode("utf-8")
    unique_names(payload)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "verify-tree", "return"):
        child = sub.add_parser(command)
        child.add_argument("--root", type=Path, default=ROOT)
        if command != "verify-tree":
            child.add_argument("--output", type=Path, required=True)
        if command == "return":
            child.add_argument("--reviewed-for-sharing", action="store_true")
    check = sub.add_parser("verify-zip")
    check.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = write_archive(args.output, source_payload(args.root), "source")
        elif args.command == "verify-tree":
            result = verify_tree(args.root)
        elif args.command == "verify-zip":
            result = verify_archive(args.archive)
        else:
            if not args.reviewed_for_sharing:
                parser.error("Review all logs locally, then explicitly use --reviewed-for-sharing")
            result = write_archive(args.output, return_payload(args.root), "results")
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
