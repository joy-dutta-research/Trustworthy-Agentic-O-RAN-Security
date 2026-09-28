"""Allowlisted source and all-session result ZIPs; no network or experiment execution.

Checksums provide integrity, not publisher authentication. Files are never
overwritten. Review result logs locally before authorizing their export.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.jsonio import strict_json_load

VERSION = "home-lab-handoff-1"
MANIFEST = "BUNDLE_MANIFEST.json"
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
SOURCE_TREES = {"src": {".py"}, "scripts": {".py", ".ps1"},
                "tests": {".py"}, "configs": {".json"}, "schemas": {".json"},
                "docs": {".md", ".tex", ".csv"}}
SOURCE_FILES = ("START_HERE.md", "HOME_ASSISTANT_PROMPT.txt", "README.md", "LICENSE",
                "SECURITY.md", "THREAT_MODEL.md", "DATASET.md", "CHANGELOG.md",
                "CONTRIBUTING.md", "pyproject.toml", ".gitignore",
                "data/conformance/conformance_v0.1.jsonl",
                "data/conformance/conformance_v0.1.manifest.json",
                "data/conformance/approval_registry_v0.1.json",
                "data/processed/netslab_contexts_v0.1.json",
                "data/processed/README.md", "data/raw/README.md",
                "review/README.md", "review/MODEL_REVIEW_GUIDE.md")
RESULT_SUFFIXES = {".json", ".jsonl", ".txt", ".md", ".log", ".csv", ".sha256", ".ready"}
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
                    rb"\b(?:sk-proj-|sk-svcacct-)[A-Za-z0-9_-]{20,}|"
                    rb"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}")


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("Invalid archive-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise ValueError("Unsafe archive-relative path")
    return value


def no_links(path):
    """Reject symlink/reparse ancestors before resolving, including output paths."""
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if not os.path.lexists(part):
            continue
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symbolic links/reparse paths are not permitted")
    return path


def read_regular(path):
    path = no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise ValueError("Non-regular or oversized artifact: " + path.name)
    data = path.read_bytes()
    if len(data) > MAX_FILE or len(data) != info.st_size:
        raise ValueError("Artifact changed while reading")
    if SECRET.search(data):
        raise ValueError("Possible credential found; export refused: " + path.name)
    return data


def walk_files(directory):
    no_links(directory)
    for parent, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in dirs:
            no_links(Path(parent) / name)
        for name in sorted(files):
            path = no_links(Path(parent) / name)
            if path.suffix not in (".pyc", ".pyo"):
                yield path


def source_payload(root):
    root = no_links(root)
    payload = {}
    for name in SOURCE_FILES:
        payload[name] = read_regular(root / name)
    for folder, suffixes in SOURCE_TREES.items():
        for path in walk_files(root / folder):
            if path.suffix in suffixes:
                payload[path.relative_to(root).as_posix()] = read_regular(path)
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ValueError("Source bundle too large")
    return payload


def manifest_for(payload, kind):
    return {"format": VERSION, "kind": kind,
            "created_utc": datetime.now(UTC).isoformat(),
            "files": {name: {"sha256": digest(data), "bytes": len(data)}
                      for name, data in sorted(payload.items())},
            "integrity_note": "Checksums detect changes; they are not digital signatures."}


def write_archive(output, payload, kind, prefix):
    output = no_links(output)
    if output.suffix.lower() != ".zip":
        raise ValueError("Output must end in .zip")
    checksum = Path(str(output) + ".sha256")
    if output.exists() or checksum.exists():
        raise FileExistsError("Refusing to overwrite ZIP or checksum")
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ValueError("Export exceeds bounded artifact size")
    for name in payload:
        clean_relative(name)
    if MANIFEST in payload:
        raise ValueError("Manifest name is reserved")
    manifest = manifest_for(payload, kind)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, data in sorted({**payload, MANIFEST: encoded(manifest)}.items()):
                item = zipfile.ZipInfo(prefix + "/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.create_system = 3
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(item, data)
    # Read the finished archive back, not merely its in-memory source list.
    verified = verify_archive(output)
    archive_hash = hashlib.sha256()
    with output.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            archive_hash.update(block)
    with checksum.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(archive_hash.hexdigest() + "  " + output.name + "\n")
    return {"zip": str(output), "sha256": archive_hash.hexdigest(),
            "file_count": verified["file_count"], "zip_bytes": output.stat().st_size,
            "kind": kind}


def verify_archive(path):
    no_links(path)
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [clean_relative(x.filename) for x in infos]
        if len(names) != len(set(names)) or len(names) != len({n.casefold() for n in names}):
            raise ValueError("Duplicate archive paths")
        roots = {name.split("/")[0] for name in names}
        if len(roots) != 1 or any("/" not in name for name in names):
            raise ValueError("Archive must have one top-level directory")
        prefix = next(iter(roots)) + "/"
        if sum(x.file_size for x in infos) > MAX_TOTAL or any(x.file_size > MAX_FILE for x in infos):
            raise ValueError("Archive exceeds bounded size")
        if any(stat.S_ISLNK(x.external_attr >> 16) or x.is_dir() for x in infos):
            raise ValueError("Unexpected non-regular archive member")
        raw = archive.read(prefix + MANIFEST)
        # Strict JSON parsing without a temporary file.
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate JSON key")
                result[key] = value
            return result
        metadata = json.loads(raw, object_pairs_hook=pairs)
        if metadata.get("format") != VERSION or not isinstance(metadata.get("files"), dict):
            raise ValueError("Unsupported manifest")
        expected = metadata["files"]
        if {n[len(prefix):] for n in names} != {*expected, MANIFEST}:
            raise ValueError("Archive membership does not match manifest")
        for name, record in expected.items():
            clean_relative(name)
            data = archive.read(prefix + name)
            if record != {"sha256": digest(data), "bytes": len(data)}:
                raise ValueError("Checksum mismatch: " + name)
    return {"status": "VERIFIED_ARCHIVE", "kind": metadata["kind"], "file_count": len(expected)}


def verify_tree(root):
    """Verify the received files; generated results/VM files are outside scope."""
    root = no_links(root)
    path = no_links(root / MANIFEST)
    metadata = strict_json_load(path, maximum_bytes=4 * 1024 * 1024)
    if metadata.get("format") != VERSION or metadata.get("kind") != "source":
        raise ValueError("A source-bundle manifest is required")
    expected = metadata.get("files")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("Empty/invalid source manifest")
    changed = []
    for name, record in expected.items():
        clean_relative(name)
        data = read_regular(root / name)
        if record != {"sha256": digest(data), "bytes": len(data)}:
            changed.append(name)
    current = source_payload(root)
    added = sorted(set(current) - set(expected))
    if changed or added:
        raise ValueError("Source differs from received bundle: " + ", ".join(changed + added))
    return {"status": "VERIFIED_SOURCE_TREE", "file_count": len(expected),
            "manifest_sha256": digest(read_regular(path))}


def return_payload(root):
    root = no_links(root)
    base = no_links(root / "results/local/handoff_runs")
    if not base.is_dir():
        raise ValueError("No handoff sessions exist; nothing has been run")
    entries = sorted(base.iterdir())
    if not entries:
        raise ValueError("No handoff sessions exist; nothing has been run")
    payload = {}
    inventory = []
    for session in entries:
        no_links(session)
        if not session.is_dir():
            raise ValueError("Unexpected file in session root; inspect before export")
        count = 0
        session_hashes = {}
        for path in walk_files(session):
            relative = path.relative_to(session).as_posix()
            if path.suffix not in RESULT_SUFFIXES or path.name.startswith("."):
                raise ValueError("Unexpected result artifact; review before export: " + relative)
            data = read_regular(path)
            name = "runs/" + session.name + "/" + relative
            payload[name] = data
            session_hashes[relative] = digest(data)
            count += 1
        # Status is an observed label, not inferred success from the directory.
        receipt = session / "session_receipt.json"
        status = "UNCLASSIFIED_OR_INTERRUPTED_RETAINED"
        if receipt.is_file():
            record = strict_json_load(receipt, maximum_bytes=4 * 1024 * 1024)
            status = record.get("status", status)
        inventory.append({"session": session.name, "reported_status": status,
                          "file_count": count, "files": session_hashes})
    source = source_payload(root)
    payload.update({"source_snapshot/" + name: data for name, data in source.items()})
    original = root / MANIFEST
    original_files = {}
    if original.is_file():
        original_raw = read_regular(original)
        payload["received_source_manifest.json"] = original_raw
        original_files = strict_json_load(original, maximum_bytes=4 * 1024 * 1024).get("files", {})
    changes = {"modified": sorted(name for name in source if name in original_files
                                   and digest(source[name]) != original_files[name].get("sha256")),
               "added": sorted(set(source) - set(original_files)),
               "missing": sorted(set(original_files) - set(source)),
               "baseline_manifest_present": bool(original_files)}
    payload["SOURCE_CHANGES.json"] = encoded(changes)
    payload["RESULTS_INDEX.json"] = encoded({"format": VERSION, "sessions": inventory,
        "selection": "All session directories, including unsuccessful and interrupted attempts.",
        "claim_boundary": "Measured pilot only if raw records establish completion; no live LLM or real O-RAN test.",
        "privacy": "Owner explicitly reviewed for sharing; raw artifacts retained unchanged."})
    payload["READ_RESULTS_FIRST.md"] = (
        "# Returned home-lab evidence\n\n"
        "Start with RESULTS_INDEX.json, SOURCE_CHANGES.json, and each runs/*/session_receipt.json.\n"
        "Missing receipts indicate an interrupted/unclassified session, not success.\n"
        "Read qualification records and unit-test logs before packet REPORT.md.\n"
        "Recompute outcomes from raw episodes, cohorts, controller and kernel logs; do not\n"
        "treat summary text or assistant narrative as ground truth. Match source/config\n"
        "hashes to each run. Include failed attempts and check cleanup and offered load.\n"
        "These are deterministic-controller PILOT results, not confirmatory research,\n"
        "an LLM evaluation, an IDS benchmark, radio/E2 validation or proof of safety.\n"
        "Do not pool packets/variants as independent trials. Do not tune then silently\n"
        "replace results. Decide the next frozen evaluation after inspecting this bundle.\n"
        "Raw logs may contain local paths; do not publish automatically.\n"
    ).encode()
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ValueError("Result package too large; do not omit failures to shrink it")
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="Create an allowlisted source ZIP")
    build.add_argument("--output", type=Path, required=True)
    sub.add_parser("verify-tree", help="Verify extracted source against its manifest")
    check = sub.add_parser("verify-zip", help="Check archive without extracting it")
    check.add_argument("archive", type=Path)
    export = sub.add_parser("return", help="Export ALL home-lab sessions and current source")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--reviewed-for-sharing", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = write_archive(args.output, source_payload(ROOT), "source", "oran-home-lab")
        elif args.command == "verify-tree":
            result = verify_tree(ROOT)
        elif args.command == "verify-zip":
            result = verify_archive(args.archive)
        else:
            if not args.reviewed_for_sharing:
                parser.error("Read all logs locally first; then explicitly use --reviewed-for-sharing")
            result = write_archive(args.output, return_payload(ROOT), "results", "oran-home-results")
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
