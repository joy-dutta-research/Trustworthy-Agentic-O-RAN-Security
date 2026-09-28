#!/usr/bin/env python3
"""Create and verify a bounded, hash-only evaluation baseline (standard library).

Reviewed specification schema (unknown fields are rejected)::

    {
      "schema_version": "evaluation-freeze-spec/v1",
      "files": [{"path": "configs/paper_policy.json",
                 "expected_sha256": "optional 64 lowercase hexadecimal characters"}],
      "trees": [{"path": "src", "suffixes": [".py"],
                 "exclude_dirs": ["__pycache__"]}],
      "provenance_only": [{"artifact_id": "netslab_archive",
                           "receipt": "data/raw/extraction_receipt.json",
                           "sha256_pointer": null, "size_pointer": null}]
    }

All filesystem paths in a spec are nonempty repository-relative POSIX paths.
``suffixes: null`` tracks all regular files in a named tree; an empty list is
invalid. Added files matching that selection are detected by verify. Other
extensions and excluded directory names are explicitly outside that selection.
Files overlapping trees are hashed once. Repeated explicit file entries must
not conflict about their expected hash. The spec itself and provenance receipts
are always directly hashed. JSON pointers use RFC 6901 object/array syntax.

Provenance-only artifacts are NEVER opened or hashed by this program: only the
receipt is opened. A null pointer means the receipt supplies no such fact. A
receipt-reported artifact digest is not a fresh verification of artifact bytes.
No file contents, absolute paths, usernames, hostnames or environment variables
are copied into the manifest. The manifest is an integrity inventory, not a
signature, immutable archive, backup, or authentication of third-party receipts.

``freeze --spec PATH [--root ROOT]`` creates a NEW stage0 directory exclusively
inside ROOT/results/evaluation_v0.2. Failed attempts retain STARTED/FAILED
receipts. ``verify --baseline PATH [--root ROOT]`` is read-only and checks the
embedded selection, manifest checksum, missing/modified/added files and receipt
facts. It never updates an existing baseline. JSON stdout and exit 0 mean pass;
exit 1 means differences; exit 2 means invalid/unsafe input or a failed freeze.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SPEC_VERSION = "evaluation-freeze-spec/v1"
BASELINE_VERSION = "evaluation-baseline/v1"
OUTPUT_ROOT = "results/evaluation_v0.2"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
MAX_JSON_BYTES = 16 * 1024 * 1024
FORBIDDEN_PARTS = {".git", ".codex", ".agents", ".vm-local", ".venv", "private"}
FORBIDDEN_TREE_ROOTS = {"results", "data", "data/raw", "review", "deliverables"}


class FreezeError(ValueError):
    """An invalid, unstable or unsafe baseline request."""


def _object(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - required - (optional or set()) or required - set(value):
        raise FreezeError("invalid object fields in specification or receipt")
    return value


def _relative(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise FreezeError("a nonempty relative path is required")
    if "\\" in value or ":" in value or value.startswith("/") or any(ord(c) < 32 for c in value):
        raise FreezeError("paths must be repository-relative POSIX paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts):
        raise FreezeError("path traversal or ambiguous path spelling refused")
    if any(part.casefold() in FORBIDDEN_PARTS for part in parts):
        raise FreezeError("private or environment-owned paths are outside this inventory")
    for part in parts:
        low = part.casefold()
        if low == "kaggle.json" or low == ".env" or low.startswith(".env.") or low.endswith((".pem", ".key")):
            raise FreezeError("credential-like paths are outside this inventory")
        if low.split(".")[0] in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}:
            raise FreezeError("reserved device path refused")
    if value.casefold() == OUTPUT_ROOT or value.casefold().startswith(OUTPUT_ROOT + "/"):
        raise FreezeError("baseline output directories cannot be tracked as inputs")
    return value


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _check_chain(path: Path, *, required: bool = True) -> bool:
    """Check every ancestor without following symbolic links or reparse points."""
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if required:
                raise FreezeError("required path is missing") from None
            return False
        except OSError:
            raise FreezeError("cannot safely inspect a requested path") from None
        if _is_link(info):
            raise FreezeError("symbolic links and reparse points are refused")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise FreezeError("non-directory path ancestor refused")
    return True


def _root(root: str | Path) -> Path:
    value = Path(os.path.abspath(root))
    _check_chain(value)
    if not value.is_dir():
        raise FreezeError("repository root must be a directory")
    return value


def _input_path(root: Path, relative: str, *, required: bool = True) -> Path | None:
    value = root.joinpath(*_relative(relative).split("/"))
    if not _check_chain(value, required=required):
        return None
    return value


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    # Windows Python versions can expose creation time through lstat.st_ctime
    # but metadata-change time through fstat.st_ctime. Do not compare these
    # unlike clocks. Check each API's own ctime separately below as well.
    time_identity = getattr(info, "st_birthtime_ns", 0) if os.name == "nt" else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, time_identity)


def _stable_bytes(path: Path, *, collect: bool = False) -> tuple[dict[str, Any], bytes | None]:
    _check_chain(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise FreezeError("only regular files can be inventoried")
    if collect and before.st_size > MAX_JSON_BYTES:
        raise FreezeError("JSON input exceeds size bound")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _stat_identity(before) != _stat_identity(opened):
                raise FreezeError("file changed before hashing")
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                if collect:
                    chunks.append(chunk)
            after_open = os.fstat(handle.fileno())
        _check_chain(path)
        after_path = path.lstat()
    except OSError:
        raise FreezeError("file became unavailable during hashing") from None
    if _stat_identity(before) != _stat_identity(after_open) or _stat_identity(before) != _stat_identity(after_path):
        raise FreezeError("file changed during hashing")
    if before.st_ctime_ns != after_path.st_ctime_ns or opened.st_ctime_ns != after_open.st_ctime_ns:
        if os.name != "nt":
            raise FreezeError("file metadata changed during hashing")
        # NTFS/Windows Python metadata timestamps can change when a newly
        # written fixture is first opened even though its content identity and
        # LastWriteTime are unchanged. Do not just ignore this discrepancy:
        # independently re-read and hash the bytes, requiring the same file
        # identity, size, LastWriteTime and digest throughout the confirmation.
        confirmation = hashlib.sha256()
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as handle:
                if _stat_identity(os.fstat(handle.fileno())) != _stat_identity(before):
                    raise FreezeError("file changed before metadata confirmation")
                while chunk := handle.read(1024 * 1024):
                    confirmation.update(chunk)
                if _stat_identity(os.fstat(handle.fileno())) != _stat_identity(before):
                    raise FreezeError("file changed during metadata confirmation")
            _check_chain(path)
            if _stat_identity(path.lstat()) != _stat_identity(before) or confirmation.digest() != digest.digest():
                raise FreezeError("content changed during metadata confirmation")
        except OSError:
            raise FreezeError("file became unavailable during metadata confirmation") from None
    return {"sha256": digest.hexdigest(), "size_bytes": before.st_size}, b"".join(chunks) if collect else None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise FreezeError("duplicate JSON keys refused")
        value[key] = item
    return value


def _read_json(path: Path) -> tuple[Any, dict[str, Any]]:
    receipt, raw = _stable_bytes(path, collect=True)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(FreezeError("nonfinite JSON refused")))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise FreezeError("invalid UTF-8 JSON") from None
    return value, receipt


def _sha(value: Any) -> str:
    if not isinstance(value, str) or HEX256.fullmatch(value) is None:
        raise FreezeError("SHA-256 must be 64 lowercase hexadecimal characters")
    return value


def _pointer(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith("/") or re.search(r"~(?![01])", value):
        raise FreezeError("receipt locators must be JSON pointers or null")
    return value


def validate_spec(value: Any) -> dict[str, Any]:
    spec = _object(value, {"schema_version", "files", "trees", "provenance_only"})
    if spec["schema_version"] != SPEC_VERSION:
        raise FreezeError("unsupported specification version")
    for key in ("files", "trees", "provenance_only"):
        if not isinstance(spec[key], list):
            raise FreezeError("specification selections must be arrays")
    pins: dict[str, str | None] = {}
    spelling: dict[str, str] = {}

    def path(value: Any) -> str:
        relative = _relative(value)
        folded = relative.casefold()
        if folded in spelling and spelling[folded] != relative:
            raise FreezeError("case-ambiguous selected paths refused")
        spelling[folded] = relative
        return relative

    for item in spec["files"]:
        item = _object(item, {"path"}, {"expected_sha256"})
        relative = path(item["path"])
        expected = _sha(item["expected_sha256"]) if "expected_sha256" in item else None
        if relative in pins and pins[relative] is not None and expected is not None and pins[relative] != expected:
            raise FreezeError("contradictory expected hashes refused")
        pins[relative] = expected or pins.get(relative)
    for item in spec["trees"]:
        item = _object(item, {"path", "suffixes", "exclude_dirs"})
        relative = path(item["path"])
        if relative.casefold() in FORBIDDEN_TREE_ROOTS or OUTPUT_ROOT.startswith(relative.casefold() + "/"):
            raise FreezeError("broad or output-containing tree refused; select named subtrees")
        suffixes = item["suffixes"]
        if suffixes is not None and (not isinstance(suffixes, list) or not suffixes or any(
            not isinstance(suffix, str) or not re.fullmatch(r"\.[A-Za-z0-9_-]+", suffix) for suffix in suffixes
        )):
            raise FreezeError("tree suffixes must be null or a nonempty extension list")
        excluded = item["exclude_dirs"]
        if not isinstance(excluded, list) or any(
            not isinstance(name, str) or not name or "/" in name or "\\" in name or name in {".", ".."}
            for name in excluded
        ):
            raise FreezeError("excluded directories must be simple names")
    identifiers: set[str] = set()
    for item in spec["provenance_only"]:
        item = _object(item, {"artifact_id", "receipt", "sha256_pointer", "size_pointer"})
        identity = item["artifact_id"]
        if not isinstance(identity, str) or IDENTIFIER.fullmatch(identity) is None or identity in identifiers:
            raise FreezeError("provenance artifact identifiers must be unique simple names")
        identifiers.add(identity)
        path(item["receipt"])
        _pointer(item["sha256_pointer"])
        _pointer(item["size_pointer"])
    if not (spec["files"] or spec["trees"] or spec["provenance_only"]):
        raise FreezeError("empty baseline selection refused")
    return spec


def _tree_files(root: Path, relative: str, selection: dict[str, Any], *, missing_ok: bool) -> set[str]:
    directory = _input_path(root, relative, required=not missing_ok)
    if directory is None:
        return set()
    if not directory.is_dir():
        raise FreezeError("selected tree is not a directory")
    found: set[str] = set()
    try:
        children = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        raise FreezeError("cannot enumerate selected tree") from None
    for child in children:
        info = child.lstat()
        if _is_link(info):
            raise FreezeError("symbolic links and reparse points are refused")
        child_relative = relative + "/" + child.name
        if stat.S_ISDIR(info.st_mode):
            if child.name in selection["exclude_dirs"]:
                continue
            _relative(child_relative)
            found.update(_tree_files(root, child_relative, selection, missing_ok=missing_ok))
        elif stat.S_ISREG(info.st_mode):
            if selection["suffixes"] is None or child.suffix in selection["suffixes"]:
                found.add(_relative(child_relative))
        else:
            raise FreezeError("special filesystem entry refused")
    return found


def _selection(root: Path, spec: dict[str, Any], spec_relative: str, *, missing_ok: bool) -> set[str]:
    selected = {spec_relative, *(item["path"] for item in spec["files"]), *(item["receipt"] for item in spec["provenance_only"])}
    for item in spec["trees"]:
        selected.update(_tree_files(root, item["path"], item, missing_ok=missing_ok))
    folded: dict[str, str] = {}
    for relative in selected:
        if relative.casefold() in folded and folded[relative.casefold()] != relative:
            raise FreezeError("case-ambiguous inventoried paths refused")
        folded[relative.casefold()] = relative
    return selected


def _at_pointer(value: Any, pointer: str | None) -> Any:
    if pointer is None:
        return None
    for token in pointer[1:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key) and int(key) < len(value):
            value = value[int(key)]
        else:
            raise FreezeError("receipt JSON pointer does not resolve")
    return value


def _provenance(root: Path, spec: dict[str, Any], files: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for item in spec["provenance_only"]:
        path = _input_path(root, item["receipt"])
        value, receipt_hash = _read_json(path)
        if receipt_hash != files[item["receipt"]]:
            raise FreezeError("provenance receipt changed during inventory")
        digest = _at_pointer(value, item["sha256_pointer"])
        size = _at_pointer(value, item["size_pointer"])
        if digest is not None:
            _sha(digest)
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise FreezeError("receipt-reported size must be a nonnegative integer")
        records.append({"artifact_id": item["artifact_id"], "receipt": item["receipt"],
                        "receipt_sha256": receipt_hash["sha256"],
                        "artifact_sha256_receipt_reported": digest,
                        "artifact_size_bytes_receipt_reported": size,
                        "verification": "receipt_only_artifact_not_rehashed"})
    return records


def _inventory(root: Path, spec: dict[str, Any], spec_relative: str, *, missing_ok: bool = False) -> dict[str, Any]:
    before = _selection(root, spec, spec_relative, missing_ok=missing_ok)
    files: dict[str, Any] = {}
    observed: dict[str, tuple[int, ...]] = {}
    for relative in sorted(before):
        path = _input_path(root, relative, required=not missing_ok)
        if path is not None:
            observed[relative] = _stat_identity(path.lstat())
            files[relative] = _stable_bytes(path)[0]
    after = _selection(root, spec, spec_relative, missing_ok=missing_ok)
    if before != after:
        raise FreezeError("selected tree membership changed during inventory")
    for relative, identity in observed.items():
        path = _input_path(root, relative)
        if identity != _stat_identity(path.lstat()):
            raise FreezeError("selected file changed before inventory completed")
    return files


def _write_new(path: Path, value: Any) -> dict[str, Any]:
    encoded = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    try:
        with path.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise FreezeError("cannot exclusively create baseline artifact") from None
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded)}


def _relative_argument(root: Path, argument: str | Path) -> str:
    path = Path(argument)
    if path.is_absolute():
        try:
            return _relative(path.relative_to(root).as_posix())
        except ValueError:
            raise FreezeError("input must be within the repository root") from None
    return _relative(path.as_posix())


def _new_output(root: Path) -> Path:
    current = root
    for part in OUTPUT_ROOT.split("/"):
        current = current / part
        if not _check_chain(current, required=False):
            try:
                current.mkdir()
            except OSError:
                raise FreezeError("cannot create dedicated result root") from None
        _check_chain(current)
        if not current.is_dir():
            raise FreezeError("result root is not a directory")
    name = "stage0_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "_" + uuid.uuid4().hex[:12]
    output = current / name
    try:
        output.mkdir()
    except OSError:
        raise FreezeError("new stage0 directory could not be created exclusively") from None
    _check_chain(output)
    return output


def freeze_baseline(root: str | Path, spec_path: str | Path) -> Path:
    repository = _root(root)
    relative = _relative_argument(repository, spec_path)
    spec, spec_hash = _read_json(_input_path(repository, relative))
    spec = validate_spec(spec)
    output = _new_output(repository)
    _write_new(output / "STARTED.json", {"schema_version": BASELINE_VERSION, "status": "started"})
    try:
        files = _inventory(repository, spec, relative)
        if files[relative] != spec_hash:
            raise FreezeError("specification changed during inventory")
        for entry in spec["files"]:
            if "expected_sha256" in entry and files[entry["path"]]["sha256"] != entry["expected_sha256"]:
                raise FreezeError("historically expected hash mismatch: " + entry["path"])
        provenance = _provenance(repository, spec, files)
        manifest = {"schema_version": BASELINE_VERSION, "created_at_utc": datetime.now(UTC).isoformat(),
                    "spec_path": relative, "spec": spec, "files": files, "provenance_only": provenance,
                    "limitations": "Hash inventory only; receipt-only artifacts were not rehashed; not a signature or backup."}
        receipt = _write_new(output / "manifest.json", manifest)
        _write_new(output / "COMPLETE.json", {"schema_version": BASELINE_VERSION, "status": "complete",
                                              "manifest_sha256": receipt["sha256"], "file_count": len(files)})
    except Exception as exc:
        message = str(exc) if isinstance(exc, FreezeError) else "unexpected inventory failure"
        _write_new(output / "FAILED.json", {"schema_version": BASELINE_VERSION, "status": "failed", "reason": message})
        raise FreezeError(message + "; incomplete artifacts retained at " + output.relative_to(repository).as_posix()) from None
    return output


def _baseline_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            raise FreezeError("baseline must be inside the dedicated result root") from None
    else:
        relative = path.as_posix()
    parts = relative.split("/")
    if len(parts) != 3 or "/".join(parts[:2]) != OUTPUT_ROOT or not re.fullmatch(r"stage0_[A-Za-z0-9_]+", parts[2]):
        raise FreezeError("baseline must be one named stage0 directory in the dedicated result root")
    selected = root.joinpath(*parts)
    _check_chain(selected)
    if not selected.is_dir():
        raise FreezeError("baseline must be a directory")
    return selected


def verify_baseline(root: str | Path, baseline: str | Path) -> dict[str, Any]:
    repository = _root(root)
    directory = _baseline_path(repository, baseline)
    _check_chain(directory / "FAILED.json", required=False)
    if (directory / "FAILED.json").exists():
        raise FreezeError("failed baseline cannot be verified as complete")
    complete, _ = _read_json(directory / "COMPLETE.json")
    _object(complete, {"schema_version", "status", "manifest_sha256", "file_count"})
    if complete["schema_version"] != BASELINE_VERSION or complete["status"] != "complete":
        raise FreezeError("baseline lacks a valid completion receipt")
    manifest, manifest_hash = _read_json(directory / "manifest.json")
    if _sha(complete["manifest_sha256"]) != manifest_hash["sha256"]:
        raise FreezeError("baseline manifest checksum mismatch")
    _object(manifest, {"schema_version", "created_at_utc", "spec_path", "spec", "files", "provenance_only", "limitations"})
    if manifest["schema_version"] != BASELINE_VERSION:
        raise FreezeError("unsupported baseline version")
    spec = validate_spec(manifest["spec"])
    relative = _relative(manifest["spec_path"])
    previous = manifest["files"]
    if not isinstance(previous, dict) or complete["file_count"] != len(previous):
        raise FreezeError("invalid baseline file inventory")
    for name, info in previous.items():
        _relative(name)
        _object(info, {"sha256", "size_bytes"})
        _sha(info["sha256"])
        if isinstance(info["size_bytes"], bool) or not isinstance(info["size_bytes"], int) or info["size_bytes"] < 0:
            raise FreezeError("invalid baseline file size")
    current = _inventory(repository, spec, relative, missing_ok=True)
    missing = sorted(set(previous) - set(current))
    added = sorted(set(current) - set(previous))
    modified = sorted(name for name in set(previous) & set(current) if previous[name] != current[name])
    provenance_changed = any(item["receipt"] in missing or item["receipt"] in modified for item in spec["provenance_only"])
    if not provenance_changed:
        provenance_changed = _provenance(repository, spec, current) != manifest["provenance_only"]
    passed = not (missing or added or modified or provenance_changed)
    return {"status": "pass" if passed else "different", "baseline": directory.relative_to(repository).as_posix(),
            "tracked_file_count": len(previous), "missing": missing, "modified": modified, "added": added,
            "provenance_changed": provenance_changed,
            "receipt_only_artifacts_not_rehashed": [item["artifact_id"] for item in spec["provenance_only"]]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("freeze", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
        command.add_argument("--spec" if name == "freeze" else "--baseline", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            root = _root(args.root)
            output = freeze_baseline(root, args.spec)
            result = {"status": "complete", "baseline": output.relative_to(root).as_posix()}
        else:
            result = verify_baseline(args.root, args.baseline)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] in {"complete", "pass"} else 1
    except (FreezeError, OSError):
        # No traceback or absolute path is printed: diagnostics remain privacy-safe.
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, FreezeError) else "filesystem operation failed"
        print(json.dumps({"status": "error", "reason": message}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
