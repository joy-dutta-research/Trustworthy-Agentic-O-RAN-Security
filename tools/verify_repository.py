"""Check a local publication draft without executing any experimental code.

Hashes establish file identity, not experimental validity or an external trust
signature. Compare the separately supplied archive digest before trusting this
manifest. This verifier uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRS = {".git", "__pycache__", ".venv", "work", "validation_work", "dist"}
MANIFEST_NAME = "REPOSITORY_MANIFEST.json"
ASSET_PREFIXES = ("evidence/raw_archives/", "evidence/history/")
WINDOWS_RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}


def digest_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_member(name: str) -> PurePosixPath:
    """Require a portable relative ZIP/manifest path; never normalize traversal."""
    path = PurePosixPath(name)
    parts = name.rstrip("/").split("/")
    if (not name or path.is_absolute() or "\\" in name or
            any(p in {"", ".", ".."} for p in parts) or
            any(":" in p or p.endswith((".", " ")) or
                any(ord(c) < 32 for c in p) or
                p.split(".", 1)[0].lower() in WINDOWS_RESERVED for p in parts)):
        raise ValueError(f"Nonportable or unsafe member: {name!r}")
    return path


def validate_zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    seen: set[str] = set()
    files: list[zipfile.ZipInfo] = []
    for info in archive.infolist():
        safe_member(info.filename)
        key = info.filename.rstrip("/").casefold()
        if key in seen:
            raise ValueError(f"Duplicate ZIP member: {info.filename}")
        seen.add(key)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError(f"Special ZIP member: {info.filename}")
        if info.flag_bits & 1:
            raise ValueError(f"Encrypted member: {info.filename}")
        if not info.is_dir():
            files.append(info)
    return files


def repository_files(root: Path) -> dict[str, Path]:
    found = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Repository symlink not permitted: {relative}")
        if path.is_file() and relative.as_posix() != MANIFEST_NAME:
            found[relative.as_posix()] = path
    return found


def folder_guidance(root: Path) -> list[str]:
    missing = []
    for folder in [root, *(p for p in root.rglob("*") if p.is_dir())]:
        relative = folder.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        if not any(p.is_file() and p.suffix.lower() == ".md" for p in folder.iterdir()):
            missing.append(relative.as_posix())
    return missing


def local_links(root: Path) -> list[str]:
    """Check current reader guidance, not immutable historical source documents."""
    errors = []
    for relative, path in repository_files(root).items():
        if path.suffix.lower() != ".md" or relative.startswith(("code/", "model_review/inputs/")):
            continue
        content = path.read_text(encoding="utf-8-sig")
        for target in re.findall(r"\]\(([^\n]+?)\)", content):
            target = target.strip().strip("<>")
            if target.startswith(("http:", "https:", "mailto:", "#")):
                continue
            # New documentation uses relative links without Markdown title text.
            target = target.split("#", 1)[0]
            if not target:
                continue
            destination = (path.parent / target).resolve()
            if not destination.is_relative_to(root.resolve()):
                errors.append(f"{relative}: link outside repository: {target}")
            elif not destination.exists():
                errors.append(f"{relative}: missing link: {target}")
    return errors


def verify_public_asset(path: Path) -> dict:
    """Stream-check each scientific member of one public evidence ZIP."""
    with zipfile.ZipFile(path) as archive:
        infos = validate_zip_members(archive)
        actual = {item.filename: item for item in infos}
        manifest = json.loads(archive.read("PUBLIC_MANIFEST.json"))
        if manifest.get("schema") != "oran-public-evidence/v1":
            raise ValueError(f"Unsupported evidence manifest: {path.name}")
        names = [item["path"] for item in manifest["files"]]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate evidence manifest entry: {path.name}")
        for identity in manifest["files"]:
            name = identity["path"]
            safe_member(name)
            if name not in actual or actual[name].file_size != identity["public_bytes"]:
                raise ValueError(f"Missing/changed member size: {path.name}/{name}")
            with archive.open(name) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != identity["public_sha256"]:
                raise ValueError(f"Changed member bytes: {path.name}/{name}")
        extras = set(actual) - set(names) - {"PUBLIC_MANIFEST.json"}
        if (len(extras) != manifest["added_readme_count"] or
                any(PurePosixPath(name).name != "README.md" for name in extras)):
            raise ValueError(f"Undeclared extra members: {path.name}")
        # Documentation overlays are bound by the outer repository file hash.
        folders = {PurePosixPath(".")}
        documented = {PurePosixPath(name).parent for name in actual if name.lower().endswith(".md")}
        for name in actual:
            folders.update(PurePosixPath(name).parents)
        for folder in folders:
            if folder not in documented:
                raise ValueError(f"Archive folder lacks Markdown: {path.name}/{folder}")
        return {"archive": path.name, "scientific_members_checked": len(names),
                "added_guides_bound_by_outer_hash": len(extras)}


def verify(root: Path, without_raw_assets: bool = False) -> dict:
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), dict):
        raise ValueError("Unsupported repository manifest")
    actual = repository_files(root)
    expected = manifest["files"]
    failures, skipped = [], []
    for name, identity in expected.items():
        safe_member(name)
        path = actual.get(name)
        is_asset = name.startswith(ASSET_PREFIXES) and name.endswith(".zip")
        if path is None and without_raw_assets and is_asset:
            skipped.append(name)
            continue
        if path is None:
            failures.append("Missing: " + name)
        elif path.stat().st_size != identity["bytes"] or digest_file(path) != identity["sha256"]:
            failures.append("Changed: " + name)
    failures += ["Unmanifested: " + name for name in sorted(set(actual) - set(expected))]
    failures += ["Folder lacks Markdown guidance: " + name for name in folder_guidance(root)]
    failures += local_links(root)
    return {
        "status": "FAIL" if failures else ("PARTIAL_SOURCE_CHECK" if skipped else "PASS"),
        "verified_files": len(expected) - len(skipped) - sum(x.startswith(("Missing:", "Changed:")) for x in failures),
        "omitted_release_assets": skipped,
        "failures": failures,
        "scope": "Recorded file identity and current reader navigation; not scientific improvement, external signature, or a complete privacy certification.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--without-raw-assets", action="store_true", help="Permit absent large release ZIPs; reports a partial source-only check")
    parser.add_argument("--deep-assets", action="store_true", help="Also stream-check every public evidence archive member (several GB uncompressed)")
    args = parser.parse_args()
    try:
        result = verify(args.root.resolve(), args.without_raw_assets)
        if args.deep_assets and result["status"] != "FAIL":
            result["deep_asset_checks"] = [verify_public_asset(path) for name, path in repository_files(args.root.resolve()).items()
                                           if name.startswith(ASSET_PREFIXES) and name.endswith(".zip")]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return int(result["status"] == "FAIL")


if __name__ == "__main__":
    sys.exit(main())
