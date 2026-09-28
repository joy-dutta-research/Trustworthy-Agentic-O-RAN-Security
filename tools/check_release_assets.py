"""Validate companion-asset instructions without downloading or executing data.

The default checks local release preparation. --require-published requires HTTPS
asset links as well, but does not test remote availability or remote file bytes.
Use verify_repository.py after obtaining assets to check their actual identities.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "evidence/raw_archives/university_windows_final.zip",
    "evidence/raw_archives/workstation_windows_final.zip",
    "evidence/raw_archives/packet_primary.zip",
    "evidence/raw_archives/packet_repeat.zip",
    "evidence/raw_archives/campaign_provenance.zip",
    "evidence/history/packet_development_context.zip",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def https_url(value: str) -> bool:
    if not isinstance(value, str) or any(c.isspace() for c in value):
        return False
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and bool(parsed.hostname) and
            parsed.username is None and parsed.password is None)


def validate(catalog: dict, manifest: dict, require_published: bool = False) -> dict:
    require(catalog.get("schema_version") == 1, "Unsupported asset catalog")
    require(catalog.get("guide_path") == "evidence/ASSET_GUIDE.md", "Unexpected asset guide path")
    assets = catalog.get("assets")
    require(isinstance(assets, list) and len(assets) == 6, "Exactly six assets are required")
    paths = [entry.get("relative_path") for entry in assets]
    require(len(set(paths)) == 6 and set(paths) == EXPECTED, "Asset destinations differ from the six approved paths")
    pending = []
    for entry in assets:
        path = entry["relative_path"]
        require(entry.get("filename") == Path(path).name, f"Filename differs: {path}")
        require(isinstance(entry.get("bytes"), int) and entry["bytes"] > 0, f"Invalid size: {path}")
        require(isinstance(entry.get("sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None, f"Invalid SHA-256: {path}")
        expected = manifest.get("files", {}).get(path, {})
        require(expected.get("distribution") == "companion_release_asset", f"Wrong distribution: {path}")
        require(all(entry[key] == expected.get(key) for key in ("bytes", "sha256")), f"Identity differs from manifest: {path}")
        require(bool(entry.get("purpose")) and bool(entry.get("required_for")), f"Missing interpretation: {path}")
        regeneration = entry.get("regeneration", {})
        require(all(isinstance(regeneration.get(key), bool) for key in ("possible", "creates_new_measurements")),
                f"Missing regeneration scope: {path}")
        require(bool(regeneration.get("guide_anchor")) and bool(regeneration.get("note")), f"Missing reproduction guidance: {path}")
        url = entry.get("download_url")
        if url is None:
            require(entry.get("publication_status") == "not_published", f"Unpublished asset marked available: {path}")
            pending.append(path)
        else:
            require(https_url(url) and entry.get("publication_status") == "published", f"Invalid publication link/status: {path}")
    page = catalog.get("release_page_url")
    require(page is None or https_url(page), "Invalid release-page URL")
    if not pending:
        require(page is not None and catalog.get("release_status") == "published", "Published assets need a release page and published status")
    else:
        require(catalog.get("release_status") in ("not_published", "partially_published"), "Incomplete links must remain explicitly pending")
    require(not require_published or not pending, "Historical-evidence publication is pending: six archive URLs must be populated before claiming a complete downloadable release")
    return {
        "status": "PREPARED_LINKS_PENDING" if pending else "CATALOG_VALID",
        "assets_checked": len(assets),
        "unpublished_assets": pending,
        "scope": "Catalog identities and local instructions only; no network availability, archive bytes or scientific claims verified.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-published", action="store_true")
    args = parser.parse_args()
    try:
        catalog = json.loads((ROOT / "evidence/RELEASE_ASSETS.json").read_text(encoding="utf-8-sig"))
        manifest = json.loads((ROOT / "REPOSITORY_MANIFEST.json").read_text(encoding="utf-8-sig"))
        result = validate(catalog, manifest, args.require_published)
        guide = (ROOT / catalog["guide_path"]).read_text(encoding="utf-8-sig")
        anchors = {re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
                   for heading in re.findall(r"^#+ (.+)$", guide, re.MULTILINE)}
        for entry in catalog["assets"]:
            require(entry["filename"] in guide, f"Asset absent from guide: {entry['filename']}")
            require(entry["regeneration"]["guide_anchor"] in anchors, f"Missing guide anchor: {entry['filename']}")
            sidecar = ROOT / (entry["relative_path"] + ".sha256")
            fields = sidecar.read_text(encoding="ascii").split()
            require(fields == [entry["sha256"], entry["filename"]], f"SHA-256 sidecar differs: {entry['filename']}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
