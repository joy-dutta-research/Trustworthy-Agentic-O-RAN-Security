#!/usr/bin/env python3
"""Fetch the pinned original 5G-NIDD processed archive; never execute or extract it.

The author DOI identifies Fairdata's open, CC BY 4.0 dataset. Etsin issues
temporary download URLs anonymously. Those URLs are used only in memory and
are deliberately absent from receipts and diagnostic output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import uuid
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DATASET_ID = "9d13ef28-2ca7-44b0-9950-225359afac65"
DATASET_DOI = "https://doi.org/10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361"
METADATA_URL = f"https://metax.fairdata.fi/v3/datasets/{DATASET_ID}"
FILES_URL = f"{METADATA_URL}/files?pagination=false"
AUTHORIZE_URL = "https://etsin.fairdata.fi/api/v3/download/authorize"
FILENAME = "Combined.zip"
EXPECTED_SIZE = 28_028_224
EXPECTED_SHA256 = "07531b251f3f35be70bf1d3dcca2e27274bd1b267c5a057c0fcea18668b9293d"
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
SOCKET_TIMEOUT = 30
TOTAL_TIMEOUT = 300
MAX_METADATA_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
ALLOWED_HOSTS = frozenset({"metax.fairdata.fi", "etsin.fairdata.fi", "download.fairdata.fi"})


class DownloadError(ValueError):
    """A sanitized operational failure; never includes an authorization URL."""


def validate_url(url: str, hosts: frozenset[str] = ALLOWED_HOSTS) -> None:
    if not isinstance(url, str) or any(ord(char) < 33 for char in url):
        raise DownloadError("invalid download URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname in hosts
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise DownloadError("URL is outside the permitted HTTPS origins")


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        # A temporary access token must not be forwarded between origins.
        if urllib.parse.urlsplit(req.full_url).hostname != urllib.parse.urlsplit(newurl).hostname:
            raise DownloadError("cross-origin redirect is not permitted")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_request(opener, url: str, *, body: dict | None = None):
    validate_url(url)
    payload = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"User-Agent": "trustworthy-oran-action-gateway/0.1 dataset-reproduction"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, headers=headers)
    try:
        response = opener.open(request, timeout=SOCKET_TIMEOUT)
        validate_url(response.geturl())
        if response.status != 200:
            response.close()
            raise DownloadError("download service returned an unexpected response")
        return response
    except (urllib.error.URLError, OSError):
        raise DownloadError("HTTPS request failed; retry later or check network access") from None


def fetch_json(opener, url: str, *, body: dict | None = None):
    with open_request(opener, url, body=body) as response:
        raw = response.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise DownloadError("metadata exceeds the configured size bound")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise DownloadError("download service returned invalid JSON metadata") from None


def verify_source_metadata(dataset: dict, files: list) -> dict:
    if not isinstance(dataset, dict) or not isinstance(files, list):
        raise DownloadError("unexpected dataset metadata structure")
    if dataset.get("id") != DATASET_ID:
        raise DownloadError("dataset identifier does not match the pinned source")
    expected_pid = DATASET_DOI.replace("https://doi.org/", "doi:")
    if dataset.get("persistent_identifier") != expected_pid:
        raise DownloadError("dataset DOI does not match the pinned source")
    rights = dataset.get("access_rights", {})
    if rights.get("access_type", {}).get("url", "").rsplit("/", 1)[-1] != "open":
        raise DownloadError("source does not currently declare open access")
    licenses = rights.get("license", [])
    if not any(item.get("custom_url") == LICENSE_URL for item in licenses):
        raise DownloadError("source license does not match the verified CC BY 4.0 license")
    matches = [item for item in files if item.get("pathname") == "/" + FILENAME]
    if len(matches) != 1:
        raise DownloadError("source must contain exactly one pinned archive")
    file = matches[0]
    if file.get("size") != EXPECTED_SIZE or file.get("checksum") != "sha256:" + EXPECTED_SHA256:
        raise DownloadError("source archive differs from the pinned version; review before updating")
    # Keep a precise public snapshot, excluding author email, service usernames,
    # temporary download tokens, and machine-specific paths.
    return {
        "receipt_version": "1.0",
        "dataset_doi": DATASET_DOI,
        "metadata_url": METADATA_URL,
        "files_url": FILES_URL,
        "dataset_id": DATASET_ID,
        "title": dataset.get("title"),
        "version": dataset.get("version"),
        "metadata_modified": dataset.get("modified"),
        "access": "open",
        "license": LICENSE_URL,
        "descriptor_doi": "https://doi.org/10.1109/IEEEDATA.2025.3592888",
        "archive": {key: file.get(key) for key in (
            "id", "storage_identifier", "pathname", "filename", "size", "checksum", "frozen", "modified"
        )},
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_existing(path: Path, size: int = EXPECTED_SIZE, digest: str = EXPECTED_SHA256) -> bool:
    if path.is_symlink():
        raise DownloadError("refusing a symbolic-link output file")
    if not path.exists():
        return False
    if not path.is_file() or path.stat().st_size != size or sha256_file(path) != digest:
        raise DownloadError("existing archive differs from the pinned source; no file was overwritten")
    return True


def publish_no_replace(partial: Path, destination: Path) -> None:
    """Atomically create the final name without replacing another process's file."""
    try:
        os.link(partial, destination)
    except FileExistsError:
        raise DownloadError("output appeared during download; no file was overwritten") from None


def stream_archive(response, destination: Path, *, size=EXPECTED_SIZE, digest=EXPECTED_SHA256) -> None:
    if verify_existing(destination, size, digest):
        return
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) != size:
                raise DownloadError("download Content-Length differs from the pinned archive")
        except ValueError:
            raise DownloadError("download has an invalid Content-Length") from None
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.parent / f".5gnidd-{uuid.uuid4().hex}.partial"
    checksum = hashlib.sha256()
    total = 0
    started = time.monotonic()
    try:
        with partial.open("xb") as output:
            while True:
                if time.monotonic() - started > TOTAL_TIMEOUT:
                    raise DownloadError("download exceeded the total time bound")
                chunk = response.read(min(CHUNK_BYTES, size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise DownloadError("download exceeds the pinned archive size")
                checksum.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if total != size or checksum.hexdigest() != digest:
            raise DownloadError("download failed pinned size/SHA-256 verification")
        publish_no_replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def list_archive(path: Path) -> list[dict]:
    """List bounded ZIP metadata only. Extraction belongs to a separate step."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > 100:
            raise DownloadError("unexpected archive member count")
        members = []
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith("/") or "\\" in name or ".." in parts
                    or ":" in name or stat.S_ISLNK(info.external_attr >> 16)):
                raise DownloadError("unexpected unsafe archive member")
            members.append({"name": name, "size": info.file_size, "compressed_size": info.compress_size,
                            "crc32": f"{info.CRC:08x}"})
        return members


def write_receipt(path: Path, receipt: dict) -> None:
    raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8")
    # Identical reruns are idempotent. Changed source metadata is preserved in a
    # new content-addressed receipt instead of overwriting the previous record.
    suffix = hashlib.sha256(raw).hexdigest()[:16]
    destination = path / f"provenance-{suffix}.json"
    if destination.is_symlink():
        raise DownloadError("refusing a symbolic-link receipt")
    if destination.exists():
        if destination.read_bytes() != raw:
            raise DownloadError("existing receipt does not match its content-addressed name")
        return
    partial = path / f".receipt-{uuid.uuid4().hex}.partial"
    try:
        with partial.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        publish_no_replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def download(output_dir: Path) -> dict:
    for ancestor in (output_dir, *output_dir.parents):
        if ancestor.is_symlink():
            raise DownloadError("refusing a symbolic-link output directory")
    opener = urllib.request.build_opener(RestrictedRedirect())
    dataset = fetch_json(opener, METADATA_URL)
    files = fetch_json(opener, FILES_URL)
    receipt = verify_source_metadata(dataset, files)
    destination = output_dir / FILENAME
    if not verify_existing(destination):
        authorization = fetch_json(opener, AUTHORIZE_URL, body={"cr_id": DATASET_ID, "file": "/" + FILENAME})
        url = authorization.get("url") if isinstance(authorization, dict) else None
        validate_url(url, frozenset({"download.fairdata.fi"}))
        with open_request(opener, url) as response:
            stream_archive(response, destination)
    receipt["archive_members"] = list_archive(destination)
    receipt["verified_sha256"] = EXPECTED_SHA256
    write_receipt(output_dir, receipt)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "raw" / "5g-nidd")
    args = parser.parse_args()
    try:
        receipt = download(args.output_dir.absolute())
    except (DownloadError, OSError, zipfile.BadZipFile, TypeError, AttributeError):
        # Some library errors can include the full token URL; intentionally do
        # not echo arbitrary upstream exceptions or tracebacks.
        parser.exit(1, "Download failed validation or network access. Existing files were preserved.\n")
    print(json.dumps({"archive": FILENAME, "size": EXPECTED_SIZE, "sha256": EXPECTED_SHA256,
                      "license": LICENSE_URL, "members": receipt["archive_members"]}, indent=2))


if __name__ == "__main__":
    main()
