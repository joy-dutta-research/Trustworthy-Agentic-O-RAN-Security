"""Fetch the pinned official Ubuntu ISO, verify its signed checksums, then SHA256.

No VM creation, installation, privilege change, shell invocation or private key.
All generated artifacts remain below .vm-local, excluded from the public repo.
An interrupted download is retained as .part and can be resumed explicitly.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.jsonio import strict_json_load
FILENAME = "ubuntu-24.04.5-live-server-amd64.iso"
EXPECTED_SHA256 = "97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8"
SIGNING_KEY = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
BASE = "https://releases.ubuntu.com/noble/"
KEY_URL = "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + SIGNING_KEY
MAX_IMAGE_BYTES = 5 * 1024**3


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        previous, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or new.netloc != previous.netloc:
            raise ValueError("Refusing cross-origin or non-HTTPS redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def opener():
    return urllib.request.build_opener(SameOriginRedirect())


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(8 * 1024 * 1024):
            result.update(block)
    return result.hexdigest()


def reject_reparse(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Refusing symlink in local VM artifact path")
    if path.exists() and getattr(path.stat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("Refusing Windows junction/reparse point in local VM artifact path")


def private_directory(*parts: str) -> Path:
    target = ROOT
    for ancestor in (ROOT, *ROOT.parents):
        reject_reparse(ancestor)
    for part in (".vm-local", *parts):
        target = target / part
        reject_reparse(target)
        if not target.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Local VM path escaped the repository")
        target.mkdir(exist_ok=True)
    return target


def fetch_small(url: str, target: Path) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ORAN-research-image-verifier/0.1"})
    with opener().open(request, timeout=60) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Verification metadata exceeds one MiB")
    with target.open("xb") as handle:
        handle.write(data)
    return data


def verify_checksum_text(value: str) -> None:
    matches = []
    for line in value.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].lstrip("*") == FILENAME:
            matches.append(parts[0].lower())
    if matches != [EXPECTED_SHA256]:
        raise ValueError("Signed Ubuntu checksum list does not contain the exact pinned image once")


def verify_gpg_status(status: str) -> None:
    records = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] ")]
    if any(len(row) > 1 and row[1] in {"BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"} for row in records):
        raise ValueError("Invalid, expired or revoked Ubuntu signature")
    valid = [row for row in records if len(row) >= 12 and row[1] == "VALIDSIG"
             and SIGNING_KEY in (row[2], row[-1]) and row[9] in {"8", "9", "10", "11"}]
    if not valid:
        raise ValueError("A valid strong-hash signature from the pinned Ubuntu key is required")


def run_gpg(executable: Path, home: Path, *arguments: str):
    # Git for Windows bundles an MSYS GnuPG: backslash Windows paths are not
    # valid GnuPG homedirs. Repository-relative POSIX paths work on both OSes.
    portable_arguments = [Path(value).relative_to(ROOT).as_posix()
                          if Path(value).is_absolute() else value for value in arguments]
    return subprocess.run([str(executable), "--no-options", "--batch", "--homedir",
                           home.relative_to(ROOT).as_posix(), *portable_arguments],
                          cwd=ROOT, capture_output=True, text=True, timeout=60, shell=False)


def download_iso(destination: Path, *, resume: bool) -> str:
    reject_reparse(destination)
    if destination.exists():
        if destination.is_symlink() or sha256(destination) != EXPECTED_SHA256:
            raise ValueError("Existing ISO is not the pinned image; refusing overwrite")
        return "existing_iso_reverified"
    partial = destination.with_suffix(destination.suffix + ".part")
    reject_reparse(partial)
    if partial.exists() and not resume:
        raise ValueError("Partial download retained; inspect it and explicitly use --resume")
    offset = partial.stat().st_size if partial.exists() else 0
    if not 0 <= offset < MAX_IMAGE_BYTES:
        raise ValueError("Partial ISO exceeds bounds")
    if shutil.disk_usage(destination.parent).free < MAX_IMAGE_BYTES - offset + 512 * 1024**2:
        raise ValueError("Insufficient free space for bounded ISO download")
    headers = {"User-Agent": "ORAN-research-image-verifier/0.1", "Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(BASE + FILENAME, headers=headers)
    with opener().open(request, timeout=60) as response:
        if offset and (response.status != 206 or not response.headers.get("Content-Range", "").startswith(f"bytes {offset}-")):
            raise ValueError("Server did not honor exact resume offset; partial file preserved")
        if not offset and response.status != 200:
            raise ValueError("Unexpected image HTTP status")
        remaining = int(response.headers.get("Content-Length", "-1"))
        total = offset + remaining
        if remaining <= 0 or not 1024**3 <= total <= MAX_IMAGE_BYTES:
            raise ValueError("Missing or out-of-bounds image length")
        count = offset
        last_report = time.monotonic()
        print(json.dumps({"status": "DOWNLOADING", "bytes_present": count, "total_bytes": total}), flush=True)
        with partial.open("ab" if partial.exists() and resume else "xb") as handle:
            while block := response.read(8 * 1024 * 1024):
                count += len(block)
                if count > total:
                    raise ValueError("Image stream exceeded declared length")
                handle.write(block)
                if time.monotonic() - last_report >= 15:
                    print(json.dumps({"status": "DOWNLOADING", "percent": round(100 * count / total, 1)}), flush=True)
                    last_report = time.monotonic()
        if count != total:
            raise ValueError("Truncated ISO retained as .part")
    if sha256(partial) != EXPECTED_SHA256:
        raise ValueError("ISO checksum mismatch; untrusted .part retained, not promoted")
    # Exclusive hard-link publication cannot overwrite a concurrent destination
    # on Windows or Linux. Both files are on the same local filesystem. If the
    # filesystem does not support hard links, fail and retain the verified part.
    os.link(partial, destination)
    partial.unlink()
    return "downloaded_and_verified"


def validate_existing_receipt(path: Path, iso: Path) -> None:
    reject_reparse(path)
    if not path.is_file():
        raise ValueError("Existing verification receipt is not a regular file")
    value = strict_json_load(path, maximum_bytes=65536)
    required = {"status": "VERIFIED_SIGNATURE_AND_SHA256", "iso_filename": FILENAME,
                "iso_sha256": EXPECTED_SHA256, "signing_key_fingerprint": SIGNING_KEY,
                "iso_bytes": iso.stat().st_size}
    if not isinstance(value, dict) or any(value.get(k) != v for k, v in required.items()):
        raise ValueError("Existing receipt is malformed/stale; preserved for inspection, not overwritten")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpg", type=Path, required=True, help="Existing trusted GnuPG executable")
    parser.add_argument("--download", action="store_true", help="Download the approximately 4 GB ISO after signature verification")
    parser.add_argument("--resume", action="store_true", help="Explicitly resume a retained partial image")
    args = parser.parse_args()
    if not args.gpg.is_file():
        parser.error("A pre-existing GnuPG executable is required")
    media = private_directory("media")
    lock = media / "prepare.lock"
    with lock.open("x", encoding="ascii") as handle:
        handle.write("Exclusive Ubuntu media preparation lock; remove manually only after confirming no runner is active.\n")
    try:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        metadata = private_directory("verification", stamp)
        home = private_directory("gnupg")
        sums = fetch_small(BASE + "SHA256SUMS", metadata / "SHA256SUMS")
        fetch_small(BASE + "SHA256SUMS.gpg", metadata / "SHA256SUMS.gpg")
        fetch_small(KEY_URL, metadata / "ubuntu-signing-key.asc")
        preview = run_gpg(args.gpg, home, "--with-colons", "--import-options", "show-only", "--import", str(metadata / "ubuntu-signing-key.asc"))
        if preview.returncode:
            raise RuntimeError("GnuPG could not inspect the key: " + preview.stderr.strip())
        if SIGNING_KEY not in [line.split(":")[9] for line in preview.stdout.splitlines() if line.startswith("fpr:")]:
            raise ValueError("Downloaded signing key does not match official pinned fingerprint")
        imported = run_gpg(args.gpg, home, "--import", str(metadata / "ubuntu-signing-key.asc"))
        if imported.returncode:
            raise ValueError("Could not import public verification key into isolated keyring")
        signature = run_gpg(args.gpg, home, "--status-fd", "1", "--verify",
                            str(metadata / "SHA256SUMS.gpg"), str(metadata / "SHA256SUMS"))
        if signature.returncode != 0:
            raise ValueError("GnuPG verification returned an error; no image may be accepted")
        verify_gpg_status(signature.stdout)
        verify_checksum_text(sums.decode("utf-8"))
        with (metadata / "signature-status.txt").open("x", encoding="utf-8") as handle:
            handle.write(signature.stdout)
        print("Official checksum signature and pinned Ubuntu image digest verified.", flush=True)
        if not args.download:
            return 0
        iso = media / FILENAME
        outcome = download_iso(iso, resume=args.resume)
        receipt = {"status": "VERIFIED_SIGNATURE_AND_SHA256", "iso_filename": FILENAME,
                   "iso_url": BASE + FILENAME, "iso_sha256": EXPECTED_SHA256,
                   "iso_bytes": iso.stat().st_size, "signing_key_fingerprint": SIGNING_KEY,
                   "checksums_sha256": sha256(metadata / "SHA256SUMS"),
                   "detached_signature_sha256": sha256(metadata / "SHA256SUMS.gpg"),
                   "gpg_status_sha256": sha256(metadata / "signature-status.txt"),
                   "verified_at": datetime.now(UTC).isoformat(), "outcome": outcome}
        receipt_path = media / (FILENAME + ".verified.json")
        if receipt_path.exists():
            validate_existing_receipt(receipt_path, iso)
        else:
            with receipt_path.open("x", encoding="utf-8") as handle:
                json.dump(receipt, handle, indent=2, sort_keys=True)
                handle.write("\n")
        print(json.dumps(receipt, indent=2), flush=True)
        return 0
    finally:
        # Only the exact lock created exclusively by this invocation is removed.
        lock.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
