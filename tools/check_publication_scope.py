"""Keep manuscript/rendered-display file formats out of this source release.

Inspect files and ZIP member names, including bounded nested source ZIPs. This
does not detect copied prose in Markdown, certify privacy or prevent reuse of
public numerical results. We review reader-facing text separately.
"""
from __future__ import annotations

import io
import json
from pathlib import Path, PurePosixPath
import zipfile

from verify_repository import repository_files, validate_zip_members

ROOT = Path(__file__).resolve().parents[1]
WITHHELD_FORMATS = {".tex", ".pdf", ".png", ".jpg", ".jpeg", ".svg", ".eps", ".docx", ".pptx"}
MAX_NESTED_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 4


def inspect_zip(archive: zipfile.ZipFile, label: str, depth: int = 0,
                budget: list[int] | None = None) -> tuple[list[str], int]:
    if budget is None:
        budget = [MAX_NESTED_BYTES]
    if depth > MAX_DEPTH:
        raise ValueError(f"Nested ZIP depth exceeds inspection limit: {label}")
    if len(archive.infolist()) > 100000:
        raise ValueError(f"ZIP member count exceeds inspection limit: {label}")
    failures, members = [], 0
    for info in validate_zip_members(archive):
        members += 1
        suffix = PurePosixPath(info.filename).suffix.lower()
        member_label = f"{label}!{info.filename}"
        if suffix in WITHHELD_FORMATS:
            failures.append(member_label)
        elif suffix == ".zip":
            if info.file_size > budget[0]:
                raise ValueError(f"Nested ZIP exceeds inspection budget: {member_label}")
            budget[0] -= info.file_size
            with archive.open(info) as stream:
                payload = stream.read(info.file_size + 1)
            if len(payload) != info.file_size:
                raise ValueError(f"Nested ZIP size differs: {member_label}")
            with zipfile.ZipFile(io.BytesIO(payload)) as nested:
                found, count = inspect_zip(nested, member_label, depth + 1, budget)
            failures.extend(found)
            members += count
    return failures, members


def check(root: Path) -> dict:
    failures, archive_members, archive_count = [], 0, 0
    files = repository_files(root)
    for name, path in files.items():
        if path.suffix.lower() in WITHHELD_FORMATS:
            failures.append(name)
        elif path.suffix.lower() == ".zip":
            archive_count += 1
            with zipfile.ZipFile(path) as archive:
                found, count = inspect_zip(archive, name)
            failures.extend(found)
            archive_members += count
    return {"status": "FAIL" if failures else "PASS", "files_examined": len(files),
            "top_level_archives_examined": archive_count, "archive_members_examined": archive_members,
            "withheld_formats_found": failures,
            "scope": "File formats and ZIP membership only. Manuscript prose and direct paper-table copies require editorial review; scientific CSV/JSON results remain included."}


def main() -> int:
    try:
        result = check(ROOT)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        result = {"status": "FAIL", "error": str(error)}
    print(json.dumps(result, indent=2))
    return int(result["status"] == "FAIL")


if __name__ == "__main__":
    raise SystemExit(main())
