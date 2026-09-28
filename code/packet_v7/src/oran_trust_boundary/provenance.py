"""Privacy-conscious provenance for reproducible benchmark releases."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest(root: str | Path) -> dict[str, str]:
    root_path = Path(root).resolve()
    included_roots = (
        root_path / "src",
        root_path / "scripts",
        root_path / "tests",
        root_path / "configs",
        root_path / "schemas",
    )
    files: list[Path] = []
    for directory in included_roots:
        if directory.exists():
            files.extend(
                item
                for item in directory.rglob("*")
                if item.is_file()
                and not item.is_symlink()
                and "__pycache__" not in item.parts
                and item.suffix != ".pyc"
            )
    return {
        path.relative_to(root_path).as_posix(): sha256_file(path)
        for path in sorted(set(files))
    }


def combined_manifest_sha256(manifest: dict[str, str]) -> str:
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_run_manifest(
    *,
    root: str | Path,
    suite_path: str | Path,
    policy_path: str | Path,
    approval_registry_path: str | Path,
    raw_results_path: str | Path,
    summary_path: str | Path,
    dataset_context_path: str | Path | None,
    repeats: int,
    timing_seed: int,
) -> dict[str, Any]:
    sources = source_manifest(root)
    clock = time.get_clock_info("perf_counter")
    inputs: dict[str, Any] = {
        "suite_sha256": sha256_file(suite_path),
        "policy_sha256": sha256_file(policy_path),
        "approval_registry_sha256": sha256_file(approval_registry_path),
        "source_tree_sha256": combined_manifest_sha256(sources),
        "source_files": sources,
        "dataset_context_sha256": None,
        "dataset_context_status": "not_supplied_smoke_test",
    }
    if dataset_context_path is not None:
        inputs["dataset_context_sha256"] = sha256_file(dataset_context_path)
        inputs["dataset_context_status"] = "included"
    return {
        "manifest_version": "0.1.0",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "experiment": {
            "repeats_per_case": repeats,
            "warmup_evaluations_per_case": 5,
            "timing_seed": timing_seed,
            "clock": {
                "implementation": clock.implementation,
                "monotonic": clock.monotonic,
                "adjustable": clock.adjustable,
                "resolution_seconds": clock.resolution,
            },
        },
        "environment": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "byte_order": sys.byteorder,
        },
        "inputs": inputs,
        "outputs": {
            "raw_decisions_sha256": sha256_file(raw_results_path),
            "summary_sha256": sha256_file(summary_path),
        },
        "privacy_note": "Usernames, hostnames, absolute paths, and environment variables are intentionally omitted.",
    }


def write_run_manifest(manifest: dict[str, Any], output: str | Path) -> Path:
    output_path = Path(output)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path
