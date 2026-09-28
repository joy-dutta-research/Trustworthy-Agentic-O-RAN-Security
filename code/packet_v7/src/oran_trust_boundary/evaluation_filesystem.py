"""Strict accounting for a growing, owned experiment-output tree.

The only tolerated disappearance is a Windows leaf named desktop.ini after
directory enumeration. Its parent chain must still exist and be safe. This
exception never applies to static source/input verification, existing files,
symlinks/reparse points, missing parents, or other I/O failures. Skips are
recorded locally and the diagnostic log itself is included in byte accounting.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

OUTPUT_MONITOR_VERSION = "dynamic-output-scan/0.2.1"
MONITOR_LOG_NAME = "_output_monitor_events.jsonl"


class OutputScanError(ValueError):
    """An output-tree entry cannot safely be included in the resource scan."""


def _is_windows() -> bool:
    return os.name == "nt"


def _reject_special(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise OutputScanError("output symbolic links and reparse points are refused")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise OutputScanError("special output filesystem entries are refused")


def _record_skips(directory: Path, events: list[dict[str, Any]],
                  check_chain: Callable[[Path], Any], observed_sizes: dict[Path, int]) -> int:
    """Append diagnostics and return their correction to this scan's byte sum."""
    path = directory / MONITOR_LOG_NAME
    check_chain(path.parent)
    prior_info = None
    try:
        prior_info = path.lstat()
    except FileNotFoundError:
        # Creating this scanner-owned log is allowed only if it was absent in
        # this enumeration, never to conceal removal of an observed log file.
        if path in observed_sizes:
            raise
        check_chain(path.parent)
    if prior_info is not None:
        _reject_special(prior_info)
        if not stat.S_ISREG(prior_info.st_mode):
            raise OutputScanError("output monitor log must be a regular file")
    payload = b"".join((json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
                       for event in events)
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if prior_info is None:
        # O_NOFOLLOW is unavailable on Windows. Exclusive creation prevents
        # following a raced-in entry when the monitor log was absent.
        flags |= os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "ab") as handle:
        opened = os.fstat(handle.fileno())
        _reject_special(opened)
        if prior_info is not None and (prior_info.st_dev, prior_info.st_ino) != (opened.st_dev, opened.st_ino):
            raise OutputScanError("output monitor log identity changed before append")
        handle.write(payload)
        handle.flush()
        after = os.fstat(handle.fileno())
    check_chain(path.parent)
    final = path.lstat()
    _reject_special(final)
    if (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino) or final.st_size < after.st_size:
        raise OutputScanError("output monitor log changed during append")
    return final.st_size - observed_sizes.get(path, 0)


def dynamic_tree_bytes(directory: Path, *, check_chain: Callable[[Path], Any]) -> int:
    """Count existing regular files; strictly validate each parent and leaf.

    Each enumerated leaf is lstat'ed once; no follow-up is_file/stat race is
    introduced. On the one permitted missing-leaf condition, validate its
    parents AGAIN so a missing directory cannot be mistaken for metadata.
    No retry or broad FileNotFound/OSError suppression is performed.
    """
    check_chain(directory)
    initial = directory.lstat()
    _reject_special(initial)
    if not stat.S_ISDIR(initial.st_mode):
        raise OutputScanError("output scan root must be a directory")
    sizes: dict[Path, int] = {}
    skipped: list[dict[str, Any]] = []

    def scan(current: Path) -> None:
        check_chain(current)
        # scandir errors (including a vanished directory) are intentionally
        # not swallowed by a recursive glob implementation.
        with os.scandir(current) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            path = current / name
            check_chain(path.parent)
            try:
                info = path.lstat()
            except FileNotFoundError as error:
                check_chain(path.parent)
                if not (_is_windows() and path.name.casefold() == "desktop.ini"):
                    raise
                skipped.append({"event": "vanished_windows_directory_metadata", "path": path.relative_to(directory).as_posix(),
                                "errno": error.errno, "winerror": getattr(error, "winerror", None),
                                "output_monitor_version": OUTPUT_MONITOR_VERSION,
                                "at_utc": datetime.now(UTC).isoformat()})
                continue
            _reject_special(info)
            if stat.S_ISDIR(info.st_mode):
                scan(path)
            else:
                sizes[path] = info.st_size

    try:
        scan(directory)
    except BaseException:
        if skipped:
            _record_skips(directory, skipped, check_chain, sizes)
        raise
    total = sum(sizes.values())
    if skipped:
        total += _record_skips(directory, skipped, check_chain, sizes)
    return total
