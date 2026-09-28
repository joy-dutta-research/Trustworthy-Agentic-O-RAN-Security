"""Strict, size-bounded JSON parsing for security-relevant inputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class StrictJsonError(ValueError):
    """Raised when JSON is ambiguous, oversized, or non-standard."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StrictJsonError(f"non-finite JSON constant is not permitted: {value}")


def strict_json_loads(value: str, *, maximum_bytes: int) -> Any:
    if not isinstance(value, str):
        raise StrictJsonError("JSON input must be text")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise StrictJsonError(f"JSON input exceeds {maximum_bytes} bytes")
    try:
        return json.loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise StrictJsonError(f"invalid JSON: {exc}") from exc


def strict_json_load(path: str | Path, *, maximum_bytes: int) -> Any:
    input_path = Path(path)
    size = input_path.stat().st_size
    if size > maximum_bytes:
        raise StrictJsonError(f"{input_path.name} exceeds {maximum_bytes} bytes")
    try:
        text = input_path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise StrictJsonError(f"{input_path.name} is not valid UTF-8") from exc
    return strict_json_loads(text, maximum_bytes=maximum_bytes)
