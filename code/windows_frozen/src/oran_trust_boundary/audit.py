"""Creation and integrity checksums for deterministic decision audit records.

The record checksum detects accidental changes but is not a digital signature.
Production deployments should anchor or sign records outside this prototype.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from typing import Any, Iterable, Mapping

from .models import ActionProposal, Decision


def canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_input_sha256(value: Any) -> str:
    """Hash untrusted input without allowing serialization errors to escape."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        fallback = _safe_fingerprint(value)
        encoded = json.dumps(fallback, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return hashlib.sha256(encoded).hexdigest()


def _safe_fingerprint(
    value: Any,
    *,
    depth: int = 0,
    seen: set[int] | None = None,
) -> Any:
    """Create a bounded fingerprint without invoking an object's ``repr``."""

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"non_finite_float": "nan"}
        if math.isinf(value):
            return {"non_finite_float": "positive_inf" if value > 0 else "negative_inf"}
        return value
    if isinstance(value, str):
        return value[:512]
    if depth >= 6:
        return {"truncated_at_depth": depth}
    if seen is None:
        seen = set()
    if isinstance(value, (dict, list, tuple)):
        identity = id(value)
        if identity in seen:
            return {"cycle": type(value).__name__}
        seen.add(identity)
        try:
            if isinstance(value, dict):
                entries = []
                for index, (key, item) in enumerate(value.items()):
                    if index >= 64:
                        entries.append({"truncated_entries": len(value) - 64})
                        break
                    entries.append(
                        [
                            _safe_fingerprint(key, depth=depth + 1, seen=seen),
                            _safe_fingerprint(item, depth=depth + 1, seen=seen),
                        ]
                    )
                return {"dict_entries": entries}
            return {
                type(value).__name__: [
                    _safe_fingerprint(item, depth=depth + 1, seen=seen)
                    for item in value[:64]
                ]
            }
        finally:
            seen.discard(identity)
    value_type = type(value)
    return {
        "unsupported_type": f"{value_type.__module__}.{value_type.__qualname__}"
    }


def _finish_record(record: dict[str, Any]) -> dict[str, Any]:
    record["record_sha256"] = canonical_sha256(record)
    return record


def verify_record_checksum(record: Mapping[str, Any]) -> bool:
    """Verify the prototype's accidental-tamper checksum."""

    if not isinstance(record, Mapping):
        return False
    supplied = record.get("record_sha256")
    if not isinstance(supplied, str):
        return False
    unsigned = dict(record)
    unsigned.pop("record_sha256", None)
    try:
        return canonical_sha256(unsigned) == supplied
    except (TypeError, ValueError, RecursionError):
        return False


def create_audit_record(
    proposal: ActionProposal,
    decision: Decision,
    reason_codes: Iterable[str],
    policy_ids: Iterable[str],
    policy_version: str,
    policy_sha256: str,
    evaluated_at: datetime,
    authenticated_principal: str | None,
) -> dict[str, Any]:
    proposal_hash = canonical_sha256(proposal.to_mapping())
    stable_identity = {
        "proposal_sha256": proposal_hash,
        "decision": decision.value,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "reason_codes": sorted(set(reason_codes)),
        "policy_ids": sorted(set(policy_ids)),
        "authenticated_principal": authenticated_principal or "unavailable",
    }
    audit_id = f"audit-{canonical_sha256(stable_identity)[:24]}"
    return _finish_record({
        "audit_id": audit_id,
        "action_id": proposal.action_id,
        "incident_id": proposal.incident_id,
        "decision": decision.value,
        "reason_codes": list(reason_codes),
        "policy_ids": list(policy_ids),
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "proposal_sha256": proposal_hash,
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        "authenticated_principal": authenticated_principal or "unavailable",
    })


def create_rejection_audit_record(
    proposal_value: Any,
    decision: Decision,
    reason_codes: Iterable[str],
    policy_ids: Iterable[str],
    policy_version: str,
    policy_sha256: str,
    evaluated_at: datetime,
    authenticated_principal: str | None,
) -> dict[str, Any]:
    proposal_hash = safe_input_sha256(proposal_value)
    action_id = "unavailable"
    incident_id = "unavailable"
    if isinstance(proposal_value, Mapping):
        if isinstance(proposal_value.get("action_id"), str):
            action_id = proposal_value["action_id"][:128]
        if isinstance(proposal_value.get("incident_id"), str):
            incident_id = proposal_value["incident_id"][:128]
    stable_identity = {
        "proposal_sha256": proposal_hash,
        "decision": decision.value,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "reason_codes": sorted(set(reason_codes)),
        "policy_ids": sorted(set(policy_ids)),
        "authenticated_principal": authenticated_principal or "unavailable",
    }
    return _finish_record(
        {
            "audit_id": f"audit-{canonical_sha256(stable_identity)[:24]}",
            "action_id": action_id,
            "incident_id": incident_id,
            "decision": decision.value,
            "reason_codes": list(reason_codes),
            "policy_ids": list(policy_ids),
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
            "proposal_sha256": proposal_hash,
            "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
            "authenticated_principal": authenticated_principal or "unavailable",
        }
    )


def completeness(record: Mapping[str, Any] | None, required_fields: Iterable[str]) -> float:
    fields = tuple(required_fields)
    if not fields or not record:
        return 0.0
    present = sum(field in record and record[field] not in (None, "", []) for field in fields)
    return present / len(fields)
