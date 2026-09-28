"""Separately specified v0.2 reference interpreter; no production-core imports.

This is specification consistency evidence, not independent human validation.
The accepted structural profile intentionally includes the documented legacy
Python restrictions, rather than claiming JSON Schema equivalence.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError("timestamp profile")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result


def _schema_accepts(value: Any, schema: dict, path: str = "") -> bool:
    if "oneOf" in schema:
        return sum(_schema_accepts(value, item, path) for item in schema["oneOf"]) == 1
    if "enum" in schema and (not isinstance(value, str) or value not in schema["enum"]):
        return False
    if "const" in schema and value != schema["const"]:
        return False
    kinds = schema.get("type", [])
    kinds = [kinds] if isinstance(kinds, str) else kinds
    checks = {"null": value is None, "object": isinstance(value, dict),
              "array": isinstance(value, list), "string": isinstance(value, str),
              "integer": type(value) is int, "boolean": type(value) is bool}
    if kinds and not any(checks.get(kind, False) for kind in kinds):
        return False
    if value is None:
        return True
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            return False
        props = schema.get("properties", {})
        if not set(schema.get("required", [])) <= value.keys():
            return False
        if schema.get("additionalProperties") is False and not value.keys() <= props.keys():
            return False
        if not schema.get("minProperties", 0) <= len(value) <= schema.get("maxProperties", math.inf):
            return False
        return all(_schema_accepts(item, props[key], path + "." + key)
                   for key, item in value.items() if key in props)
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", math.inf):
            return False
        if schema.get("uniqueItems") and len({canonical_digest(x) for x in value}) != len(value):
            return False
        return all(_schema_accepts(x, schema.get("items", {}), path + "[]") for x in value)
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", math.inf):
            return False
        if schema.get("minLength", 0) > 0 and not value.strip():
            return False
        if schema.get("format") == "date-time":
            try:
                _instant(value)
            except (ValueError, OverflowError):
                return False
    if type(value) is int:
        return schema.get("minimum", -math.inf) <= value <= schema.get("maximum", math.inf)
    return True


def _parameter_profile(value: Any, depth: int = 0, ancestors: frozenset = frozenset()) -> bool:
    if depth > 6:
        return False
    if isinstance(value, (dict, list)):
        if id(value) in ancestors or len(value) > 64:
            return False
        ancestors = ancestors | {id(value)}
        if isinstance(value, dict):
            if any(not isinstance(k, str) or not 1 <= len(k) <= 128 for k in value):
                return False
            value = value.values()
        return all(_parameter_profile(x, depth + 1, ancestors) for x in value)
    if isinstance(value, str):
        return len(value) <= 1024
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (int, bool))


class ReferencePolicy:
    """Interpret the separately authored table using only standard-library code."""

    def __init__(self, reference_path: str | Path | None = None,
                 policy_path: str | Path | None = None):
        self.spec = json.loads(Path(reference_path or ROOT / "configs/evaluation_v0.2/reference_policy_v0.1.json").read_text(encoding="utf-8"))
        policy = json.loads(Path(policy_path or ROOT / "configs/paper_policy.json").read_text(encoding="utf-8"))
        self.operator_policy = deepcopy(policy)
        self.principals = dict(policy["principals"])
        self.protected_slices = list(policy["protected_slices"])
        self.schema = json.loads((ROOT / "schemas/action.schema.json").read_text(encoding="utf-8"))
        self.overrides = {}

    def with_overrides(self, *, maximum_reduction_percent: float | None = None,
                       maximum_ttl_seconds: int | None = None) -> "ReferencePolicy":
        result = deepcopy(self)
        if maximum_reduction_percent is not None:
            if type(maximum_reduction_percent) not in (int, float) or not 1 <= maximum_reduction_percent <= 100:
                raise ValueError("invalid reduction bound")
            result.spec["actions"]["rate_limit_ue"]["numeric_bounds"]["reduction_percent"][1] = maximum_reduction_percent
            result.overrides["maximum_reduction_percent"] = maximum_reduction_percent
            result.operator_policy["parameter_bounds"]["rate_limit_ue"]["reduction_percent"]["maximum"] = maximum_reduction_percent
        if maximum_ttl_seconds is not None:
            if type(maximum_ttl_seconds) is not int or not 1 <= maximum_ttl_seconds <= 86400:
                raise ValueError("invalid TTL bound")
            result.spec["time_boundaries"]["maximum_ttl_seconds"] = maximum_ttl_seconds
            result.overrides["maximum_ttl_seconds"] = maximum_ttl_seconds
            result.operator_policy["max_ttl_seconds"] = maximum_ttl_seconds
        return result

    def structural_valid(self, value: Any) -> bool:
        try:
            if not _schema_accepts(value, self.schema):
                return False
            parameters = value["parameters"]
            return (_parameter_profile(parameters) and len(json.dumps(parameters, sort_keys=True,
                    separators=(",", ":"), allow_nan=False).encode()) <= 4096)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False

    def evaluate(self, case: dict) -> dict:
        p = case["proposal"]
        if not self.structural_valid(p):
            return {"decision": "DENY", "reasons": [], "violated_rules": ["R01"],
                    "legacy_limitations": ["L07"], "reason_comparison": "structural_nonempty"}
        now = _instant(case["evaluation_time"])
        action = self.spec["actions"][p["action"]]
        bounds = self.spec["time_boundaries"]
        age = (now - _instant(p["requested_at"])).total_seconds()
        hard: list[tuple[str, str]] = []
        review: list[tuple[str, str]] = []
        limitations = ["L01", "L02", "L08"]
        principal = case.get("authenticated_principal")
        declared = p["agent"]
        identity_reason = (
            "AUTHENTICATED_PRINCIPAL_REQUIRED" if principal is None else
            "AGENT_IDENTITY_MISMATCH" if principal != declared["agent_id"] else
            "UNKNOWN_PRINCIPAL" if principal not in self.principals else
            "AGENT_ROLE_MISMATCH" if self.principals[principal] != declared["role"] else None)
        if identity_reason:
            hard.append(("R02", identity_reason))
        predicates = [
            ("R03", declared["role"] not in action["authorized_roles"], "UNAUTHORIZED_AGENT"),
            ("R04", p["interface"] != action["interface"], "ACTION_INTERFACE_MISMATCH"),
            ("R05", p["target"]["target_type"] != action["target_type"], "ACTION_TARGET_MISMATCH"),
            ("R06", age < -bounds["maximum_future_skew_seconds"], "REQUEST_TIMESTAMP_IN_FUTURE"),
            ("R06", age > bounds["maximum_proposal_age_seconds"], "STALE_ACTION_PROPOSAL"),
            ("R07", action["disruptive"] and p["target"]["slice_id"] in self.protected_slices, "PROTECTED_SLICE_VIOLATION"),
            ("R08", set(p["parameters"]) != set(action["required_fields"]), "ACTION_PARAMETER_CONTRACT_MISMATCH"),
            ("R08", p["parameters"].get("control_parameter") != action["control_parameter"], "CONTROL_PARAMETER_MISMATCH"),
            ("R09", self.spec["risk_order"].index(p["risk_level"]) < self.spec["risk_order"].index(action["minimum_risk"]), "RISK_CLASSIFICATION_UNDERSTATED"),
            ("R10", p["ttl_seconds"] > bounds["maximum_ttl_seconds"], "TTL_EXCEEDS_POLICY"),
            ("R10", age > p["ttl_seconds"], "ACTION_TTL_EXPIRED"),
            ("R11", action["disruptive"] and (not p["rollback"]["available"] or not p["rollback"]["procedure"].strip()), "ROLLBACK_REQUIRED"),
        ]
        hard.extend((rule, reason) for rule, failed, reason in predicates if failed)
        for field, (lower, upper) in action["numeric_bounds"].items():
            value = p["parameters"].get(field)
            if type(value) not in (int, float):
                hard.append(("R08", "REQUIRED_NUMERIC_PARAMETER_MISSING"))
            elif not lower <= value <= upper:
                hard.append(("R08", "PARAMETER_OUT_OF_RANGE"))
        if p["action"] == "rollback_policy":
            limitations.extend(["L03", "L06"])
        elif p["action"] == "notify_operator":
            limitations.append("L06")
        for active in case.get("active_actions", []):
            if not self.structural_valid(active):
                review.append(("R12", "ACTIVE_STATE_UNVERIFIABLE"))
                break
            limitations.append("L05")
            if active["action_id"] == p["action_id"]:
                limitations.append("L04")
                continue
            key = lambda q: (q["interface"], q["target"]["target_type"], q["target"]["target_id"], q["parameters"].get("control_parameter"))
            if active["parameters"].get("control_parameter") and key(active) == key(p):
                review.append(("R12", "ACTION_CONFLICT"))
                break
        approval = p["approval"]
        required = action["action_requires_approval"] or p["risk_level"] in ("high", "critical")
        approval_reason = None
        if required:
            if approval is None:
                approval_reason = "HUMAN_APPROVAL_REQUIRED"
            elif _instant(approval["expires_at"]) <= now:
                approval_reason = "HUMAN_APPROVAL_EXPIRED"
            else:
                record = case.get("approval_registry", {}).get(approval["approval_id"])
                if not isinstance(record, dict) or record.get("status") != "approved":
                    approval_reason = "HUMAN_APPROVAL_UNTRUSTED"
                else:
                    expected = {"action_id": p["action_id"], "agent_id": declared["agent_id"],
                                "approved_by_role": approval["approved_by_role"], "expires_at": approval["expires_at"],
                                "proposal_sha256": canonical_digest(p)}
                    if any(record.get(key) != value for key, value in expected.items()):
                        approval_reason = "HUMAN_APPROVAL_BINDING_MISMATCH"
            if approval_reason:
                review.append(("R13", approval_reason))
        elif approval is not None:
            limitations.append("L09")
        winning = hard or review
        return {"decision": "DENY" if hard else "ESCALATE" if review else "ALLOW",
                "reasons": sorted({reason for _, reason in winning}) if winning else ["POLICY_CHECKS_PASSED"],
                "violated_rules": sorted({rule for rule, _ in hard + review}),
                "legacy_limitations": sorted(set(limitations)), "reason_comparison": "exact_set"}
