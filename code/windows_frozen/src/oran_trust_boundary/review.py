"""Blinded co-author label-review support."""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable


ALLOWED_DECISIONS = ("ALLOW", "DENY", "ESCALATE")


def _opaque_id(blind_key: bytes, namespace: str, value: str) -> str:
    digest = hmac.new(
        blind_key,
        f"{namespace}:{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{namespace}-{digest[:16]}"


def export_blinded_review(
    cases: Iterable[dict[str, Any]],
    output: str | Path,
    *,
    blind_key: bytes,
) -> tuple[Path, dict[str, str]]:
    """Export proposals without generated labels, categories, or expected reasons."""

    if not isinstance(blind_key, bytes) or len(blind_key) < 32:
        raise ValueError("blind_key must contain at least 32 bytes")

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "review_id",
        "evaluation_time",
        "authenticated_principal",
        "source_context_json",
        "proposal_json",
        "active_actions_json",
        "reviewer_decision",
        "reviewer_reason",
        "reviewer_notes",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        mapping: dict[str, str] = {}
        for case in sorted(cases, key=lambda item: item["case_id"]):
            case_id = case["case_id"]
            review_id = _opaque_id(blind_key, "review", case_id)
            if review_id in mapping:
                raise ValueError("opaque review ID collision")
            mapping[review_id] = case_id
            proposal = deepcopy(case["proposal"])
            proposal["action_id"] = _opaque_id(
                blind_key, "action", proposal["action_id"]
            )
            if proposal["approval"] is not None:
                proposal["approval"]["approval_id"] = _opaque_id(
                    blind_key,
                    "approval",
                    proposal["approval"]["approval_id"],
                )
            active_actions = deepcopy(case["active_actions"])
            for active in active_actions:
                active["action_id"] = _opaque_id(
                    blind_key, "active", active["action_id"]
                )
                if active["approval"] is not None:
                    active["approval"]["approval_id"] = _opaque_id(
                        blind_key,
                        "active-approval",
                        active["approval"]["approval_id"],
                    )
            writer.writerow(
                {
                    "review_id": review_id,
                    "evaluation_time": case["evaluation_time"],
                    "authenticated_principal": case["authenticated_principal"],
                    "source_context_json": json.dumps(
                        case["source_context"], sort_keys=True, separators=(",", ":")
                    ),
                    "proposal_json": json.dumps(
                        proposal, sort_keys=True, separators=(",", ":")
                    ),
                    "active_actions_json": json.dumps(
                        active_actions, sort_keys=True, separators=(",", ":")
                    ),
                    "reviewer_decision": "",
                    "reviewer_reason": "",
                    "reviewer_notes": "",
                }
            )
    return output_path, mapping


def load_review(path: str | Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=2):
            case_id = (row.get("review_id") or "").strip()
            decision = (row.get("reviewer_decision") or "").strip().upper()
            if not case_id:
                raise ValueError(f"missing review_id on row {row_number}")
            if case_id in labels:
                raise ValueError(f"duplicate review_id {case_id}")
            if decision not in ALLOWED_DECISIONS:
                raise ValueError(
                    f"invalid or missing reviewer_decision for {case_id}: {decision!r}"
                )
            labels[case_id] = decision
    return labels


def compare_reviews(first: dict[str, str], second: dict[str, str]) -> dict[str, Any]:
    if set(first) != set(second):
        missing_first = sorted(set(second) - set(first))
        missing_second = sorted(set(first) - set(second))
        raise ValueError(
            f"review case sets differ; missing_first={missing_first}, "
            f"missing_second={missing_second}"
        )
    case_ids = sorted(first)
    total = len(case_ids)
    if total == 0:
        raise ValueError("reviews are empty")
    observed_count = sum(first[case] == second[case] for case in case_ids)
    first_counts = Counter(first.values())
    second_counts = Counter(second.values())
    expected_agreement = sum(
        (first_counts[label] / total) * (second_counts[label] / total)
        for label in ALLOWED_DECISIONS
    )
    observed_agreement = observed_count / total
    kappa = (
        (observed_agreement - expected_agreement) / (1 - expected_agreement)
        if expected_agreement < 1
        else 1.0
    )
    confusion = {
        first_label: {
            second_label: sum(
                first[case] == first_label and second[case] == second_label
                for case in case_ids
            )
            for second_label in ALLOWED_DECISIONS
        }
        for first_label in ALLOWED_DECISIONS
    }
    disagreements = [case for case in case_ids if first[case] != second[case]]
    return {
        "case_count": total,
        "observed_agreement": observed_agreement,
        "cohens_kappa": kappa,
        "confusion_matrix": confusion,
        "disagreement_case_ids": disagreements,
    }
