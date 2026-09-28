"""Bounded reference controller for a separate, optional packet-level lab.

No sockets, shell commands, scenario labels, or model calls belong here. The
frozen original TrustBoundary is composed, never modified. This controller is
NOT an LLM, IDS benchmark, E2 client, or proof of production safety.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import math
from statistics import fmean
from typing import Any

from .audit import canonical_sha256
from .engine import TrustBoundary

METHODS = ("no_action", "fixed_rule", "current_gate", "evidence_feedback")
TARGET = "ue-lab-suspect"
PRINCIPAL = "agent-responder-01"


@dataclass(frozen=True)
class Settings:
    version: str = "closed-loop-pilot-0.1"
    capacity_kbit: int = 1000
    packet_bytes: int = 512
    duration_seconds: int = 20
    legitimate_pps: int = 100
    background_pps: int = 120
    flood_pps: int = 400
    event_start: int = 4
    event_end: int = 14
    benign_burst_seconds: float = 0.6
    alert_pps: float = 250
    minimum_delivery_ratio: float = 0.85
    maximum_evidence_age_seconds: float = 2.5
    corroboration_windows: int = 2
    reduction_percent: int = 80
    action_ttl_seconds: int = 6
    monitor_grace_seconds: float = 1
    monitor_windows: int = 2
    minimum_delivery_improvement: float = 0.10
    maximum_delivery_worsening: float = 0.10

    @classmethod
    def from_mapping(cls, value: Any) -> "Settings":
        if not isinstance(value, dict) or set(value) != {f.name for f in fields(cls)}:
            raise ValueError("Closed-loop settings require exactly the documented fields")
        result = cls(**value)
        if result.version != "closed-loop-pilot-0.1":
            raise ValueError("Unknown pilot protocol version")
        integers = ("capacity_kbit", "packet_bytes", "duration_seconds", "legitimate_pps",
                    "background_pps", "flood_pps", "event_start", "event_end",
                    "corroboration_windows", "reduction_percent", "action_ttl_seconds",
                    "monitor_windows")
        for name, item in value.items():
            if name == "version":
                continue
            if isinstance(item, bool) or not isinstance(item, (float, int)) or not math.isfinite(item):
                raise ValueError(f"Invalid finite numeric setting: {name}")
            if name in integers and not isinstance(item, int):
                raise ValueError(f"Integer required: {name}")
            if item <= 0:
                raise ValueError(f"Positive setting required: {name}")
        if not 100 <= result.capacity_kbit <= 10000 or not 64 <= result.packet_bytes <= 1200:
            raise ValueError("Capacity or packet size exceeds lab bounds")
        if not 10 <= result.duration_seconds <= 60:
            raise ValueError("Episode duration must be 10..60 seconds")
        if any(getattr(result, key) > 1000 for key in ("legitimate_pps", "background_pps", "flood_pps")):
            raise ValueError("Offered rate exceeds lab bound")
        if result.flood_pps != 400 or result.packet_bytes != 512:
            raise ValueError("Pilot actuator mapping is fixed to a 400 pps, 512-byte reference")
        if not 0 < result.event_start < result.event_end < result.duration_seconds:
            raise ValueError("Invalid event interval")
        if not result.benign_burst_seconds < result.event_end - result.event_start:
            raise ValueError("Benign burst must be shorter than the event")
        if not 1 <= result.reduction_percent <= 80 or result.action_ttl_seconds > 30:
            raise ValueError("Actuation exceeds pilot bounds")
        if result.corroboration_windows != 2 or not 1 <= result.monitor_windows <= 5:
            raise ValueError("Unsupported monitoring window count")
        for key in ("minimum_delivery_ratio", "minimum_delivery_improvement", "maximum_delivery_worsening"):
            if not 0 < getattr(result, key) <= 1:
                raise ValueError(f"Ratio outside (0,1]: {key}")
        if result.maximum_evidence_age_seconds > 5 or result.monitor_grace_seconds > 5:
            raise ValueError("Unbounded evidence age or monitoring grace")
        if result.action_ttl_seconds <= result.monitor_grace_seconds + result.monitor_windows:
            raise ValueError("TTL must leave time for feedback before expiry")
        return result


@dataclass(frozen=True)
class Observation:
    """Only live measurements; no scenario or intended-answer fields."""
    window_start: float
    window_end: float
    legitimate_sent: int
    legitimate_received: int
    suspect_sent: int
    target: str = TARGET

    def valid_at(self, now: float, maximum_age: float) -> bool:
        numeric = (self.window_start, self.window_end, now)
        if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) for x in numeric):
            return False
        counts = (self.legitimate_sent, self.legitimate_received, self.suspect_sent)
        if any(type(x) is not int or not 0 <= x <= 5000 for x in counts):
            return False
        return (self.target == TARGET and self.window_start >= 0
                and 0.9 <= self.window_end - self.window_start <= 1.1
                and 0 <= now - self.window_end <= maximum_age
                and 0 <= self.legitimate_received <= self.legitimate_sent
                and self.legitimate_sent > 0)

    @property
    def delivery_ratio(self) -> float:
        # Worker publishes matched send cohorts after a fixed 500 ms deadline.
        return self.legitimate_received / self.legitimate_sent

    @property
    def suspect_pps(self) -> float:
        return self.suspect_sent / (self.window_end - self.window_start)


class ReferenceController:
    """One bounded intervention per episode, with optional evidence/feedback.

Action execution is separate: the caller must acknowledge successful dispatch
with ``applied``. Acknowledgement is not evidence of mitigation effectiveness.
"""
    def __init__(self, method: str, settings: Settings, gate: TrustBoundary):
        if method not in METHODS:
            raise ValueError("Unknown comparator")
        self.method = method
        self.settings = Settings.from_mapping(asdict(settings))
        self.gate = gate
        self.history: list[Observation] = []
        self.after: list[Observation] = []
        self.applied_at: float | None = None
        self.pre_delivery: float | None = None
        self.pending = False
        self.authorized_at: float | None = None
        self.finished = False
        self.last_end = -1.0

    def validate_dispatch(self, now: float) -> None:
        if (not self.pending or isinstance(now, bool) or not isinstance(now, (int, float))
                or not math.isfinite(now) or self.authorized_at is None
                or not 0 <= now - self.authorized_at <= 1.0
                or not all(x.valid_at(now, self.settings.maximum_evidence_age_seconds) for x in self.history)):
            raise ValueError("No authorized pending action")

    def applied(self, now: float) -> None:
        self.validate_dispatch(now)
        self.pending = False
        # Start TTL at authorization, never extend it with slow dispatch.
        self.applied_at = self.authorized_at

    def restored(self) -> None:
        self.applied_at = None
        self.pending = False
        self.authorized_at = None
        self.finished = True

    def expiry(self, now: float) -> dict[str, Any] | None:
        if self.applied_at is not None and now - self.applied_at >= self.settings.action_ttl_seconds:
            return {"kind": "restore", "reason": "ACTION_TTL_EXPIRED"}
        return None

    def watchdog(self, now: float) -> dict[str, Any] | None:
        expiry = self.expiry(now)
        if expiry:
            return expiry
        if (self.applied_at is not None and self.method == "evidence_feedback"
                and now - self.last_end > self.settings.maximum_evidence_age_seconds):
            return {"kind": "restore", "reason": "POST_ACTION_TELEMETRY_MISSING"}
        return None

    def step(self, observation: Observation, *, now: float, utc_now: datetime) -> dict[str, Any]:
        if utc_now.tzinfo is None:
            raise ValueError("UTC-aware proposal timestamp required")
        expiry = self.expiry(now)
        if expiry:
            return expiry
        if self.finished or self.method == "no_action":
            return {"kind": "observe", "reason": "NO_INTERVENTION"}
        if not observation.valid_at(now, self.settings.maximum_evidence_age_seconds):
            self.history.clear()
            if self.applied_at is not None and self.method == "evidence_feedback":
                return {"kind": "restore", "reason": "POST_ACTION_TELEMETRY_UNVERIFIABLE"}
            return {"kind": "abstain", "reason": "EVIDENCE_INVALID_OR_STALE"}
        if observation.window_end <= self.last_end:
            return {"kind": "abstain", "reason": "DUPLICATE_OR_REORDERED_WINDOW"}
        if self.history and abs(observation.window_start - self.history[-1].window_end) > 0.01:
            self.history.clear()
            self.after.clear()
        self.last_end = observation.window_end
        self.history = (self.history + [observation])[-self.settings.corroboration_windows:]
        if self.applied_at is not None:
            if (self.method == "evidence_feedback"
                    and observation.window_start >= self.applied_at + self.settings.monitor_grace_seconds):
                self.after.append(observation)
                self.after = [x for x in self.after[-self.settings.monitor_windows:]
                              if x.valid_at(now, self.settings.maximum_evidence_age_seconds)]
                if len(self.after) >= self.settings.monitor_windows:
                    change = fmean(x.delivery_ratio for x in self.after) - self.pre_delivery
                    if change <= -self.settings.maximum_delivery_worsening:
                        return {"kind": "restore", "reason": "OBSERVED_SERVICE_WORSENING", "delivery_change": change}
                    if change < self.settings.minimum_delivery_improvement:
                        return {"kind": "restore", "reason": "NO_OBSERVED_BENEFIT", "delivery_change": change}
            return {"kind": "observe", "reason": "MONITOR_ACTIVE_INTERVENTION"}
        if self.pending:
            return {"kind": "abstain", "reason": "DISPATCH_PENDING"}
        if observation.suspect_pps < self.settings.alert_pps:
            return {"kind": "observe", "reason": "RATE_ALERT_ABSENT"}
        if self.method == "evidence_feedback":
            corroborated = (len(self.history) == self.settings.corroboration_windows
                            and all(x.suspect_pps >= self.settings.alert_pps
                                    and x.delivery_ratio < self.settings.minimum_delivery_ratio
                                    and x.valid_at(now, self.settings.maximum_evidence_age_seconds)
                                    for x in self.history))
            if not corroborated:
                return {"kind": "abstain", "reason": "PERSISTENT_SERVICE_IMPACT_NOT_CORROBORATED"}
        evidence_digest = canonical_sha256(asdict(observation))
        proposal = {
            "action_id": f"lab-action-{int(observation.window_end)}",
            "incident_id": "lab-rate-alert",
            "requested_at": utc_now.isoformat(),
            "agent": {"agent_id": PRINCIPAL, "role": "security_responder"},
            "action": "rate_limit_ue", "interface": "E2",
            "target": {"target_type": "ue", "target_id": TARGET,
                       "cell_id": "cell-lab", "slice_id": "slice-lab-best-effort"},
            "parameters": {"control_parameter": "traffic_rate_limit",
                           "reduction_percent": self.settings.reduction_percent},
            "risk_level": "medium", "ttl_seconds": self.settings.action_ttl_seconds,
            "expected_kpi": "legitimate_delivery_ratio",
            "rollback": {"available": True, "procedure": "Remove only owned lab ingress limiter; verify readback."},
            "evidence_refs": ["lab-observation-sha256:" + canonical_sha256(asdict(x)) for x in self.history],
            "approval": None,
        }
        decision: dict[str, Any] = {"kind": "apply", "reason": "REFERENCE_RATE_ALERT",
                                    "proposal": proposal, "observation_sha256": evidence_digest}
        if self.method in ("current_gate", "evidence_feedback"):
            outcome = self.gate.evaluate(proposal, authenticated_principal=PRINCIPAL, as_of=utc_now)
            decision["gate_evaluation"] = outcome.to_mapping()
            if outcome.decision.value != "ALLOW":
                decision["kind"] = "abstain"
                decision["reason"] = "GOVERNANCE_GATE_NOT_ALLOW"
                return decision
        self.pre_delivery = fmean(x.delivery_ratio for x in self.history)
        self.pending = True
        self.authorized_at = now
        return decision
