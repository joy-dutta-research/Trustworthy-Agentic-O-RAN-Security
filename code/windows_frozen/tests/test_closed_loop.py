from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.closed_loop import METHODS, Observation, ReferenceController, Settings
from oran_trust_boundary.engine import TrustBoundary
from oran_trust_boundary.jsonio import strict_json_load


class ClosedLoopControllerTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings.from_mapping(strict_json_load(
            ROOT / "configs/closed_loop_pilot.json", maximum_bytes=16384))
        self.gate = TrustBoundary.from_file(ROOT / "configs/paper_policy.json")
        self.timestamp = datetime(2026, 1, 1, tzinfo=UTC)

    def controller(self, method="evidence_feedback"):
        return ReferenceController(method, self.settings, self.gate)

    def obs(self, end, received=40, suspect=400):
        return Observation(end - 1, end, 100, received, suspect)

    def step(self, controller, observation, now=None):
        return controller.step(observation, now=observation.window_end if now is None else now,
                               utc_now=self.timestamp)

    def test_settings_reject_unknown_missing_nonfinite_and_unsafe_values(self):
        for change in ({"new": 1}, {"reduction_percent": 81}, {"duration_seconds": 61},
                       {"legitimate_pps": True}, {"alert_pps": float("nan")},
                       {"packet_bytes": 1000}, {"action_ttl_seconds": 2}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                Settings.from_mapping(asdict(self.settings) | change)
        value = asdict(self.settings)
        del value["version"]
        with self.assertRaises(ValueError):
            Settings.from_mapping(value)

    def test_no_action_never_proposes(self):
        self.assertEqual(self.step(self.controller("no_action"), self.obs(1))["kind"], "observe")

    def test_current_gate_passes_real_contract_without_modifying_policy(self):
        before = self.gate.policy_sha256
        event = self.step(self.controller("current_gate"), self.obs(1))
        self.assertEqual(event["kind"], "apply")
        self.assertEqual(event["gate_evaluation"]["decision"], "ALLOW")
        self.assertEqual(before, self.gate.policy_sha256)

    def test_fixed_rule_and_current_gate_same_bounded_proposal(self):
        first = self.step(self.controller("fixed_rule"), self.obs(1))
        second = self.step(self.controller("current_gate"), self.obs(1))
        self.assertEqual(first["proposal"], second["proposal"])

    def test_two_consecutive_impaired_windows_required(self):
        c = self.controller()
        self.assertEqual(self.step(c, self.obs(1))["kind"], "abstain")
        self.assertEqual(self.step(c, self.obs(2))["kind"], "apply")

    def test_short_burst_does_not_trigger_full_controller(self):
        c = self.controller()
        self.assertEqual(self.step(c, self.obs(1))["kind"], "abstain")
        self.assertEqual(self.step(c, self.obs(2, received=100, suspect=120))["kind"], "observe")
        self.assertFalse(c.pending)

    def test_high_rate_without_service_impairment_not_sufficient(self):
        c = self.controller()
        self.step(c, self.obs(1, received=100))
        self.assertEqual(self.step(c, self.obs(2, received=100))["kind"], "abstain")

    def test_duplicate_windows_cannot_supply_corroboration(self):
        c = self.controller()
        self.step(c, self.obs(1))
        self.assertEqual(self.step(c, self.obs(1))["reason"], "DUPLICATE_OR_REORDERED_WINDOW")
        self.assertFalse(c.pending)

    def test_nonconsecutive_windows_clear_corroboration(self):
        c = self.controller()
        self.step(c, self.obs(1))
        self.assertEqual(self.step(c, self.obs(3))["kind"], "abstain")

    def test_earlier_corroboration_is_rechecked_for_freshness(self):
        c = self.controller()
        self.step(c, self.obs(1))
        self.assertEqual(self.step(c, self.obs(2), now=4)["kind"], "abstain")

    def test_missing_post_action_window_resets_monitor(self):
        c = self.controller()
        self.activate(c)
        self.step(c, self.obs(4))
        self.assertEqual(self.step(c, self.obs(6))["kind"], "observe")

    def test_invalid_stale_future_wrong_target_evidence_fails_closed(self):
        examples = [(self.obs(1), 4), (self.obs(1), 0),
                    (replace(self.obs(1), target="other"), 1),
                    (replace(self.obs(1), legitimate_sent=0), 1),
                    (replace(self.obs(1), suspect_sent=True), 1),
                    (replace(self.obs(1), window_start=float("nan")), 1)]
        for observation, now in examples:
            for method in METHODS[1:]:
                with self.subTest(observation=observation, method=method):
                    self.assertEqual(self.step(self.controller(method), observation, now)["kind"], "abstain")

    def activate(self, c):
        self.step(c, self.obs(1))
        self.step(c, self.obs(2))
        c.applied(2)

    def test_no_benefit_requests_restore(self):
        c = self.controller()
        self.activate(c)
        self.assertEqual(self.step(c, self.obs(4))["kind"], "observe")
        self.assertEqual(self.step(c, self.obs(5))["reason"], "NO_OBSERVED_BENEFIT")

    def test_improvement_kept_until_ttl(self):
        c = self.controller()
        self.activate(c)
        self.step(c, self.obs(4, received=95))
        self.assertEqual(self.step(c, self.obs(5, received=95))["kind"], "observe")
        self.assertIsNone(c.expiry(7.9))
        self.assertEqual(c.expiry(8)["kind"], "restore")

    def test_worsening_requests_restore(self):
        c = self.controller()
        self.activate(c)
        self.step(c, self.obs(4, received=10))
        self.assertEqual(self.step(c, self.obs(5, received=10))["reason"], "OBSERVED_SERVICE_WORSENING")

    def test_unverifiable_post_action_observation_restores(self):
        c = self.controller()
        self.activate(c)
        self.assertEqual(self.step(c, replace(self.obs(3), target="wrong"))["kind"], "restore")

    def test_after_verified_restoration_no_repeat_intervention(self):
        c = self.controller()
        self.activate(c)
        c.restored()
        self.assertEqual(self.step(c, self.obs(4))["kind"], "observe")
        self.assertFalse(c.pending)

    def test_invalid_dispatch_and_naive_clock_rejected(self):
        c = self.controller()
        with self.assertRaises(ValueError):
            c.applied(0)
        with self.assertRaises(ValueError):
            c.step(self.obs(1), now=1, utc_now=datetime(2026, 1, 1))

    def test_dispatch_does_not_refresh_expired_authorization(self):
        c = self.controller()
        self.step(c, self.obs(1))
        self.step(c, self.obs(2))
        with self.assertRaises(ValueError):
            c.applied(20)

    def test_full_evidence_chain_bound_to_proposal(self):
        c = self.controller()
        self.step(c, self.obs(1))
        event = self.step(c, self.obs(2))
        self.assertEqual(len(event["proposal"]["evidence_refs"]), 2)

    def test_missing_telemetry_watchdog_precedes_ttl(self):
        c = self.controller()
        self.activate(c)
        self.assertIsNone(c.watchdog(4.4))
        self.assertEqual(c.watchdog(4.6)["reason"], "POST_ACTION_TELEMETRY_MISSING")


if __name__ == "__main__":
    unittest.main()
