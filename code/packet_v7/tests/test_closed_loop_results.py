from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oran_trust_boundary.closed_loop_results import (check_offered_load, paired_pilot_summary,
                                                    percentile, read_jsonl, score_cohorts, score_server)


class ClosedLoopResultTests(unittest.TestCase):
    def records(self):
        return [{"type": "cohort_summary", "counters": {}, "cohorts": [
            {"window_start": i, "window_end": i + 1, "sent": 10, "received": 8,
             "rtt_ms": [10] * 7 + [600]} for i in range(2)]}]

    def test_cohort_denominators_include_late_and_missing_packets(self):
        score = score_cohorts(self.records(), 0, 2, 512)
        self.assertEqual(score["sent"], 20)
        self.assertEqual(score["received"], 16)
        self.assertEqual(score["timely_500ms"], 14)
        self.assertEqual(score["lost_after_drain"], 4)
        self.assertAlmostEqual(score["timely_delivery_ratio"], 0.7)
        self.assertAlmostEqual(score["deadline_miss_ratio"], 0.3)
        self.assertEqual(score["rtt_p95_ms_received_only"], 600)

    def test_loss_never_hidden_by_latency_percentile(self):
        value = self.records()
        for row in value[0]["cohorts"]:
            row["received"] = 0
            row["rtt_ms"] = []
        score = score_cohorts(value, 0, 2, 512)
        self.assertIsNone(score["rtt_p95_ms_received_only"])
        self.assertEqual(score["deadline_miss_ratio"], 1)

    def test_incomplete_duplicate_and_malformed_cohorts_rejected(self):
        bad = []
        value = self.records()
        value[0]["cohorts"].pop()
        bad.append(value)
        value = self.records()
        value[0]["cohorts"][0]["rtt_ms"] = [float("nan")] * 8
        bad.append(value)
        value = self.records()
        value[0]["cohorts"][0]["sent"] = True
        bad.append(value)
        bad.append(self.records() + self.records())
        for value in bad:
            with self.assertRaises(ValueError):
                score_cohorts(value, 0, 2, 512)

    def test_pacing_rejects_undergeneration_but_not_network_loss(self):
        schedule = [{"start": 0, "end": 2, "pps": 10}]
        self.assertEqual(check_offered_load(self.records(), 2, schedule)["actually_sent"], 20)
        with self.assertRaises(ValueError):
            check_offered_load(self.records(), 2, [{"start": 0, "end": 2, "pps": 20}])

    def test_paired_delta_is_episode_level_and_benign_harm_separate(self):
        base = {"scenario": "benign_burst", "method": "no_action", "replicate": 0,
                "legitimate": {"timely_delivery_ratio": 0.8},
                "suspect": {"echo_goodput_kbit_s": 500}}
        other = deepcopy(base)
        other.update(method="evidence_feedback")
        other["legitimate"]["timely_delivery_ratio"] = 0.9
        other["suspect"]["echo_goodput_kbit_s"] = 400
        result = paired_pilot_summary([base, other])["comparisons"][0]
        self.assertEqual(result["paired_episodes"], 1)
        self.assertAlmostEqual(result["mean_delta_legitimate_timely_delivery"], 0.1)
        self.assertEqual(result["mean_delta_suspect_goodput_kbit_s"], -100)
        self.assertTrue(result["suspect_is_benign"])
        self.assertIsNone(result["confidence_interval"])
        with self.assertRaises(ValueError):
            paired_pilot_summary([other])

    def test_live_reader_ignores_only_incomplete_trailing_record(self):
        path = Mock()
        path.exists.return_value = True
        path.is_symlink.return_value = False
        path.stat.return_value.st_size = 100
        path.read_text.return_value = '{"a":1}\n{"a":'
        self.assertEqual(read_jsonl(path), [{"a": 1}])
        with self.assertRaises(ValueError):
            read_jsonl(path, completed=True)
        for text in ('{"a":1,"a":2}\n', '{"a":NaN}\n', '[]\n'):
            path.read_text.return_value = text
            with self.assertRaises(ValueError):
                read_jsonl(path)

    def test_percentile_definition(self):
        self.assertEqual(percentile(list(range(1, 101))), 95)
        self.assertIsNone(percentile([]))

    def test_pacing_cannot_hide_a_missed_window_in_total(self):
        value = self.records()
        value[0]["cohorts"][0]["sent"] = 8
        value[0]["cohorts"][1]["sent"] = 12
        # Use larger count to remove the allowed one-packet rounding tolerance.
        for row in value[0]["cohorts"]:
            row["sent"] *= 10
        with self.assertRaises(ValueError):
            check_offered_load(value, 2, [{"start": 0, "end": 2, "pps": 100}])

    def test_server_counters_are_not_substituted_by_client_echo_counts(self):
        clients = {role: [{"type": "cohort_summary", "sent": 20, "received": 15}]
                   for role in ("legitimate", "suspect")}
        server = [{"type": "server_summary", "invalid": 0, "sources": {
            role: {"received": 18, "received_bytes": 18 * 512, "echoed": 18, "echo_errors": 0}
            for role in clients}}]
        value = score_server(server, clients, 2, 512)
        self.assertEqual(value["sources"]["suspect"]["received_datagrams"], 18)
        clients["suspect"][0]["received"] = 19
        with self.assertRaises(ValueError):
            score_server(server, clients, 2, 512)


if __name__ == "__main__":
    unittest.main()
