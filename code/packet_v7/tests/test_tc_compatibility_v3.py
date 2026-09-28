"""Regression tests using preserved Ubuntu iproute2 6.1.0 diagnostic readbacks."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import mock_open, patch
from oran_trust_boundary.closed_loop_lab import LinuxLab
from test_closed_loop_lab import FakeCommands, READY, MODULE

CONFIG = '[{"protocol":"ip","pref":1,"kind":"u32","chain":0},{"protocol":"ip","pref":1,"kind":"u32","chain":0,"options":{"fh":"800:","ht_divisor":1}},{"protocol":"ip","pref":1,"kind":"u32","chain":0,"options":{"fh":"800::800","order":2048,"key_ht":"800","bkt":"0","flowid":":1","not_in_hw":true,"match":{"value":"acb0202","mask":"ffffffff","offmask":"","off":12},"kind":"police","index":1,"control_action":{"type":"drop"},"overhead":0,"ref":1,"bind":1}}]\n'
BROKEN_COMBINED = '[{"protocol":"ip","pref":1,"kind":"u32","chain":0},{"protocol":"ip","pref":1,"kind":"u32","chain":0,"options":{"fh":"800:","ht_divisor":1}},{"protocol":"ip","pref":1,"kind":"u32","chain":0,"options":{"fh":"800::800","order":2048,"key_ht":"800","bkt":"0","flowid":":1","not_in_hw":true,"match":{"value":"acb0202","mask":"ffffffff","offmask":"","off":12},"kind":"police","index":1,"control_action":{"type":"drop"},"overhead":0,"ref":1,"bind":1} Sent 0 bytes 0 pkts (dropped 0, overlimits 0) }]\n'
STATS = 'filter protocol ip pref 1 u32 chain 0 \nfilter protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1 \nfilter protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 *flowid :1 not_in_hw \n  match 0acb0202/ffffffff at 12\n police 0x1 rate 327680bit burst 8Kb mtu 2Kb action drop overhead 0b \n\tref 1 bind 1 \n\n Sent 0 bytes 0 pkts (dropped 0, overlimits 0) \n'

class CapturedCommands(FakeCommands):
    configuration = CONFIG
    statistics_fail = False
    def __call__(self, command, **kwargs):
        result = super().__call__(command, **kwargs)
        if "filter" in command and "show" in command:
            if "-j" in command:
                text = BROKEN_COMBINED if "-s" in command else self.configuration
                return subprocess.CompletedProcess(command,0,text,"")
            if "-s" in command:
                return subprocess.CompletedProcess(command,1 if self.statistics_fail else 0,STATS,
                                                   "statistics failed" if self.statistics_fail else "")
        return result

class TcCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.fake = CapturedCommands()
        for p in (patch(f"{MODULE}.preflight",return_value=READY),
                  patch(f"{MODULE}.subprocess.run",side_effect=self.fake),
                  patch.object(Path,"mkdir"),patch.object(Path,"open",mock_open())):
            p.start(); self.addCleanup(p.stop)
    def test_real_legacy_combined_output_is_invalid_and_not_repaired(self):
        with self.assertRaises(json.JSONDecodeError): json.loads(BROKEN_COMBINED)
    def test_configuration_and_statistics_are_separate_and_preserved(self):
        with LinuxLab(Path("uncreated-compat-test")) as lab:
            action = lab.apply_limit(80)
            self.assertTrue(action["configuration_verified"])
            self.assertEqual(action["filters"],json.loads(CONFIG))
            self.assertEqual(action["filter_statistics_raw"],STATS)
            readbacks=[c for c in self.fake.commands if "filter" in c and "show" in c]
            self.assertEqual(len(readbacks),2)
            self.assertFalse(any("-j" in c and "-s" in c for c in readbacks))
            change=next(c for c in self.fake.commands if "filter" in c and "replace" in c)
            self.assertEqual(change[5:],["filter","replace","dev","suspect0","parent","ffff:",
                "protocol","ip","pref","1","u32","match","ip","src","10.203.2.2/32",
                "police","rate","327.680kbit","burst","8192","drop","flowid",":1"])
    def test_malformed_configuration_still_fails_closed(self):
        self.fake.configuration = BROKEN_COMBINED
        with LinuxLab(Path("uncreated-compat-test")) as lab:
            with self.assertRaises(json.JSONDecodeError):lab.apply_limit(80)
    def test_missing_policer_is_not_success(self):
        self.fake.configuration = '[{"kind":"u32","options":{}}]'
        with LinuxLab(Path("uncreated-compat-test")) as lab:
            with self.assertRaisesRegex(RuntimeError,"readback failed"):lab.apply_limit(80)
    def test_statistics_command_failure_is_preserved_as_failure(self):
        self.fake.statistics_fail = True
        with LinuxLab(Path("uncreated-compat-test")) as lab:
            with self.assertRaisesRegex(RuntimeError,"Lab command failed"):lab.apply_limit(80)

if __name__ == "__main__":unittest.main()
