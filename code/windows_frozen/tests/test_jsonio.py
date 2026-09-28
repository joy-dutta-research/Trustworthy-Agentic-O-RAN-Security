from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.jsonio import StrictJsonError, strict_json_loads


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaises(StrictJsonError):
            strict_json_loads('{"decision":"ALLOW","decision":"DENY"}', maximum_bytes=1024)

    def test_non_finite_constants_are_rejected(self) -> None:
        with self.assertRaises(StrictJsonError):
            strict_json_loads('{"risk":NaN}', maximum_bytes=1024)

    def test_size_limit_is_enforced(self) -> None:
        with self.assertRaises(StrictJsonError):
            strict_json_loads('{"field":"too long"}', maximum_bytes=4)


if __name__ == "__main__":
    unittest.main()
