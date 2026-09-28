#!/usr/bin/env python3
"""Run all comparison systems against the frozen conformance suite."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.cli import main


if __name__ == "__main__":
    main()

