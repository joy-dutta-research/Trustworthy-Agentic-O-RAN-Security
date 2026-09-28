"""Additive Stage 2 dataset evaluation. Run large jobs under the v0.2 supervisor."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from oran_trust_boundary.evaluation_datasets import run_census, run_panels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='stage', required=True)
    census = sub.add_parser('census', help='Full pinned-release eligible census and seeded selection')
    census.add_argument('--archive', type=Path, default=ROOT / 'data/raw/5g-nidd/Combined.zip')
    census.add_argument('--pilot-records', type=int, help='Instrumentation-only first 1..1000 eligible rows; never a completed census')
    census.add_argument('--output', required=True, type=Path)
    panels = sub.add_parser('panels', help='Largest-panel conformance and separate false-alarm probes')
    panels.add_argument('--census-output', required=True, type=Path)
    panels.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.stage == 'census':
        run_census(args.archive, args.output, pilot_records=args.pilot_records)
    else:
        run_panels(args.census_output, args.output)


if __name__ == '__main__':
    main()
