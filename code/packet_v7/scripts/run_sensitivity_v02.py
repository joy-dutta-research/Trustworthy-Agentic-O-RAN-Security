"""Stage 3 OFAT sensitivity. Original policy and frozen source artifacts are read-only."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from oran_trust_boundary.evaluation_datasets import CONDITIONS, run_sensitivity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, choices=('nidd', 'netslab'))
    parser.add_argument('--input', required=True, type=Path,
                        help='Complete census panels.json/directory or frozen NetsLab cases JSONL/directory')
    parser.add_argument('--condition', required=True, choices=tuple(CONDITIONS))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    run_sensitivity(args.source, args.input, args.condition, args.output)


if __name__ == '__main__':
    main()
