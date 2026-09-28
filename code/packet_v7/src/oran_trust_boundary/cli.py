"""Installed command-line entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from .benchmark import load_cases, run_benchmark, write_results
from .engine import TrustBoundary
from .provenance import create_run_manifest, write_run_manifest


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Run the O-RAN Trust-Boundary benchmark")
    parser.add_argument(
        "--suite",
        type=Path,
        default=root / "data" / "conformance" / "conformance_v0.1.jsonl",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=root / "configs" / "paper_policy.json",
    )
    parser.add_argument(
        "--approval-registry",
        type=Path,
        default=root / "data" / "conformance" / "approval_registry_v0.1.json",
    )
    parser.add_argument("--output", type=Path, default=root / "results" / "local")
    parser.add_argument(
        "--dataset-context",
        type=Path,
        default=root / "data" / "processed" / "netslab_contexts_v0.1.json",
        help="Optional generated dataset-context manifest; included in run provenance when present.",
    )
    parser.add_argument("--repeats", type=int, default=100)
    parser.add_argument("--timing-seed", type=int, default=20260922)
    args = parser.parse_args()

    cases = load_cases(args.suite)
    engine = TrustBoundary.from_file(args.policy, args.approval_registry)
    raw_rows, summaries = run_benchmark(
        cases,
        engine,
        repeats=args.repeats,
        timing_seed=args.timing_seed,
    )
    raw_path, summary_path = write_results(raw_rows, summaries, args.output)
    manifest = create_run_manifest(
        root=root,
        suite_path=args.suite,
        policy_path=args.policy,
        approval_registry_path=args.approval_registry,
        raw_results_path=raw_path,
        summary_path=summary_path,
        dataset_context_path=(
            args.dataset_context if args.dataset_context.is_file() else None
        ),
        repeats=args.repeats,
        timing_seed=args.timing_seed,
    )
    manifest_path = write_run_manifest(manifest, args.output / "run_manifest.json")
    print(f"cases={len(cases)}")
    print(f"raw={raw_path}")
    print(f"summary={summary_path}")
    print(f"manifest={manifest_path}")
    for summary in summaries:
        print(
            f"{summary['system']}: accuracy={summary['decision_accuracy']:.3f}, "
            f"unsafe_admission={summary['unsafe_action_admission_rate']:.3f}, "
            f"p95_ms={summary['latency_p95_ms']:.6f}"
        )


if __name__ == "__main__":
    main()
