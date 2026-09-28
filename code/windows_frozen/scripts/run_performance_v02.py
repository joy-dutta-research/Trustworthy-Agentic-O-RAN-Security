#!/usr/bin/env python3
"""Prepare or run the frozen local v0.2 timing/scaling/load experiment.

Always select a NEW --output under results/evaluation_v0.2. Modes micro,
scaling, and load run one dataset per invocation to support bounded partitions.
No network traffic, virtual machine, policy change, or model API is involved.
External supervisory resource containment remains recommended for worker trees.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oran_trust_boundary.evaluation_performance import (
    PerformanceError, local_path, new_output, prepare_workloads, read_json,
    run_experiment, run_worker, utc_now, write_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--netslab-cases", required=True)
    prepare.add_argument("--5gnidd-cases", dest="nidd_cases", required=True)
    prepare.add_argument("--fallback-approval-registry")
    prepare.add_argument("--output", required=True)
    for mode in ("micro", "scaling", "load"):
        command = commands.add_parser(mode)
        command.add_argument("--design", default="configs/evaluation_v0.2/study_design.json")
        command.add_argument("--workloads", required=True)
        command.add_argument("--dataset", choices=("netslab", "5gnidd"), required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--block-start", type=int, default=0)
        command.add_argument("--block-stop", type=int)
        if mode == "scaling":
            command.add_argument("--state-size", type=int)
        if mode == "load":
            command.add_argument("--rate", type=int)
    worker = commands.add_parser("worker", help=argparse.SUPPRESS)
    worker.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    output = None
    diagnostic_output = None
    try:
        if args.mode == "worker":
            job_path = local_path(ROOT, args.job)
            diagnostic_output = job_path.parent
            result = run_worker(ROOT, job_path)
            print(json.dumps({"status": result["status"]}, sort_keys=True), flush=True)
            return 0
        output = new_output(ROOT, args.output)
        diagnostic_output = output
        write_json(output / "STARTED.json", {"status": "started", "mode": args.mode, "at": utc_now()})
        if args.mode == "prepare":
            fallback = None
            if args.fallback_approval_registry:
                fallback = read_json(local_path(ROOT, args.fallback_approval_registry))["approvals"]
            result = prepare_workloads(ROOT, {"netslab": local_path(ROOT, args.netslab_cases),
                                             "5gnidd": local_path(ROOT, args.nidd_cases)}, output, fallback)
        else:
            result = run_experiment(ROOT, local_path(ROOT, args.design), local_path(ROOT, args.workloads), output,
                                    args.mode, args.dataset, block_start=args.block_start, block_stop=args.block_stop,
                                    state_size=getattr(args, "state_size", None), rate=getattr(args, "rate", None))
        write_json(output / "COMPLETE.json", {"status": result["status"], "mode": args.mode, "at": utc_now()})
        print(json.dumps({"status": result["status"], "output": output.relative_to(ROOT).as_posix()}, sort_keys=True), flush=True)
        # An unfavorable scientific finding is a completed experiment, not a
        # technical failure. Preserve the explicit status in receipts/results.
        return 0 if result["status"] in {"complete", "PREPARED_NOT_MEASURED", "completed_with_reference_disagreement"} else 1
    except (Exception, KeyboardInterrupt) as error:
        # Keep the original traceback locally, including chained native errors.
        # It may contain private absolute paths: review before public release.
        # Failure to save diagnostics must not overwrite an earlier trace or
        # conceal the original failure, and never causes an execution retry.
        trace_status = "no_safe_output_directory"
        if diagnostic_output is not None:
            try:
                with (diagnostic_output / "failure_traceback.txt").open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(traceback.format_exc())
                trace_status = "saved_local_failure_traceback.txt_review_before_sharing"
            except OSError as diagnostic_error:
                trace_status = "not_saved_" + type(diagnostic_error).__name__
        reason = str(error) if isinstance(error, PerformanceError) else "interrupted or unexpected execution failure; inspect retained local logs"
        if output is not None:
            write_json(output / "INCOMPLETE.json", {"status": "incomplete", "type": type(error).__name__, "reason": reason,
                                                    "diagnostic_trace": trace_status, "at": utc_now()})
        print(json.dumps({"status": "incomplete", "reason": reason, "diagnostic_trace": trace_status}, sort_keys=True), flush=True)
        return 2


if __name__ == "__main__":
    mp_support = __import__("multiprocessing")
    mp_support.freeze_support()
    raise SystemExit(main())
