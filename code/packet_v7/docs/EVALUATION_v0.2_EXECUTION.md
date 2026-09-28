# Orders 0–5: execution and reproduction record

Completed on 2026-09-23. This record supplements the original proposed plan;
it does not retrospectively rewrite frozen protocols or earlier results.

## Read these first

- `docs/EVALUATION_v0.2_PAPER_TAKEAWAYS.md`: concise scientific interpretation.
- `results/evaluation_v0.2/final_verified_20260923/REPORT.md`: detailed tables.
- The adjacent `analysis.json`: exact selected runs, excluded directories,
  all process-block/seed metrics, sensitivity summaries and limitations.
- The adjacent `manifest.json`: SHA-256 of consumed compact artifacts and
  generated outputs, plus the postprocessor's source identity.
- `results/evaluation_v0.2/raw_spot_audit/REPORT.md`: independent raw accounting
  spot-check of block0 for both methods in all six load conditions (12/60
  cells), with reproducible script and raw hashes in the same directory.

The raw spot-check passed after streaming 1,708,000 arrival rows and 1,069,564
completion rows, including warm-up. It reconciles counts, identities,
timestamps, deadlines, lateness and outstanding-work accounting. It does not
recompute every latency percentile or constitute a full 60-cell raw audit.

## Environment and operational safeguards

Windows 11 10.0.26200; Intel Core Ultra 7 268V, eight logical processors;
33,895,956,480 bytes physical RAM; CPython 3.12.14. This is one ordinary
institution-managed workstation, not an isolated real-time benchmark host.
Background idleness was not certified. Power plan, security controls,
priority and affinity were unchanged. Full host context is retained in
`results/evaluation_v0.2/performance_pilot_protocol/host_context.json`.

All experiment partitions were run serially; each load cell intentionally
uses concurrent producer and consumer processes. Supervisory polling remained active. The
supervisor bounds its own Windows Job process tree, committed memory at
2 GiB, wall time at one hour per partition and new output at 5 GiB; it checks
at least 10 GiB free disk before a large run. It samples process peak RSS
separately. The frozen design's legacy `maximum_worker_rss_bytes` field is
implemented by a Windows commitment limit, not a hard RSS limit; receipts
state the actual mechanism. No unrelated processes are terminated.

No administrator setting change, VM, network traffic generation, OpenAI key,
model call, commit or upload was used for this campaign. Normal child-process
and temporary-folder access was needed to execute local tests; this is not
Windows administrator access.

## Frozen and retained evidence

Qualified baseline:
`results/evaluation_v0.2/stage0_20260923T101641448206Z_0c66c46b4df9`.
All 128 tracked baseline files remain unchanged. The earlier preparation
baseline is retained; its one freeze-helper correction and qualification
history are documented in `docs/EVALUATION_PROGRESS.md`.

The user chose to preserve v0.1 and disclose its limitations. No silent
protected-service/rollback policy correction was made.

Orders 1–3 use the original completed run identities listed in the final
analysis. Timing/load selection uses only these predeclared label families:

```
rev1_stage4_micro_{dataset}
rev1_stage5_scaling_{dataset}_{state_size}
rev1_stage5_load_{dataset}_{rate}
```

Datasets: `netslab`, `5gnidd`. State sizes: 0, 1, 10, 100, 1000.
Rates: 100, 1000, 5000. Each actual directory appends a timestamp and random
identifier. There must be exactly one valid final partition per condition;
the synthesizer refuses ambiguous duplicates or missing evidence.

All 18 final performance partitions have one identical source-snapshot hash:
`2f7bb5d1ab6ef96e7072713ff686b21bea344adaf935960f7d5ca8f268a56b88`.
The final postprocessor verifies that equality as well as each run's
before/after source equality, design/workload identity and baseline receipts.

The Windows dynamic-output scanner was narrowly corrected after a diagnostic
trace located a disappearing `desktop.ini` metadata leaf. No creator/deleter
was identified. All performance conditions were then rerun under monitor
`dynamic-output-scan/0.2.1`; earlier runs were not selected for favorable
timings. See `monitor_revision_protocol/ADDENDUM.md` under the results root.
All old complete, failed, diagnostic and pilot attempts remain retained.

Prepared timing workloads are frozen at:
`results/evaluation_v0.2/stage4_prepared_20260923T103537Z_74cfd849/work`.
Later workload/sampling manifests resolve the deliberately open preparation
markers in the Stage0 design before their respective measurements; those
historical preparation markers were not retrospectively edited.

## Reproduce the analysis without rerunning measurements

From the repository root, using a compatible Python installation:

The package declares no runtime dependencies; this campaign used Python
3.12.14. Final regression: 317 tests run, 316 passed, one permission-dependent
symlink test skipped. No paid API or external service is required.

```powershell
python -m unittest discover -s tests
python scripts/freeze_evaluation_baseline.py verify --baseline results/evaluation_v0.2/stage0_20260923T101641448206Z_0c66c46b4df9
python scripts/summarize_evaluation_v02.py --output results/evaluation_v0.2/my_fresh_summary
```

The output directory must not already exist. Expect all18 required performance
partitions and status `COMPLETE_WITH_REPORTED_FINDINGS`, zero missing-evidence
errors—not a universal scientific “pass.” Numerical content should agree;
the excluded-directory index can differ as additional local analysis folders
are created. The summary tool is a campaign-specific evidence selector with
explicit run identities, not an automatic importer of arbitrary new studies.

It reads compact summaries/receipts and their recorded provenance. It does
not rehash the entire NetsLab parent archive, whose original receipt is
explicitly marked receipt-only, or independently recompute every raw row.
The separate raw spot audit has its own narrower verification scope.

## Reproduce measurements on a second computer

Use a fresh checkout/export with the authorized datasets and preserved
manifests, following `DATASET.md`; do not redistribute raw data without
checking its license. Verify hashes and run the short instrumentation pilots
before large measurements. The current guarded large-run supervisor targets
Windows. Porting that supervisor requires separately qualified resource
monitoring; the unfinished Ubuntu packet experiment is a different study.

Each selected run's `STARTED.json` records its script, exact arguments,
baseline, label and limits. Each performance `work/run_plan.json` records
the process jobs, runtime, seeds and design/workload hashes. Read these as
data. Do not blindly execute arbitrary commands from an untrusted result
archive. For a new reproduction, use fresh labels and update upstream output
paths in dependency order; do not reuse or overwrite the original outputs.

The measurement order is:

1. Baseline verification and regression tests.
2. `run_validity_v02.py --mode validity`, then `--mode netslab`.
3. `run_dataset_evaluation_v02.py census`, then `panels` with that census.
4. The 12 declared `run_sensitivity_v02.py` conditions, using the fixed inputs.
5. `run_performance_v02.py prepare` from completed NetsLab and NIDD conformance
   case outputs, then short excluded pilots for each dataset/mode.
6. `micro` once per dataset, `scaling` once per dataset/state size, then
   `load` once per dataset/rate; all serial, with the unchanged full design.

Use `scripts/supervise_evaluation_v02.py` for each measurement invocation.
For example, this reruns only one full latency partition against the retained
workload and qualified baseline:

```powershell
python scripts/supervise_evaluation_v02.py --script scripts/run_performance_v02.py --label replication_micro_netslab --baseline results/evaluation_v0.2/stage0_20260923T101641448206Z_0c66c46b4df9 -- micro --workloads results/evaluation_v0.2/stage4_prepared_20260923T103537Z_74cfd849/work --dataset netslab
```

Do not provide the child `--output` when using the supervisor; it assigns a
fresh owned directory. Keep source files unchanged throughout comparative
runs. Retain unfavorable completed observations and scheduler-limited cells.
An execution COMPLETE receipt establishes provenance/completion only; inspect
the child findings. Technical failures stay incomplete and preserved, not
silently promoted to passes or filled with partial observations.

Reproduction runs must be compared separately with this campaign. They do not
automatically become new primary results or replace slower original blocks.
Never infer an identical wall-clock result on different hardware.

## Publication boundary

No public-release claim is made yet. Author reference-table/standards checks,
threshold approval, data-license review, author/ORCID metadata, repository URL
and a clean second-machine reproduction remain human/release tasks.
Diagnostic traces may include private absolute paths: inspect/redact a
separate release copy rather than altering the original evidence.

The Ubuntu experiment is still needed for packet/service outcomes and
rollback effects. Orders0–5 do not establish detector accuracy, LLM planning
accuracy, mitigation effectiveness or live O-RAN interoperability.
