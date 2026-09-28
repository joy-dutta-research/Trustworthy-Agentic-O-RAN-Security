# Evaluation progress (working record)

Updated 2026-09-23. The user authorized execution through Orders 0–5, one stage
at a time, and explicitly chose to preserve the original policy while reporting
the rollback-policy limitation. Ubuntu/packet experiments are outside this run.

## Completed preparation

- Preserved and immediately reverified 128 baseline files. Historical pins
  matched the original core, selected datasets, recorded 5G-NIDD outputs and
  portable home ZIP.
- Baseline: `results/evaluation_v0.2/stage0_20260923T095817671208Z_e34320e14653`.
- Original regression suite: 207 tests passed.
- Stage-0 specification: 8 tests passed. Inventory helper: 20 passed, one
  symlink-creation test skipped because this account lacks that Windows right;
  reparse-point refusal was tested separately.
- Supervisor qualification: 4 tests passed, including attaching/observing a
  small owned Python process in a bounded Windows Job. No administrative
  configuration or network activity was involved.
- Declarative policy table records fourteen rule groups, six actions, exact
  timing boundaries, parser/schema differences, and known legacy limitations.

## Qualification correction and new baseline

- Full regression qualification: 292 tests run, 291 passed, one Windows
  symlink-permission test skipped. An earlier attempt recorded one Windows
  metadata verification error; no research measurement had started.
- The inventory helper now independently re-reads and re-hashes content on a
  Windows-only metadata discrepancy, while still requiring stable file
  identity, size, modification time and matching bytes. Content-change
  refusal was not removed.
- This helper was itself inventoried. Its correction therefore deliberately
  made the first baseline report one modified file. That baseline is retained.
  Exactly 127 other inventoried files, including the original core/policy,
  datasets and historical results, remained identical.
- Qualified baseline for execution:
  `results/evaluation_v0.2/stage0_20260923T101641448206Z_0c66c46b4df9`.
  Both manifests preserve the before/after helper hashes.
- Performance/dataset integration was corrected before measurement so the
  timing preparation requires a completed panel campaign, not a census receipt.

## Execution log (earlier entries retained)

Stage 1 completed: 777 cases, 669 normalized configurations, no gateway
decision/reason/audit mismatches or unhandled errors. All 1,346 feasible
declared pair assignments and 128 targeted triple assignments covered;
14/14 targeted mutations detected and 25/25 scoped property witnesses passed.
The 130 policy-permitted proposals include 12 admitted legacy-limitation
probes; they must not be described as physically safe actions. No admission
among the 647 policy-block-required cases. Independent result review agrees.
Run: `stage1_validity_20260923T101717Z_f62545ac/work`.

Stage 2 NetsLab completed: 20 seeds, 20,000 constructed cases, 19,945 normalized
configurations; 0/16,000 block-required admissions and 4,000/4,000 permitted
admissions. No gateway decision/reason mismatch or unhandled error.
Run: `stage2_netslab_20260923T101734Z_08a19383/work`.

Stage 2 5G-NIDD completed: 1,215,890 rows reconciled, 733,693 eligible records,
2,934,772 comparator decisions. Every natural proposal was permitted under all
four methods; only 33 normalized configurations. Thus the natural census has
no block-required denominator and is not blocking-superiority evidence.
Run: `stage2_nidd_census_20260923T101817Z_8b8ce16b/work`.

Twenty controlled panels: 95,000 proposals, 0/75,000 required-block admissions,
20,000/20,000 permitted admissions. All 5,000 separate false-alarm probes were
admitted, a limitation, not a successful safety result. The conformance group
has 162 normalized configurations, and the false-alarm group one. Largest
panels contain 20,000 source-record occurrences but 14,831 unique records.
Run: `stage2_nidd_panels_20260923T102414Z_8f176b45/work`.

Stage 3 completed: all 12 declared conditions matched their policy reference,
with no decision/reason/audit findings. Several 5G-NIDD changes did not activate
the altered policy bounds; unchanged outcomes are not added boundary coverage.

Initial Stage 4 campaign (subsequently superseded): 160 cells per dataset, all 20 paired process blocks and both
boundaries. Mean paired block-p95 differences versus bypass in the matched
local buffered-logging path: 116.688 microseconds (NetsLab) and 95.828
microseconds (5G-NIDD). These are differences of block percentiles, not a
per-request tail-overhead distribution or end-to-end latency guarantee.

Initial Stage 5 campaign (subsequently superseded): NetsLab scaling completed at all five state sizes (720 cells). The
first 5G-NIDD zero-state attempt stopped at cell 47 (zero-based), with a
monitoring error: "required path is missing". The exact path was not recorded,
so its cause is unresolved. All source/baseline hashes and post-failure retained
output-path/workload checks passed. Failed attempt:
`stage5_scaling_5gnidd_0_20260923T105639Z_43bc0ff3`.
No partial observations from it enter final estimates. A complete fresh retry
with unchanged code/configuration and unchanged guards is planned; the failed
attempt is retained. No policy/gateway changes have been made.

All final campaigns will run via `scripts/supervise_evaluation_v02.py`, with
original-baseline verification, before/after source inventories, a bounded
owned Windows process tree, finite memory/wall/output limits, and preserved
failure artifacts. A COMPLETE execution receipt is not by itself a positive
scientific result: each runner's findings must be inspected separately.

Host power scheme was read without modification: Customized Peak (ConfigMgr).
An initial sandboxed WMI metadata query was denied; no privileges or settings
were changed to work around it. Available metadata and any unavailable fields
must be disclosed in the measurement record.

No API key, live network, VM, code publication, commit or upload is required or
performed by this Windows-only evaluation.

## Final status — 2026-09-23

Orders 0–5 are complete. Orders 1–3 above remain valid. All primary Orders 4–5
measurements were rerun under the one frozen `dynamic-output-scan/0.2.1`
monitor, following the selection rule declared in
`results/evaluation_v0.2/monitor_revision_protocol/ADDENDUM.md`.

Three earlier scaling attempts failed; the last diagnostic traceback located
a vanished Windows `desktop.ini` leaf, not a missing study artifact. Its
creator/deleter was not established. The narrowly corrected scanner logs such
vanished metadata but still fails on missing study files, missing parents,
unsafe links and other I/O errors. Earlier complete, failed and diagnostic
performance attempts are retained and not pooled into primary estimates.
The new monitor addendum is outside the frozen protocol directory; all 128
original baseline files verify unchanged.

Qualification: 315 regression tests ran, 314 passed and one symlink-creation
permission test was skipped. All six revised instrumentation pilots passed
and are excluded from final scientific estimates.

Final performance selection: 18 partitions, 1,820/1,820 planned cells,
320 latency + 1,440 state-scaling + 60 load cells. No selected run has missing
provenance or gateway reference disagreement. All selected runs have unchanged
source and passing baseline verification. One source snapshot and design were
used throughout the revised performance campaign.

Matched-local mean paired block-p95 additions versus bypass: NetsLab
112.9845 µs (95% block-bootstrap CI 108.9131–117.9725), 5G-NIDD 93.22525 µs
(90.3858–96.3448). No-conflict evaluator mean block p95 at 1,000 existing
actions: 19.3665 ms and 19.0063 ms, respectively.

At 100 proposals/s with 100 existing actions, all five blocks for both methods
and both datasets completed all offered requests. Gateway mean completion
fractions at 1,000/s were 66.993% / 67.0977%; at 5,000/s, 14.382% / 14.9272%
(NetsLab / 5G-NIDD). Bypass completed all offered requests. Non-completions
were queue overflow, not unreported losses; no measurement requests remained
right-censored at drain. Two generator-limited NetsLab cells are retained and
flagged. These are host-specific, single-worker observations, not certified
production capacity or a hard-real-time guarantee.

Final synthesis: `results/evaluation_v0.2/final_verified_20260923/REPORT.md`.
Paper interpretation: `docs/EVALUATION_v0.2_PAPER_TAKEAWAYS.md`.
The earlier synthesis is retained. Postprocessing was hardened to require
the identical source snapshot across all final partitions, without changing
measurements or numerical aggregation. A separate raw spot-check passed
for 12/60 load cells (block0, both methods, both datasets, all three rates).
Final regression after that report-only hardening: 317 tests ran, 316 passed,
one permission-dependent symlink test skipped. The final verified report has
zero evidence errors; its performance, dataset and sensitivity payloads are
identical to the preceding synthesis. All 128 baseline files still verify.
Ubuntu closed-loop validation, author verification and second-machine
reproduction remain outstanding; this campaign does not mark them complete.
