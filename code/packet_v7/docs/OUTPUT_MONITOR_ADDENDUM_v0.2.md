# Dynamic-output monitor addendum

Recorded before the replacement performance campaign. Monitor version:
`dynamic-output-scan/0.2.1`. Measurement/workload schema remains
`evaluation-performance/0.2.0`.

## Observed technical failure

The retained diagnostic traceback from
`stage5_scaling_5gnidd_1_retry1_20260923T110532Z_dfcaa524` identifies a Windows
`FileNotFoundError` (errno 2, winerror 2) for the enumerated output leaf
`work/cell_0006/desktop.ini`. The failing stack is the output-size resource
monitor, not a gateway decision or a missing study-input file. The evidence
does not identify which process created or removed that directory entry.

## Narrow monitoring change

Both the performance runner and its supervisor now use one shared scanner.
It validates every parent chain and inspects each enumerated leaf without
following links. Only on Windows, and only when an enumerated leaf whose name
is exactly `desktop.ini` (case-insensitive) disappears before its `lstat`, may
the scanner continue. Its parent chain must pass a second strict check first.
Each such event is recorded in `_output_monitor_events.jsonl`; that log is
included in output-byte accounting. An existing `desktop.ini` is counted like
any other regular file.

Missing experiment files, missing parents, non-Windows missing files, symbolic
links, reparse points, special entries, permission errors and other I/O errors
remain failures. Static source, input, provenance and baseline checks are
unchanged. No broad exclusion, retry, resource-limit increase or policy change
is introduced.

## Research accounting

Action decisions, workloads, seeds, timing boundaries, repetitions, queue and
load parameters, uncertainty analysis, and resource ceilings are unchanged.
The full Stage 4–5 campaign will be rerun under one frozen updated monitor.
Earlier completed, incomplete and diagnostic attempts remain retained and
are superseded, not selected according to favorable timing. Orders 1–3 remain
separate unchanged results. The updated monitor version is recorded in run
plans, performance summaries and supervisor receipts.

Exact preceding source snapshots and SHA-256 manifests are retained under
`results/evaluation_v0.2/monitor_diagnostics/preserved_v020` and
`results/evaluation_v0.2/monitor_diagnostics/preserved_diagnostics_only`.
Diagnostic tracebacks may contain private absolute paths and require review
before public release.
