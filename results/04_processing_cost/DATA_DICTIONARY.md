# Column meanings and units

`host` preserves the raw identifiers: `university` means Workstation 1 and `workstation` means Workstation 2. Reader-facing Markdown tables use Workstation 1/2. `dataset`, `method`, and `boundary` define the timing cell. `blocks` counts repeated processes, and `measured_requests` is their total measured call count. `block_percentile_statistics_microseconds.p50/p95/p99.mean` is the arithmetic mean of each process block's percentile in microseconds. Its `minimum`/`maximum` describe the observed block range, not a confidence interval. `cpu_seconds_including_instrumentation` is process CPU seconds with instrumentation; `peak_rss_bytes` is process resident memory in bytes.

Paired-block comparisons use nanoseconds under `absolute_added_ns`, and a unitless multiplier under `slowdown_ratio`. `ci95` is the recorded within-host bootstrap interval based on the stated `blocks`, `draws` and `analysis_seed`; no interval is recalculated here. The `statistic` names the per-block percentile being compared. It is not a distribution of paired per-request delays. Missing state/input fields in microbenchmarks are not applicable.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
