# Column meanings and units

Scaling rows use the same timing/resource units as Stage 4. `state_size` is the number of active actions, `state_path` locates the conflict/validation path, `large_input` identifies the near-limit payload, and `resource_only` identifies runs used only for resource measurement. Missing timing values in resource-only runs stay unavailable.

Load `offered_per_second` is scheduled action proposals/s. `counts.scheduled_measurement` is the all-offered denominator, `completed_measurement` counts completions including drain, `overflow_measurement` counts queue drops, and `unfinished_at_drain_bound` counts right-censored admitted requests. `all_offered_fractions` are 0–1 ratios. `deadline_success_fractions_all_offered.1/.10/.100` use millisecond deadlines and the all-offered denominator.

`completion_latency_completed_only`, `queue_latency_completed_only`, `service_latency_completed_only`, and `generator_lateness` expose mean/percentile/maximum nanoseconds and sample counts. Completion latency begins at scheduled arrival; it is not service time alone. Generator-limited cells remain flagged. Producer/consumer CPU are seconds, peak RSS is bytes; neither is whole-machine memory. Counts divided by offering duration are explicitly not sustained-capacity estimates.

`load_summary` converts completion/deadline fractions to 0–100 percent and completion p95 to milliseconds, then averages the five seed statistics within each host/dataset/method/rate. Min/max are observed ranges, not confidence intervals. No request-level values or physical hosts are pooled.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
