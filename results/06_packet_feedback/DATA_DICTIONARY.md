# Column meanings and units

`vm` is `first` or `repeat`, identifying two separately installed VMs on Workstation 2, not two physical computers. `replicate` is the paired episode identity (0, 1, 2). `episode_id` is its stable local episode identifier. The `protected` and `suspect` objects contain event-cohort `sent`, `received`, `timely_500ms` and loss counts. Delivery/deadline-miss fields are 0–1 ratios. `rtt_p95_ms_received_only` is milliseconds conditional on receiving an echo; `echo_goodput_kbit_s` is echoed payload in decimal kbit/s.

`intervention_count` is the number of apply decisions. Action/restore time fields name their seconds or milliseconds explicitly. List values remain JSON arrays inside CSV cells: an empty list means no corresponding event, not zero delay. `operator_review_requested` is a local flag, not evidence of a human response.

In condition means, `mean_legitimate_timely_percent` uses a 0–100 percentage scale, `mean_suspect_goodput_kbit_s` is decimal kbit/s and `mean_legitimate_received_rtt_p95_ms` is the mean of three received-only episode p95s. `intervention_count` sums apply events across the three episodes. `restore_reasons` contains reason counts. Action-delay means average only episodes where an action occurred.

Paired `delta_timely_pp` is method minus no action in percentage points; `delta_suspect_goodput_kbit_s` is the same paired subtraction in decimal kbit/s. A suspect-goodput decrease is desired for the flood but collateral loss for the benign scenario. `paired_episode_contrasts` explicitly keys both sides by VM/scenario/replicate. All conditions use three repetitions; packet counts are not replication counts.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
