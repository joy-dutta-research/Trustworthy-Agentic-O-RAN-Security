# Column meanings and units

The NetsLab comparison uses the Stage 1 count definitions. In 5G-NIDD group rows, each measurement such as `decision_agreement` or `policy_block_required_admissions` has a `numerator`, `denominator`, and 0–1 `rate`. CSV writes nested names as dotted column names. For example, `policy_block_required_admissions.numerator` is the admitted count and `.denominator` is the block-required count. A zero denominator has `rate = null`, not zero risk.

`benign_disruptive_admission` is a specifically constructed false-alarm probe outcome, not a detector metric. `compliant_action_acceptance` is deliberately null for that probe group, so it is not silently relabelled useful mitigation. `distinct_configurations_union` counts normalized meaningful proposals across the group's categories, not source rows. Audit-field completeness/checksum validity concern the recorded audit format, not adversarial integrity or remote persistence.

The eligibility audit has original source-row counts and exclusion reasons. Source records, unique eligible records, generated case occurrences and distinct proposal configurations are different denominators. Seed overlap statistics describe shared selected rows; do not sum panels into an independent sample size.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
