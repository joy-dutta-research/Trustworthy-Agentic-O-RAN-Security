# Column meanings and units

`case_occurrences`/`evaluations` are constructed cases, not independent real incidents. `reference_decision_agreement` counts exact agreement with the reference ALLOW/DENY/ESCALATE decision. `block_required_admitted` counts ALLOW outcomes when the reference required DENY or ESCALATE; `block_required_total` is that population's denominator. `permitted_admitted` and `permitted_total` count reference-ALLOW cases. `actual_*` and `reference_*` in strata are decision counts. Strata overlap (for example, an action and a test group), so do not add all strata to form an overall total.

Property rows name the selected action/witness, original/actual decisions and reasons; `passed` is the scoped check outcome. Mutation rows name the injected test-only mutation and the number of mismatches detected; their witness list is illustrative, not a separate denominator. All counts are unitless integers.

CSV and JSON contain the same data. JSON preserves nested structure; CSV flattens object keys with dots and encodes lists explicitly as JSON strings. Empty CSV cells correspond to missing/not-applicable JSON values, not measured zeros. Booleans are true/false. `source` fields are repository-relative evidence filenames followed by JSON Pointers; array indexes are zero-based. Source pointers locate the saved input value, not another independent experiment.

[Back to this stage](README.md)
